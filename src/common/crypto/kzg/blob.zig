//! EIP-4844 polynomial commitments over blobs (consensus-specs deneb
//! `polynomial-commitments.md`, mirrored by c-kzg-4844).
//!
//! A blob is 4096 canonical big-endian field elements: the evaluations of a degree
//! < 4096 polynomial over the roots of unity of order 4096 in bit-reversal order.
//! The commitment is the MSM of those evaluations with the Lagrange-form setup points.
//!
//! No hidden state and no allocation: `Settings.init` decodes the embedded setup into
//! caller-provided `Settings.Storage`, and every operation that needs scratch memory
//! takes a caller-provided `Workspace` (about 512 KiB). Everything here handles public
//! data only, so the code is variable time.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const sha256 = @import("../sha256.zig");
const kzg = @import("root.zig");
const verify = @import("verify.zig");

const Fr = bls.Fr;
const G1 = bls.G1;
const G1Affine = bls.G1Affine;

pub const field_elements = kzg.field_elements_per_blob;
pub const Blob = [kzg.bytes_per_blob]u8;
pub const Commitment = [kzg.bytes_per_commitment]u8;
pub const Proof = [kzg.bytes_per_proof]u8;
pub const FieldBytes = [kzg.bytes_per_field_element]u8;

pub const Error = error{
    /// A blob element, `z`, or `y` is not a canonical field element (>= BLS_MODULUS).
    InvalidFieldElement,
    /// A commitment or proof is not a valid compressed G1 point in the subgroup.
    InvalidPoint,
};

pub const BatchError = Error || error{ScratchTooSmall};

/// Domain separation tags (consensus-specs `FIAT_SHAMIR_PROTOCOL_DOMAIN` and
/// `RANDOM_CHALLENGE_KZG_BATCH_DOMAIN`).
const fiat_shamir_domain = "FSBLOBVERIFY_V1_";
const batch_domain = "RCKZGBATCH___V1_";

/// The spec's primitive root of the scalar field, the generator of the 2^32 subgroup
/// is `primitive_root^((r - 1) / 2^32)`.
const primitive_root = 7;

const field_elements_log2 = 12;

/// 1 / 4096 mod r. Since r = 1 mod 4096, 4096 * ((r - 1) / 4096) = -1, so the inverse
/// is r - (r - 1) / 4096.
const inverse_width: u256 = kzg.bls_modulus - (kzg.bls_modulus - 1) / field_elements;

comptime {
    assert(field_elements == 1 << field_elements_log2);
    assert((kzg.bls_modulus - 1) % field_elements == 0);
    const width: u512 = field_elements;
    assert(width * inverse_width % kzg.bls_modulus == 1);
    assert(@sizeOf(Fr) == 32);
}

/// Decoded setup: the Lagrange G1 points and the roots of unity, both ready to use.
/// Holds pointers into the `Storage` it was initialised from, which must outlive it.
pub const Settings = struct {
    /// Lagrange-form setup points in bit-reversal order (matching `roots_brp`).
    g1_lagrange: *const [field_elements]G1Affine,
    /// omega^bit_reverse(i) for i in 0..4096; the evaluation domain of a blob.
    roots_brp: *const [field_elements]Fr,

    /// About 560 KiB. Place it in static memory or on the heap, not on a small stack.
    pub const Storage = struct {
        g1_lagrange: [field_elements]G1Affine,
        roots_brp: [field_elements]Fr,
    };

    pub const InitError = error{InvalidSetup};

    /// Decodes the embedded trusted setup into `storage` (a few tens of ms). Points are
    /// decoded without subgroup checks: the setup is public and its hash is asserted in
    /// tests, which also verify samples are in the subgroup.
    pub fn init(storage: *Storage) InitError!Settings {
        // The file holds the Lagrange points in natural order; blobs are bit-reversed.
        for (0..field_elements) |index| {
            const bytes = kzg.setup_g1_lagrange(@intCast(index));
            const point = bls.g1.decompress_unchecked(bytes) catch return error.InvalidSetup;
            if (point.infinity) return error.InvalidSetup;
            storage.g1_lagrange[@bitReverse(@as(u12, @intCast(index)))] = point;
        }
        fill_roots_brp(&storage.roots_brp);
        return .{ .g1_lagrange = &storage.g1_lagrange, .roots_brp = &storage.roots_brp };
    }
};

/// Scratch memory for blob operations (about 512 KiB); contents are meaningless between
/// calls. One workspace serves one call at a time.
pub const Workspace = struct {
    polynomial: [field_elements]Fr,
    denominators: [field_elements]Fr,
    prefix: [field_elements]Fr,
    scalars: [field_elements]u256,
};

/// Roots of unity of order 4096 in bit-reversal permutation order:
/// `roots[bit_reverse(i)] = omega^i` with omega = 7^((r - 1) / 4096).
pub fn fill_roots_brp(roots: *[field_elements]Fr) void {
    const omega = Fr.from_int_comptime(primitive_root)
        .pow((kzg.bls_modulus - 1) / field_elements);
    var power = Fr.one;
    for (0..field_elements) |index| {
        const reversed: u12 = @bitReverse(@as(u12, @intCast(index)));
        roots[reversed] = power;
        power = power.mul(omega);
    }
    assert(power.eql(Fr.one)); // omega has order dividing 4096.
    assert(roots[0].eql(Fr.one) and !roots[1].eql(Fr.one));
}

/// In-place batch inversion (Montgomery's trick): one field inversion for all values.
/// Zeros stay zero. `prefix` is scratch of the same length.
pub fn batch_inverse(values: []Fr, prefix: []Fr) void {
    assert(values.len == prefix.len);
    var accumulator = Fr.one;
    for (values, prefix) |value, *slot| {
        slot.* = accumulator;
        if (!value.is_zero()) accumulator = accumulator.mul(value);
    }
    var inverse = accumulator.inverse();
    var index = values.len;
    while (index > 0) {
        index -= 1;
        const value = values[index];
        if (value.is_zero()) continue;
        values[index] = inverse.mul(prefix[index]);
        inverse = inverse.mul(value);
    }
    assert(inverse.eql(Fr.one) or accumulator.is_zero());
}

/// Parses the blob into canonical field elements.
fn blob_to_polynomial(blob: *const Blob, polynomial: *[field_elements]Fr) Error!void {
    for (polynomial, 0..) |*element, index| {
        const bytes: *const FieldBytes = blob[index * 32 ..][0..32];
        element.* = Fr.from_bytes_be(bytes) orelse return error.InvalidFieldElement;
    }
}

/// Validates the blob and writes its elements as plain integers (MSM scalars).
fn blob_to_scalars(blob: *const Blob, scalars: *[field_elements]u256) Error!void {
    for (scalars, 0..) |*scalar, index| {
        scalar.* = std.mem.readInt(u256, blob[index * 32 ..][0..32], .big);
        if (scalar.* >= kzg.bls_modulus) return error.InvalidFieldElement;
    }
}

fn read_field(bytes: *const FieldBytes) Error!Fr {
    return Fr.from_bytes_be(bytes) orelse error.InvalidFieldElement;
}

fn decode_g1(bytes: *const [48]u8) Error!G1Affine {
    return bls.g1.decompress(bytes) catch error.InvalidPoint;
}

fn encode_g1(point: G1) [48]u8 {
    const affine = point.to_affine();
    assert(affine.is_on_curve());
    return bls.g1.compress(affine);
}

fn lincomb(settings: *const Settings, workspace: *Workspace) G1 {
    return bls.msm.msm(G1, settings.g1_lagrange, &workspace.scalars);
}

/// `blob_to_kzg_commitment`: MSM of the blob with the Lagrange setup.
pub fn blob_to_kzg_commitment(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
) Error!Commitment {
    try blob_to_scalars(blob, &workspace.scalars);
    const commitment = encode_g1(lincomb(settings, workspace));
    assert(commitment[0] & 0x80 != 0);
    return commitment;
}

/// `compute_challenge`: Fiat-Shamir evaluation point for a blob and its commitment.
pub fn compute_challenge(blob: *const Blob, commitment: *const Commitment) Fr {
    var hasher = sha256.Hasher.init();
    hasher.update(fiat_shamir_domain);
    var degree: [16]u8 = undefined;
    std.mem.writeInt(u128, &degree, field_elements, .big);
    hasher.update(&degree);
    hasher.update(blob);
    hasher.update(commitment);
    return hash_to_field(hasher.final());
}

/// `hash_to_bls_field`: the digest as a big-endian integer, reduced mod r.
fn hash_to_field(digest: sha256.Digest) Fr {
    return Fr.from_int(std.mem.readInt(u256, &digest, .big));
}

/// Writes z - roots[i] to `denominators` and inverts them in place (zeros stay zero).
/// Returns the index of the root equal to `z` when `z` is in the domain.
fn inverse_denominators(settings: *const Settings, workspace: *Workspace, z: Fr) ?u32 {
    var domain_index: ?u32 = null;
    for (&workspace.denominators, settings.roots_brp, 0..) |*slot, root, index| {
        slot.* = z.sub(root);
        if (slot.is_zero()) {
            assert(domain_index == null); // Roots are distinct.
            domain_index = @intCast(index);
        }
    }
    batch_inverse(&workspace.denominators, &workspace.prefix);
    return domain_index;
}

/// Barycentric evaluation for `z` outside the domain, given the inverted denominators:
/// (z^N - 1) / N * sum_i p_i * w_i / (z - w_i).
fn evaluate_outside_domain(
    settings: *const Settings,
    polynomial: *const [field_elements]Fr,
    inverses: *const [field_elements]Fr,
    z: Fr,
) Fr {
    var sum = Fr.zero;
    for (polynomial, settings.roots_brp, inverses) |value, root, inverse| {
        sum = sum.add(value.mul(root).mul(inverse));
    }
    var z_power = z;
    for (0..field_elements_log2) |_| z_power = z_power.square();
    const factor = z_power.sub(Fr.one).mul(Fr.from_int_comptime(inverse_width));
    return sum.mul(factor);
}

/// `evaluate_polynomial_in_evaluation_form`: the polynomial given by its evaluations
/// over the (bit-reversed) domain, evaluated at `z`. Handles `z` equal to a root.
pub fn evaluate_polynomial_in_evaluation_form(
    settings: *const Settings,
    workspace: *Workspace,
    polynomial: *const [field_elements]Fr,
    z: Fr,
) Fr {
    if (inverse_denominators(settings, workspace, z)) |index| {
        assert(settings.roots_brp[index].eql(z));
        return polynomial[index];
    }
    return evaluate_outside_domain(settings, polynomial, &workspace.denominators, z);
}

pub const ProofAndValue = struct {
    proof: Proof,
    /// The evaluation of the blob polynomial at `z`, canonical big-endian.
    y: FieldBytes,
};

/// `compute_kzg_proof`: the proof that the blob polynomial evaluates to `y` at `z`.
pub fn compute_kzg_proof(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
    z_bytes: *const FieldBytes,
) Error!ProofAndValue {
    const z = try read_field(z_bytes);
    try blob_to_polynomial(blob, &workspace.polynomial);
    const result = prove_loaded(settings, workspace, z);
    return .{ .proof = encode_g1(result.proof), .y = result.y.to_bytes_be() };
}

/// `compute_blob_kzg_proof`: the proof at the Fiat-Shamir challenge, for the verifier
/// to check with `verify_blob_kzg_proof`. The commitment must be a valid point.
pub fn compute_blob_kzg_proof(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
    commitment: *const Commitment,
) Error!Proof {
    _ = try decode_g1(commitment);
    try blob_to_polynomial(blob, &workspace.polynomial);
    const z = compute_challenge(blob, commitment);
    return encode_g1(prove_loaded(settings, workspace, z).proof);
}

/// `compute_kzg_proof_impl` over `workspace.polynomial`: y = p(z) and the quotient
/// (p(X) - y) / (X - z) in evaluation form, committed with the Lagrange setup.
fn prove_loaded(settings: *const Settings, workspace: *Workspace, z: Fr) struct {
    proof: G1,
    y: Fr,
} {
    const domain_index = inverse_denominators(settings, workspace, z);
    const polynomial = &workspace.polynomial;
    const inverses = &workspace.denominators;
    const y = if (domain_index) |index|
        polynomial[index]
    else
        evaluate_outside_domain(settings, polynomial, inverses, z);

    // Out-of-range sentinel when z is not a root, so no iteration is skipped.
    const skipped: usize = if (domain_index) |index| index else field_elements;
    var domain_sum = Fr.zero;
    for (workspace.scalars[0..], polynomial, inverses, 0..) |*scalar, value, inverse, index| {
        if (index == skipped) continue;
        // term = (p_i - y) / (z - w_i); the quotient divides by (w_i - z) instead.
        const term = value.sub(y).mul(inverse);
        scalar.* = term.neg().to_int();
        if (domain_index != null) {
            domain_sum = domain_sum.add(term.mul(settings.roots_brp[index]));
        }
    }
    if (domain_index) |index| {
        // compute_quotient_eval_within_domain: sum_{i != m} f_i w_i / (w_m (w_m - w_i)).
        assert(!z.is_zero() and index < field_elements);
        workspace.scalars[index] = domain_sum.mul(z.inverse()).to_int();
    }
    return .{ .proof = lincomb(settings, workspace), .y = y };
}

/// `verify_blob_kzg_proof`: true when `proof` proves the blob matches `commitment`.
pub fn verify_blob_kzg_proof(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
    commitment_bytes: *const Commitment,
    proof_bytes: *const Proof,
) Error!bool {
    const commitment = try decode_g1(commitment_bytes);
    const proof = try decode_g1(proof_bytes);
    try blob_to_polynomial(blob, &workspace.polynomial);
    const z = compute_challenge(blob, commitment_bytes);
    const polynomial = &workspace.polynomial;
    const y = evaluate_polynomial_in_evaluation_form(settings, workspace, polynomial, z);
    return verify.verify_kzg_proof_points(commitment, z.to_int(), y.to_int(), proof);
}

/// Per-batch scratch for `verify_blob_kzg_proof_batch`: holds at least `n` blobs when
/// `zs.len >= n`, `ys.len >= n`, and `points.len`, `scalars.len >= 2n + 1`.
pub const BatchScratch = struct {
    points: []G1Affine,
    scalars: []u256,
    zs: []Fr,
    ys: []Fr,
};

/// Fixed-capacity storage for batches of up to `capacity` blobs.
pub fn BatchStorage(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        points: [2 * capacity + 1]G1Affine = undefined,
        scalars: [2 * capacity + 1]u256 = undefined,
        zs: [capacity]Fr = undefined,
        ys: [capacity]Fr = undefined,

        pub fn scratch(self: *Self) BatchScratch {
            return .{
                .points = &self.points,
                .scalars = &self.scalars,
                .zs = &self.zs,
                .ys = &self.ys,
            };
        }
    };
}

/// `verify_blob_kzg_proof_batch`: one pairing check for many blobs via a random linear
/// combination (r from the hash of every input). An empty batch is valid.
///
/// With r_i = r^i the check e(sum r_i proof_i, [tau]G2) == e(sum r_i (C_i - [y_i]G1 +
/// [z_i] proof_i), G2) is evaluated as two MSMs; the y terms collapse to one multiple
/// of the generator, as in c-kzg-4844.
pub fn verify_blob_kzg_proof_batch(
    settings: *const Settings,
    workspace: *Workspace,
    scratch: BatchScratch,
    blobs: []const *const Blob,
    commitments: []const Commitment,
    proofs: []const Proof,
) BatchError!bool {
    assert(blobs.len == commitments.len and blobs.len == proofs.len);
    const count = blobs.len;
    if (count == 0) return true;
    if (scratch.zs.len < count or scratch.ys.len < count) return error.ScratchTooSmall;
    if (scratch.points.len < 2 * count + 1 or scratch.scalars.len < 2 * count + 1) {
        return error.ScratchTooSmall;
    }
    for (blobs, commitments, proofs, 0..) |blob, *commitment_bytes, *proof_bytes, index| {
        scratch.points[count + index] = try decode_g1(commitment_bytes);
        scratch.points[index] = try decode_g1(proof_bytes);
        try blob_to_polynomial(blob, &workspace.polynomial);
        const z = compute_challenge(blob, commitment_bytes);
        scratch.zs[index] = z;
        const polynomial = &workspace.polynomial;
        scratch.ys[index] =
            evaluate_polynomial_in_evaluation_form(settings, workspace, polynomial, z);
    }
    const r = batch_challenge(scratch, commitments, proofs, count);
    return check_batch(scratch, r, count);
}

/// Hash of the whole batch to a field element: the base of the random powers.
fn batch_challenge(
    scratch: BatchScratch,
    commitments: []const Commitment,
    proofs: []const Proof,
    count: usize,
) Fr {
    var hasher = sha256.Hasher.init();
    hasher.update(batch_domain);
    var header: [16]u8 = undefined;
    std.mem.writeInt(u64, header[0..8], field_elements, .big);
    std.mem.writeInt(u64, header[8..16], count, .big);
    hasher.update(&header);
    for (commitments[0..count], proofs[0..count], 0..) |*commitment, *proof, index| {
        hasher.update(commitment);
        hasher.update(&scratch.zs[index].to_bytes_be());
        hasher.update(&scratch.ys[index].to_bytes_be());
        hasher.update(proof);
    }
    return hash_to_field(hasher.final());
}

/// Final pairing check of the batch; points hold proofs then commitments.
fn check_batch(scratch: BatchScratch, r: Fr, count: usize) bool {
    const points = scratch.points;
    const scalars = scratch.scalars;
    var power = Fr.one;
    var y_sum = Fr.zero;
    for (0..count) |index| {
        scalars[index] = power.to_int();
        scalars[count + index] = scalars[index];
        y_sum = y_sum.add(power.mul(scratch.ys[index]));
        power = power.mul(r);
    }
    const proof_lincomb = bls.msm.msm(G1, points[0..count], scalars[0..count]);
    power = Fr.one;
    for (0..count) |index| {
        scalars[index] = power.mul(scratch.zs[index]).to_int();
        power = power.mul(r);
    }
    points[2 * count] = bls.g1.generator;
    scalars[2 * count] = y_sum.neg().to_int();
    const left = bls.msm.msm(G1, points[0 .. 2 * count + 1], scalars[0 .. 2 * count + 1]);
    return verify.pairing_check_fixed_g2(left.to_affine(), proof_lincomb.to_affine());
}

const testing = std.testing;

test "blob: inverse width constant" {
    const inverse = Fr.from_int_comptime(inverse_width);
    try testing.expect(inverse.mul(Fr.from_int(field_elements)).eql(Fr.one));
}

const builtin = @import("builtin");
const Prng = @import("../../../testing/prng.zig").Prng;

/// Full MSM-heavy coverage runs outside Debug; Debug keeps one case per code path
/// (an MSM over 4096 points takes seconds unoptimised).
const heavy_tests = builtin.mode != .debug;

// Tests share one decoded setup and workspace (about 1.1 MiB, too big for the stack).
var test_storage: Settings.Storage = undefined;
var test_workspace: Workspace = undefined;
var test_settings: ?Settings = null;

fn shared_settings() !*const Settings {
    if (test_settings == null) test_settings = try Settings.init(&test_storage);
    return &test_settings.?;
}

fn random_blob(prng: *Prng, blob: *Blob) void {
    for (0..field_elements) |index| {
        prng.fill(blob[index * 32 ..][0..32]);
        blob[index * 32] &= 0x3f; // < 2^254 < r
    }
}

fn blob_element(blob: *const Blob, index: usize) Fr {
    return Fr.from_bytes_be(blob[index * 32 ..][0..32]).?;
}

test "blob: roots of unity are in bit-reversal order" {
    const settings = try shared_settings();
    const roots = settings.roots_brp;
    try testing.expect(roots[0].eql(Fr.one));
    // omega^2048 = -1 sits at bit_reverse(1) = 2048 and omega^1024 at index 1024's mirror.
    try testing.expect(roots[1].eql(Fr.one.neg()));
    const omega = Fr.from_int_comptime(primitive_root).pow((kzg.bls_modulus - 1) / field_elements);
    for ([_]usize{ 0, 3, 2047 }) |index| {
        const reversed: u12 = @bitReverse(@as(u12, @intCast(index)));
        try testing.expect(roots[reversed].eql(omega.pow(index)));
        try testing.expect(roots[reversed].pow(field_elements).eql(Fr.one));
    }
    // Primitive: omega^2048 != 1, and the generator 7 has no 4096th-root shortcut.
    try testing.expect(!omega.pow(field_elements / 2).eql(Fr.one));
    // Distinct elements: the squares of the second half of the domain are the first half.
    for (0..16) |index| {
        const square = roots[index + 16].square();
        try testing.expect(!square.eql(roots[index + 16]));
    }
}

test "blob: sampled setup points are in the subgroup" {
    const settings = try shared_settings();
    for ([_]usize{ 0, 1999, 4095 }) |index| {
        const point = settings.g1_lagrange[index];
        try testing.expect(point.is_on_curve() and !point.infinity);
        // The subgroup check takes about a second per point in Debug.
        if (heavy_tests or index == 1999) try testing.expect(bls.g1.is_in_subgroup(point));
    }
    // File point i sits at bit-reversed index: the last lands at 4095, point 1 at 2048.
    const last = try bls.g1.decompress_unchecked(kzg.setup_g1_lagrange(field_elements - 1));
    try testing.expect(settings.g1_lagrange[4095].eql(last));
    const second = try bls.g1.decompress_unchecked(kzg.setup_g1_lagrange(1));
    try testing.expect(settings.g1_lagrange[2048].eql(second));
}

test "blob: batch inversion matches single inversions" {
    var prng = Prng.init(0x1417);
    var values: [37]Fr = undefined;
    var original: [37]Fr = undefined;
    var prefix: [37]Fr = undefined;
    for (&values, 0..) |*value, index| {
        value.* = if (index % 9 == 4) Fr.zero else Fr.from_int(prng.int(u256));
    }
    original = values;
    batch_inverse(&values, &prefix);
    for (values, original) |inverse, value| {
        try testing.expect(inverse.eql(value.inverse()));
        if (!value.is_zero()) try testing.expect(inverse.mul(value).eql(Fr.one));
    }
    var empty: [0]Fr = .{};
    batch_inverse(&empty, &empty);
}

fn evaluate(settings: *const Settings, polynomial: *const [field_elements]Fr, z: Fr) Fr {
    return evaluate_polynomial_in_evaluation_form(settings, &test_workspace, polynomial, z);
}

test "blob: evaluation of low-degree polynomials in evaluation form" {
    const settings = try shared_settings();
    var prng = Prng.init(0xe7a1);
    const a = Fr.from_int(prng.int(u256));
    const b = Fr.from_int(prng.int(u256));
    // p(x) = a + b x has evaluations a + b w_i in domain order.
    var linear: [field_elements]Fr = undefined;
    for (&linear, settings.roots_brp) |*value, root| value.* = a.add(b.mul(root));
    var points: [6]Fr = undefined;
    for (points[0..3]) |*z| z.* = Fr.from_int(prng.int(u256));
    points[3] = settings.roots_brp[0];
    points[4] = settings.roots_brp[1234];
    points[5] = Fr.zero; // Not a root: 0 is outside the multiplicative group.
    for (points) |z| {
        const value = evaluate(settings, &linear, z);
        try testing.expect(value.eql(a.add(b.mul(z))));
    }
    if (!heavy_tests) return;
    // A constant polynomial evaluates to the constant everywhere.
    const constant: [field_elements]Fr = @splat(a);
    for (points) |z| {
        const value = evaluate(settings, &constant, z);
        try testing.expect(value.eql(a));
    }
    // p(x) = x^3 stays within degree < 4096.
    var cubic: [field_elements]Fr = undefined;
    for (&cubic, settings.roots_brp) |*value, root| value.* = root.square().mul(root);
    for (points) |z| {
        const value = evaluate(settings, &cubic, z);
        try testing.expect(value.eql(z.square().mul(z)));
    }
}

test "blob: invalid inputs are rejected" {
    const settings = try shared_settings();
    var blob: Blob = @splat(0);
    const zero: FieldBytes = @splat(0);
    std.mem.writeInt(u256, blob[77 * 32 ..][0..32], kzg.bls_modulus, .big);
    try testing.expectError(
        error.InvalidFieldElement,
        blob_to_kzg_commitment(settings, &test_workspace, &blob),
    );
    try testing.expectError(
        error.InvalidFieldElement,
        compute_kzg_proof(settings, &test_workspace, &blob, &zero),
    );
    blob = @splat(0);
    var modulus_bytes: FieldBytes = undefined;
    std.mem.writeInt(u256, &modulus_bytes, kzg.bls_modulus, .big);
    try testing.expectError(
        error.InvalidFieldElement,
        compute_kzg_proof(settings, &test_workspace, &blob, &modulus_bytes),
    );
    // Undecodable encodings are cheap; the subgroup check is slow in Debug, so the
    // off-subgroup point is tried once.
    const garbage: Commitment = @splat(0xff);
    const infinity = bls.g1.compress(bls.G1Affine.identity);
    if (heavy_tests) {
        const off = bls.g1.compress(bls.g1.test_point_off_subgroup(3));
        try testing.expectError(
            error.InvalidPoint,
            compute_blob_kzg_proof(settings, &test_workspace, &blob, &off),
        );
    }
    try testing.expectError(
        error.InvalidPoint,
        verify_blob_kzg_proof(settings, &test_workspace, &blob, &garbage, &infinity),
    );
    try testing.expectError(
        error.InvalidPoint,
        verify_blob_kzg_proof(settings, &test_workspace, &blob, &infinity, &garbage),
    );
}

fn stored_blob(index: u32) *const Blob {
    assert(index < stored_blob_count);
    const offset = @as(usize, index) * kzg.bytes_per_blob;
    return vector_blobs[offset..][0..kzg.bytes_per_blob];
}

const vector_blobs = @embedFile("blob_vectors.bin");
const vector_lines = @embedFile("blob_vectors.txt");
const stored_blob_count = 7;
var synthetic_blobs: [2]Blob = undefined;

fn parse_hex(comptime length: usize, hex: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if (hex.len != 2 * length) return error.BadVector;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

/// Blob `index` of the vectors: seven stored blobs, then two synthetic non-canonical
/// ones (all 0xff, and zeros with one element equal to the modulus).
fn vector_blob(index: u32) *const Blob {
    if (index < stored_blob_count) return stored_blob(index);
    assert(index < stored_blob_count + 2);
    const synthetic = &synthetic_blobs[index - stored_blob_count];
    if (index == stored_blob_count) {
        synthetic.* = @splat(0xff);
    } else {
        synthetic.* = @splat(0);
        std.mem.writeInt(u256, synthetic[2111 * 32 ..][0..32], kzg.bls_modulus, .big);
    }
    return synthetic;
}

const Fields = std.mem.TokenIterator(u8, .scalar);

fn next_field(fields: *Fields) ![]const u8 {
    return fields.next() orelse error.BadVector;
}

/// Debug runs one MSM-based vector: the first in-domain evaluation point on a random
/// blob (an MSM over 4096 points takes seconds unoptimised).
fn debug_runs_proof(settings: *const Settings, index: u32, z_bytes: *const FieldBytes) bool {
    const z = Fr.from_bytes_be(z_bytes) orelse return false;
    for (settings.roots_brp) |root| {
        if (root.eql(z) and index == 2 and !debug_proof_done) {
            debug_proof_done = true;
            return true;
        }
    }
    return false;
}

var debug_proof_done = false;

fn run_commitment_vector(settings: *const Settings, fields: *Fields, index: u32) !void {
    const expected = try next_field(fields);
    if (expected[0] == 'E') {
        const result = blob_to_kzg_commitment(settings, &test_workspace, vector_blob(index));
        return testing.expect(std.meta.isError(result));
    }
    if (!heavy_tests) return;
    const result = try blob_to_kzg_commitment(settings, &test_workspace, vector_blob(index));
    try testing.expectEqualSlices(u8, &(try parse_hex(48, expected)), &result);
}

fn run_proof_vector(settings: *const Settings, fields: *Fields, index: u32) !void {
    const z = try parse_hex(32, try next_field(fields));
    const expected = try next_field(fields);
    if (expected[0] == 'E') {
        const result = compute_kzg_proof(settings, &test_workspace, vector_blob(index), &z);
        return testing.expect(std.meta.isError(result));
    }
    if (!heavy_tests and !debug_runs_proof(settings, index, &z)) return;
    const result = try compute_kzg_proof(settings, &test_workspace, vector_blob(index), &z);
    try testing.expectEqualSlices(u8, &(try parse_hex(48, expected)), &result.proof);
    try testing.expectEqualSlices(u8, &(try parse_hex(32, try next_field(fields))), &result.y);
}

fn run_blob_proof_vector(settings: *const Settings, fields: *Fields, index: u32) !void {
    const commitment = try parse_hex(48, try next_field(fields));
    const expected = try next_field(fields);
    if (!heavy_tests) return; // Verified indirectly by the `V` vectors in Debug.
    const blob = vector_blob(index);
    const result = compute_blob_kzg_proof(settings, &test_workspace, blob, &commitment);
    if (expected[0] == 'E') return testing.expect(std.meta.isError(result));
    try testing.expectEqualSlices(u8, &(try parse_hex(48, expected)), &(try result));
}

fn expect_verdict(result: anytype, verdict: u8) !void {
    switch (verdict) {
        '1' => try testing.expect(try result),
        '0' => try testing.expect(!(try result)),
        'E' => try testing.expect(std.meta.isError(result)),
        else => return error.BadVector,
    }
}

fn run_verify_vector(settings: *const Settings, fields: *Fields, index: u32) !void {
    const commitment = try parse_hex(48, try next_field(fields));
    const proof = try parse_hex(48, try next_field(fields));
    const verdict = (try next_field(fields))[0];
    // Debug: error cases (cheap) and the first random blob only (pairings are slow).
    if (!heavy_tests and !(index == 2 and verdict == '1')) return;
    const blob = vector_blob(index);
    const result = verify_blob_kzg_proof(settings, &test_workspace, blob, &commitment, &proof);
    try expect_verdict(result, verdict);
}

fn run_batch_vector(settings: *const Settings, fields: *Fields, count: u32) !void {
    var blobs: [8]*const Blob = undefined;
    var commitments: [8]Commitment = undefined;
    var proofs: [8]Proof = undefined;
    if (count > blobs.len) return error.BadVector;
    if (!heavy_tests and count != 2) return; // One batch case in Debug (slow pairing).
    var indices = std.mem.tokenizeScalar(u8, try next_field(fields), ',');
    var commitment_hex = std.mem.tokenizeScalar(u8, try next_field(fields), ',');
    var proof_hex = std.mem.tokenizeScalar(u8, try next_field(fields), ',');
    for (0..count) |slot| {
        blobs[slot] = vector_blob(try std.fmt.parseInt(u32, indices.next().?, 10));
        commitments[slot] = try parse_hex(48, commitment_hex.next().?);
        proofs[slot] = try parse_hex(48, proof_hex.next().?);
    }
    var storage: BatchStorage(8) = .{};
    const result = verify_blob_kzg_proof_batch(
        settings,
        &test_workspace,
        storage.scratch(),
        blobs[0..count],
        commitments[0..count],
        proofs[0..count],
    );
    try expect_verdict(result, (try next_field(fields))[0]);
}

test "blob: c-kzg-4844 vectors" {
    const settings = try shared_settings();
    var lines = std.mem.tokenizeScalar(u8, vector_lines, '\n');
    var counts: [5]u32 = @splat(0);
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = (try next_field(&fields))[0];
        const number = try std.fmt.parseInt(u32, try next_field(&fields), 10);
        switch (kind) {
            'B' => try run_commitment_vector(settings, &fields, number),
            'P' => try run_proof_vector(settings, &fields, number),
            'C' => try run_blob_proof_vector(settings, &fields, number),
            'V' => try run_verify_vector(settings, &fields, number),
            'X' => try run_batch_vector(settings, &fields, number),
            else => return error.BadVector,
        }
        counts[std.mem.indexOfScalar(u8, "BPCVX", kind).?] += 1;
    }
    // 9 commitment, 48 proof, 11 blob proof, 23 verify, 14 batch cases.
    try testing.expectEqualSlices(u32, &.{ 9, 48, 11, 23, 14 }, &counts);
}

test "blob: batch edge cases" {
    const settings = try shared_settings();
    var storage: BatchStorage(2) = .{};
    // An empty batch is valid.
    const scratch = storage.scratch();
    try testing.expect(try verify_blob_kzg_proof_batch(
        settings,
        &test_workspace,
        scratch,
        &.{},
        &.{},
        &.{},
    ));
    // Scratch for 2 blobs rejects a batch of 3 before doing any work.
    const blob = stored_blob(0);
    const commitment: Commitment = bls.g1.compress(bls.G1Affine.identity);
    const blobs = [3]*const Blob{ blob, blob, blob };
    const commitments = [3]Commitment{ commitment, commitment, commitment };
    try testing.expectError(error.ScratchTooSmall, verify_blob_kzg_proof_batch(
        settings,
        &test_workspace,
        storage.scratch(),
        &blobs,
        &commitments,
        &commitments,
    ));
    if (!heavy_tests) return;
    // The zero polynomial has the identity as commitment and proof, in a batch of 2.
    try testing.expect(try verify_blob_kzg_proof_batch(
        settings,
        &test_workspace,
        storage.scratch(),
        blobs[0..2],
        commitments[0..2],
        commitments[0..2],
    ));
}

fn verify_one(
    settings: *const Settings,
    blob: *const Blob,
    commitment: *const Commitment,
    proof: *const Proof,
) !bool {
    return verify_blob_kzg_proof(settings, &test_workspace, blob, commitment, proof);
}

fn round_trip_case(settings: *const Settings, prng: *Prng) !void {
    var blob: Blob = undefined;
    random_blob(prng, &blob);
    const commitment = try blob_to_kzg_commitment(settings, &test_workspace, &blob);
    // Evaluate at a random point and at a domain point; both proofs verify with the
    // plain KZG verifier, so the blob API and verify.zig agree.
    var z_values: [2]FieldBytes = undefined;
    prng.fill(&z_values[0]);
    z_values[0][0] &= 0x3f;
    z_values[1] = settings.roots_brp[prng.below(field_elements)].to_bytes_be();
    for (z_values) |z| {
        const result = try compute_kzg_proof(settings, &test_workspace, &blob, &z);
        try testing.expect(try verify.verify_kzg_proof(&commitment, &z, &result.y, &result.proof));
        var wrong_y = result.y;
        wrong_y[31] ^= 1;
        try testing.expect(!try verify.verify_kzg_proof(&commitment, &z, &wrong_y, &result.proof));
    }
    const proof = try compute_blob_kzg_proof(settings, &test_workspace, &blob, &commitment);
    try testing.expect(try verify_one(settings, &blob, &commitment, &proof));
    // Any change to the blob, commitment, or proof breaks verification.
    var changed = blob;
    changed[32 * prng.below(field_elements) + 31] ^= 1;
    try testing.expect(!try verify_one(settings, &changed, &commitment, &proof));
    var other = commitment;
    other[0] ^= 0x20; // The negated point is a valid encoding of a different commitment.
    try testing.expect(!try verify_one(settings, &blob, &other, &proof));
    try testing.expect(!try verify_one(settings, &blob, &commitment, &commitment));
}

test "blob: commit, prove, verify round trips (seeded)" {
    if (!heavy_tests) return error.SkipZigTest;
    const settings = try shared_settings();
    var prng = Prng.init(0x4844_b10b);
    for (0..4) |_| try round_trip_case(settings, &prng);
}

test "blob: batch of random blobs verifies and detects one bad proof" {
    if (!heavy_tests) return error.SkipZigTest;
    const settings = try shared_settings();
    var prng = Prng.init(0xba7c4);
    const count = 3;
    var blob_data: [count]Blob = undefined;
    var blobs: [count]*const Blob = undefined;
    var commitments: [count]Commitment = undefined;
    var proofs: [count]Proof = undefined;
    for (0..count) |index| {
        random_blob(&prng, &blob_data[index]);
        blobs[index] = &blob_data[index];
        commitments[index] = try blob_to_kzg_commitment(settings, &test_workspace, blobs[index]);
        proofs[index] = try compute_blob_kzg_proof(
            settings,
            &test_workspace,
            blobs[index],
            &commitments[index],
        );
    }
    var storage: BatchStorage(count) = .{};
    const scratch = storage.scratch();
    const args = .{ settings, &test_workspace, scratch, &blobs, &commitments };
    try testing.expect(try @call(.auto, verify_blob_kzg_proof_batch, args ++ .{&proofs}));
    // Swapping two proofs leaves every point valid but every pairing wrong.
    std.mem.swap(Proof, &proofs[0], &proofs[2]);
    try testing.expect(!try @call(.auto, verify_blob_kzg_proof_batch, args ++ .{&proofs}));
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    const settings = try shared_settings();
    // Sparse blob: fuzz bytes at the start (non-canonical elements are reachable), zeros
    // after, so decoding and verification stay cheap.
    var blob: Blob = @splat(0);
    _ = smith.slice(blob[0..128]);
    var commitment: Commitment = undefined;
    var proof: Proof = undefined;
    smith.bytes(&commitment);
    smith.bytes(&proof);
    _ = verify_one(settings, &blob, &commitment, &proof) catch {};
    var z_bytes: FieldBytes = undefined;
    smith.bytes(&z_bytes);
    const z = Fr.from_bytes_be(&z_bytes) orelse return;
    var polynomial: [field_elements]Fr = undefined;
    blob_to_polynomial(&blob, &polynomial) catch return;
    _ = evaluate(settings, &polynomial, z);
}

test "blob: coverage-guided fuzz (never crashes)" {
    try testing.fuzz({}, fuzz_one, .{});
}

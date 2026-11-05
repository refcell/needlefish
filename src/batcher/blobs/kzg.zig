//! KZG prover for EIP-4844 blobs: `blob_to_kzg_commitment` and
//! `compute_blob_kzg_proof` from the consensus-specs polynomial-commitments document.
//!
//! The setup's G1 points are in Lagrange form; permuted into the blob's bit-reversed
//! evaluation domain, a commitment is one MSM of the blob's field elements. The
//! proof is the MSM of the quotient (p(x) - y) / (x - z) in evaluation form, where
//! z is the Fiat-Shamir challenge and y = p(z) is found with the barycentric formula.
//! `Prover.init` decodes the setup and the roots of unity once (static allocation).

const std = @import("std");
const assert = std.debug.assert;
const kzg = @import("../../common/crypto/kzg/root.zig");
const bls = @import("../../common/crypto/bls12_381/root.zig");
const sha256 = @import("../../common/crypto/sha256.zig");

const Fr = bls.Fr;
const n = kzg.field_elements_per_blob;
const log2_n = 12;

pub const Blob = [kzg.bytes_per_blob]u8;
pub const Commitment = [kzg.bytes_per_commitment]u8;
pub const Proof = [kzg.bytes_per_proof]u8;

pub const versioned_hash = kzg.versioned_hash;
pub const versioned_hash_version = kzg.versioned_hash_version_kzg;

pub const fiat_shamir_domain = "FSBLOBVERIFY_V1_";
/// Generator of the multiplicative group of Fr used by the specs.
const primitive_root_of_unity = 7;

pub const Error = error{
    /// A blob word is not a canonical field element (>= BLS modulus).
    InvalidFieldElement,
    /// The challenge hit the evaluation domain (probability ~2^-243).
    ChallengeInDomain,
};

comptime {
    assert(1 << log2_n == n);
}

pub const Prover = struct {
    setup: []bls.G1Affine,
    /// Roots of unity in bit-reversed order (the blob evaluation domain).
    roots: []Fr,
    /// Scratch: polynomial, quotient scalars, and batch inversion space.
    polynomial: []Fr,
    scalars: []u256,
    scratch: []Fr,
    prefix: []Fr,

    pub fn init(allocator: std.mem.Allocator) !Prover {
        const setup = try allocator.alloc(bls.G1Affine, n);
        errdefer allocator.free(setup);
        for (setup, 0..) |*point, index| {
            // trusted_setup.txt lists the Lagrange points in natural order; like c-kzg's
            // loader, permute them into the blob's bit-reversed domain order. The
            // ceremony output is trusted, so the subgroup check is skipped.
            const source_index: u32 = @bitReverse(@as(u12, @intCast(index)));
            point.* = bls.g1.decompress_unchecked(kzg.setup_g1_lagrange(source_index)) catch
                unreachable; // The setup file is checked by its sha256 in crypto/kzg.
        }
        const roots = try allocator.alloc(Fr, n);
        errdefer allocator.free(roots);
        compute_roots_brp(roots);
        const polynomial = try allocator.alloc(Fr, n);
        errdefer allocator.free(polynomial);
        const scalars = try allocator.alloc(u256, n);
        errdefer allocator.free(scalars);
        const scratch = try allocator.alloc(Fr, n);
        errdefer allocator.free(scratch);
        const prefix = try allocator.alloc(Fr, n);
        return .{
            .setup = setup,
            .roots = roots,
            .polynomial = polynomial,
            .scalars = scalars,
            .scratch = scratch,
            .prefix = prefix,
        };
    }

    pub fn deinit(prover: *Prover, allocator: std.mem.Allocator) void {
        allocator.free(prover.setup);
        allocator.free(prover.roots);
        allocator.free(prover.polynomial);
        allocator.free(prover.scalars);
        allocator.free(prover.scratch);
        allocator.free(prover.prefix);
        prover.* = undefined;
    }

    pub fn commitment(prover: *Prover, blob: *const Blob) Error!Commitment {
        try prover.load_blob(blob);
        for (prover.polynomial, prover.scalars) |value, *scalar| scalar.* = value.to_int();
        const point = bls.msm.msm(bls.G1, prover.setup, prover.scalars);
        return bls.g1.compress(point.to_affine());
    }

    /// `compute_blob_kzg_proof(blob, commitment)`.
    pub fn blob_proof(
        prover: *Prover,
        blob: *const Blob,
        commitment_bytes: *const Commitment,
    ) Error!Proof {
        const z = challenge(blob, commitment_bytes);
        try prover.load_blob(blob);
        const y = try prover.evaluate(z);
        // Quotient q_i = (p_i - y) / (w_i - z); z is not in the domain (checked).
        for (prover.roots, prover.scratch) |root, *denominator| denominator.* = root.sub(z);
        batch_inverse(prover.scratch, prover.prefix);
        for (prover.polynomial, prover.scratch, prover.scalars) |value, inverse, *scalar| {
            scalar.* = value.sub(y).mul(inverse).to_int();
        }
        const point = bls.msm.msm(bls.G1, prover.setup, prover.scalars);
        return bls.g1.compress(point.to_affine());
    }

    fn load_blob(prover: *Prover, blob: *const Blob) Error!void {
        for (prover.polynomial, 0..) |*value, index| {
            const word = blob[index * 32 ..][0..32];
            value.* = Fr.from_bytes_be(word) orelse return error.InvalidFieldElement;
        }
    }

    /// Barycentric evaluation: p(z) = (z^n - 1) / n * sum(p_i * w_i / (z - w_i)).
    fn evaluate(prover: *Prover, z: Fr) Error!Fr {
        for (prover.roots, prover.scratch) |root, *denominator| {
            denominator.* = z.sub(root);
            if (denominator.is_zero()) return error.ChallengeInDomain;
        }
        batch_inverse(prover.scratch, prover.prefix);
        var sum = Fr.from_int(0);
        for (prover.polynomial, prover.roots, prover.scratch) |value, root, inverse| {
            sum = sum.add(value.mul(root).mul(inverse));
        }
        const n_inverse = Fr.from_int(n).inverse();
        return z.pow(n).sub(Fr.from_int(1)).mul(n_inverse).mul(sum);
    }
};

/// `compute_challenge`: sha256(domain || n as u128 BE || blob || commitment) mod r.
pub fn challenge(blob: *const Blob, commitment_bytes: *const Commitment) Fr {
    var hasher = sha256.Hasher.init();
    hasher.update(fiat_shamir_domain);
    var degree: [16]u8 = undefined;
    std.mem.writeInt(u128, &degree, n, .big);
    hasher.update(&degree);
    hasher.update(blob);
    hasher.update(commitment_bytes);
    const digest = hasher.final();
    const value = std.mem.readInt(u256, &digest, .big) % kzg.bls_modulus;
    return Fr.from_int(value);
}

fn compute_roots_brp(roots: []Fr) void {
    assert(roots.len == n);
    const exponent = (kzg.bls_modulus - 1) / n;
    const root = Fr.from_int(primitive_root_of_unity).pow(exponent);
    var power = Fr.from_int(1);
    for (0..n) |index| {
        const reversed = @bitReverse(@as(u12, @intCast(index)));
        roots[reversed] = power;
        power = power.mul(root);
    }
    assert(power.eql(Fr.from_int(1))); // root has order exactly dividing n.
}

/// In-place Montgomery batch inversion; `prefix` is scratch of the same length.
/// Every input must be nonzero.
fn batch_inverse(values: []Fr, prefix: []Fr) void {
    assert(values.len == prefix.len);
    var running = Fr.from_int(1);
    for (values, prefix) |value, *product| {
        assert(!value.is_zero());
        product.* = running;
        running = running.mul(value);
    }
    var inverse = running.inverse();
    var index = values.len;
    while (index > 0) {
        index -= 1;
        const value = values[index];
        values[index] = inverse.mul(prefix[index]);
        inverse = inverse.mul(value);
    }
}

const testing = std.testing;
const verify = @import("../../common/crypto/kzg/verify.zig");

test "kzg prover: commitment and proof verify against the setup's G2 points" {
    var prover = try Prover.init(testing.allocator);
    defer prover.deinit(testing.allocator);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    var prng = @import("../../testing/prng.zig").Prng.init(0x4844);
    for (0..n) |index| {
        // Random canonical field elements: top byte zero keeps them below r.
        prng.fill(blob[index * 32 + 1 ..][0..31]);
    }
    const commitment_bytes = try prover.commitment(blob);
    const proof = try prover.blob_proof(blob, &commitment_bytes);
    const z = challenge(blob, &commitment_bytes);
    try prover.load_blob(blob);
    const y = try prover.evaluate(z);
    const z_bytes = z.to_bytes_be();
    const y_bytes = y.to_bytes_be();
    try testing.expect(try verify.verify_kzg_proof(&commitment_bytes, &z_bytes, &y_bytes, &proof));
    // A different claimed value must not verify.
    const wrong_y = y.add(Fr.from_int(1)).to_bytes_be();
    try testing.expect(!try verify.verify_kzg_proof(&commitment_bytes, &z_bytes, &wrong_y, &proof));
}

test "kzg prover: zero blob commits to infinity; non-canonical words rejected" {
    var prover = try Prover.init(testing.allocator);
    defer prover.deinit(testing.allocator);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    const commitment_bytes = try prover.commitment(blob);
    try testing.expectEqual(@as(u8, 0xc0), commitment_bytes[0]);
    for (commitment_bytes[1..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    @memset(blob[0..32], 0xff);
    try testing.expectError(error.InvalidFieldElement, prover.commitment(blob));
}

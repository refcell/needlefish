//! KZG commitments over BLS12-381 for EIP-4844 blobs.
//!
//! Holds the public Ethereum KZG ceremony output (the c-kzg-4844
//! `trusted_setup.txt`: 4096 G1 points in Lagrange form, 65 G2 points in monomial
//! form, and 4096 G1 points in monomial form for EIP-7594 cells, compressed) and the
//! input framing of the point evaluation precompile (address 0x0A). Proof verification
//! lives in `verify.zig`, the blob API in `blob.zig`, and EIP-7594 cells in `cells.zig`.

const std = @import("std");
const assert = std.debug.assert;
const sha256 = @import("../sha256.zig");

pub const field_elements_per_blob = 4096;
pub const bytes_per_field_element = 32;
pub const bytes_per_blob = field_elements_per_blob * bytes_per_field_element;
pub const bytes_per_commitment = 48;
pub const bytes_per_proof = 48;
pub const bytes_per_g2 = 96;
pub const g2_points_count = 65;

/// Order of the BLS12-381 scalar field.
pub const bls_modulus: u256 =
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

/// Version byte of a blob versioned hash (EIP-4844 `VERSIONED_HASH_VERSION_KZG`).
pub const versioned_hash_version_kzg: u8 = 0x01;

/// The compressed setup in `trusted_setup.txt` order: G1 Lagrange points, G2 monomial
/// points, then G1 monomial points.
/// sha256 of this file: 608ac720ba55fc77f65d155391020fc5b0501db266a3e360e734d6c0db0dfae3.
const trusted_setup_bytes = @embedFile("trusted_setup.bin");
const g1_monomial_offset =
    field_elements_per_blob * bytes_per_commitment + g2_points_count * bytes_per_g2;

comptime {
    assert(trusted_setup_bytes.len ==
        g1_monomial_offset + field_elements_per_blob * bytes_per_commitment);
    assert(bytes_per_blob == 131072);
}

/// Compressed G1 point `index` of the setup in Lagrange form.
pub fn setup_g1_lagrange(index: u32) *const [bytes_per_commitment]u8 {
    assert(index < field_elements_per_blob);
    const offset = @as(usize, index) * bytes_per_commitment;
    return trusted_setup_bytes[offset..][0..bytes_per_commitment];
}

/// Compressed G2 point `index` of the setup in monomial form ([tau^index]_2).
pub fn setup_g2_monomial(index: u32) *const [bytes_per_g2]u8 {
    assert(index < g2_points_count);
    const base = field_elements_per_blob * bytes_per_commitment;
    const offset = base + @as(usize, index) * bytes_per_g2;
    return trusted_setup_bytes[offset..][0..bytes_per_g2];
}

/// Compressed G1 point `index` of the setup in monomial form ([tau^index]_1).
pub fn setup_g1_monomial(index: u32) *const [bytes_per_commitment]u8 {
    assert(index < field_elements_per_blob);
    const offset = g1_monomial_offset + @as(usize, index) * bytes_per_commitment;
    assert(offset + bytes_per_commitment <= trusted_setup_bytes.len);
    return trusted_setup_bytes[offset..][0..bytes_per_commitment];
}

/// `kzg_to_versioned_hash`: sha256(commitment) with the first byte replaced.
pub fn versioned_hash(commitment: *const [bytes_per_commitment]u8) [32]u8 {
    var digest = sha256.sha256(commitment);
    digest[0] = versioned_hash_version_kzg;
    assert(digest[0] == versioned_hash_version_kzg);
    return digest;
}

pub const input_length = 192;

pub const PointEvaluationInput = struct {
    versioned_hash: [32]u8,
    z: [32]u8,
    y: [32]u8,
    commitment: [bytes_per_commitment]u8,
    proof: [bytes_per_proof]u8,
};

pub const PrecompileError = error{
    InvalidInputLength,
    MismatchedVersionedHash,
    InvalidFieldElement,
    VerificationFailed,
};

/// Splits and validates the framing of the 0x0A input (length, versioned hash, and
/// canonical field elements); leaves curve point validation to the verifier.
pub fn parse_input(input: []const u8) PrecompileError!PointEvaluationInput {
    if (input.len != input_length) return error.InvalidInputLength;
    var parsed: PointEvaluationInput = undefined;
    @memcpy(&parsed.versioned_hash, input[0..32]);
    @memcpy(&parsed.z, input[32..64]);
    @memcpy(&parsed.y, input[64..96]);
    @memcpy(&parsed.commitment, input[96..144]);
    @memcpy(&parsed.proof, input[144..192]);
    const expected = versioned_hash(&parsed.commitment);
    if (!std.mem.eql(u8, &expected, &parsed.versioned_hash)) {
        return error.MismatchedVersionedHash;
    }
    if (std.mem.readInt(u256, &parsed.z, .big) >= bls_modulus) return error.InvalidFieldElement;
    if (std.mem.readInt(u256, &parsed.y, .big) >= bls_modulus) return error.InvalidFieldElement;
    return parsed;
}

/// Output on success: FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as 32-byte big-endian.
pub const success_output: [64]u8 = blk: {
    var out: [64]u8 = undefined;
    std.mem.writeInt(u256, out[0..32], field_elements_per_blob, .big);
    std.mem.writeInt(u256, out[32..64], bls_modulus, .big);
    break :blk out;
};

pub const verify = @import("verify.zig");
pub const verify_kzg_proof = verify.verify_kzg_proof;
pub const blob = @import("blob.zig");
pub const fft = @import("fft.zig");
pub const bench = @import("bench.zig");
pub const precompile_point_evaluation = verify.precompile_point_evaluation;

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
const Prng = @import("../../../testing/prng.zig").Prng;
const bls_g1 = @import("../bls12_381/g1.zig");

test "kzg: trusted setup layout" {
    // Compressed points have the compression flag (top bit) set and are never infinity
    // in the setup (infinity flag is bit 6).
    for (0..field_elements_per_blob) |index| {
        const point = setup_g1_lagrange(@intCast(index));
        try testing.expect(point[0] & 0x80 != 0);
        try testing.expect(point[0] & 0x40 == 0);
        const monomial = setup_g1_monomial(@intCast(index));
        try testing.expect(monomial[0] & 0x80 != 0);
        try testing.expect(monomial[0] & 0x40 == 0);
    }
    // G1 monomial point 0 is [1]G1, the standard generator.
    try testing.expectEqualSlices(
        u8,
        &bls_g1.compress(bls_g1.generator),
        setup_g1_monomial(0),
    );
    // G2 point 0 is the standard G2 generator, compressed.
    const g2_generator_prefix = [_]u8{ 0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60 };
    try testing.expectEqualSlices(u8, &g2_generator_prefix, setup_g2_monomial(0)[0..8]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(trusted_setup_bytes, &digest, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "608ac720ba55fc77f65d155391020fc5b0501db266a3e360e734d6c0db0dfae3",
    );
    try testing.expectEqual(expected, digest);
}

test "kzg: monomial G1 points agree with the Lagrange and G2 setup" {
    // sum_i L_i(tau) = 1, so the Lagrange points sum to [1]G1 = monomial point 0.
    var sum = bls_g1.G1.identity;
    for (0..field_elements_per_blob) |index| {
        const point = try bls_g1.decompress_unchecked(setup_g1_lagrange(@intCast(index)));
        sum = sum.add_affine(point);
    }
    const first = try bls_g1.decompress_unchecked(setup_g1_monomial(0));
    try testing.expect(sum.eql(first.to_jacobian()));
    // e([tau^(i+1)]G1, G2) = e([tau^i]G1, [tau]G2) for a few consecutive points.
    const bls = @import("../bls12_381/root.zig");
    const tau_g2 = try bls.g2.decompress(setup_g2_monomial(1));
    for ([_]u32{ 0, 63, 4094 }) |index| {
        const low = try bls_g1.decompress(setup_g1_monomial(index));
        const high = try bls_g1.decompress(setup_g1_monomial(index + 1));
        const pairs = [2]bls.pairing.Pair{
            .{ .g1 = high, .g2 = bls.g2.generator },
            .{ .g1 = low.neg(), .g2 = tau_g2 },
        };
        try testing.expect(bls.pairing.pairing_check(&pairs));
    }
}

test "kzg: success output encodes blob size and modulus" {
    try testing.expectEqual(@as(u256, 4096), std.mem.readInt(u256, success_output[0..32], .big));
    try testing.expectEqual(bls_modulus, std.mem.readInt(u256, success_output[32..64], .big));
}

fn build_input(prng: *Prng, out: *[input_length]u8) void {
    prng.fill(out);
    const commitment = out[96..144];
    const hash = versioned_hash(commitment);
    @memcpy(out[0..32], &hash);
    // Keep z and y canonical by clearing their top bits.
    out[32] &= 0x3f;
    out[64] &= 0x3f;
}

test "kzg: precompile framing (seeded)" {
    var prng = Prng.init(0x4844);
    var input: [input_length]u8 = undefined;
    for (0..200) |_| {
        build_input(&prng, &input);
        const parsed = try parse_input(&input);
        try testing.expectEqualSlices(u8, input[96..144], &parsed.commitment);
        try testing.expectError(error.InvalidInputLength, parse_input(input[0..191]));

        var bad_hash = input;
        bad_hash[0] = 0x02;
        try testing.expectError(error.MismatchedVersionedHash, parse_input(&bad_hash));

        var bad_z = input;
        std.mem.writeInt(u256, bad_z[32..64], bls_modulus, .big);
        try testing.expectError(error.InvalidFieldElement, parse_input(&bad_z));
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    const length = smith.slice(&buffer);
    const result = parse_input(buffer[0..length]);
    if (length != input_length) try testing.expect(std.meta.isError(result));
}

test "kzg: coverage-guided fuzz of framing" {
    try testing.fuzz({}, fuzz_one, .{});
}

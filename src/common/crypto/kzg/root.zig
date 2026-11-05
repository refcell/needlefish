//! KZG commitments over BLS12-381 for EIP-4844 blobs.
//!
//! Holds the public Ethereum KZG ceremony output (the c-kzg-4844
//! `trusted_setup.txt`: 4096 G1 points in Lagrange form and 65 G2 points in
//! monomial form, compressed) and the input framing of the point evaluation
//! precompile (address 0x0A). The pairing check itself lives with the BLS12-381
//! code and plugs in through `precompile_point_evaluation`.

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

/// The compressed setup, laid out as G1 Lagrange points then G2 monomial points.
/// sha256 of this file: 2721e57b4a7ec42d5a1c0a29ab1b14419f1f1008bd159b538c332ed923886a7e.
const trusted_setup_bytes = @embedFile("trusted_setup.bin");

comptime {
    assert(trusted_setup_bytes.len ==
        field_elements_per_blob * bytes_per_commitment + g2_points_count * bytes_per_g2);
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

/// Point evaluation precompile with the proof check injected:
/// `verify(commitment, z, y, proof)` must return true iff the KZG proof is valid
/// and both points decode to G1 subgroup elements.
pub fn precompile_point_evaluation(
    input: []const u8,
    comptime verify: fn (
        commitment: *const [bytes_per_commitment]u8,
        z: *const [32]u8,
        y: *const [32]u8,
        proof: *const [bytes_per_proof]u8,
    ) bool,
) PrecompileError![64]u8 {
    const parsed = try parse_input(input);
    if (!verify(&parsed.commitment, &parsed.z, &parsed.y, &parsed.proof)) {
        return error.VerificationFailed;
    }
    return success_output;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "kzg: trusted setup layout" {
    // Compressed points have the compression flag (top bit) set and are never infinity
    // in the setup (infinity flag is bit 6).
    for (0..field_elements_per_blob) |index| {
        const point = setup_g1_lagrange(@intCast(index));
        try testing.expect(point[0] & 0x80 != 0);
        try testing.expect(point[0] & 0x40 == 0);
    }
    // G2 point 0 is the standard G2 generator, compressed.
    const g2_generator_prefix = [_]u8{ 0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60 };
    try testing.expectEqualSlices(u8, &g2_generator_prefix, setup_g2_monomial(0)[0..8]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(trusted_setup_bytes, &digest, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "2721e57b4a7ec42d5a1c0a29ab1b14419f1f1008bd159b538c332ed923886a7e",
    );
    try testing.expectEqual(expected, digest);
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

fn reject_all(
    _: *const [bytes_per_commitment]u8,
    _: *const [32]u8,
    _: *const [32]u8,
    _: *const [bytes_per_proof]u8,
) bool {
    return false;
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    const length = smith.slice(&buffer);
    const result = precompile_point_evaluation(buffer[0..length], reject_all);
    try testing.expect(std.meta.isError(result));
}

test "kzg: coverage-guided fuzz of framing" {
    try testing.fuzz({}, fuzz_one, .{});
}

//! KZG proof verification (EIP-4844 `verify_kzg_proof`) and the point evaluation
//! precompile (address 0x0A).
//!
//! Checks e(C - [y]G1, G2) * e(-proof, [tau]G2 - [z]G2) == 1, the same equation as
//! c-kzg-4844 `verify_kzg_proof_impl`, with one shared final exponentiation.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const setup = @import("root.zig");

pub const VerifyError = error{ InvalidPoint, InvalidFieldElement };

/// [tau]G2 from the trusted setup (G2 monomial point 1), decoded ahead of time so
/// verification skips an Fp2 square root. A test checks it against the setup bytes.
const tau_g2: bls.G2Affine = .{
    .x = bls.Fp2.from_ints_comptime(
        0x185cbfee53492714734429b7b38608e23926c911cceceac9 << 192 |
            0xa36851477ba4c60b087041de621000edc98edada20c1def2,
        0x15bfd7dd8cdeb128843bc287230af38926187075cbfbefa8 << 192 |
            0x1009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72,
    ),
    .y = bls.Fp2.from_ints_comptime(
        0x014353bdb96b626dd7d5ee8599d1fca2131569490e28de18 << 192 |
            0xe82451a496a9c9794ce26d105941f383ee689bfbbb832a99,
        0x1666c54b0a32529503432fcae0181b4bef79de09fc63671f << 192 |
            0xda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f,
    ),
    .infinity = false,
};

fn read_scalar(bytes: *const [32]u8) VerifyError!u256 {
    const value = std.mem.readInt(u256, bytes, .big);
    if (value >= setup.bls_modulus) return error.InvalidFieldElement;
    return value;
}

/// True when `proof` proves that the polynomial committed to by `commitment`
/// evaluates to `y` at `z`. Errors for undecodable points or non-canonical scalars.
pub fn verify_kzg_proof(
    commitment_bytes: *const [setup.bytes_per_commitment]u8,
    z_bytes: *const [32]u8,
    y_bytes: *const [32]u8,
    proof_bytes: *const [setup.bytes_per_proof]u8,
) VerifyError!bool {
    const commitment = bls.g1.decompress(commitment_bytes) catch return error.InvalidPoint;
    const proof = bls.g1.decompress(proof_bytes) catch return error.InvalidPoint;
    const z = try read_scalar(z_bytes);
    const y = try read_scalar(y_bytes);

    return verify_kzg_proof_points(commitment, z, y, proof);
}

/// `verify_kzg_proof` on decoded points and canonical scalars (z, y < r).
pub fn verify_kzg_proof_points(
    commitment: bls.G1Affine,
    z: u256,
    y: u256,
    proof: bls.G1Affine,
) bool {
    assert(z < setup.bls_modulus and y < setup.bls_modulus);
    // e(C - [y]G1, G2) * e(-proof, [tau - z]G2) == 1 is rewritten with
    // e(proof, [z]G2) = e([z]proof, G2) so both G2 inputs are fixed and only G1
    // scalar multiplications remain: e(C - [y]G1 + [z]proof, G2) * e(-proof, [tau]G2).
    const g1_generator = bls.g1.generator.to_jacobian();
    const left = commitment.to_jacobian()
        .sub(bls.g1.mul_glv(g1_generator, y))
        .add(bls.g1.mul_glv(proof.to_jacobian(), z))
        .to_affine();
    return pairing_check_fixed_g2(left, proof);
}

/// Miller loop lines of the two fixed G2 points, computed at compile time.
const prepared_generator: bls.pairing.PreparedG2 = blk: {
    @setEvalBranchQuota(100_000_000);
    break :blk bls.pairing.prepare(bls.g2.generator);
};
const prepared_tau: bls.pairing.PreparedG2 = blk: {
    @setEvalBranchQuota(100_000_000);
    break :blk bls.pairing.prepare(tau_g2);
};

/// True when e(left, G2) * e(-proof, [tau]G2) == 1 (the shared form of every KZG check).
pub fn pairing_check_fixed_g2(left: bls.G1Affine, proof: bls.G1Affine) bool {
    const pairs = [2]bls.pairing.PreparedPair{
        .{ .g1 = left, .g2 = &prepared_generator },
        .{ .g1 = proof.neg(), .g2 = &prepared_tau },
    };
    assert(pairs[0].g1.is_on_curve() and pairs[1].g1.is_on_curve());
    return bls.pairing.pairing_check_prepared(&pairs);
}

/// The 0x0A precompile: 192-byte input, versioned hash match, valid proof.
/// Every failure is an error (the EVM consumes all gas); success returns
/// FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS.
pub fn precompile_point_evaluation(input: []const u8) setup.PrecompileError![64]u8 {
    const parsed = try setup.parse_input(input);
    const valid = verify_kzg_proof(&parsed.commitment, &parsed.z, &parsed.y, &parsed.proof) catch
        return error.VerificationFailed;
    if (!valid) return error.VerificationFailed;
    return setup.success_output;
}

const testing = std.testing;

test "kzg verify: comptime prepared lines match runtime preparation" {
    const runtime_generator = bls.pairing.prepare(bls.g2.generator);
    const runtime_tau = bls.pairing.prepare(tau_g2);
    for (runtime_generator.lines, prepared_generator.lines) |a, b| {
        for (a, b) |x, y| try testing.expect(x.eql(y));
    }
    for (runtime_tau.lines, prepared_tau.lines) |a, b| {
        for (a, b) |x, y| try testing.expect(x.eql(y));
    }
}

test "kzg verify: setup [tau]G2 is a valid G2 subgroup point" {
    const point = try bls.g2.decompress(setup.setup_g2_monomial(1));
    try testing.expect(point.eql(tau_g2));
    try testing.expect(tau_g2.is_on_curve());
    try testing.expect(bls.g2.is_in_subgroup(tau_g2));
    const generator = try bls.g2.decompress(setup.setup_g2_monomial(0));
    try testing.expect(generator.eql(bls.g2.generator));
}

fn parse_hex(comptime length: usize, hex: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if (hex.len != 2 * length) return error.BadVector;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

test "kzg verify: c-kzg-4844 verify_kzg_proof vectors" {
    // Format per line: expected (1 valid, 0 invalid, E error) commitment z y proof.
    const vectors = @embedFile("verify_kzg_proof_vectors.txt");
    var lines = std.mem.tokenizeScalar(u8, vectors, '\n');
    var count: u32 = 0;
    while (lines.next()) |line| : (count += 1) {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const expected = fields.next().?;
        const commitment = try parse_hex(48, fields.next().?);
        const z = try parse_hex(32, fields.next().?);
        const y = try parse_hex(32, fields.next().?);
        const proof = try parse_hex(48, fields.next().?);
        const result = verify_kzg_proof(&commitment, &z, &y, &proof);
        switch (expected[0]) {
            '1' => try testing.expect(try result),
            '0' => try testing.expect(!(try result)),
            'E' => try testing.expect(std.meta.isError(result)),
            else => return error.BadVector,
        }
    }
    try testing.expect(count >= 100);
}

test "kzg verify: go-ethereum pointEvaluation precompile vector" {
    const input = try parse_hex(192, "01e798154708fe7789429634053cbf9f99b619f9f08404892733" ++
        "3fce637f" ++
        "549b564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d3630624d25032e67a7e6a" ++
        "4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a18f59a8d2a1a625a17f3fea0fe5eb8c896db3" ++
        "764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7873033e038326e87ed3e1276" ++
        "fd140253fa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a");
    const output = try precompile_point_evaluation(&input);
    try testing.expectEqual(setup.success_output, output);
    var tampered = input;
    tampered[191] ^= 1;
    try testing.expect(std.meta.isError(precompile_point_evaluation(&tampered)));
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [setup.input_length]u8 = undefined;
    smith.bytes(&buffer);
    // Make the versioned hash match so the fuzzer reaches point decoding.
    const hash = setup.versioned_hash(buffer[96..144]);
    @memcpy(buffer[0..32], &hash);
    _ = precompile_point_evaluation(&buffer) catch {};
}

test "kzg verify: coverage-guided fuzz (never crashes)" {
    try testing.fuzz({}, fuzz_one, .{});
}

//! EIP-196 / EIP-197 precompile semantics (0x06 ECADD, 0x07 ECMUL, 0x08 pairing),
//! matching revm and the base/base precompile set. Gas accounting lives in the
//! evm lane; these functions only map input bytes to output bytes or an error.
//!
//! Encoding: field elements are 32-byte big-endian and must be < p. The point at
//! infinity is all zeros. G2 coordinates are ordered (x.c1, x.c0, y.c1, y.c0).

const std = @import("std");
const assert = std.debug.assert;
const fp = @import("fp.zig");
const Fp = fp.Fp;
const Fp2 = @import("fp2.zig").Fp2;
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const pairing = @import("pairing.zig");
const G1 = g1.G1;
const G1Affine = g1.G1Affine;
const G2Affine = g2.G2Affine;

pub const Error = error{
    /// A coordinate is >= p.
    InvalidFieldElement,
    PointNotOnCurve,
    /// A G2 point is on the twist but not in the order-r subgroup.
    PointNotInSubgroup,
    /// Pairing input length is not a multiple of 192.
    InvalidPairingLength,
};

pub const add_input_length = 128;
pub const mul_input_length = 96;
pub const pairing_pair_length = 192;
const g1_length = 64;
const g2_length = 128;

fn read_fp(bytes: *const [32]u8) Error!Fp {
    return Fp.from_bytes_be(bytes) orelse error.InvalidFieldElement;
}

pub fn decode_g1(bytes: *const [g1_length]u8) Error!G1Affine {
    const x = try read_fp(bytes[0..32]);
    const y = try read_fp(bytes[32..64]);
    if (x.is_zero() and y.is_zero()) return G1Affine.infinity_affine;
    assert(!x.is_zero() or !y.is_zero());
    const point: G1Affine = .{ .x = x, .y = y, .is_infinity = false };
    if (!point.is_on_curve()) return error.PointNotOnCurve;
    assert(!point.is_infinity);
    return point;
}

/// Decodes a G2 point and enforces the subgroup check required by EIP-197.
pub fn decode_g2(bytes: *const [g2_length]u8) Error!G2Affine {
    const x: Fp2 = .{ .c1 = try read_fp(bytes[0..32]), .c0 = try read_fp(bytes[32..64]) };
    const y: Fp2 = .{ .c1 = try read_fp(bytes[64..96]), .c0 = try read_fp(bytes[96..128]) };
    if (x.is_zero() and y.is_zero()) return G2Affine.infinity_affine;
    const point: G2Affine = .{ .x = x, .y = y, .is_infinity = false };
    if (!point.is_on_curve()) return error.PointNotOnCurve;
    if (!g2.is_in_subgroup(point)) return error.PointNotInSubgroup;
    assert(!point.is_infinity);
    return point;
}

pub fn encode_g1(point: G1) [g1_length]u8 {
    var out: [g1_length]u8 = @splat(0);
    const affine = point.to_affine();
    if (affine.is_infinity) return out;
    assert(affine.is_on_curve());
    out[0..32].* = affine.x.to_bytes_be();
    out[32..64].* = affine.y.to_bytes_be();
    return out;
}

/// Copies `input` into a zero-filled fixed buffer (right-pad or truncate).
fn right_pad(comptime length: usize, input: []const u8) [length]u8 {
    var out: [length]u8 = @splat(0);
    const used = @min(length, input.len);
    @memcpy(out[0..used], input[0..used]);
    assert(used <= length);
    return out;
}

/// 0x06: P1 + P2. Input is right-padded or truncated to 128 bytes.
pub fn precompile_bn254_add(input: []const u8) Error![64]u8 {
    const padded = right_pad(add_input_length, input);
    const a = try decode_g1(padded[0..64]);
    const b = try decode_g1(padded[64..128]);
    const sum = G1.from_affine(a).add_affine(b);
    assert(sum.is_on_curve());
    return encode_g1(sum);
}

/// 0x07: scalar * P. The 256-bit scalar is used as is (never rejected).
pub fn precompile_bn254_mul(input: []const u8) Error![64]u8 {
    const padded = right_pad(mul_input_length, input);
    const point = try decode_g1(padded[0..64]);
    const scalar = std.mem.readInt(u256, padded[64..96], .big);
    // Every point on G1 has order r (cofactor 1), so reducing the scalar is exact.
    const product = g1.mul(G1.from_affine(point), scalar);
    assert(product.is_on_curve());
    assert(!point.is_infinity or product.is_infinity());
    return encode_g1(product);
}

/// 0x08: returns 32-byte 1 when prod e(P_i, Q_i) = 1 (also for empty input), else 0.
pub fn precompile_bn254_pairing(input: []const u8) Error![32]u8 {
    if (input.len % pairing_pair_length != 0) return error.InvalidPairingLength;
    var checker: pairing.Checker = .{};
    var offset: usize = 0;
    while (offset < input.len) : (offset += pairing_pair_length) {
        const pair = input[offset..][0..pairing_pair_length];
        const p = try decode_g1(pair[0..g1_length]);
        const q = try decode_g2(pair[g1_length..pairing_pair_length]);
        checker.push(p, q);
    }
    assert(offset == input.len);
    var out: [32]u8 = @splat(0);
    out[31] = @intFromBool(checker.finish());
    return out;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const vectors = @import("vectors.zig");

fn decode_hex(comptime hex: []const u8, buffer: []u8) []u8 {
    assert(hex.len % 2 == 0);
    return std.fmt.hexToBytes(buffer, hex) catch unreachable; // Committed vectors are valid hex.
}

test "precompile: official bn256Add vectors" {
    inline for (vectors.add) |vector| {
        var input_buffer: [vector.input.len / 2]u8 = undefined;
        var expected: [64]u8 = undefined;
        const input = decode_hex(vector.input, &input_buffer);
        _ = decode_hex(vector.expected, &expected);
        try testing.expectEqualSlices(u8, &expected, &try precompile_bn254_add(input));
    }
}

test "precompile: official bn256ScalarMul vectors" {
    inline for (vectors.mul) |vector| {
        var input_buffer: [vector.input.len / 2]u8 = undefined;
        var expected: [64]u8 = undefined;
        const input = decode_hex(vector.input, &input_buffer);
        _ = decode_hex(vector.expected, &expected);
        try testing.expectEqualSlices(u8, &expected, &try precompile_bn254_mul(input));
    }
}

test "precompile: official bn256Pairing vectors" {
    inline for (vectors.pairing) |vector| {
        var input_buffer: [vector.input.len / 2]u8 = undefined;
        var expected: [32]u8 = undefined;
        const input = decode_hex(vector.input, &input_buffer);
        _ = decode_hex(vector.expected, &expected);
        try testing.expectEqualSlices(u8, &expected, &try precompile_bn254_pairing(input));
    }
}

test "precompile: rejects invalid inputs" {
    var input: [pairing_pair_length]u8 = @splat(0);
    // Coordinate equal to p.
    std.mem.writeInt(u256, input[0..32], fp.p, .big);
    try testing.expectError(error.InvalidFieldElement, precompile_bn254_add(input[0..128]));
    try testing.expectError(error.InvalidFieldElement, precompile_bn254_mul(input[0..96]));
    // (1, 3) is not on y^2 = x^3 + 3.
    std.mem.writeInt(u256, input[0..32], 1, .big);
    std.mem.writeInt(u256, input[32..64], 3, .big);
    try testing.expectError(error.PointNotOnCurve, precompile_bn254_add(input[0..128]));
    try testing.expectError(error.PointNotOnCurve, precompile_bn254_mul(input[0..96]));
    try testing.expectError(error.PointNotOnCurve, precompile_bn254_pairing(&input));
    // G1 generator with an on-twist G2 point outside the subgroup (x = 1).
    std.mem.writeInt(u256, input[32..64], 2, .big);
    std.mem.writeInt(u256, input[96..128], 1, .big);
    const y_c0 = 0x2869111d5381f072f8e2728fdb825a51aadd70e52c9830e9ab4b871c0531f1bb;
    const y_c1 = 0x0d1271953ed9ea0836846e70a1934187998c7f790cb4d7511b7f8da82de048a4;
    std.mem.writeInt(u256, input[128..160], y_c1, .big);
    std.mem.writeInt(u256, input[160..192], y_c0, .big);
    try testing.expectError(error.PointNotInSubgroup, precompile_bn254_pairing(&input));
    try testing.expectError(error.InvalidPairingLength, precompile_bn254_pairing(input[0..191]));
    // Infinity pairs are skipped; empty input is true.
    const zeros: [pairing_pair_length]u8 = @splat(0);
    try testing.expectEqual(@as(u8, 1), (try precompile_bn254_pairing(&zeros))[31]);
    try testing.expectEqual(@as(u8, 1), (try precompile_bn254_pairing(""))[31]);
}

test "precompile: short inputs are right-padded with zeros" {
    // Generator alone (infinity second operand) via a 64-byte add input.
    var generator_bytes: [64]u8 = @splat(0);
    generator_bytes[31] = 1;
    generator_bytes[63] = 2;
    const doubled_input = try precompile_bn254_add(&generator_bytes);
    try testing.expectEqualSlices(u8, &generator_bytes, &doubled_input);
    // Missing scalar means scalar 0, giving infinity.
    const zero_point: [64]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zero_point, &try precompile_bn254_mul(&generator_bytes));
    try testing.expectEqualSlices(u8, &zero_point, &try precompile_bn254_add(""));
}

test "precompile: seeded fuzz never crashes and is consistent" {
    var prng = Prng.init(0xb254);
    var buffer: [pairing_pair_length * 2]u8 = undefined;
    for (0..200) |_| {
        const length: usize = @intCast(prng.below(buffer.len + 1));
        prng.fill(buffer[0..length]);
        // Bias toward valid encodings: small coordinates and real points.
        if (prng.chance(1, 2)) @memset(buffer[0..@min(length, 16)], 0);
        _ = precompile_bn254_add(buffer[0..length]) catch {};
        _ = precompile_bn254_mul(buffer[0..length]) catch {};
        if (length <= pairing_pair_length) {
            _ = precompile_bn254_pairing(buffer[0..length]) catch {};
        }
    }
    // mul by 2 equals add to itself for random multiples of the generator.
    for (0..20) |_| {
        var mul_input: [96]u8 = @splat(0);
        mul_input[31] = 1;
        mul_input[63] = 2;
        std.mem.writeInt(u256, mul_input[64..96], prng.int(u256), .big);
        const point = try precompile_bn254_mul(&mul_input);
        var add_input: [128]u8 = undefined;
        add_input[0..64].* = point;
        add_input[64..128].* = point;
        @memcpy(mul_input[0..64], &point);
        std.mem.writeInt(u256, mul_input[64..96], 2, .big);
        const doubled = try precompile_bn254_mul(&mul_input);
        try testing.expectEqualSlices(u8, &doubled, &try precompile_bn254_add(&add_input));
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [pairing_pair_length * 2]u8 = undefined;
    const length = smith.slice(&buffer);
    const data = buffer[0..length];
    _ = precompile_bn254_add(data) catch {};
    _ = precompile_bn254_mul(data) catch {};
    _ = precompile_bn254_pairing(data) catch {};
}

test "bn254 precompile: coverage-guided fuzz never crashes" {
    try testing.fuzz({}, fuzz_one, .{});
}

fn reduce_r(value: u512) u256 {
    return @intCast(value % fp.r);
}

/// [scalar]G1 by plain double-and-add, independent of the GLV path behind 0x07.
fn generator_multiple(scalar: u256) [g1_length]u8 {
    return encode_g1(G1.from_affine(g1.generator).mul_reference(scalar));
}

fn encode_g2(point: G2Affine) [g2_length]u8 {
    var out: [g2_length]u8 = @splat(0);
    if (point.is_infinity) return out;
    out[0..32].* = point.x.c1.to_bytes_be();
    out[32..64].* = point.x.c0.to_bytes_be();
    out[64..96].* = point.y.c1.to_bytes_be();
    out[96..128].* = point.y.c0.to_bytes_be();
    return out;
}

/// Valid points from fuzzed scalars: checks add, mul, and pairing against group laws.
fn fuzz_algebra(_: void, smith: *testing.Smith) anyerror!void {
    const a = smith.value(u256);
    const b = smith.value(u256);
    const c = smith.value(u256);
    const a_reduced = reduce_r(a);
    const point_a = generator_multiple(a);
    const point_b = generator_multiple(b);
    const sum = try precompile_bn254_add(&(point_a ++ point_b));
    const expected_sum = generator_multiple(reduce_r(@as(u512, a_reduced) + reduce_r(b)));
    try testing.expectEqualSlices(u8, &expected_sum, &sum);
    var scalar_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &scalar_bytes, c, .big);
    const product = try precompile_bn254_mul(&(point_a ++ scalar_bytes));
    const expected_product = generator_multiple(reduce_r(@as(u512, a_reduced) * c));
    try testing.expectEqualSlices(u8, &expected_product, &product);
    // e(aG, Q) e(-aG, Q) = 1; a single pair is 1 only if aG or Q is the identity.
    const q = encode_g2(g2.G2.from_affine(g2.generator).mul(b).to_affine());
    const negated = generator_multiple(if (a_reduced == 0) 0 else fp.r - a_reduced);
    const balanced = try precompile_bn254_pairing(&(point_a ++ q ++ negated ++ q));
    try testing.expectEqual(@as(u8, 1), balanced[31]);
    const single = try precompile_bn254_pairing(&(point_a ++ q));
    const trivial = a_reduced == 0 or reduce_r(b) == 0;
    try testing.expectEqual(@as(u8, @intFromBool(trivial)), single[31]);
}

test "bn254 precompile: coverage-guided fuzz of add, mul, pairing vs group laws" {
    try testing.fuzz({}, fuzz_algebra, .{});
}

test "bn254 precompile: group laws on seeded random scalars" {
    var prng = Prng.init(0x6c617773);
    var input: [96]u8 = undefined;
    for (0..3) |_| {
        prng.fill(&input);
        var smith: testing.Smith = .{ .in = &input };
        try fuzz_algebra({}, &smith);
    }
}

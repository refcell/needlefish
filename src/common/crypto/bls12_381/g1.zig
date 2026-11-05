//! G1: the order-r subgroup of E(Fp): y^2 = x^3 + 4.
//!
//! Subgroup membership uses the GLV endomorphism phi(x, y) = (beta x, y), which
//! acts on G1 as multiplication by -x^2 (Scott, eprint 2021/1130 section 6, proof
//! corrected in eprint 2022/352). Cofactor clearing multiplies by h_eff = 1 - x
//! (RFC 9380 section 8.8.1). Compressed points follow the ZCash serialization.

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const curve = @import("curve.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const Fp = fields.Fp;

pub const G1 = curve.Curve(Fp, Fp.from_int_comptime(4));
pub const Affine = G1.Affine;

/// |x| for the BLS parameter x = -0xd201000000010000.
pub const x_abs: u64 = 0xd201000000010000;

pub const generator: Affine = .{
    .x = Fp.from_int_comptime(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905 << 192 |
        0xa14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
    .y = Fp.from_int_comptime(0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af6 << 192 |
        0x00db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1),
    .infinity = false,
};

/// A primitive cube root of unity in Fp, chosen so phi acts as -x^2 on G1.
const beta = Fp.from_int_comptime(0x5f19672fdf76ce51ba69c6076a0f77ea << 192 |
    0xddb3a93be6f89688de17d813620a00022e01fffffffefffe);

pub const compressed_length = 48;

pub const DecodeError = error{ InvalidEncoding, NotOnCurve, NotInSubgroup };

pub fn endomorphism(point: G1) G1 {
    return .{ .x = point.x.mul(beta), .y = point.y, .z = point.z };
}

/// Multiplication by the (negative) BLS parameter x.
pub fn mul_by_x(point: G1) G1 {
    return point.mul_u64(x_abs).neg();
}

/// True when `point` (assumed on the curve) lies in the order-r subgroup.
pub fn is_in_subgroup(point: Affine) bool {
    if (point.infinity) return true;
    assert(point.is_on_curve());
    const jacobian = point.to_jacobian();
    const minus_x_squared = mul_by_x(mul_by_x(jacobian)).neg();
    return minus_x_squared.eql(endomorphism(jacobian));
}

/// x^2 for the BLS parameter; r = x^4 - x^2 + 1, so scalars mod r split into two
/// halves below x^2 (128 bits).
const x_squared: u128 = @as(u128, x_abs) * x_abs;

pub const wnaf_width = 5;
/// Odd multiples 1P, 3P, ..., 15P.
pub const wnaf_table_size = 1 << (wnaf_width - 2);
/// A 128-bit scalar recodes to at most 129 width-5 NAF digits.
pub const wnaf_digits_max = 130;

/// Width-5 NAF of `scalar`: digits are zero or odd in [-15, 15]. Returns the length.
pub fn wnaf_recode(scalar: u128, digits: *[wnaf_digits_max]i8) u32 {
    var value: u130 = scalar;
    var length: u32 = 0;
    while (value != 0) : (length += 1) {
        assert(length < wnaf_digits_max);
        var digit: i8 = 0;
        if (value & 1 == 1) {
            const low: i8 = @intCast(value & 31);
            digit = if (low >= 16) low - 32 else low;
            if (digit >= 0) value -= @intCast(digit) else value += @intCast(-digit);
        }
        digits[length] = digit;
        value >>= 1;
    }
    assert(length <= 129);
    return length;
}

/// Affine odd multiples of `point` with a single inversion.
fn odd_multiples(point: G1, table: *[wnaf_table_size]Affine) void {
    assert(!point.is_identity());
    var jacobian: [wnaf_table_size]G1 = undefined;
    jacobian[0] = point;
    const twice = point.double();
    for (1..wnaf_table_size) |index| jacobian[index] = jacobian[index - 1].add(twice);
    var scratch: [wnaf_table_size]Fp = undefined;
    G1.batch_to_affine(&jacobian, table, &scratch);
}

inline fn add_digit(result: G1, table: *const [wnaf_table_size]Affine, digit: i8) G1 {
    if (digit > 0) return result.add_affine(table[@intCast((digit - 1) >> 1)]);
    if (digit < 0) return result.add_affine(table[@intCast((-digit - 1) >> 1)].neg());
    return result;
}

/// Scalar multiplication for points in G1 using the GLV endomorphism: with
/// k = k1 + k2 x^2 and x^2 P = -phi(P), kP = k1 P + k2 (-phi(P)). Both 128-bit halves
/// are recoded to width-5 NAF and share one doubling chain with mixed additions
/// from affine tables. Public scalars only.
/// Precondition: `point` is in the order-r subgroup (phi acts as -x^2 only there).
pub fn mul_glv(point: G1, scalar: u256) G1 {
    const k = scalar % fields.r;
    if (k == 0 or point.is_identity()) return G1.identity;
    const k1: u128 = @intCast(k % x_squared);
    const k2: u128 = @intCast(k / x_squared);
    assert(@as(u256, k2) * x_squared + k1 == k);
    var table1: [wnaf_table_size]Affine = undefined;
    odd_multiples(point, &table1);
    // -phi on affine points: (x, y) -> (beta x, -y); valid on every table entry.
    var table2: [wnaf_table_size]Affine = undefined;
    for (&table2, table1) |*entry, source| {
        entry.* = .{ .x = source.x.mul(beta), .y = source.y.neg(), .infinity = source.infinity };
    }
    var digits1: [wnaf_digits_max]i8 = @splat(0);
    var digits2: [wnaf_digits_max]i8 = @splat(0);
    const length = @max(wnaf_recode(k1, &digits1), wnaf_recode(k2, &digits2));
    var result = G1.identity;
    var index = length;
    while (index > 0) {
        index -= 1;
        if (!result.is_identity()) result = result.double();
        result = add_digit(result, &table1, digits1[index]);
        result = add_digit(result, &table2, digits2[index]);
    }
    return result;
}

/// Maps a curve point into G1: multiplication by h_eff = 1 - x = 1 + |x|.
pub fn clear_cofactor(point: G1) G1 {
    const result = point.add(point.mul_u64(x_abs));
    assert(point.is_identity() == false or result.is_identity());
    return result;
}

fn is_lexicographically_largest(value: Fp) bool {
    return value.to_int() > (fields.p - 1) / 2;
}

/// ZCash compressed encoding: big-endian x with flag bits in the top byte
/// (0x80 compressed, 0x40 infinity, 0x20 y is the larger root).
pub fn compress(point: Affine) [compressed_length]u8 {
    var out: [compressed_length]u8 = @splat(0);
    if (point.infinity) {
        out[0] = 0xc0;
        return out;
    }
    out = point.x.to_bytes_be();
    assert(out[0] & 0xe0 == 0);
    out[0] |= 0x80;
    if (is_lexicographically_largest(point.y)) out[0] |= 0x20;
    return out;
}

/// Decodes a compressed point and checks it is on the curve and in G1.
pub fn decompress(bytes: *const [compressed_length]u8) DecodeError!Affine {
    const point = try decompress_unchecked(bytes);
    if (!is_in_subgroup(point)) return error.NotInSubgroup;
    return point;
}

/// Decodes a compressed point on the curve without the subgroup check.
pub fn decompress_unchecked(bytes: *const [compressed_length]u8) DecodeError!Affine {
    const flags = bytes[0] & 0xe0;
    if (flags & 0x80 == 0) return error.InvalidEncoding;
    var body = bytes.*;
    body[0] &= 0x1f;
    if (flags & 0x40 != 0) {
        if (flags & 0x20 != 0) return error.InvalidEncoding;
        for (body) |byte| if (byte != 0) return error.InvalidEncoding;
        return Affine.identity;
    }
    const x = Fp.from_bytes_be(&body) orelse return error.InvalidEncoding;
    var y = x.square().mul(x).add(G1.coefficient_b).sqrt() orelse return error.NotOnCurve;
    if (is_lexicographically_largest(y) != (flags & 0x20 != 0)) y = y.neg();
    const point: Affine = .{ .x = x, .y = y, .infinity = false };
    assert(point.is_on_curve());
    return point;
}

const testing = std.testing;

/// A point on E(Fp) that is (almost surely) outside G1, found by trying x values.
pub fn test_point_off_subgroup(seed: u64) Affine {
    var prng = Prng.init(seed);
    for (0..64) |_| {
        const x = Fp.from_int(prng.int(u384));
        if (x.square().mul(x).add(G1.coefficient_b).sqrt()) |y| {
            return .{ .x = x, .y = y, .infinity = false };
        }
    }
    unreachable; // Half of all x are valid; 64 failures has probability 2^-64.
}

test "g1: width-5 NAF recoding reconstructs the scalar" {
    var prng = Prng.init(0x6e6166);
    for (0..500) |round| {
        const scalar: u128 = if (round < 3) round else prng.int(u128) >> @intCast(prng.below(128));
        var digits: [wnaf_digits_max]i8 = @splat(0);
        const length = wnaf_recode(scalar, &digits);
        var value: i256 = 0;
        var index = length;
        while (index > 0) {
            index -= 1;
            const digit = digits[index];
            const odd_in_range = @rem(digit, 2) != 0 and digit >= -15 and digit <= 15;
            try testing.expect(digit == 0 or odd_in_range);
            value = value * 2 + digit;
        }
        try testing.expectEqual(@as(i256, scalar), value);
    }
}

test "g1: GLV multiplication matches plain multiplication" {
    var prng = Prng.init(0x676c76);
    const g = generator.to_jacobian();
    try testing.expect(mul_glv(g, 0).is_identity());
    try testing.expect(mul_glv(g, fields.r).is_identity());
    try testing.expect(mul_glv(G1.identity, 12345).is_identity());
    const edges = [_]u256{ 1, 2, x_squared - 1, x_squared, x_squared + 1, fields.r - 1 };
    for (edges) |k| try testing.expect(mul_glv(g, k).eql(g.mul(k)));
    for (0..16) |_| {
        const base = g.mul(prng.int(u256));
        const k = prng.int(u256);
        try testing.expect(mul_glv(base, k).eql(base.mul(k)));
    }
}

test "g1: generator, order, and group laws" {
    const g = generator.to_jacobian();
    try testing.expect(generator.is_on_curve());
    try testing.expect(is_in_subgroup(generator));
    try testing.expect(g.mul(fields.r).is_identity());
    try testing.expect(!g.mul(fields.r - 1).is_identity());
    try testing.expect(beta.square().mul(beta).eql(Fp.one) and !beta.eql(Fp.one));
    var prng = Prng.init(0x61);
    for (0..8) |_| {
        const a = prng.int(u256) % fields.r;
        const b = prng.int(u256) % fields.r;
        const pa = g.mul(a);
        const pb = g.mul(b);
        try testing.expect(g.mul((a + b) % fields.r).eql(pa.add(pb)));
        try testing.expect(pa.add(pa).eql(pa.double()));
        try testing.expect(pa.add(pb).eql(pa.add_affine(pb.to_affine())));
        try testing.expect(pa.sub(pa).is_identity());
        try testing.expect(pa.is_on_curve() and pa.to_affine().is_on_curve());
        try testing.expect(pa.add_affine(pa.to_affine()).eql(pa.double()));
        try testing.expect(pa.add_affine(pa.neg().to_affine()).is_identity());
        try testing.expect(endomorphism(pa).eql(mul_by_x(mul_by_x(pa)).neg()));
    }
}

test "g1: subgroup check agrees with multiplication by r" {
    for (0..6) |seed| {
        const point = test_point_off_subgroup(seed);
        try testing.expect(point.is_on_curve());
        try testing.expect(!is_in_subgroup(point));
        try testing.expect(!point.to_jacobian().mul(fields.r).is_identity());
        const cleared = clear_cofactor(point.to_jacobian()).to_affine();
        try testing.expect(is_in_subgroup(cleared));
        try testing.expect(cleared.to_jacobian().mul(fields.r).is_identity());
    }
}

test "g1: compressed encoding" {
    var expected: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905" ++
        "a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    try testing.expectEqualSlices(u8, &expected, &compress(generator));
    try testing.expect((try decompress(&expected)).eql(generator));
    const minus = generator.neg();
    try testing.expect((try decompress(&compress(minus))).eql(minus));
    const infinity = compress(Affine.identity);
    try testing.expect((try decompress(&infinity)).infinity);
    var bad = infinity;
    bad[47] = 1;
    try testing.expectError(error.InvalidEncoding, decompress(&bad));
    bad = expected;
    bad[0] &= 0x7f;
    try testing.expectError(error.InvalidEncoding, decompress(&bad));
    const off = test_point_off_subgroup(9);
    try testing.expectError(error.NotInSubgroup, decompress(&compress(off)));
}

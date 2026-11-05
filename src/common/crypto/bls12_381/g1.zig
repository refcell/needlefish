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

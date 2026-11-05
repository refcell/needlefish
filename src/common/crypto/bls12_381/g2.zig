//! G2: the order-r subgroup of the sextic twist E'(Fp2): y^2 = x^3 + 4 (u + 1).
//!
//! psi = untwist-Frobenius-twist acts on G2 as multiplication by x, which gives
//! the membership test psi(P) = [x] P (Scott, eprint 2021/1130 section 4) and the
//! Budroni-Pintore cofactor clearing of RFC 9380 appendix G.3. Compressed points
//! follow the ZCash serialization (x.c1 first, then x.c0).

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const curve = @import("curve.zig");
const g1 = @import("g1.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const Fp = fields.Fp;
const Fp2 = fields.Fp2;

pub const G2 = curve.Curve(Fp2, Fp2.from_ints_comptime(4, 4));
pub const Affine = G2.Affine;

pub const x_abs: u64 = 0xd201000000010000;

pub const generator: Affine = .{
    .x = Fp2.from_ints_comptime(
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02 << 192 |
            0xb4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61a << 192 |
            0xb5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
    ),
    .y = Fp2.from_ints_comptime(
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a7 << 192 |
            0x6d429a695160d12c923ac9cc3baca289e193548608b82801,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af << 192 |
            0x267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be,
    ),
    .infinity = false,
};

/// 1 / (u + 1)^((p - 1) / 3) and 1 / (u + 1)^((p - 1) / 2) (RFC 9380 G.3).
const psi_x = Fp2.from_ints_comptime(
    0,
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4 << 192 |
        0x897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad,
);
const psi_y = Fp2.from_ints_comptime(
    0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60 << 192 |
        0xef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2,
    0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e << 192 |
        0x77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09,
);

pub const compressed_length = 96;

pub const DecodeError = error{ InvalidEncoding, NotOnCurve, NotInSubgroup };

/// psi(x, y) = (conj(x) psi_x, conj(y) psi_y); conjugation commutes with Z powers.
pub fn psi(point: G2) G2 {
    return .{
        .x = point.x.conjugate().mul(psi_x),
        .y = point.y.conjugate().mul(psi_y),
        .z = point.z.conjugate(),
    };
}

pub fn mul_by_x(point: G2) G2 {
    return point.mul_u64(x_abs).neg();
}

/// True when `point` (assumed on the curve) lies in the order-r subgroup.
pub fn is_in_subgroup(point: Affine) bool {
    if (point.infinity) return true;
    assert(point.is_on_curve());
    const jacobian = point.to_jacobian();
    return psi(jacobian).eql(mul_by_x(jacobian));
}

fn psi_affine(point: Affine) Affine {
    if (point.infinity) return point;
    return .{
        .x = point.x.conjugate().mul(psi_x),
        .y = point.y.conjugate().mul(psi_y),
        .infinity = false,
    };
}

inline fn add_digit(result: G2, table: *const [g1.wnaf_table_size]Affine, digit: i8) G2 {
    if (digit > 0) return result.add_affine(table[@intCast((digit - 1) >> 1)]);
    if (digit < 0) return result.add_affine(table[@intCast((-digit - 1) >> 1)].neg());
    return result;
}

/// Scalar multiplication for points in G2 using the GLS endomorphism psi = [x]:
/// k mod r = sum d_i |x|^i with four 64-bit digits, and [|x|^i] Q = (-psi)^i (Q),
/// so kQ = sum d_i (-psi)^i (Q) with one 64-step doubling chain, width-5 NAF
/// digits and mixed additions from affine tables. Public scalars only.
/// Precondition: `point` is in the order-r subgroup (psi acts as [x] only there).
pub fn mul_gls(point: G2, scalar: u256) G2 {
    var k = scalar % fields.r;
    if (k == 0 or point.is_identity()) return G2.identity;
    var tables: [4][g1.wnaf_table_size]Affine = undefined;
    var jacobian: [g1.wnaf_table_size]G2 = undefined;
    jacobian[0] = point;
    const twice = point.double();
    for (1..g1.wnaf_table_size) |index| jacobian[index] = jacobian[index - 1].add(twice);
    var scratch: [g1.wnaf_table_size]Fp2 = undefined;
    G2.batch_to_affine(&jacobian, &tables[0], &scratch);
    for (1..4) |power| {
        for (&tables[power], tables[power - 1]) |*entry, source| {
            entry.* = psi_affine(source).neg();
        }
    }
    var digits: [4][g1.wnaf_digits_max]i8 = @splat(@splat(0));
    var length: u32 = 0;
    for (&digits) |*row| {
        const digit: u64 = @intCast(k % x_abs);
        k /= x_abs;
        length = @max(length, g1.wnaf_recode(digit, row));
    }
    assert(k == 0);
    assert(length <= 65);
    var result = G2.identity;
    var index = length;
    while (index > 0) {
        index -= 1;
        if (!result.is_identity()) result = result.double();
        inline for (0..4) |power| {
            result = add_digit(result, &tables[power], digits[power][index]);
        }
    }
    return result;
}

/// RFC 9380 clear_cofactor_bls12381_g2 (multiplication by h_eff).
pub fn clear_cofactor(point: G2) G2 {
    const t1 = mul_by_x(point);
    const t2 = psi(point);
    const t3 = psi(psi(point.double())).sub(t2);
    const t4 = mul_by_x(t1.add(t2));
    const result = t3.add(t4).sub(t1).sub(point);
    assert(!point.is_identity() or result.is_identity());
    return result;
}

fn is_lexicographically_largest(value: Fp2) bool {
    const half = (fields.p - 1) / 2;
    if (!value.c1.is_zero()) return value.c1.to_int() > half;
    return value.c0.to_int() > half;
}

/// ZCash compressed encoding: x.c1 || x.c0 big-endian with flags in byte 0.
pub fn compress(point: Affine) [compressed_length]u8 {
    var out: [compressed_length]u8 = @splat(0);
    if (point.infinity) {
        out[0] = 0xc0;
        return out;
    }
    out[0..48].* = point.x.c1.to_bytes_be();
    out[48..96].* = point.x.c0.to_bytes_be();
    assert(out[0] & 0xe0 == 0);
    out[0] |= 0x80;
    if (is_lexicographically_largest(point.y)) out[0] |= 0x20;
    return out;
}

/// Decodes a compressed point and checks it is on the curve and in G2.
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
    const x: Fp2 = .{
        .c0 = Fp.from_bytes_be(body[48..96]) orelse return error.InvalidEncoding,
        .c1 = Fp.from_bytes_be(body[0..48]) orelse return error.InvalidEncoding,
    };
    const rhs = x.square().mul(x).add(G2.coefficient_b);
    var y = rhs.sqrt() orelse return error.NotOnCurve;
    if (is_lexicographically_largest(y) != (flags & 0x20 != 0)) y = y.neg();
    const point: Affine = .{ .x = x, .y = y, .infinity = false };
    assert(point.is_on_curve());
    return point;
}

const testing = std.testing;

test "g2: GLS multiplication matches plain multiplication" {
    var prng = Prng.init(0x676c73);
    const g = generator.to_jacobian();
    try testing.expect(mul_gls(g, 0).is_identity());
    try testing.expect(mul_gls(g, fields.r).is_identity());
    try testing.expect(mul_gls(G2.identity, 99).is_identity());
    const edges = [_]u256{ 1, 2, x_abs - 1, x_abs, x_abs + 1, fields.r - 1 };
    for (edges) |k| try testing.expect(mul_gls(g, k).eql(g.mul(k)));
    for (0..8) |_| {
        const base = g.mul(prng.int(u256));
        const k = prng.int(u256);
        try testing.expect(mul_gls(base, k).eql(base.mul(k)));
    }
}

/// A point on E'(Fp2) that is (almost surely) outside G2.
pub fn test_point_off_subgroup(seed: u64) Affine {
    var prng = Prng.init(seed);
    for (0..64) |_| {
        const x: Fp2 = .{ .c0 = Fp.from_int(prng.int(u384)), .c1 = Fp.from_int(prng.int(u384)) };
        if (x.square().mul(x).add(G2.coefficient_b).sqrt()) |y| {
            return .{ .x = x, .y = y, .infinity = false };
        }
    }
    unreachable; // Half of all x are valid; 64 failures has probability 2^-64.
}

test "g2: generator, order, and group laws" {
    const g = generator.to_jacobian();
    try testing.expect(generator.is_on_curve());
    try testing.expect(is_in_subgroup(generator));
    try testing.expect(g.mul(fields.r).is_identity());
    const xi: Fp2 = .{ .c0 = .one, .c1 = .one };
    try testing.expect(psi_x.eql(xi.pow((fields.p - 1) / 3).inverse()));
    try testing.expect(psi_y.eql(xi.pow((fields.p - 1) / 2).inverse()));
    var prng = Prng.init(0x62);
    for (0..4) |_| {
        const a = prng.int(u256) % fields.r;
        const b = prng.int(u256) % fields.r;
        const pa = g.mul(a);
        const pb = g.mul(b);
        try testing.expect(g.mul((a + b) % fields.r).eql(pa.add(pb)));
        try testing.expect(pa.add(pa).eql(pa.double()));
        try testing.expect(pa.add(pb).eql(pa.add_affine(pb.to_affine())));
        try testing.expect(pa.is_on_curve() and pa.to_affine().is_on_curve());
        try testing.expect(psi(pa).eql(mul_by_x(pa)));
    }
}

test "g2: subgroup check and cofactor clearing" {
    for (0..3) |seed| {
        const point = test_point_off_subgroup(seed);
        try testing.expect(point.is_on_curve());
        try testing.expect(!is_in_subgroup(point));
        try testing.expect(!point.to_jacobian().mul(fields.r).is_identity());
        const cleared = clear_cofactor(point.to_jacobian()).to_affine();
        try testing.expect(cleared.is_on_curve());
        try testing.expect(is_in_subgroup(cleared));
        try testing.expect(cleared.to_jacobian().mul(fields.r).is_identity());
    }
}

test "g2: compressed encoding" {
    var expected: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "93e02b6052719f607dacd3a088274f65596bd0d09920b61a" ++
        "b5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e" ++
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02" ++
        "b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
    try testing.expectEqualSlices(u8, &expected, &compress(generator));
    try testing.expect((try decompress(&expected)).eql(generator));
    const minus = generator.neg();
    try testing.expect((try decompress(&compress(minus))).eql(minus));
    try testing.expect((try decompress(&compress(Affine.identity))).infinity);
    const off = test_point_off_subgroup(5);
    try testing.expectError(error.NotInSubgroup, decompress(&compress(off)));
}

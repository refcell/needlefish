//! G1: the bn254 curve y^2 = x^3 + 3 over Fp. Cofactor 1, so every curve point
//! has order r. Scalar multiplication uses the GLV endomorphism
//! phi(x, y) = (beta x, y) = [lambda] P to halve the doubling chain, with
//! interleaved width-5 wNAF over the two half-size scalars.

const std = @import("std");
const assert = std.debug.assert;
const fp = @import("fp.zig");
const Fp = fp.Fp;
const curve = @import("curve.zig");

pub const G1 = curve.Curve(Fp, Fp.from_int_comptime(3));
pub const G1Affine = G1.Affine;

pub const generator: G1Affine = .{
    .x = Fp.from_int_comptime(1),
    .y = Fp.from_int_comptime(2),
    .is_infinity = false,
};

/// Cube root of unity in Fp with phi(P) = [lambda] P on G1.
const beta = Fp.from_int_comptime(0x59e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe);
pub const lambda: u256 = 0xb3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd;

// Short basis of the lattice {(a, b) : a + b lambda = 0 mod r}, and the rounded
// constants g1 = floor(b2 2^256 / r), g2 = floor(-b1 2^256 / r) for Babai rounding.
const basis_a1: i512 = 9931322734385697763;
const basis_b1: i512 = -147946756881789319000765030803803410728;
const basis_a2: i512 = 147946756881789319010696353538189108491;
const basis_b2: i512 = 9931322734385697763;
const round_g1: u512 = 0x2d91d232ec7e0b3d7;
const round_g2: u512 = 0x24ccef014a773d2cf7a7bd9d4391eb18d;

comptime {
    const r: i512 = fp.r;
    assert(@mod(basis_a1 + basis_b1 * lambda, r) == 0);
    assert(@mod(basis_a2 + basis_b2 * lambda, r) == 0);
    assert(basis_a1 * basis_b2 - basis_a2 * basis_b1 == r);
    @setEvalBranchQuota(10_000);
    assert(round_g1 == (@as(u512, @intCast(basis_b2)) << 256) / fp.r);
    assert(round_g2 == (@as(u512, @intCast(-basis_b1)) << 256) / fp.r);
}

pub const Decomposition = struct {
    k1: u128,
    k1_negative: bool,
    k2: u128,
    k2_negative: bool,
};

/// Splits k (< r) into k1 + k2 lambda = k mod r with |k1|, |k2| < 2^128.
pub fn decompose(k: u256) Decomposition {
    assert(k < fp.r);
    const c1: i512 = @intCast((@as(u512, k) * round_g1) >> 256);
    const c2: i512 = @intCast((@as(u512, k) * round_g2) >> 256);
    const k1: i512 = @as(i512, k) - c1 * basis_a1 - c2 * basis_a2;
    const k2: i512 = -c1 * basis_b1 - c2 * basis_b2;
    assert(@abs(k1) < (1 << 128));
    assert(@abs(k2) < (1 << 128));
    return .{
        .k1 = @intCast(@abs(k1)),
        .k1_negative = k1 < 0,
        .k2 = @intCast(@abs(k2)),
        .k2_negative = k2 < 0,
    };
}

pub fn endomorphism(point: G1) G1 {
    return .{ .x = point.x.mul(beta), .y = point.y, .z = point.z };
}

/// scalar * point for a point in G1 (any curve point, cofactor 1).
pub fn mul(point: G1, scalar: u256) G1 {
    const split = decompose(scalar % fp.r);
    const base1 = if (split.k1_negative) point.neg() else point;
    const table1 = G1.odd_multiples(base1);
    var table2: G1.Table = undefined;
    const flip = split.k1_negative != split.k2_negative;
    for (&table2, table1) |*entry, source| {
        const mapped = endomorphism(source);
        entry.* = if (flip) mapped.neg() else mapped;
    }
    var digits1: [curve.wnaf_digits_max]i8 = @splat(0);
    var digits2: [curve.wnaf_digits_max]i8 = @splat(0);
    const length1 = curve.wnaf_digits(split.k1, &digits1);
    const length2 = curve.wnaf_digits(split.k2, &digits2);
    assert(length1 <= 129 and length2 <= 129);
    var result = G1.infinity;
    var index = @max(length1, length2);
    while (index > 0) {
        index -= 1;
        result = result.double();
        result = G1.add_digit(result, &table1, digits1[index]);
        result = G1.add_digit(result, &table2, digits2[index]);
    }
    return result;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "g1: generator on curve, order r, endomorphism eigenvalue" {
    const g = G1.from_affine(generator);
    try testing.expect(generator.is_on_curve());
    try testing.expect(G1.mul_reference(g, fp.r).is_infinity());
    try testing.expect(endomorphism(g).eql(G1.mul_reference(g, lambda)));
    try testing.expect(mul(g, fp.r).is_infinity());
    try testing.expect(mul(g, 0).is_infinity());
    try testing.expect(mul(g, 1).eql(g));
}

test "g1: seeded fuzz of group laws and scalar multiplication" {
    var prng = Prng.init(0x91);
    const g = G1.from_affine(generator);
    for (0..40) |round| {
        const a = prng.int(u256);
        const b = prng.int(u256) >> @intCast(prng.below(256));
        const pa = G1.mul_reference(g, a);
        const pb = G1.mul_reference(g, b);
        try testing.expect(mul(g, a).eql(pa));
        try testing.expect(G1.mul(g, a).eql(pa));
        try testing.expect(pa.add(pb).eql(pb.add(pa)));
        try testing.expect(pa.add(pa).eql(pa.double()));
        try testing.expect(pa.add(pa.neg()).is_infinity());
        try testing.expect(pa.add_affine(pb.to_affine()).eql(pa.add(pb)));
        try testing.expect(pa.to_affine().is_on_curve());
        // (a + b) P = aP + bP with wrap-around mod r.
        const sum: u256 = @intCast((@as(u512, a) + b) % fp.r);
        try testing.expect(mul(g, sum).eql(pa.add(pb)));
        // Repeated addition equals multiplication for small scalars.
        var repeated = G1.infinity;
        for (0..round % 9) |_| repeated = repeated.add(pa);
        try testing.expect(mul(pa, round % 9).eql(repeated));
    }
}

test "g1: decomposition edge cases" {
    var prng = Prng.init(0xd1);
    for (0..2000) |round| {
        const k: u256 = switch (round) {
            0 => 0,
            1 => fp.r - 1,
            2 => lambda,
            3 => fp.r / 2,
            else => prng.int(u256) % fp.r,
        };
        const split = decompose(k);
        var k1: i512 = split.k1;
        var k2: i512 = split.k2;
        if (split.k1_negative) k1 = -k1;
        if (split.k2_negative) k2 = -k2;
        try testing.expectEqual(@as(i512, k), @mod(k1 + k2 * lambda, fp.r));
    }
}

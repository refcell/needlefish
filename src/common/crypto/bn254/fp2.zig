//! Fp2 = Fp[u] / (u^2 + 1), the quadratic extension carrying the G2 twist.
//!
//! The API mirrors `montgomery.Field` (add, sub, mul, square, inverse, ...) so the
//! generic Jacobian curve code in `curve.zig` serves both G1 and G2.

const std = @import("std");
const assert = std.debug.assert;
const Fp = @import("fp.zig").Fp;

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub const zero: Fp2 = .{ .c0 = .zero, .c1 = .zero };
    pub const one: Fp2 = .{ .c0 = .one, .c1 = .zero };

    /// Element for compile-time integers c0 + c1 * u.
    pub fn from_ints(comptime c0: comptime_int, comptime c1: comptime_int) Fp2 {
        return .{ .c0 = Fp.from_int_comptime(c0), .c1 = Fp.from_int_comptime(c1) };
    }

    pub fn is_zero(a: Fp2) bool {
        return a.c0.is_zero() and a.c1.is_zero();
    }

    pub fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    pub fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }

    pub fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }

    pub fn double(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.double(), .c1 = a.c1.double() };
    }

    pub fn neg(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }

    /// Complex conjugate; equals the p-power Frobenius on Fp2.
    pub fn conjugate(a: Fp2) Fp2 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    /// Karatsuba: three base-field multiplications.
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        const cross = a.c0.add(a.c1).mul(b.c0.add(b.c1));
        return .{ .c0 = v0.sub(v1), .c1 = cross.sub(v0).sub(v1) };
    }

    /// Complex squaring: two base-field multiplications.
    pub fn square(a: Fp2) Fp2 {
        const product = a.c0.mul(a.c1);
        const c0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1));
        return .{ .c0 = c0, .c1 = product.double() };
    }

    pub fn mul_by_fp(a: Fp2, b: Fp) Fp2 {
        return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b) };
    }

    /// Multiplies by the sextic non-residue xi = 9 + u.
    pub fn mul_by_nonresidue(a: Fp2) Fp2 {
        const a0_times_8 = a.c0.double().double().double();
        const a1_times_8 = a.c1.double().double().double();
        return .{
            .c0 = a0_times_8.add(a.c0).sub(a.c1),
            .c1 = a1_times_8.add(a.c1).add(a.c0),
        };
    }

    /// Multiplicative inverse; inverse(0) = 0.
    pub fn inverse(a: Fp2) Fp2 {
        const norm = a.c0.square().add(a.c1.square());
        const norm_inverse = norm.inverse();
        const result: Fp2 = .{ .c0 = a.c0.mul(norm_inverse), .c1 = a.c1.mul(norm_inverse).neg() };
        assert(a.is_zero() or result.mul(a).eql(one));
        assert(!a.is_zero() or result.is_zero());
        return result;
    }

    /// a^(p^power) for power in [0, 12): conjugation for odd powers.
    pub fn frobenius(a: Fp2, power: u32) Fp2 {
        assert(power < 12);
        return if (power % 2 == 1) a.conjugate() else a;
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

pub fn random_fp2(prng: *Prng) Fp2 {
    return .{ .c0 = Fp.from_int(prng.int(u256)), .c1 = Fp.from_int(prng.int(u256)) };
}

test "fp2: ring laws, squaring, inverse, non-residue" {
    var prng = Prng.init(0xf2);
    const xi = Fp2.from_ints(9, 1);
    for (0..200) |_| {
        const a = random_fp2(&prng);
        const b = random_fp2(&prng);
        const c = random_fp2(&prng);
        try testing.expect(a.mul(b).eql(b.mul(a)));
        try testing.expect(a.mul(b.add(c)).eql(a.mul(b).add(a.mul(c))));
        try testing.expect(a.square().eql(a.mul(a)));
        try testing.expect(a.mul_by_nonresidue().eql(a.mul(xi)));
        try testing.expect(a.sub(b).add(b).eql(a));
        if (!a.is_zero()) try testing.expect(a.mul(a.inverse()).eql(Fp2.one));
    }
    // u^2 = -1.
    const u = Fp2.from_ints(0, 1);
    try testing.expect(u.square().eql(Fp2.one.neg()));
}

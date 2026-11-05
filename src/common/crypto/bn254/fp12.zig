//! Fp12 = Fp6[w] / (w^2 - v), the pairing target field.
//!
//! Besides generic arithmetic it carries the pieces the pairing needs: sparse
//! multiplication by Miller-loop lines, Frobenius maps, and Granger-Scott
//! squaring for elements of the cyclotomic subgroup (after the easy part of the
//! final exponentiation).

const std = @import("std");
const assert = std.debug.assert;
const Fp2 = @import("fp2.zig").Fp2;
const Fp6 = @import("fp6.zig").Fp6;

pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub const one: Fp12 = .{ .c0 = .one, .c1 = .zero };

    /// Frobenius coefficients xi^((p^k - 1) / 6) for w, k = 1, 2, 3.
    const frobenius_c1 = [3]Fp2{
        Fp2.from_ints(
            0x1284b71c2865a7dfe8b99fdd76e68b605c521e08292f2176d60b35dadcc9e470,
            0x246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac,
        ),
        Fp2.from_ints(0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd49, 0),
        Fp2.from_ints(
            0x19dc81cfcc82e4bbefe9608cd0acaa90894cb38dbe55d24ae86f7d391ed4a67f,
            0x00abf8b60be77d7306cbeee33576139d7f03a5e397d439ec7694aa2bf4c0c101,
        ),
    };

    pub fn eql(a: Fp12, b: Fp12) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    pub fn is_one(a: Fp12) bool {
        return a.eql(one);
    }

    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        const t0 = a.c0.mul(b.c0);
        const t1 = a.c1.mul(b.c1);
        const cross = a.c0.add(a.c1).mul(b.c0.add(b.c1));
        return .{ .c0 = t0.add(t1.mul_by_nonresidue()), .c1 = cross.sub(t0).sub(t1) };
    }

    /// Complex squaring: two Fp6 multiplications.
    pub fn square(a: Fp12) Fp12 {
        const product = a.c0.mul(a.c1);
        const mixed = a.c0.add(a.c1).mul(a.c0.add(a.c1.mul_by_nonresidue()));
        const c0 = mixed.sub(product).sub(product.mul_by_nonresidue());
        return .{ .c0 = c0, .c1 = product.double() };
    }

    /// a^(p^6): for unitary elements this is the inverse.
    pub fn conjugate(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }

    pub fn inverse(a: Fp12) Fp12 {
        const t = a.c0.square().sub(a.c1.square().mul_by_nonresidue());
        const t_inverse = t.inverse();
        const result: Fp12 = .{ .c0 = a.c0.mul(t_inverse), .c1 = a.c1.mul(t_inverse).neg() };
        assert(t.is_zero() or result.mul(a).is_one());
        assert(!t.is_zero() or result.c0.is_zero());
        return result;
    }

    /// Product with a sparse line d0 + d3 w + d4 v w (a D-type twist line).
    pub fn mul_by_034(a: Fp12, d0: Fp2, d3: Fp2, d4: Fp2) Fp12 {
        const t0 = a.c0.mul_by_fp2(d0);
        const t1 = a.c1.mul_by_01(d3, d4);
        const cross = a.c0.add(a.c1).mul_by_01(d0.add(d3), d4);
        return .{ .c0 = t1.mul_by_nonresidue().add(t0), .c1 = cross.sub(t0).sub(t1) };
    }

    /// a^(p^power) for power in {1, 2, 3}.
    pub fn frobenius(a: Fp12, power: u32) Fp12 {
        assert(power >= 1 and power <= 3);
        const coefficient = frobenius_c1[power - 1];
        const c1 = a.c1.frobenius(power);
        return .{
            .c0 = a.c0.frobenius(power),
            .c1 = .{
                .c0 = c1.c0.mul(coefficient),
                .c1 = c1.c1.mul(coefficient),
                .c2 = c1.c2.mul(coefficient),
            },
        };
    }

    /// Granger-Scott squaring, valid only in the cyclotomic subgroup.
    pub fn cyclotomic_square(a: Fp12) Fp12 {
        const z0 = a.c0.c0;
        const z4 = a.c0.c1;
        const z3 = a.c0.c2;
        const z2 = a.c1.c0;
        const z1 = a.c1.c1;
        const z5 = a.c1.c2;
        const t01 = fp4_square(z0, z1);
        const t23 = fp4_square(z2, z3);
        const t45 = fp4_square(z4, z5);
        const result: Fp12 = .{
            .c0 = .{
                .c0 = t01[0].sub(z0).double().add(t01[0]),
                .c1 = t23[0].sub(z4).double().add(t23[0]),
                .c2 = t45[0].sub(z3).double().add(t45[0]),
            },
            .c1 = .{
                .c0 = t45[1].mul_by_nonresidue().add(z2).double().add(t45[1].mul_by_nonresidue()),
                .c1 = t01[1].add(z1).double().add(t01[1]),
                .c2 = t23[1].add(z5).double().add(t23[1]),
            },
        };
        return result;
    }

    /// (a + b y)^2 in Fp4 = Fp2[y] / (y^2 - xi).
    fn fp4_square(a: Fp2, b: Fp2) [2]Fp2 {
        const product = a.mul(b);
        const c0 = a.add(b).mul(b.mul_by_nonresidue().add(a))
            .sub(product).sub(product.mul_by_nonresidue());
        return .{ c0, product.double() };
    }

    /// a^exponent by square-and-multiply over a public exponent (tests, oracles).
    pub fn pow(a: Fp12, exponent: u256) Fp12 {
        var result = one;
        var index: u32 = 256;
        while (index > 0) {
            index -= 1;
            result = result.square();
            if ((exponent >> @intCast(index)) & 1 == 1) result = result.mul(a);
        }
        return result;
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const random_fp6 = @import("fp6.zig").random_fp6;
const random_fp2 = @import("fp2.zig").random_fp2;
const p = @import("fp.zig").p;

pub fn random_fp12(prng: *Prng) Fp12 {
    return .{ .c0 = random_fp6(prng), .c1 = random_fp6(prng) };
}

test "fp12: ring laws, sparse mul, inverse" {
    var prng = Prng.init(0xf12);
    for (0..30) |_| {
        const a = random_fp12(&prng);
        const b = random_fp12(&prng);
        try testing.expect(a.mul(b).eql(b.mul(a)));
        try testing.expect(a.square().eql(a.mul(a)));
        try testing.expect(a.mul(a.inverse()).is_one());
        const d0 = random_fp2(&prng);
        const d3 = random_fp2(&prng);
        const d4 = random_fp2(&prng);
        const sparse: Fp12 = .{
            .c0 = .{ .c0 = d0, .c1 = .zero, .c2 = .zero },
            .c1 = .{ .c0 = d3, .c1 = d4, .c2 = .zero },
        };
        try testing.expect(a.mul_by_034(d0, d3, d4).eql(a.mul(sparse)));
    }
}

test "fp12: frobenius matches exponentiation by p" {
    var prng = Prng.init(0xf120);
    for (0..3) |_| {
        const a = random_fp12(&prng);
        const a_p = a.pow(p);
        try testing.expect(a.frobenius(1).eql(a_p));
        try testing.expect(a.frobenius(2).eql(a_p.pow(p)));
        try testing.expect(a.frobenius(3).eql(a_p.pow(p).pow(p)));
    }
}

test "fp12: cyclotomic squaring matches squaring on unitary elements" {
    var prng = Prng.init(0xc7c);
    for (0..20) |_| {
        const a = random_fp12(&prng);
        // a^((p^6 - 1)(p^2 + 1)) lies in the cyclotomic subgroup.
        const t = a.conjugate().mul(a.inverse());
        const cyclotomic = t.frobenius(2).mul(t);
        try testing.expect(cyclotomic.cyclotomic_square().eql(cyclotomic.square()));
        try testing.expect(cyclotomic.mul(cyclotomic.conjugate()).is_one());
    }
}

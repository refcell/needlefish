//! Fp6 = Fp2[v] / (v^3 - xi) with xi = 9 + u, the middle layer of the tower.

const std = @import("std");
const assert = std.debug.assert;
const Fp2 = @import("fp2.zig").Fp2;

pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    pub const zero: Fp6 = .{ .c0 = .zero, .c1 = .zero, .c2 = .zero };
    pub const one: Fp6 = .{ .c0 = .one, .c1 = .zero, .c2 = .zero };

    /// Frobenius coefficients xi^((p^k - 1) / 3) for v, k = 1, 2, 3.
    const frobenius_c1 = [3]Fp2{
        Fp2.from_ints(
            0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d,
            0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2,
        ),
        Fp2.from_ints(0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48, 0),
        Fp2.from_ints(
            0x0856e078b755ef0abaff1c77959f25ac805ffd3d5d6942d37b746ee87bdcfb6d,
            0x04f1de41b3d1766fa9f30e6dec26094f0fdf31bf98ff2631380cab2baaa586de,
        ),
    };
    /// Frobenius coefficients xi^(2 (p^k - 1) / 3) for v^2, k = 1, 2, 3.
    const frobenius_c2 = [3]Fp2{
        Fp2.from_ints(
            0x05b54f5e64eea80180f3c0b75a181e84d33365f7be94ec72848a1f55921ea762,
            0x2c145edbe7fd8aee9f3a80b03b0b1c923685d2ea1bdec763c13b4711cd2b8126,
        ),
        Fp2.from_ints(0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe, 0),
        Fp2.from_ints(
            0x0bc58c6611c08dab19bee0f7b5b2444ee633094575b06bcb0e1a92bc3ccbf066,
            0x23d5e999e1910a12feb0f6ef0cd21d04a44a9e08737f96e55fe3ed9d730c239f,
        ),
    };

    pub fn is_zero(a: Fp6) bool {
        return a.c0.is_zero() and a.c1.is_zero() and a.c2.is_zero();
    }

    pub fn eql(a: Fp6, b: Fp6) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1) and a.c2.eql(b.c2);
    }

    pub fn add(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }

    pub fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }

    pub fn double(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.double(), .c1 = a.c1.double(), .c2 = a.c2.double() };
    }

    pub fn neg(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg(), .c2 = a.c2.neg() };
    }

    /// Multiplies by v: (a0, a1, a2) -> (xi a2, a0, a1).
    pub fn mul_by_nonresidue(a: Fp6) Fp6 {
        return .{ .c0 = a.c2.mul_by_nonresidue(), .c1 = a.c0, .c2 = a.c1 };
    }

    pub fn mul_by_fp2(a: Fp6, b: Fp2) Fp6 {
        return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b), .c2 = a.c2.mul(b) };
    }

    /// Karatsuba over three coefficients: six Fp2 multiplications.
    pub fn mul(a: Fp6, b: Fp6) Fp6 {
        const t0 = a.c0.mul(b.c0);
        const t1 = a.c1.mul(b.c1);
        const t2 = a.c2.mul(b.c2);
        const s12 = a.c1.add(a.c2).mul(b.c1.add(b.c2)).sub(t1).sub(t2);
        const s01 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(t0).sub(t1);
        const s02 = a.c0.add(a.c2).mul(b.c0.add(b.c2)).sub(t0).sub(t2);
        return .{
            .c0 = t0.add(s12.mul_by_nonresidue()),
            .c1 = s01.add(t2.mul_by_nonresidue()),
            .c2 = s02.add(t1),
        };
    }

    /// Chung-Hasan SQR2.
    pub fn square(a: Fp6) Fp6 {
        const s0 = a.c0.square();
        const s1 = a.c0.mul(a.c1).double();
        const s2 = a.c0.sub(a.c1).add(a.c2).square();
        const s3 = a.c1.mul(a.c2).double();
        const s4 = a.c2.square();
        return .{
            .c0 = s0.add(s3.mul_by_nonresidue()),
            .c1 = s1.add(s4.mul_by_nonresidue()),
            .c2 = s1.add(s2).add(s3).sub(s0).sub(s4),
        };
    }

    /// Product with the sparse element b0 + b1 v.
    pub fn mul_by_01(a: Fp6, b0: Fp2, b1: Fp2) Fp6 {
        const t0 = a.c0.mul(b0);
        const t1 = a.c1.mul(b1);
        const c0 = a.c1.add(a.c2).mul(b1).sub(t1).mul_by_nonresidue().add(t0);
        const c1 = a.c0.add(a.c1).mul(b0.add(b1)).sub(t0).sub(t1);
        const c2 = a.c0.add(a.c2).mul(b0).sub(t0).add(t1);
        return .{ .c0 = c0, .c1 = c1, .c2 = c2 };
    }

    pub fn inverse(a: Fp6) Fp6 {
        const c0 = a.c0.square().sub(a.c1.mul(a.c2).mul_by_nonresidue());
        const c1 = a.c2.square().mul_by_nonresidue().sub(a.c0.mul(a.c1));
        const c2 = a.c1.square().sub(a.c0.mul(a.c2));
        const t = a.c2.mul(c1).add(a.c1.mul(c2)).mul_by_nonresidue().add(a.c0.mul(c0));
        const t_inverse = t.inverse();
        const result: Fp6 = .{
            .c0 = c0.mul(t_inverse),
            .c1 = c1.mul(t_inverse),
            .c2 = c2.mul(t_inverse),
        };
        assert(a.is_zero() or result.mul(a).eql(one));
        assert(!a.is_zero() or result.is_zero());
        return result;
    }

    /// a^(p^power) for power in {1, 2, 3}.
    pub fn frobenius(a: Fp6, power: u32) Fp6 {
        assert(power >= 1 and power <= 3);
        const index = power - 1;
        return .{
            .c0 = a.c0.frobenius(power),
            .c1 = a.c1.frobenius(power).mul(frobenius_c1[index]),
            .c2 = a.c2.frobenius(power).mul(frobenius_c2[index]),
        };
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const random_fp2 = @import("fp2.zig").random_fp2;

pub fn random_fp6(prng: *Prng) Fp6 {
    return .{ .c0 = random_fp2(prng), .c1 = random_fp2(prng), .c2 = random_fp2(prng) };
}

test "fp6: ring laws, sparse mul, inverse, frobenius" {
    var prng = Prng.init(0xf6);
    const v: Fp6 = .{ .c0 = .zero, .c1 = .one, .c2 = .zero };
    for (0..50) |_| {
        const a = random_fp6(&prng);
        const b = random_fp6(&prng);
        const c = random_fp6(&prng);
        try testing.expect(a.mul(b).eql(b.mul(a)));
        try testing.expect(a.mul(b.add(c)).eql(a.mul(b).add(a.mul(c))));
        try testing.expect(a.square().eql(a.mul(a)));
        try testing.expect(a.mul_by_nonresidue().eql(a.mul(v)));
        const sparse: Fp6 = .{ .c0 = b.c0, .c1 = b.c1, .c2 = .zero };
        try testing.expect(a.mul_by_01(b.c0, b.c1).eql(a.mul(sparse)));
        try testing.expect(a.mul(a.inverse()).eql(Fp6.one));
        // Frobenius is a ring homomorphism; composition adds powers.
        try testing.expect(a.mul(b).frobenius(1).eql(a.frobenius(1).mul(b.frobenius(1))));
        try testing.expect(a.frobenius(1).frobenius(1).eql(a.frobenius(2)));
        try testing.expect(a.frobenius(1).frobenius(2).eql(a.frobenius(3)));
    }
    // v^3 = xi.
    const xi: Fp6 = .{ .c0 = Fp2.from_ints(9, 1), .c1 = .zero, .c2 = .zero };
    try testing.expect(v.square().mul(v).eql(xi));
}

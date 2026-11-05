//! G2: the sextic D-type twist y^2 = x^3 + 3 / (9 + u) over Fp2.
//!
//! The twist group has a large cofactor, so EIP-197 requires a subgroup check on
//! every pairing input. We use the endomorphism test of El Housni, Guillevic and
//! Piellard (eprint 2022/352, BN case): Q is in G2 iff
//! [x + 1] Q + psi([x] Q) + psi^2([x] Q) = psi^3([2x] Q), where psi is the
//! untwist-Frobenius-twist map. It needs one 63-bit multiplication instead of the
//! 127-bit [6x^2] Q of the older psi(Q) = [6x^2] Q test (kept as a test oracle).

const std = @import("std");
const assert = std.debug.assert;
const fp = @import("fp.zig");
const Fp2 = @import("fp2.zig").Fp2;
const curve = @import("curve.zig");

/// b' = 3 / (9 + u).
pub const twist_b = Fp2.from_ints(
    0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5,
    0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2,
);

pub const G2 = curve.Curve(Fp2, twist_b);
pub const G2Affine = G2.Affine;

pub const generator: G2Affine = .{
    .x = Fp2.from_ints(
        0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed,
        0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
    ),
    .y = Fp2.from_ints(
        0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa,
        0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
    ),
    .is_infinity = false,
};

/// xi^((p - 1) / 3) and xi^((p - 1) / 2): psi scales x and y by these.
pub const psi_x = Fp2.from_ints(
    0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d,
    0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2,
);
pub const psi_y = Fp2.from_ints(
    0x063cf305489af5dcdc5ec698b6e2f9b9dbaae0eda9c95998dc54014671a0135a,
    0x07c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3,
);

/// 6 x^2, the eigenvalue of psi on G2.
pub const six_x_squared: u256 = 6 * @as(u256, fp.curve_x) * fp.curve_x;

comptime {
    assert(six_x_squared == 0x6f4d8248eeb859fbf83e9682e87cfd46);
    assert(six_x_squared % fp.r == fp.p % fp.r);
}

/// psi(x, y) = (conj(x) psi_x, conj(y) psi_y), acting as [p] on G2.
pub fn psi(point: G2) G2 {
    return .{
        .x = point.x.conjugate().mul(psi_x),
        .y = point.y.conjugate().mul(psi_y),
        .z = point.z.conjugate(),
    };
}

pub fn psi_affine(point: G2Affine) G2Affine {
    assert(!point.is_infinity);
    const result: G2Affine = .{
        .x = point.x.conjugate().mul(psi_x),
        .y = point.y.conjugate().mul(psi_y),
        .is_infinity = false,
    };
    assert(result.is_on_curve() == point.is_on_curve());
    return result;
}

/// True when an on-curve point lies in the order-r subgroup.
pub fn is_in_subgroup(point: G2Affine) bool {
    assert(point.is_on_curve());
    if (point.is_infinity) return true;
    const projective = G2.from_affine(point);
    const x_point = projective.mul(fp.curve_x);
    const psi_x_point = psi(x_point);
    const psi2_x_point = psi(psi_x_point);
    const left = x_point.add(projective).add(psi_x_point).add(psi2_x_point);
    const right = psi(psi2_x_point).double();
    return left.eql(right);
}

/// The psi(Q) = [6x^2] Q test: an independent oracle for `is_in_subgroup`.
fn is_in_subgroup_reference(point: G2Affine) bool {
    assert(point.is_on_curve());
    if (point.is_infinity) return true;
    const projective = G2.from_affine(point);
    return psi(projective).eql(projective.mul(six_x_squared));
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "g2: generator in subgroup, order r" {
    const g = G2.from_affine(generator);
    try testing.expect(generator.is_on_curve());
    try testing.expect(is_in_subgroup(generator));
    try testing.expect(g.mul(fp.r).is_infinity());
    try testing.expect(psi(g).eql(g.mul(fp.p % fp.r)));
}

test "g2: rejects an on-curve point outside the subgroup" {
    // x = 1 lies on the twist; its order is not r.
    const point: G2Affine = .{
        .x = Fp2.one,
        .y = Fp2.from_ints(
            0x2869111d5381f072f8e2728fdb825a51aadd70e52c9830e9ab4b871c0531f1bb,
            0x0d1271953ed9ea0836846e70a1934187998c7f790cb4d7511b7f8da82de048a4,
        ),
        .is_infinity = false,
    };
    try testing.expect(point.is_on_curve());
    try testing.expect(!is_in_subgroup(point));
    try testing.expect(!G2.from_affine(point).mul(fp.r).is_infinity());
}

/// On the twist with x = 1, outside G2 (its order is not r).
const outside_point: G2Affine = .{
    .x = Fp2.one,
    .y = Fp2.from_ints(
        0x2869111d5381f072f8e2728fdb825a51aadd70e52c9830e9ab4b871c0531f1bb,
        0x0d1271953ed9ea0836846e70a1934187998c7f790cb4d7511b7f8da82de048a4,
    ),
    .is_infinity = false,
};

/// A random twist point of (almost surely) mixed order: a random multiple of
/// `outside_point`.
fn random_twist_point(prng: *Prng) G2Affine {
    const point = G2.from_affine(outside_point).mul(prng.int(u256) | 1).to_affine();
    assert(point.is_on_curve());
    return point;
}

test "g2: fast subgroup check matches [r] Q = O and the psi = [6x^2] oracle" {
    var prng = Prng.init(0x5ab6);
    const g = G2.from_affine(generator);
    for (0..12) |_| {
        // Random twist points: almost surely outside G2.
        const any = random_twist_point(&prng);
        const in_group = G2.from_affine(any).mul(fp.r).is_infinity();
        try testing.expectEqual(in_group, is_in_subgroup(any));
        try testing.expectEqual(in_group, is_in_subgroup_reference(any));
        // Subgroup points are accepted.
        const member = g.mul(prng.int(u256) % fp.r).to_affine();
        try testing.expect(is_in_subgroup(member));
        // Member + a cofactor-order component ([r] R lies in the cofactor part) is rejected.
        const torsion = G2.from_affine(any).mul(fp.r);
        const mixed = G2.from_affine(member).add(torsion).to_affine();
        try testing.expectEqual(torsion.is_infinity(), is_in_subgroup(mixed));
        try testing.expectEqual(is_in_subgroup_reference(mixed), is_in_subgroup(mixed));
    }
}

test "g2: seeded fuzz of group laws" {
    var prng = Prng.init(0x92);
    const g = G2.from_affine(generator);
    for (0..10) |_| {
        const a = prng.int(u256) % fp.r;
        const b = prng.int(u256) % fp.r;
        const pa = g.mul(a);
        const pb = g.mul(b);
        try testing.expect(pa.eql(g.mul_reference(a)));
        try testing.expect(pa.add(pb).eql(g.mul((a + b) % fp.r)));
        try testing.expect(pa.add(pa).eql(pa.double()));
        try testing.expect(pa.add_affine(pb.to_affine()).eql(pa.add(pb)));
        try testing.expect(is_in_subgroup(pa.to_affine()));
    }
}

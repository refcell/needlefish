//! BLS12-381 benchmark bodies, registered in `src/common/crypto/bench.zig`.
//! Each function runs `iterations` operations and returns a value derived from
//! the results so the optimizer cannot drop the work.

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const msm = @import("msm.zig");
const pairing = @import("pairing.zig");
const map = @import("map.zig");

const scalar: u256 =
    0x5f0e_1d2c_3b4a_5968_7786_95a4_b3c2_d1e0_0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0;

pub fn g1_add(iterations: u32) u64 {
    var accumulator = g1.generator.to_jacobian();
    const step = accumulator.double();
    for (0..iterations) |_| accumulator = accumulator.add(step);
    assert(accumulator.is_on_curve());
    return accumulator.x.limbs_value[0];
}

pub fn g1_mul(iterations: u32) u64 {
    var point = g1.generator.to_jacobian();
    for (0..iterations) |_| point = point.mul(scalar);
    assert(point.is_on_curve());
    return point.x.limbs_value[0];
}

pub fn g1_mul_glv(iterations: u32) u64 {
    var point = g1.generator.to_jacobian();
    for (0..iterations) |_| point = g1.mul_glv(point, scalar);
    assert(point.is_on_curve());
    return point.x.limbs_value[0];
}

pub fn g2_mul(iterations: u32) u64 {
    var point = g2.generator.to_jacobian();
    for (0..iterations) |_| point = point.mul(scalar);
    assert(point.is_on_curve());
    return point.x.c0.limbs_value[0];
}

pub fn g2_mul_gls(iterations: u32) u64 {
    var point = g2.generator.to_jacobian();
    for (0..iterations) |_| point = g2.mul_gls(point, scalar);
    assert(point.is_on_curve());
    return point.x.c0.limbs_value[0];
}

pub fn pairing_2(iterations: u32) u64 {
    const pairs = [2]pairing.Pair{
        .{ .g1 = g1.generator, .g2 = g2.generator },
        .{ .g1 = g1.generator.neg(), .g2 = g2.generator },
    };
    var valid: u64 = 0;
    for (0..iterations) |_| valid += @intFromBool(pairing.pairing_check(&pairs));
    assert(valid == iterations);
    return valid;
}

pub fn map_fp_to_g1(iterations: u32) u64 {
    var u = fields.Fp.from_int(0x1234_5678_9abc_def0);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const point = map.map_fp_to_g1(u);
        accumulator +%= point.x.limbs_value[0];
        u = u.add(fields.Fp.one);
    }
    return accumulator;
}

pub fn g1_msm_64(iterations: u32) u64 {
    var points: [64]g1.Affine = undefined;
    var scalars: [64]u256 = undefined;
    var point = g1.generator.to_jacobian();
    for (&points, &scalars, 0..) |*slot, *value, index| {
        point = point.double().add(g1.generator.to_jacobian());
        slot.* = point.to_affine();
        value.* = scalar *% (index + 1) % fields.r;
    }
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const result = msm.msm(g1.G1, &points, &scalars);
        accumulator +%= result.x.limbs_value[0];
    }
    return accumulator;
}

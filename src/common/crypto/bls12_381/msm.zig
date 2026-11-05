//! Multi-scalar multiplication sum_i [s_i] P_i with Pippenger's bucket method,
//! generic over the curve (G1 or G2).
//!
//! Scalars are recoded into signed base-2^c digits in [-2^(c-1), 2^(c-1)], so a
//! window needs 2^(c-1) buckets. Inputs are processed in chunks of at most
//! `chunk_points_max` points with stack-resident digit and bucket arrays, so the
//! memory bound is static and independent of the input length.

const std = @import("std");
const assert = std.debug.assert;

pub const chunk_points_max = 256;
const window_bits_min = 2;
const window_bits_max = 7;
const scalar_bits = 256;
const windows_max = scalar_bits / window_bits_min + 1;
const buckets_max = 1 << (window_bits_max - 1);

comptime {
    assert(std.math.log2_int(u32, chunk_points_max) - 1 <= window_bits_max);
    assert(windows_max * window_bits_min > scalar_bits);
}

/// Window width for `count` points: about log2(count) - 1, clamped.
fn window_bits(count: usize) u32 {
    assert(count > 0);
    const log = std.math.log2_int(usize, count);
    const bits: u32 = @intCast(std.math.clamp(log -| 1, window_bits_min, window_bits_max));
    assert(bits >= window_bits_min and bits <= window_bits_max);
    return bits;
}

/// Signed base-2^c recoding of a 256-bit scalar into `digits`; returns the count.
fn recode(scalar: u256, bits: u32, digits: *[windows_max]i16) u32 {
    const window_count = scalar_bits / bits + 1;
    assert(window_count <= windows_max);
    const half: i32 = @as(i32, 1) << @intCast(bits - 1);
    const mask: u256 = (@as(u256, 1) << @intCast(bits)) - 1;
    var carry: i32 = 0;
    for (0..window_count) |window| {
        const shift = window * bits;
        const chunk: i32 = if (shift >= scalar_bits)
            0
        else
            @intCast((scalar >> @intCast(shift)) & mask);
        var value = chunk + carry;
        carry = 0;
        if (value > half) {
            value -= half << 1;
            carry = 1;
        }
        digits[window] = @intCast(value);
    }
    assert(carry == 0);
    return window_count;
}

/// sum_i [scalars[i]] points[i] for any number of points.
pub fn msm(comptime C: type, points: []const C.Affine, scalars: []const u256) C {
    assert(points.len == scalars.len);
    var result = C.identity;
    var start: usize = 0;
    while (start < points.len) {
        const end = @min(points.len, start + chunk_points_max);
        result = result.add(msm_chunk(C, points[start..end], scalars[start..end]));
        start = end;
    }
    assert(start == points.len);
    return result;
}

fn msm_chunk(comptime C: type, points: []const C.Affine, scalars: []const u256) C {
    assert(points.len <= chunk_points_max);
    assert(points.len == scalars.len);
    if (points.len == 0) return C.identity;
    if (points.len == 1) return points[0].to_jacobian().mul(scalars[0]);
    const bits = window_bits(points.len);
    var digits: [chunk_points_max][windows_max]i16 = undefined;
    var window_count: u32 = 0;
    for (scalars, 0..) |scalar, index| window_count = recode(scalar, bits, &digits[index]);
    const bucket_count = @as(usize, 1) << @intCast(bits - 1);
    var buckets: [buckets_max]C = undefined;
    var result = C.identity;
    var window = window_count;
    while (window > 0) {
        window -= 1;
        for (0..bits) |_| result = result.double();
        @memset(buckets[0..bucket_count], C.identity);
        for (points, 0..) |point, index| {
            if (point.infinity) continue;
            const digit = digits[index][window];
            if (digit > 0) {
                const slot: usize = @intCast(digit - 1);
                buckets[slot] = buckets[slot].add_affine(point);
            } else if (digit < 0) {
                const slot: usize = @intCast(-digit - 1);
                buckets[slot] = buckets[slot].add_affine(point.neg());
            }
        }
        result = result.add(sum_buckets(C, buckets[0..bucket_count]));
    }
    return result;
}

/// sum_j (j + 1) buckets[j] with a running sum.
fn sum_buckets(comptime C: type, buckets: []const C) C {
    assert(buckets.len > 0);
    var running = C.identity;
    var total = C.identity;
    var index = buckets.len;
    while (index > 0) {
        index -= 1;
        running = running.add(buckets[index]);
        total = total.add(running);
    }
    return total;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");

test "msm: signed recoding reconstructs the scalar" {
    var prng = Prng.init(0x4d534d);
    for (0..50) |round| {
        const scalar: u256 = if (round == 0) std.math.maxInt(u256) else prng.int(u256);
        const bits: u32 = @intCast(window_bits_min + round % (window_bits_max - 1));
        var digits: [windows_max]i16 = undefined;
        const count = recode(scalar, bits, &digits);
        var value: i512 = 0;
        var index = count;
        while (index > 0) {
            index -= 1;
            value = (value << @intCast(bits)) + digits[index];
            try testing.expect(@abs(digits[index]) <= @as(u16, 1) << @intCast(bits - 1));
        }
        try testing.expectEqual(@as(i512, scalar), value);
    }
}

fn check_msm(comptime C: type, generator: C.Affine, count: usize, seed: u64) !void {
    var prng = Prng.init(seed);
    var points: [300]C.Affine = undefined;
    var scalars: [300]u256 = undefined;
    var expected = C.identity;
    const base = generator.to_jacobian();
    var point = base.mul(prng.int(u64) | 1);
    for (0..count) |index| {
        point = point.add(base);
        points[index] = if (index % 17 == 5) C.Affine.identity else point.to_affine();
        scalars[index] = switch (index % 11) {
            3 => 0,
            4 => std.math.maxInt(u256),
            else => prng.int(u256),
        };
        if (!points[index].infinity) {
            expected = expected.add(point.mul(scalars[index]));
        }
    }
    try testing.expect(msm(C, points[0..count], scalars[0..count]).eql(expected));
}

test "msm: G1 matches the sum of scalar multiplications" {
    for ([_]usize{ 0, 1, 2, 3, 9, 40 }, 0..) |count, seed| {
        try check_msm(g1.G1, g1.generator, count, seed);
    }
}

test "msm: G2 matches the sum of scalar multiplications" {
    for ([_]usize{ 2, 7 }, 0..) |count, seed| try check_msm(g2.G2, g2.generator, count, seed);
}

test "msm: chunking across the chunk bound" {
    try check_msm(g1.G1, g1.generator, chunk_points_max + 3, 99);
}

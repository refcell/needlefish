//! Multi-scalar multiplication sum_i [s_i] P_i with Pippenger's bucket method,
//! generic over the curve (G1 or G2).
//!
//! Scalars are read as signed base-2^c (Booth) digits in [-2^(c-1), 2^(c-1)],
//! computed statelessly from three bit ranges of the scalar, so no digit array is
//! stored and all points share one pass per window. The only memory is the bucket
//! array, statically bounded by the per-curve maximum window width.

const std = @import("std");
const assert = std.debug.assert;

/// Batch size the precompiles use to decode inputs into stack arrays.
pub const chunk_points_max = 256;
const window_bits_min = 2;
const scalar_bits = 256;

/// Widest window for curve C: 512 G1 buckets (74 KiB) or 256 G2 buckets (74 KiB).
fn window_bits_max(comptime C: type) u32 {
    return if (@sizeOf(C) > 200) 9 else 10;
}

/// Window width for `count` points: about log2(count) - 1, clamped.
fn window_bits(comptime C: type, count: usize) u32 {
    assert(count > 0);
    const log = std.math.log2_int(usize, count);
    const bits: u32 = @intCast(std.math.clamp(log -| 1, window_bits_min, window_bits_max(C)));
    assert(bits >= window_bits_min and bits <= window_bits_max(C));
    return bits;
}

fn scalar_bit(scalar: u256, index: i64) i32 {
    if (index < 0 or index >= scalar_bits) return 0;
    return @intCast((scalar >> @intCast(index)) & 1);
}

/// Booth digit `window` of width `bits`: -2^(c-1) b[(w+1)c-1] + sum_{i<c-1} 2^i b[wc+i]
/// + b[wc-1]. Over windows 0..256/c these reconstruct the scalar exactly.
fn digit_at(scalar: u256, window: u32, bits: u32) i32 {
    assert(bits >= window_bits_min and bits <= 16);
    const start: i64 = @as(i64, window) * bits;
    var low: i32 = 0;
    if (start < scalar_bits) {
        const mask: u256 = (@as(u256, 1) << @intCast(bits - 1)) - 1;
        low = @intCast((scalar >> @intCast(start)) & mask);
    }
    const top = scalar_bit(scalar, start + bits - 1);
    const digit = low + scalar_bit(scalar, start - 1) - (top << @intCast(bits - 1));
    assert(@abs(digit) <= @as(u32, 1) << @intCast(bits - 1));
    return digit;
}

fn window_count_for(bits: u32) u32 {
    return scalar_bits / bits + 1;
}

/// sum_i [scalars[i]] points[i] for any number of points.
pub fn msm(comptime C: type, points: []const C.Affine, scalars: []const u256) C {
    assert(points.len == scalars.len);
    if (points.len == 0) return C.identity;
    if (points.len == 1) return single_mul(C, points[0], scalars[0]);
    if (C == g1.G1 and points.len >= batch_affine_points_min) {
        return msm_batch_affine(C, points, scalars);
    }
    const bits = window_bits(C, points.len);
    const bucket_count = @as(usize, 1) << @intCast(bits - 1);
    var buckets: [1 << (window_bits_max(C) - 1)]C = undefined;
    var result = C.identity;
    var window = window_count_for(bits);
    while (window > 0) {
        window -= 1;
        if (!result.is_identity()) {
            for (0..bits) |_| result = result.double();
        }
        @memset(buckets[0..bucket_count], C.identity);
        for (points, scalars) |point, scalar| {
            if (point.infinity) continue;
            const digit = digit_at(scalar, window, bits);
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

/// Below this many points the per-batch inversion does not pay off.
const batch_affine_points_min = 256;
/// Pending affine bucket additions that share one field inversion.
const batch_size = 128;

/// Bucket state for batch-affine accumulation: affine buckets updated in batches
/// with one shared inversion (Montgomery's trick), plus Jacobian side buckets for
/// additions that cannot join the current batch (slot already pending, or equal x).
fn BatchAffine(comptime C: type) type {
    const F = @TypeOf(@as(C.Affine, undefined).x);
    const buckets_cap = 1 << (window_bits_max(C) - 1);
    return struct {
        const Self = @This();
        affine: [buckets_cap]C.Affine = undefined,
        side: [buckets_cap]C = undefined,
        pending_slot: [buckets_cap]bool = undefined,
        slots: [batch_size]u16 = undefined,
        addends: [batch_size]C.Affine = undefined,
        denominators: [batch_size]F = undefined,
        prefix: [batch_size]F = undefined,
        count: u32 = 0,

        fn reset(self: *Self, bucket_count: usize) void {
            assert(bucket_count <= buckets_cap);
            @memset(self.affine[0..bucket_count], C.Affine.identity);
            @memset(self.side[0..bucket_count], C.identity);
            @memset(self.pending_slot[0..bucket_count], false);
            self.count = 0;
        }

        fn add(self: *Self, slot: usize, point: C.Affine) void {
            assert(!point.infinity);
            const bucket = self.affine[slot];
            if (bucket.infinity and !self.pending_slot[slot]) {
                self.affine[slot] = point;
            } else if (self.pending_slot[slot] or bucket.x.eql(point.x)) {
                self.side[slot] = self.side[slot].add_affine(point);
            } else {
                self.pending_slot[slot] = true;
                self.slots[self.count] = @intCast(slot);
                self.addends[self.count] = point;
                self.denominators[self.count] = point.x.sub(bucket.x);
                self.count += 1;
                if (self.count == batch_size) self.flush();
            }
        }

        /// Applies every pending addition with a single inversion.
        fn flush(self: *Self) void {
            if (self.count == 0) return;
            const count = self.count;
            self.prefix[0] = self.denominators[0];
            for (1..count) |index| {
                self.prefix[index] = self.prefix[index - 1].mul(self.denominators[index]);
            }
            var inverse = self.prefix[count - 1].inverse();
            var index: usize = count;
            while (index > 0) {
                index -= 1;
                const inverse_here =
                    if (index > 0) inverse.mul(self.prefix[index - 1]) else inverse;
                inverse = inverse.mul(self.denominators[index]);
                const slot = self.slots[index];
                const bucket = self.affine[slot];
                const point = self.addends[index];
                const lambda = point.y.sub(bucket.y).mul(inverse_here);
                const x3 = lambda.square().sub(bucket.x).sub(point.x);
                const y3 = lambda.mul(bucket.x.sub(x3)).sub(bucket.y);
                self.affine[slot] = .{ .x = x3, .y = y3, .infinity = false };
                self.pending_slot[slot] = false;
            }
            self.count = 0;
        }

        fn total(self: *Self, bucket_count: usize) C {
            assert(self.count == 0);
            for (self.side[0..bucket_count], self.affine[0..bucket_count]) |*side, affine| {
                side.* = side.add_affine(affine);
            }
            return sum_buckets(C, self.side[0..bucket_count]);
        }
    };
}

fn msm_batch_affine(comptime C: type, points: []const C.Affine, scalars: []const u256) C {
    assert(points.len == scalars.len and points.len >= batch_affine_points_min);
    const bits = window_bits(C, points.len);
    const bucket_count = @as(usize, 1) << @intCast(bits - 1);
    var state: BatchAffine(C) = .{};
    var result = C.identity;
    var window = window_count_for(bits);
    while (window > 0) {
        window -= 1;
        if (!result.is_identity()) {
            for (0..bits) |_| result = result.double();
        }
        state.reset(bucket_count);
        for (points, scalars) |point, scalar| {
            if (point.infinity) continue;
            const digit = digit_at(scalar, window, bits);
            if (digit > 0) state.add(@intCast(digit - 1), point);
            if (digit < 0) state.add(@intCast(-digit - 1), point.neg());
        }
        state.flush();
        result = result.add(state.total(bucket_count));
    }
    return result;
}

/// Windows of width `bits` that cover a scalar below 2^255 (Booth digits beyond are zero).
pub fn precomputed_window_count(comptime bits: u32) u32 {
    comptime assert(bits >= window_bits_min);
    return (scalar_bits + bits - 1) / bits;
}

/// Fixed-base MSM over precomputed shifts: `shifted[i * W + w] = [2^(w * bits)] P_i` for
/// W = `precomputed_window_count(bits)`. Every window then shares one batch-affine bucket
/// pass and no doublings are needed. Scalars must be below 2^255 (field elements of Fr).
pub fn msm_precomputed(
    comptime C: type,
    comptime bits: u32,
    shifted: []const C.Affine,
    scalars: []const u256,
) C {
    comptime assert(bits >= window_bits_min and bits <= window_bits_max(C));
    const windows = precomputed_window_count(bits);
    assert(shifted.len == scalars.len * windows);
    if (scalars.len == 0) return C.identity;
    const bucket_count = @as(usize, 1) << @intCast(bits - 1);
    var state: BatchAffine(C) = .{};
    state.reset(bucket_count);
    for (scalars, 0..) |scalar, index| {
        assert(scalar >> (scalar_bits - 1) == 0);
        const row = shifted[index * windows ..][0..windows];
        for (row, 0..) |point, window| {
            if (point.infinity) continue;
            const digit = digit_at(scalar, @intCast(window), bits);
            if (digit > 0) state.add(@intCast(digit - 1), point);
            if (digit < 0) state.add(@intCast(-digit - 1), point.neg());
        }
    }
    state.flush();
    return state.total(bucket_count);
}

/// Fills `out[w] = [2^(w * bits)] point` for every precomputed window.
pub fn precompute_shifts(
    comptime C: type,
    comptime bits: u32,
    point: C.Affine,
    out: *[precomputed_window_count(bits)]C.Affine,
) void {
    const F = @TypeOf(point.x);
    const windows = comptime precomputed_window_count(bits);
    var jacobian: [windows]C = undefined;
    var scratch: [windows]F = undefined;
    var current = point.to_jacobian();
    for (&jacobian) |*slot| {
        slot.* = current;
        for (0..bits) |_| current = current.double();
    }
    C.batch_to_affine(&jacobian, out, &scratch);
    assert(out[0].eql(point));
    assert(windows * bits >= scalar_bits);
}

/// One point: use the endomorphism-accelerated multiplication. MSM inputs are in the
/// order-r subgroup (the precompiles check it), which those methods require.
fn single_mul(comptime C: type, point: C.Affine, scalar: u256) C {
    if (C == g1.G1) return g1.mul_glv(point.to_jacobian(), scalar);
    if (C == g2.G2) return g2.mul_gls(point.to_jacobian(), scalar);
    return point.to_jacobian().mul(scalar);
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
        const bits: u32 = @intCast(window_bits_min + round % 9);
        var value: i512 = 0;
        var index = window_count_for(bits);
        while (index > 0) {
            index -= 1;
            value = (value << @intCast(bits)) + digit_at(scalar, index, bits);
        }
        try testing.expectEqual(@as(i512, scalar), value);
    }
}

const max_scalar: u256 = std.math.maxInt(u256);

fn check_msm(
    comptime C: type,
    generator: C.Affine,
    count: usize,
    seed: u64,
    scalar_mask: u256,
) !void {
    var prng = Prng.init(seed);
    var points: [320]C.Affine = undefined;
    var scalars: [320]u256 = undefined;
    var expected = C.identity;
    const base = generator.to_jacobian();
    var point = base.mul(prng.int(u64) | 1);
    for (0..count) |index| {
        point = point.add(base);
        points[index] = if (index % 17 == 5) C.Affine.identity else point.to_affine();
        scalars[index] = switch (index % 11) {
            3 => 0,
            4 => scalar_mask,
            else => prng.int(u256) & scalar_mask,
        };
        if (!points[index].infinity) {
            expected = expected.add(point.mul(scalars[index]));
        }
    }
    try testing.expect(msm(C, points[0..count], scalars[0..count]).eql(expected));
}

test "msm: G1 matches the sum of scalar multiplications" {
    for ([_]usize{ 0, 1, 2, 3, 9, 40 }, 0..) |count, seed| {
        try check_msm(g1.G1, g1.generator, count, seed, max_scalar);
    }
}

test "msm: G2 matches the sum of scalar multiplications" {
    for ([_]usize{ 2, 7 }, 0..) |count, seed| {
        try check_msm(g2.G2, g2.generator, count, seed, max_scalar);
    }
}

test "msm: many points with a wide window" {
    // Short scalars keep the reference scalar multiplications cheap in Debug.
    try check_msm(g1.G1, g1.generator, chunk_points_max + 3, 99, std.math.maxInt(u24));
    // Tiny scalars force bucket collisions, equal-x additions and cancellations.
    try check_msm(g1.G1, g1.generator, chunk_points_max + 40, 7, 3);
}

test "msm: precomputed fixed-base msm matches msm (seeded)" {
    const C = g1.G1;
    const bits = 8;
    const windows = comptime precomputed_window_count(bits);
    var prng = Prng.init(0x46495845);
    var points: [70]C.Affine = undefined;
    var scalars: [70]u256 = undefined;
    var shifted: [70 * windows]C.Affine = undefined;
    const base = g1.generator.to_jacobian();
    for (0..70) |index| {
        points[index] = if (index % 23 == 7)
            C.Affine.identity
        else
            base.mul(prng.int(u64) | 1).to_affine();
        scalars[index] = switch (index % 5) {
            0 => 0,
            1 => (@as(u256, 1) << 255) - 1,
            2 => prng.int(u8),
            else => prng.int(u256) >> 1,
        };
        precompute_shifts(C, bits, points[index], shifted[index * windows ..][0..windows]);
    }
    for ([_]usize{ 0, 1, 2, 9, 64, 70 }) |count| {
        const expected = msm(C, points[0..count], scalars[0..count]);
        const actual = msm_precomputed(C, bits, shifted[0 .. count * windows], scalars[0..count]);
        try testing.expect(actual.eql(expected));
    }
    // Repeated points force side-bucket (equal x) additions.
    @memset(scalars[0..64], 3);
    for (1..64) |index| @memcpy(shifted[index * windows ..][0..windows], shifted[0..windows]);
    const actual = msm_precomputed(C, bits, shifted[0 .. 64 * windows], scalars[0..64]);
    try testing.expect(actual.eql(points[0].to_jacobian().mul(3 * 64)));
}

fn fuzz_precomputed(_: void, smith: *testing.Smith) anyerror!void {
    const C = g1.G1;
    const bits = 9;
    const windows = comptime precomputed_window_count(bits);
    var points: [6]C.Affine = undefined;
    var scalars: [6]u256 = undefined;
    var shifted: [6 * windows]C.Affine = undefined;
    const count: usize = smith.value(u8) % 7;
    const base = g1.generator.to_jacobian();
    for (0..count) |index| {
        const multiplier = smith.value(u16);
        points[index] = base.mul(multiplier).to_affine(); // 0 gives the identity.
        scalars[index] = smith.value(u256) >> 1;
        precompute_shifts(C, bits, points[index], shifted[index * windows ..][0..windows]);
    }
    const expected = msm(C, points[0..count], scalars[0..count]);
    const actual = msm_precomputed(C, bits, shifted[0 .. count * windows], scalars[0..count]);
    try testing.expect(actual.eql(expected));
}

test "msm: coverage-guided fuzz of msm_precomputed vs msm" {
    try testing.fuzz({}, fuzz_precomputed, .{});
}

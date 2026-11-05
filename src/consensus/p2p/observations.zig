//! Plain (non-atomic) histogram buckets the service fills on hot paths; `Metrics.update`
//! copies them into `metrics.Histogram` cells. Same semantics as `metrics.Histogram.observe`:
//! per-bucket non-cumulative counts, values above the last bound only in `count`, and the
//! sum in nanounits with non-positive values contributing zero.

const std = @import("std");
const assert = std.debug.assert;

/// Gossipsub peer score buckets (scores go negative for misbehaving peers).
pub const score_bounds = [_]f64{ -100, -50, -20, -10, -5, -1, 0, 1, 5, 10, 20, 50, 100 };

/// Connection duration buckets in seconds: 1 s .. 1 day.
pub const duration_bounds_s = [_]f64{
    1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200, 21600, 86400,
};

pub fn Buckets(comptime bounds: []const f64) type {
    comptime {
        assert(bounds.len > 0 and bounds.len <= 16);
        for (bounds[1..], bounds[0 .. bounds.len - 1]) |upper, lower| assert(upper > lower);
    }
    return struct {
        const Self = @This();
        pub const upper_bounds = bounds;

        counts: [bounds.len]u64 = @splat(0),
        count: u64 = 0,
        sum_nano: u64 = 0,

        pub fn observe(self: *Self, value: f64) void {
            assert(!std.math.isNan(value));
            for (bounds, 0..) |bound, index| {
                if (value <= bound) {
                    self.counts[index] += 1;
                    break;
                }
            }
            self.count += 1;
            const nano_max: f64 = 4.611686018427388e18;
            const nano = if (value <= 0) 0 else @min(value * 1e9, nano_max);
            self.sum_nano +|= @intFromFloat(nano);
            assert(self.count > 0);
        }

        pub fn observe_ns(self: *Self, duration_ns: u64) void {
            self.observe(@as(f64, @floatFromInt(duration_ns)) / 1e9);
        }
    };
}

pub const Scores = Buckets(&score_bounds);
pub const Durations = Buckets(&duration_bounds_s);

const testing = std.testing;

test "observations: buckets, overflow, and sums" {
    var scores: Scores = .{};
    scores.observe(-200); // Below the first bound: first bucket.
    scores.observe(0);
    scores.observe(0.5);
    scores.observe(1000); // Above the last bound: count only.
    try testing.expectEqual(@as(u64, 4), scores.count);
    try testing.expectEqual(@as(u64, 1), scores.counts[0]);
    try testing.expectEqual(@as(u64, 1), scores.counts[6]);
    try testing.expectEqual(@as(u64, 1), scores.counts[7]);
    var total: u64 = 0;
    for (scores.counts) |count| total += count;
    try testing.expectEqual(@as(u64, 3), total);
    try testing.expectEqual(@as(u64, 1000_500_000_000), scores.sum_nano);
    var durations: Durations = .{};
    durations.observe_ns(90 * std.time.ns_per_s);
    try testing.expectEqual(@as(u64, 1), durations.counts[5]); // <= 300 s.
}

test "observations: seeded fuzz keeps count >= bucket total" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x0b5e);
    const random = prng.random();
    var scores: Scores = .{};
    for (0..2000) |_| {
        const value = (random.float(f64) - 0.5) * 400;
        scores.observe(value);
        var total: u64 = 0;
        for (scores.counts) |count| total += count;
        try testing.expect(total <= scores.count);
    }
    try testing.expectEqual(@as(u64, 2000), scores.count);
}

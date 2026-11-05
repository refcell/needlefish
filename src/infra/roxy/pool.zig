//! Upstream pool: round-robin selection over healthy upstreams with passive health checks.
//!
//! IO-free state machine: the proxy reports each attempt's outcome with the current time.
//! `failures_to_eject` consecutive failures eject an upstream for a backoff that doubles with
//! every ejection in a row (`backoff_initial_ns` .. `backoff_max_ns`). When the backoff ends
//! the upstream is re-admitted on probation: one more failure ejects it again with the next
//! backoff, one success clears its record. If every upstream is ejected, selection fails
//! open to the one whose ejection ends first, so the proxy degrades instead of refusing all
//! traffic; a success there re-admits the upstream at once.

const std = @import("std");
const assert = std.debug.assert;

pub const upstreams_max = 64;
/// Bit `i` set: upstream `i`.
pub const Mask = u64;
comptime {
    assert(@bitSizeOf(Mask) >= upstreams_max);
}
/// Backoff doubles at most this many times.
const backoff_shift_max = 20;

pub const Options = struct {
    failures_to_eject: u32 = 3,
    backoff_initial_ns: u64 = 1 * std.time.ns_per_s,
    backoff_max_ns: u64 = 60 * std.time.ns_per_s,
};

pub const Upstream = struct {
    consecutive_failures: u32 = 0,
    /// Ejections in a row without a success since; drives the backoff exponent.
    streak: u32 = 0,
    /// Ejected while `now < ejected_until_ns`.
    ejected_until_ns: u64 = 0,
    /// Re-admitted after an ejection and not yet successful.
    probation: bool = false,
    failures_total: u64 = 0,
    ejections_total: u64 = 0,
};

pub const Selection = union(enum) {
    upstream: u32,
    /// The chosen upstream has no free capacity (`busy`); try again later.
    wait,
    /// Every upstream is excluded.
    exhausted,
};

pub const Pool = struct {
    options: Options,
    upstreams: [upstreams_max]Upstream = @splat(.{}),
    count: u32,
    /// Round-robin cursor: the next upstream to consider first.
    cursor: u32 = 0,

    pub fn init(count: u32, options: Options) Pool {
        assert(count > 0 and count <= upstreams_max);
        assert(options.failures_to_eject > 0);
        assert(options.backoff_initial_ns > 0);
        assert(options.backoff_initial_ns <= options.backoff_max_ns);
        return .{ .options = options, .count = count };
    }

    pub fn ejected(pool: *const Pool, index: u32, now_ns: u64) bool {
        assert(index < pool.count);
        return now_ns < pool.upstreams[index].ejected_until_ns;
    }

    /// True when at least one upstream is admitted (not ejected).
    pub fn any_admitted(pool: *const Pool, now_ns: u64) bool {
        assert(pool.count > 0);
        for (0..pool.count) |index| {
            if (!pool.ejected(@intCast(index), now_ns)) return true;
        }
        return false;
    }

    /// Picks the next upstream outside `excluded`. Admitted upstreams are tried round-robin,
    /// skipping `busy` ones; with none admitted, the eligible upstream whose ejection ends
    /// first is used. `.wait` means the pick is busy.
    pub fn select(pool: *Pool, now_ns: u64, excluded: Mask, busy: Mask) Selection {
        assert(pool.cursor < pool.count);
        const eligible = mask_all(pool.count) & ~excluded;
        if (eligible == 0) return .exhausted;
        var admitted_seen = false;
        for (0..pool.count) |offset| {
            const index: u32 = @intCast((pool.cursor + offset) % pool.count);
            if (eligible & bit(index) == 0) continue;
            if (pool.ejected(index, now_ns)) continue;
            admitted_seen = true;
            if (busy & bit(index) != 0) continue;
            pool.cursor = (index + 1) % pool.count;
            return .{ .upstream = index };
        }
        if (admitted_seen) return .wait;
        const index = pool.earliest_return(eligible);
        assert(pool.ejected(index, now_ns));
        if (busy & bit(index) != 0) return .wait;
        return .{ .upstream = index };
    }

    fn earliest_return(pool: *const Pool, eligible: Mask) u32 {
        assert(eligible != 0);
        var best: ?u32 = null;
        for (0..pool.count) |offset| {
            const index: u32 = @intCast(offset);
            if (eligible & bit(index) == 0) continue;
            const until_ns = pool.upstreams[index].ejected_until_ns;
            if (best == null or until_ns < pool.upstreams[best.?].ejected_until_ns) best = index;
        }
        return best.?;
    }

    pub fn record_success(pool: *Pool, index: u32) void {
        assert(index < pool.count);
        const upstream = &pool.upstreams[index];
        upstream.consecutive_failures = 0;
        upstream.streak = 0;
        upstream.probation = false;
        // A success while ejected (fail-open traffic) proves it healthy: re-admit at once.
        upstream.ejected_until_ns = 0;
        assert(upstream.consecutive_failures == 0);
    }

    /// Counts a failure; returns true if the upstream was (re-)ejected by it.
    pub fn record_failure(pool: *Pool, index: u32, now_ns: u64) bool {
        assert(index < pool.count);
        const upstream = &pool.upstreams[index];
        upstream.failures_total += 1;
        upstream.consecutive_failures +|= 1;
        // Ejected (used by fail-open) or on probation: one failure ejects again.
        const should_eject = pool.ejected(index, now_ns) or upstream.probation or
            upstream.consecutive_failures >= pool.options.failures_to_eject;
        if (!should_eject) return false;
        pool.eject(index, now_ns);
        assert(pool.ejected(index, now_ns));
        return true;
    }

    fn eject(pool: *Pool, index: u32, now_ns: u64) void {
        const upstream = &pool.upstreams[index];
        const duration_ns = pool.backoff_ns(upstream.streak);
        assert(duration_ns >= pool.options.backoff_initial_ns);
        assert(duration_ns <= pool.options.backoff_max_ns);
        upstream.ejected_until_ns = now_ns +| duration_ns;
        upstream.streak = @min(upstream.streak + 1, backoff_shift_max);
        upstream.consecutive_failures = 0;
        upstream.probation = true;
        upstream.ejections_total += 1;
    }

    pub fn backoff_ns(pool: *const Pool, streak: u32) u64 {
        const shift: u6 = @intCast(@min(streak, backoff_shift_max));
        const scaled = std.math.shlExact(u64, pool.options.backoff_initial_ns, shift) catch
            return pool.options.backoff_max_ns;
        return @min(scaled, pool.options.backoff_max_ns);
    }
};

/// The mask of upstreams `0..count`.
pub fn mask_all(count: u32) Mask {
    assert(count > 0 and count <= upstreams_max);
    if (count == upstreams_max) return ~@as(Mask, 0);
    return (@as(Mask, 1) << @intCast(count)) - 1;
}

pub fn bit(index: u32) Mask {
    assert(index < upstreams_max);
    return @as(Mask, 1) << @intCast(index);
}

const testing = std.testing;
const s = std.time.ns_per_s;

test "pool: round-robin over admitted upstreams, skipping busy ones" {
    var pool = Pool.init(3, .{});
    try testing.expectEqual(Selection{ .upstream = 0 }, pool.select(0, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 1 }, pool.select(0, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 2 }, pool.select(0, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 0 }, pool.select(0, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 2 }, pool.select(0, bit(1), 0));
    try testing.expectEqual(Selection{ .upstream = 1 }, pool.select(0, 0, bit(0) | bit(2)));
    try testing.expectEqual(Selection.wait, pool.select(0, 0, 0b111));
    try testing.expectEqual(Selection.exhausted, pool.select(0, 0b111, 0));
}

test "pool: ejection, backoff growth, probation, and recovery" {
    var pool = Pool.init(2, .{
        .failures_to_eject = 2,
        .backoff_initial_ns = s,
        .backoff_max_ns = 3 * s,
    });
    try testing.expect(!pool.record_failure(0, 0));
    try testing.expect(pool.record_failure(0, 0));
    try testing.expect(pool.ejected(0, s - 1));
    try testing.expect(!pool.ejected(0, s));
    // Ejected: selection skips it.
    try testing.expectEqual(Selection{ .upstream = 1 }, pool.select(0, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 1 }, pool.select(0, 0, 0));
    // Probation: one failure re-ejects with double backoff, capped.
    try testing.expect(pool.record_failure(0, s));
    try testing.expect(pool.ejected(0, 3 * s - 1));
    try testing.expect(pool.record_failure(0, 3 * s));
    try testing.expect(!pool.ejected(0, 6 * s));
    try testing.expectEqual(@as(u64, 3), pool.upstreams[0].ejections_total);
    pool.record_success(0);
    try testing.expect(!pool.record_failure(0, 7 * s));
    try testing.expect(pool.any_admitted(7 * s));
}

test "pool: fails open to the upstream whose ejection ends first" {
    var pool = Pool.init(3, .{ .failures_to_eject = 1, .backoff_initial_ns = 10 * s });
    _ = pool.record_failure(0, 2 * s);
    _ = pool.record_failure(1, 0);
    _ = pool.record_failure(2, 1 * s);
    try testing.expect(!pool.any_admitted(3 * s));
    try testing.expectEqual(Selection{ .upstream = 1 }, pool.select(3 * s, 0, 0));
    try testing.expectEqual(Selection{ .upstream = 2 }, pool.select(3 * s, bit(1), 0));
    try testing.expectEqual(Selection.wait, pool.select(3 * s, 0, bit(1)));
}

/// Drives a pool with arbitrary operations and checks its invariants after each.
fn check_operations(bytes: []const u8) !void {
    var pool = Pool.init(@as(u32, @intCast(bytes.len % 5)) + 1, .{
        .failures_to_eject = 2,
        .backoff_initial_ns = 100,
        .backoff_max_ns = 1000,
    });
    var now_ns: u64 = 0;
    for (bytes) |byte| {
        const index: u32 = (byte >> 3) % pool.count;
        switch (byte & 7) {
            0, 1 => now_ns += byte,
            2 => pool.record_success(index),
            3, 4 => _ = pool.record_failure(index, now_ns),
            else => {
                const excluded: Mask = byte >> 5;
                switch (pool.select(now_ns, excluded, @as(Mask, byte) >> 6)) {
                    .upstream => |chosen| {
                        try testing.expect(chosen < pool.count);
                        try testing.expect(excluded & bit(chosen) == 0);
                        // Never an ejected upstream while an eligible admitted one is idle.
                        if (pool.ejected(chosen, now_ns)) {
                            for (0..pool.count) |other| {
                                const o: u32 = @intCast(other);
                                if (excluded & bit(o) != 0) continue;
                                try testing.expect(pool.ejected(o, now_ns));
                            }
                        }
                    },
                    .wait, .exhausted => {},
                }
            },
        }
        for (pool.upstreams[0..pool.count]) |upstream| {
            try testing.expect(upstream.ejected_until_ns <= now_ns + 1000);
            try testing.expect(upstream.consecutive_failures < 2);
            try testing.expect(upstream.ejections_total <= upstream.failures_total);
        }
        try testing.expect(pool.cursor < pool.count);
    }
}

test "pool: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x9001);
    var bytes: [512]u8 = undefined;
    for (0..500) |_| {
        const size = prng.below(bytes.len);
        prng.fill(bytes[0..size]);
        try check_operations(bytes[0..size]);
    }
}

fn fuzz_pool(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var bytes: [1024]u8 = undefined;
    const size = smith.slice(&bytes);
    try check_operations(bytes[0..size]);
}

test "pool: fuzz operations" {
    try testing.fuzz({}, fuzz_pool, .{});
}

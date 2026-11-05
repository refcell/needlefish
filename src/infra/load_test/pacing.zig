//! Open-loop pacing (base/base `load-tests/src/runner/pacing.rs`, steady submission).
//!
//! The target is `rate_per_s` sends per second measured from the start, independent of how
//! fast the chain includes them (open loop: a slow chain shows up as latency, not as a
//! lower offered load). A late cycle may catch up, but by at most `catchup_multiplier`
//! times the target rate over the time since the previous cycle, so a backlog left by a
//! stall drains gradually instead of in one burst (base/base `STEADY_CATCHUP_RATE = 2`).

const std = @import("std");
const assert = std.debug.assert;

pub const Pacer = struct {
    rate_per_s: u32,
    catchup_multiplier: u32 = 2,
    start_ms: u64,
    last_ms: u64,
    sent: u64 = 0,

    pub fn init(rate_per_s: u32, now_ms: u64) Pacer {
        assert(rate_per_s > 0);
        return .{ .rate_per_s = rate_per_s, .start_ms = now_ms, .last_ms = now_ms };
    }

    /// Sends owed now. Call `record_sent` with how many actually went out.
    pub fn due(pacer: *Pacer, now_ms: u64) u64 {
        assert(now_ms >= pacer.last_ms);
        const elapsed_ms = now_ms - pacer.start_ms;
        const target = @as(u64, pacer.rate_per_s) * elapsed_ms / 1000;
        const owed = target -| pacer.sent;
        const window_ms = now_ms - pacer.last_ms;
        // Round the burst cap up so short cycles at low rates still make progress.
        const rate_cap = @as(u64, pacer.rate_per_s) * pacer.catchup_multiplier;
        const cap = (rate_cap * window_ms + 999) / 1000;
        pacer.last_ms = now_ms;
        const result = @min(owed, cap);
        assert(result <= owed);
        return result;
    }

    pub fn record_sent(pacer: *Pacer, count: u64) void {
        pacer.sent += count;
        const elapsed_ms = pacer.last_ms - pacer.start_ms;
        assert(pacer.sent <= @as(u64, pacer.rate_per_s) * elapsed_ms / 1000);
    }
};

const testing = std.testing;

test "pacing: steady rate" {
    var pacer = Pacer.init(10, 1_000);
    var total: u64 = 0;
    var now_ms: u64 = 1_000;
    for (0..100) |_| {
        now_ms += 100;
        const count = pacer.due(now_ms);
        pacer.record_sent(count);
        total += count;
    }
    try testing.expectEqual(@as(u64, 100), total);
}

test "pacing: a stall catches up at twice the rate, not in one burst" {
    var pacer = Pacer.init(10, 0);
    var now_ms: u64 = 0;
    // Cycles run every second but nothing goes out for 10 s (every sender was full).
    for (0..10) |_| {
        now_ms += 1_000;
        _ = pacer.due(now_ms);
        pacer.record_sent(0);
    }
    // The backlog of 100 drains at 2x rate per cycle, never in one burst.
    var seconds: u32 = 0;
    while (pacer.sent < pacer.rate_per_s * now_ms / 1000 and seconds < 30) : (seconds += 1) {
        now_ms += 1_000;
        const count = pacer.due(now_ms);
        try testing.expect(count <= 20);
        pacer.record_sent(count);
    }
    // 100 owed, 20 per second against 10 new per second: 10 seconds.
    try testing.expectEqual(@as(u32, 10), seconds);
}

fn check_bounds(random: std.Random) !void {
    var pacer = Pacer.init(random.intRangeAtMost(u32, 1, 5_000), 0);
    var now_ms: u64 = 0;
    for (0..200) |_| {
        const step_ms = random.uintAtMost(u64, 2_000);
        now_ms += step_ms;
        const count = pacer.due(now_ms);
        try testing.expect(count <= (@as(u64, pacer.rate_per_s) * 2 * step_ms + 999) / 1000);
        const sent = random.uintAtMost(u64, count);
        pacer.record_sent(sent);
        // Never ahead of the open-loop target.
        try testing.expect(pacer.sent <= @as(u64, pacer.rate_per_s) * now_ms / 1000);
    }
}

test "pacing: seeded fuzz bounds" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x9ace);
    for (0..200) |_| try check_bounds(prng.random());
}

test "pacing: fuzz bounds" {
    try testing.fuzz({}, fuzz_bounds, .{});
}

fn fuzz_bounds(_: void, smith: *testing.Smith) anyerror!void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    try check_bounds(prng.random());
}

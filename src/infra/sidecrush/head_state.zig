//! Block-production health classification (base/base `sidecrush/src/healthcheck`).
//!
//! With 200 ms blocks, header timestamps (whole seconds) are too coarse to measure block
//! age, so age is the local monotonic time since the head number last advanced (base/base
//! `HeadState`, its `newHeads` mode); here the heads come from polling `latest`. A failed
//! poll is `error`. A new instance reports healthy until it first sees a head whose
//! timestamp lags the wall clock by at most the grace period plus one second (timestamp
//! rounding), so a node still syncing is not reported stalled.

const std = @import("std");
const assert = std.debug.assert;

pub const State = enum(u8) {
    healthy = 0,
    delayed = 1,
    unhealthy = 2,
    @"error" = 3,
};

pub const Config = struct {
    /// base/base defaults.
    grace_ms: u64 = 2_000,
    unhealthy_ms: u64 = 3_000,

    pub fn valid(config: Config) bool {
        return config.grace_ms > 0 and config.unhealthy_ms > config.grace_ms;
    }
};

pub const HeadState = struct {
    connected: bool = false,
    /// Baseline for the age until a head arrives; never moved, so a node that never produces
    /// a head stays stalled.
    first_connected_ms: ?u64 = null,
    last_number: ?u64 = null,
    last_seen_ms: ?u64 = null,
    new_instance: bool,

    pub fn init(new_instance: bool) HeadState {
        return .{ .new_instance = new_instance };
    }

    /// A successful poll returned `number` with a header that lags the wall clock by
    /// `header_lag_ms`. Returns true when this took the node out of new-instance mode.
    pub fn on_head(
        state: *HeadState,
        config: Config,
        number: u64,
        header_lag_ms: u64,
        now_ms: u64,
    ) bool {
        assert(config.valid());
        state.connected = true;
        if (state.first_connected_ms == null) state.first_connected_ms = now_ms;
        // Polling can replay the same head; only an advancing number refreshes the age.
        if (state.last_number) |last| if (number <= last) return false;
        state.last_number = number;
        state.last_seen_ms = now_ms;
        if (state.new_instance and header_lag_ms <= config.grace_ms +| 1_000) {
            state.new_instance = false;
            return true;
        }
        assert(state.last_seen_ms != null);
        return false;
    }

    pub fn on_failure(state: *HeadState) void {
        state.connected = false;
        assert(!state.connected);
    }

    /// Milliseconds since the last advancing head (or the first poll), null before any.
    pub fn head_age_ms(state: *const HeadState, now_ms: u64) ?u64 {
        const since = state.last_seen_ms orelse state.first_connected_ms orelse return null;
        return now_ms -| since;
    }

    pub fn classify(state: *const HeadState, config: Config, now_ms: u64) State {
        assert(config.valid());
        if (!state.connected) return .@"error";
        if (state.new_instance) return .healthy;
        const age_ms = state.head_age_ms(now_ms) orelse return .healthy;
        if (age_ms >= config.unhealthy_ms) return .unhealthy;
        if (age_ms > config.grace_ms) return .delayed;
        return .healthy;
    }
};

const testing = std.testing;

test "head state: healthy, delayed, unhealthy, error" {
    const config: Config = .{};
    var state = HeadState.init(false);
    try testing.expectEqual(State.@"error", state.classify(config, 0));
    _ = state.on_head(config, 10, 0, 1_000);
    try testing.expectEqual(State.healthy, state.classify(config, 1_200));
    // The same head polled again does not refresh the age.
    _ = state.on_head(config, 10, 0, 3_000);
    try testing.expectEqual(State.delayed, state.classify(config, 3_500));
    try testing.expectEqual(State.unhealthy, state.classify(config, 4_000));
    _ = state.on_head(config, 11, 0, 4_100);
    try testing.expectEqual(State.healthy, state.classify(config, 4_200));
    state.on_failure();
    try testing.expectEqual(State.@"error", state.classify(config, 4_300));
}

test "head state: a new instance is healthy until it reaches the tip" {
    const config: Config = .{};
    var state = HeadState.init(true);
    // Syncing: heads 60 s behind the wall clock, and then a stall.
    try testing.expect(!state.on_head(config, 1, 60_000, 0));
    try testing.expectEqual(State.healthy, state.classify(config, 10_000));
    // Caught up within grace + 1 s rounding.
    try testing.expect(state.on_head(config, 2, 2_900, 10_000));
    try testing.expectEqual(State.unhealthy, state.classify(config, 13_000));
}

test "head state: a node that never produces a head stays stalled" {
    const config: Config = .{};
    var state = HeadState.init(false);
    _ = state.on_head(config, 5, 0, 0);
    state.on_failure();
    _ = state.on_head(config, 5, 0, 10_000); // Reconnected, same head.
    try testing.expectEqual(State.unhealthy, state.classify(config, 10_000));
}

fn check_sequence(random: std.Random) !void {
    const grace_ms = random.intRangeAtMost(u64, 1, 5_000);
    const config: Config = .{
        .grace_ms = grace_ms,
        .unhealthy_ms = grace_ms + random.intRangeAtMost(u64, 1, 5_000),
    };
    var state = HeadState.init(random.boolean());
    var now_ms: u64 = 0;
    var number: u64 = 0;
    for (0..200) |_| {
        now_ms += random.uintAtMost(u64, 1_000);
        if (random.uintLessThan(u8, 8) == 0) {
            state.on_failure();
            try testing.expectEqual(State.@"error", state.classify(config, now_ms));
            continue;
        }
        if (random.boolean()) number += 1;
        const lag_ms = random.uintAtMost(u64, 10_000);
        const advanced = state.last_number == null or number > state.last_number.?;
        _ = state.on_head(config, number, lag_ms, now_ms);
        const result = state.classify(config, now_ms);
        // A fresh advancing head is always healthy at the moment it arrives.
        if (advanced) try testing.expectEqual(State.healthy, result);
        try testing.expect(result != .@"error");
    }
}

test "head state: seeded fuzz invariants" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x51de);
    for (0..300) |_| try check_sequence(prng.random());
}

test "head state: fuzz invariants" {
    try testing.fuzz({}, fuzz_sequence, .{});
}

fn fuzz_sequence(_: void, smith: *testing.Smith) anyerror!void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    try check_sequence(prng.random());
}

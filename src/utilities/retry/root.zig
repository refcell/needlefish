//! Exponential backoff with jitter, deterministic under simulation.
//!
//! Mirrors base/base `RetryConfig`: bounded (`max_attempts` retries after the first call) or
//! unbounded, with an initial delay that doubles up to `max_delay`, both clamped to at least
//! 1 ms. Jitter comes from a seeded SplitMix64 state owned by the `Backoff`, never from OS
//! randomness, so the same seed yields the same delays in the simulator. The caller waits
//! with its IO's `timeout`; this module only computes delays.

const std = @import("std");
const assert = std.debug.assert;

pub const min_delay_ns: u64 = std.time.ns_per_ms;

pub const Config = struct {
    /// Retries after the initial call; `null` retries forever.
    max_attempts: ?u32,
    initial_delay_ns: u64,
    max_delay_ns: u64,
    jitter: bool = true,

    /// base/base defaults: 5 retries, 100 ms initial, 10 s max.
    pub const bounded_default: Config = .{
        .max_attempts = 5,
        .initial_delay_ns = 100 * std.time.ns_per_ms,
        .max_delay_ns = 10 * std.time.ns_per_s,
    };

    /// base/base unbounded defaults: 250 ms initial, 30 s max.
    pub const unbounded_default: Config = .{
        .max_attempts = null,
        .initial_delay_ns = 250 * std.time.ns_per_ms,
        .max_delay_ns = 30 * std.time.ns_per_s,
    };

    pub fn normalized_max_delay_ns(config: Config) u64 {
        return @max(config.max_delay_ns, min_delay_ns);
    }

    pub fn normalized_initial_delay_ns(config: Config) u64 {
        return @min(@max(config.initial_delay_ns, min_delay_ns), config.normalized_max_delay_ns());
    }
};

pub const Backoff = struct {
    config: Config,
    /// Retries handed out so far.
    attempts: u32 = 0,
    current_ns: u64,
    random_state: u64,

    pub fn init(config: Config, seed: u64) Backoff {
        return .{
            .config = config,
            .current_ns = config.normalized_initial_delay_ns(),
            .random_state = seed,
        };
    }

    /// The delay before the next retry, or `null` when retries are exhausted.
    pub fn next_delay_ns(backoff: *Backoff) ?u64 {
        if (backoff.config.max_attempts) |max| {
            if (backoff.attempts >= max) return null;
        }
        backoff.attempts +|= 1;
        const base = backoff.current_ns;
        const max_ns = backoff.config.normalized_max_delay_ns();
        assert(base >= min_delay_ns and base <= max_ns);
        backoff.current_ns = @min(base *| 2, max_ns);
        if (!backoff.config.jitter) return base;
        // Add up to one base delay of jitter, keeping the total at or below the max delay.
        const jitter = backoff.next_random() % base;
        const delay = @min(base + jitter, max_ns);
        assert(delay >= base);
        return delay;
    }

    /// Restarts the schedule after a success.
    pub fn reset(backoff: *Backoff) void {
        backoff.attempts = 0;
        backoff.current_ns = backoff.config.normalized_initial_delay_ns();
    }

    fn next_random(backoff: *Backoff) u64 {
        backoff.random_state +%= 0x9e3779b97f4a7c15;
        var z = backoff.random_state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }
};

test "retry: bounded schedule without jitter" {
    var config = Config.bounded_default;
    config.jitter = false;
    var backoff = Backoff.init(config, 0);
    const ms = std.time.ns_per_ms;
    const expected = [_]u64{ 100 * ms, 200 * ms, 400 * ms, 800 * ms, 1600 * ms };
    for (expected) |delay| try std.testing.expectEqual(@as(?u64, delay), backoff.next_delay_ns());
    try std.testing.expectEqual(@as(?u64, null), backoff.next_delay_ns());
    backoff.reset();
    try std.testing.expectEqual(@as(?u64, 100 * ms), backoff.next_delay_ns());
}

test "retry: normalization and caps" {
    const zero: Config = .{ .max_attempts = null, .initial_delay_ns = 0, .max_delay_ns = 0 };
    try std.testing.expectEqual(min_delay_ns, zero.normalized_initial_delay_ns());
    const inverted: Config = .{ .max_attempts = 1, .initial_delay_ns = 50, .max_delay_ns = 10 };
    try std.testing.expectEqual(min_delay_ns, inverted.normalized_max_delay_ns());
    var backoff = Backoff.init(Config.unbounded_default, 7);
    for (0..200) |_| {
        const delay = backoff.next_delay_ns().?;
        try std.testing.expect(delay >= min_delay_ns and delay <= 30 * std.time.ns_per_s);
    }
}

test "retry: jitter is deterministic per seed and bounded" {
    var a = Backoff.init(Config.bounded_default, 42);
    var b = Backoff.init(Config.bounded_default, 42);
    var c = Backoff.init(Config.bounded_default, 43);
    var differs = false;
    var base: u64 = 100 * std.time.ns_per_ms;
    while (a.next_delay_ns()) |delay| {
        try std.testing.expectEqual(@as(?u64, delay), b.next_delay_ns());
        const other = c.next_delay_ns().?;
        differs = differs or other != delay;
        try std.testing.expect(delay >= base and delay < 2 * base);
        base *= 2;
    }
    try std.testing.expect(differs);
}

//! Time on top of the injected IO: a monotonic-guarded clock, deadlines, and a drift-free
//! periodic ticker.
//!
//! Library code never reads the OS clock. It reads `Clock(IO)`, which wraps the IO backend's
//! `now_monotonic_ns` / `now_realtime_ns`; under `SimIo` that is simulated time, so a seed
//! replays exactly. `ManualClock` is a minimal clock for unit tests of pure state machines
//! that need time but no IO.

const std = @import("std");
const assert = std.debug.assert;

pub const ns_per_us: u64 = std.time.ns_per_us;
pub const ns_per_ms: u64 = std.time.ns_per_ms;
pub const ns_per_s: u64 = std.time.ns_per_s;

/// Wraps an IO backend (or anything with `now_monotonic_ns` and `now_realtime_ns`).
/// Monotonic readings never go backwards, even if the backend misbehaves.
pub fn Clock(comptime IO: type) type {
    return struct {
        io: *IO,
        monotonic_last_ns: u64 = 0,

        const Self = @This();

        pub fn init(io: *IO) Self {
            return .{ .io = io };
        }

        pub fn monotonic_ns(clock: *Self) u64 {
            const now_ns = clock.io.now_monotonic_ns();
            // A kernel clock is monotonic by contract; clamp instead of crashing the node
            // if a VM migration or a buggy backend steps it back.
            const result = @max(now_ns, clock.monotonic_last_ns);
            clock.monotonic_last_ns = result;
            assert(result >= now_ns);
            return result;
        }

        /// Wall clock in nanoseconds since the Unix epoch. May jump; never use for intervals.
        pub fn realtime_ns(clock: *Self) u64 {
            const now_ns = clock.io.now_realtime_ns();
            assert(now_ns > 0);
            return now_ns;
        }

        /// Wall clock in whole seconds since the Unix epoch (block timestamps, JWT `iat`).
        pub fn realtime_s(clock: *Self) u64 {
            return clock.realtime_ns() / ns_per_s;
        }

        pub fn deadline_after(clock: *Self, duration_ns: u64) Deadline {
            return Deadline.init(clock.monotonic_ns(), duration_ns);
        }
    };
}

/// A point on the monotonic clock after which something is late.
pub const Deadline = struct {
    expires_ns: u64,

    pub fn init(now_ns: u64, duration_ns: u64) Deadline {
        return .{ .expires_ns = now_ns +| duration_ns };
    }

    pub fn expired(deadline: Deadline, now_ns: u64) bool {
        return now_ns >= deadline.expires_ns;
    }

    pub fn remaining_ns(deadline: Deadline, now_ns: u64) u64 {
        if (now_ns >= deadline.expires_ns) return 0;
        return deadline.expires_ns - now_ns;
    }
};

/// A clock advanced by hand. Satisfies the clock interface used by `Clock`.
pub const ManualClock = struct {
    monotonic_now_ns: u64 = 0,
    realtime_start_ns: u64 = 1_700_000_000 * ns_per_s,

    pub fn now_monotonic_ns(clock: *const ManualClock) u64 {
        return clock.monotonic_now_ns;
    }

    pub fn now_realtime_ns(clock: *const ManualClock) u64 {
        return clock.realtime_start_ns + clock.monotonic_now_ns;
    }

    pub fn advance(clock: *ManualClock, duration_ns: u64) void {
        const before = clock.monotonic_now_ns;
        clock.monotonic_now_ns += duration_ns;
        assert(clock.monotonic_now_ns >= before);
    }
};

/// Calls `callback(context)` every `period_ns`. Each expiry is scheduled from the previous
/// target time, not from when the callback ran, so periods do not drift. If the loop falls
/// more than one period behind, missed ticks are skipped (counted in `ticks_skipped`) rather
/// than fired in a burst.
pub fn Ticker(comptime IO: type, comptime Context: type) type {
    return struct {
        io: *IO,
        context: Context,
        callback: *const fn (context: Context) void,
        period_ns: u64,
        completion: IO.Completion = .{},
        target_ns: u64 = 0,
        running: bool = false,
        stop_requested: bool = false,
        ticks: u64 = 0,
        ticks_skipped: u64 = 0,

        const Self = @This();
        const TimeoutResult = @import("../io/common.zig").TimeoutError!void;

        pub fn init(
            io: *IO,
            period_ns: u64,
            context: Context,
            callback: *const fn (context: Context) void,
        ) Self {
            assert(period_ns > 0);
            return .{ .io = io, .context = context, .callback = callback, .period_ns = period_ns };
        }

        /// `ticker` must not move while running.
        pub fn start(ticker: *Self) void {
            assert(!ticker.running);
            ticker.running = true;
            ticker.stop_requested = false;
            ticker.target_ns = ticker.io.now_monotonic_ns() +| ticker.period_ns;
            ticker.arm();
        }

        /// Cancels the pending timeout; no further callbacks run. `running` clears once the
        /// canceled timeout's completion has been delivered.
        pub fn stop(ticker: *Self) void {
            if (!ticker.running or ticker.stop_requested) return;
            ticker.stop_requested = true;
            ticker.io.cancel(&ticker.completion);
        }

        fn arm(ticker: *Self) void {
            const now_ns = ticker.io.now_monotonic_ns();
            const wait_ns = if (ticker.target_ns > now_ns) ticker.target_ns - now_ns else 0;
            ticker.io.timeout(*Self, ticker, on_timeout, &ticker.completion, wait_ns);
        }

        fn on_timeout(ticker: *Self, completion: *IO.Completion, result: TimeoutResult) void {
            assert(completion == &ticker.completion);
            assert(ticker.running);
            result catch {};
            if (ticker.stop_requested) {
                ticker.running = false;
                return;
            }
            ticker.ticks += 1;
            const now_ns = ticker.io.now_monotonic_ns();
            ticker.target_ns +|= ticker.period_ns;
            if (ticker.target_ns <= now_ns) {
                const behind_ns = now_ns - ticker.target_ns;
                const skipped = behind_ns / ticker.period_ns + 1;
                ticker.ticks_skipped += skipped;
                ticker.target_ns +|= skipped * ticker.period_ns;
            }
            assert(ticker.target_ns > now_ns);
            ticker.arm();
            ticker.callback(ticker.context);
        }
    };
}

const io_module = @import("../io/root.zig");

test "time: clock is monotonic over manual clock" {
    var manual: ManualClock = .{};
    var clock = Clock(ManualClock).init(&manual);
    try std.testing.expectEqual(@as(u64, 0), clock.monotonic_ns());
    manual.advance(5 * ns_per_ms);
    try std.testing.expectEqual(5 * ns_per_ms, clock.monotonic_ns());
    // A backend stepping back is clamped.
    manual.monotonic_now_ns = 1;
    try std.testing.expectEqual(5 * ns_per_ms, clock.monotonic_ns());
    try std.testing.expectEqual(@as(u64, 1_700_000_000), clock.realtime_s());
}

test "time: deadline" {
    const deadline = Deadline.init(100, 50);
    try std.testing.expect(!deadline.expired(149));
    try std.testing.expect(deadline.expired(150));
    try std.testing.expectEqual(@as(u64, 10), deadline.remaining_ns(140));
    try std.testing.expectEqual(@as(u64, 0), deadline.remaining_ns(200));
    const saturated = Deadline.init(std.math.maxInt(u64) - 1, 10);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), saturated.expires_ns);
}

const TickCounter = struct {
    io: *io_module.SimIo,
    times_ns: [8]u64 = @splat(0),
    count: u32 = 0,

    fn on_tick(counter: *TickCounter) void {
        if (counter.count < counter.times_ns.len) {
            counter.times_ns[counter.count] = counter.io.now_monotonic_ns();
        }
        counter.count += 1;
    }
};

test "time: ticker fires on period without drift under SimIo" {
    var world = try io_module.SimWorld.init(std.testing.allocator, .{ .seed = 1 });
    defer world.deinit();
    var io: io_module.SimIo = undefined;
    try io_module.SimIo.init(&io, std.testing.allocator, &world, .{
        .host = io_module.Address.loopback(0),
    });
    defer io.deinit();

    var counter: TickCounter = .{ .io = &io };
    const T = Ticker(io_module.SimIo, *TickCounter);
    var ticker = T.init(&io, 2 * ns_per_s, &counter, TickCounter.on_tick);
    ticker.start();
    try io.run_for_ns(9 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 4), counter.count);
    for (counter.times_ns[0..4], 1..) |time_ns, index| {
        try std.testing.expectEqual(index * 2 * ns_per_s, time_ns);
    }
    ticker.stop();
    try io.run_for_ns(10 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 4), counter.count);
    try std.testing.expect(!ticker.running);
    try std.testing.expectEqual(@as(u64, 0), ticker.ticks_skipped);
}

test "time: clock over SimIo follows simulated time" {
    var world = try io_module.SimWorld.init(std.testing.allocator, .{ .seed = 2 });
    defer world.deinit();
    var io: io_module.SimIo = undefined;
    try io_module.SimIo.init(&io, std.testing.allocator, &world, .{
        .host = io_module.Address.loopback(0),
        .realtime_offset_ns = -3 * @as(i64, ns_per_s),
    });
    defer io.deinit();
    var clock = Clock(io_module.SimIo).init(&io);
    try io.run_for_ns(7 * ns_per_s);
    try std.testing.expectEqual(7 * ns_per_s, clock.monotonic_ns());
    try std.testing.expectEqual(@as(u64, 1_700_000_004), clock.realtime_s());
    const deadline = clock.deadline_after(ns_per_s);
    try std.testing.expect(!deadline.expired(clock.monotonic_ns()));
}

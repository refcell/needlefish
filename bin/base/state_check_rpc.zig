//! `base state-check` (`state_check.zig`): the reference endpoint, paced to its rate limit.
//!
//! Public endpoints charge every call of a batch and answer over-limit calls with HTTP 429 or
//! a per-item "request limit reached" error (sepolia.base.org, measured: about ten
//! `eth_getProof` calls a minute sustained, bursts of a few, then ~20 s refused; the storage
//! keys of one call are not charged: 1024-key calls every 7 s went through like 1-key ones).
//! So `Pacer` spaces calls adaptively: a rate-limited call doubles the interval and starts a
//! cool-down that doubles while limits continue; successes shrink the interval again, an
//! eighth at a time. Rate limits never count toward giving up: only the deadline does (the
//! moment block N leaves the endpoint's `eth_getProof` window). Other failures (network,
//! undecodable answers) give up after `failures_max` in a row.
//!
//! A batch keeps the calls that were answered and resends only the rest.

const std = @import("std");
const Io = std.Io;

const HttpTransport = @import("http_transport.zig").HttpTransport;

const json = std.json;
const assert = std.debug.assert;

/// Calls per JSON-RPC batch at most.
pub const batch_max = 5;
/// Failures in a row (not rate limits) before the endpoint is given up.
pub const failures_max = 10;
/// Attempts of one batch at most (the deadline ends it far sooner).
const attempts_max = 100_000;

pub const Pacer = struct {
    config: Config,
    /// Spacing between calls.
    interval_ms: u32,
    /// Clock time (ms) before which the next request waits.
    next_ms: i64 = 0,
    /// Successes since the interval last changed.
    successes: u32 = 0,
    /// Rate-limited answers since the last success.
    limited_streak: u32 = 0,

    pub const Config = struct {
        /// sepolia.base.org's sustained rate: one call every 6 s held for 20 calls.
        pub const interval_initial_default_ms = 6_000;
        pub const interval_floor_ms = 4_000;
        pub const interval_ceiling_ms = 30_000;

        interval_initial_ms: u32 = interval_initial_default_ms,
        interval_min_ms: u32 = interval_floor_ms,
        interval_max_ms: u32 = interval_ceiling_ms,
        /// The first cool-down after a rate limit; it doubles with every limit in a row.
        cooldown_base_ms: u32 = 10_000,
        cooldown_max_ms: u32 = 60_000,
        /// Successes in a row after which the interval shrinks by an eighth.
        ramp_successes: u32 = 4,
    };

    pub fn init(config: Config) Pacer {
        assert(config.interval_min_ms > 0);
        assert(config.interval_min_ms <= config.interval_initial_ms);
        assert(config.interval_initial_ms <= config.interval_max_ms);
        assert(config.cooldown_base_ms <= config.cooldown_max_ms);
        assert(config.ramp_successes > 0);
        return .{ .config = config, .interval_ms = config.interval_initial_ms };
    }

    pub fn success(pacer: *Pacer) void {
        pacer.limited_streak = 0;
        pacer.successes += 1;
        if (pacer.successes >= pacer.config.ramp_successes) {
            pacer.successes = 0;
            const lower = pacer.interval_ms - pacer.interval_ms / 8;
            pacer.interval_ms = @max(lower, pacer.config.interval_min_ms);
        }
        assert(pacer.interval_ms >= pacer.config.interval_min_ms);
        assert(pacer.successes < pacer.config.ramp_successes);
    }

    /// When a request sent at `now_ms` may go.
    pub fn ready_at(pacer: *const Pacer, now_ms: i64) i64 {
        const start = @max(now_ms, pacer.next_ms);
        assert(start >= now_ms);
        return start;
    }

    /// A request of `calls` calls went at `start_ms`: the next waits `calls` intervals.
    pub fn sent(pacer: *Pacer, start_ms: i64, calls: u32) void {
        assert(calls > 0);
        assert(start_ms >= pacer.next_ms);
        pacer.next_ms = start_ms + @as(i64, calls) * pacer.interval_ms;
    }

    /// `calls` calls were rate limited at `now_ms`: slow down and wait out a cool-down.
    pub fn limited_at(pacer: *Pacer, now_ms: i64, calls: u32) void {
        assert(calls > 0);
        const cooldown_ms = pacer.limited();
        pacer.next_ms = @max(pacer.next_ms, now_ms + cooldown_ms);
        assert(pacer.next_ms >= now_ms + cooldown_ms);
    }

    /// The `failures_in_row`th failure in a row (not a rate limit) at `now_ms`: back off.
    pub fn failed_at(pacer: *Pacer, now_ms: i64, failures_in_row: u32) void {
        assert(failures_in_row > 0);
        const shift: u5 = @intCast(@min(failures_in_row, 6));
        const wait_ms: i64 = @min(@as(i64, 500) << shift, 30_000);
        pacer.next_ms = @max(pacer.next_ms, now_ms + wait_ms);
        assert(pacer.next_ms >= now_ms + wait_ms);
    }

    /// A rate-limited answer; returns how long to wait before the next call.
    pub fn limited(pacer: *Pacer) u32 {
        pacer.successes = 0;
        const doubled = @as(u64, pacer.interval_ms) * 2;
        pacer.interval_ms = @intCast(@min(doubled, pacer.config.interval_max_ms));
        const shift: u6 = @intCast(@min(pacer.limited_streak, 8));
        pacer.limited_streak +|= 1;
        const cooldown = @as(u64, pacer.config.cooldown_base_ms) << shift;
        const cooldown_ms: u32 = @intCast(@min(cooldown, pacer.config.cooldown_max_ms));
        assert(cooldown_ms >= @min(pacer.config.cooldown_base_ms, pacer.config.cooldown_max_ms));
        assert(pacer.interval_ms <= pacer.config.interval_max_ms);
        return cooldown_ms;
    }
};

/// What one item of an answer says.
pub const ItemState = enum { ok, limited, out_of_window, failed };

/// Error messages nodes give for state they no longer (or do not yet) serve. Only the proof
/// range counts: "eth_getLogs is limited to a 200 range" is a request too large, not state
/// out of the window.
const window_signs = [_][]const u8{
    "missing trie node",   "eth_getproof is limited", "historical state", "pruned",
    "state not available", "state is not available",  "header not found", "proof window",
};

/// Error messages of rate limits.
const limit_signs = [_][]const u8{
    "limit reached", "rate limit", "too many requests", "limit exceeded", "exceeded the quota",
};

fn contains_any(message: []const u8, comptime signs: []const []const u8) bool {
    assert(signs.len > 0);
    var start: usize = 0;
    while (start < message.len) : (start += 1) {
        for (signs) |sign| {
            if (std.ascii.startsWithIgnoreCase(message[start..], sign)) return true;
        }
    }
    assert(start == message.len);
    return false;
}

pub fn error_message(item: json.Value) ?[]const u8 {
    if (item != .object) return null;
    const failure = item.object.get("error") orelse return null;
    if (failure == .object) {
        if (failure.object.get("message")) |message| {
            if (message == .string) return message.string;
        }
    }
    return "error without a message";
}

fn error_code(item: json.Value) ?i64 {
    const failure = item.object.get("error") orelse return null;
    if (failure != .object) return null;
    const code = failure.object.get("code") orelse return null;
    return if (code == .integer) code.integer else null;
}

pub fn classify_item(item: json.Value) ItemState {
    if (item != .object) return .failed;
    const message = error_message(item) orelse {
        return if (item.object.get("result") == null) .failed else .ok;
    };
    if (contains_any(message, &window_signs)) return .out_of_window;
    if (contains_any(message, &limit_signs)) return .limited;
    const code = error_code(item) orelse return .failed;
    const limited = code == 429 or code == -32005 or code == -32011;
    assert(item.object.get("error") != null);
    return if (limited) .limited else .failed;
}

/// The outcome of one answer to the calls `sent` (ids into `results`).
pub const Absorbed = struct {
    answered: u32 = 0,
    limited: u32 = 0,
    failed: u32 = 0,
    /// The first out-of-window message, which ends the check.
    out_of_window: ?[]const u8 = null,
    /// The first message of a limited or failed item.
    message: ?[]const u8 = null,
};

/// Takes what an answer gives: each item for a pending id in `sent` fills `results` and sets
/// its bit in `done`. Items for other ids and repeats count as failed; calls the answer skips
/// count as limited when an item without an id (a top-level error) says so, else failed.
pub fn absorb_answer(
    value: json.Value,
    sent: u64,
    results: []json.Value,
    done: *u64,
) Absorbed {
    assert(results.len > 0 and results.len <= 64);
    assert(sent != 0 and sent & done.* == 0);
    const done_before = done.*;
    var absorbed: Absorbed = .{};
    const items: []const json.Value = switch (value) {
        .array => |array| array.items,
        .object => (&value)[0..1],
        else => &.{},
    };
    var seen: u64 = 0;
    var anonymous_limited = false;
    for (items) |item| {
        const state = classify_item(item);
        if (state != .ok and absorbed.message == null) absorbed.message = error_message(item);
        if (state == .out_of_window and absorbed.out_of_window == null) {
            absorbed.out_of_window = error_message(item);
        }
        const id = id_bit(item, results.len);
        const bit = if (id) |bit| bit & sent & ~seen else 0;
        if (bit == 0) {
            if (state == .ok) absorbed.failed += 1;
            anonymous_limited = anonymous_limited or state == .limited;
            continue;
        }
        seen |= bit;
        switch (state) {
            .ok => {
                done.* |= bit;
                results[@ctz(bit)] = item.object.get("result").?;
                absorbed.answered += 1;
            },
            .limited => absorbed.limited += 1,
            .failed => absorbed.failed += 1,
            .out_of_window => {},
        }
    }
    const missing: u32 = @popCount(sent & ~seen);
    if (anonymous_limited) absorbed.limited += missing else absorbed.failed += missing;
    assert(done.* & ~sent == done_before);
    assert(absorbed.answered == @popCount(sent & done.*));
    return absorbed;
}

fn id_bit(item: json.Value, count: usize) ?u64 {
    if (item != .object) return null;
    const id = item.object.get("id") orelse return null;
    if (id != .integer or id.integer < 0 or id.integer >= count) return null;
    return @as(u64, 1) << @intCast(id.integer);
}

pub const Stop = error{ OutOfWindow, WindowClosing, EndpointFailed };

/// One JSON-RPC endpoint.
pub const Endpoint = struct {
    io: Io,
    http: HttpTransport,
    response: []u8,
    pacer: Pacer,
    /// Awake-clock time (ms) at which block N leaves the window: no wait may pass it.
    deadline_ms: i64 = std.math.maxInt(i64),
    requests: u64 = 0,
    calls: u64 = 0,
    limited: u64 = 0,
    failures: u64 = 0,
    failures_in_row: u32 = 0,
    waited_ms: u64 = 0,
    /// Why the last call failed or was limited (copied: answers live in an arena).
    last_problem: [160]u8 = undefined,
    last_problem_len: u32 = 0,

    pub fn problem(endpoint: *const Endpoint) []const u8 {
        assert(endpoint.last_problem_len <= endpoint.last_problem.len);
        return endpoint.last_problem[0..endpoint.last_problem_len];
    }

    fn note(endpoint: *Endpoint, method: []const u8, message: []const u8) void {
        var writer: Io.Writer = .fixed(&endpoint.last_problem);
        writer.print("{s}: {s}", .{ method, message }) catch {};
        endpoint.last_problem_len = @intCast(writer.buffered().len);
        assert(endpoint.last_problem_len <= endpoint.last_problem.len);
    }

    fn now_ms(endpoint: *const Endpoint) i64 {
        return Io.Clock.awake.now(endpoint.io).toMilliseconds();
    }

    /// Waits until the next call of `calls` items may go; `error.WindowClosing` when the
    /// wait would pass the deadline.
    fn pace(endpoint: *Endpoint, calls: u32) !void {
        assert(calls > 0 and calls <= batch_max);
        const now = endpoint.now_ms();
        const start = endpoint.pacer.ready_at(now);
        if (start >= endpoint.deadline_ms) return error.WindowClosing;
        if (start > now) {
            try endpoint.io.sleep(.fromMilliseconds(start - now), .awake);
            endpoint.waited_ms += @intCast(start - now);
        }
        endpoint.pacer.sent(start, calls);
        assert(endpoint.pacer.next_ms > start);
    }

    /// A rate limit: the pacer slows down and the next call waits out a cool-down.
    fn on_limited(endpoint: *Endpoint, calls: u32) void {
        assert(calls > 0);
        endpoint.limited += calls;
        endpoint.pacer.limited_at(endpoint.now_ms(), calls);
        assert(endpoint.pacer.limited_streak > 0);
    }

    /// A failure that is not a rate limit; `error.EndpointFailed` after `failures_max` in a
    /// row, else a backoff.
    fn on_failure(endpoint: *Endpoint, method: []const u8, message: []const u8) !void {
        endpoint.failures += 1;
        endpoint.failures_in_row += 1;
        endpoint.note(method, message);
        std.debug.print("  {s} {s}: {s}\n", .{ endpoint.http.url, method, message });
        if (endpoint.failures_in_row >= failures_max) return error.EndpointFailed;
        endpoint.pacer.failed_at(endpoint.now_ms(), endpoint.failures_in_row);
        assert(endpoint.failures_in_row < failures_max);
    }

    fn body_of(
        arena: std.mem.Allocator,
        method: []const u8,
        params: []const []const u8,
        pending: u64,
    ) ![]const u8 {
        var body: Io.Writer.Allocating = .init(arena);
        try body.writer.writeAll("[");
        var first = true;
        for (params, 0..) |param, id| {
            if (pending & (@as(u64, 1) << @intCast(id)) == 0) continue;
            try body.writer.print("{s}{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\"," ++
                "\"params\":{s}}}", .{ if (first) "" else ",", id, method, param });
            first = false;
        }
        try body.writer.writeAll("]");
        assert(!first);
        return body.written();
    }

    /// Calls `method` once per entry of `params`; returns each result in order.
    pub fn batch(
        endpoint: *Endpoint,
        arena: std.mem.Allocator,
        method: []const u8,
        params: []const []const u8,
    ) ![]json.Value {
        assert(params.len > 0 and params.len <= batch_max);
        const results = try arena.alloc(json.Value, params.len);
        const all: u64 = (@as(u64, 1) << @intCast(params.len)) - 1;
        var done: u64 = 0;
        var attempt: u32 = 0;
        while (done != all and attempt < attempts_max) : (attempt += 1) {
            const pending = all & ~done;
            const calls: u32 = @popCount(pending);
            try endpoint.pace(calls);
            endpoint.requests += 1;
            endpoint.calls += calls;
            const body = try body_of(arena, method, params, pending);
            const transport = endpoint.http.transport();
            const text = transport.send(body, endpoint.response) catch |err| {
                if (endpoint.http.status == .too_many_requests) {
                    endpoint.note(method, "HTTP 429 too many requests");
                    endpoint.on_limited(calls);
                } else try endpoint.on_failure(method, @errorName(err));
                continue;
            };
            const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch {
                try endpoint.on_failure(method, "an answer that is not JSON");
                continue;
            };
            try endpoint.absorb(method, value, pending, results, &done);
        }
        if (done != all) return error.EndpointFailed;
        assert(done == all);
        return results;
    }

    fn absorb(
        endpoint: *Endpoint,
        method: []const u8,
        value: json.Value,
        pending: u64,
        results: []json.Value,
        done: *u64,
    ) !void {
        const absorbed = absorb_answer(value, pending, results, done);
        if (absorbed.out_of_window) |message| {
            endpoint.note(method, message);
            std.debug.print("  {s} {s}: {s}\n", .{ endpoint.http.url, method, message });
            return error.OutOfWindow;
        }
        for (0..absorbed.answered) |_| endpoint.pacer.success();
        if (absorbed.answered > 0) endpoint.failures_in_row = 0;
        if (absorbed.limited > 0) {
            endpoint.note(method, absorbed.message orelse "rate limited");
            endpoint.on_limited(absorbed.limited);
        }
        if (absorbed.failed > 0 and absorbed.answered == 0) {
            try endpoint.on_failure(method, absorbed.message orelse "an incomplete answer");
        }
    }

    pub fn call(
        endpoint: *Endpoint,
        arena: std.mem.Allocator,
        method: []const u8,
        params: []const u8,
    ) !json.Value {
        const results = try endpoint.batch(arena, method, &.{params});
        assert(results.len == 1);
        return results[0];
    }
};

// Tests.

const testing = std.testing;

test "state-check: the pacer slows on rate limits and ramps back on successes" {
    var pacer: Pacer = .init(.{});
    const config = pacer.config;
    try testing.expectEqual(config.interval_initial_ms, pacer.interval_ms);
    // Limits in a row: the interval doubles to its cap, the cool-down doubles to its cap.
    try testing.expectEqual(config.cooldown_base_ms, pacer.limited());
    try testing.expectEqual(config.interval_initial_ms * 2, pacer.interval_ms);
    try testing.expectEqual(config.cooldown_base_ms * 2, pacer.limited());
    var cooldown_ms: u32 = 0;
    for (0..20) |_| cooldown_ms = pacer.limited();
    try testing.expectEqual(config.cooldown_max_ms, cooldown_ms);
    try testing.expectEqual(config.interval_max_ms, pacer.interval_ms);
    // One success resets the cool-down streak but not the interval.
    pacer.success();
    try testing.expectEqual(@as(u32, 0), pacer.limited_streak);
    try testing.expectEqual(config.interval_max_ms, pacer.interval_ms);
    try testing.expectEqual(config.cooldown_base_ms, pacer.limited());
    // Successes ramp down an eighth per `ramp_successes`, never below the floor.
    const before = pacer.interval_ms;
    for (0..config.ramp_successes) |_| pacer.success();
    try testing.expectEqual(before - before / 8, pacer.interval_ms);
    for (0..1000) |_| pacer.success();
    try testing.expectEqual(config.interval_min_ms, pacer.interval_ms);
    // Three successes then a limit: no ramp happened, the interval doubles.
    for (0..config.ramp_successes - 1) |_| pacer.success();
    _ = pacer.limited();
    try testing.expectEqual(config.interval_min_ms * 2, pacer.interval_ms);
}

test "state-check: answer items are ok, limited, out of the window, or failed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { text: []const u8, state: ItemState };
    const cases = [_]Case{
        .{ .text = "{\"id\":0,\"result\":null}", .state = .ok },
        .{ .text =
        \\{"id":0,"error":{"code":-32011,"message":"request limit reached"}}
        , .state = .limited },
        .{ .text = "{\"id\":0,\"error\":{\"code\":429}}", .state = .limited },
        .{ .text =
        \\{"id":0,"error":{"code":-32000,"message":"Too Many Requests"}}
        , .state = .limited },
        .{ .text =
        \\{"error":{"code":-32614,"message":"eth_getProof is limited to a 10,000 range"}}
        , .state = .out_of_window },
        .{ .text =
        \\{"error":{"message":"distance to target block exceeds maximum proof window"}}
        , .state = .out_of_window },
        .{ .text =
        \\{"error":{"code":-32000,"message":"missing trie node ab"}}
        , .state = .out_of_window },
        .{ .text =
        \\{"error":{"code":-32602,"message":"invalid argument"}}
        , .state = .failed },
        .{ .text =
        \\{"error":{"code":-32614,"message":"eth_getLogs is limited to a 200 range"}}
        , .state = .failed },
        .{ .text = "{\"id\":0}", .state = .failed },
        .{ .text = "7", .state = .failed },
    };
    for (cases) |case| {
        const value = try json.parseFromSliceLeaky(json.Value, arena, case.text, .{});
        try testing.expectEqual(case.state, classify_item(value));
    }
}

test "state-check: a batch keeps answered calls and leaves limited ones pending" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var results: [4]json.Value = undefined;
    var done: u64 = 0;
    const partial = try json.parseFromSliceLeaky(json.Value, arena,
        \\[{"id":2,"result":"c"},{"id":0,"error":{"message":"request limit reached"}},
        \\{"id":1,"result":"b"},{"id":3,"error":{"code":-32011,"message":"request limit reached"}}]
    , .{});
    const first = absorb_answer(partial, 0b1111, &results, &done);
    try testing.expectEqual(@as(u32, 2), first.answered);
    try testing.expectEqual(@as(u32, 2), first.limited);
    try testing.expectEqual(@as(u32, 0), first.failed);
    try testing.expectEqual(@as(u64, 0b0110), done);
    try testing.expectEqualStrings("b", results[1].string);
    // The resend carries ids 0 and 3 only; an answer for id 1 again is not taken.
    const rest = try json.parseFromSliceLeaky(json.Value, arena,
        \\[{"id":3,"result":"d"},{"id":1,"result":"x"},{"id":0,"result":"a"}]
    , .{});
    const second = absorb_answer(rest, 0b1001, &results, &done);
    try testing.expectEqual(@as(u32, 2), second.answered);
    try testing.expectEqual(@as(u32, 1), second.failed);
    try testing.expectEqual(@as(u64, 0b1111), done);
    try testing.expectEqualStrings("a", results[0].string);
    try testing.expectEqualStrings("b", results[1].string);
    // A top-level rate limit answers nothing; an out-of-window item ends the check.
    done = 0;
    const top = try json.parseFromSliceLeaky(json.Value, arena,
        \\{"jsonrpc":"2.0","error":{"code":-32011,"message":"request limit reached"}}
    , .{});
    const limited = absorb_answer(top, 0b11, results[0..2], &done);
    try testing.expectEqual(@as(u32, 2), limited.limited);
    try testing.expectEqual(@as(u64, 0), done);
    const window = try json.parseFromSliceLeaky(json.Value, arena,
        \\[{"id":0,"result":1},{"id":1,"error":{"message":"missing trie node 4f"}}]
    , .{});
    const out = absorb_answer(window, 0b11, results[0..2], &done);
    try testing.expectEqualStrings("missing trie node 4f", out.out_of_window.?);
    // A short answer without errors fails the calls it skipped.
    done = 0;
    const short = try json.parseFromSliceLeaky(json.Value, arena, "[{\"id\":0,\"result\":1}]", .{});
    const skipped = absorb_answer(short, 0b11, results[0..2], &done);
    try testing.expectEqual(@as(u32, 1), skipped.failed);
    try testing.expectEqual(@as(u64, 0b01), done);
}

/// A rate limiter like sepolia.base.org's, as measured: a bucket of `capacity` calls that
/// refills one call every `refill_ms`; a call that finds it empty is refused.
const Bucket = struct {
    capacity: u32,
    refill_ms: i64,
    tokens: u32,
    refilled_ms: i64 = 0,

    fn take(bucket: *Bucket, now_ms: i64) bool {
        const refills: u64 = @intCast(@divTrunc(now_ms - bucket.refilled_ms, bucket.refill_ms));
        if (refills > 0) {
            bucket.tokens = @intCast(@min(bucket.capacity, bucket.tokens + refills));
            bucket.refilled_ms += @as(i64, @intCast(refills)) * bucket.refill_ms;
        }
        if (bucket.tokens == 0) return false;
        bucket.tokens -= 1;
        return true;
    }
};

/// Simulated time for `calls` single calls through `bucket`; also how many were refused.
fn simulate(pacer: *Pacer, bucket: *Bucket, calls: u32) struct { ms: i64, refused: u32 } {
    var now_ms: i64 = 0;
    var answered: u32 = 0;
    var refused: u32 = 0;
    var steps: u32 = 0;
    while (answered < calls and steps < 100 * calls) : (steps += 1) {
        now_ms = pacer.ready_at(now_ms);
        pacer.sent(now_ms, 1);
        now_ms += 300; // The round trip.
        if (bucket.take(now_ms)) {
            answered += 1;
            pacer.success();
        } else {
            refused += 1;
            pacer.limited_at(now_ms, 1);
        }
    }
    assert(answered == calls);
    return .{ .ms = now_ms, .refused = refused };
}

test "state-check: paced calls finish under a sepolia.base.org-like limit" {
    // Ten calls a minute sustained, a burst of ten: 200 calls need at least ~19 minutes.
    var bucket: Bucket = .{ .capacity = 10, .refill_ms = 6_000, .tokens = 10 };
    var pacer: Pacer = .init(.{});
    const run = simulate(&pacer, &bucket, 200);
    try testing.expect(run.ms >= 190 * 6_000);
    try testing.expect(run.ms <= 25 * 60_000);
    // Rate limits are absorbed, not avoided entirely, and they stay rare.
    try testing.expect(run.refused > 0 and run.refused < 40);
    try testing.expect(pacer.interval_ms >= pacer.config.interval_min_ms);
    // A generous limit: the interval ramps down to its floor and nothing is refused.
    var open: Bucket = .{ .capacity = 1000, .refill_ms = 100, .tokens = 1000 };
    var fast: Pacer = .init(.{});
    const quick = simulate(&fast, &open, 200);
    try testing.expectEqual(@as(u32, 0), quick.refused);
    try testing.expectEqual(fast.config.interval_min_ms, fast.interval_ms);
    try testing.expect(quick.ms < 200 * 5_000);
    // A pacer that never slows (mutation check): refused calls pile up.
    var stuck: Pacer = .init(.{
        .interval_initial_ms = 1_000,
        .interval_min_ms = 1_000,
        .interval_max_ms = 1_000,
        .cooldown_base_ms = 0,
        .cooldown_max_ms = 0,
    });
    var again: Bucket = .{ .capacity = 10, .refill_ms = 6_000, .tokens = 10 };
    const hammered = simulate(&stuck, &again, 200);
    try testing.expect(hammered.refused > 4 * run.refused);
}

fn fuzz_answer(_: void, input: []const u8) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const value = json.parseFromSliceLeaky(json.Value, arena_state.allocator(), input, .{}) catch
        return;
    var results: [3]json.Value = undefined;
    var done: u64 = 0b010;
    // Any server bytes: never crash, never mark a call outside the pending set.
    const absorbed = absorb_answer(value, 0b101, &results, &done);
    try testing.expect(done & ~@as(u64, 0b111) == 0);
    try testing.expect(absorbed.answered <= 2);
}

test "state-check: fuzz batch answers" {
    const corpus = [_][]const u8{
        "[{\"id\":0,\"result\":1},{\"id\":2,\"error\":{\"message\":\"request limit reached\"}}]",
        "[{\"id\":2,\"result\":1},{\"id\":2,\"result\":1},{\"id\":1,\"result\":1}]",
    };
    const base = @import("base");
    try base.testing.fuzz.run_bytes({}, fuzz_answer, .{ .iterations = 512, .corpus = &corpus });
}

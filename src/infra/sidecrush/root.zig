//! Block-production health sidecar (`base sidecrush`, base/base `crates/infra/sidecrush`):
//! polls an execution node's `latest` block over JSON-RPC and classifies block production
//! as healthy, delayed, unhealthy, or error (`head_state.zig`).
//!
//! Endpoints on one HTTP server:
//!   GET /         liveness (`utilities/health`)
//!   GET /healthz  version (`utilities/health`)
//!   GET /readyz   200 while healthy or delayed, 503 when unhealthy or on error
//!   GET /metrics  state code (0 healthy, 1 delayed, 2 unhealthy, 3 error), head number, head
//!                 age, poll counts, and one counter per state incremented every poll tick
//!                 (base/base's StatsD heartbeat, as Prometheus counters).

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const time = @import("../../utilities/time/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const health = @import("../../utilities/health/root.zig");
const http = @import("../../utilities/http/root.zig");
const http_client = @import("../../utilities/http/client.zig");

pub const head_state = @import("head_state.zig");
pub const State = head_state.State;
pub const Address = rpc.client.Address;

pub const Options = struct {
    /// Polls per 200 ms block: one.
    poll_interval_ns: u64 = 200 * std.time.ns_per_ms,
    thresholds: head_state.Config = .{},
    /// Report healthy until the node first reaches the tip (base/base `--new-instance`).
    new_instance: bool = true,
    version: []const u8 = "unknown",
    http: http_client.Options = .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 12 * 1024 },
    },
};

const state_count = std.enums.values(State).len;

pub fn Checker(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Rpc = rpc.Client(IO);

        rpc: Rpc,
        ticker: time.Ticker(IO, *Self),
        io: *IO,
        options: Options,
        head: head_state.HeadState,
        polls_ok: u64 = 0,
        polls_failed: u64 = 0,
        polls_skipped: u64 = 0,
        ticks: [state_count]u64 = @splat(0),
        registry: metrics.Registry(12) = .{},
        state_gauge: metrics.Gauge = .{},
        head_number: metrics.Gauge = .{},
        head_age_ms: metrics.Gauge = .{},
        ok_counter: metrics.Counter = .{},
        failed_counter: metrics.Counter = .{},
        skipped_counter: metrics.Counter = .{},
        tick_counters: [state_count]metrics.Counter = @splat(.{}),

        /// In place: the ticker and the registry keep pointers into `checker`.
        pub fn init(
            checker: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            endpoint: Address,
            options: Options,
        ) !void {
            assert(options.poll_interval_ns > 0);
            if (!options.thresholds.valid()) return error.InvalidThresholds;
            checker.* = .{
                .rpc = try Rpc.init(
                    allocator,
                    io,
                    endpoint,
                    options.http,
                    options.http.limits.body_size_max,
                ),
                .ticker = .init(io, options.poll_interval_ns, checker, on_tick),
                .io = io,
                .options = options,
                .head = .init(options.new_instance),
            };
            errdefer checker.rpc.deinit();
            try checker.register();
        }

        fn register(checker: *Self) !void {
            const registry = &checker.registry;
            try registry.gauge(
                "sidecrush_state",
                "0 healthy, 1 delayed, 2 unhealthy, 3 error.",
                &checker.state_gauge,
            );
            try registry.gauge(
                "sidecrush_head_number",
                "Latest block number seen.",
                &checker.head_number,
            );
            try registry.gauge(
                "sidecrush_head_age_milliseconds",
                "Time since the head last advanced (-1 before any).",
                &checker.head_age_ms,
            );
            try registry.counter(
                "sidecrush_polls_total",
                "Successful polls.",
                &checker.ok_counter,
            );
            try registry.counter(
                "sidecrush_poll_failures_total",
                "Failed polls.",
                &checker.failed_counter,
            );
            try registry.counter(
                "sidecrush_polls_skipped_total",
                "Polls skipped while one was in flight.",
                &checker.skipped_counter,
            );
            const names = [state_count][]const u8{
                "sidecrush_healthy_ticks_total",
                "sidecrush_delayed_ticks_total",
                "sidecrush_unhealthy_ticks_total",
                "sidecrush_error_ticks_total",
            };
            for (names, &checker.tick_counters) |name, *counter| {
                try registry.counter(name, "Poll ticks spent in this state.", counter);
            }
            assert(registry.count == 6 + state_count);
        }

        /// Requires `stopped()` once started.
        pub fn deinit(checker: *Self) void {
            assert(checker.stopped());
            checker.rpc.deinit();
            checker.* = undefined;
        }

        pub fn start(checker: *Self) void {
            assert(!checker.ticker.running);
            checker.poll();
            checker.ticker.start();
        }

        pub fn stop(checker: *Self) void {
            checker.ticker.stop();
        }

        pub fn stopped(checker: *const Self) bool {
            return !checker.ticker.running and !checker.rpc.http.busy();
        }

        fn now_ms(checker: *const Self) u64 {
            return checker.io.now_monotonic_ns() / std.time.ns_per_ms;
        }

        pub fn state(checker: *const Self) State {
            return checker.head.classify(checker.options.thresholds, checker.now_ms());
        }

        fn on_tick(checker: *Self) void {
            checker.ticks[@backingInt(checker.state())] += 1;
            checker.rpc.http.tick(); // Enforces the request timeout.
            checker.poll();
        }

        fn poll(checker: *Self) void {
            if (checker.rpc.http.busy()) {
                checker.polls_skipped += 1;
                return;
            }
            const method = "eth_getBlockByNumber";
            checker.rpc.call(*Self, checker, on_result, method, checker, write_params) catch {
                checker.record_failure();
            };
        }

        fn write_params(_: *Self, writer: *json.Writer) json.Writer.WriteError!void {
            try writer.string("latest");
            try writer.boolean(false);
        }

        fn on_result(
            checker: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &checker.rpc);
            const value = result catch return checker.record_failure();
            const raw = switch (value) {
                .ok => |raw| raw,
                .rpc_error => return checker.record_failure(),
            };
            const head = parse_head(raw) catch return checker.record_failure();
            const wall_ms = checker.io.now_realtime_ns() / std.time.ns_per_ms;
            const lag_ms = wall_ms -| head.timestamp_s *| 1000;
            const config = checker.options.thresholds;
            _ = checker.head.on_head(config, head.number, lag_ms, checker.now_ms());
            checker.polls_ok += 1;
        }

        fn record_failure(checker: *Self) void {
            checker.polls_failed += 1;
            checker.head.on_failure();
        }

        /// HTTP handler for `http.Server`.
        pub fn handle(
            checker: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (health.respond(checker.options.version, request, response)) return;
            const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse
                request.target.len;
            const path = request.target[0..path_end];
            if (request.method != .GET and request.method != .HEAD) return response.fail(405);
            if (std.mem.eql(u8, path, "/readyz")) {
                response.content_type = "text/plain";
                const current = checker.state();
                response.status = if (current == .healthy or current == .delayed) 200 else 503;
                response.writer().print("{t}\n", .{current}) catch {};
                return;
            }
            if (!std.mem.eql(u8, path, "/metrics")) return response.fail(404);
            checker.sync();
            response.content_type = "text/plain; version=0.0.4";
            checker.registry.write_prometheus(response.writer()) catch response.fail(500);
        }

        fn sync(checker: *Self) void {
            checker.state_gauge.set(@backingInt(checker.state()));
            const number = checker.head.last_number orelse 0;
            checker.head_number.set(@intCast(@min(number, std.math.maxInt(i64))));
            const age = checker.head.head_age_ms(checker.now_ms());
            checker.head_age_ms.set(if (age) |ms| @intCast(@min(ms, std.math.maxInt(i64))) else -1);
            sync_counter(&checker.ok_counter, checker.polls_ok);
            sync_counter(&checker.failed_counter, checker.polls_failed);
            sync_counter(&checker.skipped_counter, checker.polls_skipped);
            for (&checker.tick_counters, checker.ticks) |*counter, value| {
                sync_counter(counter, value);
            }
        }

        fn sync_counter(counter: *metrics.Counter, value: u64) void {
            const current = counter.get();
            assert(value >= current);
            counter.add(value - current);
            assert(counter.get() == value);
        }
    };
}

pub const Head = struct { number: u64, timestamp_s: u64 };

/// `number` and `timestamp` of a raw `eth_getBlockByNumber` result.
pub fn parse_head(raw: []const u8) error{InvalidBlock}!Head {
    const number = json.find_path(raw, &.{"number"}) catch return error.InvalidBlock;
    const timestamp = json.find_path(raw, &.{"timestamp"}) catch return error.InvalidBlock;
    const head: Head = .{
        .number = try quantity(number orelse return error.InvalidBlock),
        .timestamp_s = try quantity(timestamp orelse return error.InvalidBlock),
    };
    return head;
}

fn quantity(raw: []const u8) error{InvalidBlock}!u64 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidBlock;
    return json.parse_quantity(u64, raw[1 .. raw.len - 1]) catch error.InvalidBlock;
}

const testing = std.testing;

test "sidecrush: parse head" {
    const head = try parse_head("{\"hash\":\"0x01\",\"number\":\"0x1a\",\"timestamp\":\"0x64\"}");
    try testing.expectEqual(@as(u64, 26), head.number);
    try testing.expectEqual(@as(u64, 100), head.timestamp_s);
    try testing.expectError(error.InvalidBlock, parse_head("null"));
    const unquoted = "{\"number\":26,\"timestamp\":\"0x1\"}";
    try testing.expectError(error.InvalidBlock, parse_head(unquoted));
}

test "sidecrush: fuzz parse head" {
    try testing.fuzz({}, fuzz_parse, .{});
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    _ = parse_head(buffer[0..smith.slice(&buffer)]) catch return;
}

test {
    _ = @import("head_state.zig");
    _ = @import("tests.zig");
}

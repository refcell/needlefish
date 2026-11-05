//! Batcher metrics: heads and activity counters fed from each service step, exposed in
//! Prometheus text format on `GET /metrics` (op-batcher's metrics port contract).
//!
//! Metric names follow op-batcher's `op_batcher_default_*` style under a `base_batcher`
//! namespace. The registry is fixed-size and allocation-free.

const std = @import("std");
const assert = std.debug.assert;

const utilities_metrics = @import("../../utilities/metrics/root.zig");
const http = @import("../../utilities/http/root.zig");
const service = @import("../service/root.zig");
const rpc = @import("../rpc/root.zig");

/// Balance poll period (base/base `BalanceMonitorLayer::DEFAULT_POLL_INTERVAL`).
pub const balance_poll_ms = 12_000;

const Counter = utilities_metrics.Counter;
const Gauge = utilities_metrics.Gauge;

pub const Registry = utilities_metrics.Registry(16);

pub const Metrics = struct {
    l1_head: Gauge = .{},
    safe_head: Gauge = .{},
    unsafe_head: Gauge = .{},
    pending_txs: Gauge = .{},
    da_backlog_bytes: Gauge = .{},
    blocks_loaded: Counter = .{},
    txs_submitted: Counter = .{},
    txs_confirmed: Counter = .{},
    resets: Counter = .{},
    step_failures: Counter = .{},
    /// The batcher account's L1 balance in gwei (gauges are integers; base/base exports
    /// ether as a float).
    balance_gwei: Gauge = .{},
    balance_polled_ms: ?u64 = null,
    registry: Registry = .{},

    /// `metrics` must not move afterwards: the registry points into it.
    pub fn register(metrics: *Metrics) utilities_metrics.RegisterError!void {
        assert(metrics.registry.count == 0);
        const r = &metrics.registry;
        try r.gauge("base_batcher_l1_head", "Latest L1 block number.", &metrics.l1_head);
        try r.gauge("base_batcher_safe_head", "L2 safe head number.", &metrics.safe_head);
        try r.gauge("base_batcher_unsafe_head", "L2 unsafe head number.", &metrics.unsafe_head);
        try r.gauge("base_batcher_pending_txs", "Unconfirmed batch txs.", &metrics.pending_txs);
        const backlog = &metrics.da_backlog_bytes;
        try r.gauge("base_batcher_da_backlog_bytes", "Estimated DA backlog.", backlog);
        const loaded = &metrics.blocks_loaded;
        try r.counter("base_batcher_blocks_loaded_total", "L2 blocks loaded.", loaded);
        const submitted = &metrics.txs_submitted;
        try r.counter("base_batcher_txs_submitted_total", "Batch txs sent.", submitted);
        const confirmed = &metrics.txs_confirmed;
        try r.counter("base_batcher_txs_confirmed_total", "Batch txs mined.", confirmed);
        try r.counter("base_batcher_resets_total", "Pipeline resets.", &metrics.resets);
        try r.counter("base_batcher_step_failures_total", "Failed steps.", &metrics.step_failures);
        const balance = &metrics.balance_gwei;
        try r.gauge("base_batcher_balance_gwei", "Batcher L1 balance in gwei.", balance);
        assert(metrics.registry.count == 11);
    }

    /// Reads the account balance at most once per `balance_poll_ms`. A failed read keeps
    /// the last value (the metric is optional) and retries at the next period.
    pub fn poll_balance(metrics: *Metrics, l1: *rpc.Client, address: [20]u8, now_ms: u64) void {
        if (metrics.balance_polled_ms) |polled_ms| {
            if (now_ms -| polled_ms < balance_poll_ms) return;
        }
        metrics.balance_polled_ms = now_ms;
        var params_buffer: [64]u8 = undefined;
        const params = std.fmt.bufPrint(&params_buffer, "[\"0x{x}\",\"latest\"]", .{&address}) catch
            unreachable; // 20 bytes of hex fit.
        const result = l1.call("eth_getBalance", params) catch return;
        const wei = rpc.quantity(u256, result) catch return;
        metrics.balance_gwei.set(gwei_of(wei));
        assert(metrics.balance_gwei.get() >= 0);
    }

    pub fn record(metrics: *Metrics, report: service.Report, pending_txs: u32) void {
        metrics.l1_head.set(@intCast(@min(report.heads.l1, std.math.maxInt(i64))));
        metrics.safe_head.set(@intCast(@min(report.heads.safe_l2, std.math.maxInt(i64))));
        metrics.unsafe_head.set(@intCast(@min(report.heads.unsafe_l2, std.math.maxInt(i64))));
        metrics.pending_txs.set(pending_txs);
        metrics.da_backlog_bytes.set(@intCast(@min(report.da_backlog_bytes, std.math.maxInt(i64))));
        metrics.blocks_loaded.add(report.blocks_loaded);
        metrics.txs_submitted.add(report.txs_submitted);
        metrics.txs_confirmed.add(report.txs_confirmed);
        metrics.resets.add(report.resets);
    }

    /// HTTP handler: `GET /metrics` renders the registry; anything else is 404/405.
    pub fn handle(
        metrics: *Metrics,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        assert(metrics.registry.count > 0);
        const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse request.target.len;
        if (!std.mem.eql(u8, request.target[0..path_end], "/metrics")) return response.fail(404);
        if (request.method != .GET and request.method != .HEAD) return response.fail(405);
        response.content_type = "text/plain; version=0.0.4";
        metrics.registry.write_prometheus(response.writer()) catch return response.fail(500);
    }
};

fn gwei_of(wei: u256) i64 {
    const gwei = wei / 1_000_000_000;
    return @intCast(@min(gwei, std.math.maxInt(i64)));
}

const testing = std.testing;

test "metrics: balance polled once per period, in gwei, failures keep the last value" {
    var answers = [_]rpc.CannedTransport.Answer{
        .{ .method = "eth_getBalance", .result = "\"0xde0b6b3a7640000\"" }, // 1 ether.
    };
    var canned: rpc.CannedTransport = .{ .answers = &answers };
    var l1 = try rpc.Client.init(testing.allocator, canned.transport(), .{});
    defer l1.deinit(testing.allocator);
    var metrics: Metrics = .{};
    metrics.poll_balance(&l1, @splat(0x11), 1_000);
    try testing.expectEqual(@as(i64, 1_000_000_000), metrics.balance_gwei.get());
    answers[0].result = "\"0x0\"";
    metrics.poll_balance(&l1, @splat(0x11), 1_000 + balance_poll_ms - 1);
    try testing.expectEqual(@as(i64, 1_000_000_000), metrics.balance_gwei.get());
    try testing.expectEqual(@as(u32, 1), canned.calls);
    answers[0].result = "\"bogus\"";
    metrics.poll_balance(&l1, @splat(0x11), 1_000 + balance_poll_ms);
    try testing.expectEqual(@as(i64, 1_000_000_000), metrics.balance_gwei.get());
    answers[0].result = "\"0x3b9aca00\""; // 1 gwei.
    metrics.poll_balance(&l1, @splat(0x11), 1_000 + 2 * balance_poll_ms);
    try testing.expectEqual(@as(i64, 1), metrics.balance_gwei.get());
}

test "metrics: seeded fuzz of the gwei conversion" {
    var prng = Prng.init(0xba1a);
    for (0..2000) |_| {
        var bytes: [32]u8 = undefined;
        prng.fill(bytes[0..prng.range(0, 32)]);
        const wei = std.mem.readInt(u256, &bytes, .little) >> @intCast(prng.below(256));
        try check_gwei(wei);
    }
    try check_gwei(std.math.maxInt(u256));
    try check_gwei(0);
}

fn check_gwei(wei: u256) !void {
    const gwei = gwei_of(wei);
    try testing.expect(gwei >= 0);
    if (wei / 1_000_000_000 <= std.math.maxInt(i64)) {
        try testing.expectEqual(wei / 1_000_000_000, @as(u256, @intCast(gwei)));
    } else try testing.expectEqual(@as(i64, std.math.maxInt(i64)), gwei);
}

test "metrics: fuzz the gwei conversion" {
    try testing.fuzz({}, fuzz_gwei, .{});
}

fn fuzz_gwei(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [32]u8 = @splat(0);
    _ = smith.slice(&bytes);
    try check_gwei(std.mem.readInt(u256, &bytes, .little));
}
const Prng = @import("../../testing/prng.zig").Prng;

fn render(metrics: *Metrics, raw: []const u8, buffer: []u8) !http.ResponseBuilder {
    var request_bytes: [256]u8 = undefined;
    @memcpy(request_bytes[0..raw.len], raw);
    const limits: http.Limits = .{ .head_size_max = 256, .body_size_max = 0 };
    const parsed = try http.parse_request(request_bytes[0..raw.len], limits);
    var response: http.ResponseBuilder = .init(buffer);
    metrics.handle(&parsed.complete.message, &response);
    return response;
}

test "metrics: step reports render as prometheus text on /metrics" {
    var metrics: Metrics = .{};
    try metrics.register();
    metrics.record(.{
        .heads = .{ .l1 = 42, .safe_l2 = 7, .unsafe_l2 = 20 },
        .blocks_loaded = 13,
        .txs_submitted = 2,
        .txs_confirmed = 1,
    }, 1);
    metrics.record(.{ .heads = .{ .l1 = 43, .safe_l2 = 9, .unsafe_l2 = 21 }, .resets = 1 }, 0);
    var buffer: [8192]u8 = undefined;
    var response = try render(&metrics, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &buffer);
    try testing.expectEqual(@as(u16, 200), response.status);
    const text = response.body.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "base_batcher_l1_head 43\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "base_batcher_safe_head 9\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "base_batcher_blocks_loaded_total 13\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "base_batcher_resets_total 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "base_batcher_pending_txs 0\n") != null);
    response = try render(&metrics, "GET /other HTTP/1.1\r\nHost: x\r\n\r\n", &buffer);
    try testing.expectEqual(@as(u16, 404), response.status);
    response = try render(&metrics, "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &buffer);
    try testing.expectEqual(@as(u16, 405), response.status);
}

test "metrics: seeded fuzz keeps counters monotonic and gauges at the last report" {
    var metrics: Metrics = .{};
    try metrics.register();
    var prng = Prng.init(0x3e7);
    var submitted: u64 = 0;
    for (0..200) |_| {
        const report: service.Report = .{
            .heads = .{ .l1 = prng.int(u64), .safe_l2 = prng.below(1000), .unsafe_l2 = 5 },
            .txs_submitted = @intCast(prng.below(8)),
        };
        submitted += report.txs_submitted;
        metrics.record(report, @intCast(prng.below(9)));
        try testing.expectEqual(submitted, metrics.txs_submitted.get());
        const l1_clamped = @min(report.heads.l1, std.math.maxInt(i64));
        try testing.expectEqual(@as(i64, @intCast(l1_clamped)), metrics.l1_head.get());
    }
}

test "metrics: fuzz handler over arbitrary request targets" {
    try testing.fuzz({}, fuzz_handler, .{});
}

fn fuzz_handler(_: void, smith: *testing.Smith) anyerror!void {
    var metrics: Metrics = .{};
    try metrics.register();
    var raw: [200]u8 = undefined;
    const prefix = "GET /";
    @memcpy(raw[0..prefix.len], prefix);
    var target: [100]u8 = undefined;
    const length = smith.slice(&target);
    var end: usize = prefix.len;
    for (target[0..length]) |byte| {
        if (byte <= ' ' or byte >= 0x7f) continue;
        raw[end] = byte;
        end += 1;
    }
    const suffix = " HTTP/1.1\r\nHost: x\r\n\r\n";
    @memcpy(raw[end..][0..suffix.len], suffix);
    var buffer: [8192]u8 = undefined;
    const response = render(&metrics, raw[0 .. end + suffix.len], &buffer) catch return;
    try testing.expect(response.status == 200 or response.status == 404);
}

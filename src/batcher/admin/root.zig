//! Batcher admin JSON-RPC API (base/base `batcher/admin`): `admin_startBatcher`,
//! `admin_stopBatcher`, `admin_flushBatcher`, `admin_getBatcherStatus`,
//! `admin_getThrottleController`, and `admin_setLogLevel` (not supported, as in base/base).
//!
//! Handlers run on the batcher's own thread between service steps, so they call the
//! service directly instead of through a command channel. Error codes match base/base:
//! -32002 for a stopped batcher, -32601 for unsupported operations.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const http = @import("../../utilities/http/root.zig");
const service_module = @import("../service/root.zig");

const Service = service_module.Service;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const stopped_code: i32 = -32002;

pub const Admin = struct {
    service: *Service,

    /// HTTP handler: POST bodies go to the router; anything else is 405.
    pub fn handle(
        admin: *Admin,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        if (request.method != .POST) return response.fail(405);
        switch (Router.handle(admin, request.body, response.writer())) {
            .response => {},
            .empty => response.status = 204,
        }
    }
};

pub const methods = [_]rpc.Method(*Admin){
    .{ .name = "admin_startBatcher", .handler = start_batcher },
    .{ .name = "admin_stopBatcher", .handler = stop_batcher },
    .{ .name = "admin_flushBatcher", .handler = flush_batcher },
    .{ .name = "admin_getBatcherStatus", .handler = get_batcher_status },
    .{ .name = "admin_getThrottleController", .handler = get_throttle_controller },
    .{ .name = "admin_setLogLevel", .handler = set_log_level },
};

pub const Router = rpc.Router(*Admin, &methods);

fn start_batcher(admin: *Admin, call: *Call) HandlerError!void {
    try call.params.finish();
    admin.service.start();
    assert(!admin.service.stopped);
    try call.writer.null_value();
}

fn stop_batcher(admin: *Admin, call: *Call) HandlerError!void {
    try call.params.finish();
    admin.service.stop();
    assert(admin.service.stopped);
    try call.writer.null_value();
}

fn flush_batcher(admin: *Admin, call: *Call) HandlerError!void {
    try call.params.finish();
    admin.service.flush() catch return call.fail(stopped_code, "batcher is stopped");
    try call.writer.null_value();
}

fn get_batcher_status(admin: *Admin, call: *Call) HandlerError!void {
    try call.params.finish();
    const status = admin.service.status();
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("stopped");
    try writer.boolean(status.stopped);
    try writer.key("in_flight");
    try writer.integer(status.in_flight);
    try writer.key("da_backlog_bytes");
    try writer.integer(status.da_backlog_bytes);
    try writer.end_object();
}

/// base/base `ThrottleInfo` (snake_case fields, intensities as JSON numbers in [0, 1]).
fn get_throttle_controller(admin: *Admin, call: *Call) HandlerError!void {
    try call.params.finish();
    const config = admin.service.throttle.config;
    const backlog = admin.service.last_da_backlog_bytes;
    const limits = config.limits(backlog);
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("strategy");
    try writer.string(@tagName(config.strategy));
    try writer.key("start_threshold_bytes");
    try writer.integer(config.start_threshold_bytes);
    try writer.key("full_threshold_bytes");
    try writer.integer(config.full_threshold_bytes);
    try writer.key("max_intensity");
    try write_ppm(writer, config.max_intensity_ppm);
    try writer.key("current_intensity");
    try write_ppm(writer, config.intensity_ppm(backlog));
    try writer.key("max_block_size");
    try writer.integer(limits.max_block_size);
    try writer.key("max_tx_size");
    try writer.integer(limits.max_tx_size);
    try writer.end_object();
}

fn set_log_level(_: *Admin, call: *Call) HandlerError!void {
    _ = try call.params.string();
    try call.params.finish();
    return call.fail(rpc.code.method_not_found, "not yet supported: set_log_level");
}

/// Writes parts-per-million as an exact decimal JSON number.
fn write_ppm(writer: anytype, value_ppm: u32) HandlerError!void {
    assert(value_ppm <= 1_000_000);
    var buffer: [16]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}.{d:0>6}", .{
        value_ppm / 1_000_000,
        value_ppm % 1_000_000,
    }) catch unreachable; // At most "1.000000".
    try writer.raw(text);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const accounts = @import("../devnet/accounts.zig");

fn test_service() !Service {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    return Service.init(testing.allocator, .{
        .channels = .{
            .channel = .{ .frame_size_max = 300, .target_frames = 4, .input_bytes_max = 4096 },
            .max_channel_duration_l1_blocks = 4,
            .batch_bytes_max = 1024,
        },
        .txs = .{
            .chain_id = 900,
            .private_key = batcher.private_key,
            .from = batcher.address,
            .to = .{ .bytes = @splat(0xff) },
            .tx_data_bytes_max = 512,
        },
        .stopped = true,
    }, @splat(1));
}

fn call_admin(admin: *Admin, body: []const u8, buffer: []u8) []const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    _ = Router.handle(admin, body, &out);
    return out.buffered();
}

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "admin: stop, start, flush, and status follow base/base semantics" {
    var service = try test_service();
    defer service.deinit(testing.allocator);
    var admin: Admin = .{ .service = &service };
    var buffer: [1024]u8 = undefined;
    const status = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_getBatcherStatus\"}";
    try expect_contains(call_admin(&admin, status, &buffer), "\"stopped\":true");
    const flush = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"admin_flushBatcher\"}";
    try expect_contains(call_admin(&admin, flush, &buffer), "\"code\":-32002");
    const start = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"admin_startBatcher\",\"params\":[]}";
    try expect_contains(call_admin(&admin, start, &buffer), "\"result\":null");
    try testing.expect(!service.stopped);
    try expect_contains(call_admin(&admin, flush, &buffer), "\"result\":null");
    try expect_contains(call_admin(&admin, status, &buffer), "\"in_flight\":0");
    const stop = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"admin_stopBatcher\"}";
    try expect_contains(call_admin(&admin, stop, &buffer), "\"result\":null");
    try testing.expect(service.stopped);
    const throttle = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"admin_getThrottleController\"}";
    const info = call_admin(&admin, throttle, &buffer);
    try expect_contains(info, "\"strategy\":\"off\"");
    try expect_contains(info, "\"current_intensity\":0.000000");
    try expect_contains(info, "\"max_intensity\":1.000000");
    const log = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"admin_setLogLevel\"," ++
        "\"params\":[\"debug\"]}";
    try expect_contains(call_admin(&admin, log, &buffer), "\"code\":-32601");
    const unknown = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"admin_nope\"}";
    try expect_contains(call_admin(&admin, unknown, &buffer), "\"code\":-32601");
}

test "admin: seeded fuzz over method sequences keeps the stopped flag consistent" {
    var service = try test_service();
    defer service.deinit(testing.allocator);
    var admin: Admin = .{ .service = &service };
    var prng = Prng.init(0xad);
    var buffer: [1024]u8 = undefined;
    var stopped = true;
    for (0..300) |index| {
        const method = methods[prng.below(methods.len)].name;
        var body_buffer: [160]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":{d}," ++
            "\"method\":\"{s}\"}}", .{ index, method }) catch unreachable;
        const reply = call_admin(&admin, body, &buffer);
        if (std.mem.eql(u8, method, "admin_startBatcher")) stopped = false;
        if (std.mem.eql(u8, method, "admin_stopBatcher")) stopped = true;
        try testing.expectEqual(stopped, service.stopped);
        try expect_contains(reply, "\"jsonrpc\":\"2.0\"");
    }
}

test "admin: fuzz request bodies" {
    try testing.fuzz({}, fuzz_admin, .{});
}

fn fuzz_admin(_: void, smith: *testing.Smith) anyerror!void {
    var service = try test_service();
    defer service.deinit(testing.allocator);
    var admin: Admin = .{ .service = &service };
    var body: [256]u8 = undefined;
    const length = smith.slice(&body);
    var buffer: [2048]u8 = undefined;
    _ = call_admin(&admin, body[0..length], &buffer);
}

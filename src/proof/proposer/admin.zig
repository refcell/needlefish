//! The proposer's admin JSON-RPC (base/base `crates/proof/proposer/src/admin.rs`):
//! `admin_startProposer`, `admin_stopProposer` and `admin_proposerRunning`, served by the
//! shared `utilities/rpc` router. Starting a running proposer or stopping a stopped one
//! fails with -32000 and base/base's message. The service loop skips ticks while stopped
//! and calls `take_start` before each tick: a start after a stop begins a fresh session
//! (`Pipeline.reset`), as base/base spawns a new pipeline task.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const http = @import("../../utilities/http/root.zig");

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

/// base/base `AdminRpcServer::rpc_error`.
pub const error_code: i32 = -32000;

pub const Admin = struct {
    running: bool = true,
    /// A start since the last `take_start`.
    start_pending: bool = false,
    starts: u64 = 0,
    stops: u64 = 0,

    pub const methods = [_]rpc.Method(*Admin){
        .{ .name = "admin_startProposer", .handler = start },
        .{ .name = "admin_stopProposer", .handler = stop },
        .{ .name = "admin_proposerRunning", .handler = running_method },
    };
    pub const Router = rpc.Router(*Admin, &methods);

    /// The HTTP handler (`http.Server(IO, *Admin, Admin.handle_http)`).
    pub fn handle_http(
        admin: *Admin,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        if (request.method != .POST) return response.fail(405);
        _ = Router.handle(admin, request.body, response.writer());
    }

    /// True once after each start: the caller begins a fresh pipeline session.
    pub fn take_start(admin: *Admin) bool {
        const pending = admin.start_pending;
        admin.start_pending = false;
        assert(!admin.start_pending);
        assert(!pending or admin.running);
        return pending;
    }

    fn start(admin: *Admin, call: *Call) HandlerError!void {
        try call.params.finish();
        if (admin.running) return call.fail(error_code, "proposer is already running");
        admin.running = true;
        admin.start_pending = true;
        admin.starts += 1;
        call.writer.null_value() catch return error.WriteFailed;
    }

    fn stop(admin: *Admin, call: *Call) HandlerError!void {
        try call.params.finish();
        if (!admin.running) return call.fail(error_code, "proposer is not running");
        admin.running = false;
        admin.start_pending = false;
        admin.stops += 1;
        call.writer.null_value() catch return error.WriteFailed;
    }

    fn running_method(admin: *Admin, call: *Call) HandlerError!void {
        try call.params.finish();
        call.writer.boolean(admin.running) catch return error.WriteFailed;
    }
};

const testing = std.testing;

fn call_method(admin: *Admin, buffer: []u8, method: []const u8) ![]const u8 {
    var request_buffer: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(
        &request_buffer,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":[]}}",
        .{method},
    );
    var out: std.Io.Writer = .fixed(buffer);
    _ = Admin.Router.handle(admin, body, &out);
    return out.buffered();
}

fn has(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

test "proposer admin: start, stop and running follow base/base" {
    var admin: Admin = .{};
    var buffer: [512]u8 = undefined;
    try testing.expect(has(try call_method(&admin, &buffer, "admin_proposerRunning"), "true"));
    var reply = try call_method(&admin, &buffer, "admin_startProposer");
    try testing.expect(has(reply, "-32000") and has(reply, "proposer is already running"));
    try testing.expect(!admin.take_start());
    reply = try call_method(&admin, &buffer, "admin_stopProposer");
    try testing.expect(has(reply, "\"result\":null"));
    try testing.expect(has(try call_method(&admin, &buffer, "admin_proposerRunning"), "false"));
    reply = try call_method(&admin, &buffer, "admin_stopProposer");
    try testing.expect(has(reply, "proposer is not running"));
    reply = try call_method(&admin, &buffer, "admin_startProposer");
    try testing.expect(has(reply, "\"result\":null"));
    try testing.expect(admin.running);
    try testing.expect(admin.take_start());
    try testing.expect(!admin.take_start());
    try testing.expectEqual(@as(u64, 1), admin.starts);
    try testing.expectEqual(@as(u64, 1), admin.stops);
    // Unknown methods are the router's -32601.
    try testing.expect(has(try call_method(&admin, &buffer, "admin_nope"), "-32601"));
}

test "proposer admin: fuzz method sequences keep the state consistent" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var admin: Admin = .{};
            var model_running = true;
            var buffer: [512]u8 = undefined;
            const names = [_][]const u8{
                "admin_startProposer", "admin_stopProposer", "admin_proposerRunning",
            };
            for (0..24) |_| {
                const pick = smith.index(names.len);
                const reply = try call_method(&admin, &buffer, names[pick]);
                const failed = has(reply, "\"error\"");
                switch (pick) {
                    0 => try testing.expectEqual(model_running, failed),
                    1 => try testing.expectEqual(!model_running, failed),
                    else => try testing.expect(!failed),
                }
                if (pick == 0) model_running = true;
                if (pick == 1) model_running = false;
                try testing.expectEqual(model_running, admin.running);
                if (smith.value(bool)) _ = admin.take_start();
            }
        }
    }.one, .{ .iterations = 500 });
}

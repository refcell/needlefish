//! Execution forwarding (base/base `--rpc.execution-forwarding-endpoint`): JSON-RPC calls
//! whose method the consensus RPC server does not serve go to the execution client's HTTP
//! RPC, params untouched, and its result or error comes back as is.
//!
//! The exact method name decides, so a served method is never forwarded. Notifications are
//! not forwarded. A forwarded call fails with an internal error (-32603) when no valid
//! JSON-RPC response comes back. Deviations from base/base: batches are served by the local
//! router only (unknown methods in a batch answer -32601), and the WebSocket server does not
//! forward; both would need per-entry deferral the servers do not have.
//!
//! Each forwarded call parks its HTTP connection (`ResponseBuilder.defer_response`) and
//! takes one of `slots_max` keep-alive clients; with none free the call fails right away.

const std = @import("std");
const assert = std.debug.assert;

const http = @import("../../utilities/http/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");

pub const slots_max = 4;
/// Longest request id copied for error replies; longer ids are not forwarded.
pub const id_length_max = 128;

pub const failed_message = "execution forwarding failed";
pub const busy_message = "execution forwarding busy";

/// The id of a single, non-notification request whose method is not in `served`, or null
/// when the local router should answer the body.
pub fn forward_id(body: []const u8, served: []const []const u8) ?[]const u8 {
    var scanner = json.Scanner.init(body);
    const first = scanner.next() catch return null;
    if (first.tag != .object_begin) return null;
    json.validate(body) catch return null;
    const request = rpc.parse_request(&scanner) catch return null;
    if (request.id.len == 0 or request.id.len > id_length_max) return null;
    for (served) |name| {
        if (std.mem.eql(u8, name, request.method)) return null;
    }
    assert(request.method.len > 0);
    return request.id;
}

pub fn Forwarder(comptime IO: type, comptime Server: type) type {
    return struct {
        const Self = @This();
        const Client = http_client.Client(IO);

        const Slot = struct {
            forwarder: *Self,
            client: Client,
            token: http.server.Deferred = undefined,
            id: [id_length_max]u8 = undefined,
            id_length: u32 = 0,
        };

        server: *Server,
        slots: [slots_max]Slot,
        forwarded: u64 = 0,
        failed: u64 = 0,
        busy_rejections: u64 = 0,

        /// `forwarder` must not move afterwards.
        pub fn init(
            forwarder: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            server: *Server,
            endpoint: http_client.Address,
            options: http_client.Options,
        ) !void {
            forwarder.* = .{ .server = server, .slots = undefined };
            var initialized: u32 = 0;
            errdefer for (forwarder.slots[0..initialized]) |*slot| slot.client.deinit();
            for (&forwarder.slots) |*slot| {
                slot.* = .{
                    .forwarder = forwarder,
                    .client = try Client.init(allocator, io, endpoint, options),
                };
                initialized += 1;
            }
            assert(initialized == slots_max);
        }

        pub fn deinit(forwarder: *Self) void {
            assert(!forwarder.busy());
            for (&forwarder.slots) |*slot| slot.client.deinit();
            forwarder.* = undefined;
        }

        pub fn busy(forwarder: *const Self) bool {
            for (&forwarder.slots) |*slot| if (slot.client.busy()) return true;
            return false;
        }

        /// Times out stuck forwarded calls.
        pub fn tick(forwarder: *Self) void {
            for (&forwarder.slots) |*slot| slot.client.tick();
        }

        /// Answers `body` through the execution client when its method is not `served`;
        /// returns false when the caller should serve it locally.
        pub fn handle(
            forwarder: *Self,
            body: []const u8,
            served: []const []const u8,
            response: *http.ResponseBuilder,
        ) bool {
            const id = forward_id(body, served) orelse return false;
            assert(id.len <= id_length_max);
            const slot = forwarder.idle_slot() orelse {
                forwarder.busy_rejections += 1;
                write_failure(response, id, busy_message);
                return true;
            };
            const headers = [_]http.parser.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            };
            slot.client.request(*Slot, slot, on_response, .POST, "/", &headers, body) catch {
                forwarder.failed += 1;
                write_failure(response, id, failed_message);
                return true;
            };
            @memcpy(slot.id[0..id.len], id);
            slot.id_length = @intCast(id.len);
            slot.token = response.defer_response();
            forwarder.forwarded += 1;
            return true;
        }

        fn idle_slot(forwarder: *Self) ?*Slot {
            for (&forwarder.slots) |*slot| if (!slot.client.busy()) return slot;
            return null;
        }

        const Reply = struct {
            slot: *Slot,
            result: http_client.Error!*const http.parser.Response,
        };

        fn on_response(
            slot: *Slot,
            _: *Client,
            result: http_client.Error!*const http.parser.Response,
        ) void {
            const forwarder = slot.forwarder;
            assert(slot.id_length > 0);
            // A stale token (the caller timed out or the server stopped) drops the reply.
            _ = forwarder.server.resume_deferred(slot.token, Reply{
                .slot = slot,
                .result = result,
            }, write_reply);
            slot.id_length = 0;
        }

        fn write_reply(reply: Reply, response: *http.ResponseBuilder) void {
            const slot = reply.slot;
            const id = slot.id[0..slot.id_length];
            const upstream = reply.result catch {
                slot.forwarder.failed += 1;
                return write_failure(response, id, failed_message);
            };
            const body = upstream.body;
            if (upstream.status != 200 or !json_rpc_reply(body)) {
                slot.forwarder.failed += 1;
                return write_failure(response, id, failed_message);
            }
            response.writer().writeAll(body) catch {
                slot.forwarder.failed += 1;
                return write_failure(response, id, failed_message);
            };
        }
    };
}

/// Whether `body` looks like a JSON-RPC reply: a valid JSON object or array.
fn json_rpc_reply(body: []const u8) bool {
    const trimmed = std.mem.trimStart(u8, body, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (trimmed[0] != '{' and trimmed[0] != '[') return false;
    json.validate(trimmed) catch return false;
    assert(trimmed.len <= body.len);
    return true;
}

/// Replies with a JSON-RPC internal error for `id` (resetting any partial body).
fn write_failure(response: *http.ResponseBuilder, id: []const u8, message: []const u8) void {
    assert(id.len > 0);
    response.fail(500); // Resets the body; the JSON reply below replaces the text.
    response.status = 200;
    response.content_type = "application/json";
    response.body.end = 0;
    rpc.write_error(response.writer(), id, rpc.code.internal_error, message) catch {
        response.fail(500);
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const served_example = [_][]const u8{ "optimism_syncStatus", "admin_sequencerActive" };

test "forwarding: only single unserved requests with an id are forwarded" {
    const forwarded =
        \\{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":[]}
    ;
    try testing.expectEqualStrings("7", forward_id(forwarded, &served_example).?);
    const string_id =
        \\{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x00","latest"],"id":"a"}
    ;
    try testing.expectEqualStrings("\"a\"", forward_id(string_id, &served_example).?);
    const cases = [_][]const u8{
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus","params":[]}
        ,
        \\{"jsonrpc":"2.0","method":"eth_chainId","params":[]}
        ,
        \\[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}]
        ,
        \\{"jsonrpc":"2.0","id":1,"method":"eth_chainId"
        ,
        \\{"jsonrpc":"1.0","id":1,"method":"eth_chainId"}
        ,
        "",
        "42",
    };
    for (cases) |body| try testing.expect(forward_id(body, &served_example) == null);
}

test "forwarding: seeded random bodies never forward served or malformed calls" {
    var prng = Prng.init(0xf0f0);
    const pieces = [_][]const u8{
        "{",
        "}",
        "\"jsonrpc\":\"2.0\"",
        "\"id\":1",
        "\"method\":\"eth_chainId\"",
        ",",
        "[",
        "]",
        "\"method\":\"optimism_syncStatus\"",
        "\"",
        ":",
        "null",
        "\"params\":[]",
    };
    var buffer: [256]u8 = undefined;
    for (0..2000) |_| {
        var writer: std.Io.Writer = .fixed(&buffer);
        const count = prng.below(10);
        for (0..count) |_| writer.writeAll(pieces[prng.below(pieces.len)]) catch break;
        const body = writer.buffered();
        if (forward_id(body, &served_example)) |id| {
            try json.validate(body);
            try testing.expect(id.len > 0);
            try testing.expect(std.mem.indexOf(u8, body, "optimism_syncStatus") == null or
                std.mem.indexOf(u8, body, "eth_chainId") != null);
        }
    }
}

fn fuzz_forward_id(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    const body = bytes[0..smith.slice(&bytes)];
    const id = forward_id(body, &served_example) orelse return;
    try json.validate(body);
    try testing.expect(id.len > 0 and id.len <= id_length_max);
}

test "forwarding: upstream replies must be JSON objects or arrays" {
    try testing.expect(json_rpc_reply("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}"));
    try testing.expect(json_rpc_reply(" [] "));
    try testing.expect(!json_rpc_reply(""));
    try testing.expect(!json_rpc_reply("\"0x1\""));
    try testing.expect(!json_rpc_reply("{\"id\":"));
}

test "forwarding: fuzz" {
    try std.testing.fuzz({}, fuzz_forward_id, .{});
}

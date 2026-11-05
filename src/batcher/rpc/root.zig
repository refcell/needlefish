//! Minimal JSON-RPC 2.0 client for the batcher and devnet tools.
//!
//! The wire transport is injected (`Transport`): binaries plug in an HTTP client,
//! tests and the simulator plug in canned or simulated responses. Memory is fixed at
//! init: one request buffer, one response buffer, and one parse arena, all reused per
//! call. Results borrow the client's buffers and stay valid until the next call.
//!
//! Lives in the batcher lane until `utilities/rpc` lands; then this becomes a thin
//! adapter over it.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const primitives = @import("../../common/primitives/root.zig");

pub const TransportError = error{ TransportFailed, ResponseTooLarge };

/// Sends one request body and writes the response body into `response`.
pub const Transport = struct {
    context: *anyopaque,
    send_fn: *const fn (
        context: *anyopaque,
        body: []const u8,
        response: []u8,
    ) TransportError!usize,

    pub fn send(transport: Transport, body: []const u8, response: []u8) TransportError![]u8 {
        assert(body.len > 0);
        const length = try transport.send_fn(transport.context, body, response);
        assert(length <= response.len);
        return response[0..length];
    }
};

pub const Error = TransportError || error{
    RequestTooLarge,
    MalformedResponse,
    /// The server answered with a JSON-RPC error object; see `Client.last_error`.
    RpcError,
};

pub const Limits = struct {
    request_bytes_max: u32 = 1024 * 1024,
    response_bytes_max: u32 = 4 * 1024 * 1024,
    /// Parsed JSON trees are a few times larger than their text.
    parse_bytes_max: u32 = 16 * 1024 * 1024,
};

pub const Client = struct {
    transport: Transport,
    next_id: u64,
    request: []u8,
    response: []u8,
    arena_memory: []u8,
    arena: std.heap.FixedBufferAllocator,
    last_error_code: i64,
    last_error_message: [256]u8,
    last_error_length: u8,

    pub fn init(allocator: std.mem.Allocator, transport: Transport, limits: Limits) !Client {
        assert(limits.request_bytes_max >= 256);
        assert(limits.response_bytes_max >= 256);
        const request = try allocator.alloc(u8, limits.request_bytes_max);
        errdefer allocator.free(request);
        const response = try allocator.alloc(u8, limits.response_bytes_max);
        errdefer allocator.free(response);
        const arena_memory = try allocator.alloc(u8, limits.parse_bytes_max);
        return .{
            .transport = transport,
            .next_id = 1,
            .request = request,
            .response = response,
            .arena_memory = arena_memory,
            .arena = .init(arena_memory),
            .last_error_code = 0,
            .last_error_message = undefined,
            .last_error_length = 0,
        };
    }

    pub fn deinit(client: *Client, allocator: std.mem.Allocator) void {
        allocator.free(client.request);
        allocator.free(client.response);
        allocator.free(client.arena_memory);
        client.* = undefined;
    }

    pub fn last_error(client: *const Client) []const u8 {
        return client.last_error_message[0..client.last_error_length];
    }

    /// Calls `method` with `params_json` (a JSON array literal) and returns `result`.
    pub fn call(client: *Client, method: []const u8, params_json: []const u8) Error!json.Value {
        assert(method.len > 0);
        assert(params_json.len >= 2 and params_json[0] == '[');
        const id = client.next_id;
        client.next_id += 1;
        const body = std.fmt.bufPrint(
            client.request,
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}",
            .{ id, method, params_json },
        ) catch return error.RequestTooLarge;
        const text = try client.transport.send(body, client.response);
        client.arena.reset();
        const root = json.parseFromSliceLeaky(json.Value, client.arena.allocator(), text, .{
            .duplicate_field_behavior = .use_last,
        }) catch return error.MalformedResponse;
        return client.result_of(root, id);
    }

    fn result_of(client: *Client, root: json.Value, id: u64) Error!json.Value {
        if (root != .object) return error.MalformedResponse;
        const response_id = root.object.get("id") orelse return error.MalformedResponse;
        if (response_id != .integer or response_id.integer != @as(i64, @intCast(id))) {
            return error.MalformedResponse;
        }
        if (root.object.get("error")) |rpc_error| {
            client.record_error(rpc_error);
            return error.RpcError;
        }
        return root.object.get("result") orelse error.MalformedResponse;
    }

    fn record_error(client: *Client, rpc_error: json.Value) void {
        client.last_error_code = 0;
        client.last_error_length = 0;
        if (rpc_error != .object) return;
        if (rpc_error.object.get("code")) |code| {
            if (code == .integer) client.last_error_code = code.integer;
        }
        if (rpc_error.object.get("message")) |message| {
            if (message != .string) return;
            const length = @min(message.string.len, client.last_error_message.len);
            @memcpy(client.last_error_message[0..length], message.string[0..length]);
            client.last_error_length = @intCast(length);
        }
    }
};

pub const DecodeError = error{MalformedResponse};

/// Parses a hex quantity (`"0x1a"`) into `T`.
pub fn quantity(comptime T: type, value: json.Value) DecodeError!T {
    if (value != .string) return error.MalformedResponse;
    return primitives.hex.decode_quantity(T, value.string) catch error.MalformedResponse;
}

/// Parses a block number given either as a JSON integer (op-node `syncStatus`) or as a
/// hex quantity (execution JSON-RPC).
pub fn number(value: json.Value) DecodeError!u64 {
    return switch (value) {
        .integer => |integer| std.math.cast(u64, integer) orelse error.MalformedResponse,
        .string => quantity(u64, value),
        else => error.MalformedResponse,
    };
}

/// Parses hex data (`"0x..."`) into `out`, returning the filled prefix.
pub fn data(value: json.Value, out: []u8) DecodeError![]u8 {
    if (value != .string) return error.MalformedResponse;
    return primitives.hex.decode_into(out, value.string) catch error.MalformedResponse;
}

/// Parses exactly `size` bytes of hex data.
pub fn fixed(comptime size: usize, value: json.Value) DecodeError![size]u8 {
    if (value != .string) return error.MalformedResponse;
    return primitives.hex.decode_array(size, value.string) catch error.MalformedResponse;
}

/// Field `name` of a JSON object.
pub fn field(value: json.Value, name: []const u8) DecodeError!json.Value {
    if (value != .object) return error.MalformedResponse;
    return value.object.get(name) orelse error.MalformedResponse;
}

/// Test and simulation transport: answers from a fixed list of (method, result JSON)
/// pairs, echoing the request id.
pub const CannedTransport = struct {
    answers: []const Answer,
    calls: u32 = 0,

    pub const Answer = struct { method: []const u8, result: []const u8 };

    pub fn transport(canned: *CannedTransport) Transport {
        return .{ .context = canned, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) TransportError!usize {
        const canned: *CannedTransport = @ptrCast(@alignCast(context));
        canned.calls += 1;
        const id = extract(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = extract(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        for (canned.answers) |answer| {
            if (!std.mem.eql(u8, answer.method, method)) continue;
            const text = std.fmt.bufPrint(
                response,
                "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}",
                .{ id, answer.result },
            ) catch return error.ResponseTooLarge;
            return text.len;
        }
        const text = std.fmt.bufPrint(
            response,
            "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                "\"error\":{{\"code\":-32601,\"message\":\"no {s}\"}}}}",
            .{ id, method },
        ) catch return error.ResponseTooLarge;
        return text.len;
    }

    fn extract(body: []const u8, prefix: []const u8, terminator: []const u8) ?[]const u8 {
        const start = (std.mem.indexOf(u8, body, prefix) orelse return null) + prefix.len;
        const length = std.mem.indexOf(u8, body[start..], terminator) orelse return null;
        return body[start..][0..length];
    }
};

const testing = std.testing;

test "rpc: call returns result and decodes quantities" {
    var canned: CannedTransport = .{ .answers = &.{
        .{ .method = "eth_blockNumber", .result = "\"0x2a\"" },
        .{ .method = "eth_getBlockByNumber", .result = "{\"hash\":\"0x0102\",\"number\":\"0x1\"}" },
    } };
    var client = try Client.init(testing.allocator, canned.transport(), .{
        .request_bytes_max = 1024,
        .response_bytes_max = 1024,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    const head = try client.call("eth_blockNumber", "[]");
    try testing.expectEqual(@as(u64, 42), try quantity(u64, head));
    const block = try client.call("eth_getBlockByNumber", "[\"0x1\",false]");
    var out: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, try data(try field(block, "hash"), &out));
    try testing.expectEqual(@as(u32, 2), canned.calls);
}

test "rpc: error objects and malformed responses" {
    var canned: CannedTransport = .{ .answers = &.{} };
    var client = try Client.init(testing.allocator, canned.transport(), .{
        .request_bytes_max = 256,
        .response_bytes_max = 1024,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    try testing.expectError(error.RpcError, client.call("eth_chainId", "[]"));
    try testing.expectEqual(@as(i64, -32601), client.last_error_code);
    try testing.expectEqualStrings("no eth_chainId", client.last_error());
    var long: [300]u8 = @splat('a');
    long[0] = '[';
    long[299] = ']';
    try testing.expectError(error.RequestTooLarge, client.call("x", &long));
    try testing.expectError(error.MalformedResponse, quantity(u64, .{ .integer = 1 }));
}

fn fuzz_response(_: void, smith: *testing.Smith) anyerror!void {
    var text: [512]u8 = undefined;
    const n = smith.slice(&text);
    var memory: [64 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&memory);
    var client: Client = undefined;
    client.last_error_length = 0;
    // Arbitrary server bytes must never crash parsing or result extraction.
    const root = json.parseFromSliceLeaky(json.Value, arena.allocator(), text[0..n], .{}) catch
        return;
    _ = client.result_of(root, 1) catch {};
}

test "rpc: fuzz response handling" {
    try testing.fuzz({}, fuzz_response, .{});
}

//! Test transport for basectl: answers JSON-RPC calls from a script of (method, result)
//! pairs. A `once` answer is consumed by its first match, so a method can return a sequence
//! (a head that advances between doctor samples). Unknown methods get -32601, and
//! `transport_down` makes every call fail like an unreachable endpoint.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../batcher/rpc/root.zig");

pub const answers_max = 64;

pub const FakeTransport = struct {
    answers: []const Answer,
    used: [answers_max]bool = @splat(false),
    transport_down: bool = false,
    calls: u32 = 0,

    pub const Answer = struct {
        method: []const u8,
        result: []const u8 = "null",
        /// Answer with a JSON-RPC error object carrying this code instead of `result`.
        error_code: ?i64 = null,
        once: bool = false,
    };

    pub fn transport(fake: *FakeTransport) rpc.Transport {
        assert(fake.answers.len <= answers_max);
        return .{ .context = fake, .send_fn = send };
    }

    /// A client with small buffers over this transport (tests only).
    pub fn client(fake: *FakeTransport, allocator: std.mem.Allocator) !rpc.Client {
        return rpc.Client.init(allocator, fake.transport(), .{
            .request_bytes_max = 1024,
            .response_bytes_max = 16 * 1024,
            .parse_bytes_max = 256 * 1024,
        });
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const fake: *FakeTransport = @ptrCast(@alignCast(context));
        fake.calls += 1;
        if (fake.transport_down) return error.TransportFailed;
        const id = extract(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = extract(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        assert(method.len > 0);
        for (fake.answers, 0..) |answer, index| {
            if (fake.used[index] or !std.mem.eql(u8, answer.method, method)) continue;
            if (answer.once) fake.used[index] = true;
            return write(response, id, answer);
        }
        return write(response, id, .{ .method = method, .error_code = -32601 });
    }

    fn write(response: []u8, id: []const u8, answer: Answer) rpc.TransportError!usize {
        const text = if (answer.error_code) |code| std.fmt.bufPrint(
            response,
            "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}",
            .{ id, code, answer.method },
        ) else std.fmt.bufPrint(
            response,
            "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}",
            .{ id, answer.result },
        );
        const written = text catch return error.ResponseTooLarge;
        assert(written.len <= response.len);
        return written.len;
    }

    fn extract(body: []const u8, prefix: []const u8, terminator: []const u8) ?[]const u8 {
        const start = (std.mem.indexOf(u8, body, prefix) orelse return null) + prefix.len;
        const length = std.mem.indexOf(u8, body[start..], terminator) orelse return null;
        return body[start..][0..length];
    }
};

test "basectl fake: once answers form a sequence, unknown methods are -32601" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_blockNumber", .result = "\"0x1\"", .once = true },
        .{ .method = "eth_blockNumber", .result = "\"0x2\"" },
    } };
    const testing = std.testing;
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    for ([_]u64{ 1, 2, 2 }) |expected| {
        try testing.expectEqual(expected, try rpc.number(try client.call("eth_blockNumber", "[]")));
    }
    try testing.expectError(error.RpcError, client.call("eth_chainId", "[]"));
    try testing.expectEqual(@as(i64, -32601), client.last_error_code);
}

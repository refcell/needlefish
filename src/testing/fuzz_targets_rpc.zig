//! Model-based fuzz target for the JSON-RPC 2.0 router (`utilities/rpc/root.zig`), which
//! every RPC server in the node (eth, engine, admin, rollup) puts in front of untrusted
//! request bodies.
//!
//! Structured bodies (a single request or a batch) mix valid calls, notifications,
//! null and string ids, unknown methods, bad params, handlers that fail or overflow the
//! output, malformed request objects, and non-object batch elements. A model of the
//! JSON-RPC 2.0 spec predicts every response. Properties:
//!   - the output is empty exactly when the model predicts no response (notifications
//!     only), and otherwise parses as JSON;
//!   - a single request gets one response object, a batch an array of the predicted
//!     responses in order, each with the predicted id and result or error code;
//!   - a handler that overflows the output yields "response too large", never a torn
//!     result;
//!   - arbitrary bytes: the output is empty or valid JSON.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const rpc = @import("../utilities/rpc/root.zig");
const json = @import("../utilities/json/root.zig");

const batch_max = 8;
const body_bytes_max = 4096;
const out_bytes_max = 2048;

/// `echo` returns its one quantity param; `fail` fails with a server error; `big` writes
/// a result larger than the output buffer.
fn handle_echo(_: void, call: *rpc.Call) rpc.HandlerError!void {
    const value = try call.params.quantity(u64);
    try call.params.finish();
    call.writer.quantity(value) catch return error.WriteFailed;
}

fn handle_fail(_: void, call: *rpc.Call) rpc.HandlerError!void {
    return call.fail(rpc.code.server_error, "nope");
}

fn handle_big(_: void, call: *rpc.Call) rpc.HandlerError!void {
    const chunk: [256]u8 = @splat('x');
    call.writer.begin_array() catch return error.WriteFailed;
    for (0..out_bytes_max / chunk.len + 1) |_| {
        call.writer.string(&chunk) catch return error.WriteFailed;
    }
    unreachable; // Proof: the strings exceed the output buffer.
}

const methods = [_]rpc.Method(void){
    .{ .name = "echo", .handler = handle_echo },
    .{ .name = "fail", .handler = handle_fail },
    .{ .name = "big", .handler = handle_big },
};
const Router = rpc.Router(void, &methods);

const IdKind = enum { absent, null, number, string };

/// What the model expects for one request object or batch element.
const Expected = struct {
    respond: bool,
    id: IdKind = .null,
    id_number: u32 = 0,
    /// Null for a result; otherwise the error code.
    error_code: ?i32 = null,
    result: u64 = 0,
};

const Body = struct {
    bytes: [body_bytes_max]u8 = undefined,
    length: usize = 0,

    fn print(body: *Body, comptime format: []const u8, arguments: anytype) void {
        const written = std.fmt.bufPrint(body.bytes[body.length..], format, arguments) catch
            unreachable; // Proof: batch_max small elements fit the body buffer.
        body.length += written.len;
    }
};

/// Appends one element to `body` and returns what the router must answer for it.
fn element(body: *Body, prng: *Prng) Expected {
    switch (prng.below(10)) {
        0 => {
            body.print("{d}", .{prng.below(100)}); // Not an object.
            return .{ .respond = true, .error_code = rpc.code.invalid_request };
        },
        1 => {
            body.print("{{\"method\":\"echo\",\"id\":1}}", .{}); // No jsonrpc member.
            return .{ .respond = true, .error_code = rpc.code.invalid_request };
        },
        2 => {
            body.print("{{\"jsonrpc\":\"2.0\",\"method\":7,\"id\":1}}", .{});
            return .{ .respond = true, .error_code = rpc.code.invalid_request };
        },
        else => return request_call(body, prng),
    }
}

fn request_call(body: *Body, prng: *Prng) Expected {
    var expected: Expected = .{ .respond = true };
    expected.id = @fromBackingInt(@intCast(prng.below(4)));
    expected.id_number = @intCast(prng.below(1000));
    body.print("{{\"jsonrpc\":\"2.0\"", .{});
    switch (expected.id) {
        .absent => expected.respond = false,
        .null => body.print(",\"id\":null", .{}),
        .number => body.print(",\"id\":{d}", .{expected.id_number}),
        .string => body.print(",\"id\":\"r{d}\"", .{expected.id_number}),
    }
    switch (prng.below(6)) {
        0, 1 => {
            expected.result = prng.int(u64);
            body.print(",\"method\":\"echo\",\"params\":[\"0x{x}\"]", .{expected.result});
        },
        2 => {
            body.print(",\"method\":\"echo\",\"params\":[true]", .{});
            expected.error_code = rpc.code.invalid_params;
        },
        3 => {
            body.print(",\"method\":\"fail\",\"params\":[]", .{});
            expected.error_code = rpc.code.server_error;
        },
        4 => {
            body.print(",\"method\":\"big\"", .{});
            expected.error_code = rpc.code.internal_error;
        },
        else => {
            body.print(",\"method\":\"nope{d}\"", .{prng.below(9)});
            expected.error_code = rpc.code.method_not_found;
        },
    }
    body.print("}}", .{});
    return expected;
}

fn expect_response(value: std.json.Value, expected: Expected) !void {
    const object = value.object;
    const id = object.get("id") orelse return error.TestUnexpectedResult;
    switch (expected.id) {
        .absent => unreachable, // Proof: notifications get no response.
        .null => try std.testing.expect(id == .null),
        .number => try std.testing.expectEqual(@as(i64, expected.id_number), id.integer),
        .string => {
            var buffer: [8]u8 = undefined;
            const text = std.fmt.bufPrint(&buffer, "r{d}", .{expected.id_number}) catch
                unreachable;
            try std.testing.expectEqualStrings(text, id.string);
        },
    }
    if (expected.error_code) |error_code| {
        const failure = object.get("error") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(i64, error_code), failure.object.get("code").?.integer);
        try std.testing.expect(object.get("result") == null);
    } else {
        const result = object.get("result") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(expected.result, try json.parse_quantity(u64, result.string));
    }
}

fn fuzz_router(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var body: Body = .{};
    var expected: [batch_max]Expected = undefined;
    const batch = prng.chance(1, 2);
    const count: usize = if (batch) @intCast(prng.range(1, batch_max)) else 1;
    if (batch) body.print("[", .{});
    for (expected[0..count], 0..) |*entry, index| {
        if (index > 0) body.print(",", .{});
        entry.* = if (batch) element(&body, &prng) else request_call(&body, &prng);
    }
    if (batch) body.print("]", .{});

    var out_buffer: [out_bytes_max]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    const outcome = Router.handle({}, body.bytes[0..body.length], &out);
    var responses: usize = 0;
    for (expected[0..count]) |entry| responses += @intFromBool(entry.respond);
    if (responses == 0) {
        try std.testing.expectEqual(rpc.Outcome.empty, outcome);
        return;
    }
    try std.testing.expectEqual(rpc.Outcome.response, outcome);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const Value = std.json.Value;
    const parsed = try std.json.parseFromSliceLeaky(Value, allocator, out.buffered(), .{});
    if (!batch) return expect_response(parsed, expected[0]);
    const items = parsed.array.items;
    try std.testing.expectEqual(responses, items.len);
    var next: usize = 0;
    for (expected[0..count]) |entry| {
        if (!entry.respond) continue;
        try expect_response(items[next], entry);
        next += 1;
    }
}

fn fuzz_router_bytes(_: void, smith: *Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.slice(&input);
    var out_buffer: [out_bytes_max]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    const outcome = Router.handle({}, input[0..length], &out);
    if (outcome == .empty) return;
    try json.validate(out.buffered());
}

test "fuzz_targets_rpc: router answers exactly what JSON-RPC 2.0 requires" {
    try fuzz.run({}, fuzz_router, .{ .iterations = 1024 });
}

test "fuzz_targets_rpc: router output is valid JSON for arbitrary bodies" {
    try fuzz.run({}, fuzz_router_bytes, .{ .iterations = 1024 });
}

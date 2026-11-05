//! A blocking JSON-RPC endpoint for the proof tools (host source, proposer, challenger):
//! each call goes through the non-blocking `rpc.Client`, then the caller's `Pump` advances
//! IO until the callback fires, for at most `steps_max` steps. Results are copied into an
//! arena that the next call resets, so a returned slice is valid until the next call.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");

pub const Address = [20]u8;
pub const Hash = [32]u8;

/// Advances the IO loop by one step (one `tick` or `run_for_ns` slice).
pub const Pump = struct {
    context: *anyopaque,
    step: *const fn (context: *anyopaque) anyerror!void,
};

pub const Error = error{
    /// A `null` result or a JSON-RPC error.
    NotFound,
    /// Transport failure, timeout, or a malformed result.
    CallFailed,
};

/// One positional JSON-RPC parameter.
pub const Param = union(enum) {
    hash: Hash,
    number: u64,
    /// A block tag (`latest`, `safe`, `finalized`) or any other string.
    string: []const u8,
    address: Address,
    /// `{"to": .., "data": ..}` for `eth_call`.
    call: struct { to: Address, data: []const u8 },

    fn write(param: Param, writer: *json.Writer) json.Writer.WriteError!void {
        switch (param) {
            .hash => |hash| try writer.data(&hash),
            .number => |number| try writer.quantity(number),
            .string => |text| try writer.string(text),
            .address => |address| try writer.data(&address),
            .call => |call| {
                try writer.begin_object();
                try writer.key("to");
                try writer.data(&call.to);
                try writer.key("data");
                try writer.data(call.data);
                try writer.end_object();
            },
        }
    }
};

/// A block selector: a number or a tag.
pub const Block = union(enum) {
    number: u64,
    latest,
    safe,
    finalized,

    pub fn param(block: Block) Param {
        return switch (block) {
            .number => |number| .{ .number = number },
            .latest => .{ .string = "latest" },
            .safe => .{ .string = "safe" },
            .finalized => .{ .string = "finalized" },
        };
    }
};

const Params = []const Param;

fn write_params(params: Params, writer: *json.Writer) json.Writer.WriteError!void {
    for (params) |param| try param.write(writer);
}

pub fn Endpoint(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Client = rpc.Client(IO);
        const CallResult = rpc.client.Error!rpc.client.Result;

        client: *Client,
        pump: Pump,
        steps_max: u32,
        arena: std.heap.ArenaAllocator,
        result: ?CallResult = null,
        calls: u64 = 0,

        pub fn init(
            allocator: std.mem.Allocator,
            client: *Client,
            pump: Pump,
            steps_max: u32,
        ) Self {
            assert(steps_max > 0);
            return .{
                .client = client,
                .pump = pump,
                .steps_max = steps_max,
                .arena = .init(allocator),
            };
        }

        pub fn deinit(endpoint: *Self) void {
            endpoint.arena.deinit();
            endpoint.* = undefined;
        }

        /// Frees the previous call's results.
        pub fn reset(endpoint: *Self) void {
            assert(endpoint.result == null);
            _ = endpoint.arena.reset(.retain_capacity);
        }

        fn on_result(endpoint: *Self, client: *Client, result: CallResult) void {
            assert(client == endpoint.client);
            assert(endpoint.result == null);
            // The client reuses its body buffer: keep a copy.
            endpoint.result = if (result) |value| switch (value) {
                .ok => |raw| if (endpoint.arena.allocator().dupe(u8, raw)) |copy|
                    .{ .ok = copy }
                else |_|
                    error.InvalidResponse,
                .rpc_error => value,
            } else |err| err;
        }

        /// One blocking call: the raw JSON result, `NotFound` for `null` or an RPC error.
        /// Results of earlier calls stay valid until `reset`.
        pub fn call(endpoint: *Self, method: []const u8, params: Params) Error![]const u8 {
            assert(endpoint.result == null);
            assert(method.len > 0);
            endpoint.client.call(*Self, endpoint, on_result, method, params, write_params) catch
                return error.CallFailed;
            endpoint.calls += 1;
            var steps: u32 = 0;
            while (endpoint.result == null) : (steps += 1) {
                if (steps == endpoint.steps_max) return error.CallFailed;
                endpoint.pump.step(endpoint.pump.context) catch return error.CallFailed;
            }
            const result = endpoint.result.?;
            endpoint.result = null;
            const raw = switch (result catch return error.CallFailed) {
                .ok => |raw| raw,
                .rpc_error => return error.NotFound,
            };
            if (std.mem.eql(u8, raw, "null")) return error.NotFound;
            return raw;
        }

        /// A JSON hex string decoded into arena bytes.
        pub fn hex(endpoint: *Self, raw: []const u8) Error![]const u8 {
            var scanner = json.Scanner.init(raw);
            const token = scanner.next() catch return error.CallFailed;
            if (token.tag != .string) return error.CallFailed;
            return endpoint.decode_hex(token.bytes);
        }

        pub fn decode_hex(endpoint: *Self, text: []const u8) Error![]const u8 {
            const size = if (text.len >= 2) (text.len - 2) / 2 else 0;
            const out = endpoint.arena.allocator().alloc(u8, size) catch return error.CallFailed;
            return json.parse_data(text, out) catch error.CallFailed;
        }

        /// A JSON array of hex strings, at most `items_max` of them.
        pub fn hex_list(endpoint: *Self, raw: []const u8, items_max: u32) Error![]const []const u8 {
            var scanner = json.Scanner.init(raw);
            const first = scanner.next() catch return error.CallFailed;
            if (first.tag != .array_begin) return error.CallFailed;
            var items: std.ArrayList([]const u8) = .empty;
            const allocator = endpoint.arena.allocator();
            while (true) {
                const token = scanner.next() catch return error.CallFailed;
                if (token.tag == .array_end) break;
                if (token.tag != .string) return error.CallFailed;
                if (items.items.len == items_max) return error.CallFailed;
                const bytes = try endpoint.decode_hex(token.bytes);
                items.append(allocator, bytes) catch return error.CallFailed;
            }
            return items.items;
        }
    };
}

/// A JSON quantity string (`"0x1a"`).
pub fn parse_quantity(raw: []const u8) Error!u64 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.CallFailed;
    return json.parse_quantity(u64, raw[1 .. raw.len - 1]) catch error.CallFailed;
}

/// A 32-byte JSON hex string.
pub fn parse_hash(raw: []const u8) Error!Hash {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.CallFailed;
    return json.parse_fixed(32, raw[1 .. raw.len - 1]) catch error.CallFailed;
}

/// The member at `path` of a JSON object.
pub fn member(raw: []const u8, path: []const []const u8) Error![]const u8 {
    return (json.find_path(raw, path) catch return error.CallFailed) orelse error.CallFailed;
}

/// A JSON number or quantity string (sync status uses plain numbers).
pub fn parse_number(raw: []const u8) Error!u64 {
    if (raw.len > 0 and raw[0] == '"') return parse_quantity(raw);
    return std.fmt.parseInt(u64, raw, 10) catch error.CallFailed;
}

const testing = std.testing;

test "endpoint: JSON value helpers" {
    try testing.expectEqual(@as(u64, 26), try parse_quantity("\"0x1a\""));
    try testing.expectError(error.CallFailed, parse_quantity("26"));
    try testing.expectEqual(@as(u64, 26), try parse_number("26"));
    try testing.expectEqual(@as(u64, 26), try parse_number("\"0x1a\""));
    const object = "{\"a\":{\"b\":\"0x01\"}}";
    try testing.expectEqualStrings("\"0x01\"", try member(object, &.{ "a", "b" }));
    try testing.expectError(error.CallFailed, member(object, &.{"c"}));
    const zero = "\"0x0000000000000000000000000000000000000000000000000000000000000000\"";
    try testing.expectEqual(@as(Hash, @splat(0)), try parse_hash(zero));
    try testing.expectError(error.CallFailed, parse_hash("\"0x00\""));
}

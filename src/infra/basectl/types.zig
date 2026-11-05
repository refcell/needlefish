//! Shared building blocks for basectl commands: bounded text and hash values that own their
//! bytes (RPC results borrow the client's buffers only until the next call), `Probe` for an
//! RPC read that may be unavailable, and the key-value text renderer.
//!
//! Everything here is allocation-free so decoders and renderers stay pure.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");

pub const Writer = std.Io.Writer;
pub const DecodeError = rpc.DecodeError;

/// JSON-RPC "method not found" (base/base reports such reads as unavailable).
pub const method_not_found_code: i64 = -32601;

/// Column the value starts at in key-value output (base/base `KeyValueTable`).
pub const key_width: u32 = 22;

/// Text copied out of a response, truncated to `capacity` bytes.
pub fn Text(comptime capacity: u16) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        length: u16 = 0,

        pub fn init(text: []const u8) Self {
            var result: Self = .{};
            const length: u16 = @intCast(@min(text.len, capacity));
            @memcpy(result.bytes[0..length], text[0..length]);
            result.length = length;
            assert(result.length <= capacity);
            return result;
        }

        pub fn slice(text: *const Self) []const u8 {
            assert(text.length <= capacity);
            return text.bytes[0..text.length];
        }

        pub fn jsonStringify(text: Self, stringify: anytype) !void {
            assert(text.length <= capacity);
            try stringify.write(text.bytes[0..text.length]);
        }
    };
}

/// A 32-byte hash printed as 0x-prefixed lowercase hex.
pub const Hash = struct {
    bytes: [32]u8 = @splat(0),

    pub fn hex(hash: Hash) [66]u8 {
        var out: [66]u8 = undefined;
        out[0] = '0';
        out[1] = 'x';
        out[2..].* = std.fmt.bytesToHex(hash.bytes, .lower);
        assert(out[1] == 'x');
        return out;
    }

    pub fn format(hash: Hash, writer: *Writer) Writer.Error!void {
        const text = hash.hex();
        try writer.writeAll(&text);
    }

    pub fn jsonStringify(hash: Hash, stringify: anytype) !void {
        const text = hash.hex();
        try stringify.write(@as([]const u8, &text));
    }
};

/// A 20-byte address printed as 0x-prefixed lowercase hex.
pub const Address = struct {
    bytes: [20]u8 = @splat(0),

    pub fn hex(address: Address) [42]u8 {
        var out: [42]u8 = undefined;
        out[0] = '0';
        out[1] = 'x';
        out[2..].* = std.fmt.bytesToHex(address.bytes, .lower);
        assert(out[1] == 'x');
        return out;
    }

    pub fn format(address: Address, writer: *Writer) Writer.Error!void {
        const text = address.hex();
        try writer.writeAll(&text);
    }

    pub fn jsonStringify(address: Address, stringify: anytype) !void {
        const text = address.hex();
        try stringify.write(@as([]const u8, &text));
    }
};

/// Up to `capacity` items; only the filled prefix renders to JSON.
pub fn List(comptime T: type, comptime capacity: u16) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();
        pub const items_max = capacity;
        items: [capacity]T = undefined,
        count: u16 = 0,

        pub fn push(list: *Self, item: T) bool {
            assert(list.count <= capacity);
            if (list.count == capacity) return false;
            list.items[list.count] = item;
            list.count += 1;
            return true;
        }

        pub fn slice(list: *const Self) []const T {
            assert(list.count <= capacity);
            return list.items[0..list.count];
        }

        pub fn jsonStringify(list: Self, stringify: anytype) !void {
            assert(list.count <= capacity);
            try stringify.write(list.items[0..list.count]);
        }
    };
}

/// Why an RPC read produced no value.
pub const Failure = enum {
    /// No endpoint was configured for this read.
    not_configured,
    /// The server does not implement the method (JSON-RPC -32601).
    unavailable,
    transport,
    rpc_error,
    malformed,

    pub fn text(failure: Failure) []const u8 {
        return switch (failure) {
            .not_configured => "not configured",
            .unavailable => "unavailable (method not served)",
            .transport => "unreachable",
            .rpc_error => "rpc error",
            .malformed => "malformed response",
        };
    }
};

/// The outcome of one RPC read: a decoded value or the reason there is none.
pub fn Probe(comptime T: type) type {
    return union(enum) {
        const Self = @This();
        ok: T,
        failed: Failure,

        pub fn get(probe_value: Self) ?T {
            return switch (probe_value) {
                .ok => |value| value,
                .failed => null,
            };
        }

        pub fn jsonStringify(probe_value: Self, stringify: anytype) !void {
            switch (probe_value) {
                .ok => |value| try stringify.write(value),
                .failed => |failure| try stringify.write(failure.text()),
            }
        }
    };
}

/// Calls `method` on `client` and decodes the result with `decode`.
pub fn probe(
    comptime T: type,
    client: ?*rpc.Client,
    method: []const u8,
    params_json: []const u8,
    comptime decode: fn (json.Value) DecodeError!T,
) Probe(T) {
    assert(method.len > 0);
    assert(params_json.len >= 2);
    const target = client orelse return .{ .failed = .not_configured };
    const result = target.call(method, params_json) catch |err| {
        return .{ .failed = failure_of(target, err) };
    };
    const value = decode(result) catch return .{ .failed = .malformed };
    return .{ .ok = value };
}

pub fn failure_of(client: *const rpc.Client, err: rpc.Error) Failure {
    return switch (err) {
        error.RpcError => if (client.last_error_code == method_not_found_code)
            .unavailable
        else
            .rpc_error,
        error.MalformedResponse => .malformed,
        error.TransportFailed, error.ResponseTooLarge, error.RequestTooLarge => .transport,
    };
}

// ------------------------------------------------------------------------------ decoders

pub fn decode_bool(value: json.Value) DecodeError!bool {
    if (value != .bool) return error.MalformedResponse;
    return value.bool;
}

/// A JSON integer or hex quantity, as op-node and execution RPCs mix both.
pub fn decode_number(value: json.Value) DecodeError!u64 {
    return rpc.number(value);
}

pub fn decode_hash(value: json.Value) DecodeError!Hash {
    return .{ .bytes = try rpc.fixed(32, value) };
}

pub fn decode_address(value: json.Value) DecodeError!Address {
    return .{ .bytes = try rpc.fixed(20, value) };
}

pub fn decode_string(comptime capacity: u16, value: json.Value) DecodeError!Text(capacity) {
    if (value != .string) return error.MalformedResponse;
    return .init(value.string);
}

/// An optional object field: absent or `null` gives `null`.
pub fn optional_field(value: json.Value, name: []const u8) DecodeError!?json.Value {
    if (value != .object) return error.MalformedResponse;
    const inner = value.object.get(name) orelse return null;
    if (inner == .null) return null;
    return inner;
}

// ------------------------------------------------------------------------------ rendering

/// One `key  value` line, the key padded to `key_width` columns.
pub fn row(writer: *Writer, key: []const u8, comptime format: []const u8, args: anytype) !void {
    assert(key.len > 0);
    try writer.writeAll(key);
    const padding = if (key.len < key_width) key_width - key.len else 1;
    assert(padding >= 1);
    try writer.splatByteAll(' ', padding);
    try writer.print(format ++ "\n", args);
}

pub fn bool_text(value: ?bool) []const u8 {
    const known = value orelse return "unknown";
    return if (known) "true" else "false";
}

/// `value` or `unknown` (base/base `OptionalValue::u64`).
pub fn OptionalNumber(comptime T: type) type {
    return struct {
        value: ?T,
        pub fn format(optional: @This(), writer: *Writer) Writer.Error!void {
            if (optional.value) |value| return writer.print("{d}", .{value});
            try writer.writeAll("unknown");
        }
    };
}

pub fn optional_number(value: ?u64) OptionalNumber(u64) {
    return .{ .value = value };
}

/// `YYYY-MM-DD HH:MM:SS UTC` for a unix timestamp.
pub const UnixTime = struct {
    seconds: u64,

    pub fn format(time: UnixTime, writer: *Writer) Writer.Error!void {
        const epoch: std.time.epoch.EpochSeconds = .{ .secs = time.seconds };
        const year_day = epoch.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_seconds = epoch.getDaySeconds();
        try writer.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
            year_day.year,
            month_day.month.numeric(),
            @as(u32, month_day.day_index) + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        });
    }
};

/// Compact duration such as `1h 2m 3s` (base/base `Format::duration`).
pub const Duration = struct {
    seconds: u64,

    pub fn format(duration: Duration, writer: *Writer) Writer.Error!void {
        const hours = duration.seconds / 3600;
        const minutes = (duration.seconds % 3600) / 60;
        const seconds = duration.seconds % 60;
        if (hours > 0) try writer.print("{d}h ", .{hours});
        if (hours > 0 or minutes > 0) try writer.print("{d}m ", .{minutes});
        try writer.print("{d}s", .{seconds});
    }
};

/// Wei as gwei with nine decimals (base/base `Format::gwei`).
pub const Gwei = struct {
    wei: u128,

    pub fn format(gwei: Gwei, writer: *Writer) Writer.Error!void {
        const whole = gwei.wei / 1_000_000_000;
        const fraction = gwei.wei % 1_000_000_000;
        try writer.print("{d}.{d:0>9} gwei", .{ whole, fraction });
    }
};

/// Writes `value` as indented JSON followed by a newline.
pub fn render_json(value: anytype, writer: *Writer) !void {
    try json.Stringify.value(value, .{ .whitespace = .indent_2 }, writer);
    try writer.writeByte('\n');
}

const testing = std.testing;

test "basectl types: text, hash, rows, time formats" {
    const text: Text(4) = .init("abcdef");
    try testing.expectEqualStrings("abcd", text.slice());
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try row(&writer, "key", "{d}", .{7});
    try row(&writer, "time", "{f}", .{UnixTime{ .seconds = 1_700_000_000 }});
    try row(&writer, "lag", "{f}", .{Duration{ .seconds = 3725 }});
    try row(&writer, "fee", "{f}", .{Gwei{ .wei = 1_500_000_001 }});
    try row(&writer, "number", "{f}", .{optional_number(null)});
    try testing.expectEqualStrings(
        "key                   7\n" ++
            "time                  2023-11-14 22:13:20 UTC\n" ++
            "lag                   1h 2m 5s\n" ++
            "fee                   1.500000001 gwei\n" ++
            "number                unknown\n",
        writer.buffered(),
    );
    const hash: Hash = .{ .bytes = @splat(0xab) };
    try testing.expectEqualStrings("0xabab", hash.hex()[0..6]);
}

test "basectl types: probe json and failure text" {
    var buffer: [256]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    const Item = struct { a: Probe(u64), b: Probe(u64), list: List(u16, 4) };
    var item: Item = .{ .a = .{ .ok = 3 }, .b = .{ .failed = .unavailable }, .list = .{} };
    try testing.expect(item.list.push(9));
    try json.Stringify.value(item, .{}, &writer);
    try testing.expectEqualStrings(
        "{\"a\":3,\"b\":\"unavailable (method not served)\",\"list\":[9]}",
        writer.buffered(),
    );
}

// ------------------------------------------------------------------------------ context

/// One RPC endpoint: its client (absent when not configured) and URL for display.
pub const Endpoint = struct {
    client: ?*rpc.Client = null,
    url: []const u8 = "",
};

/// The endpoints every command reads from, plus the network label it prints.
pub const Context = struct {
    network: []const u8 = "devnet",
    l1: Endpoint = .{},
    l2: Endpoint = .{},
    rollup: Endpoint = .{},
    batcher: Endpoint = .{},
    conductor: Endpoint = .{},
};

/// A required read that failed: which one, and why.
pub const CommandFailure = struct {
    what: []const u8,
    failure: Failure,
};

/// A command's fetch result: its report, or the required read that failed.
pub fn Fetched(comptime T: type) type {
    return union(enum) {
        ok: T,
        failed: CommandFailure,
    };
}

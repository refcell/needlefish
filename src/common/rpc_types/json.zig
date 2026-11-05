//! Streaming JSON writer for Ethereum JSON-RPC objects: quantities (`0x`-prefixed,
//! no leading zeros), data (`0x`-prefixed hex), checksummed addresses. Writes straight
//! to a `std.Io.Writer`; nothing is allocated.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const Writer = std.Io.Writer;
const Address = primitives.Address;

pub const Error = Writer.Error;

pub fn write_quantity(w: *Writer, value: u256) Error!void {
    var buffer: [66]u8 = undefined;
    try w.writeByte('"');
    try w.writeAll(primitives.hex.encode_quantity(&buffer, value));
    try w.writeByte('"');
}

/// `"0x" ++ hex(bytes)`, streamed in bounded chunks.
pub fn write_data(w: *Writer, bytes: []const u8) Error!void {
    const chunk_size = 64;
    var buffer: [chunk_size * 2]u8 = undefined;
    try w.writeAll("\"0x");
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = @min(offset + chunk_size, bytes.len);
        const chunk = bytes[offset..end];
        primitives.hex.encode(buffer[0 .. chunk.len * 2], chunk);
        try w.writeAll(buffer[0 .. chunk.len * 2]);
        offset = end;
    }
    assert(offset == bytes.len);
    try w.writeByte('"');
}

/// EIP-55 checksummed, as reth/alloy serialize addresses.
pub fn write_address(w: *Writer, address: Address) Error!void {
    const text = primitives.bytes.checksum(address, null);
    try w.writeByte('"');
    try w.writeAll(&text);
    try w.writeByte('"');
}

/// An object being written: `begin`, fields, `end`.
pub const Object = struct {
    w: *Writer,
    first: bool = true,

    pub fn begin(w: *Writer) Error!Object {
        try w.writeByte('{');
        return .{ .w = w };
    }

    pub fn end(object: *Object) Error!void {
        try object.w.writeByte('}');
    }

    /// Writes `"name":` (with a separating comma); the caller writes the value.
    pub fn key(object: *Object, name: []const u8) Error!void {
        assert(name.len > 0);
        if (!object.first) try object.w.writeByte(',');
        object.first = false;
        try object.w.writeByte('"');
        try object.w.writeAll(name);
        try object.w.writeAll("\":");
    }

    pub fn quantity(object: *Object, name: []const u8, value: anytype) Error!void {
        try object.key(name);
        try write_quantity(object.w, value);
    }

    /// Omitted when null.
    pub fn optional_quantity(object: *Object, name: []const u8, value: anytype) Error!void {
        if (value) |present| try object.quantity(name, present);
    }

    pub fn data(object: *Object, name: []const u8, bytes: []const u8) Error!void {
        try object.key(name);
        try write_data(object.w, bytes);
    }

    /// Fixed-size byte types (`B256`, `Bloom`, `B64`).
    pub fn fixed(object: *Object, name: []const u8, value: anytype) Error!void {
        try object.data(name, &value.bytes);
    }

    pub fn optional_fixed(object: *Object, name: []const u8, value: anytype) Error!void {
        if (value) |present| try object.fixed(name, present);
    }

    pub fn address(object: *Object, name: []const u8, value: Address) Error!void {
        try object.key(name);
        try write_address(object.w, value);
    }

    /// `null` when absent (fields like `to` and `contractAddress` are always present).
    pub fn address_or_null(object: *Object, name: []const u8, value: ?Address) Error!void {
        try object.key(name);
        if (value) |present| {
            try write_address(object.w, present);
        } else {
            try object.w.writeAll("null");
        }
    }

    pub fn quantity_or_null(object: *Object, name: []const u8, value: anytype) Error!void {
        try object.key(name);
        if (value) |present| {
            try write_quantity(object.w, present);
        } else {
            try object.w.writeAll("null");
        }
    }

    pub fn fixed_or_null(object: *Object, name: []const u8, value: anytype) Error!void {
        try object.key(name);
        if (value) |present| {
            try write_data(object.w, &present.bytes);
        } else {
            try object.w.writeAll("null");
        }
    }

    pub fn boolean(object: *Object, name: []const u8, value: bool) Error!void {
        try object.key(name);
        try object.w.writeAll(if (value) "true" else "false");
    }
};

const testing = std.testing;

test "rpc json: object encodings" {
    var buffer: [512]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    var object = try Object.begin(&w);
    try object.quantity("zero", @as(u64, 0));
    try object.quantity("big", @as(u256, 0x1234));
    try object.optional_quantity("skipped", @as(?u64, null));
    try object.data("empty", &.{});
    try object.data("bytes", &.{ 0xde, 0xad });
    try object.address_or_null("to", null);
    try object.boolean("flag", true);
    try object.end();
    try testing.expectEqualStrings(
        \\{"zero":"0x0","big":"0x1234","empty":"0x","bytes":"0xdead","to":null,"flag":true}
    , w.buffered());
}

test "rpc json: long data and checksum" {
    var buffer: [1024]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    var bytes: [200]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index);
    try write_data(&w, &bytes);
    try testing.expectEqual(@as(usize, 2 + 2 + 400), w.buffered().len);
    try testing.expectEqualStrings("\"0x0001", w.buffered()[0..7]);
    var w2: Writer = .fixed(&buffer);
    try write_address(&w2, Address.comptime_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
    try testing.expectEqualStrings("\"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\"", w2.buffered());
}

//! Preimage archive: a recorded host store as one canonical byte string, so a proof run
//! recorded online can be replayed offline (base/base keeps a disk KV store; the needlefish
//! host writes this file through `utilities.io` instead).
//!
//! Layout (integers little-endian):
//!   magic "NFPA" | version u32 = 1 | count u32 |
//!   count × (key [32]u8 | length u32 | value [length]u8)
//! Keys strictly increase (bytewise), so an archive has exactly one encoding. The decoder
//! is strict: bad magic or version, unsorted or duplicate keys, truncation and trailing
//! bytes are all errors.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const store_module = @import("store.zig");

const Store = store_module.Store;

pub const magic = "NFPA";
pub const version: u32 = 1;
pub const header_bytes = 12;
pub const entry_header_bytes = 36;

pub const DecodeError = store_module.Error || error{
    InvalidMagic,
    UnsupportedVersion,
    Truncated,
    UnsortedKeys,
    TrailingBytes,
    InvalidKey,
};

fn less_than(_: void, a: [32]u8, b: [32]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

/// The archive size of `store`.
pub fn encoded_bytes(store: *const Store) u64 {
    var total: u64 = header_bytes;
    var values = store.map.valueIterator();
    while (values.next()) |value| total += entry_header_bytes + value.len;
    return total;
}

/// Writes `store` as an archive. `keys_scratch` must hold `store.count()` keys.
pub fn encode(
    store: *const Store,
    keys_scratch: [][32]u8,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    assert(keys_scratch.len >= store.count());
    const keys = keys_scratch[0..store.count()];
    var iterator = store.map.keyIterator();
    for (keys) |*key| key.* = iterator.next().?.*;
    assert(iterator.next() == null);
    std.mem.sort([32]u8, keys, {}, less_than);
    try writer.writeAll(magic);
    try writer.writeInt(u32, version, .little);
    try writer.writeInt(u32, @intCast(keys.len), .little);
    for (keys) |*key| {
        const value = store.map.get(key.*).?;
        try writer.writeAll(key);
        try writer.writeInt(u32, @intCast(value.len), .little);
        try writer.writeAll(value);
    }
}

/// Loads every entry of `bytes` into `store`.
pub fn decode(bytes: []const u8, store: *Store) DecodeError!void {
    if (bytes.len < header_bytes) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.InvalidMagic;
    if (std.mem.readInt(u32, bytes[4..8], .little) != version) return error.UnsupportedVersion;
    const count = std.mem.readInt(u32, bytes[8..12], .little);
    var offset: usize = header_bytes;
    var previous: ?[32]u8 = null;
    for (0..count) |_| {
        if (bytes.len - offset < entry_header_bytes) return error.Truncated;
        const raw: [32]u8 = bytes[offset..][0..32].*;
        const length = std.mem.readInt(u32, bytes[offset + 32 ..][0..4], .little);
        offset += entry_header_bytes;
        if (bytes.len - offset < length) return error.Truncated;
        if (previous) |last| if (!less_than({}, last, raw)) return error.UnsortedKeys;
        previous = raw;
        const key = preimage.Key.from_bytes(raw) catch return error.InvalidKey;
        try store.put(key, bytes[offset..][0..length]);
        offset += length;
    }
    if (offset != bytes.len) return error.TrailingBytes;
    assert(store.count() >= count);
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

fn round_trip(store: *const Store) ![]u8 {
    const keys = try testing.allocator.alloc([32]u8, store.count());
    defer testing.allocator.free(keys);
    const buffer = try testing.allocator.alloc(u8, @intCast(encoded_bytes(store)));
    errdefer testing.allocator.free(buffer);
    var writer: std.Io.Writer = .fixed(buffer);
    try encode(store, keys, &writer);
    try testing.expectEqual(buffer.len, writer.buffered().len);
    return buffer;
}

test "archive: round trip is canonical and strict" {
    var store: Store = .init(testing.allocator, .{});
    defer store.deinit();
    _ = try store.put_keccak("node");
    try store.put(.local(1), &@as([32]u8, @splat(1)));
    try store.put(.sha256(@splat(2)), "commitment");
    const bytes = try round_trip(&store);
    defer testing.allocator.free(bytes);
    var loaded: Store = .init(testing.allocator, .{});
    defer loaded.deinit();
    try decode(bytes, &loaded);
    try testing.expectEqual(store.count(), loaded.count());
    try testing.expectEqualStrings("commitment", loaded.get(.sha256(@splat(2))).?);
    const again = try round_trip(&loaded);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
    var scratch: Store = .init(testing.allocator, .{});
    defer scratch.deinit();
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1], &scratch));
    const bad_magic = "XXXX\x01\x00\x00\x00\x00\x00\x00\x00";
    try testing.expectError(error.InvalidMagic, decode(bad_magic, &scratch));
    // Two entries with keys in decreasing order.
    var unsorted: [header_bytes + 2 * entry_header_bytes]u8 = @splat(0);
    @memcpy(unsorted[0..4], magic);
    std.mem.writeInt(u32, unsorted[4..8], version, .little);
    std.mem.writeInt(u32, unsorted[8..12], 2, .little);
    unsorted[header_bytes] = 0x05; // Key type blob, data 0x05..
    unsorted[header_bytes + 1] = 9;
    unsorted[header_bytes + entry_header_bytes] = 0x05;
    try testing.expectError(error.UnsortedKeys, decode(&unsorted, &scratch));
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u32, bytes[4..8], version, .little);
    const length = 8 + smith.slice(bytes[8..]);
    var store: Store = .init(testing.allocator, .{ .entries_max = 64, .bytes_max = 4096 });
    defer store.deinit();
    // Arbitrary input decodes or fails cleanly; a success re-encodes to the same bytes.
    decode(bytes[0..length], &store) catch return;
    const again = try round_trip(&store);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, bytes[0..length], again);
}

test "archive: fuzz decode" {
    try fuzz.run({}, fuzz_decode, .{ .iterations = 1024 });
}

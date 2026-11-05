//! Nibble paths and hex-prefix (compact) encoding.
//!
//! A trie key is walked one nibble (half byte) at a time. `Nibbles` stores one nibble per byte,
//! which keeps slicing and comparison trivial. Hex-prefix encoding packs a nibble path back into
//! bytes with a flag nibble that marks leaf versus extension and odd versus even length.

const std = @import("std");
const assert = std.debug.assert;

/// Longest key the trie supports, in bytes. State keys are 32-byte hashes; the public trie test
/// vectors use keys up to this length.
pub const key_bytes_max = 64;
pub const nibbles_max = key_bytes_max * 2;
/// Longest hex-prefix encoding: flag byte plus packed nibbles.
pub const hex_prefix_bytes_max = key_bytes_max + 1;

comptime {
    assert(nibbles_max <= std.math.maxInt(u8));
}

pub const Nibbles = struct {
    len: u8 = 0,
    data: [nibbles_max]u8 = undefined,

    pub fn from_bytes(bytes: []const u8) Nibbles {
        assert(bytes.len <= key_bytes_max);
        var result: Nibbles = .{ .len = @intCast(bytes.len * 2) };
        for (bytes, 0..) |byte, index| {
            result.data[index * 2] = byte >> 4;
            result.data[index * 2 + 1] = byte & 0x0f;
        }
        assert(result.len % 2 == 0);
        return result;
    }

    pub fn from_nibbles(nibbles: []const u8) Nibbles {
        assert(nibbles.len <= nibbles_max);
        var result: Nibbles = .{ .len = @intCast(nibbles.len) };
        for (nibbles, 0..) |nibble, index| {
            assert(nibble < 16);
            result.data[index] = nibble;
        }
        return result;
    }

    pub fn slice(self: *const Nibbles) []const u8 {
        return self.data[0..self.len];
    }

    pub fn push(self: *Nibbles, nibble: u8) void {
        assert(nibble < 16);
        assert(self.len < nibbles_max);
        self.data[self.len] = nibble;
        self.len += 1;
    }

    pub fn append(self: *Nibbles, nibbles: []const u8) void {
        assert(self.len + nibbles.len <= nibbles_max);
        for (nibbles) |nibble| self.push(nibble);
    }

    pub fn truncate(self: *Nibbles, len: u32) void {
        assert(len <= self.len);
        self.len = @intCast(len);
    }

    /// Packs an even-length path back into bytes.
    pub fn pack(self: *const Nibbles, out: []u8) []u8 {
        assert(self.len % 2 == 0);
        assert(out.len >= self.len / 2);
        const count = self.len / 2;
        for (0..count) |index| {
            out[index] = (self.data[index * 2] << 4) | self.data[index * 2 + 1];
        }
        return out[0..count];
    }
};

pub fn common_prefix_length(a: []const u8, b: []const u8) u32 {
    const limit = @min(a.len, b.len);
    var index: u32 = 0;
    while (index < limit and a[index] == b[index]) index += 1;
    assert(index <= a.len and index <= b.len);
    return index;
}

/// Lexicographic order on nibble paths; a proper prefix sorts first.
pub fn order(a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, a, b);
}

/// Encodes `path` with the hex-prefix flag. Returns the number of bytes written to `out`.
pub fn hex_prefix_encode(path: []const u8, leaf: bool, out: *[hex_prefix_bytes_max]u8) u32 {
    assert(path.len <= nibbles_max);
    const odd = path.len % 2 == 1;
    const flag: u8 = (if (leaf) @as(u8, 2) else 0) + (if (odd) @as(u8, 1) else 0);
    var rest = path;
    if (odd) {
        assert(path[0] < 16);
        out[0] = (flag << 4) | path[0];
        rest = path[1..];
    } else {
        out[0] = flag << 4;
    }
    assert(rest.len % 2 == 0);
    const pairs = rest.len / 2;
    for (0..pairs) |index| {
        assert(rest[index * 2] < 16 and rest[index * 2 + 1] < 16);
        out[1 + index] = (rest[index * 2] << 4) | rest[index * 2 + 1];
    }
    const written: u32 = @intCast(1 + pairs);
    assert(written == path.len / 2 + 1);
    return written;
}

pub const HexPrefixError = error{ InvalidHexPrefix, PathTooLong };

pub const Decoded = struct {
    path: Nibbles,
    leaf: bool,
};

pub fn hex_prefix_decode(encoded: []const u8) HexPrefixError!Decoded {
    if (encoded.len == 0) return error.InvalidHexPrefix;
    const flag = encoded[0] >> 4;
    if (flag > 3) return error.InvalidHexPrefix;
    const odd = flag & 1 == 1;
    if (!odd and encoded[0] & 0x0f != 0) return error.InvalidHexPrefix;
    const length = (encoded.len - 1) * 2 + @intFromBool(odd);
    if (length > nibbles_max) return error.PathTooLong;
    var result: Decoded = .{ .path = .{}, .leaf = flag & 2 == 2 };
    if (odd) result.path.push(encoded[0] & 0x0f);
    for (encoded[1..]) |byte| {
        result.path.push(byte >> 4);
        result.path.push(byte & 0x0f);
    }
    assert(result.path.len == length);
    return result;
}

const testing = std.testing;

test "nibbles: hex prefix examples from the yellow paper" {
    var out: [hex_prefix_bytes_max]u8 = undefined;
    var n = hex_prefix_encode(&.{ 1, 2, 3, 4, 5 }, false, &out);
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x23, 0x45 }, out[0..n]);
    n = hex_prefix_encode(&.{ 0, 1, 2, 3, 4, 5 }, false, &out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x23, 0x45 }, out[0..n]);
    n = hex_prefix_encode(&.{ 0, 15, 1, 12, 11, 8 }, true, &out);
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x0f, 0x1c, 0xb8 }, out[0..n]);
    n = hex_prefix_encode(&.{ 15, 1, 12, 11, 8 }, true, &out);
    try testing.expectEqualSlices(u8, &.{ 0x3f, 0x1c, 0xb8 }, out[0..n]);
    n = hex_prefix_encode(&.{}, true, &out);
    try testing.expectEqualSlices(u8, &.{0x20}, out[0..n]);
}

test "nibbles: hex prefix rejects bad flags" {
    try testing.expectError(error.InvalidHexPrefix, hex_prefix_decode(&.{}));
    try testing.expectError(error.InvalidHexPrefix, hex_prefix_decode(&.{0x40}));
    try testing.expectError(error.InvalidHexPrefix, hex_prefix_decode(&.{0x05}));
}

fn check_roundtrip(path: []const u8, leaf: bool) !void {
    var out: [hex_prefix_bytes_max]u8 = undefined;
    const n = hex_prefix_encode(path, leaf, &out);
    const decoded = try hex_prefix_decode(out[0..n]);
    try testing.expectEqual(leaf, decoded.leaf);
    try testing.expectEqualSlices(u8, path, decoded.path.slice());
}

test "nibbles: seeded fuzz hex prefix roundtrip" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x1b);
    var path: [nibbles_max]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < 2000) : (iteration += 1) {
        const length = prng.below(nibbles_max + 1);
        for (path[0..length]) |*nibble| nibble.* = @intCast(prng.below(16));
        try check_roundtrip(path[0..length], prng.chance(1, 2));
    }
}

fn fuzz_hex_prefix(_: void, smith: *testing.Smith) anyerror!void {
    var input: [hex_prefix_bytes_max + 4]u8 = undefined;
    const length = smith.slice(&input);
    const decoded = hex_prefix_decode(input[0..length]) catch return;
    try check_roundtrip(decoded.path.slice(), decoded.leaf);
}

test "nibbles: fuzz hex prefix decode" {
    try testing.fuzz({}, fuzz_hex_prefix, .{});
}

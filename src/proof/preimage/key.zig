//! Preimage keys. Port of base/base `crates/proof/preimage/src/key.rs`.
//!
//! A key is 32 bytes on the wire: byte 0 is the key type, bytes 1..32 are the key
//! data. Local keys carry a big-endian `u64` identifier in the low 8 bytes; hash keys
//! carry the low 31 bytes of the digest.

const std = @import("std");
const assert = std.debug.assert;
const keccak = @import("../../common/crypto/keccak.zig");

pub const key_size = 32;
pub const data_size = 31;

pub const KeyType = enum(u8) {
    local = 1,
    keccak256 = 2,
    global_generic = 3,
    sha256 = 4,
    blob = 5,
    precompile = 6,

    pub fn from_byte(byte: u8) error{InvalidPreimageKey}!KeyType {
        return switch (byte) {
            1...6 => @fromBackingInt(@intCast(byte)),
            else => error.InvalidPreimageKey,
        };
    }
};

comptime {
    assert(@backingInt(KeyType.local) == 1);
    assert(@backingInt(KeyType.precompile) == 6);
}

pub const Key = struct {
    data: [data_size]u8,
    key_type: KeyType,

    /// Builds a key from a 32-byte value, dropping byte 0 (it becomes the type).
    pub fn init(raw: [key_size]u8, key_type: KeyType) Key {
        var key: Key = .{ .data = undefined, .key_type = key_type };
        @memcpy(&key.data, raw[1..]);
        assert(std.mem.eql(u8, &key.data, raw[1..]));
        return key;
    }

    pub fn local(identifier: u64) Key {
        var key: Key = .{ .data = @splat(0), .key_type = .local };
        std.mem.writeInt(u64, key.data[data_size - 8 ..], identifier, .big);
        assert(key.data[0] == 0);
        return key;
    }

    pub fn keccak256(digest: [key_size]u8) Key {
        return init(digest, .keccak256);
    }

    pub fn sha256(digest: [key_size]u8) Key {
        return init(digest, .sha256);
    }

    /// Key for a precompile call: keccak256(address ++ input) typed as precompile.
    pub fn precompile(address: [20]u8, input: []const u8) Key {
        var hasher = keccak.Hasher.init();
        hasher.update(&address);
        hasher.update(input);
        return init(hasher.final(), .precompile);
    }

    /// The 31 data bytes as a big-endian integer.
    pub fn value(key: Key) u248 {
        return std.mem.readInt(u248, &key.data, .big);
    }

    pub fn to_bytes(key: Key) [key_size]u8 {
        var raw: [key_size]u8 = undefined;
        raw[0] = @backingInt(key.key_type);
        @memcpy(raw[1..], &key.data);
        assert(raw[0] >= 1 and raw[0] <= 6);
        return raw;
    }

    pub fn from_bytes(raw: [key_size]u8) error{InvalidPreimageKey}!Key {
        const key_type = try KeyType.from_byte(raw[0]);
        return init(raw, key_type);
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.key_type == b.key_type and std.mem.eql(u8, &a.data, &b.data);
    }

    pub fn format(key: Key, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const raw = key.to_bytes();
        try writer.print("0x{x}", .{&raw});
    }
};

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "key: type from byte" {
    try testing.expectEqual(KeyType.local, try KeyType.from_byte(1));
    try testing.expectEqual(KeyType.keccak256, try KeyType.from_byte(2));
    try testing.expectEqual(KeyType.global_generic, try KeyType.from_byte(3));
    try testing.expectEqual(KeyType.sha256, try KeyType.from_byte(4));
    try testing.expectEqual(KeyType.blob, try KeyType.from_byte(5));
    try testing.expectEqual(KeyType.precompile, try KeyType.from_byte(6));
    try testing.expectError(error.InvalidPreimageKey, KeyType.from_byte(0));
    try testing.expectError(error.InvalidPreimageKey, KeyType.from_byte(7));
}

test "key: local value" {
    const key = Key.local(0xff);
    try testing.expectEqual(KeyType.local, key.key_type);
    try testing.expectEqual(@as(u248, 0xff), key.value());
}

test "key: value of all ones" {
    const key = Key.init(@splat(0xff), .local);
    try testing.expectEqual(std.math.maxInt(u248), key.value());
}

test "key: display" {
    var buffer: [80]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{Key.init(@splat(0xff), .local)});
    try testing.expectEqualStrings(
        "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        text,
    );
}

test "key: rendering for every type" {
    var byte: u8 = 1;
    while (byte <= 6) : (byte += 1) {
        const key_type = try KeyType.from_byte(byte);
        const key = Key.init(@splat(0xff), key_type);
        var expected: [key_size]u8 = @splat(0xff);
        expected[0] = byte;
        try testing.expectEqualSlices(u8, &expected, &key.to_bytes());
        try testing.expect(key.eql(try Key.from_bytes(expected)));
    }
}

test "key: precompile hashes address and input" {
    const address: [20]u8 = @splat(0x01);
    const key = Key.precompile(address, "abc");
    var concatenated: [23]u8 = undefined;
    @memcpy(concatenated[0..20], &address);
    @memcpy(concatenated[20..], "abc");
    const digest = keccak.keccak256(&concatenated);
    try testing.expectEqualSlices(u8, digest[1..], &key.data);
    try testing.expectEqual(KeyType.precompile, key.key_type);
}

fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    var raw: [key_size]u8 = undefined;
    smith.bytes(&raw);
    const parsed = Key.from_bytes(raw) catch {
        try testing.expect(raw[0] == 0 or raw[0] > 6);
        return;
    };
    try testing.expectEqualSlices(u8, &raw, &parsed.to_bytes());
    try testing.expectEqual(std.mem.readInt(u248, raw[1..], .big), parsed.value());
}

test "key: fuzz byte round trip" {
    try fuzz.run({}, fuzz_round_trip, .{});
}

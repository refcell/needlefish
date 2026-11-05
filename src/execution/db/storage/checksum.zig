//! 128-bit checksums for every on-disk structure.
//!
//! AEGIS-128L as a MAC with an all-zero key: hardware AES makes it faster than any
//! non-cryptographic hash of comparable strength, and 128 bits make an accidental match
//! (torn write, bit rot, misdirected I/O) practically impossible. The key is public, so this
//! detects corruption, not tampering.

const std = @import("std");
const assert = std.debug.assert;

const Mac = std.crypto.auth.aegis.Aegis128LMac_128;
const key: [Mac.key_length]u8 = @splat(0);

comptime {
    assert(Mac.mac_length == 16);
}

pub fn checksum(bytes: []const u8) u128 {
    var out: [Mac.mac_length]u8 = undefined;
    Mac.create(&out, bytes, &key);
    return std.mem.readInt(u128, &out, .little);
}

/// Incremental form: `Stream` over chunks equals `checksum` over their concatenation.
pub const Stream = struct {
    mac: Mac,

    pub fn init() Stream {
        return .{ .mac = Mac.init(&key) };
    }

    pub fn update(stream: *Stream, bytes: []const u8) void {
        stream.mac.update(bytes);
    }

    pub fn final(stream: *Stream) u128 {
        var out: [Mac.mac_length]u8 = undefined;
        stream.mac.final(&out);
        return std.mem.readInt(u128, &out, .little);
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "checksum: stable test vectors" {
    // Pinned values: changing the checksum function silently invalidates every data file.
    try testing.expectEqual(@as(u128, 0x635037dbb2b81e9bf114d2092a5aa1ad), checksum(""));
    var bytes: [4096]u8 = undefined;
    var prng = Prng.init(42);
    prng.fill(&bytes);
    try testing.expectEqual(@as(u128, 0x678aa24c61a6c25bb9c39dbb34379e50), checksum(&bytes));
}

test "checksum: stream equals one shot, single bit flips change it" {
    var prng = Prng.init(7);
    var bytes: [1000]u8 = undefined;
    for (0..64) |_| {
        const length: usize = @intCast(prng.below(bytes.len + 1));
        prng.fill(bytes[0..length]);
        var stream = Stream.init();
        var position: usize = 0;
        while (position < length) {
            const step: usize = @intCast(prng.range(1, length - position));
            stream.update(bytes[position .. position + step]);
            position += step;
        }
        const expected = checksum(bytes[0..length]);
        try testing.expectEqual(expected, stream.final());
        if (length > 0) {
            const index: usize = @intCast(prng.below(length));
            bytes[index] ^= @as(u8, 1) << @intCast(prng.below(8));
            try testing.expect(checksum(bytes[0..length]) != expected);
        }
    }
}

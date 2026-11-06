//! Split-block Bloom filter (the Parquet/Impala layout) for LSM tables.
//!
//! The filter is an array of 32-byte blocks of eight `u32` words. A key's 64-bit hash picks
//! one block from its high half; its low half, multiplied by eight odd salts, sets one bit in
//! each word. A probe touches one cache line, and at 10 bits per key the false-positive rate
//! is about 1%.
//!
//! The filter only ever answers "maybe present" or "absent": a table that a filter rules out
//! is never read, so a false negative would lose data. `may_contain` therefore must hold for
//! every inserted hash, which the tests check exhaustively over random sets.

const std = @import("std");
const assert = std.debug.assert;

pub const words_per_block: u32 = 8;
pub const block_bytes: u32 = words_per_block * 4;

const salts: [words_per_block]u32 = .{
    0x47b6137b, 0x44974d91, 0x8824ad5b, 0xa2b7289d,
    0x705495c7, 0x2df1424b, 0x9efc4947, 0x5c6bfb31,
};

comptime {
    assert(block_bytes == 32);
    for (salts) |salt| assert(salt % 2 == 1);
}

/// Words a filter for `keys_max` keys at `bits_per_key` needs (at least one block).
pub fn word_count(keys_max: u64, bits_per_key: u32) u32 {
    assert(bits_per_key > 0);
    assert(keys_max > 0);
    const bits = keys_max * bits_per_key;
    const blocks = @max(1, std.math.divCeil(u64, bits, block_bytes * 8) catch unreachable);
    return @intCast(blocks * words_per_block);
}

/// The hash filters use for a key.
pub fn hash(key: []const u8) u64 {
    assert(key.len > 0);
    return std.hash.Wyhash.hash(0x6c73_6d66, key);
}

fn block_of(words: []const u32, key_hash: u64) usize {
    const blocks: u64 = words.len / words_per_block;
    assert(blocks > 0);
    // Multiply-shift maps the high half onto `blocks` without a division.
    const block: usize = @intCast(((key_hash >> 32) * blocks) >> 32);
    assert(block < blocks);
    return block * words_per_block;
}

pub fn insert(words: []u32, key_hash: u64) void {
    assert(words.len % words_per_block == 0);
    const first = block_of(words, key_hash);
    const low: u32 = @truncate(key_hash);
    inline for (salts, 0..) |salt, index| {
        const bit: u5 = @intCast((low *% salt) >> 27);
        words[first + index] |= @as(u32, 1) << bit;
    }
    assert(may_contain(words, key_hash));
}

pub fn may_contain(words: []const u32, key_hash: u64) bool {
    assert(words.len % words_per_block == 0);
    const first = block_of(words, key_hash);
    const low: u32 = @truncate(key_hash);
    var missing: u32 = 0;
    inline for (salts, 0..) |salt, index| {
        const bit: u5 = @intCast((low *% salt) >> 27);
        missing |= ~words[first + index] & (@as(u32, 1) << bit);
    }
    return missing == 0;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

test "lsm filter: no false negatives, about 1% false positives at 10 bits per key" {
    var prng = Prng.init(7);
    var words: [word_count(4096, 10)]u32 = undefined;
    for ([_]u32{ 1, 17, 1000, 4096 }) |count| {
        @memset(&words, 0);
        const filter = words[0..word_count(count, 10)];
        const seed = prng.int(u64);
        var index: u64 = 0;
        while (index < count) : (index += 1) {
            insert(filter, hash(std.mem.asBytes(&(seed +% index))));
        }
        index = 0;
        while (index < count) : (index += 1) {
            try testing.expect(may_contain(filter, hash(std.mem.asBytes(&(seed +% index)))));
        }
        var positives: u32 = 0;
        const probes: u32 = 20_000;
        var probe: u64 = 0;
        while (probe < probes) : (probe += 1) {
            const key = prng.int(u64) | (1 << 63);
            if (may_contain(filter, hash(std.mem.asBytes(&key)))) positives += 1;
        }
        // 10 bits per key: ~1% expected; 3% leaves room for tiny filters' rounding.
        if (count >= 1000) try testing.expect(positives < probes * 3 / 100);
    }
}

//! A bounded memo of KECCAK256 digests for short inputs.
//!
//! Most KECCAK256 inputs are Solidity mapping keys (`key ++ slot`, 64 bytes) and repeat across
//! transactions and blocks: the same balances and allowances are read and written again and
//! again. evm2 (with reth) ships alloy's process-global `keccak-cache-global` for this; this is
//! the same idea owned by one `Evm` and sized at init.
//!
//! Direct-mapped: one entry per slot, replaced on a miss. A hit compares the whole stored input
//! and its length, so the memo never returns a digest for a different input. Entries are
//! reserved lazily (only touched pages become resident); a separate validity bitset, cleared at
//! init, marks which entries hold data.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const B256 = primitives.B256;

/// Longer inputs are hashed directly: they rarely repeat and would make entries large.
pub const input_bytes_max = 64;

const Entry = struct {
    /// The input, zero-padded to `input_bytes_max`.
    key: [input_bytes_max]u8,
    digest: B256,
    len: u8,
};

pub const KeccakMemo = struct {
    /// Empty when the memo is disabled (`entries_count == 0`).
    entries: []Entry,
    /// Bit `i` set when `entries[i]` holds an input and its digest.
    valid: []u64,

    /// `entries_count` is 0 (disabled) or a power of two of at least 64.
    pub fn init(allocator: std.mem.Allocator, entries_count: u32) !KeccakMemo {
        if (entries_count == 0) return .{ .entries = &.{}, .valid = &.{} };
        assert(std.math.isPowerOfTwo(entries_count));
        assert(entries_count >= 64);
        const entries = try lazy.alloc(allocator, Entry, entries_count);
        errdefer lazy.free(allocator, entries);
        const valid = try allocator.alloc(u64, entries_count / 64);
        @memset(valid, 0);
        return .{ .entries = entries, .valid = valid };
    }

    pub fn deinit(memo: *KeccakMemo, allocator: std.mem.Allocator) void {
        if (memo.entries.len > 0) {
            lazy.free(allocator, memo.entries);
            allocator.free(memo.valid);
        }
        memo.* = undefined;
    }

    /// keccak256(`data`), from the memo when it holds `data`.
    pub fn hash(memo: *KeccakMemo, data: []const u8) B256 {
        if (memo.entries.len == 0 or data.len > input_bytes_max) {
            return primitives.keccak256(data);
        }
        assert(memo.valid.len * 64 == memo.entries.len);
        var key: [input_bytes_max]u8 = @splat(0);
        @memcpy(key[0..data.len], data);
        const index = slot(&key, data.len, memo.entries.len);
        const entry = &memo.entries[index];
        const word = &memo.valid[index / 64];
        const bit = @as(u64, 1) << @intCast(index % 64);
        if (word.* & bit != 0 and entry.len == data.len and std.mem.eql(u8, &entry.key, &key)) {
            return entry.digest;
        }
        const digest = primitives.keccak256(data);
        entry.* = .{ .key = key, .digest = digest, .len = @intCast(data.len) };
        word.* |= bit;
        return digest;
    }

    /// Multiplicative hash of the padded input's words and length; the high bits pick the slot.
    fn slot(key: *const [input_bytes_max]u8, len: usize, count: usize) usize {
        assert(len <= input_bytes_max);
        var accumulator: u64 = len;
        inline for (0..input_bytes_max / 8) |index| {
            const lane = std.mem.readInt(u64, key[index * 8 ..][0..8], .little);
            accumulator = (accumulator ^ lane) *% 0x9e37_79b9_7f4a_7c15;
        }
        const result: usize = @intCast((accumulator >> 32) & (count - 1));
        assert(result < count);
        return result;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "keccak memo: hits, collisions, and long inputs all return the exact digest" {
    var memo = try KeccakMemo.init(testing.allocator, 64);
    defer memo.deinit(testing.allocator);
    var prng = Prng.init(0x6b656363616b_6d65);
    // Few distinct inputs over a small table: repeats hit, and colliding inputs evict each
    // other. Same-prefix inputs of different lengths must not be confused (zero padding).
    var inputs: [200][80]u8 = undefined;
    var lengths: [200]usize = undefined;
    for (&inputs, &lengths) |*input, *length| {
        prng.fill(input);
        length.* = @intCast(prng.below(81));
    }
    @memset(inputs[1][0..80], 0);
    @memset(inputs[2][0..80], 0);
    lengths[1] = 31;
    lengths[2] = 32;
    for (0..4000) |_| {
        const pick: usize = @intCast(prng.below(inputs.len));
        const data = inputs[pick][0..lengths[pick]];
        try testing.expectEqual(primitives.keccak256(data), memo.hash(data));
    }
    var disabled = try KeccakMemo.init(testing.allocator, 0);
    defer disabled.deinit(testing.allocator);
    try testing.expectEqual(primitives.keccak256("abc"), disabled.hash("abc"));
}

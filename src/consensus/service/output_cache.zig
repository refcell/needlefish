//! Finalized outputs for `optimism_outputAtBlock` by number. The L2 provider expires
//! by-number results after a short TTL (unsafe numbers move on reorgs), and the node answers
//! a miss with "not available" while it fetches. A client that asks once per poll interval,
//! like the proposer every 12 s, would then start a fetch and miss on every call. So the node
//! remembers the finalized numbers the RPC was asked for, keeps fetching them each tick, and
//! keeps their outputs: a finalized block never changes.

const std = @import("std");
const assert = std.debug.assert;

const rollup_rpc = @import("../rpc/rollup.zig");

const OutputAtBlock = rollup_rpc.OutputAtBlock;

pub const OutputCache = struct {
    pub const entries_max = 32;
    pub const pending_max = 8;

    /// A ring of cached outputs; `entries_next` is overwritten next.
    entries: [entries_max]OutputAtBlock = undefined,
    entries_count: u32 = 0,
    entries_next: u32 = 0,
    /// Requested numbers still being fetched, oldest first.
    pending: [pending_max]u64 = undefined,
    pending_count: u32 = 0,

    pub fn get(cache: *const OutputCache, number: u64) ?OutputAtBlock {
        for (cache.entries[0..cache.entries_count]) |entry| {
            if (entry.block_ref.block_info.number == number) return entry;
        }
        return null;
    }

    /// Keeps `output` (a finalized block's), replacing the oldest entry when full.
    pub fn put(cache: *OutputCache, output: OutputAtBlock) void {
        const number = output.block_ref.block_info.number;
        cache.resolve(number);
        if (cache.get(number) != null) return;
        cache.entries[cache.entries_next] = output;
        cache.entries_next = (cache.entries_next + 1) % entries_max;
        cache.entries_count = @min(cache.entries_count + 1, entries_max);
        assert(cache.get(number) != null);
        assert(cache.entries_count <= entries_max);
    }

    /// Fetches `number` until it resolves; the oldest request is dropped when full.
    pub fn request(cache: *OutputCache, number: u64) void {
        for (cache.pending[0..cache.pending_count]) |known| if (known == number) return;
        if (cache.pending_count == pending_max) cache.remove_at(0);
        cache.pending[cache.pending_count] = number;
        cache.pending_count += 1;
        assert(cache.pending_count <= pending_max);
    }

    /// Stops fetching `number` (resolved, or not found).
    pub fn resolve(cache: *OutputCache, number: u64) void {
        for (cache.pending[0..cache.pending_count], 0..) |known, index| {
            if (known == number) return cache.remove_at(index);
        }
    }

    pub fn pending_numbers(cache: *const OutputCache) []const u64 {
        return cache.pending[0..cache.pending_count];
    }

    fn remove_at(cache: *OutputCache, index: usize) void {
        assert(index < cache.pending_count);
        const tail = cache.pending[index + 1 .. cache.pending_count];
        std.mem.copyForwards(u64, cache.pending[index .. cache.pending_count - 1], tail);
        cache.pending_count -= 1;
    }
};

const testing = std.testing;

fn test_output(number: u64) OutputAtBlock {
    var result: OutputAtBlock = undefined;
    result.block_ref = .{};
    result.block_ref.block_info.number = number;
    result.block_ref.block_info.hash = .init(@splat(@truncate(number)));
    return result;
}

test "output cache: keeps finalized outputs and evicts the oldest" {
    var cache: OutputCache = .{};
    try testing.expect(cache.get(5) == null);
    cache.put(test_output(5));
    cache.put(test_output(5)); // Same number: kept once.
    try testing.expectEqual(@as(u32, 1), cache.entries_count);
    try testing.expectEqual(@as(u64, 5), cache.get(5).?.block_ref.block_info.number);
    for (0..OutputCache.entries_max) |index| cache.put(test_output(100 + index));
    try testing.expect(cache.get(5) == null); // The oldest went first.
    try testing.expect(cache.get(100) != null);
    try testing.expect(cache.get(100 + OutputCache.entries_max - 1) != null);
}

test "output cache: requests stay pending until put or resolved" {
    var cache: OutputCache = .{};
    cache.request(7);
    cache.request(9);
    cache.request(7);
    try testing.expectEqualSlices(u64, &.{ 7, 9 }, cache.pending_numbers());
    cache.put(test_output(7));
    try testing.expectEqualSlices(u64, &.{9}, cache.pending_numbers());
    cache.resolve(9);
    try testing.expectEqual(@as(usize, 0), cache.pending_numbers().len);
    for (0..OutputCache.pending_max + 2) |index| cache.request(index);
    try testing.expectEqual(@as(u64, 2), cache.pending_numbers()[0]); // Oldest dropped.
    try testing.expectEqual(@as(usize, OutputCache.pending_max), cache.pending_numbers().len);
}

//! Flashblocks that arrived before their parent's canonical header. Mirrors base/base
//! `cache.rs` (`FlashblockCache`): a flashblock is cacheable up to
//! `cache_ahead_blocks + 1` blocks past the latest canonical block; inserting one keeps
//! only blocks within `cache_ahead_blocks` below it; a canonical update drops everything at
//! or below it; `take_lowest` drains a block's flashblocks in index order.
//!
//! Entries hold the flashblock re-encoded as JSON (`common/flashblocks.encode_json`) in a
//! fixed byte arena, so the cache owns its data with no allocation after `init`. base/base
//! uses unbounded hash maps; here an insert that does not fit `entries_max` or
//! `bytes_max` is refused like an uncacheable one.

const std = @import("std");
const assert = std.debug.assert;

const flashblocks = @import("../../common/flashblocks/root.zig");

/// base/base `MAX_CACHE_AHEAD_BLOCKS`.
pub const cache_ahead_blocks: u64 = 5;

pub const Options = struct {
    entries_max: u32 = 64,
    bytes_max: u32 = 4 << 20,
};

const Entry = struct { block_number: u64, index: u64, start: u32, size: u32 };

pub const Cache = struct {
    entries: []Entry,
    entry_count: u32 = 0,
    arena: []u8,
    arena_size: u32 = 0,
    latest_canonical: ?u64,

    pub fn init(allocator: std.mem.Allocator, options: Options, latest_canonical: ?u64) !Cache {
        assert(options.entries_max > 0);
        assert(options.bytes_max > 0);
        const entries = try allocator.alloc(Entry, options.entries_max);
        errdefer allocator.free(entries);
        const arena = try allocator.alloc(u8, options.bytes_max);
        return .{ .entries = entries, .arena = arena, .latest_canonical = latest_canonical };
    }

    pub fn deinit(cache: *Cache, allocator: std.mem.Allocator) void {
        allocator.free(cache.arena);
        allocator.free(cache.entries);
        cache.* = undefined;
    }

    /// Distinct block numbers held (base/base `len`).
    pub fn block_count(cache: *const Cache) u32 {
        var count: u32 = 0;
        for (cache.live(), 0..) |entry, position| {
            const seen = for (cache.live()[0..position]) |earlier| {
                if (earlier.block_number == entry.block_number) break true;
            } else false;
            if (!seen) count += 1;
        }
        assert(count <= cache.entry_count);
        return count;
    }

    /// Flashblocks held (base/base `total_flashblocks`).
    pub fn total_flashblocks(cache: *const Cache) u32 {
        return cache.entry_count;
    }

    pub fn is_empty(cache: *const Cache) bool {
        return cache.entry_count == 0;
    }

    pub fn has_flashblock(cache: *const Cache, block_number: u64, index: u64) bool {
        return cache.find(block_number, index) != null;
    }

    pub fn is_cacheable(cache: *const Cache, block_number: u64) bool {
        const canonical = cache.latest_canonical orelse return false;
        return block_number <= canonical +| (cache_ahead_blocks + 1);
    }

    /// Caches `flashblock`, replacing an entry at the same position. Returns false when it
    /// is too far ahead of the canonical chain or does not fit.
    pub fn insert(cache: *Cache, flashblock: flashblocks.Flashblock) bool {
        const block_number = flashblock.metadata.block_number;
        if (!cache.is_cacheable(block_number)) return false;
        const retain_above = block_number -| cache_ahead_blocks;
        cache.remove_at_or_below(retain_above);
        if (cache.find(block_number, flashblock.index)) |position| cache.remove(position);
        if (cache.entry_count == cache.entries.len) return false;
        const free = cache.arena[cache.arena_size..];
        const json = flashblocks.encode_json(flashblock, free) catch return false;
        cache.entries[cache.entry_count] = .{
            .block_number = block_number,
            .index = flashblock.index,
            .start = cache.arena_size,
            .size = @intCast(json.len),
        };
        cache.entry_count += 1;
        cache.arena_size += @intCast(json.len);
        assert(cache.arena_size <= cache.arena.len);
        assert(cache.has_flashblock(block_number, flashblock.index));
        return true;
    }

    /// Removes the lowest-index flashblock of `block_number`, copying its JSON into `out`
    /// (at least the entry's size; `bytes_max` always suffices). Null when none is left.
    pub fn take_lowest(cache: *Cache, block_number: u64, out: []u8) ?[]u8 {
        var best: ?u32 = null;
        for (cache.live(), 0..) |entry, position| {
            if (entry.block_number != block_number) continue;
            if (best) |b| {
                if (cache.entries[b].index <= entry.index) continue;
            }
            best = @intCast(position);
        }
        const position = best orelse return null;
        const entry = cache.entries[position];
        assert(out.len >= entry.size);
        @memcpy(out[0..entry.size], cache.arena[entry.start..][0..entry.size]);
        cache.remove(position);
        return out[0..entry.size];
    }

    /// base/base `update_canonical`.
    pub fn update_canonical(cache: *Cache, block_number: u64) void {
        cache.latest_canonical = block_number;
        cache.remove_at_or_below(block_number);
        assert(cache.latest_canonical.? == block_number);
    }

    fn live(cache: *const Cache) []const Entry {
        return cache.entries[0..cache.entry_count];
    }

    fn find(cache: *const Cache, block_number: u64, index: u64) ?u32 {
        for (cache.live(), 0..) |entry, position| {
            if (entry.block_number == block_number and entry.index == index) {
                return @intCast(position);
            }
        }
        return null;
    }

    fn remove_at_or_below(cache: *Cache, bound: u64) void {
        var position: u32 = 0;
        // Each pass removes an entry or advances: at most `entries.len` iterations.
        while (position < cache.entry_count) {
            if (cache.entries[position].block_number <= bound) {
                cache.remove(position);
            } else {
                position += 1;
            }
        }
        for (cache.live()) |entry| assert(entry.block_number > bound);
    }

    /// Removes an entry and compacts the arena and entry list.
    fn remove(cache: *Cache, position: u32) void {
        assert(position < cache.entry_count);
        const removed = cache.entries[position];
        const tail_start = removed.start + removed.size;
        std.mem.copyForwards(
            u8,
            cache.arena[removed.start..],
            cache.arena[tail_start..cache.arena_size],
        );
        cache.arena_size -= removed.size;
        for (cache.entries[0..cache.entry_count]) |*entry| {
            if (entry.start > removed.start) entry.start -= removed.size;
        }
        std.mem.copyForwards(
            Entry,
            cache.entries[position..],
            cache.entries[position + 1 .. cache.entry_count],
        );
        cache.entry_count -= 1;
        assert(cache.arena_size <= cache.arena.len);
    }
};

test {
    _ = @import("cache_test.zig");
}

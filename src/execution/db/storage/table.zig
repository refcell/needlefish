//! Immutable sorted tables on the grid, and the bounded block cache reads go through.
//!
//! A table is a sorted run of (key, value) records with fixed-size keys and variable-size
//! values, written once and never changed:
//! - Data blocks hold whole records in key order. Payload: `count u32`, `reserved u32`,
//!   `ends u32[count]` (end offset of each record within the payload), then the records,
//!   each `key ++ value`. A record never spans blocks.
//! - One index block names every data block. Payload: `count u32`, `reserved u32`, then per
//!   data block its first key and its `grid.Reference`.
//! - `Info` (the manifest entry) names the index block and records the key range and counts.
//!
//! Point lookup: index block (binary search on first keys), then one data block (binary
//! search on keys): at most two block reads, none on a cache hit. Range scan: the data blocks
//! from the one holding the start key, in order.
//!
//! Every block read is verified by the grid (checksum, address, kind) and then structurally
//! (`data_valid`, `index_valid`), so a decoder never trusts a byte. Static memory only: the
//! builder, reader, and cache allocate their buffers at init.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const free_set_module = @import("free_set.zig");

const sector_size = storage.sector_size;
const Reference = grid_module.Reference;
const BlockKind = grid_module.BlockKind;
const FreeSet = free_set_module.FreeSet;
const Reservation = free_set_module.Reservation;

pub const Error = error{ Corrupt, Empty, TableTooLarge };
pub const Status = @import("table_reader.zig").Status;

const payload_header_size: u32 = 8;

fn read_u32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn write_u32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

/// A set-associative block cache with CLOCK eviction per set (TigerBeetle's shape): a lookup
/// scans one set of `ways` tags, so hits and misses cost the same bounded work. Entries are
/// keyed by address and checksum, so a reused address never serves a stale block.
pub const BlockCache = struct {
    pub const ways: u32 = 16;

    block_size: u32,
    set_count: u32,
    /// Per slot: address (0 = empty), checksum, CLOCK reference bit.
    addresses: []u64,
    checksums: []u128,
    referenced: []bool,
    /// Per set: the CLOCK hand.
    hands: []u8,
    blocks: []align(sector_size) u8,
    stats: Stats = .{},

    pub const Stats = struct { hits: u64 = 0, misses: u64 = 0, evictions: u64 = 0 };

    comptime {
        assert(ways <= std.math.maxInt(u8));
    }

    pub fn init(allocator: std.mem.Allocator, block_size: u32, blocks_max: u32) !BlockCache {
        assert(blocks_max >= ways);
        assert(block_size % sector_size == 0);
        const set_count = blocks_max / ways;
        const slots: usize = @as(usize, set_count) * ways;
        const addresses = try allocator.alloc(u64, slots);
        errdefer allocator.free(addresses);
        const checksums = try allocator.alloc(u128, slots);
        errdefer allocator.free(checksums);
        const referenced = try allocator.alloc(bool, slots);
        errdefer allocator.free(referenced);
        const hands = try allocator.alloc(u8, set_count);
        errdefer allocator.free(hands);
        const blocks = try allocator.alignedAlloc(u8, .fromByteUnits(sector_size), slots *
            block_size);
        @memset(addresses, 0);
        @memset(checksums, 0);
        @memset(referenced, false);
        @memset(hands, 0);
        return .{
            .block_size = block_size,
            .set_count = set_count,
            .addresses = addresses,
            .checksums = checksums,
            .referenced = referenced,
            .hands = hands,
            .blocks = blocks,
        };
    }

    pub fn deinit(self: *BlockCache, allocator: std.mem.Allocator) void {
        allocator.free(self.addresses);
        allocator.free(self.checksums);
        allocator.free(self.referenced);
        allocator.free(self.hands);
        allocator.free(self.blocks);
        self.* = undefined;
    }

    fn set_of(self: *const BlockCache, address: u64) usize {
        const mixed = address *% 0x9e37_79b9_7f4a_7c15;
        return @intCast((mixed >> 32) % self.set_count);
    }

    fn block_at(self: *const BlockCache, slot: usize) []align(sector_size) u8 {
        const start = slot * self.block_size;
        return @alignCast(self.blocks[start..][0..self.block_size]);
    }

    /// The cached block for `reference`, or null. Valid until the next `put`.
    pub fn get(self: *BlockCache, reference: Reference) ?[]const u8 {
        const block = self.peek(reference);
        if (block == null) self.stats.misses += 1 else self.stats.hits += 1;
        return block;
    }

    /// `get` without counting a hit or a miss (a prefetch's probe). A hit is marked
    /// referenced all the same: the block is about to be used.
    pub fn peek(self: *BlockCache, reference: Reference) ?[]const u8 {
        assert(reference.address > 0);
        const first = self.set_of(reference.address) * ways;
        for (first..first + ways) |slot| {
            if (self.addresses[slot] != reference.address) continue;
            if (self.checksums[slot] != reference.checksum) break;
            self.referenced[slot] = true;
            assert(slot < first + ways);
            return self.block_at(slot);
        }
        return null;
    }

    /// Caches a verified block for `reference` and returns the cached copy (valid until the
    /// next `put`). Replaces any entry at the same address.
    pub fn put(self: *BlockCache, reference: Reference, block: []const u8) []const u8 {
        assert(reference.address > 0);
        assert(block.len <= self.block_size);
        const set = self.set_of(reference.address);
        const first = set * ways;
        const slot = for (first..first + ways) |slot| {
            if (self.addresses[slot] == reference.address) break slot;
        } else self.evict(set);
        self.addresses[slot] = reference.address;
        self.checksums[slot] = reference.checksum;
        self.referenced[slot] = false;
        const target = self.block_at(slot);
        @memcpy(target[0..block.len], block);
        assert(self.addresses[slot] == reference.address);
        return target[0..block.len];
    }

    /// A slot for a block about to be read straight into it (no copy): `buffer` is the slot's
    /// whole block. The slot holds nothing until `fill` names it (a read that fails leaves
    /// it empty). Replaces any entry at the same address, as `put` does.
    pub const Claim = struct { slot: usize, buffer: []align(sector_size) u8 };

    pub fn claim(self: *BlockCache, reference: Reference) Claim {
        assert(reference.address > 0);
        const set = self.set_of(reference.address);
        const first = set * ways;
        const slot = for (first..first + ways) |slot| {
            if (self.addresses[slot] == reference.address) break slot;
        } else self.evict(set);
        self.addresses[slot] = 0;
        self.referenced[slot] = false;
        assert(slot >= first and slot < first + ways);
        return .{ .slot = slot, .buffer = self.block_at(slot) };
    }

    /// Names the claimed slot `reference`'s verified block, of `length` bytes (header and
    /// payload), and returns it (valid until the next `put` or `claim`).
    pub fn fill(self: *BlockCache, claimed: Claim, reference: Reference, length: usize) []const u8 {
        assert(reference.address > 0);
        assert(length <= self.block_size);
        assert(self.addresses[claimed.slot] == 0);
        assert(claimed.buffer.ptr == self.block_at(claimed.slot).ptr);
        self.addresses[claimed.slot] = reference.address;
        self.checksums[claimed.slot] = reference.checksum;
        return claimed.buffer[0..length];
    }

    /// CLOCK: the first slot from the hand without a reference bit, clearing bits on the way.
    fn evict(self: *BlockCache, set: usize) usize {
        const first = set * ways;
        var step: u32 = 0;
        // Bounded: after one full turn every bit is clear.
        while (step <= 2 * ways) : (step += 1) {
            const slot = first + self.hands[set];
            self.hands[set] = @intCast((self.hands[set] + 1) % ways);
            if (self.addresses[slot] == 0) return slot;
            if (!self.referenced[slot]) {
                self.stats.evictions += 1;
                return slot;
            }
            self.referenced[slot] = false;
        }
        unreachable; // One turn clears every bit, the next finds a slot.
    }
};

/// Keys up to 72 bytes: the widest key space is a storage-branch path key (65 bytes).
pub const key_size_max: u32 = 72;

/// Bytes after the fence keys that keep `Info` free of implicit padding (whose bytes would be
/// undefined in a checkpoint): the counts start 8-aligned and the size is a multiple of 16.
fn info_padding_size(key_size: u32) u32 {
    const keys_end = @sizeOf(Reference) + 2 * key_size;
    return std.mem.alignForward(u32, keys_end + 16, 16) - 16 - keys_end;
}

pub fn TableType(comptime Storage: type, comptime key_size: u32) type {
    comptime assert(key_size > 0 and key_size <= key_size_max);
    return struct {
        pub const Key = [key_size]u8;
        pub const Grid = grid_module.GridType(Storage);

        /// The manifest entry for one table.
        pub const Info = extern struct {
            index: Reference,
            key_min: Key,
            key_max: Key,
            /// Zero; present only for key sizes whose fence keys end unaligned.
            padding: [info_padding_size(key_size)]u8 = @splat(0),
            record_count: u64,
            data_block_count: u32,
            reserved: u32 = 0,
        };

        comptime {
            // No implicit padding: every byte of a checkpointed `Info` is defined.
            const size = @sizeOf(Reference) + 2 * key_size + info_padding_size(key_size) + 16;
            assert(@sizeOf(Info) == size);
            assert(@offsetOf(Info, "record_count") % 8 == 0);
        }

        pub const Record = struct {
            key: *const Key,
            value: []const u8,
        };

        pub const Source = struct {
            context: *anyopaque,
            /// The next record in strictly ascending key order, or null at the end. The
            /// record's bytes stay valid until the following call.
            next: *const fn (context: *anyopaque) ?Record,
        };

        pub const index_entry_size: u32 = key_size + @sizeOf(Reference);

        pub fn value_size_max(block_size: u32) u32 {
            return grid_module.payload_capacity_of(block_size) - payload_header_size - 4 -
                key_size;
        }

        /// Payload bytes of a data block for record ends and records.
        pub fn data_room(block_size: u32) u32 {
            return grid_module.payload_capacity_of(block_size) - payload_header_size;
        }

        /// Whether a record of `record_size` bytes (key and value) still fits a data block
        /// that holds `count` records of `records_bytes` bytes. The builder packs by this rule,
        /// and callers that cut tables by data blocks mirror it.
        pub fn data_fits(block_size: u32, records_bytes: u32, count: u32, record_size: u32) bool {
            assert(record_size >= key_size);
            return records_bytes + record_size + 4 * (count + 1) <= data_room(block_size);
        }

        pub fn index_capacity(block_size: u32) u32 {
            const capacity = grid_module.payload_capacity_of(block_size) - payload_header_size;
            return capacity / index_entry_size;
        }

        /// Blocks (data + index) a table of `record_count` records with `bytes_total` key
        /// and value bytes needs at most. Two consecutive data blocks together hold more than
        /// one block's room, since a record moves on only when it does not fit.
        pub fn blocks_max(block_size: u32, record_count: u64, bytes_total: u64) u64 {
            const room = grid_module.payload_capacity_of(block_size) - payload_header_size;
            const bytes = bytes_total + record_count * 4;
            const data = @min(record_count, 2 * (std.math.divCeil(u64, bytes, room) catch
                unreachable) + 1); // room > 0.
            return data + 1;
        }

        pub fn key_order(a: *const Key, b: *const Key) std.math.Order {
            return std.mem.order(u8, a, b);
        }

        // Data block decoding. `payload` has passed `data_valid`.

        pub fn data_count(payload: []const u8) u32 {
            return read_u32(payload, 0);
        }

        pub fn data_record(payload: []const u8, index: u32) []const u8 {
            const count = data_count(payload);
            assert(index < count);
            const start = if (index == 0)
                payload_header_size + 4 * count
            else
                read_u32(payload, payload_header_size + 4 * (index - 1));
            const end = read_u32(payload, payload_header_size + 4 * index);
            return payload[start..end];
        }

        pub fn record_key(record: []const u8) *const Key {
            return record[0..key_size];
        }

        /// The first record index whose key is at or above `key` (`count` if none).
        pub fn data_lower_bound(payload: []const u8, key: *const Key) u32 {
            var low: u32 = 0;
            var high: u32 = data_count(payload);
            while (low < high) {
                const middle = low + (high - low) / 2;
                const order = key_order(record_key(data_record(payload, middle)), key);
                if (order == .lt) low = middle + 1 else high = middle;
            }
            return low;
        }

        pub fn data_search(payload: []const u8, key: *const Key) ?[]const u8 {
            const index = data_lower_bound(payload, key);
            if (index == data_count(payload)) return null;
            const record = data_record(payload, index);
            if (key_order(record_key(record), key) != .eq) return null;
            return record[key_size..];
        }

        /// Structural check of a data block payload: ends in order and in range, every record
        /// holds a key, keys strictly ascending.
        pub fn data_valid(payload: []const u8) bool {
            if (payload.len < payload_header_size) return false;
            const count = data_count(payload);
            if (count == 0 or read_u32(payload, 4) != 0) return false;
            if (count > (payload.len - payload_header_size) / (4 + key_size)) return false;
            var start: u64 = payload_header_size + 4 * @as(u64, count);
            var index: u32 = 0;
            while (index < count) : (index += 1) {
                const end = read_u32(payload, payload_header_size + 4 * index);
                if (end < start + key_size or end > payload.len) return false;
                if (index > 0) {
                    const previous = data_record(payload, index - 1);
                    const current = payload[@intCast(start)..end];
                    if (key_order(record_key(previous), record_key(current)) != .lt) return false;
                }
                start = end;
            }
            return start == payload.len;
        }

        // Index block decoding. `payload` has passed `index_valid`.

        pub fn index_count(payload: []const u8) u32 {
            return read_u32(payload, 0);
        }

        pub fn index_key(payload: []const u8, ordinal: u32) *const Key {
            assert(ordinal < index_count(payload));
            const offset = payload_header_size + ordinal * index_entry_size;
            return payload[offset..][0..key_size];
        }

        pub fn index_reference(payload: []const u8, ordinal: u32) Reference {
            assert(ordinal < index_count(payload));
            const offset = payload_header_size + ordinal * index_entry_size + key_size;
            var reference: Reference = undefined;
            @memcpy(std.mem.asBytes(&reference), payload[offset..][0..@sizeOf(Reference)]);
            return reference;
        }

        /// The last data block whose first key is at or below `key`, or null.
        pub fn index_find(payload: []const u8, key: *const Key) ?u32 {
            var low: u32 = 0;
            var high: u32 = index_count(payload);
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (key_order(index_key(payload, middle), key) == .gt) high = middle else {
                    low = middle + 1;
                }
            }
            if (low == 0) return null;
            return low - 1;
        }

        pub fn index_valid(payload: []const u8, block_count: u64) bool {
            if (payload.len < payload_header_size) return false;
            const count = index_count(payload);
            if (count == 0 or read_u32(payload, 4) != 0) return false;
            if (payload.len != payload_header_size + @as(u64, count) * index_entry_size) {
                return false;
            }
            var ordinal: u32 = 0;
            while (ordinal < count) : (ordinal += 1) {
                const reference = index_reference(payload, ordinal);
                if (reference.address == 0 or reference.address > block_count) return false;
                if (reference.reserved != 0) return false;
                if (ordinal == 0) continue;
                const previous = index_key(payload, ordinal - 1);
                const order = key_order(previous, index_key(payload, ordinal));
                if (order != .lt) return false;
            }
            return true;
        }

        pub const Builder = BuilderType();
        pub const Reader = ReaderType();

        fn BuilderType() type {
            return @import("table_builder.zig").BuilderType(@This());
        }

        fn ReaderType() type {
            return @import("table_reader.zig").ReaderType(@This());
        }
    };
}

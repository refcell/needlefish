//! Archive: a node's history on disk, a bounded window of recent blocks. For every block the
//! owner commits it keeps the block's record (header, transactions, receipts; opaque bytes),
//! its transaction hashes, and the old value of every key the block changed ("reverse
//! diff": accounts, slots, trie records, by kind). State at block N is then the head state
//! with each key replaced by its old value in the first block after N that changed it.
//!
//! Layout: one file of fixed capacity (sparse: it grows as it fills), two superblock copies
//! and a ring. The ring holds units, each starting on a sector and never straddling the
//! ring's end (a unit that does not fit is written at the next lap's start). Positions are
//! log offsets that only grow; a unit at log offset L lives at ring position L % ring size.
//! - A block unit per block: header, transaction hashes, entries (kind, key, old value),
//!   record. Written as the block commits.
//! - Blocks are grouped in segments of about `segment_blocks`. The open segment (the newest)
//!   is indexed in memory: a hash table from key fingerprint to its newest entry, with
//!   chains to older ones. Sealing a segment writes an index unit after its blocks: the
//!   block table (log offset of each block unit), a Bloom filter of its distinct
//!   fingerprints, page fences, and its entries sorted by (fingerprint, block), 256 to a
//!   4 KiB page. A sealed segment's filter and fences stay in memory; a lookup reads one or
//!   two index pages.
//! - Fingerprints are 64-bit; every hit is checked against the full key in the block unit,
//!   so a collision costs a read, never a wrong answer. Units, index metadata, and index
//!   pages are checksummed; a mismatch is an error (`Corrupt`), never an answer.
//!
//! Pruning: before a write would overwrite the oldest segment, that segment is dropped from
//! the superblock, durably, and only then overwritten. A segment is sealed early when it
//! nears a quarter of the ring, so the open segment never wraps onto itself.
//!
//! Crash safety: a block unit becomes visible to `open` once written (the open segment is
//! recovered by scanning its units, each checked by checksum, generation, number, and parent
//! hash, stopping at the first that fails). Sealing writes the index unit, syncs, then
//! writes the superblock that names it and syncs again. `rebase` reconciles the archive with
//! its owner's head after a crash: it truncates blocks above the head (reopening sealed
//! segments when needed), and the owner appends any blocks the archive lacks or resets it.
//!
//! IO: every write is waited for before `append`/`seal` return, so reads (`read_sectors_sync`)
//! never overlap a write. `sync` (fsync) runs asynchronously every `sync_blocks` blocks.
//! Single-threaded. All memory is reserved at `init` (`lazy_alloc`: committed on use).

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const storage_module = @import("../db/storage/storage.zig");
const checksum_module = @import("../db/storage/checksum.zig");

pub const sector_size = storage_module.sector_size;
const sector_alignment = std.mem.Alignment.fromByteUnits(sector_size);
pub const Hash = [32]u8;

/// What an entry's key names. Every kind has its own fingerprint space.
pub const Kind = enum(u8) {
    /// Key: block hash. Indexed only (no entry bytes); found by `find`.
    block = 1,
    /// Key: transaction hash; the location's aux is the transaction's index in its block.
    transaction = 2,
    /// Key: keccak(address). Value: the account record, or absent.
    account = 3,
    /// Key: keccak(address) ++ keccak(slot). Value: the 32-byte word, absent when zero.
    slot = 4,
    /// Key: the account trie's branch-record path key. Value: the record, or absent.
    account_branch = 5,
    /// Key: a storage trie's branch-record key. Value: the record, or absent.
    storage_branch = 6,
};

pub const key_bytes_max = 65;
/// Largest value: a branch record (`branch_record.value_bytes_max`).
pub const value_bytes_max = 1077;
const entry_header_bytes = 4;
pub const entry_bytes_max = entry_header_bytes + key_bytes_max + value_bytes_max;

/// One changed key of a block, with its value before the block (null: absent).
pub const Change = struct {
    kind: Kind,
    key: []const u8,
    old: ?[]const u8,
};

/// A block to append. `changes` must not name `block` or `transaction` kinds.
pub const BlockInput = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    /// Opaque record bytes; empty when the block's record is unknown (`Unit.record` null).
    record: []const u8,
    transaction_hashes: []const Hash,
    changes: []const Change,
};

pub const Config = struct {
    /// Blocks per segment (sealing starts at this many).
    segment_blocks: u32 = 8192,
    /// Index entries one segment holds at most (sealed early when the next block would
    /// not fit).
    segment_entries_max: u32 = 1 << 22,
    /// Segments retained at most (the window is also bounded by the ring's bytes).
    segments_max: u32 = 1024,
    /// The largest block unit (header, hashes, entries, record), rounded to sectors.
    unit_bytes_max: u32 = 80 << 20,
    /// Bloom filter bytes per sealed segment (a power of two).
    filter_bytes: u32 = 1 << 20,
    /// Blocks between asynchronous syncs.
    sync_blocks: u32 = 16,

    fn segment_blocks_max(config: *const Config) u32 {
        return 2 * config.segment_blocks;
    }
};

pub const Error = error{
    /// A unit, index page, or index metadata failed its checksum or did not decode.
    Corrupt,
    /// The storage could not read.
    ReadFailed,
    /// A block does not fit (more entries or bytes than a segment or unit holds).
    BlockTooLarge,
    /// `append` takes the head's child only.
    NotNextBlock,
    /// The storage did not complete an operation within the tick bound.
    Stalled,
};

const magic_unit: u32 = 0x5541_464e; // "NFAU"
const magic_superblock: u32 = 0x5341_464e; // "NFAS"
const version: u16 = 1;
const unit_kind_block: u8 = 1;
const unit_kind_index: u8 = 2;
const flag_record: u8 = 1;
const ticks_max: u32 = 1 << 24;
const entries_per_page = sector_size / @sizeOf(IndexEntry);
const filter_probes = 6;
const no_entry = std.math.maxInt(u32);

const UnitHeader = extern struct {
    /// Over the header after this field.
    checksum: u128,
    /// Block: transaction hashes ++ entries. Index: block table ++ filter ++ fences.
    meta_checksum: u128,
    /// Block: the record. Index: zero (pages carry their own checksums in the fences).
    record_checksum: u128,
    magic: u32,
    version: u16,
    kind: u8,
    flags: u8,
    generation: u64,
    /// Block: its number. Index: the segment's first block.
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    meta_bytes: u32,
    /// Block: record bytes. Index: entry page bytes (after the metadata, sector-aligned).
    record_bytes: u32,
    /// Block: transactions. Index: blocks.
    count_a: u32,
    /// Block: entries. Index: index entries.
    count_b: u32,
    filter_bytes: u32,
    reserved: [36]u8 = @splat(0),

    fn seal(header: *UnitHeader) void {
        header.checksum = checksum_module.checksum(std.mem.asBytes(header)[16..]);
    }

    fn valid(header: *const UnitHeader, generation: u64) bool {
        if (header.checksum != checksum_module.checksum(std.mem.asBytes(header)[16..])) {
            return false;
        }
        return header.magic == magic_unit and header.version == version and
            header.generation == generation;
    }

    fn body_bytes(header: *const UnitHeader) u64 {
        return @as(u64, header.meta_bytes) + header.record_bytes;
    }
};

comptime {
    assert(@sizeOf(UnitHeader) == 192);
    assert(@sizeOf(IndexEntry) == 16);
    assert(@sizeOf(Fence) == 32);
    assert(sector_size % @sizeOf(IndexEntry) == 0);
    assert(entry_bytes_max <= sector_size);
}

/// A sorted index entry: the key's fingerprint, the block (relative to the segment's first),
/// and `aux` (the entry's offset in its block unit, or a transaction index).
const IndexEntry = extern struct {
    fingerprint: u64,
    delta: u32,
    aux: u32,

    fn before(a: IndexEntry, fp: u64, delta: u32) bool {
        if (a.fingerprint != fp) return a.fingerprint < fp;
        return a.delta < delta;
    }
};

/// The first entry of an index page and the page's checksum.
const Fence = extern struct {
    fingerprint: u64,
    delta: u32,
    reserved: u32 = 0,
    checksum: u128,
};

const SuperblockHeader = extern struct {
    checksum: u128,
    magic: u32,
    version: u16,
    reserved_a: u16 = 0,
    segments_count: u32,
    reserved_b: u32 = 0,
    sequence: u64,
    generation: u64,
    ring_bytes: u64,
    /// The open segment: its first block (`open_present`) and log offset.
    open_present: u64,
    open_first_block: u64,
    open_start: u64,
    /// Where the next unit goes when the open segment is empty.
    log_end: u64,
};

const SegmentRecord = extern struct {
    first_block: u64,
    blocks: u64,
    start: u64,
    index: u64,
    end: u64,
};

pub fn fingerprint(kind: Kind, key: []const u8) u64 {
    assert(key.len > 0 and key.len <= key_bytes_max);
    return std.hash.Wyhash.hash(@backingInt(kind), key);
}

/// A sealed segment's in-memory part: the window into its index.
const Sealed = struct {
    first_block: u64 = 0,
    blocks: u32 = 0,
    start: u64 = 0,
    index: u64 = 0,
    end: u64 = 0,
    entries: u32 = 0,
    /// Log offset of the first entry page.
    pages: u64 = 0,
    block_offsets: []u64,
    filter: []u8,
    fences: []Fence,

    fn fences_count(sealed: *const Sealed) u32 {
        return std.math.divCeil(u32, sealed.entries, entries_per_page) catch unreachable;
    }

    fn may_contain(sealed: *const Sealed, fp: u64) bool {
        return filter_contains(sealed.filter, fp);
    }
};

/// The open segment: its blocks and an in-memory index.
const Open = struct {
    present: bool = false,
    first_block: u64 = 0,
    start: u64 = 0,
    blocks: u32 = 0,
    block_offsets: []u64,
    entries: []IndexEntry,
    entries_len: u32 = 0,
    /// Per entry: the previous entry with the same fingerprint (`no_entry`: none).
    chain: []u32,
    /// Fingerprint -> newest entry, open addressing (`no_entry`: free).
    table: []u32,
};

pub const Location = struct { number: u64, aux: u32 };

/// A block unit as read: valid until the next read.
pub const Unit = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    /// Null when the block was appended without its record.
    record: ?[]const u8,
    transaction_hashes: []const Hash,
    entries_count: u32,
};

/// The value a key had before `number` (the first block after the asked one that changed
/// it); `old` is null when the key was absent. Valid until the next read.
pub const Found = struct { number: u64, old: ?[]const u8 };

pub fn ArchiveType(comptime Storage: type) type {
    storage_module.assert_interface(Storage);
    return struct {
        const Archive = @This();

        storage: *Storage,
        config: Config,
        superblock_bytes: u64,
        ring_bytes: u64,
        generation: u64 = 1,
        sequence: u64 = 0,
        /// Where the next unit is written.
        log_end: u64 = 0,
        /// The newest block (null: empty).
        head: ?u64 = null,
        head_hash: Hash = @splat(0),
        open: Open,
        /// Sealed segments, oldest first, as a ring over `slots`.
        slots: []Sealed,
        oldest_slot: u32 = 0,
        sealed_count: u32 = 0,
        /// Block and index units are built here.
        write_buffer: []align(sector_size) u8,
        read_buffer: []align(sector_size) u8,
        /// The block whose unit `read_buffer` holds (null: none or stale).
        read_cached: ?u64 = null,
        page_buffer: []align(sector_size) u8,
        superblock_buffer: []align(sector_size) u8,
        sort_scratch: []IndexEntry,
        radix_counts: []u32,
        write: storage_module.Write = .{},
        writing: bool = false,
        sync_op: storage_module.Sync = .{},
        syncing: bool = false,
        /// A sync was asked while one ran: run another when it completes.
        sync_again: bool = false,
        blocks_since_sync: u32 = 0,
        stats: Stats = .{},

        pub const Stats = struct {
            blocks: u64 = 0,
            unit_bytes: u64 = 0,
            entries: u64 = 0,
            seals: u64 = 0,
            evictions: u64 = 0,
            resets: u64 = 0,
            lookups: u64 = 0,
            page_reads: u64 = 0,
            unit_reads: u64 = 0,
            filter_skips: u64 = 0,
        };

        pub fn init(allocator: std.mem.Allocator, storage: *Storage, config: Config) !Archive {
            assert(config.segment_blocks >= 2);
            assert(config.segments_max >= 2);
            assert(std.math.isPowerOfTwo(config.filter_bytes));
            assert(config.unit_bytes_max % sector_size == 0);
            assert(config.segment_entries_max % entries_per_page == 0);
            const superblock_bytes = superblock_size(config.segments_max);
            const size = storage.size_bytes();
            if (size <= 2 * superblock_bytes) return error.ArchiveTooSmall;
            const ring_bytes = size - 2 * superblock_bytes;
            // The open segment (at most a quarter of the ring) holds a block and an index.
            const unit_and_index = @as(u64, config.unit_bytes_max) + index_unit_bytes_max(&config);
            if (ring_bytes / 8 < 2 * unit_and_index) return error.ArchiveTooSmall;
            var archive: Archive = .{
                .storage = storage,
                .config = config,
                .superblock_bytes = superblock_bytes,
                .ring_bytes = ring_bytes,
                .open = undefined,
                .slots = &.{},
                .write_buffer = &.{},
                .read_buffer = &.{},
                .page_buffer = &.{},
                .superblock_buffer = &.{},
                .sort_scratch = &.{},
                .radix_counts = &.{},
            };
            try archive.allocate(allocator);
            return archive;
        }

        fn allocate(archive: *Archive, allocator: std.mem.Allocator) !void {
            const config = &archive.config;
            const buffer_bytes = @max(config.unit_bytes_max, index_unit_bytes_max(config));
            const aligned = sector_alignment;
            archive.write_buffer = try lazy.alloc_aligned(allocator, u8, aligned, buffer_bytes);
            archive.read_buffer = try lazy.alloc_aligned(allocator, u8, aligned, buffer_bytes);
            archive.page_buffer = try lazy.alloc_aligned(allocator, u8, aligned, 2 * sector_size);
            const superblock_bytes: usize = @intCast(archive.superblock_bytes);
            archive.superblock_buffer =
                try lazy.alloc_aligned(allocator, u8, sector_alignment, superblock_bytes);
            const entries_max = config.segment_entries_max;
            archive.sort_scratch = try lazy.alloc(allocator, IndexEntry, entries_max);
            archive.radix_counts = try lazy.alloc(allocator, u32, 1 << 16);
            const table_len = 2 * std.math.ceilPowerOfTwoAssert(u32, config.segment_entries_max);
            archive.open = .{
                .block_offsets = try lazy.alloc(allocator, u64, config.segment_blocks_max()),
                .entries = try lazy.alloc(allocator, IndexEntry, config.segment_entries_max),
                .chain = try lazy.alloc(allocator, u32, config.segment_entries_max),
                .table = try lazy.alloc(allocator, u32, table_len),
            };
            @memset(archive.open.table, no_entry);
            archive.slots = try allocator.alloc(Sealed, config.segments_max);
            const fences_max = config.segment_entries_max / entries_per_page;
            for (archive.slots) |*slot| slot.* = .{
                .block_offsets = try lazy.alloc(allocator, u64, config.segment_blocks_max()),
                .filter = try lazy.alloc(allocator, u8, config.filter_bytes),
                .fences = try lazy.alloc(allocator, Fence, fences_max),
            };
        }

        pub fn deinit(archive: *Archive, allocator: std.mem.Allocator) void {
            assert(!archive.writing);
            for (archive.slots) |*slot| {
                lazy.free(allocator, slot.fences);
                lazy.free(allocator, slot.filter);
                lazy.free(allocator, slot.block_offsets);
            }
            allocator.free(archive.slots);
            lazy.free(allocator, archive.open.table);
            lazy.free(allocator, archive.open.chain);
            lazy.free(allocator, archive.open.entries);
            lazy.free(allocator, archive.open.block_offsets);
            lazy.free(allocator, archive.radix_counts);
            lazy.free(allocator, archive.sort_scratch);
            lazy.free_aligned(allocator, sector_alignment, archive.superblock_buffer);
            lazy.free_aligned(allocator, sector_alignment, archive.page_buffer);
            lazy.free_aligned(allocator, sector_alignment, archive.read_buffer);
            lazy.free_aligned(allocator, sector_alignment, archive.write_buffer);
            archive.* = undefined;
        }

        // ---- Window ----------------------------------------------------------------------

        /// The oldest block retained (null: empty).
        pub fn oldest(archive: *const Archive) ?u64 {
            if (archive.head == null) return null;
            if (archive.sealed_count > 0) return archive.sealed_at(0).first_block;
            assert(archive.open.present);
            return archive.open.first_block;
        }

        /// Bytes of the ring the retained window spans.
        pub fn bytes_used(archive: *const Archive) u64 {
            const start = if (archive.sealed_count > 0)
                archive.sealed_at(0).start
            else if (archive.open.present) archive.open.start else archive.log_end;
            assert(start <= archive.log_end);
            return archive.log_end - start;
        }

        fn sealed_at(archive: *const Archive, index: u32) *Sealed {
            assert(index < archive.sealed_count);
            const position = (archive.oldest_slot + index) % archive.config.segments_max;
            return &archive.slots[position];
        }

        // ---- Append ----------------------------------------------------------------------

        /// Appends the head's child (any block when empty). Writes its unit and waits.
        pub fn append(archive: *Archive, block: *const BlockInput) Error!void {
            if (archive.head) |head| {
                if (block.number != head + 1) return error.NotNextBlock;
                if (!std.mem.eql(u8, &block.parent_hash, &archive.head_hash)) {
                    return error.NotNextBlock;
                }
            }
            const entries = block.transaction_hashes.len + 1 + block.changes.len;
            if (entries > archive.config.segment_entries_max) return error.BlockTooLarge;
            const unit_bytes = block_unit_bytes(block);
            if (unit_bytes > archive.config.unit_bytes_max) return error.BlockTooLarge;
            if (archive.open.present and archive.open_full(@intCast(entries), unit_bytes)) {
                try archive.seal();
            }
            if (!archive.open.present) archive.open_begin(block.number);
            const offset = try archive.reserve(unit_bytes);
            const bytes = archive.encode_block(block);
            assert(bytes.len == unit_bytes);
            try archive.write_wait(bytes, offset);
            archive.index_block(block, offset);
            archive.head = block.number;
            archive.head_hash = block.hash;
            archive.stats.blocks += 1;
            archive.stats.unit_bytes += unit_bytes;
            archive.blocks_since_sync += 1;
            if (archive.blocks_since_sync >= archive.config.sync_blocks) archive.sync_start();
            assert(archive.open.blocks <= archive.config.segment_blocks_max());
        }

        fn open_full(archive: *const Archive, entries: u32, unit_bytes: u64) bool {
            const open = &archive.open;
            assert(open.present);
            if (open.blocks + 1 > archive.config.segment_blocks_max()) return true;
            if (open.entries_len + entries > archive.config.segment_entries_max) return true;
            // A lap skip pads at most one unit: twice each unit bounds the span.
            const span = archive.log_end - open.start + 2 * unit_bytes;
            return span + 2 * index_unit_bytes_max(&archive.config) > archive.ring_bytes / 4;
        }

        /// Whether the open segment is due for sealing (`tick` seals it).
        pub fn seal_due(archive: *const Archive) bool {
            return archive.open.present and archive.open.blocks >= archive.config.segment_blocks;
        }

        fn open_begin(archive: *Archive, first_block: u64) void {
            const open = &archive.open;
            assert(!open.present);
            assert(open.entries_len == 0 and open.blocks == 0);
            open.present = true;
            open.first_block = first_block;
            open.start = archive.log_end;
        }

        /// The log offset of a unit of `bytes` bytes: the next one that does not straddle
        /// the ring's end, after dropping every segment the write would overwrite.
        fn reserve(archive: *Archive, bytes: u64) Error!u64 {
            assert(bytes > 0 and bytes % sector_size == 0);
            assert(bytes <= archive.ring_bytes / 4);
            var offset = archive.log_end;
            const position = offset % archive.ring_bytes;
            if (position + bytes > archive.ring_bytes) offset += archive.ring_bytes - position;
            const end = offset + bytes;
            var evicted = false;
            while (archive.sealed_count > 0) {
                if (archive.sealed_at(0).start + archive.ring_bytes >= end) break;
                archive.oldest_slot = (archive.oldest_slot + 1) % archive.config.segments_max;
                archive.sealed_count -= 1;
                archive.stats.evictions += 1;
                evicted = true;
            }
            // The open segment never wraps onto itself (sealed at a quarter of the ring).
            assert(!archive.open.present or archive.open.start + archive.ring_bytes >= end);
            // The oldest segments leave the superblock durably before they are overwritten.
            if (evicted) try archive.superblock_write();
            archive.log_end = end;
            archive.read_cached = null;
            return offset;
        }

        fn block_unit_bytes(block: *const BlockInput) u64 {
            var meta: u64 = 32 * @as(u64, block.transaction_hashes.len);
            for (block.changes) |*change| {
                const old_len = if (change.old) |old| old.len else 0;
                meta += entry_header_bytes + change.key.len + old_len;
            }
            const total = @sizeOf(UnitHeader) + meta + block.record.len;
            return std.mem.alignForward(u64, total, sector_size);
        }

        fn encode_block(archive: *Archive, block: *const BlockInput) []const u8 {
            const total = block_unit_bytes(block);
            const out = archive.write_buffer[0..@intCast(total)];
            var position: usize = @sizeOf(UnitHeader);
            for (block.transaction_hashes) |*hash| {
                @memcpy(out[position..][0..32], hash);
                position += 32;
            }
            for (block.changes) |*change| {
                assert(change.kind != .block and change.kind != .transaction);
                const old = change.old orelse &.{};
                assert(old.len <= value_bytes_max and (change.old == null or old.len > 0));
                assert(change.key.len > 0 and change.key.len <= key_bytes_max);
                out[position] = @backingInt(change.kind);
                out[position + 1] = @intCast(change.key.len);
                std.mem.writeInt(u16, out[position + 2 ..][0..2], @intCast(old.len), .little);
                position += entry_header_bytes;
                @memcpy(out[position..][0..change.key.len], change.key);
                position += change.key.len;
                @memcpy(out[position..][0..old.len], old);
                position += old.len;
            }
            const meta_end = position;
            @memcpy(out[position..][0..block.record.len], block.record);
            position += block.record.len;
            @memset(out[position..], 0);
            const header: *UnitHeader = @ptrCast(@alignCast(out[0..@sizeOf(UnitHeader)]));
            header.* = .{
                .checksum = 0,
                .meta_checksum = checksum_module.checksum(out[@sizeOf(UnitHeader)..meta_end]),
                .record_checksum = checksum_module.checksum(block.record),
                .magic = magic_unit,
                .version = version,
                .kind = unit_kind_block,
                .flags = if (block.record.len > 0) flag_record else 0,
                .generation = archive.generation,
                .number = block.number,
                .hash = block.hash,
                .parent_hash = block.parent_hash,
                .meta_bytes = @intCast(meta_end - @sizeOf(UnitHeader)),
                .record_bytes = @intCast(block.record.len),
                .count_a = @intCast(block.transaction_hashes.len),
                .count_b = @intCast(block.changes.len),
                .filter_bytes = 0,
            };
            header.seal();
            return out;
        }

        /// Adds the block's keys to the open segment's index.
        fn index_block(archive: *Archive, block: *const BlockInput, offset: u64) void {
            const open = &archive.open;
            assert(open.present);
            assert(block.number == open.first_block + open.blocks);
            const delta: u32 = open.blocks;
            open.block_offsets[open.blocks] = offset;
            open.blocks += 1;
            archive.open_add(fingerprint(.block, &block.hash), delta, 0);
            for (block.transaction_hashes, 0..) |*hash, index| {
                archive.open_add(fingerprint(.transaction, hash), delta, @intCast(index));
            }
            var position: u32 = @sizeOf(UnitHeader) + 32 * @as(u32, @intCast(
                block.transaction_hashes.len,
            ));
            for (block.changes) |*change| {
                archive.open_add(fingerprint(change.kind, change.key), delta, position);
                const old_len: u32 = if (change.old) |old| @intCast(old.len) else 0;
                position += entry_header_bytes + @as(u32, @intCast(change.key.len)) + old_len;
            }
            archive.stats.entries += block.changes.len;
        }

        fn open_add(archive: *Archive, fp: u64, delta: u32, aux: u32) void {
            const open = &archive.open;
            assert(open.entries_len < open.entries.len);
            const index = open.entries_len;
            open.entries[index] = .{ .fingerprint = fp, .delta = delta, .aux = aux };
            const mask = open.table.len - 1;
            var position: usize = @intCast(fp & mask);
            var probes: usize = 0;
            while (probes < open.table.len) : (probes += 1) {
                const occupant = open.table[position];
                if (occupant == no_entry) {
                    open.chain[index] = no_entry;
                    break;
                }
                if (open.entries[occupant].fingerprint == fp) {
                    open.chain[index] = occupant;
                    break;
                }
                position = (position + 1) & mask;
            } else unreachable; // The table has twice the entries' capacity.
            open.table[position] = index;
            open.entries_len += 1;
        }

        /// The newest open entry with fingerprint `fp`, else `no_entry`.
        fn open_newest(archive: *const Archive, fp: u64) u32 {
            const open = &archive.open;
            const mask = open.table.len - 1;
            var position: usize = @intCast(fp & mask);
            var probes: usize = 0;
            while (probes < open.table.len) : (probes += 1) {
                const occupant = open.table[position];
                if (occupant == no_entry) return no_entry;
                if (open.entries[occupant].fingerprint == fp) return occupant;
                position = (position + 1) & mask;
            }
            return no_entry;
        }

        fn open_reset(archive: *Archive) void {
            const open = &archive.open;
            // Clear only the table slots this segment used.
            for (open.entries[0..open.entries_len]) |*entry| {
                const mask = open.table.len - 1;
                var position: usize = @intCast(entry.fingerprint & mask);
                var probes: usize = 0;
                while (open.table[position] != no_entry and probes < open.table.len) {
                    open.table[position] = no_entry;
                    position = (position + 1) & mask;
                    probes += 1;
                }
            }
            open.present = false;
            open.blocks = 0;
            open.entries_len = 0;
            assert(open.table[0] == no_entry or open.table.len > 1);
        }

        // ---- Seal ------------------------------------------------------------------------

        /// Seals the open segment when it is due; drives the storage.
        pub fn tick(archive: *Archive) Error!void {
            archive.storage.tick();
            if (archive.seal_due()) try archive.seal();
        }

        /// Writes the open segment's index unit, syncs, and records it in the superblock.
        pub fn seal(archive: *Archive) Error!void {
            const open = &archive.open;
            assert(open.present and open.blocks > 0);
            if (archive.sealed_count == archive.config.segments_max) {
                // The directory is full: the oldest segment goes first.
                archive.oldest_slot = (archive.oldest_slot + 1) % archive.config.segments_max;
                archive.sealed_count -= 1;
                archive.stats.evictions += 1;
                try archive.superblock_write();
            }
            const sorted = archive.sort_entries();
            const index_bytes = index_unit_bytes(&archive.config, open.blocks, open.entries_len);
            const offset = try archive.reserve(index_bytes);
            const position = (archive.oldest_slot + archive.sealed_count) %
                archive.config.segments_max;
            const sealed = &archive.slots[position];
            const bytes = archive.encode_index(sorted, sealed, offset);
            assert(bytes.len == index_bytes);
            try archive.write_wait(bytes, offset);
            try archive.sync_wait();
            archive.sealed_count += 1;
            archive.open_reset();
            try archive.superblock_write();
            archive.stats.seals += 1;
        }

        /// The open entries sorted by (fingerprint, block): a stable LSD radix sort on the
        /// fingerprint of entries appended in block order.
        fn sort_entries(archive: *Archive) []const IndexEntry {
            const open = &archive.open;
            var source = open.entries[0..open.entries_len];
            var target = archive.sort_scratch[0..open.entries_len];
            const counts = archive.radix_counts;
            var shift: u6 = 0;
            for (0..4) |pass| {
                @memset(counts, 0);
                for (source) |entry| counts[digit(entry.fingerprint, shift)] += 1;
                var total: u32 = 0;
                for (counts) |*count| {
                    const value = count.*;
                    count.* = total;
                    total += value;
                }
                assert(total == source.len);
                for (source) |entry| {
                    const d = digit(entry.fingerprint, shift);
                    target[counts[d]] = entry;
                    counts[d] += 1;
                }
                std.mem.swap([]IndexEntry, &source, &target);
                if (pass < 3) shift += 16;
            }
            // Four passes: the result is back in `open.entries` (chains are dead now).
            assert(source.ptr == open.entries.ptr);
            for (1..source.len) |i| {
                const previous = source[i - 1];
                assert(!IndexEntry.before(source[i], previous.fingerprint, previous.delta));
            }
            return source;
        }

        fn digit(value: u64, shift: u6) usize {
            return @intCast((value >> shift) & 0xffff);
        }

        fn encode_index(
            archive: *Archive,
            sorted: []const IndexEntry,
            sealed: *Sealed,
            offset: u64,
        ) []const u8 {
            const open = &archive.open;
            const config = &archive.config;
            const total = index_unit_bytes(config, open.blocks, open.entries_len);
            const out = archive.write_buffer[0..@intCast(total)];
            const pages_offset = index_pages_offset(config, open.blocks, open.entries_len);
            sealed.* = .{
                .first_block = open.first_block,
                .blocks = open.blocks,
                .start = open.start,
                .index = offset,
                .end = offset + total,
                .entries = open.entries_len,
                .pages = offset + pages_offset,
                .block_offsets = sealed.block_offsets,
                .filter = sealed.filter,
                .fences = sealed.fences,
            };
            @memcpy(sealed.block_offsets[0..open.blocks], open.block_offsets[0..open.blocks]);
            @memset(sealed.filter, 0);
            for (sorted, 0..) |entry, i| {
                if (i > 0 and sorted[i - 1].fingerprint == entry.fingerprint) continue;
                filter_add(sealed.filter, entry.fingerprint);
            }
            const pages = out[@intCast(pages_offset)..];
            @memset(pages, 0);
            @memcpy(pages[0 .. sorted.len * @sizeOf(IndexEntry)], std.mem.sliceAsBytes(sorted));
            for (0..sealed.fences_count()) |page| {
                const first = sorted[page * entries_per_page];
                const page_bytes = pages[page * sector_size ..][0..sector_size];
                sealed.fences[page] = .{
                    .fingerprint = first.fingerprint,
                    .delta = first.delta,
                    .checksum = checksum_module.checksum(page_bytes),
                };
            }
            const meta = archive.encode_index_meta(out, sealed);
            const header: *UnitHeader = @ptrCast(@alignCast(out[0..@sizeOf(UnitHeader)]));
            header.* = .{
                .checksum = 0,
                .meta_checksum = checksum_module.checksum(meta),
                .record_checksum = 0,
                .magic = magic_unit,
                .version = version,
                .kind = unit_kind_index,
                .flags = 0,
                .generation = archive.generation,
                .number = sealed.first_block,
                .hash = archive.head_hash,
                .parent_hash = @splat(0),
                .meta_bytes = @intCast(meta.len),
                .record_bytes = @intCast(total - pages_offset),
                .count_a = sealed.blocks,
                .count_b = sealed.entries,
                .filter_bytes = config.filter_bytes,
            };
            header.seal();
            return out;
        }

        /// Block table, filter, fences after the header; zero padding to the pages.
        fn encode_index_meta(archive: *Archive, out: []u8, sealed: *const Sealed) []const u8 {
            const table = std.mem.sliceAsBytes(sealed.block_offsets[0..sealed.blocks]);
            const fences = std.mem.sliceAsBytes(sealed.fences[0..sealed.fences_count()]);
            var position: usize = @sizeOf(UnitHeader);
            @memcpy(out[position..][0..table.len], table);
            position += table.len;
            @memcpy(out[position..][0..sealed.filter.len], sealed.filter);
            position += sealed.filter.len;
            @memcpy(out[position..][0..fences.len], fences);
            position += fences.len;
            const pages_offset = index_pages_offset(&archive.config, sealed.blocks, sealed.entries);
            @memset(out[position..@intCast(pages_offset)], 0);
            return out[@sizeOf(UnitHeader)..position];
        }

        fn index_meta_bytes(config: *const Config, blocks: u32, entries: u32) u64 {
            const fences = std.math.divCeil(u64, entries, entries_per_page) catch unreachable;
            return 8 * @as(u64, blocks) + config.filter_bytes + fences * @sizeOf(Fence);
        }

        fn index_pages_offset(config: *const Config, blocks: u32, entries: u32) u64 {
            const meta = index_meta_bytes(config, blocks, entries);
            return std.mem.alignForward(u64, @sizeOf(UnitHeader) + meta, sector_size);
        }

        fn index_unit_bytes(config: *const Config, blocks: u32, entries: u32) u64 {
            const pages = std.math.divCeil(u64, entries, entries_per_page) catch unreachable;
            return index_pages_offset(config, blocks, entries) + pages * sector_size;
        }

        fn index_unit_bytes_max(config: *const Config) u64 {
            const blocks_max = config.segment_blocks_max();
            return index_unit_bytes(config, blocks_max, config.segment_entries_max);
        }

        // ---- Storage ---------------------------------------------------------------------

        fn physical(archive: *const Archive, offset: u64) u64 {
            return 2 * archive.superblock_bytes + offset % archive.ring_bytes;
        }

        fn write_wait(archive: *Archive, bytes: []const u8, offset: u64) Error!void {
            assert(!archive.writing);
            const position = offset % archive.ring_bytes;
            assert(position + bytes.len <= archive.ring_bytes);
            archive.writing = true;
            const physical_offset = archive.physical(offset);
            archive.storage.write_sectors(write_done, &archive.write, bytes, physical_offset);
            try archive.wait_for(&archive.writing);
        }

        fn write_raw_wait(archive: *Archive, bytes: []const u8, physical_offset: u64) Error!void {
            assert(!archive.writing);
            archive.writing = true;
            archive.storage.write_sectors(write_done, &archive.write, bytes, physical_offset);
            try archive.wait_for(&archive.writing);
        }

        fn write_done(write: *storage_module.Write) void {
            const archive: *Archive = @fieldParentPtr("write", write);
            assert(archive.writing);
            archive.writing = false;
        }

        fn wait_for(archive: *Archive, flag: *const bool) Error!void {
            var ticks: u32 = 0;
            while (flag.*) : (ticks += 1) {
                if (ticks >= ticks_max) return error.Stalled;
                archive.storage.tick();
            }
        }

        /// Starts an asynchronous sync (one at a time; another follows if asked meanwhile).
        pub fn sync_start(archive: *Archive) void {
            archive.blocks_since_sync = 0;
            if (archive.syncing) {
                archive.sync_again = true;
                return;
            }
            archive.syncing = true;
            archive.storage.sync(sync_done, &archive.sync_op);
        }

        fn sync_done(sync_op: *storage_module.Sync) void {
            const archive: *Archive = @fieldParentPtr("sync_op", sync_op);
            assert(archive.syncing);
            archive.syncing = false;
            if (archive.sync_again) {
                archive.sync_again = false;
                archive.syncing = true;
                archive.storage.sync(sync_done, &archive.sync_op);
            }
        }

        /// A sync that covers every write so far, waited for.
        fn sync_wait(archive: *Archive) Error!void {
            try archive.wait_for(&archive.syncing);
            archive.syncing = true;
            archive.storage.sync(sync_done, &archive.sync_op);
            try archive.wait_for(&archive.syncing);
        }

        /// Waits for every write and sync in flight (before closing, or in tests).
        pub fn flush(archive: *Archive) Error!void {
            try archive.sync_wait();
            assert(!archive.writing and !archive.syncing);
        }

        // ---- Superblock ------------------------------------------------------------------

        fn superblock_size(segments_max: u32) u64 {
            const records = @as(u64, segments_max) * @sizeOf(SegmentRecord);
            const bytes = @sizeOf(SuperblockHeader) + records;
            return std.mem.alignForward(u64, bytes, sector_size);
        }

        /// Writes the next superblock copy and syncs.
        fn superblock_write(archive: *Archive) Error!void {
            archive.sequence += 1;
            const out = archive.superblock_buffer;
            @memset(out, 0);
            const header_bytes = out[0..@sizeOf(SuperblockHeader)];
            const header: *SuperblockHeader = @ptrCast(@alignCast(header_bytes));
            header.* = .{
                .checksum = 0,
                .magic = magic_superblock,
                .version = version,
                .segments_count = archive.sealed_count,
                .sequence = archive.sequence,
                .generation = archive.generation,
                .ring_bytes = archive.ring_bytes,
                .open_present = @intFromBool(archive.open.present),
                .open_first_block = archive.open.first_block,
                .open_start = archive.open.start,
                .log_end = archive.log_end,
            };
            const records_bytes = archive.config.segments_max * @sizeOf(SegmentRecord);
            const records: []SegmentRecord = @alignCast(std.mem.bytesAsSlice(
                SegmentRecord,
                out[@sizeOf(SuperblockHeader)..][0..records_bytes],
            ));
            for (0..archive.sealed_count) |index| {
                const sealed = archive.sealed_at(@intCast(index));
                records[index] = .{
                    .first_block = sealed.first_block,
                    .blocks = sealed.blocks,
                    .start = sealed.start,
                    .index = sealed.index,
                    .end = sealed.end,
                };
            }
            header.checksum = checksum_module.checksum(out[16..]);
            const copy = archive.sequence % 2;
            try archive.sync_wait();
            try archive.write_raw_wait(out, copy * archive.superblock_bytes);
            try archive.sync_wait();
        }

        // ---- Open ------------------------------------------------------------------------

        /// Loads the archive from its storage: the newest valid superblock, every sealed
        /// segment it names (dropping a segment that fails its checks, and every older
        /// one), and the open segment's blocks.
        pub fn load(archive: *Archive) Error!void {
            assert(archive.head == null and archive.sealed_count == 0);
            const header = try archive.superblock_read() orelse {
                // A new (or unreadable) file: start empty, at a new generation.
                archive.generation +%= 1;
                try archive.superblock_write();
                return;
            };
            archive.generation = header.generation;
            archive.sequence = header.sequence;
            archive.log_end = header.log_end;
            const records_bytes = header.segments_count * @sizeOf(SegmentRecord);
            const records: []const SegmentRecord = @alignCast(std.mem.bytesAsSlice(
                SegmentRecord,
                archive.superblock_buffer[@sizeOf(SuperblockHeader)..][0..records_bytes],
            ));
            // Newest first: a segment that fails ends the window there (older ones would
            // leave a gap between them and the head).
            var loaded: u32 = 0;
            var index = records.len;
            while (index > 0) {
                index -= 1;
                if (!try archive.segment_load(&records[index], @intCast(index))) break;
                loaded += 1;
            }
            archive.oldest_slot = @intCast(records.len - loaded);
            archive.sealed_count = loaded;
            if (loaded > 0) {
                const newest = archive.sealed_at(loaded - 1);
                archive.head = newest.first_block + newest.blocks - 1;
                const last = newest.block_offsets[newest.blocks - 1];
                archive.head_hash = try archive.unit_hash(last);
            }
            if (header.open_present != 0) {
                try archive.open_scan(header.open_first_block, header.open_start, null);
            }
            assert(archive.head == null or archive.oldest() != null);
        }

        fn superblock_read(archive: *Archive) Error!?SuperblockHeader {
            var best: ?SuperblockHeader = null;
            var best_copy: u64 = 0;
            for (0..2) |copy| {
                const out = archive.superblock_buffer;
                const offset = @as(u64, copy) * archive.superblock_bytes;
                archive.storage.read_sectors_sync(out, offset) catch return error.ReadFailed;
                const header_bytes = out[0..@sizeOf(SuperblockHeader)];
                const header: *const SuperblockHeader = @ptrCast(@alignCast(header_bytes));
                if (header.checksum != checksum_module.checksum(out[16..])) continue;
                if (header.magic != magic_superblock or header.version != version) continue;
                if (header.ring_bytes != archive.ring_bytes) continue;
                if (header.segments_count > archive.config.segments_max) continue;
                if (best == null or header.sequence > best.?.sequence) {
                    best = header.*;
                    best_copy = @intCast(copy);
                }
            }
            if (best == null) return null;
            archive.storage.read_sectors_sync(
                archive.superblock_buffer,
                @as(u64, best_copy) * archive.superblock_bytes,
            ) catch return error.ReadFailed;
            return best;
        }

        /// Loads a sealed segment's metadata into the slot it will take (records are
        /// loaded newest first into slots `index`); false when it fails a check.
        fn segment_load(archive: *Archive, record: *const SegmentRecord, index: u32) Error!bool {
            const config = &archive.config;
            if (record.blocks == 0 or record.blocks > config.segment_blocks_max()) return false;
            if (record.end <= record.index or record.index < record.start) return false;
            if (record.start + archive.ring_bytes < archive.log_end) return false;
            const sealed = &archive.slots[index];
            const header = try archive.read_unit_header(record.index) orelse return false;
            if (header.kind != unit_kind_index or header.number != record.first_block) return false;
            if (header.count_a != record.blocks) return false;
            if (header.count_b > config.segment_entries_max) return false;
            if (header.filter_bytes != config.filter_bytes) return false;
            const entries = header.count_b;
            const blocks = header.count_a;
            if (header.meta_bytes != index_meta_bytes(config, blocks, entries)) return false;
            const total = index_unit_bytes(config, blocks, entries);
            if (record.end - record.index != total) return false;
            const pages_offset = index_pages_offset(config, blocks, entries);
            const meta_end = @sizeOf(UnitHeader) + header.meta_bytes;
            const meta_read = std.mem.alignForward(u64, meta_end, sector_size);
            assert(meta_read <= pages_offset);
            const buffer = archive.read_buffer[0..@intCast(meta_read)];
            archive.storage.read_sectors_sync(buffer, archive.physical(record.index)) catch
                return error.ReadFailed;
            archive.read_cached = null;
            const meta = buffer[@sizeOf(UnitHeader)..][0..header.meta_bytes];
            if (checksum_module.checksum(meta) != header.meta_checksum) return false;
            sealed.* = .{
                .first_block = record.first_block,
                .blocks = blocks,
                .start = record.start,
                .index = record.index,
                .end = record.end,
                .entries = entries,
                .pages = record.index + pages_offset,
                .block_offsets = sealed.block_offsets,
                .filter = sealed.filter,
                .fences = sealed.fences,
            };
            const table_bytes = 8 * @as(usize, blocks);
            @memcpy(std.mem.sliceAsBytes(sealed.block_offsets[0..blocks]), meta[0..table_bytes]);
            @memcpy(sealed.filter, meta[table_bytes..][0..config.filter_bytes]);
            const fences = std.mem.sliceAsBytes(sealed.fences[0..sealed.fences_count()]);
            @memcpy(fences, meta[table_bytes + config.filter_bytes ..][0..fences.len]);
            return true;
        }

        fn read_unit_header(archive: *Archive, offset: u64) Error!?UnitHeader {
            const buffer = archive.page_buffer[0..sector_size];
            archive.storage.read_sectors_sync(buffer, archive.physical(offset)) catch
                return error.ReadFailed;
            const header: *const UnitHeader = @ptrCast(@alignCast(buffer[0..@sizeOf(UnitHeader)]));
            if (!header.valid(archive.generation)) return null;
            return header.*;
        }

        fn unit_hash(archive: *Archive, offset: u64) Error!Hash {
            const header = try archive.read_unit_header(offset) orelse return error.Corrupt;
            return header.hash;
        }

        /// Rebuilds the open segment from its units at `start`: each must be the next block
        /// (and child of the last), valid, and at or below `last` when given.
        fn open_scan(archive: *Archive, first_block: u64, start: u64, last: ?u64) Error!void {
            assert(!archive.open.present);
            archive.log_end = start;
            archive.open_begin(first_block);
            var offset = start;
            var scanned: u32 = 0;
            while (scanned < archive.config.segment_blocks_max()) : (scanned += 1) {
                const number = first_block + scanned;
                if (last) |bound| if (number > bound) break;
                const found = try archive.scan_unit(offset, number) orelse break;
                offset = found.offset;
                const header = try archive.read_unit_header(offset) orelse unreachable;
                archive.index_scanned(&header, offset);
                offset += unit_bytes_of(&header);
                archive.log_end = offset;
            }
            if (archive.open.blocks == 0) archive.open.present = false;
        }

        const Scanned = struct { offset: u64 };

        /// The valid unit of block `number` at `offset`, or at the next lap's start when it
        /// would not have fit before the ring's end.
        fn scan_unit(archive: *Archive, offset: u64, number: u64) Error!?Scanned {
            if (try archive.check_unit(offset, number)) |bytes| {
                _ = bytes;
                return .{ .offset = offset };
            }
            const position = offset % archive.ring_bytes;
            if (position == 0) return null;
            const lap = offset + archive.ring_bytes - position;
            const bytes = try archive.check_unit(lap, number) orelse return null;
            if (position + bytes <= archive.ring_bytes) return null;
            return .{ .offset = lap };
        }

        /// The unit bytes when a valid unit of block `number` (the head's child) is there.
        fn check_unit(archive: *Archive, offset: u64, number: u64) Error!?u64 {
            const header = try archive.read_unit_header(offset) orelse return null;
            if (header.kind != unit_kind_block or header.number != number) return null;
            if (archive.head) |head| {
                if (head + 1 != number) return null;
                if (!std.mem.eql(u8, &header.parent_hash, &archive.head_hash)) return null;
            }
            const bytes = unit_bytes_of(&header);
            if (bytes > archive.config.unit_bytes_max) return null;
            if (offset % archive.ring_bytes + bytes > archive.ring_bytes) return null;
            const unit = archive.read_unit_bytes(offset, bytes) catch |err| switch (err) {
                error.Corrupt => return null,
                else => return err,
            };
            _ = unit;
            return bytes;
        }

        /// Indexes a scanned unit (now in `read_buffer`) into the open segment.
        fn index_scanned(archive: *Archive, header: *const UnitHeader, offset: u64) void {
            const unit = archive.read_buffer;
            const open = &archive.open;
            const delta = open.blocks;
            open.block_offsets[delta] = offset;
            open.blocks += 1;
            archive.open_add(fingerprint(.block, &header.hash), delta, 0);
            var position: u32 = @sizeOf(UnitHeader);
            for (0..header.count_a) |index| {
                const hash = unit[position..][0..32];
                archive.open_add(fingerprint(.transaction, hash), delta, @intCast(index));
                position += 32;
            }
            for (0..header.count_b) |_| {
                const entry = decode_entry(unit[position..]);
                archive.open_add(fingerprint(entry.kind, entry.key), delta, position);
                position += entry.bytes;
            }
            archive.head = header.number;
            archive.head_hash = header.hash;
        }

        // ---- Rebase and reset ------------------------------------------------------------

        pub const Rebase = enum {
            /// The archive's head is the owner's head.
            aligned,
            /// The archive ends below the owner's head: append the missing blocks or reset.
            behind,
            /// The archive is empty.
            empty,
        };

        /// Truncates blocks above `number`; `hash` must be the owner's block there. Resets
        /// the archive when its block at `number` differs.
        pub fn rebase(archive: *Archive, number: u64, hash: Hash) Error!Rebase {
            const head = archive.head orelse return .empty;
            if (head > number) {
                const oldest_block = archive.oldest().?;
                if (number + 1 <= oldest_block) {
                    try archive.reset();
                    return .empty;
                }
                try archive.truncate(number);
            }
            if (archive.head.? < number) return .behind;
            if (!std.mem.eql(u8, &archive.head_hash, &hash)) {
                try archive.reset();
                return .empty;
            }
            return .aligned;
        }

        /// Drops every block above `number` (reopening sealed segments as needed).
        fn truncate(archive: *Archive, number: u64) Error!void {
            assert(archive.head.? > number);
            var first: u64 = undefined;
            var start: u64 = undefined;
            if (archive.open.present and archive.open.first_block <= number) {
                first = archive.open.first_block;
                start = archive.open.start;
            } else {
                // Reopen the newest sealed segment that holds `number`.
                var reopened: ?Sealed = null;
                while (archive.sealed_count > 0) {
                    const newest = archive.sealed_at(archive.sealed_count - 1).*;
                    archive.sealed_count -= 1;
                    if (newest.first_block <= number) {
                        reopened = newest;
                        break;
                    }
                }
                const segment = reopened orelse unreachable; // number >= oldest (caller).
                first = segment.first_block;
                start = segment.start;
            }
            archive.open_reset();
            archive.head = null;
            if (archive.sealed_count > 0) {
                const newest = archive.sealed_at(archive.sealed_count - 1);
                archive.head = newest.first_block + newest.blocks - 1;
                archive.head_hash = try archive.unit_hash(newest.block_offsets[newest.blocks - 1]);
            }
            try archive.open_scan(first, start, number);
            if (archive.head == null or archive.head.? != number) return error.Corrupt;
            try archive.superblock_write();
        }

        /// Drops everything; the next append starts the window (at any block).
        pub fn reset(archive: *Archive) Error!void {
            archive.generation +%= 1;
            archive.sealed_count = 0;
            archive.open_reset();
            archive.head = null;
            archive.head_hash = @splat(0);
            archive.read_cached = null;
            archive.stats.resets += 1;
            try archive.superblock_write();
        }

        // ---- Reads -----------------------------------------------------------------------

        /// The log offset of block `number`'s unit, when retained.
        fn unit_offset(archive: *const Archive, number: u64) ?u64 {
            const head = archive.head orelse return null;
            if (number > head or number < archive.oldest().?) return null;
            if (archive.open.present and number >= archive.open.first_block) {
                return archive.open.block_offsets[@intCast(number - archive.open.first_block)];
            }
            const index = archive.segment_of(number) orelse return null;
            const sealed = archive.sealed_at(index);
            return sealed.block_offsets[@intCast(number - sealed.first_block)];
        }

        /// The sealed segment (index from the oldest) that holds `number`.
        fn segment_of(archive: *const Archive, number: u64) ?u32 {
            var low: u32 = 0;
            var high: u32 = archive.sealed_count;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const sealed = archive.sealed_at(middle);
                if (number < sealed.first_block) {
                    high = middle;
                } else if (number >= sealed.first_block + sealed.blocks) {
                    low = middle + 1;
                } else return middle;
            }
            return null;
        }

        /// Reads and checks `bytes` of the unit at `offset` into `read_buffer`.
        fn read_unit_bytes(archive: *Archive, offset: u64, bytes: u64) Error![]const u8 {
            assert(!archive.writing);
            assert(bytes <= archive.read_buffer.len);
            const buffer = archive.read_buffer[0..@intCast(bytes)];
            archive.storage.read_sectors_sync(buffer, archive.physical(offset)) catch
                return error.ReadFailed;
            archive.read_cached = null;
            archive.stats.unit_reads += 1;
            const header: *const UnitHeader = @ptrCast(@alignCast(buffer[0..@sizeOf(UnitHeader)]));
            if (!header.valid(archive.generation)) return error.Corrupt;
            if (@sizeOf(UnitHeader) + header.body_bytes() > bytes) return error.Corrupt;
            const meta = buffer[@sizeOf(UnitHeader)..][0..header.meta_bytes];
            if (checksum_module.checksum(meta) != header.meta_checksum) return error.Corrupt;
            const record_start = @sizeOf(UnitHeader) + header.meta_bytes;
            const record = buffer[record_start..][0..header.record_bytes];
            if (checksum_module.checksum(record) != header.record_checksum) return error.Corrupt;
            return buffer;
        }

        /// Block `number`'s unit into `read_buffer` (cached until the next read or write).
        fn load_unit(archive: *Archive, number: u64) Error!?*const UnitHeader {
            const offset = archive.unit_offset(number) orelse return null;
            if (archive.read_cached != number) {
                const header = try archive.read_unit_header(offset) orelse return error.Corrupt;
                if (header.kind != unit_kind_block or header.number != number) return error.Corrupt;
                const bytes = std.mem.alignForward(
                    u64,
                    @sizeOf(UnitHeader) + header.body_bytes(),
                    sector_size,
                );
                if (bytes > archive.read_buffer.len) return error.Corrupt;
                _ = try archive.read_unit_bytes(offset, bytes);
                archive.read_cached = number;
            }
            return @ptrCast(@alignCast(archive.read_buffer[0..@sizeOf(UnitHeader)]));
        }

        /// Block `number` as stored, when retained. Valid until the next read.
        pub fn block_at(archive: *Archive, number: u64) Error!?Unit {
            const header = try archive.load_unit(number) orelse return null;
            const unit = archive.read_buffer;
            const hashes_bytes = 32 * @as(usize, header.count_a);
            const hashes: []const Hash = @alignCast(std.mem.bytesAsSlice(
                Hash,
                unit[@sizeOf(UnitHeader)..][0..hashes_bytes],
            ));
            const record_start = @sizeOf(UnitHeader) + header.meta_bytes;
            const record: ?[]const u8 = if (header.flags & flag_record != 0)
                unit[record_start..][0..header.record_bytes]
            else
                null;
            return .{
                .number = number,
                .hash = header.hash,
                .parent_hash = header.parent_hash,
                .record = record,
                .transaction_hashes = hashes,
                .entries_count = header.count_b,
            };
        }

        /// Where the block or transaction with this hash is (`kind` `block` or
        /// `transaction`), newest first.
        pub fn find(archive: *Archive, kind: Kind, hash: *const Hash) Error!?Location {
            assert(kind == .block or kind == .transaction);
            archive.stats.lookups += 1;
            const fp = fingerprint(kind, hash);
            var candidate = archive.open_newest(fp);
            while (candidate != no_entry) : (candidate = archive.open.chain[candidate]) {
                const entry = archive.open.entries[candidate];
                const number = archive.open.first_block + entry.delta;
                if (try archive.hash_matches(kind, hash, number, entry.aux)) {
                    return .{ .number = number, .aux = entry.aux };
                }
            }
            var index = archive.sealed_count;
            while (index > 0) {
                index -= 1;
                var cursor = try archive.sealed_seek(index, fp, 0) orelse continue;
                while (try archive.sealed_next(index, &cursor, fp)) |entry| {
                    const number = archive.sealed_at(index).first_block + entry.delta;
                    if (try archive.hash_matches(kind, hash, number, entry.aux)) {
                        return .{ .number = number, .aux = entry.aux };
                    }
                }
            }
            return null;
        }

        fn hash_matches(
            archive: *Archive,
            kind: Kind,
            hash: *const Hash,
            number: u64,
            aux: u32,
        ) Error!bool {
            const unit = try archive.block_at(number) orelse return error.Corrupt;
            if (kind == .block) return std.mem.eql(u8, &unit.hash, hash);
            if (aux >= unit.transaction_hashes.len) return error.Corrupt;
            return std.mem.eql(u8, &unit.transaction_hashes[aux], hash);
        }

        /// The value `key` had after block `number`: its old value in the first retained
        /// block after `number` that changed it; null when no such block changed it (the
        /// head's value stands). `number` must be within `[oldest - 1, head]`.
        pub fn value_after(
            archive: *Archive,
            kind: Kind,
            key: []const u8,
            number: u64,
        ) Error!?Found {
            assert(kind != .block and kind != .transaction);
            const head = archive.head.?;
            assert(number <= head and number + 1 >= archive.oldest().?);
            archive.stats.lookups += 1;
            if (number == head) return null;
            const fp = fingerprint(kind, key);
            const target = number + 1;
            var index = archive.segment_of(target) orelse archive.sealed_count;
            while (index < archive.sealed_count) : (index += 1) {
                const sealed = archive.sealed_at(index);
                const delta: u32 = if (target > sealed.first_block)
                    @intCast(target - sealed.first_block)
                else
                    0;
                var cursor = try archive.sealed_seek(index, fp, delta) orelse continue;
                while (try archive.sealed_next(index, &cursor, fp)) |entry| {
                    const block_number = sealed.first_block + entry.delta;
                    if (try archive.entry_value(kind, key, block_number, entry.aux)) |old| {
                        return .{ .number = block_number, .old = old.value };
                    }
                }
            }
            return archive.open_value_after(kind, key, fp, target);
        }

        fn open_value_after(
            archive: *Archive,
            kind: Kind,
            key: []const u8,
            fp: u64,
            target: u64,
        ) Error!?Found {
            const open = &archive.open;
            if (!open.present) return null;
            // The chain runs newest to oldest: the earliest entry at or after `target` comes
            // last. Collisions are rare; on one, the next later candidate is tried.
            var floor = target;
            var rounds: u32 = 0;
            while (rounds < open.entries_len + 1) : (rounds += 1) {
                var best: u32 = no_entry;
                var candidate = archive.open_newest(fp);
                while (candidate != no_entry) : (candidate = open.chain[candidate]) {
                    const number = open.first_block + open.entries[candidate].delta;
                    if (number < floor) break;
                    best = candidate;
                }
                if (best == no_entry) return null;
                const entry = open.entries[best];
                const number = open.first_block + entry.delta;
                if (try archive.entry_value(kind, key, number, entry.aux)) |old| {
                    return .{ .number = number, .old = old.value };
                }
                floor = number + 1;
            }
            return null;
        }

        const Value = struct { value: ?[]const u8 };

        /// The entry at `aux` in block `number`'s unit when it names `key`.
        fn entry_value(
            archive: *Archive,
            kind: Kind,
            key: []const u8,
            number: u64,
            aux: u32,
        ) Error!?Value {
            const header = try archive.load_unit(number) orelse return error.Corrupt;
            const meta_end = @sizeOf(UnitHeader) + header.meta_bytes;
            if (aux < @sizeOf(UnitHeader)) return error.Corrupt;
            if (aux + entry_header_bytes > meta_end) return error.Corrupt;
            const entry = decode_entry(archive.read_buffer[aux..meta_end]);
            if (aux + entry.bytes > meta_end) return error.Corrupt;
            if (entry.kind != kind or !std.mem.eql(u8, entry.key, key)) return null;
            return .{ .value = entry.old };
        }

        const Cursor = struct { page: u32, slot: u32 };

        /// The first index position of segment `index` at or after (fp, delta), when the
        /// segment may hold `fp`.
        fn sealed_seek(archive: *Archive, index: u32, fp: u64, delta: u32) Error!?Cursor {
            const sealed = archive.sealed_at(index);
            if (!sealed.may_contain(fp)) {
                archive.stats.filter_skips += 1;
                return null;
            }
            const fences = sealed.fences[0..sealed.fences_count()];
            // The last page whose first entry is before (fp, delta).
            var low: u32 = 0;
            var high: u32 = @intCast(fences.len);
            while (low < high) {
                const middle = low + (high - low) / 2;
                const fence = &fences[middle];
                const entry: IndexEntry = .{
                    .fingerprint = fence.fingerprint,
                    .delta = fence.delta,
                    .aux = 0,
                };
                if (IndexEntry.before(entry, fp, delta)) low = middle + 1 else high = middle;
            }
            const page: u32 = if (low == 0) 0 else low - 1;
            const entries = try archive.page_read(index, page);
            var position: u32 = 0;
            while (position < entries.len and IndexEntry.before(entries[position], fp, delta)) {
                position += 1;
            }
            return .{ .page = page, .slot = position };
        }

        /// The entry at the cursor when it has fingerprint `fp`, advancing the cursor.
        fn sealed_next(archive: *Archive, index: u32, cursor: *Cursor, fp: u64) Error!?IndexEntry {
            const sealed = archive.sealed_at(index);
            var entries = try archive.page_read(index, cursor.page);
            if (cursor.slot == entries.len) {
                if (cursor.page + 1 == sealed.fences_count()) return null;
                cursor.page += 1;
                cursor.slot = 0;
                entries = try archive.page_read(index, cursor.page);
            }
            const entry = entries[cursor.slot];
            if (entry.fingerprint != fp) return null;
            cursor.slot += 1;
            return entry;
        }

        /// The entries of page `page` of segment `index`, checked against its fence.
        fn page_read(archive: *Archive, index: u32, page: u32) Error![]const IndexEntry {
            const sealed = archive.sealed_at(index);
            assert(page < sealed.fences_count());
            const buffer = archive.page_buffer[0..sector_size];
            const offset = sealed.pages + @as(u64, page) * sector_size;
            archive.storage.read_sectors_sync(buffer, archive.physical(offset)) catch
                return error.ReadFailed;
            archive.stats.page_reads += 1;
            if (checksum_module.checksum(buffer) != sealed.fences[page].checksum) {
                return error.Corrupt;
            }
            const count = @min(entries_per_page, sealed.entries - page * entries_per_page);
            const entries: []const IndexEntry =
                @alignCast(std.mem.bytesAsSlice(IndexEntry, buffer));
            return entries[0..count];
        }
    };
}

/// A unit's bytes on disk: header and body, rounded up to sectors.
fn unit_bytes_of(header: *const UnitHeader) u64 {
    return std.mem.alignForward(u64, @sizeOf(UnitHeader) + header.body_bytes(), sector_size);
}

const DecodedEntry = struct { kind: Kind, key: []const u8, old: ?[]const u8, bytes: u32 };

fn decode_entry(bytes: []const u8) DecodedEntry {
    const kind: Kind = @fromBackingInt(@intCast(bytes[0]));
    const key_len = bytes[1];
    const old_len = std.mem.readInt(u16, bytes[2..4], .little);
    const key = bytes[entry_header_bytes..][0..key_len];
    const old = bytes[entry_header_bytes + key_len ..][0..old_len];
    return .{
        .kind = kind,
        .key = key,
        .old = if (old_len == 0) null else old,
        .bytes = entry_header_bytes + key_len + old_len,
    };
}

fn filter_add(filter: []u8, fp: u64) void {
    const bits: u64 = filter.len * 8;
    const h1: u64 = fp & 0xffff_ffff;
    const h2: u64 = (fp >> 32) | 1;
    for (0..filter_probes) |i| {
        const bit = (h1 +% i * h2) & (bits - 1);
        filter[@intCast(bit / 8)] |= @as(u8, 1) << @intCast(bit % 8);
    }
}

fn filter_contains(filter: []const u8, fp: u64) bool {
    const bits: u64 = filter.len * 8;
    const h1: u64 = fp & 0xffff_ffff;
    const h2: u64 = (fp >> 32) | 1;
    for (0..filter_probes) |i| {
        const bit = (h1 +% i * h2) & (bits - 1);
        if (filter[@intCast(bit / 8)] & (@as(u8, 1) << @intCast(bit % 8)) == 0) return false;
    }
    return true;
}

test {
    _ = @import("test.zig");
}

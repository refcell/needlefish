//! LSM tree over the grid: fixed-size keys (up to 72 bytes) and fixed-size values
//! (`TreeType`) or values of 1..`value_size_max` bytes (`TreeVariableType`), the primitive for
//! flat state (disk state phase 2). One tree per key space: hashed accounts (32-byte keys),
//! hashed storage slots (64-byte keys, account hash ++ slot hash), and trie branch records.
//!
//! Shape (leveled, TigerBeetle/RocksDB style):
//! - Two static memtables (`lsm_memtable.zig`): writes go to the mutable one; once it holds
//!   `flush_entries_min` entries and the other is empty, they swap and the full one becomes
//!   immutable, sorted once, and is flushed into new level-0 tables (one per
//!   `table_records_max` records or full index block: several when the memtable is larger
//!   than a table). A put into a full
//!   mutable memtable fails with `error.Busy` (backpressure, as the journal does); nothing is
//!   allocated after `init`.
//! - Level 0 holds up to `level0_tables_max` tables that may overlap (newest first). Levels
//!   1.. hold disjoint tables sorted by key; level i holds about `capacity[i]` records, level
//!   1 as much as a full level 0 and each next level `growth_factor` times more.
//! - Tables are `table.zig` tables. A record's value is `value_size` bytes (variable trees:
//!   1..`value_size_max`), or empty for a tombstone (a delete). Tables are cut at
//!   `table_records_max` records or at `Layout.data_blocks_max` data blocks (one index block),
//!   whichever comes first; fixed trees size their tables so the record limit always comes
//!   first. Checkpoint memtable entries are `key ++ tag u8 ++ value` (fixed) or
//!   `key ++ length u16 ++ value bytes` (variable, length 0 for a tombstone). Compaction
//!   drops shadowed versions and drops tombstones once no deeper level can hold the key.
//! - Point lookup: mutable, immutable, then each level-0 table newest first, then the one
//!   table per deeper level whose key range (fence keys `key_min`/`key_max`) holds the key.
//!   Every level but the last has a split-block Bloom filter per table (`lsm_filter.zig`),
//!   resident in RAM, so a lookup of an absent key reads at most the last level's block
//!   (Monkey: most records live in the last level, where a filter costs the most).
//!   `lookup` is asynchronous (grid reads complete from a storage tick); `get` is the same
//!   search with blocking grid reads (`Grid.read_sync`), for synchronous callers.
//!
//! Compaction (`lsm_compaction.zig`) runs one job at a time (a memtable flush or a level
//! merge), paced by `compact(blocks)`: each call (one per durable commit) grants a fixed
//! number of grid block reads and writes, and unused grants do not accumulate. So compaction
//! IO per commit is bounded and is a pure function of the commit sequence (DST).
//!
//! Bulk load (`lsm_bulk.zig`): a sorted stream written straight into the last level of an
//! empty tree. Merges cut their outputs at grandparent overlap, so later merges into such a
//! last level of thousands of tables stay bounded.
//!
//! Checkpoint (`checkpoint_encode`, in the caller's checkpoint bytes): the table list per
//! level (the manifest), both memtables (the immutable one only while its flush is pending),
//! and the blocks the running job acquired ("orphans"). A checkpoint may start at any time:
//! the job's inputs are still in the manifest and its outputs are not, so open (`open_decode`
//! + `open_scan`, which reads every level but the last) releases the orphans and the job
//! reruns. Blocks of compacted tables are
//! released through the free set, which reuses them only once no retained checkpoint can
//! name them. Journal replay after open writes through `put_replay`, which may use the
//! `replay_entries_max` entries that normal puts keep free. A replay can leave the mutable
//! memtable past the normal limit while a flush is pending; a checkpoint then would leave the
//! next replay less than a full reserve, so the owner checkpoints only when
//! `checkpoint_ready` (asserted by `checkpoint_encode`), driving compaction until it is.
//!
//! Static memory: two memtables, per table slot its `Info`, block addresses, and filter (none
//! for the last level), the job's buffers (`lsm_compaction.zig`), and one table reader.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const table_module = @import("table.zig");
const free_set_module = @import("free_set.zig");
const filter_module = @import("lsm_filter.zig");
const memtable_module = @import("lsm_memtable.zig");
const compaction_module = @import("lsm_compaction.zig");

const FreeSet = free_set_module.FreeSet;
const BlockCache = table_module.BlockCache;

pub const levels_max: u32 = 8;
pub const Status = enum { done, pending };
pub const ScanOutcome = enum { loaded, corrupt };
pub const Error = error{Corrupt};

/// "lsmt" read as a little-endian u32.
const checkpoint_magic: u32 = 0x746d_736c;
const checkpoint_header_size: u32 = 32 + 4 * levels_max;

pub const Config = struct {
    block_size: u32,
    /// Grid blocks (addresses `1..block_count`).
    block_count: u64,
    /// Entries one memtable holds.
    memtable_entries_max: u32,
    /// The mutable memtable swaps for flushing once it holds this many entries.
    flush_entries_min: u32,
    /// Entries normal puts leave free for journal replay after open (the most puts the
    /// journal can hold).
    replay_entries_max: u32,
    /// Records one table holds at most (compaction cuts its output here).
    table_records_max: u32,
    level0_tables_max: u32 = 4,
    levels_count: u32 = 6,
    growth_factor: u32 = 8,
    bits_per_key: u32 = 10,
};

pub const Stats = struct {
    puts: u64 = 0,
    lookups: u64 = 0,
    lookups_memtable: u64 = 0,
    /// Tables a lookup skipped on its filter, and tables it read.
    filter_negatives: u64 = 0,
    table_probes: u64 = 0,
    flushes: u64 = 0,
    merges: u64 = 0,
    blocks_read: u64 = 0,
    blocks_written: u64 = 0,
    records_written: u64 = 0,
    tombstones_dropped: u64 = 0,
    /// Steps the job waited for a free block (the grid full or reserved by another writer).
    stalls: u64 = 0,
    busy: u64 = 0,
    /// Synchronous point reads (`get`).
    gets: u64 = 0,
    /// Merges into the last level.
    merges_last: u64 = 0,
    /// Output tables a merge cut at grandparent overlap.
    cuts_overlap: u64 = 0,
    /// Blocks of an interrupted job that open released.
    orphans_released: u64 = 0,
};

pub const ValueMode = enum { fixed, variable };

/// A tree whose values are exactly `value_size` bytes.
pub fn TreeType(comptime Storage: type, comptime key_size: u32, comptime value_size: u32) type {
    return TreeShapeType(Storage, .{
        .key_size = key_size,
        .value_size = value_size,
        .mode = .fixed,
    });
}

/// A tree whose values are 1..`value_size_max` bytes.
pub fn TreeVariableType(
    comptime Storage: type,
    comptime key_size: u32,
    comptime value_size_max: u32,
) type {
    return TreeShapeType(Storage, .{
        .key_size = key_size,
        .value_size = value_size_max,
        .mode = .variable,
    });
}

const Shape = struct { key_size: u32, value_size: u32, mode: ValueMode };

fn TreeShapeType(comptime Storage: type, comptime shape: Shape) type {
    const key_size = shape.key_size;
    const value_size = shape.value_size;
    const mode = shape.mode;
    comptime assert(value_size > 0);
    comptime assert(mode == .fixed or value_size <= std.math.maxInt(u16));
    return struct {
        const Tree = @This();

        pub const variable = mode == .variable;
        pub const Table = table_module.TableType(Storage, key_size);
        pub const Grid = Table.Grid;
        pub const Key = Table.Key;
        /// Fixed: the value. Variable: room for the largest value.
        pub const Value = [value_size]u8;
        /// What a put takes: the value (fixed) or its bytes (variable, 1..`value_size`).
        pub const ValueIn = if (variable) []const u8 else *const Value;
        pub const Info = Table.Info;
        pub const Memtable = memtable_module.MemtableType(key_size, value_size, variable);
        pub const Compaction = compaction_module.CompactionType(Tree);
        pub const Callback = *const fn (*Tree) void;
        pub const info_size: u32 = @sizeOf(Info);
        pub const key_bytes = key_size;
        /// Fixed: the value size. Variable: the largest value size.
        pub const value_bytes = value_size;
        /// Checkpoint bytes of one memtable entry before its value (key and tag or length).
        pub const entry_header_size: u32 = key_size + if (variable) 2 else 1;
        /// Checkpoint bytes of one memtable entry at most.
        pub const entry_size: u32 = entry_header_size + value_size;

        pub const Layout = struct {
            /// Records a data block holds at least when values are their largest.
            records_per_block_full: u32,
            /// Records a data block holds at most (all tombstones).
            records_per_block_max: u32,
            /// Data blocks one table holds at most (compaction cuts its output here).
            data_blocks_max: u32,
            blocks_per_table: u32,
            /// Records every table of a job's output but its last holds at least (each is cut
            /// at `table_records_max` records or at `data_blocks_max` full data blocks).
            table_records_min: u32,
            capacity: [levels_max]u64,
            tables_max: [levels_max]u32,
            /// Level `l`'s table slots are `slot_base[l]..slot_base[l + 1]`.
            slot_base: [levels_max + 1]u32,
            filter_words: u32,
            /// Output tables one job may write cut by records or blocks (merges must fit).
            job_record_tables_max: u32,
            /// Output tables one job may write, also counting cuts at grandparent overlap.
            job_tables_max: u32,
            orphans_max: u32,
        };

        config: Config,
        layout: Layout,
        grid: *Grid,
        free_set: ?*FreeSet = null,
        memtables: [2]Memtable,
        mutable: u1 = 0,
        slot_infos: []Info,
        slot_used: []bool,
        /// Per slot `blocks_per_table` addresses: index block first, then data blocks.
        slot_blocks: []u64,
        /// Per slot below `slot_base[levels_count - 1]`: its filter.
        filters: []u32,
        /// Per level its slots in order (level 0 newest first, others by key).
        level_slots: []u32,
        level_count: [levels_max]u32 = @splat(0),
        level_records: [levels_max]u64 = @splat(0),
        /// Per level the key after which the next merge picks its table (round robin).
        compact_cursor: [levels_max]Key = @splat(@splat(0)),
        /// Orphans from the checkpoint open loaded, released once the scan verifies.
        orphans: []u64,
        orphan_count: u32 = 0,
        compaction: Compaction,
        reader: Table.Reader,
        /// `get`'s block buffer (one block, read synchronously) and its copy of the value.
        get_buffer: []align(storage.sector_size) u8,
        get_value: Value = undefined,
        lookup_active: bool = false,
        lookup_asynchronous: bool = false,
        lookup_key: Key = undefined,
        lookup_level: u32 = 0,
        lookup_position: u32 = 0,
        lookup_callback: ?Callback = null,
        /// The lookup's outcome: found (`lookup_value` holds the value) or absent.
        lookup_result: Error!bool = false,
        lookup_value: Value = undefined,
        /// Bytes of `lookup_value` that are the value (fixed trees: `value_size`).
        lookup_length: u32 = 0,
        scan_level: u32 = 0,
        scan_callback: ?Callback = null,
        scan_outcome: ScanOutcome = .loaded,
        /// A table block failed to verify outside open: the tree stops compacting.
        fault: bool = false,
        /// A bulk load (`lsm_bulk.zig`) is writing the last level: no compaction, no
        /// checkpoint until it finishes.
        bulk_active: bool = false,
        /// Called after a compaction job installs (the owner may wait for `checkpoint_ready`).
        install_callback: ?Callback = null,
        stats: Stats = .{},

        pub fn layout_of(config: Config) Layout {
            assert(config.levels_count >= 2 and config.levels_count <= levels_max);
            assert(config.growth_factor >= 2 and config.level0_tables_max >= 1);
            assert(config.table_records_max > 0 and config.memtable_entries_max > 0);
            assert(value_size <= Table.value_size_max(config.block_size));
            const room = Table.data_room(config.block_size);
            const full: u32 = room / (key_size + value_size + 4);
            assert(full >= if (variable) 1 else 2);
            // Every data block of a table but its last holds at least `full` records (a block
            // closes only when the next record does not fit), so `table_records_max` records
            // need at most this many blocks.
            const data_blocks_records = std.math.divCeil(u32, config.table_records_max, full) catch
                unreachable; // full > 0.
            const index_capacity = Table.index_capacity(config.block_size);
            // Fixed trees fit `table_records_max` in one index block; variable trees cut a
            // table at a full index block when their values are large.
            if (!variable) assert(data_blocks_records + 1 <= index_capacity);
            const data_blocks = @min(data_blocks_records, index_capacity - 1);
            const table_records_min = @min(config.table_records_max, data_blocks * full);
            var layout: Layout = .{
                .records_per_block_full = full,
                .records_per_block_max = room / (key_size + 4),
                .data_blocks_max = data_blocks,
                .blocks_per_table = data_blocks + 1,
                .table_records_min = table_records_min,
                .capacity = @splat(0),
                .tables_max = @splat(0),
                .slot_base = @splat(0),
                .filter_words = filter_module.word_count(
                    config.table_records_max,
                    config.bits_per_key,
                ),
                .job_record_tables_max = 0,
                .job_tables_max = 0,
                .orphans_max = 0,
            };
            layout_levels(config, &layout);
            return layout;
        }

        /// Level capacities and table counts, job output and orphan bounds.
        fn layout_levels(config: Config, layout: *Layout) void {
            assert(layout.table_records_min > 0);
            // A flush writes at most this many level-0 tables.
            const flush_tables = std.math.divCeil(
                u32,
                config.memtable_entries_max,
                layout.table_records_min,
            ) catch unreachable; // table_records_min > 0.
            const level0_records = @as(u64, config.level0_tables_max) *
                config.memtable_entries_max;
            var deep_tables_max: u32 = 0;
            for (0..config.levels_count) |level| {
                layout.capacity[level] = if (level <= 1)
                    level0_records
                else
                    layout.capacity[level - 1] * config.growth_factor;
                const records = layout.capacity[level];
                const tables = std.math.divCeil(u64, records, config.table_records_max) catch
                    unreachable; // table_records_max > 0.
                // A flush starts only below `level0_tables_max` tables.
                layout.tables_max[level] = if (level == 0)
                    config.level0_tables_max - 1 + flush_tables
                else
                    @intCast(3 * tables + 2 * config.growth_factor + 4);
                layout.slot_base[level + 1] = layout.slot_base[level] + layout.tables_max[level];
                if (level >= 2) deep_tables_max = @max(deep_tables_max, layout.tables_max[level]);
            }
            layout.job_record_tables_max = @max(
                layout.tables_max[1] + layout.tables_max[0] + 1,
                2 * config.growth_factor + 8,
            );
            // Cuts at grandparent overlap: each advances the grandparent cursor by at least
            // `growth_factor` tables (`lsm_compaction.zig` `overlap_cut`).
            const overlap_cuts = std.math.divCeil(u32, deep_tables_max, config.growth_factor) catch
                unreachable; // growth_factor >= 2.
            layout.job_tables_max = layout.job_record_tables_max + overlap_cuts + 1;
            // A job's records need at most `job_record_tables_max - 1` tables' worth of full
            // data blocks, plus per output table a partial last data block and an index block.
            layout.orphans_max = layout.job_record_tables_max * layout.data_blocks_max +
                2 * layout.job_tables_max;
            assert(layout.job_tables_max > layout.job_record_tables_max);
        }

        pub fn init(
            allocator: std.mem.Allocator,
            grid: *Grid,
            cache: *BlockCache,
            config: Config,
        ) !Tree {
            assert(config.block_size == grid.config.block_size);
            assert(config.flush_entries_min > 0);
            assert(config.flush_entries_min + config.replay_entries_max <=
                config.memtable_entries_max);
            const layout = layout_of(config);
            const slots: usize = layout.slot_base[config.levels_count];
            const filter_slots: usize = layout.slot_base[config.levels_count - 1];
            var mutable = try Memtable.init(allocator, config.memtable_entries_max);
            errdefer mutable.deinit(allocator);
            var immutable = try Memtable.init(allocator, config.memtable_entries_max);
            errdefer immutable.deinit(allocator);
            const slot_infos = try allocator.alloc(Info, slots);
            errdefer allocator.free(slot_infos);
            const slot_used = try allocator.alloc(bool, slots);
            errdefer allocator.free(slot_used);
            const slot_blocks = try allocator.alloc(u64, slots * layout.blocks_per_table);
            errdefer allocator.free(slot_blocks);
            const filters = try allocator.alloc(u32, filter_slots * layout.filter_words);
            errdefer allocator.free(filters);
            const level_slots = try allocator.alloc(u32, slots);
            errdefer allocator.free(level_slots);
            const orphans = try allocator.alloc(u64, layout.orphans_max);
            errdefer allocator.free(orphans);
            var compaction = try Compaction.init(allocator, grid, config, layout);
            errdefer compaction.deinit(allocator);
            var reader = try Table.Reader.init(allocator, grid, cache);
            errdefer reader.deinit(allocator);
            const alignment = comptime std.mem.Alignment.fromByteUnits(storage.sector_size);
            const get_buffer = try allocator.alignedAlloc(u8, alignment, config.block_size);
            @memset(get_buffer, 0);
            @memset(slot_used, false);
            @memset(slot_blocks, 0);
            @memset(filters, 0);
            return .{
                .config = config,
                .layout = layout,
                .grid = grid,
                .memtables = .{ mutable, immutable },
                .slot_infos = slot_infos,
                .slot_used = slot_used,
                .slot_blocks = slot_blocks,
                .filters = filters,
                .level_slots = level_slots,
                .orphans = orphans,
                .compaction = compaction,
                .reader = reader,
                .get_buffer = get_buffer,
            };
        }

        /// Frees memory. Grid IO may be in flight only if the storage dropped it (crash).
        pub fn deinit(self: *Tree, allocator: std.mem.Allocator) void {
            for (&self.memtables) |*memtable| memtable.deinit(allocator);
            allocator.free(self.slot_infos);
            allocator.free(self.slot_used);
            allocator.free(self.slot_blocks);
            allocator.free(self.filters);
            allocator.free(self.level_slots);
            allocator.free(self.orphans);
            self.compaction.deinit(allocator);
            self.reader.deinit(allocator);
            allocator.free(self.get_buffer);
            self.* = undefined;
        }

        /// Names the grid and free set (the owner's engine may move after `init`).
        pub fn bind(self: *Tree, grid: *Grid, free_set: *FreeSet) void {
            assert(grid.config.block_size == self.config.block_size);
            assert(free_set.block_count == self.config.block_count);
            self.grid = grid;
            self.free_set = free_set;
            self.reader.grid = grid;
            self.compaction.bind(grid);
        }

        pub fn mutable_memtable(self: *Tree) *Memtable {
            return &self.memtables[self.mutable];
        }

        pub fn immutable_memtable(self: *Tree) *Memtable {
            return &self.memtables[1 - self.mutable];
        }

        // Writes.

        /// Entries normal puts may still add before `error.Busy`.
        pub fn capacity_free(self: *Tree) u32 {
            const limit = self.config.memtable_entries_max - self.config.replay_entries_max;
            return limit -| self.mutable_memtable().count;
        }

        /// Entries `put_replay` may still add: the rest of the mutable memtable, and a whole
        /// memtable more when the immutable one is empty (the full one swaps into it).
        pub fn replay_capacity_free(self: *Tree) u32 {
            const max = self.config.memtable_entries_max;
            assert(self.mutable_memtable().count <= max);
            const free = max - self.mutable_memtable().count;
            if (self.immutable_memtable().count > 0) return free;
            return free + max;
        }

        /// Whether a value of `length` bytes is valid for this tree (0, a tombstone, is not).
        pub fn value_length_valid(length: usize) bool {
            if (variable) return length >= 1 and length <= value_size;
            return length == value_size;
        }

        fn value_slice(value: ?ValueIn) ?[]const u8 {
            const bytes: []const u8 = value orelse return null;
            assert(value_length_valid(bytes.len));
            return bytes;
        }

        /// Writes `key` (a delete when `value` is null). `error.Busy`: the memtable is full;
        /// keep calling `compact` and retry.
        pub fn put(self: *Tree, key: *const Key, value: ?ValueIn) error{Busy}!void {
            assert(self.scan_callback == null);
            if (self.capacity_free() == 0) {
                self.stats.busy += 1;
                return error.Busy;
            }
            try self.mutable_memtable().put(key, value_slice(value));
            self.stats.puts += 1;
        }

        /// A put during journal replay: may use the replay reserve.
        pub fn put_replay(self: *Tree, key: *const Key, value: ?ValueIn) error{Busy}!void {
            assert(self.scan_callback == null);
            assert(!self.compaction.active);
            if (self.mutable_memtable().count == self.config.memtable_entries_max and
                self.immutable_memtable().count == 0) _ = self.swap();
            try self.mutable_memtable().put(key, value_slice(value));
            self.stats.puts += 1;
        }

        /// Makes the mutable memtable immutable (sorted, pending flush) if the immutable one
        /// is empty and the mutable one is not. Returns whether it swapped.
        pub fn swap(self: *Tree) bool {
            if (self.immutable_memtable().count > 0) return false;
            if (self.mutable_memtable().count == 0) return false;
            self.mutable = 1 - self.mutable;
            self.immutable_memtable().sort();
            assert(self.mutable_memtable().count == 0);
            return true;
        }

        /// One commit's compaction: grants `blocks` grid block reads and writes (unused grants
        /// are dropped at the next call), swapping memtables when the mutable one is due.
        pub fn compact(self: *Tree, blocks: u64) void {
            assert(blocks > 0);
            assert(self.free_set != null);
            assert(!self.bulk_active);
            if (self.mutable_memtable().count >= self.config.flush_entries_min) _ = self.swap();
            if (self.fault) return;
            self.compaction.grant(blocks);
        }

        /// No job running and nothing pending flush.
        pub fn compaction_idle(self: *Tree) bool {
            return !self.compaction.active and self.immutable_memtable().count == 0;
        }

        // Lookup.

        /// The memtable entry for `key`: mutable first, then immutable.
        fn memtable_find(self: *Tree, key: *const Key) ?struct { *Memtable, u32 } {
            const mutable = self.mutable_memtable();
            if (mutable.find(key)) |entry| return .{ mutable, entry };
            const immutable = self.immutable_memtable();
            if (immutable.count == 0) return null;
            if (immutable.find(key)) |entry| return .{ immutable, entry };
            return null;
        }

        /// The value the last lookup found (valid when `lookup_result` is true).
        pub fn lookup_bytes(self: *const Tree) []const u8 {
            assert(self.lookup_length <= value_size);
            return self.lookup_value[0..self.lookup_length];
        }

        fn lookup_set(self: *Tree, value: []const u8) void {
            assert(value.len <= value_size);
            @memcpy(self.lookup_value[0..value.len], value);
            self.lookup_length = @intCast(value.len);
        }

        /// Finds `key`. On `.done` (or in the callback after `.pending`) `lookup_result` says
        /// whether it is present, and `lookup_bytes` (or `lookup_value`) holds its value. One
        /// lookup at a time.
        pub fn lookup(self: *Tree, key: *const Key, callback: Callback) Status {
            assert(!self.lookup_active);
            assert(self.scan_callback == null);
            self.stats.lookups += 1;
            if (self.memtable_find(key)) |found| {
                const memtable, const entry = found;
                self.stats.lookups_memtable += 1;
                self.lookup_result = !memtable.tombstones[entry];
                self.lookup_set(memtable.value(entry));
                return .done;
            }
            if (self.fault) {
                self.lookup_result = error.Corrupt;
                return .done;
            }
            self.lookup_active = true;
            self.lookup_asynchronous = false;
            self.lookup_key = key.*;
            self.lookup_level = 0;
            self.lookup_position = 0;
            self.lookup_callback = callback;
            return self.lookup_advance();
        }

        /// The next table that may hold the lookup key, or null when none is left.
        fn lookup_candidate(self: *Tree) ?u32 {
            var steps: u32 = 0;
            // Bounded: every level-0 table once, then one step per deeper level.
            while (steps <= self.layout.tables_max[0] + levels_max) : (steps += 1) {
                const level = self.lookup_level;
                if (level == self.config.levels_count) return null;
                const slots = self.level_list(level);
                if (level == 0) {
                    if (self.lookup_position < slots.len) {
                        self.lookup_position += 1;
                        const slot = slots[self.lookup_position - 1];
                        if (self.in_range(slot, &self.lookup_key)) return slot;
                        continue;
                    }
                } else if (self.lookup_position == 0) {
                    self.lookup_position = 1;
                    if (self.level_find(level, &self.lookup_key)) |slot| return slot;
                }
                self.lookup_level += 1;
                self.lookup_position = 0;
            }
            unreachable; // The bound covers every candidate.
        }

        fn lookup_advance(self: *Tree) Status {
            assert(self.lookup_active);
            var steps: u32 = 0;
            while (steps <= self.layout.tables_max[0] + levels_max) : (steps += 1) {
                const slot = self.lookup_candidate() orelse return self.lookup_complete(false);
                if (self.slot_filter(slot)) |words| {
                    if (!filter_module.may_contain(words, filter_module.hash(&self.lookup_key))) {
                        self.stats.filter_negatives += 1;
                        continue;
                    }
                }
                self.stats.table_probes += 1;
                const info = &self.slot_infos[slot];
                switch (self.reader.lookup(info, &self.lookup_key, on_reader)) {
                    .pending => {
                        self.lookup_asynchronous = true;
                        return .pending;
                    },
                    .done => if (self.lookup_found()) |found| return self.lookup_complete(found),
                }
            }
            unreachable; // `lookup_candidate` runs out first.
        }

        /// The reader's outcome: present, a tombstone, or null to keep looking.
        fn lookup_found(self: *Tree) ?Error!bool {
            self.reader.result catch return error.Corrupt;
            const value = self.reader.value orelse return null;
            if (value.len == 0) return false;
            if (!value_length_valid(value.len)) return error.Corrupt;
            self.lookup_set(value);
            return true;
        }

        fn on_reader(reader: *Table.Reader) void {
            const self: *Tree = @alignCast(@fieldParentPtr("reader", reader));
            assert(self.lookup_active);
            if (self.lookup_found()) |found| {
                _ = self.lookup_complete(found);
                return;
            }
            _ = self.lookup_advance();
        }

        fn lookup_complete(self: *Tree, result: Error!bool) Status {
            assert(self.lookup_active);
            self.lookup_result = result;
            if (result) |_| {} else |_| self.fault = true;
            self.lookup_active = false;
            const callback = self.lookup_callback.?;
            self.lookup_callback = null;
            // A job finished while the lookup read its tables: install it now, before the
            // callback can start another lookup.
            self.compaction.lookup_done();
            if (self.lookup_asynchronous) callback(self);
            return .done;
        }

        // Synchronous point read.

        /// What one table holds for a key: a value or a tombstone (null: neither).
        const Probe = union(enum) { tombstone, value: []const u8 };

        /// Reads `key` at once (no callback, no tick): its value, or null when absent. Same
        /// search as `lookup` (memtables, then level 0 newest first, then one table per deeper
        /// level, filters first), but table blocks come from the block cache or a blocking
        /// grid read (`Grid.read_sync`). The value stays valid until the next `get`. A block
        /// that fails to verify returns `error.Corrupt` and faults the tree, as a lookup does
        /// (sticky: later reads past the memtables return `error.Corrupt` too). Manifest
        /// changes (job installs) run only from callbacks, so none happens during a call.
        pub fn get(self: *Tree, key: *const Key) Error!?[]const u8 {
            assert(self.scan_callback == null);
            self.stats.gets += 1;
            if (self.memtable_find(key)) |found| {
                const memtable, const entry = found;
                if (memtable.tombstones[entry]) return null;
                return self.get_copy(memtable.value(entry));
            }
            if (self.fault) return error.Corrupt;
            for (self.level_list(0)) |slot| {
                if (!self.in_range(slot, key)) continue;
                const probe = try self.get_table(slot, key) orelse continue;
                return switch (probe) {
                    .tombstone => null,
                    .value => |value| value,
                };
            }
            var level: u32 = 1;
            while (level < self.config.levels_count) : (level += 1) {
                const slot = self.level_find(level, key) orelse continue;
                const probe = try self.get_table(slot, key) orelse continue;
                return switch (probe) {
                    .tombstone => null,
                    .value => |value| value,
                };
            }
            return null;
        }

        fn get_copy(self: *Tree, value: []const u8) []const u8 {
            assert(value_length_valid(value.len));
            @memcpy(self.get_value[0..value.len], value);
            return self.get_value[0..value.len];
        }

        fn get_table(self: *Tree, slot: u32, key: *const Key) Error!?Probe {
            assert(self.slot_used[slot]);
            if (self.slot_filter(slot)) |words| {
                if (!filter_module.may_contain(words, filter_module.hash(key))) {
                    self.stats.filter_negatives += 1;
                    return null;
                }
            }
            self.stats.table_probes += 1;
            const info = &self.slot_infos[slot];
            const index = try self.get_block(info.index, .table_index);
            const ordinal = Table.index_find(index, key) orelse return null;
            // Taken before the data block's cache put can evict the index block.
            const reference = Table.index_reference(index, ordinal);
            const data = try self.get_block(reference, .table_data);
            const value = Table.data_search(data, key) orelse return null;
            if (value.len == 0) return .tombstone;
            if (!value_length_valid(value.len)) return self.get_fault();
            return .{ .value = self.get_copy(value) };
        }

        /// The verified payload of a table block: cached, or read at once and cached.
        fn get_block(
            self: *Tree,
            reference: grid_module.Reference,
            kind: grid_module.BlockKind,
        ) Error![]const u8 {
            const cache = self.reader.cache;
            const block = cache.get(reference) orelse block: {
                const payload = self.grid.read_sync(self.get_buffer, reference, kind) orelse
                    return self.get_fault();
                const valid = switch (kind) {
                    .table_index => Table.index_valid(payload, self.grid.config.block_count),
                    .table_data => Table.data_valid(payload),
                    _ => false,
                };
                if (!valid) return self.get_fault();
                const length = grid_module.block_header_size + payload.len;
                break :block cache.put(reference, self.get_buffer[0..length]);
            };
            const header: *const grid_module.BlockHeader = @ptrCast(@alignCast(
                block[0..grid_module.block_header_size],
            ));
            assert(header.address == reference.address);
            return block[grid_module.block_header_size..][0..header.payload_size];
        }

        fn get_fault(self: *Tree) error{Corrupt} {
            self.fault = true;
            return error.Corrupt;
        }

        // Levels and table slots.

        pub fn level_list(self: *const Tree, level: u32) []u32 {
            assert(level < self.config.levels_count);
            return self.level_slots[self.layout.slot_base[level]..][0..self.level_count[level]];
        }

        pub fn slot_filter(self: *const Tree, slot: u32) ?[]u32 {
            if (slot >= self.layout.slot_base[self.config.levels_count - 1]) return null;
            const words = self.layout.filter_words;
            return self.filters[@as(usize, slot) * words ..][0..words];
        }

        pub fn table_blocks(self: *const Tree, slot: u32) []u64 {
            const count = self.slot_infos[slot].data_block_count + 1;
            assert(count <= self.layout.blocks_per_table);
            return self.slot_blocks[@as(usize, slot) * self.layout.blocks_per_table ..][0..count];
        }

        fn in_range(self: *const Tree, slot: u32, key: *const Key) bool {
            const info = &self.slot_infos[slot];
            return Table.key_order(key, &info.key_min) != .lt and
                Table.key_order(key, &info.key_max) != .gt;
        }

        /// The table of a level >= 1 whose range holds `key`, or null.
        fn level_find(self: *const Tree, level: u32, key: *const Key) ?u32 {
            assert(level >= 1);
            const slots = self.level_list(level);
            var low: usize = 0;
            var high: usize = slots.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const order = Table.key_order(&self.slot_infos[slots[middle]].key_min, key);
                if (order == .gt) high = middle else low = middle + 1;
            }
            if (low == 0) return null;
            const slot = slots[low - 1];
            return if (self.in_range(slot, key)) slot else null;
        }

        /// The first position and count of level `level`'s tables overlapping the range.
        pub fn level_overlap(
            self: *const Tree,
            level: u32,
            key_min: *const Key,
            key_max: *const Key,
        ) struct { u32, u32 } {
            assert(level >= 1);
            assert(Table.key_order(key_min, key_max) != .gt);
            const slots = self.level_list(level);
            var first: u32 = 0;
            while (first < slots.len) : (first += 1) {
                const info = &self.slot_infos[slots[first]];
                if (Table.key_order(&info.key_max, key_min) != .lt) break;
            }
            var end = first;
            while (end < slots.len) : (end += 1) {
                const info = &self.slot_infos[slots[end]];
                if (Table.key_order(&info.key_min, key_max) == .gt) break;
            }
            return .{ first, end - first };
        }

        /// A free slot of `level` (now used).
        pub fn slot_acquire(self: *Tree, level: u32) u32 {
            const base = self.layout.slot_base[level];
            const end = self.layout.slot_base[level + 1];
            var slot = base;
            while (slot < end) : (slot += 1) {
                if (!self.slot_used[slot]) break;
            } else unreachable; // Callers check the level's room first.
            self.slot_used[slot] = true;
            if (self.slot_filter(slot)) |words| @memset(words, 0);
            return slot;
        }

        /// Adds a written table to its level (level 0 at the front, others by key).
        pub fn level_insert(self: *Tree, level: u32, slot: u32) void {
            assert(self.slot_used[slot]);
            assert(self.level_count[level] < self.layout.tables_max[level]);
            const info = &self.slot_infos[slot];
            const base = self.layout.slot_base[level];
            const slots = self.level_slots[base..][0 .. self.level_count[level] + 1];
            var position: usize = 0;
            const last = if (slots.len > 1) &self.slot_infos[slots[slots.len - 2]] else null;
            if (level > 0 and last != null and
                Table.key_order(&last.?.key_min, &info.key_min) == .lt)
            {
                // Appending past the level's last table (a bulk load): no search.
                position = slots.len - 1;
            } else if (level > 0) {
                while (position + 1 < slots.len) : (position += 1) {
                    const other = &self.slot_infos[slots[position]];
                    if (Table.key_order(&other.key_min, &info.key_min) == .gt) break;
                }
            }
            std.mem.copyBackwards(u32, slots[position + 1 ..], slots[position .. slots.len - 1]);
            slots[position] = slot;
            self.level_count[level] += 1;
            self.level_records[level] += info.record_count;
        }

        /// Removes a table from its level and frees its slot; releases its blocks when asked.
        pub fn level_remove(self: *Tree, level: u32, slot: u32, release: bool) void {
            const slots = self.level_list(level);
            const position = std.mem.indexOfScalar(u32, slots, slot).?;
            std.mem.copyForwards(u32, slots[position .. slots.len - 1], slots[position + 1 ..]);
            self.level_count[level] -= 1;
            self.level_records[level] -= self.slot_infos[slot].record_count;
            if (release) {
                const blocks = self.table_blocks(slot);
                // The block list is known: written, scanned, or read by the job removing it.
                assert(blocks[0] == self.slot_infos[slot].index.address);
                for (blocks) |address| self.free_set.?.release(address);
            }
            self.slot_used[slot] = false;
            assert(self.level_list(level).len == slots.len - 1);
        }

        /// Empty tree: no tables, empty memtables (a fresh database, or before a load).
        pub fn reset(self: *Tree) void {
            assert(!self.compaction.active and !self.lookup_active);
            for (&self.memtables) |*memtable| memtable.reset();
            @memset(self.slot_used, false);
            self.level_count = @splat(0);
            self.level_records = @splat(0);
            self.compact_cursor = @splat(@splat(0));
            self.orphan_count = 0;
            self.fault = false;
            assert(!self.bulk_active);
        }

        // Checkpoint: header, level counts, tables, memtable entries, orphans.

        /// True when a checkpoint now leaves the next replay `replay_entries_max` free entries:
        /// the immutable memtable is empty (replay can swap into a whole memtable), or the
        /// mutable one is within the normal-put limit. False only after a replay that filled
        /// into the reserve while a flush was pending, until that flush installs. A faulted
        /// tree no longer compacts, so it never becomes ready: checkpoints go ahead as is.
        pub fn checkpoint_ready(self: *Tree) bool {
            const limit = self.config.memtable_entries_max - self.config.replay_entries_max;
            assert(self.mutable_memtable().count <= self.config.memtable_entries_max);
            if (self.fault) return true;
            if (self.immutable_memtable().count == 0) return true;
            return self.mutable_memtable().count <= limit;
        }

        pub fn checkpoint_size_max(self: *const Tree) u32 {
            return checkpoint_size_of(self.config, &self.layout);
        }

        /// `checkpoint_size_max` of a tree with `config`, without building it (sizing).
        pub fn checkpoint_size_max_of(config: Config) u32 {
            const layout = layout_of(config);
            return checkpoint_size_of(config, &layout);
        }

        fn checkpoint_size_of(config: Config, layout: *const Layout) u32 {
            const slots = layout.slot_base[config.levels_count];
            assert(slots > 0);
            return checkpoint_header_size + slots * info_size +
                2 * config.memtable_entries_max * entry_size + layout.orphans_max * 8;
        }

        /// Checkpoint bytes of a memtable's entries.
        fn entries_size(memtable: *const Memtable) u32 {
            if (!variable) return memtable.count * entry_size;
            const size = memtable.count * entry_header_size + memtable.value_bytes_total;
            assert(size <= memtable.count * entry_size);
            return @intCast(size);
        }

        pub fn checkpoint_size(self: *Tree) u32 {
            var tables: u32 = 0;
            for (self.level_count) |count| tables += count;
            const orphans: u32 = @intCast(self.compaction.orphans().len);
            const entries_bytes = entries_size(&self.memtables[0]) +
                entries_size(&self.memtables[1]);
            const size = checkpoint_header_size + tables * info_size + entries_bytes + orphans * 8;
            assert(size <= self.checkpoint_size_max());
            return size;
        }

        /// Writes the tree's checkpoint bytes (call at the engine checkpoint's snapshot point:
        /// right before `checkpoint`, with no tick between). Returns their length.
        pub fn checkpoint_encode(self: *Tree, out: []u8) u32 {
            assert(self.scan_callback == null);
            assert(!self.bulk_active);
            assert(self.checkpoint_ready());
            const size = self.checkpoint_size();
            assert(out.len >= size);
            const orphans = self.compaction.orphans();
            @memset(out[0..checkpoint_header_size], 0);
            write_u32(out, 0, checkpoint_magic);
            write_u32(out, 4, self.config.levels_count);
            write_u32(out, 8, self.immutable_memtable().count);
            write_u32(out, 12, self.mutable_memtable().count);
            write_u32(out, 16, @intCast(orphans.len));
            for (self.level_count, 0..) |count, level| write_u32(out, 32 + 4 * level, count);
            var offset: usize = checkpoint_header_size;
            for (0..self.config.levels_count) |level| {
                for (self.level_list(@intCast(level))) |slot| {
                    @memcpy(out[offset..][0..info_size], std.mem.asBytes(&self.slot_infos[slot]));
                    offset += info_size;
                }
            }
            for ([_]*Memtable{ self.immutable_memtable(), self.mutable_memtable() }) |memtable| {
                offset += encode_entries(memtable, out[offset..]);
            }
            for (orphans) |address| {
                std.mem.writeInt(u64, out[offset..][0..8], address, .little);
                offset += 8;
            }
            assert(offset == size);
            return size;
        }

        /// Writes a memtable's entries; returns their length.
        fn encode_entries(memtable: *const Memtable, out: []u8) usize {
            var offset: usize = 0;
            var entry: u32 = 0;
            while (entry < memtable.count) : (entry += 1) {
                const header = out[offset..][0..entry_header_size];
                @memcpy(header[0..key_size], &memtable.keys[entry]);
                const body = out[offset + entry_header_size ..];
                if (variable) {
                    const value = memtable.value(entry);
                    std.mem.writeInt(u16, header[key_size..][0..2], @intCast(value.len), .little);
                    @memcpy(body[0..value.len], value);
                    offset += entry_header_size + value.len;
                } else {
                    // Tombstones carry zeros (the memtable zeroes their values).
                    header[key_size] = @intFromBool(memtable.tombstones[entry]);
                    @memcpy(body[0..value_size], &memtable.values[entry]);
                    offset += entry_size;
                }
            }
            assert(offset == entries_size(memtable));
            return offset;
        }

        /// Loads checkpoint bytes into an empty tree (empty bytes: the empty tree). Checks the
        /// structure only; `open_scan` then reads and verifies the tables above the last level.
        pub fn open_decode(self: *Tree, bytes: []const u8) error{InvalidCheckpoint}!void {
            assert(!self.compaction.active and !self.lookup_active);
            self.reset();
            if (bytes.len == 0) return;
            self.decode(bytes) catch {
                self.reset();
                return error.InvalidCheckpoint;
            };
        }

        fn decode(self: *Tree, bytes: []const u8) error{InvalidCheckpoint}!void {
            if (bytes.len < checkpoint_header_size) return error.InvalidCheckpoint;
            if (read_u32(bytes, 0) != checkpoint_magic) return error.InvalidCheckpoint;
            if (read_u32(bytes, 4) != self.config.levels_count) return error.InvalidCheckpoint;
            for ([_]usize{ 20, 24, 28 }) |offset| {
                if (read_u32(bytes, offset) != 0) return error.InvalidCheckpoint;
            }
            const entries_old = read_u32(bytes, 8);
            const entries_new = read_u32(bytes, 12);
            const orphans = read_u32(bytes, 16);
            const capacity = self.config.memtable_entries_max;
            if (entries_old > capacity or entries_new > capacity) return error.InvalidCheckpoint;
            if (orphans > self.layout.orphans_max) return error.InvalidCheckpoint;
            var tables: u64 = 0;
            for (0..levels_max) |level| {
                const count = read_u32(bytes, 32 + 4 * level);
                const used = level < self.config.levels_count;
                const limit = if (used) self.layout.tables_max[level] else 0;
                if (count > limit) return error.InvalidCheckpoint;
                tables += count;
            }
            // Everything but the entries; fixed entries have a known size too.
            const size_fixed = checkpoint_header_size + tables * info_size + @as(u64, orphans) * 8;
            const entries = @as(u64, entries_old) + entries_new;
            if (bytes.len < size_fixed + entries * entry_header_size) {
                return error.InvalidCheckpoint;
            }
            if (bytes.len > size_fixed + entries * entry_size) return error.InvalidCheckpoint;
            var offset: usize = checkpoint_header_size;
            for (0..self.config.levels_count) |level| {
                const count = read_u32(bytes, 32 + 4 * level);
                try self.decode_level(@intCast(level), bytes[offset..][0 .. count * info_size]);
                offset += count * info_size;
            }
            const entries_end = bytes.len - @as(usize, orphans) * 8;
            const memtable_old = self.immutable_memtable();
            offset += try decode_entries(memtable_old, bytes[offset..entries_end], entries_old);
            const memtable_new = self.mutable_memtable();
            offset += try decode_entries(memtable_new, bytes[offset..entries_end], entries_new);
            if (offset != entries_end) return error.InvalidCheckpoint;
            memtable_old.sort();
            for (self.orphans[0..orphans]) |*address| {
                address.* = std.mem.readInt(u64, bytes[offset..][0..8], .little);
                offset += 8;
                if (address.* == 0 or address.* > self.config.block_count) {
                    return error.InvalidCheckpoint;
                }
            }
            self.orphan_count = orphans;
            assert(offset == bytes.len);
        }

        /// One level's tables, in checkpoint order (level 0 newest first, others by key).
        fn decode_level(self: *Tree, level: u32, bytes: []const u8) error{InvalidCheckpoint}!void {
            assert(bytes.len % info_size == 0);
            const count: u32 = @intCast(bytes.len / info_size);
            var index: u32 = 0;
            while (index < count) : (index += 1) {
                // Level 0 inserts at the front: insert oldest first.
                const ordinal = if (level == 0) count - 1 - index else index;
                var table_info: Info = undefined;
                @memcpy(std.mem.asBytes(&table_info), bytes[ordinal * info_size ..][0..info_size]);
                if (!self.info_valid(&table_info)) return error.InvalidCheckpoint;
                if (level > 0 and index > 0) {
                    const previous = self.level_list(level)[index - 1];
                    const previous_max = &self.slot_infos[previous].key_max;
                    const order = Table.key_order(previous_max, &table_info.key_min);
                    if (order != .lt) return error.InvalidCheckpoint;
                }
                const slot = self.slot_acquire(level);
                self.slot_infos[slot] = table_info;
                // Unknown until its index block is read (scan or merge): see `level_remove`.
                @memset(self.table_blocks(slot), 0);
                self.level_insert(level, slot);
            }
            assert(self.level_count[level] == count);
        }

        /// Decodes `count` entries from the front of `bytes`; returns the bytes they took.
        fn decode_entries(
            memtable: *Memtable,
            bytes: []const u8,
            count: u32,
        ) error{InvalidCheckpoint}!usize {
            assert(memtable.count == 0);
            assert(count <= memtable.capacity());
            var offset: usize = 0;
            var index: u32 = 0;
            while (index < count) : (index += 1) {
                if (bytes.len - offset < entry_header_size) return error.InvalidCheckpoint;
                const header = bytes[offset..][0..entry_header_size];
                const key = header[0..key_size];
                var tombstone: bool = undefined;
                var length: usize = value_size;
                if (variable) {
                    length = std.mem.readInt(u16, header[key_size..][0..2], .little);
                    if (length > value_size) return error.InvalidCheckpoint;
                    tombstone = length == 0;
                } else {
                    if (header[key_size] > 1) return error.InvalidCheckpoint;
                    tombstone = header[key_size] == 1;
                }
                if (bytes.len - offset - entry_header_size < length) return error.InvalidCheckpoint;
                const value = bytes[offset + entry_header_size ..][0..length];
                // Fixed tombstones carry zeros, so every decoded entry re-encodes the same.
                if (!variable and tombstone and !std.mem.allEqual(u8, value, 0)) {
                    return error.InvalidCheckpoint;
                }
                offset += entry_header_size + length;
                const before = memtable.count;
                memtable.put(key, if (tombstone) null else value) catch unreachable; // Counted.
                // A key appears at most once per memtable.
                if (memtable.count != before + 1) return error.InvalidCheckpoint;
            }
            assert(offset <= bytes.len);
            return offset;
        }

        fn info_valid(self: *const Tree, table_info: *const Info) bool {
            const address = table_info.index.address;
            if (address == 0 or address > self.config.block_count) return false;
            if (table_info.index.reserved != 0 or table_info.reserved != 0) return false;
            if (table_info.data_block_count == 0) return false;
            if (table_info.data_block_count >= self.layout.blocks_per_table) return false;
            if (table_info.record_count < table_info.data_block_count) return false;
            if (table_info.record_count > self.config.table_records_max) return false;
            return Table.key_order(&table_info.key_min, &table_info.key_max) != .gt;
        }

        // Open scan: read and verify the tables above the last level, rebuild filters, release
        // orphans.

        /// Reads every table `open_decode` loaded above the last level (block checks, every
        /// block acquired and not released in the loaded free set), rebuilds the filters, then
        /// releases the orphans. Last-level tables are not read (a restart over hundreds of GB
        /// must not read them all): a rotted one is found by the first read of its block, which
        /// reports `error.Corrupt` and faults the tree; their block lists (`table_blocks`) are
        /// filled by the merge that reads them before it releases them.
        /// The callback fires with `scan_outcome` (at once when there is nothing to read). On
        /// `.corrupt` the caller resumes the engine as corrupt (fallback).
        pub fn open_scan(self: *Tree, callback: Callback) void {
            assert(self.free_set != null);
            assert(self.scan_callback == null and !self.compaction.active);
            self.scan_callback = callback;
            self.scan_level = 0;
            self.scan_pump();
        }

        fn scan_pump(self: *Tree) void {
            const walker = &self.compaction.walkers[0];
            var steps: u32 = 0;
            // Bounded: one pass per level; each data block's records are visited at once.
            while (steps <= levels_max) : (steps += 1) {
                if (walker.slots.len == 0 or walker.done()) {
                    if (walker.slots.len > 0) self.scan_level += 1;
                    while (self.scan_level < self.scan_end() and
                        self.level_count[self.scan_level] == 0) self.scan_level += 1;
                    if (self.scan_level == self.scan_end()) return self.scan_finish();
                    walker.start(self, self.level_list(self.scan_level));
                }
                var record_steps: u64 = 0;
                while (walker.peek()) |record| : (record_steps += 1) {
                    assert(record_steps < self.layout.records_per_block_max);
                    const slot = walker.slots[walker.table];
                    if (self.slot_filter(slot)) |words| {
                        filter_module.insert(words, filter_module.hash(record.key));
                    }
                    walker.advance();
                    if (!walker.data_loaded) break;
                }
                if (walker.done()) continue;
                if (walker.data_loaded) continue;
                return walker.fetch(on_scan_read);
            }
            unreachable; // Every level is reached within the bound.
        }

        /// The scan stops above the last level: it holds most of the data and has no filter
        /// to rebuild, and its blocks are verified when read (`get`, `lookup`, merges).
        fn scan_end(self: *const Tree) u32 {
            assert(self.config.levels_count >= 2);
            return self.config.levels_count - 1;
        }

        fn on_scan_read(walker: *Compaction.Walker) void {
            const self = walker.tree;
            assert(self.scan_callback != null);
            if (!walker.ok) {
                self.scan_outcome = .corrupt;
                return self.scan_done();
            }
            self.scan_pump();
        }

        fn scan_finish(self: *Tree) void {
            const free_set = self.free_set.?;
            self.scan_outcome = .loaded;
            for (self.orphans[0..self.orphan_count]) |address| {
                if (!free_set.is_acquired(address) or free_set.is_released(address)) {
                    self.scan_outcome = .corrupt;
                    break;
                }
                free_set.release(address);
                self.stats.orphans_released += 1;
            }
            self.orphan_count = 0;
            self.scan_done();
        }

        fn scan_done(self: *Tree) void {
            self.compaction.walkers[0].slots = &.{};
            const callback = self.scan_callback.?;
            self.scan_callback = null;
            callback(self);
        }
    };
}

fn read_u32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn write_u32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

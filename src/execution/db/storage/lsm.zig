//! LSM tree over the grid: fixed-size keys and values, the primitive for flat state (disk state
//! phase 2). One tree per key space: hashed accounts (32-byte keys) and hashed storage slots
//! (64-byte keys, account hash ++ slot hash).
//!
//! Shape (leveled, TigerBeetle/RocksDB style):
//! - Two static memtables (`lsm_memtable.zig`): writes go to the mutable one; once it holds
//!   `flush_entries_min` entries and the other is empty, they swap and the full one becomes
//!   immutable, sorted once, and is flushed into a new level-0 table. A put into a full
//!   mutable memtable fails with `error.Busy` (backpressure, as the journal does); nothing is
//!   allocated after `init`.
//! - Level 0 holds up to `level0_tables_max` tables that may overlap (newest first). Levels
//!   1.. hold disjoint tables sorted by key; level i holds about `capacity[i]` records, level
//!   1 as much as a full level 0 and each next level `growth_factor` times more.
//! - Tables are `table.zig` tables. A record's value is `value_size` bytes, or empty for a
//!   tombstone (a delete). Compaction drops shadowed versions and drops tombstones once no
//!   deeper level can hold the key.
//! - Point lookup: mutable, immutable, then each level-0 table newest first, then the one
//!   table per deeper level whose key range (fence keys `key_min`/`key_max`) holds the key.
//!   Every level but the last has a split-block Bloom filter per table (`lsm_filter.zig`),
//!   resident in RAM, so a lookup of an absent key reads at most the last level's block
//!   (Monkey: most records live in the last level, where a filter costs the most).
//!
//! Compaction (`lsm_compaction.zig`) runs one job at a time (a memtable flush or a level
//! merge), paced by `compact(blocks)`: each call (one per durable commit) grants a fixed
//! number of grid block reads and writes, and unused grants do not accumulate. So compaction
//! IO per commit is bounded and is a pure function of the commit sequence (DST).
//!
//! Checkpoint (`checkpoint_encode`, in the caller's checkpoint bytes): the table list per
//! level (the manifest), both memtables (the immutable one only while its flush is pending),
//! and the blocks the running job acquired ("orphans"). A checkpoint may start at any time:
//! the job's inputs are still in the manifest and its outputs are not, so open (`open_decode`
//! + `open_scan`) releases the orphans and the job reruns. Blocks of compacted tables are
//! released through the free set, which reuses them only once no retained checkpoint can
//! name them. Journal replay after open writes through `put_replay`, which may use the
//! `replay_entries_max` entries that normal puts keep free.
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
    /// Blocks of an interrupted job that open released.
    orphans_released: u64 = 0,
};

pub fn TreeType(comptime Storage: type, comptime key_size: u32, comptime value_size: u32) type {
    return struct {
        const Tree = @This();

        pub const Table = table_module.TableType(Storage, key_size);
        pub const Grid = Table.Grid;
        pub const Key = Table.Key;
        pub const Value = [value_size]u8;
        pub const Info = Table.Info;
        pub const Memtable = memtable_module.MemtableType(key_size, value_size);
        pub const Compaction = compaction_module.CompactionType(Tree);
        pub const Callback = *const fn (*Tree) void;
        pub const info_size: u32 = @sizeOf(Info);
        pub const key_bytes = key_size;
        pub const value_bytes = value_size;
        pub const entry_size: u32 = key_size + 1 + value_size;

        pub const Layout = struct {
            records_per_block_full: u32,
            /// Records a data block holds at most (all tombstones).
            records_per_block_max: u32,
            blocks_per_table: u32,
            capacity: [levels_max]u64,
            tables_max: [levels_max]u32,
            /// Level `l`'s table slots are `slot_base[l]..slot_base[l + 1]`.
            slot_base: [levels_max + 1]u32,
            filter_words: u32,
            /// Output tables one job may write.
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
        lookup_active: bool = false,
        lookup_asynchronous: bool = false,
        lookup_key: Key = undefined,
        lookup_level: u32 = 0,
        lookup_position: u32 = 0,
        lookup_callback: ?Callback = null,
        /// The lookup's outcome: found (`lookup_value` holds the value) or absent.
        lookup_result: Error!bool = false,
        lookup_value: Value = undefined,
        scan_level: u32 = 0,
        scan_callback: ?Callback = null,
        scan_outcome: ScanOutcome = .loaded,
        /// A table block failed to verify outside open: the tree stops compacting.
        fault: bool = false,
        stats: Stats = .{},

        pub fn layout_of(config: Config) Layout {
            assert(config.levels_count >= 2 and config.levels_count <= levels_max);
            assert(config.growth_factor >= 2 and config.level0_tables_max >= 1);
            const room = grid_module.payload_capacity_of(config.block_size) - 8;
            const full: u32 = room / (key_size + value_size + 4);
            assert(full >= 2);
            const data_blocks = std.math.divCeil(u32, config.table_records_max, full) catch
                unreachable; // full > 0.
            assert(data_blocks + 1 <= Table.index_capacity(config.block_size));
            var layout: Layout = .{
                .records_per_block_full = full,
                .records_per_block_max = room / (key_size + 4),
                .blocks_per_table = data_blocks + 1,
                .capacity = @splat(0),
                .tables_max = @splat(0),
                .slot_base = @splat(0),
                .filter_words = filter_module.word_count(
                    config.table_records_max,
                    config.bits_per_key,
                ),
                .job_tables_max = 0,
                .orphans_max = 0,
            };
            const level0_records = @as(u64, config.level0_tables_max) *
                config.memtable_entries_max;
            for (0..config.levels_count) |level| {
                layout.capacity[level] = if (level <= 1)
                    level0_records
                else
                    layout.capacity[level - 1] * config.growth_factor;
                const records = layout.capacity[level];
                const tables = std.math.divCeil(u64, records, config.table_records_max) catch
                    unreachable; // table_records_max > 0.
                layout.tables_max[level] = if (level == 0)
                    config.level0_tables_max
                else
                    @intCast(3 * tables + 2 * config.growth_factor + 4);
                layout.slot_base[level + 1] = layout.slot_base[level] + layout.tables_max[level];
            }
            layout.job_tables_max = @max(
                layout.tables_max[1] + config.level0_tables_max + 1,
                2 * config.growth_factor + 8,
            );
            layout.orphans_max = layout.job_tables_max * layout.blocks_per_table;
            return layout;
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
            assert(config.memtable_entries_max <= config.table_records_max);
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
            const reader = try Table.Reader.init(allocator, grid, cache);
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

        /// Writes `key` (a delete when `value` is null). `error.Busy`: the memtable is full;
        /// keep calling `compact` and retry.
        pub fn put(self: *Tree, key: *const Key, value: ?*const Value) error{Busy}!void {
            assert(self.scan_callback == null);
            if (self.capacity_free() == 0) {
                self.stats.busy += 1;
                return error.Busy;
            }
            try self.mutable_memtable().put(key, value);
            self.stats.puts += 1;
        }

        /// A put during journal replay: may use the replay reserve.
        pub fn put_replay(self: *Tree, key: *const Key, value: ?*const Value) error{Busy}!void {
            assert(self.scan_callback == null);
            assert(!self.compaction.active);
            if (self.mutable_memtable().count == self.config.memtable_entries_max and
                self.immutable_memtable().count == 0) _ = self.swap();
            try self.mutable_memtable().put(key, value);
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

        /// Finds `key`. On `.done` (or in the callback after `.pending`) `lookup_result` says
        /// whether it is present, and `lookup_value` holds its value. One lookup at a time.
        pub fn lookup(self: *Tree, key: *const Key, callback: Callback) Status {
            assert(!self.lookup_active);
            assert(self.scan_callback == null);
            self.stats.lookups += 1;
            if (self.memtable_find(key)) |found| {
                const memtable, const entry = found;
                self.stats.lookups_memtable += 1;
                self.lookup_result = !memtable.tombstones[entry];
                self.lookup_value = memtable.values[entry];
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
            while (steps <= self.config.level0_tables_max + levels_max) : (steps += 1) {
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
            while (steps <= self.config.level0_tables_max + levels_max) : (steps += 1) {
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
            if (value.len != value_size) return error.Corrupt;
            self.lookup_value = value[0..value_size].*;
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
            if (level > 0) {
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
                for (self.table_blocks(slot)) |address| self.free_set.?.release(address);
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
        }

        // Checkpoint: header, level counts, tables, memtable entries, orphans.

        pub fn checkpoint_size_max(self: *const Tree) u32 {
            const slots = self.layout.slot_base[self.config.levels_count];
            return checkpoint_header_size + slots * info_size +
                2 * self.config.memtable_entries_max * entry_size + self.layout.orphans_max * 8;
        }

        pub fn checkpoint_size(self: *Tree) u32 {
            var tables: u32 = 0;
            for (self.level_count) |count| tables += count;
            const entries = self.memtables[0].count + self.memtables[1].count;
            const orphans: u32 = @intCast(self.compaction.orphans().len);
            const size = checkpoint_header_size + tables * info_size + entries * entry_size +
                orphans * 8;
            assert(size <= self.checkpoint_size_max());
            return size;
        }

        /// Writes the tree's checkpoint bytes (call at the engine checkpoint's snapshot point:
        /// right before `checkpoint`, with no tick between). Returns their length.
        pub fn checkpoint_encode(self: *Tree, out: []u8) u32 {
            assert(self.scan_callback == null);
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
                for (0..memtable.count) |entry| {
                    @memcpy(out[offset..][0..key_size], &memtable.keys[entry]);
                    out[offset + key_size] = @intFromBool(memtable.tombstones[entry]);
                    @memcpy(out[offset + key_size + 1 ..][0..value_size], &memtable.values[entry]);
                    offset += entry_size;
                }
            }
            for (orphans) |address| {
                std.mem.writeInt(u64, out[offset..][0..8], address, .little);
                offset += 8;
            }
            assert(offset == size);
            return size;
        }

        /// Loads checkpoint bytes into an empty tree (empty bytes: the empty tree). Checks the
        /// structure only; `open_scan` then reads and verifies every table.
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
            const size = checkpoint_header_size + tables * info_size +
                (@as(u64, entries_old) + entries_new) * entry_size + @as(u64, orphans) * 8;
            if (bytes.len != size) return error.InvalidCheckpoint;
            var offset: usize = checkpoint_header_size;
            for (0..self.config.levels_count) |level| {
                const count = read_u32(bytes, 32 + 4 * level);
                try self.decode_level(@intCast(level), bytes[offset..][0 .. count * info_size]);
                offset += count * info_size;
            }
            const memtable_old = self.immutable_memtable();
            try decode_entries(memtable_old, bytes[offset..][0 .. entries_old * entry_size]);
            offset += entries_old * entry_size;
            const memtable_new = self.mutable_memtable();
            try decode_entries(memtable_new, bytes[offset..][0 .. entries_new * entry_size]);
            offset += entries_new * entry_size;
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
                self.level_insert(level, slot);
            }
            assert(self.level_count[level] == count);
        }

        fn decode_entries(memtable: *Memtable, bytes: []const u8) error{InvalidCheckpoint}!void {
            assert(bytes.len % entry_size == 0);
            assert(memtable.count == 0);
            var offset: usize = 0;
            while (offset < bytes.len) : (offset += entry_size) {
                const key = bytes[offset..][0..key_size];
                const tag = bytes[offset + key_size];
                const value = bytes[offset + key_size + 1 ..][0..value_size];
                if (tag > 1) return error.InvalidCheckpoint;
                const tombstone = tag == 1;
                if (tombstone and !std.mem.allEqual(u8, value, 0)) return error.InvalidCheckpoint;
                const count = memtable.count;
                memtable.put(key, if (tombstone) null else value) catch unreachable; // Counted.
                // A key appears at most once per memtable.
                if (memtable.count != count + 1) return error.InvalidCheckpoint;
            }
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

        // Open scan: read and verify every table, rebuild filters, release orphans.

        /// Reads every table `open_decode` loaded (block checks, every block acquired and not
        /// released in the loaded free set), rebuilds the filters, then releases the orphans.
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
                    while (self.scan_level < self.config.levels_count and
                        self.level_count[self.scan_level] == 0) self.scan_level += 1;
                    if (self.scan_level == self.config.levels_count) return self.scan_finish();
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

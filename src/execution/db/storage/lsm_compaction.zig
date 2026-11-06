//! LSM compaction: one job at a time, a memtable flush or a level merge, paced in grid blocks.
//!
//! A job merges its input streams (the sorted immutable memtable for a flush; for a merge,
//! every level-0 table or one table of level i, plus the overlapping tables of the next
//! level) newest first: of equal keys only the newest survives, and a tombstone is dropped
//! when no level below the output can hold the key. Merged records go to a small staging
//! ring; the table builder pulls from it one data block per grant, and the job cuts output
//! tables at `table_records_max` records.
//!
//! The builder's `Source` is synchronous, while input blocks arrive asynchronously, so the
//! job refills the staging ring (reading input blocks as needed) until it holds a whole
//! block's worth of records plus one (a block holds at most `records_per_block_max`, and the
//! builder pulls one extra record that it keeps for the next block) before each block write.
//!
//! Pacing: `grant(blocks)` sets the job's budget of block reads and writes for this commit;
//! every read and every write spends one. Unused budget is dropped at the next grant, so a
//! commit never does more compaction IO than it was granted. One read or write is in flight
//! at a time, and the order of every step depends only on the commit sequence and the
//! storage's completion order (DST).
//!
//! Blocks: each output block comes from a one-block free-set reservation taken right before
//! the write and closed right after (so the job never holds a reservation across ticks, and
//! the code store can reserve between steps). A job that finds no free block stalls until
//! the next grant. Every acquired block is recorded (`acquired`): until the job installs its
//! outputs they are orphans, which a checkpoint names so open can release them. Installing
//! removes the inputs from their levels and releases their blocks to the free set, which
//! reuses them only once no retained checkpoint references them. A job never installs while
//! a lookup is reading tables; it defers until the lookup completes.
//!
//! `Walker` reads one list of tables in key order, a block at a time, verifying every block
//! against its table's `Info` (and the free set: each block acquired, none released); the
//! open scan uses it too.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const free_set_module = @import("free_set.zig");
const filter_module = @import("lsm_filter.zig");

const sector_size = storage.sector_size;
const block_header_size = grid_module.block_header_size;
const Reservation = free_set_module.Reservation;

pub fn WalkerType(comptime Tree: type) type {
    return struct {
        const Walker = @This();
        const Table = Tree.Table;
        pub const Callback = *const fn (*Walker) void;
        pub const Record = struct { key: *const Tree.Key, value: []const u8 };

        tree: *Tree = undefined,
        index_buffer: []align(sector_size) u8,
        data_buffer: []align(sector_size) u8,
        index_payload: []const u8 = &.{},
        data_payload: []const u8 = &.{},
        read: Tree.Grid.Read = .{},
        slots: []const u32 = &.{},
        /// Position: table (in `slots`), data block (index ordinal), record (in the block).
        table: u32 = 0,
        ordinal: u32 = 0,
        record: u32 = 0,
        index_loaded: bool = false,
        data_loaded: bool = false,
        /// Records of the current table seen in verified data blocks.
        records_seen: u64 = 0,
        callback: ?Callback = null,
        /// Whether the last block read verified.
        ok: bool = true,

        pub fn init(allocator: std.mem.Allocator, block_size: u32) !Walker {
            assert(block_size % sector_size == 0);
            const alignment = comptime std.mem.Alignment.fromByteUnits(sector_size);
            const index_buffer = try allocator.alignedAlloc(u8, alignment, block_size);
            errdefer allocator.free(index_buffer);
            const data_buffer = try allocator.alignedAlloc(u8, alignment, block_size);
            @memset(index_buffer, 0);
            @memset(data_buffer, 0);
            return .{ .index_buffer = index_buffer, .data_buffer = data_buffer };
        }

        pub fn deinit(self: *Walker, allocator: std.mem.Allocator) void {
            allocator.free(self.index_buffer);
            allocator.free(self.data_buffer);
            self.* = undefined;
        }

        pub fn start(self: *Walker, tree: *Tree, slots: []const u32) void {
            assert(self.callback == null);
            for (slots) |slot| assert(tree.slot_used[slot]);
            self.* = .{
                .tree = tree,
                .index_buffer = self.index_buffer,
                .data_buffer = self.data_buffer,
                .slots = slots,
            };
        }

        pub fn done(self: *const Walker) bool {
            assert(self.table <= self.slots.len);
            return self.table == self.slots.len;
        }

        fn info(self: *const Walker) *const Table.Info {
            return &self.tree.slot_infos[self.slots[self.table]];
        }

        /// The current record, or null when done or a block must be read first (`fetch`).
        pub fn peek(self: *const Walker) ?Record {
            if (self.done() or !self.data_loaded) return null;
            assert(self.index_loaded);
            const record = Table.data_record(self.data_payload, self.record);
            return .{ .key = Table.record_key(record), .value = record[Tree.key_bytes..] };
        }

        pub fn advance(self: *Walker) void {
            assert(self.data_loaded);
            self.record += 1;
            if (self.record < Table.data_count(self.data_payload)) return;
            self.record = 0;
            self.data_loaded = false;
            self.ordinal += 1;
            if (self.ordinal < self.info().data_block_count) return;
            assert(self.records_seen == self.info().record_count);
            self.ordinal = 0;
            self.index_loaded = false;
            self.records_seen = 0;
            self.table += 1;
        }

        /// Reads the block the walker needs next; `callback` fires with `ok` set.
        pub fn fetch(self: *Walker, callback: Callback) void {
            assert(!self.done() and !self.data_loaded);
            assert(self.callback == null);
            self.callback = callback;
            const grid = self.tree.grid;
            if (!self.index_loaded) {
                const reference = self.info().index;
                grid.read_block(on_read, &self.read, self.index_buffer, reference, .table_index);
            } else {
                const reference = Table.index_reference(self.index_payload, self.ordinal);
                grid.read_block(on_read, &self.read, self.data_buffer, reference, .table_data);
            }
        }

        fn on_read(read: *Tree.Grid.Read) void {
            const self: *Walker = @alignCast(@fieldParentPtr("read", read));
            const callback = self.callback.?;
            self.callback = null;
            self.ok = if (read.payload) |payload| switch (read.kind) {
                .table_index => self.index_check(payload),
                .table_data => self.data_check(payload),
                _ => false,
            } else false;
            callback(self);
        }

        /// Checks an index block against the table's `Info` and records its block addresses.
        fn index_check(self: *Walker, payload: []const u8) bool {
            const tree = self.tree;
            const table_info = self.info();
            if (!Table.index_valid(payload, tree.config.block_count)) return false;
            if (Table.index_count(payload) != table_info.data_block_count) return false;
            const first = Table.index_key(payload, 0);
            if (Table.key_order(first, &table_info.key_min) != .eq) return false;
            const blocks = tree.table_blocks(self.slots[self.table]);
            blocks[0] = table_info.index.address;
            for (blocks[1..], 0..) |*address, ordinal| {
                address.* = Table.index_reference(payload, @intCast(ordinal)).address;
            }
            const free_set = tree.free_set.?;
            for (blocks) |address| {
                if (!free_set.is_acquired(address) or free_set.is_released(address)) return false;
            }
            self.index_payload = payload;
            self.index_loaded = true;
            return true;
        }

        /// Checks a data block: structure, value sizes, keys inside its index fences.
        fn data_check(self: *Walker, payload: []const u8) bool {
            if (!Table.data_valid(payload)) return false;
            const table_info = self.info();
            const count = Table.data_count(payload);
            var index: u32 = 0;
            while (index < count) : (index += 1) {
                const value = Table.data_record(payload, index)[Tree.key_bytes..];
                if (value.len != 0 and value.len != Tree.value_bytes) return false;
            }
            const first = Table.record_key(Table.data_record(payload, 0));
            const last = Table.record_key(Table.data_record(payload, count - 1));
            const fence = Table.index_key(self.index_payload, self.ordinal);
            if (Table.key_order(first, fence) != .eq) return false;
            const final = self.ordinal + 1 == table_info.data_block_count;
            if (final) {
                if (Table.key_order(last, &table_info.key_max) != .eq) return false;
            } else {
                const next = Table.index_key(self.index_payload, self.ordinal + 1);
                if (Table.key_order(last, next) != .lt) return false;
            }
            self.records_seen += count;
            if (final and self.records_seen != table_info.record_count) return false;
            if (!final and self.records_seen >= table_info.record_count) return false;
            self.data_payload = payload;
            self.data_loaded = true;
            self.record = 0;
            return true;
        }
    };
}

pub fn CompactionType(comptime Tree: type) type {
    return struct {
        const Compaction = @This();
        const Table = Tree.Table;
        const Key = Tree.Key;
        const Value = Tree.Value;
        pub const Walker = WalkerType(Tree);
        pub const Kind = enum { flush, merge };
        const Fill = enum { ready, pending, blocked };

        config: @import("lsm.zig").Config,
        layout: Tree.Layout,
        walkers: []Walker,
        /// The level each walker's tables live in.
        walker_levels: []u32,
        walker_count: u32 = 0,
        /// The slot lists the walkers read (slices of this).
        input_slots: []u32,
        memtable_stream: bool = false,
        memtable_cursor: u32 = 0,
        kind: Kind = .flush,
        level_out: u32 = 0,
        drop_tombstones: bool = false,
        staging_keys: []Key,
        staging_values: []Value,
        staging_tombstones: []bool,
        staging_head: u32 = 0,
        staging_count: u32 = 0,
        merge_done: bool = false,
        builder: Table.Builder,
        building: bool = false,
        reservation: Reservation = undefined,
        output_slot: u32 = 0,
        output_records: u32 = 0,
        outputs: []u32,
        output_count: u32 = 0,
        acquired: []u64,
        acquired_count: u32 = 0,
        /// The record handed to the builder: two slots, since it may hold the previous one.
        out_keys: [2]Key = undefined,
        out_values: [2]Value = undefined,
        out_toggle: u1 = 0,
        budget: u64 = 0,
        io_pending: bool = false,
        active: bool = false,
        finish_deferred: bool = false,

        pub fn init(
            allocator: std.mem.Allocator,
            grid: *Tree.Grid,
            config: @import("lsm.zig").Config,
            layout: Tree.Layout,
        ) !Compaction {
            const walker_count = config.level0_tables_max + 1;
            const walkers = try allocator.alloc(Walker, walker_count);
            errdefer allocator.free(walkers);
            var initialized: u32 = 0;
            errdefer for (walkers[0..initialized]) |*walker| walker.deinit(allocator);
            while (initialized < walker_count) : (initialized += 1) {
                walkers[initialized] = try Walker.init(allocator, config.block_size);
            }
            const walker_levels = try allocator.alloc(u32, walker_count);
            errdefer allocator.free(walker_levels);
            var level_tables_max: u32 = 0;
            for (layout.tables_max) |tables| level_tables_max = @max(level_tables_max, tables);
            const input_slots = try allocator.alloc(u32, walker_count + level_tables_max);
            errdefer allocator.free(input_slots);
            const staging = layout.records_per_block_max + 2;
            const staging_keys = try allocator.alloc(Key, staging);
            errdefer allocator.free(staging_keys);
            const staging_values = try allocator.alloc(Value, staging);
            errdefer allocator.free(staging_values);
            const staging_tombstones = try allocator.alloc(bool, staging);
            errdefer allocator.free(staging_tombstones);
            const outputs = try allocator.alloc(u32, layout.job_tables_max);
            errdefer allocator.free(outputs);
            const acquired = try allocator.alloc(u64, layout.orphans_max);
            errdefer allocator.free(acquired);
            var builder = try Table.Builder.init(allocator, grid);
            builder.pause_callback = on_paused;
            return .{
                .config = config,
                .layout = layout,
                .walkers = walkers,
                .walker_levels = walker_levels,
                .input_slots = input_slots,
                .staging_keys = staging_keys,
                .staging_values = staging_values,
                .staging_tombstones = staging_tombstones,
                .builder = builder,
                .outputs = outputs,
                .acquired = acquired,
            };
        }

        pub fn deinit(self: *Compaction, allocator: std.mem.Allocator) void {
            for (self.walkers) |*walker| walker.deinit(allocator);
            allocator.free(self.walkers);
            allocator.free(self.walker_levels);
            allocator.free(self.input_slots);
            allocator.free(self.staging_keys);
            allocator.free(self.staging_values);
            allocator.free(self.staging_tombstones);
            allocator.free(self.outputs);
            allocator.free(self.acquired);
            self.builder.deinit(allocator);
            self.* = undefined;
        }

        pub fn bind(self: *Compaction, grid: *Tree.Grid) void {
            assert(!self.io_pending);
            self.builder.grid = grid;
        }

        fn tree(self: *Compaction) *Tree {
            return @alignCast(@fieldParentPtr("compaction", self));
        }

        /// The blocks the running job acquired and has not installed (orphans).
        pub fn orphans(self: *const Compaction) []const u64 {
            assert(self.active or self.acquired_count == 0);
            return self.acquired[0..self.acquired_count];
        }

        /// This commit's budget; drops what the last commit left unused.
        pub fn grant(self: *Compaction, blocks: u64) void {
            assert(blocks > 0);
            self.budget = blocks;
            self.drive();
        }

        /// Called when a lookup completes: installs a job that finished meanwhile.
        pub fn lookup_done(self: *Compaction) void {
            if (!self.finish_deferred) return;
            assert(self.active);
            self.finish_deferred = false;
            self.install();
            self.drive();
        }

        /// Runs the job until it waits for IO, runs out of budget, or has no work.
        fn drive(self: *Compaction) void {
            var steps: u32 = 0;
            // Bounded: each pass starts a job, finishes one, fills the staging ring, or
            // returns; a block write or read always returns.
            while (steps < 16) : (steps += 1) {
                if (self.io_pending or self.finish_deferred or self.tree().fault) return;
                if (!self.active) {
                    if (!self.start()) return;
                    continue;
                }
                if (self.budget == 0) return;
                if (!self.merge_done and self.staging_count < self.staging_target()) {
                    switch (self.merge_fill()) {
                        .ready => continue,
                        .pending, .blocked => return,
                    }
                }
                if (self.staging_count == 0 and !self.building) {
                    assert(self.merge_done);
                    self.finish();
                    continue;
                }
                _ = self.write_block();
                return;
            }
        }

        fn staging_target(self: *const Compaction) u32 {
            return self.layout.records_per_block_max + 1;
        }

        // Job selection.

        /// Starts the most urgent job; false when there is nothing to do.
        fn start(self: *Compaction) bool {
            assert(!self.active);
            const owner = self.tree();
            var level: u32 = 0;
            if (owner.level_count[0] < self.config.level0_tables_max) {
                if (owner.immutable_memtable().count > 0) {
                    self.start_flush();
                    return true;
                }
                level = self.level_due() orelse return false;
            }
            // A job whose output does not fit makes room one level down first.
            while (level + 1 < self.config.levels_count) : (level += 1) {
                if (self.start_merge(level)) return true;
            }
            @panic("lsm: the last level is full (configure more levels or capacity)");
        }

        /// The deepest level above the last that is over its capacity or fragmented.
        fn level_due(self: *Compaction) ?u32 {
            const owner = self.tree();
            var level = self.config.levels_count - 1;
            while (level > 1) {
                level -= 1;
                const over = owner.level_records[level] > self.layout.capacity[level];
                const fragmented = owner.level_count[level] > self.layout.tables_max[level] / 2;
                if (over or fragmented) return level;
            }
            return null;
        }

        fn job_begin(self: *Compaction, kind: Kind, level_out: u32) void {
            assert(!self.active and !self.building);
            assert(self.acquired_count == 0 and self.output_count == 0);
            const owner = self.tree();
            self.kind = kind;
            self.level_out = level_out;
            self.active = true;
            self.merge_done = false;
            self.staging_head = 0;
            self.staging_count = 0;
            self.walker_count = 0;
            self.memtable_stream = false;
            self.memtable_cursor = 0;
            // Tombstones go once no level below the output can hold their keys (level 0's
            // other tables overlap, so a flush drops them only into an empty tree).
            var level = level_out + 1;
            var deeper_empty = kind == .merge or owner.level_count[0] == 0;
            while (level < self.config.levels_count) : (level += 1) {
                if (owner.level_count[level] > 0) deeper_empty = false;
            }
            self.drop_tombstones = deeper_empty;
        }

        fn start_flush(self: *Compaction) void {
            const owner = self.tree();
            assert(owner.immutable_memtable().sorted);
            self.job_begin(.flush, 0);
            self.memtable_stream = true;
        }

        /// Merges level-0 (every table) or one table of `level_in` into the next level, if
        /// its output fits there.
        fn start_merge(self: *Compaction, level_in: u32) bool {
            const owner = self.tree();
            const level_out = level_in + 1;
            const inputs_all = owner.level_list(level_in);
            assert(inputs_all.len > 0);
            const inputs = if (level_in == 0)
                inputs_all
            else
                inputs_all[self.pick(level_in)..][0..1];
            var range = Range.of(owner, inputs[0]);
            for (inputs) |slot| range.add(owner, slot);
            const overlap_first, const overlap_count =
                owner.level_overlap(level_out, &range.key_min, &range.key_max);
            const overlap = owner.level_list(level_out)[overlap_first..][0..overlap_count];
            for (overlap) |slot| range.records += owner.slot_infos[slot].record_count;
            const table_records = self.config.table_records_max;
            const outputs_max = std.math.divCeil(u64, range.records, table_records) catch
                unreachable; // table_records_max > 0.
            if (outputs_max + 1 > self.layout.job_tables_max) return false;
            const tables_max = self.layout.tables_max[level_out];
            if (owner.level_count[level_out] + outputs_max + 1 > tables_max) return false;
            self.job_begin(.merge, level_out);
            if (level_in > 0) owner.compact_cursor[level_in] = range.key_max;
            self.walkers_setup(level_in, inputs, overlap);
            return true;
        }

        /// The position of the next table of `level_in` to merge, round robin by key.
        fn pick(self: *Compaction, level_in: u32) usize {
            assert(level_in > 0);
            const owner = self.tree();
            const cursor = &owner.compact_cursor[level_in];
            const slots = owner.level_list(level_in);
            for (slots, 0..) |slot, position| {
                const order = Table.key_order(&owner.slot_infos[slot].key_min, cursor);
                if (order == .gt) return position;
            }
            return 0;
        }

        const Range = struct {
            key_min: Key,
            key_max: Key,
            records: u64 = 0,

            fn of(owner: *const Tree, slot: u32) Range {
                const table_info = &owner.slot_infos[slot];
                return .{ .key_min = table_info.key_min, .key_max = table_info.key_max };
            }

            fn add(range: *Range, owner: *const Tree, slot: u32) void {
                const table_info = &owner.slot_infos[slot];
                if (Table.key_order(&table_info.key_min, &range.key_min) == .lt) {
                    range.key_min = table_info.key_min;
                }
                if (Table.key_order(&table_info.key_max, &range.key_max) == .gt) {
                    range.key_max = table_info.key_max;
                }
                range.records += table_info.record_count;
            }
        };

        /// One walker per input table of level 0 (newest first, they overlap) or one for the
        /// single table of a deeper level, then one for the overlapping next-level tables.
        fn walkers_setup(
            self: *Compaction,
            level_in: u32,
            inputs: []const u32,
            overlap: []const u32,
        ) void {
            assert(inputs.len + 1 <= self.walkers.len);
            const owner = self.tree();
            @memcpy(self.input_slots[0..inputs.len], inputs);
            @memcpy(self.input_slots[inputs.len..][0..overlap.len], overlap);
            for (inputs, 0..) |_, index| {
                self.walkers[index].start(owner, self.input_slots[index..][0..1]);
                self.walker_levels[index] = level_in;
            }
            self.walker_count = @intCast(inputs.len);
            if (overlap.len == 0) return;
            const slots = self.input_slots[inputs.len..][0..overlap.len];
            self.walkers[self.walker_count].start(owner, slots);
            self.walker_levels[self.walker_count] = level_in + 1;
            self.walker_count += 1;
        }

        // Merge.

        /// The current record of stream `stream` (0 = the memtable for a flush, else walker
        /// `stream - 1`), or null when it is done or waits for a block.
        fn stream_peek(self: *Compaction, stream: u32) ?Walker.Record {
            if (stream == 0) {
                if (!self.memtable_stream) return null;
                const memtable = self.tree().immutable_memtable();
                if (self.memtable_cursor == memtable.count) return null;
                const entry = memtable.order[self.memtable_cursor];
                const value: []const u8 = if (memtable.tombstones[entry])
                    &.{}
                else
                    &memtable.values[entry];
                return .{ .key = &memtable.keys[entry], .value = value };
            }
            return self.walkers[stream - 1].peek();
        }

        fn stream_advance(self: *Compaction, stream: u32) void {
            if (stream == 0) {
                assert(self.memtable_stream);
                self.memtable_cursor += 1;
            } else self.walkers[stream - 1].advance();
        }

        /// Merges records into the staging ring until it holds `staging_target` or every
        /// stream is done. `.pending`: an input block read was started; `.blocked`: one is
        /// needed but this commit's budget is spent.
        fn merge_fill(self: *Compaction) Fill {
            const streams = self.walker_count + 1;
            var steps: u32 = 0;
            const steps_max = self.staging_target() * 1024;
            while (self.staging_count < self.staging_target()) : (steps += 1) {
                // A run of dropped records yields to the next commit.
                if (steps == steps_max) return .blocked;
                for (self.walkers[0..self.walker_count]) |*walker| {
                    if (walker.done() or walker.data_loaded) continue;
                    if (self.budget == 0) return .blocked;
                    self.budget -= 1;
                    self.io_pending = true;
                    self.tree().stats.blocks_read += 1;
                    walker.fetch(on_walker_read);
                    return .pending;
                }
                var best: ?u32 = null;
                var stream: u32 = 0;
                while (stream < streams) : (stream += 1) {
                    const record = self.stream_peek(stream) orelse continue;
                    if (best) |current| {
                        const best_key = self.stream_peek(current).?.key;
                        if (Table.key_order(record.key, best_key) != .lt) continue;
                    }
                    best = stream;
                }
                const winner = best orelse {
                    self.merge_done = true;
                    return .ready;
                };
                self.merge_take(winner, streams);
            }
            return .ready;
        }

        /// Stages the winner's record (unless a dropped tombstone) and advances every stream
        /// holding the same key (older versions).
        fn merge_take(self: *Compaction, winner: u32, streams: u32) void {
            const record = self.stream_peek(winner).?;
            const key = record.key.*;
            const tombstone = record.value.len == 0;
            if (tombstone and self.drop_tombstones) {
                self.tree().stats.tombstones_dropped += 1;
            } else {
                const capacity: u32 = @intCast(self.staging_keys.len);
                assert(self.staging_count < capacity);
                const index = (self.staging_head + self.staging_count) % capacity;
                self.staging_keys[index] = key;
                self.staging_tombstones[index] = tombstone;
                if (!tombstone) self.staging_values[index] = record.value[0..Tree.value_bytes].*;
                self.staging_count += 1;
            }
            var stream = winner;
            while (stream < streams) : (stream += 1) {
                const other = self.stream_peek(stream) orelse continue;
                if (Table.key_order(other.key, &key) == .eq) self.stream_advance(stream);
            }
        }

        fn on_walker_read(walker: *Walker) void {
            const owner = walker.tree;
            const self = &owner.compaction;
            assert(self.io_pending);
            self.io_pending = false;
            if (!walker.ok) {
                owner.fault = true;
                return;
            }
            self.drive();
        }

        // Output.

        /// Writes the next output block (data or index) from a one-block reservation; false
        /// when no block is free now.
        fn write_block(self: *Compaction) bool {
            assert(self.budget > 0 and !self.io_pending);
            assert(self.merge_done or self.staging_count >= self.staging_target());
            const owner = self.tree();
            const free_set = owner.free_set.?;
            if (free_set.reserved) {
                owner.stats.stalls += 1;
                return false;
            }
            self.reservation = free_set.reserve(1) catch {
                owner.stats.stalls += 1;
                return false;
            };
            assert(self.acquired_count < self.acquired.len);
            self.acquired[self.acquired_count] = self.reservation.address_first;
            self.acquired_count += 1;
            self.budget -= 1;
            self.io_pending = true;
            owner.stats.blocks_written += 1;
            if (self.building) {
                self.builder.grant(1);
            } else {
                assert(self.staging_count > 0);
                assert(self.output_count < self.outputs.len);
                self.building = true;
                self.output_slot = owner.slot_acquire(self.level_out);
                self.output_records = 0;
                const source: Table.Source = .{ .context = self, .next = source_next };
                self.builder.build_paced(source, free_set, &self.reservation, 1, on_built);
            }
            assert(self.reservation.acquired == 1);
            free_set.forfeit(&self.reservation);
            return true;
        }

        fn source_next(context: *anyopaque) ?Table.Record {
            const self: *Compaction = @ptrCast(@alignCast(context));
            if (self.output_records == self.config.table_records_max) return null;
            if (self.staging_count == 0) {
                assert(self.merge_done);
                return null;
            }
            const capacity: u32 = @intCast(self.staging_keys.len);
            const index = self.staging_head;
            self.staging_head = (self.staging_head + 1) % capacity;
            self.staging_count -= 1;
            self.out_toggle +%= 1;
            const slot = self.out_toggle;
            self.out_keys[slot] = self.staging_keys[index];
            self.out_values[slot] = self.staging_values[index];
            self.output_records += 1;
            const owner = self.tree();
            owner.stats.records_written += 1;
            if (owner.slot_filter(self.output_slot)) |words| {
                filter_module.insert(words, filter_module.hash(&self.out_keys[slot]));
            }
            const value: []const u8 = if (self.staging_tombstones[index])
                &.{}
            else
                &self.out_values[slot];
            return .{ .key = &self.out_keys[slot], .value = value };
        }

        fn on_paused(builder: *Table.Builder) void {
            const self: *Compaction = @alignCast(@fieldParentPtr("builder", builder));
            assert(self.io_pending and self.building);
            self.io_pending = false;
            self.drive();
        }

        fn on_built(builder: *Table.Builder) void {
            const self: *Compaction = @alignCast(@fieldParentPtr("builder", builder));
            assert(self.io_pending and self.building);
            self.io_pending = false;
            self.building = false;
            // A table starts only with staged records and is cut at `table_records_max`,
            // which `layout_of` keeps within one index block.
            const table_info = builder.result catch unreachable;
            const owner = self.tree();
            owner.slot_infos[self.output_slot] = table_info;
            const blocks = owner.table_blocks(self.output_slot);
            blocks[0] = table_info.index.address;
            const index = builder.index_block[block_header_size..];
            for (blocks[1..], 0..) |*address, ordinal| {
                address.* = Table.index_reference(index, @intCast(ordinal)).address;
            }
            self.outputs[self.output_count] = self.output_slot;
            self.output_count += 1;
            self.drive();
        }

        fn finish(self: *Compaction) void {
            assert(self.active and self.merge_done and !self.building);
            assert(self.staging_count == 0);
            if (self.tree().lookup_active) {
                self.finish_deferred = true;
                return;
            }
            self.install();
        }

        /// Replaces the inputs with the outputs in the manifest; releases the inputs' blocks.
        fn install(self: *Compaction) void {
            assert(self.active and !self.io_pending);
            const owner = self.tree();
            for (self.walkers[0..self.walker_count], 0..) |*walker, index| {
                assert(walker.done());
                for (walker.slots) |slot| owner.level_remove(self.walker_levels[index], slot, true);
            }
            if (self.kind == .flush) {
                assert(self.memtable_cursor == owner.immutable_memtable().count);
                owner.immutable_memtable().reset();
                owner.stats.flushes += 1;
            } else owner.stats.merges += 1;
            for (self.outputs[0..self.output_count]) |slot| {
                owner.level_insert(self.level_out, slot);
            }
            self.active = false;
            self.walker_count = 0;
            self.output_count = 0;
            self.acquired_count = 0;
            self.memtable_stream = false;
            assert(!self.active and !self.io_pending);
            if (owner.install_callback) |callback| callback(owner);
        }
    };
}

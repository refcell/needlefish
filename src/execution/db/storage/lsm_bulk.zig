//! LSM bulk load: writes a strictly ascending stream of records as tables straight into the
//! last level of an empty tree, with no memtable, flush, or merge (disk-state import).
//!
//! Push-based, so one pass over a source can feed several trees: `begin` on an empty tree,
//! `append(key, value)` per record, `finish(callback)`. `append` stages the record in a ring
//! and, once the ring holds a whole data block's worth plus one (the builder pulls one record
//! more than a block holds and keeps it for the next block), writes one block. One block write
//! is in flight at a time; `error.Busy` means the ring is full while it is: tick the storage
//! and retry. Tables are cut where compaction cuts them (`table_records_max` records or
//! `Layout.data_blocks_max` data blocks, by the builder's own packing rule, `PackerType`), and
//! each is installed into the last level as its index block lands (`key_min` above the
//! previous table's `key_max`). The last level has no filters, so nothing else is built.
//!
//! Blocks come from one-block free-set reservations taken right before each write and closed
//! right after, as compaction does, so other writers (the code store) may reserve between
//! steps; a reservation held by another writer stalls the load (`poll` resumes it). A table
//! starts only when the free set has a whole table's blocks free and the last level a slot,
//! else the load fails with `error.NoSpace` or `error.TreeFull` (sticky; `finish` still calls
//! back with `result` set). A failed load may leave its unfinished table's blocks acquired:
//! the caller discards the datadir (formats again).
//!
//! While loading, the tree refuses compaction and checkpoints (`Tree.bulk_active`). Nothing is
//! durable until the owner's next checkpoint after `finish`; a crash before it opens the
//! previous checkpoint (the empty tree), whose free set never named the loaded blocks.

const std = @import("std");
const assert = std.debug.assert;

const grid_module = @import("grid.zig");
const free_set_module = @import("free_set.zig");
const compaction_module = @import("lsm_compaction.zig");

const block_header_size = grid_module.block_header_size;
const Reservation = free_set_module.Reservation;

pub const Error = error{ Busy, KeyOrder, TreeFull, NoSpace };

pub fn BulkLoaderType(comptime Tree: type) type {
    return struct {
        const Loader = @This();
        const Table = Tree.Table;
        const Key = Tree.Key;
        const Value = Tree.Value;
        const Packer = compaction_module.PackerType(Tree);

        pub const Callback = *const fn (*Loader) void;
        pub const Stats = struct {
            records: u64 = 0,
            tables: u64 = 0,
            blocks_written: u64 = 0,
            busy: u64 = 0,
            /// Writes deferred because another writer held the free set's reservation.
            stalls: u64 = 0,
        };

        tree: *Tree,
        builder: Table.Builder,
        staging_keys: []Key,
        staging_values: []Value,
        staging_lengths: []u16,
        staging_head: u32 = 0,
        staging_count: u32 = 0,
        /// The record handed to the builder: two slots, since it may hold the previous one.
        out_keys: [2]Key = undefined,
        out_values: [2]Value = undefined,
        out_toggle: u1 = 0,
        packer: Packer = .{},
        reservation: Reservation = undefined,
        building: bool = false,
        io_pending: bool = false,
        active: bool = false,
        finishing: bool = false,
        callback: ?Callback = null,
        key_last: Key = undefined,
        /// Sticky: the load failed (`error.TreeFull` or `error.NoSpace`).
        result: Error!void = {},
        stats: Stats = .{},

        /// `tree` must be bound to its grid and free set, and must not move while loading.
        pub fn init(allocator: std.mem.Allocator, tree: *Tree) !Loader {
            assert(tree.free_set != null);
            const staging: usize = 2 * (@as(usize, tree.layout.records_per_block_max) + 1);
            const staging_keys = try allocator.alloc(Key, staging);
            errdefer allocator.free(staging_keys);
            const staging_values = try allocator.alloc(Value, staging);
            errdefer allocator.free(staging_values);
            const staging_lengths = try allocator.alloc(u16, staging);
            errdefer allocator.free(staging_lengths);
            var builder = try Table.Builder.init(allocator, tree.grid);
            builder.pause_callback = on_paused;
            return .{
                .tree = tree,
                .builder = builder,
                .staging_keys = staging_keys,
                .staging_values = staging_values,
                .staging_lengths = staging_lengths,
            };
        }

        /// Frees memory. A write may be in flight only if the storage dropped it (crash).
        pub fn deinit(self: *Loader, allocator: std.mem.Allocator) void {
            assert(self.staging_keys.len == self.staging_lengths.len);
            allocator.free(self.staging_keys);
            allocator.free(self.staging_values);
            allocator.free(self.staging_lengths);
            self.builder.deinit(allocator);
            self.* = undefined;
        }

        /// Starts a load into an empty tree (no tables, empty memtables, nothing running).
        pub fn begin(self: *Loader) void {
            const tree = self.tree;
            assert(!self.active and !tree.bulk_active);
            assert(tree.free_set != null and !tree.fault);
            assert(!tree.compaction.active and !tree.lookup_active and tree.scan_callback == null);
            for (tree.level_count) |count| assert(count == 0);
            for (&tree.memtables) |*memtable| assert(memtable.count == 0);
            self.builder.grid = tree.grid;
            tree.bulk_active = true;
            self.active = true;
            self.finishing = false;
            self.callback = null;
            self.staging_head = 0;
            self.staging_count = 0;
            self.result = {};
            self.stats = .{};
        }

        /// Appends a record; its key must be above every key appended before
        /// (`error.KeyOrder` otherwise, and the record is not taken). `error.Busy`: tick the
        /// storage and retry the same record.
        pub fn append(self: *Loader, key: *const Key, value: Tree.ValueIn) Error!void {
            assert(self.active and !self.finishing);
            const bytes: []const u8 = value;
            assert(Tree.value_length_valid(bytes.len));
            try self.result;
            const first = self.stats.records == 0 and self.staging_count == 0;
            if (!first and Table.key_order(&self.key_last, key) != .lt) return error.KeyOrder;
            self.pump();
            try self.result;
            const capacity: u32 = @intCast(self.staging_keys.len);
            if (self.staging_count == capacity) {
                self.stats.busy += 1;
                return error.Busy;
            }
            const index = (self.staging_head + self.staging_count) % capacity;
            self.staging_keys[index] = key.*;
            @memcpy(self.staging_values[index][0..bytes.len], bytes);
            self.staging_lengths[index] = @intCast(bytes.len);
            self.staging_count += 1;
            self.key_last = key.*;
            self.pump();
        }

        /// Writes what is staged and calls back once the last table is installed (or the
        /// load failed: see `result`). May call back before returning.
        pub fn finish(self: *Loader, callback: Callback) void {
            assert(self.active and !self.finishing);
            assert(self.callback == null);
            self.finishing = true;
            self.callback = callback;
            self.pump();
        }

        /// Resumes a load stalled on another writer's reservation (after ticking).
        pub fn poll(self: *Loader) void {
            assert(self.active);
            self.pump();
        }

        fn staging_target(self: *const Loader) u32 {
            return self.tree.layout.records_per_block_max + 1;
        }

        /// Writes the next block if one is due and none is in flight; completes a finish.
        fn pump(self: *Loader) void {
            assert(self.active);
            if (self.io_pending) return;
            var failed = false;
            self.result catch {
                failed = true;
            };
            if (!failed) {
                const draining = self.finishing and (self.staging_count > 0 or self.building);
                if (self.staging_count >= self.staging_target() or draining) self.write_block();
                if (self.io_pending) return;
                self.result catch {
                    failed = true;
                };
            }
            if (!self.finishing) return;
            if (!failed and (self.staging_count > 0 or self.building)) return; // Stalled.
            self.done();
        }

        fn done(self: *Loader) void {
            assert(self.finishing and !self.io_pending);
            assert(self.tree.bulk_active);
            self.active = false;
            self.finishing = false;
            self.tree.bulk_active = false;
            const callback = self.callback.?;
            self.callback = null;
            callback(self);
        }

        /// Writes one block (data or index) from a one-block reservation.
        fn write_block(self: *Loader) void {
            assert(!self.io_pending);
            assert(self.staging_count > 0 or self.building);
            const tree = self.tree;
            const free_set = tree.free_set.?;
            if (free_set.reserved) {
                self.stats.stalls += 1;
                return;
            }
            if (!self.building) {
                const level = tree.config.levels_count - 1;
                if (tree.level_count[level] == tree.layout.tables_max[level]) {
                    self.result = error.TreeFull;
                    return;
                }
                if (free_set.count_free() < tree.layout.blocks_per_table) {
                    self.result = error.NoSpace;
                    return;
                }
            }
            self.reservation = free_set.reserve(1) catch {
                self.result = error.NoSpace;
                return;
            };
            self.io_pending = true;
            self.stats.blocks_written += 1;
            if (self.building) {
                self.builder.grant(1);
            } else {
                self.building = true;
                self.packer = .{};
                const source: Table.Source = .{ .context = self, .next = source_next };
                self.builder.build_paced(source, free_set, &self.reservation, 1, on_built);
            }
            assert(self.reservation.acquired == 1);
            free_set.forfeit(&self.reservation);
        }

        fn source_next(context: *anyopaque) ?Table.Record {
            const self: *Loader = @ptrCast(@alignCast(context));
            if (self.staging_count == 0) {
                // A block starts only with a whole block's records staged, but at the end.
                assert(self.finishing);
                return null;
            }
            const capacity: u32 = @intCast(self.staging_keys.len);
            const index = self.staging_head;
            const length = self.staging_lengths[index];
            if (!self.packer.take(self.tree, Tree.key_bytes + length)) return null;
            self.staging_head = (self.staging_head + 1) % capacity;
            self.staging_count -= 1;
            self.out_toggle +%= 1;
            const slot = self.out_toggle;
            self.out_keys[slot] = self.staging_keys[index];
            @memcpy(self.out_values[slot][0..length], self.staging_values[index][0..length]);
            self.stats.records += 1;
            return .{ .key = &self.out_keys[slot], .value = self.out_values[slot][0..length] };
        }

        fn on_paused(builder: *Table.Builder) void {
            const self: *Loader = @alignCast(@fieldParentPtr("builder", builder));
            assert(self.io_pending and self.building);
            self.io_pending = false;
            self.pump();
        }

        fn on_built(builder: *Table.Builder) void {
            const self: *Loader = @alignCast(@fieldParentPtr("builder", builder));
            assert(self.io_pending and self.building);
            self.io_pending = false;
            self.building = false;
            // A table starts only with staged records and the packer cuts it within one
            // index block.
            const table_info = builder.result catch unreachable;
            self.install(&table_info);
            self.pump();
        }

        /// Appends a written table to the last level.
        fn install(self: *Loader, table_info: *const Table.Info) void {
            const tree = self.tree;
            const level = tree.config.levels_count - 1;
            assert(tree.level_count[level] < tree.layout.tables_max[level]);
            const tables = tree.level_list(level);
            if (tables.len > 0) {
                const previous = &tree.slot_infos[tables[tables.len - 1]];
                assert(Table.key_order(&previous.key_max, &table_info.key_min) == .lt);
            }
            const slot = tree.slot_acquire(level);
            tree.slot_infos[slot] = table_info.*;
            const blocks = tree.table_blocks(slot);
            blocks[0] = table_info.index.address;
            const index = self.builder.index_block[block_header_size..];
            for (blocks[1..], 0..) |*address, ordinal| {
                address.* = Table.index_reference(index, @intCast(ordinal)).address;
            }
            tree.level_insert(level, slot);
            self.stats.tables += 1;
            assert(tree.level_list(level)[tree.level_count[level] - 1] == slot);
        }
    };
}

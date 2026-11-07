//! Code store: contract codes in immutable sorted tables on the engine's grid, so a
//! checkpoint image carries a table list instead of every code (disk state phase 1d).
//!
//! Codes stay resident in `State.code_arena` (`State.code_by_hash` is unchanged and
//! synchronous); the tables only take them out of the checkpoint image. The arena is
//! append-only and codes are immutable, so one watermark describes what the tables hold:
//! every code at an arena offset below `arena_flushed` and at most `value_size_max` long is
//! in a table, every other code is carried by the checkpoint image (`code_filter`).
//!
//! - Flush (`flush_start`, before each database checkpoint): the codes added since the last
//!   flush, sorted by hash, are written as one or more tables (each at most one index
//!   block's worth), paced like checkpoint chunks (`grant`). Below `flush_bytes_min` of new
//!   code the flush is skipped and those codes ride in the image. Blocks come from one
//!   free-set reservation for the whole flush, so it never runs out halfway; without room
//!   it is skipped and the codes stay in the image.
//! - Rewrite: when the new tables would overflow `tables_max`, every code in the arena is
//!   written into fresh tables instead and the old tables' blocks are released to the free
//!   set, which reuses them only once no retained checkpoint can name them.
//! - Open (`manifest_load` + `scan_start`, during the engine's open pause): each table's
//!   index block, then its data blocks, are read and verified, and every code is inserted
//!   into the arena (its hash checked) before the checkpoint image's own codes.
//!
//! Static memory: the builder's three blocks, two scan blocks, the manifest and the one
//! being built (with every block address, so a rewrite can release them), and one sort
//! entry per code (`codes_max`), all allocated at init.

const std = @import("std");
const assert = std.debug.assert;

const state_module = @import("state.zig");
const snapshot_module = @import("snapshot.zig");
const storage_module = @import("storage/storage.zig");
const grid_module = @import("storage/grid.zig");
const table_module = @import("storage/table.zig");
const free_set_module = @import("storage/free_set.zig");
const keccak256 = @import("../trie/node.zig").keccak256;

const State = state_module.State;
const Hash = state_module.Hash;
const FreeSet = free_set_module.FreeSet;
const Reservation = free_set_module.Reservation;
const sector_size = storage_module.sector_size;
const block_header_size = grid_module.block_header_size;
const payload_header_size: u32 = 8;

pub const Config = struct {
    block_size: u32,
    /// Grid blocks (addresses `1..block_count`).
    block_count: u64,
    tables_max: u32,
    codes_max: u32,
    code_bytes_max: u32,
    /// New code bytes below which a flush is skipped (they stay in the image).
    flush_bytes_min: u32,
};

pub const Status = enum { done, pending };
pub const ScanOutcome = enum { loaded, corrupt };

pub const Stats = struct {
    flushes: u64 = 0,
    rewrites: u64 = 0,
    tables_written: u64 = 0,
    /// Flushes skipped: too little new code, or no room on the grid.
    flushes_small: u64 = 0,
    flushes_no_space: u64 = 0,
};

pub fn CodeStoreType(comptime Storage: type) type {
    return struct {
        const Self = @This();

        pub const Table = table_module.TableType(Storage, 32);
        pub const Grid = Table.Grid;
        pub const Info = Table.Info;
        pub const Callback = *const fn (*Self) void;
        pub const info_size: u32 = @sizeOf(Info);

        const Entry = struct { hash: Hash, offset: u32, len: u32 };

        /// A table list with every block address of every table (index block first).
        const Manifest = struct {
            infos: []Info,
            blocks: []u64,
            count: u32 = 0,
        };

        const FlushState = enum { idle, building, waiting };
        const ScanStep = enum { idle, index, data };

        comptime {
            assert(info_size == 112);
        }

        config: Config,
        /// The callbacks' context, set by the owner before a scan or flush.
        owner: ?*anyopaque = null,
        /// Blocks one table holds at most (data blocks + the index block).
        blocks_per_table: u32,
        /// Record bytes (key + value + end offset) one table holds at most.
        table_bytes_max: u64,
        value_size_max: u32,
        grid: ?*Grid = null,
        free_set: ?*FreeSet = null,
        tables: Manifest,
        pending: Manifest,
        /// Arena bytes the tables cover (see the file comment).
        arena_flushed: u32 = 0,
        entries: []Entry,
        entries_len: u32 = 0,
        builder: Table.Builder,
        reservation: Reservation = undefined,
        flush_state: FlushState = .idle,
        flush_rewrite: bool = false,
        flush_cut: u32 = 0,
        flush_arena: []const u8 = &.{},
        flush_callback: ?Callback = null,
        /// Next entry to write, and the end of the table being built.
        cursor: u32 = 0,
        chunk_end: u32 = 0,
        scan_index: []align(sector_size) u8,
        scan_data: []align(sector_size) u8,
        scan_read: Grid.Read = .{},
        scan_step: ScanStep = .idle,
        scan_table: u32 = 0,
        scan_ordinal: u32 = 0,
        scan_records: u64 = 0,
        scan_state: ?*State = null,
        scan_callback: ?Callback = null,
        scan_outcome: ScanOutcome = .loaded,
        stats: Stats = .{},

        /// `grid` is used only for its block size here; `bind` names the engine's grid
        /// before every scan and flush (the database value moves after init).
        pub fn init(allocator: std.mem.Allocator, grid: *Grid, config: Config) !Self {
            assert(config.tables_max >= 2);
            assert(config.block_size == grid.config.block_size);
            const capacity = Table.index_capacity(config.block_size);
            const table_bytes_max = table_bytes_max_of(config.block_size);
            const value_size_max = Table.value_size_max(config.block_size);
            // Every code fits half the table list, so a rewrite always leaves room.
            assert(config.tables_max >= tables_max_min(
                config.block_size,
                config.codes_max,
                config.code_bytes_max,
            ));
            var tables = try manifest_init(allocator, config.tables_max, capacity + 1);
            errdefer manifest_deinit(allocator, &tables);
            var pending = try manifest_init(allocator, config.tables_max, capacity + 1);
            errdefer manifest_deinit(allocator, &pending);
            const entries = try allocator.alloc(Entry, config.codes_max);
            errdefer allocator.free(entries);
            var builder = try Table.Builder.init(allocator, grid);
            errdefer builder.deinit(allocator);
            const alignment = comptime std.mem.Alignment.fromByteUnits(sector_size);
            const scan_index = try allocator.alignedAlloc(u8, alignment, config.block_size);
            errdefer allocator.free(scan_index);
            const scan_data = try allocator.alignedAlloc(u8, alignment, config.block_size);
            @memset(scan_index, 0);
            @memset(scan_data, 0);
            return .{
                .config = config,
                .blocks_per_table = capacity + 1,
                .table_bytes_max = table_bytes_max,
                .value_size_max = value_size_max,
                .tables = tables,
                .pending = pending,
                .entries = entries,
                .builder = builder,
                .scan_index = scan_index,
                .scan_data = scan_data,
            };
        }

        /// Record bytes (key + value + end offset) one table holds at most.
        fn table_bytes_max_of(block_size: u32) u64 {
            const capacity = Table.index_capacity(block_size);
            const room = grid_module.payload_capacity_of(block_size) - payload_header_size;
            return @as(u64, room) * ((capacity - 1) / 2);
        }

        /// The fewest `Config.tables_max` `init` accepts for these code limits: every code
        /// fits half the table list, so a rewrite always leaves room.
        pub fn tables_max_min(block_size: u32, codes_max: u32, code_bytes_max: u32) u32 {
            const table_bytes_max = table_bytes_max_of(block_size);
            const all_bytes = @as(u64, code_bytes_max) + @as(u64, codes_max) * 36;
            const record_max = 36 + @as(u64, Table.value_size_max(block_size));
            assert(table_bytes_max > 2 * record_max);
            const tables = (all_bytes / (table_bytes_max - record_max) + 1) * 2;
            assert(tables >= 2);
            return @intCast(tables);
        }

        fn manifest_init(allocator: std.mem.Allocator, tables_max: u32, per_table: u32) !Manifest {
            const infos = try allocator.alloc(Info, tables_max);
            errdefer allocator.free(infos);
            const blocks = try allocator.alloc(u64, @as(usize, tables_max) * per_table);
            @memset(blocks, 0);
            return .{ .infos = infos, .blocks = blocks };
        }

        fn manifest_deinit(allocator: std.mem.Allocator, manifest: *Manifest) void {
            allocator.free(manifest.infos);
            allocator.free(manifest.blocks);
        }

        /// Frees memory. Grid IO may be in flight only if the storage dropped it (crash).
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            manifest_deinit(allocator, &self.tables);
            manifest_deinit(allocator, &self.pending);
            allocator.free(self.entries);
            self.builder.deinit(allocator);
            allocator.free(self.scan_index);
            allocator.free(self.scan_data);
            self.* = undefined;
        }

        fn bind(self: *Self, grid: *Grid, free_set: *FreeSet) void {
            assert(grid.config.block_size == self.config.block_size);
            assert(free_set.block_count == self.config.block_count);
            self.grid = grid;
            self.free_set = free_set;
            self.builder.grid = grid;
        }

        /// No tables and nothing flushed: a fresh database, or before a fallback load.
        pub fn reset(self: *Self) void {
            assert(self.flush_state == .idle);
            assert(self.scan_step == .idle);
            self.tables.count = 0;
            self.arena_flushed = 0;
        }

        pub fn flushing(self: *const Self) bool {
            return self.flush_state != .idle;
        }

        /// The codes a checkpoint image must carry: those no table holds.
        pub fn code_filter(self: *const Self) snapshot_module.CodeFilter {
            assert(self.flush_state == .idle or self.arena_flushed <= self.flush_cut);
            return .{ .offset_min = self.arena_flushed, .length_max = self.value_size_max };
        }

        // Manifest (the table list in the database checkpoint).

        pub fn manifest_size(self: *const Self) u32 {
            return 4 + self.tables.count * info_size;
        }

        pub fn manifest_size_max(config: Config) u32 {
            return 4 + config.tables_max * info_size;
        }

        /// Writes the table list: count u32, then each `Info`.
        pub fn manifest_encode(self: *const Self, out: []u8) u32 {
            const size = self.manifest_size();
            assert(out.len >= size);
            std.mem.writeInt(u32, out[0..4], self.tables.count, .little);
            const infos = std.mem.sliceAsBytes(self.tables.infos[0..self.tables.count]);
            @memcpy(out[4..][0..infos.len], infos);
            return size;
        }

        /// Reads a table list (structure only; the blocks are checked by `scan_start`).
        pub fn manifest_decode(self: *Self, bytes: []const u8) error{InvalidManifest}!u32 {
            assert(self.tables.count == 0 and self.arena_flushed == 0);
            if (bytes.len < 4) return error.InvalidManifest;
            const count = std.mem.readInt(u32, bytes[0..4], .little);
            if (count > self.config.tables_max) return error.InvalidManifest;
            const size = 4 + count * info_size;
            if (bytes.len < size) return error.InvalidManifest;
            const infos = self.tables.infos[0..count];
            @memcpy(std.mem.sliceAsBytes(infos), bytes[4..size]);
            for (infos) |*info| {
                if (!self.info_valid(info)) return error.InvalidManifest;
            }
            self.tables.count = count;
            return size;
        }

        fn info_valid(self: *const Self, info: *const Info) bool {
            const address = info.index.address;
            if (address == 0 or address > self.config.block_count) return false;
            if (info.index.reserved != 0 or info.reserved != 0) return false;
            if (info.data_block_count == 0) return false;
            if (info.data_block_count >= self.blocks_per_table) return false;
            if (info.record_count < info.data_block_count) return false;
            return Table.key_order(&info.key_min, &info.key_max) != .gt;
        }

        fn table_blocks(manifest: *const Manifest, per_table: u32, table: u32) []u64 {
            assert(table < manifest.infos.len);
            const count = manifest.infos[table].data_block_count + 1;
            assert(count <= per_table);
            return manifest.blocks[@as(usize, table) * per_table ..][0..count];
        }

        // Open: scan every table into the state's code arena.

        /// Reads every table of the decoded manifest into `state` (no accounts loaded yet),
        /// then calls back with `scan_outcome` (at once when there are no tables). On
        /// `.corrupt` the caller drops the codes (`State.reset_codes`) and `reset`s.
        pub fn scan_start(
            self: *Self,
            grid: *Grid,
            free_set: *FreeSet,
            state: *State,
            callback: Callback,
        ) void {
            assert(self.scan_step == .idle and self.flush_state == .idle);
            assert(state.account_table.count() == 0 and state.code_table.count() == 0);
            self.bind(grid, free_set);
            self.scan_state = state;
            self.scan_callback = callback;
            self.scan_table = 0;
            self.scan_records = 0;
            self.scan_next_table();
        }

        fn scan_next_table(self: *Self) void {
            assert(self.scan_table <= self.tables.count);
            if (self.scan_table == self.tables.count) return self.scan_finish(.loaded);
            const info = &self.tables.infos[self.scan_table];
            self.scan_step = .index;
            self.scan_ordinal = 0;
            const buffer = self.scan_index;
            self.grid.?.read_block(on_scan_read, &self.scan_read, buffer, info.index, .table_index);
        }

        fn on_scan_read(read: *Grid.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("scan_read", read));
            assert(self.scan_step != .idle);
            const payload = read.payload orelse return self.scan_finish(.corrupt);
            const valid = switch (self.scan_step) {
                .index => self.scan_index_block(payload),
                .data => self.scan_data_block(payload),
                .idle => unreachable,
            };
            if (!valid) return self.scan_finish(.corrupt);
            const info = &self.tables.infos[self.scan_table];
            if (self.scan_ordinal == info.data_block_count) {
                self.scan_table += 1;
                return self.scan_next_table();
            }
            const index = self.scan_index[block_header_size..];
            const reference = Table.index_reference(index, self.scan_ordinal);
            self.scan_step = .data;
            const buffer = self.scan_data;
            self.grid.?.read_block(on_scan_read, &self.scan_read, buffer, reference, .table_data);
        }

        /// Checks the index block and records the table's block addresses.
        fn scan_index_block(self: *Self, payload: []const u8) bool {
            const info = &self.tables.infos[self.scan_table];
            if (!Table.index_valid(payload, self.config.block_count)) return false;
            if (Table.index_count(payload) != info.data_block_count) return false;
            if (Table.key_order(Table.index_key(payload, 0), &info.key_min) != .eq) return false;
            const blocks = table_blocks(&self.tables, self.blocks_per_table, self.scan_table);
            blocks[0] = info.index.address;
            for (blocks[1..], 0..) |*address, ordinal| {
                address.* = Table.index_reference(payload, @intCast(ordinal)).address;
            }
            // A block the checkpoint names is acquired and not released in its free set.
            const free_set = self.free_set.?;
            for (blocks) |address| {
                if (!free_set.is_acquired(address) or free_set.is_released(address)) return false;
            }
            self.scan_records = 0;
            return true;
        }

        /// Checks one data block and inserts its codes.
        fn scan_data_block(self: *Self, payload: []const u8) bool {
            const info = &self.tables.infos[self.scan_table];
            if (!Table.data_valid(payload)) return false;
            const state = self.scan_state.?;
            const count = Table.data_count(payload);
            var index: u32 = 0;
            while (index < count) : (index += 1) {
                const record = Table.data_record(payload, index);
                const key = Table.record_key(record);
                const code = record[32..];
                if (code.len == 0 or code.len > self.value_size_max) return false;
                const inserted = state.insert_code(code) catch return false;
                if (!inserted.new or !std.mem.eql(u8, &inserted.hash, key)) return false;
            }
            self.scan_records += count;
            self.scan_ordinal += 1;
            if (self.scan_ordinal < info.data_block_count) return true;
            const last = Table.data_record(payload, count - 1);
            if (Table.key_order(Table.record_key(last), &info.key_max) != .eq) return false;
            return self.scan_records == info.record_count;
        }

        fn scan_finish(self: *Self, outcome: ScanOutcome) void {
            const state = self.scan_state.?;
            self.scan_step = .idle;
            self.scan_outcome = outcome;
            self.scan_state = null;
            // Only table codes are in the arena yet: the tables cover all of it.
            if (outcome == .loaded) self.arena_flushed = state.code_arena_len;
            const callback = self.scan_callback.?;
            self.scan_callback = null;
            callback(self);
        }

        // Flush: new codes (or, on a rewrite, every code) into tables.

        /// Starts writing the codes added since the last flush into tables, at most
        /// `blocks_allowed` blocks before pausing for `grant`. `.done`: nothing to write
        /// (no callback). `.pending`: the callback fires once every table is written.
        pub fn flush_start(
            self: *Self,
            grid: *Grid,
            free_set: *FreeSet,
            state: *const State,
            blocks_allowed: u64,
            callback: Callback,
        ) Status {
            assert(self.flush_state == .idle and self.scan_step == .idle);
            assert(blocks_allowed > 0);
            self.bind(grid, free_set);
            const cut = state.code_arena_len;
            assert(cut >= self.arena_flushed);
            if (cut == self.arena_flushed) return .done;
            const new_bytes = self.collect(state, self.arena_flushed, cut);
            if (self.entries_len == 0) {
                // Only codes too long for a table: they stay in the image (`code_filter`).
                self.arena_flushed = cut;
                return .done;
            }
            if (new_bytes < self.config.flush_bytes_min) {
                self.stats.flushes_small += 1;
                return .done;
            }
            const rewrite = self.tables.count + self.chunk_count() > self.config.tables_max;
            if (rewrite) _ = self.collect(state, 0, cut);
            assert(self.chunk_count() <= self.config.tables_max);
            self.reservation = free_set.reserve(self.blocks_needed()) catch {
                self.stats.flushes_no_space += 1;
                return .done;
            };
            self.flush_state = .building;
            self.flush_rewrite = rewrite;
            self.flush_cut = cut;
            self.flush_arena = state.code_arena;
            self.flush_callback = callback;
            self.pending.count = 0;
            self.cursor = 0;
            self.build_next(blocks_allowed);
            return .pending;
        }

        /// Lets a paced flush write `blocks` more blocks; a no-op when none runs.
        pub fn grant(self: *Self, blocks: u64) void {
            assert(blocks > 0);
            switch (self.flush_state) {
                .idle => {},
                .building => self.builder.grant(blocks),
                .waiting => self.build_next(blocks),
            }
        }

        fn record_size(length: u32) u64 {
            return 32 + 4 + @as(u64, length);
        }

        /// Fills `entries` with the table-sized codes at arena offsets in `[low, high)`,
        /// sorted by hash; returns their code bytes.
        fn collect(self: *Self, state: *const State, low: u32, high: u32) u64 {
            assert(low < high);
            self.entries_len = 0;
            var bytes: u64 = 0;
            var codes = state.code_table.iterator();
            while (codes.next()) |code| {
                const ref = code.value_ptr.*;
                if (ref.offset < low or ref.offset >= high) continue;
                if (ref.len > self.value_size_max) continue;
                assert(self.entries_len < self.entries.len);
                self.entries[self.entries_len] = .{
                    .hash = code.key_ptr.*,
                    .offset = ref.offset,
                    .len = ref.len,
                };
                self.entries_len += 1;
                bytes += ref.len;
            }
            std.mem.sortUnstable(Entry, self.entries[0..self.entries_len], {}, entry_less);
            return bytes;
        }

        fn entry_less(_: void, a: Entry, b: Entry) bool {
            return std.mem.order(u8, &a.hash, &b.hash) == .lt;
        }

        /// The end of the table that starts at entry `start`: records while they fit.
        fn chunk_end_from(self: *const Self, start: u32) u32 {
            assert(start < self.entries_len);
            var bytes: u64 = 0;
            var end = start;
            while (end < self.entries_len) : (end += 1) {
                const size = record_size(self.entries[end].len);
                if (end > start and bytes + size > self.table_bytes_max) break;
                bytes += size;
            }
            assert(end > start);
            return end;
        }

        fn chunk_count(self: *const Self) u32 {
            var count: u32 = 0;
            var start: u32 = 0;
            while (start < self.entries_len) : (count += 1) start = self.chunk_end_from(start);
            assert(count > 0);
            return count;
        }

        /// Blocks the whole flush needs at most (`Table.blocks_max` per table).
        fn blocks_needed(self: *const Self) u64 {
            var blocks: u64 = 0;
            var start: u32 = 0;
            while (start < self.entries_len) {
                const end = self.chunk_end_from(start);
                var bytes: u64 = 0;
                for (self.entries[start..end]) |entry| bytes += 32 + @as(u64, entry.len);
                const table = Table.blocks_max(self.config.block_size, end - start, bytes);
                assert(table <= self.blocks_per_table);
                blocks += table;
                start = end;
            }
            return blocks;
        }

        fn build_next(self: *Self, blocks_allowed: u64) void {
            assert(self.cursor < self.entries_len);
            assert(blocks_allowed > 0);
            self.flush_state = .building;
            self.chunk_end = self.chunk_end_from(self.cursor);
            const source: Table.Source = .{ .context = self, .next = source_next };
            const reservation = &self.reservation;
            const free_set = self.free_set.?;
            self.builder.build_paced(source, free_set, reservation, blocks_allowed, on_built);
        }

        fn source_next(context: *anyopaque) ?Table.Record {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.cursor <= self.chunk_end);
            if (self.cursor == self.chunk_end) return null;
            const entry = &self.entries[self.cursor];
            self.cursor += 1;
            return .{ .key = &entry.hash, .value = self.flush_arena[entry.offset..][0..entry.len] };
        }

        fn on_built(builder: *Table.Builder) void {
            const self: *Self = @alignCast(@fieldParentPtr("builder", builder));
            assert(self.flush_state == .building);
            assert(self.cursor == self.chunk_end);
            // Each table is sized to fit one index block and holds at least one record.
            const info = builder.result catch unreachable;
            const table = self.pending.count;
            self.pending.infos[table] = info;
            self.pending.count += 1;
            const blocks = table_blocks(&self.pending, self.blocks_per_table, table);
            blocks[0] = info.index.address;
            const index = builder.index_block[block_header_size..];
            for (blocks[1..], 0..) |*address, ordinal| {
                address.* = Table.index_reference(index, @intCast(ordinal)).address;
            }
            self.stats.tables_written += 1;
            if (self.cursor < self.entries_len) {
                if (builder.blocks_allowed == 0) {
                    self.flush_state = .waiting;
                    return;
                }
                return self.build_next(builder.blocks_allowed);
            }
            self.flush_finish();
        }

        /// Every table is written: they replace (rewrite) or extend the table list.
        fn flush_finish(self: *Self) void {
            assert(self.flush_state == .building);
            assert(self.pending.count > 0);
            const free_set = self.free_set.?;
            free_set.forfeit(&self.reservation);
            if (self.flush_rewrite) {
                for (0..self.tables.count) |table_index| {
                    const table: u32 = @intCast(table_index);
                    const blocks = table_blocks(&self.tables, self.blocks_per_table, table);
                    for (blocks) |address| free_set.release(address);
                }
                self.tables.count = 0;
                self.stats.rewrites += 1;
            }
            assert(self.tables.count + self.pending.count <= self.config.tables_max);
            for (0..self.pending.count) |table| {
                const target = self.tables.count;
                self.tables.infos[target] = self.pending.infos[table];
                const from = table_blocks(&self.pending, self.blocks_per_table, @intCast(table));
                const to = table_blocks(&self.tables, self.blocks_per_table, target);
                @memcpy(to, from);
                self.tables.count += 1;
            }
            self.pending.count = 0;
            self.arena_flushed = self.flush_cut;
            self.stats.flushes += 1;
            self.flush_state = .idle;
            const callback = self.flush_callback.?;
            self.flush_callback = null;
            callback(self);
        }
    };
}

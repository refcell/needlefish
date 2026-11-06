//! Table builder: pulls a sorted run of records from a `Source` and writes it to the grid as
//! data blocks and one index block (`table.zig` has the formats).
//!
//! The builder is a state machine over the grid: fill a data block, write it, and on the
//! write's completion fill the next; after the last data block, write the index block and
//! report the table's `Info`. Blocks come from a free-set reservation the caller made with
//! `Table.blocks_max`, so the build never runs out of space halfway. The builder never
//! syncs: the caller makes the blocks durable (the engine's checkpoint sync covers every
//! grid write that completed before the checkpoint started).
//!
//! Pacing: `build_paced` writes at most a given number of blocks, then pauses until `grant`
//! allows more, so a table flush can spread over several commits like a paced checkpoint.
//!
//! Memory: one data block, one index block, and one record scratch buffer, allocated at init.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const free_set_module = @import("free_set.zig");

const sector_size = storage.sector_size;
const block_header_size = grid_module.block_header_size;
const FreeSet = free_set_module.FreeSet;
const Reservation = free_set_module.Reservation;
const payload_header_size: u32 = 8;

pub fn BuilderType(comptime Table: type) type {
    const key_size = @sizeOf(Table.Key);
    return struct {
        const Self = @This();

        pub const Callback = *const fn (*Self) void;
        pub const State = enum { idle, writing_data, writing_index };

        grid: *Table.Grid,
        block_size: u32,
        data_block: []align(sector_size) u8,
        index_block: []align(sector_size) u8,
        /// Records of the data block being filled, packed `key ++ value`.
        records: []u8,
        /// End offset (within `records`) of each record of the block being filled.
        ends: []u32,
        records_len: u32 = 0,
        count: u32 = 0,
        state: State = .idle,
        callback: ?Callback = null,
        source: ?Table.Source = null,
        /// A record pulled from the source that did not fit the previous data block.
        pending: ?Table.Record = null,
        source_done: bool = false,
        free_set: ?*FreeSet = null,
        reservation: ?*Reservation = null,
        key_last: Table.Key = undefined,
        info: Table.Info = undefined,
        write: Table.Grid.Write = .{},
        result: anyerror!Table.Info = error.Empty,
        /// Block writes left before the build pauses; what remains is reported after it ends.
        blocks_allowed: u64 = 0,
        /// The build waits for `grant` before its next block.
        paused: bool = false,
        /// Optional: called when a paced build pauses (its last granted block is written), so
        /// an owner that grants one block at a time learns the write completed.
        pause_callback: ?Callback = null,

        pub fn init(allocator: std.mem.Allocator, grid: *Table.Grid) !Self {
            const block_size = grid.config.block_size;
            const data_block = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                block_size,
            );
            errdefer allocator.free(data_block);
            const index_block = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                block_size,
            );
            errdefer allocator.free(index_block);
            const records = try allocator.alloc(u8, block_size);
            errdefer allocator.free(records);
            const ends = try allocator.alloc(u32, block_size / (4 + key_size) + 1);
            @memset(data_block, 0);
            @memset(index_block, 0);
            return .{
                .grid = grid,
                .block_size = block_size,
                .data_block = data_block,
                .index_block = index_block,
                .records = records,
                .ends = ends,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.data_block);
            allocator.free(self.index_block);
            allocator.free(self.records);
            allocator.free(self.ends);
            self.* = undefined;
        }

        /// Builds a table from `source`. On completion `result` holds its `Info`, or
        /// `error.Empty` (no records) or `error.TableTooLarge` (more data blocks than one
        /// index block names). Blocks are acquired from `reservation`; the caller forfeits
        /// what is left (and, on error, releases nothing: no block was referenced yet, but
        /// the acquired ones stay acquired until the caller releases them).
        pub fn build(
            self: *Self,
            source: Table.Source,
            free_set: *FreeSet,
            reservation: *Reservation,
            callback: Callback,
        ) void {
            self.build_paced(source, free_set, reservation, std.math.maxInt(u64), callback);
        }

        /// Like `build`, but writes at most `blocks_allowed` blocks before it pauses for
        /// `grant`. After the callback, `blocks_allowed` holds the unused allowance.
        pub fn build_paced(
            self: *Self,
            source: Table.Source,
            free_set: *FreeSet,
            reservation: *Reservation,
            blocks_allowed: u64,
            callback: Callback,
        ) void {
            assert(blocks_allowed > 0);
            assert(self.state == .idle);
            self.blocks_allowed = blocks_allowed;
            self.paused = false;
            assert(self.callback == null);
            self.source = source;
            self.free_set = free_set;
            self.reservation = reservation;
            self.callback = callback;
            self.pending = null;
            self.source_done = false;
            self.info = std.mem.zeroes(Table.Info);
            write_u32(self.index_block[block_header_size..], 0, 0);
            write_u32(self.index_block[block_header_size..], 4, 0);
            self.state = .writing_data;
            self.next_data_block();
        }

        /// Lets a paced build write `blocks` more blocks (saturating); resumes it if paused.
        pub fn grant(self: *Self, blocks: u64) void {
            assert(blocks > 0);
            self.blocks_allowed +|= blocks;
            if (!self.paused) return;
            assert(self.state == .writing_data);
            self.paused = false;
            self.next_data_block();
        }

        /// Spends one block of the allowance on the write about to be submitted.
        fn spend_block(self: *Self) void {
            assert(self.blocks_allowed > 0);
            assert(!self.paused);
            self.blocks_allowed -= 1;
        }

        fn room(self: *const Self) u32 {
            return grid_module.payload_capacity_of(self.block_size) - payload_header_size;
        }

        /// Pulls records until the next one does not fit; returns how many the block holds.
        fn fill(self: *Self) u32 {
            self.count = 0;
            self.records_len = 0;
            var pulls: u64 = 0;
            while (!self.source_done) : (pulls += 1) {
                assert(pulls <= self.ends.len);
                const source = self.source.?;
                const record = self.pending orelse source.next(source.context) orelse {
                    self.source_done = true;
                    break;
                };
                self.pending = null;
                assert(record.value.len <= Table.value_size_max(self.block_size));
                const size: u32 = @intCast(key_size + record.value.len);
                if (self.records_len + size + 4 * (self.count + 1) > self.room()) {
                    assert(self.count > 0);
                    self.pending = record;
                    break;
                }
                if (self.info.record_count > 0 or self.count > 0) {
                    assert(Table.key_order(&self.key_last, record.key) == .lt);
                }
                self.key_last = record.key.*;
                @memcpy(self.records[self.records_len..][0..key_size], record.key);
                const value_start = self.records_len + key_size;
                @memcpy(self.records[value_start..][0..record.value.len], record.value);
                self.records_len += size;
                self.ends[self.count] = self.records_len;
                self.count += 1;
            }
            return self.count;
        }

        fn next_data_block(self: *Self) void {
            assert(self.state == .writing_data);
            const index_payload = self.index_block[block_header_size..];
            const data_blocks = read_u32(index_payload, 0);
            const first_record = self.info.record_count;
            if (self.fill() == 0) return self.write_index();
            if (data_blocks == Table.index_capacity(self.block_size)) {
                return self.finish(error.TableTooLarge);
            }
            const payload = self.data_block[block_header_size..];
            const ends_size = 4 * self.count;
            write_u32(payload, 0, self.count);
            write_u32(payload, 4, 0);
            for (self.ends[0..self.count], 0..) |end, index| {
                write_u32(payload, payload_header_size + 4 * index, end + payload_header_size +
                    ends_size);
            }
            const records_start = payload_header_size + ends_size;
            const records = self.records[0..self.records_len];
            @memcpy(payload[records_start..][0..records.len], records);
            const payload_size = records_start + self.records_len;
            assert(Table.data_valid(payload[0..payload_size]));

            const address = self.free_set.?.acquire(self.reservation.?);
            const reference = grid_module.seal(
                self.data_block,
                self.grid.format_id,
                address,
                .table_data,
                payload_size,
            );
            // Index entry: the block's first key and its reference.
            const entry = payload_header_size + data_blocks * Table.index_entry_size;
            @memcpy(index_payload[entry..][0..key_size], self.records[0..key_size]);
            @memcpy(
                index_payload[entry + key_size ..][0..@sizeOf(grid_module.Reference)],
                std.mem.asBytes(&reference),
            );
            write_u32(index_payload, 0, data_blocks + 1);
            if (first_record == 0) self.info.key_min = self.records[0..key_size].*;
            self.info.key_max = self.key_last;
            self.info.record_count += self.count;
            self.info.data_block_count = data_blocks + 1;
            self.spend_block();
            self.grid.write_block(on_write, &self.write, self.data_block, address);
        }

        fn write_index(self: *Self) void {
            assert(self.state == .writing_data);
            const index_payload = self.index_block[block_header_size..];
            const data_blocks = read_u32(index_payload, 0);
            if (data_blocks == 0) return self.finish(error.Empty);
            const payload_size = payload_header_size + data_blocks * Table.index_entry_size;
            assert(Table.index_valid(index_payload[0..payload_size], self.grid.config.block_count));
            const address = self.free_set.?.acquire(self.reservation.?);
            self.info.index = grid_module.seal(
                self.index_block,
                self.grid.format_id,
                address,
                .table_index,
                payload_size,
            );
            self.state = .writing_index;
            self.spend_block();
            self.grid.write_block(on_write, &self.write, self.index_block, address);
        }

        fn on_write(write: *Table.Grid.Write) void {
            const self: *Self = @alignCast(@fieldParentPtr("write", write));
            switch (self.state) {
                .writing_data => {
                    // The next step writes one block (data or index) or none (an error).
                    if (self.blocks_allowed == 0) {
                        self.paused = true;
                        // Last: the owner may `grant` from inside the callback.
                        if (self.pause_callback) |callback| callback(self);
                        return;
                    }
                    self.next_data_block();
                },
                .writing_index => self.finish(self.info),
                .idle => unreachable,
            }
        }

        fn finish(self: *Self, result: anyerror!Table.Info) void {
            assert(self.state != .idle);
            const callback = self.callback.?;
            self.result = result;
            self.state = .idle;
            self.callback = null;
            self.source = null;
            self.pending = null;
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

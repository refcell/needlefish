//! Table reader: point lookups and range scans over one table, through the block cache.
//!
//! One operation at a time per reader. Each step needs one block (the index block, then a
//! data block); a cached block is used at once, otherwise the reader reads it into its own
//! buffer, verifies it (grid checks, then `data_valid`/`index_valid`), caches a copy, and
//! continues from the read's completion. So an operation whose blocks are all cached
//! completes inside `lookup`/`scan` (returning `.done`, no callback), and one that reads
//! completes from a storage tick (returning `.pending`, callback later). A cache refill
//! never waits on a write.
//!
//! Values (and scanned records) point into the cache and stay valid until the next cache
//! `put`, that is, until the caller's next read operation on that cache.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const table_module = @import("table.zig");

const sector_size = storage.sector_size;
const Reference = grid_module.Reference;
const BlockKind = grid_module.BlockKind;
const BlockCache = table_module.BlockCache;

pub const Status = enum { done, pending };

pub fn ReaderType(comptime Table: type) type {
    const key_size = @sizeOf(Table.Key);
    return struct {
        const Self = @This();

        pub const Callback = *const fn (*Self) void;
        pub const Operation = enum { idle, lookup, scan };
        pub const Visitor = struct {
            context: *anyopaque,
            /// Receives each record in key order; returns false to stop the scan.
            visit: *const fn (context: *anyopaque, key: *const Table.Key, value: []const u8) bool,
        };

        grid: *Table.Grid,
        cache: *BlockCache,
        buffer: []align(sector_size) u8,
        read: Table.Grid.Read = .{},
        operation: Operation = .idle,
        reading: bool = false,
        /// The operation started a read, so it completes through the callback.
        asynchronous: bool = false,
        callback: ?Callback = null,
        info: Table.Info = undefined,
        key: Table.Key = undefined,
        key_last: Table.Key = undefined,
        visitor: ?Visitor = null,
        /// Scan: the data block to visit next (an index ordinal), and whether it is the first.
        ordinal: u32 = 0,
        scan_first: bool = true,
        /// Lookup: the value found (null when absent). Scan: unused.
        value: ?[]const u8 = null,
        result: table_module.Error!void = {},

        pub fn init(allocator: std.mem.Allocator, grid: *Table.Grid, cache: *BlockCache) !Self {
            assert(cache.block_size == grid.config.block_size);
            const buffer = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                grid.config.block_size,
            );
            @memset(buffer, 0);
            return .{ .grid = grid, .cache = cache, .buffer = buffer };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(!self.reading);
            allocator.free(self.buffer);
            self.* = undefined;
        }

        /// Finds `key`. On `.done` (or in the callback after `.pending`), `result` and `value`
        /// hold the outcome.
        pub fn lookup(
            self: *Self,
            info: *const Table.Info,
            key: *const Table.Key,
            callback: Callback,
        ) Status {
            assert(self.operation == .idle);
            assert(!self.reading);
            self.begin(.lookup, info, callback);
            self.key = key.*;
            const outside = Table.key_order(key, &info.key_min) == .lt or
                Table.key_order(key, &info.key_max) == .gt;
            if (outside) return self.complete({});
            return self.advance();
        }

        /// Visits every record with `key_first <= key <= key_last` in order, until the visitor
        /// returns false.
        pub fn scan(
            self: *Self,
            info: *const Table.Info,
            key_first: *const Table.Key,
            key_last: *const Table.Key,
            visitor: Visitor,
            callback: Callback,
        ) Status {
            assert(self.operation == .idle);
            assert(Table.key_order(key_first, key_last) != .gt);
            self.begin(.scan, info, callback);
            self.key = key_first.*;
            self.key_last = key_last.*;
            self.visitor = visitor;
            self.ordinal = std.math.maxInt(u32); // Resolved from the index block.
            self.scan_first = true;
            const outside = Table.key_order(key_last, &info.key_min) == .lt or
                Table.key_order(key_first, &info.key_max) == .gt;
            if (outside) return self.complete({});
            return self.advance();
        }

        fn begin(
            self: *Self,
            operation: Operation,
            info: *const Table.Info,
            callback: Callback,
        ) void {
            assert(info.data_block_count > 0);
            self.operation = operation;
            self.info = info.*;
            self.callback = callback;
            self.value = null;
            self.result = {};
            self.asynchronous = false;
        }

        /// The verified payload of `reference`, from the cache; or null after starting a read.
        fn block(self: *Self, reference: Reference, kind: BlockKind) ?[]const u8 {
            if (self.cache.get(reference)) |cached| return payload_of(cached);
            self.reading = true;
            self.asynchronous = true;
            self.grid.read_block(on_read, &self.read, self.buffer, reference, kind);
            return null;
        }

        fn payload_of(block_bytes: []const u8) []const u8 {
            const header: *const grid_module.BlockHeader = @ptrCast(@alignCast(
                block_bytes[0..grid_module.block_header_size],
            ));
            return block_bytes[grid_module.block_header_size..][0..header.payload_size];
        }

        fn on_read(read: *Table.Grid.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("read", read));
            assert(self.reading);
            self.reading = false;
            const payload = read.payload orelse {
                _ = self.complete(error.Corrupt);
                return;
            };
            const valid = switch (read.kind) {
                .table_index => Table.index_valid(payload, self.grid.config.block_count),
                .table_data => Table.data_valid(payload),
                _ => false,
            };
            if (!valid) {
                _ = self.complete(error.Corrupt);
                return;
            }
            const length = grid_module.block_header_size + payload.len;
            _ = self.cache.put(read.reference, self.buffer[0..length]);
            // The block is cached now: the next step finds it there.
            _ = self.advance();
        }

        /// Runs steps until one needs a read (`.pending`) or the operation completes.
        fn advance(self: *Self) Status {
            var steps: u32 = 0;
            // Bounded: each data block is visited once, plus one index step per data block.
            while (steps <= 2 * self.info.data_block_count + 2) : (steps += 1) {
                const index = self.block(self.info.index, .table_index) orelse return .pending;
                if (self.ordinal == std.math.maxInt(u32)) {
                    self.ordinal = Table.index_find(index, &self.key) orelse 0;
                }
                if (self.operation == .lookup) {
                    const found = Table.index_find(index, &self.key);
                    self.ordinal = found orelse return self.complete({});
                }
                if (self.ordinal >= Table.index_count(index)) return self.complete({});
                const reference = Table.index_reference(index, self.ordinal);
                const data = self.block(reference, .table_data) orelse return .pending;
                if (self.operation == .lookup) {
                    self.value = Table.data_search(data, &self.key);
                    return self.complete({});
                }
                if (!self.scan_data(data)) return self.complete({});
                self.ordinal += 1;
                self.scan_first = false;
            }
            unreachable; // The loop bound covers every data block.
        }

        /// Visits the in-range records of one data block; false when the scan is over.
        fn scan_data(self: *Self, data: []const u8) bool {
            const count = Table.data_count(data);
            var index: u32 = if (self.scan_first) Table.data_lower_bound(data, &self.key) else 0;
            while (index < count) : (index += 1) {
                const record = Table.data_record(data, index);
                const key = Table.record_key(record);
                if (Table.key_order(key, &self.key_last) == .gt) return false;
                if (!self.visitor.?.visit(self.visitor.?.context, key, record[key_size..])) {
                    return false;
                }
            }
            return true;
        }

        /// Ends the operation; calls back only if it went asynchronous.
        fn complete(self: *Self, result: table_module.Error!void) Status {
            assert(self.operation != .idle);
            assert(!self.reading);
            self.result = result;
            self.operation = .idle;
            self.visitor = null;
            const callback = self.callback.?;
            self.callback = null;
            if (self.asynchronous) callback(self);
            return .done;
        }
    };
}

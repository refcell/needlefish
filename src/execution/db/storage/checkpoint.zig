//! Checkpoints: full snapshots streamed into one of two zones (A/B).
//!
//! The writer pulls bytes from a producer into fixed-size blocks. Each block starts with a
//! header (checksum, format id, checkpoint sequence, block index, payload size) and is
//! written sequentially at `zone_offset + index * block_size`; only the used sectors of a
//! block are written. After the last block a sync makes the snapshot durable, and the result
//! (zone, size, checksum of the whole payload stream, sequence) goes into the superblock.
//!
//! The reader re-derives the block count from the size, verifies every block (including
//! index and sequence, so blocks left over from an older checkpoint in the same zone are
//! rejected) and the total checksum. A new checkpoint always goes into the zone the current
//! superblock does not name, so the live checkpoint is never overwritten.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const checksum_module = @import("checksum.zig");
const superblock_module = @import("superblock.zig");

const sector_size = storage.sector_size;
pub const Checkpoint = superblock_module.Checkpoint;

/// "nfchkpnt" read as a little-endian u64.
pub const magic: u64 = 0x746e_706b_6863_666e;

pub const BlockHeader = extern struct {
    /// Checksum of the header bytes after this field followed by the payload.
    checksum: u128,
    format_id: u128,
    magic: u64,
    checkpoint_sequence: u64,
    block_index: u64,
    payload_size: u32,
    reserved_a: u32,
    reserved: [64]u8,

    pub fn compute_checksum(header: *const BlockHeader, payload: []const u8) u128 {
        assert(payload.len == header.payload_size);
        var stream = checksum_module.Stream.init();
        stream.update(std.mem.asBytes(header)[@sizeOf(u128)..]);
        stream.update(payload);
        return stream.final();
    }
};

pub const block_header_size: u32 = @sizeOf(BlockHeader);

comptime {
    assert(block_header_size == 128);
    assert(block_header_size < sector_size);
}

pub const Config = struct {
    /// Absolute storage offsets of zone A and zone B.
    zone_offsets: [2]u64,
    zone_size_bytes: u64,
    block_size: u32,
};

pub const Producer = struct {
    context: *anyopaque,
    /// Fills a prefix of `buffer` and returns its length; zero means the snapshot is complete.
    produce: *const fn (context: *anyopaque, buffer: []u8) u32,
};

pub const Consumer = struct {
    context: *anyopaque,
    /// Receives the next verified chunk of the snapshot, valid only during the call.
    consume: *const fn (context: *anyopaque, chunk: []const u8) void,
};

pub const Error = error{ CheckpointTooLarge, CheckpointCorrupt };

pub fn payload_capacity(block_size: u32) u32 {
    assert(block_size > block_header_size);
    return block_size - block_header_size;
}

/// Number of blocks a checkpoint of `size_bytes` occupies.
pub fn block_count(size_bytes: u64, block_size: u32) u64 {
    const capacity = payload_capacity(block_size);
    return std.math.divCeil(u64, size_bytes, capacity) catch unreachable; // capacity > 0.
}

pub fn CheckpointType(comptime Storage: type) type {
    storage.assert_interface(Storage);
    return struct {
        const Self = @This();

        pub const Callback = *const fn (*Self) void;
        pub const read_attempts_max: u32 = 4;
        pub const State = enum { idle, writing, syncing, reading };

        storage: *Storage,
        config: Config,
        buffer: []align(sector_size) u8,
        state: State = .idle,
        callback: ?Callback = null,
        read: storage.Read = .{},
        write: storage.Write = .{},
        sync: storage.Sync = .{},
        format_id: u128 = 0,
        /// Writing: the checkpoint being built. Reading: the checkpoint expected.
        checkpoint: Checkpoint = .{},
        block_index: u64 = 0,
        size_bytes: u64 = 0,
        total: checksum_module.Stream = undefined,
        producer: ?Producer = null,
        producer_done: bool = false,
        consumer: ?Consumer = null,
        read_attempts: u32 = 0,
        result: Error!void = {},

        pub fn init(allocator: std.mem.Allocator, storage_: *Storage, config: Config) !Self {
            assert(config.block_size % sector_size == 0);
            assert(config.block_size > block_header_size);
            assert(config.zone_size_bytes % config.block_size == 0);
            assert(config.zone_size_bytes >= config.block_size);
            for (config.zone_offsets) |offset| {
                assert(offset % sector_size == 0);
                assert(offset + config.zone_size_bytes <= storage_.size_bytes());
            }
            const buffer = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                config.block_size,
            );
            @memset(buffer, 0);
            return .{ .storage = storage_, .config = config, .buffer = buffer };
        }

        /// May run with an operation in flight: after a simulated crash the storage has
        /// dropped it and will never call back.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(self.buffer.len > 0);
            allocator.free(self.buffer);
            self.* = undefined;
        }

        pub fn blocks_max(self: *const Self) u64 {
            return self.config.zone_size_bytes / self.config.block_size;
        }

        /// Streams a snapshot from `producer` into `zone`. On completion `result` is set and,
        /// on success, `checkpoint` describes the durable snapshot.
        pub fn write_start(
            self: *Self,
            format_id: u128,
            zone: u8,
            sequence: u64,
            producer: Producer,
            callback: Callback,
        ) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(zone <= 1);
            assert(sequence > 0);
            self.format_id = format_id;
            self.checkpoint = .{ .zone = zone, .sequence = sequence };
            self.block_index = 0;
            self.size_bytes = 0;
            self.total = .init();
            self.producer = producer;
            self.producer_done = false;
            self.result = {};
            self.callback = callback;
            self.state = .writing;
            self.write_block();
        }

        fn write_block(self: *Self) void {
            assert(self.state == .writing);
            assert(!self.producer_done);
            const payload = self.buffer[block_header_size..];
            const filled = self.fill(payload);
            if (filled == 0) {
                assert(self.producer_done);
                self.state = .syncing;
                return self.storage.sync(on_sync, &self.sync);
            }
            if (self.block_index >= self.blocks_max()) {
                self.result = error.CheckpointTooLarge;
                return self.finish();
            }
            const header: *BlockHeader = @ptrCast(self.buffer[0..block_header_size]);
            header.* = std.mem.zeroes(BlockHeader);
            header.format_id = self.format_id;
            header.magic = magic;
            header.checkpoint_sequence = self.checkpoint.sequence;
            header.block_index = self.block_index;
            header.payload_size = filled;
            header.checksum = header.compute_checksum(payload[0..filled]);
            self.total.update(payload[0..filled]);
            self.size_bytes += filled;

            const length = storage.sector_ceil(block_header_size + filled);
            @memset(self.buffer[block_header_size + filled .. @intCast(length)], 0);
            self.storage.write_sectors(
                on_write,
                &self.write,
                self.buffer[0..@intCast(length)],
                self.block_offset(self.checkpoint.zone, self.block_index),
            );
        }

        /// Pulls from the producer until `payload` is full or the producer is done.
        fn fill(self: *Self, payload: []u8) u32 {
            var filled: u32 = 0;
            var calls: u64 = 0;
            while (filled < payload.len and !self.producer_done) : (calls += 1) {
                assert(calls <= payload.len); // Every call but the last makes progress.
                const produced = self.producer.?.produce(
                    self.producer.?.context,
                    payload[filled..],
                );
                assert(produced <= payload.len - filled);
                if (produced == 0) self.producer_done = true;
                filled += produced;
            }
            return filled;
        }

        fn on_write(write: *storage.Write) void {
            const self: *Self = @alignCast(@fieldParentPtr("write", write));
            assert(self.state == .writing);
            self.block_index += 1;
            if (!self.producer_done) return self.write_block();
            self.state = .syncing;
            self.storage.sync(on_sync, &self.sync);
        }

        fn on_sync(sync: *storage.Sync) void {
            const self: *Self = @alignCast(@fieldParentPtr("sync", sync));
            assert(self.state == .syncing);
            assert(block_count(self.size_bytes, self.config.block_size) == self.block_index);
            self.checkpoint.size_bytes = self.size_bytes;
            self.checkpoint.checksum = self.total.final();
            self.producer = null;
            self.finish();
        }

        /// Streams the verified snapshot `checkpoint` into `consumer`. Requires a non-empty
        /// checkpoint (an empty one has nothing to read; compare its checksum directly).
        pub fn read_start(
            self: *Self,
            format_id: u128,
            checkpoint: Checkpoint,
            consumer: Consumer,
            callback: Callback,
        ) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(checkpoint.size_bytes > 0);
            assert(checkpoint.sequence > 0);
            // The caller rejects a superblock naming a checkpoint larger than a zone.
            assert(block_count(checkpoint.size_bytes, self.config.block_size) <= self.blocks_max());
            self.format_id = format_id;
            self.checkpoint = checkpoint;
            self.block_index = 0;
            self.size_bytes = 0;
            self.total = .init();
            self.consumer = consumer;
            self.result = {};
            self.callback = callback;
            self.state = .reading;
            self.read_attempts = 0;
            self.read_block();
        }

        fn payload_expected(self: *const Self) u32 {
            const capacity = payload_capacity(self.config.block_size);
            const remaining = self.checkpoint.size_bytes - self.size_bytes;
            assert(remaining > 0);
            return @intCast(@min(capacity, remaining));
        }

        fn read_block(self: *Self) void {
            assert(self.state == .reading);
            self.read_attempts += 1;
            const length = storage.sector_ceil(block_header_size + self.payload_expected());
            self.storage.read_sectors(
                on_read,
                &self.read,
                self.buffer[0..@intCast(length)],
                self.block_offset(self.checkpoint.zone, self.block_index),
            );
        }

        fn on_read(read: *storage.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("read", read));
            assert(self.state == .reading);
            const payload_size = self.payload_expected();
            const payload = self.buffer[block_header_size..][0..payload_size];
            if (!self.block_valid(payload_size)) {
                if (self.read_attempts < read_attempts_max) return self.read_block();
                self.result = error.CheckpointCorrupt;
                self.consumer = null;
                return self.finish();
            }
            self.total.update(payload);
            self.size_bytes += payload_size;
            self.block_index += 1;
            self.consumer.?.consume(self.consumer.?.context, payload);
            if (self.size_bytes < self.checkpoint.size_bytes) {
                self.read_attempts = 0;
                return self.read_block();
            }
            assert(self.size_bytes == self.checkpoint.size_bytes);
            if (self.total.final() != self.checkpoint.checksum) {
                self.result = error.CheckpointCorrupt;
            }
            self.consumer = null;
            self.finish();
        }

        fn block_valid(self: *const Self, payload_size: u32) bool {
            const header: *const BlockHeader = @ptrCast(self.buffer[0..block_header_size]);
            if (header.payload_size != payload_size) return false;
            const payload = self.buffer[block_header_size..][0..payload_size];
            if (header.checksum != header.compute_checksum(payload)) return false;
            if (header.magic != magic or header.format_id != self.format_id) return false;
            if (header.checkpoint_sequence != self.checkpoint.sequence) return false;
            if (header.block_index != self.block_index) return false;
            if (header.reserved_a != 0) return false;
            for (header.reserved) |byte| {
                if (byte != 0) return false;
            }
            return true;
        }

        fn block_offset(self: *const Self, zone: u8, index: u64) u64 {
            assert(zone <= 1);
            assert(index < self.blocks_max());
            return self.config.zone_offsets[zone] + index * self.config.block_size;
        }

        fn finish(self: *Self) void {
            assert(self.state != .idle);
            const callback = self.callback.?;
            self.state = .idle;
            self.callback = null;
            callback(self);
        }
    };
}

const testing = std.testing;
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;

const TestCheckpoint = CheckpointType(SimStorage);
const test_block_size = 2 * sector_size;
const test_zone_size = 8 * test_block_size;

const Harness = struct {
    checkpoint: TestCheckpoint,
    done: bool = false,
    source: []const u8 = &.{},
    source_position: usize = 0,
    sink: [test_zone_size]u8 = undefined,
    sink_size: usize = 0,
    prng: Prng,

    fn on_done(checkpoint: *TestCheckpoint) void {
        const self: *Harness = @alignCast(@fieldParentPtr("checkpoint", checkpoint));
        self.done = true;
    }

    fn produce(context: *anyopaque, buffer: []u8) u32 {
        const self: *Harness = @ptrCast(@alignCast(context));
        const remaining = self.source.len - self.source_position;
        // Uneven chunks, to exercise block packing.
        const step = @min(remaining, buffer.len, self.prng.range(1, 3000));
        @memcpy(buffer[0..step], self.source[self.source_position..][0..step]);
        self.source_position += step;
        return @intCast(step);
    }

    fn consume(context: *anyopaque, chunk: []const u8) void {
        const self: *Harness = @ptrCast(@alignCast(context));
        @memcpy(self.sink[self.sink_size..][0..chunk.len], chunk);
        self.sink_size += chunk.len;
    }

    fn wait(self: *Harness, sim: *SimStorage) !void {
        var ticks: u32 = 0;
        while (!self.done) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            sim.tick();
        }
        self.done = false;
    }

    fn write(self: *Harness, sim: *SimStorage, zone: u8, sequence: u64, source: []const u8) !void {
        self.source = source;
        self.source_position = 0;
        const producer: Producer = .{ .context = self, .produce = produce };
        self.checkpoint.write_start(9, zone, sequence, producer, on_done);
        try self.wait(sim);
    }

    fn read(self: *Harness, sim: *SimStorage, checkpoint: Checkpoint) !void {
        self.sink_size = 0;
        const consumer: Consumer = .{ .context = self, .consume = consume };
        self.checkpoint.read_start(9, checkpoint, consumer, on_done);
        try self.wait(sim);
    }
};

fn setup(sim: *SimStorage) !*Harness {
    const harness = try testing.allocator.create(Harness);
    harness.* = .{
        .prng = Prng.init(11),
        .checkpoint = try .init(testing.allocator, sim, .{
            .zone_offsets = .{ 0, test_zone_size },
            .zone_size_bytes = test_zone_size,
            .block_size = test_block_size,
        }),
    };
    return harness;
}

fn teardown(harness: *Harness) void {
    harness.checkpoint.deinit(testing.allocator);
    testing.allocator.destroy(harness);
}

test "checkpoint: write then read round trip at many sizes" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = 2 * test_zone_size,
        .seed = 1,
    });
    defer sim.deinit(testing.allocator);
    const harness = try setup(&sim);
    defer teardown(harness);
    var prng = Prng.init(1);
    var source: [8 * payload_capacity(test_block_size)]u8 = undefined;
    prng.fill(&source);
    const capacity = payload_capacity(test_block_size);
    const sizes = [_]usize{
        1,            100,          capacity - 1, capacity,
        capacity + 1, 3 * capacity, source.len,
    };
    for (sizes, 0..) |size, index| {
        const zone: u8 = @intCast(index % 2);
        try harness.write(&sim, zone, index + 1, source[0..size]);
        try harness.checkpoint.result;
        const checkpoint = harness.checkpoint.checkpoint;
        try testing.expectEqual(@as(u64, size), checkpoint.size_bytes);
        try testing.expectEqual(checksum_module.checksum(source[0..size]), checkpoint.checksum);
        try testing.expectEqual(zone, checkpoint.zone);
        try testing.expectEqual(@as(u32, 0), sim.unsynced_sector_count());
        try harness.read(&sim, checkpoint);
        try harness.checkpoint.result;
        try testing.expectEqualSlices(u8, source[0..size], harness.sink[0..harness.sink_size]);
    }
}

test "checkpoint: too large, corrupt block, stale sequence are rejected" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = 2 * test_zone_size,
        .seed = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try setup(&sim);
    defer teardown(harness);
    var prng = Prng.init(2);
    var source: [9 * payload_capacity(test_block_size)]u8 = undefined;
    prng.fill(&source);
    try harness.write(&sim, 0, 1, &source);
    try testing.expectError(error.CheckpointTooLarge, harness.checkpoint.result);

    const size = 3 * payload_capacity(test_block_size);
    try harness.write(&sim, 1, 2, source[0..size]);
    try harness.checkpoint.result;
    const good = harness.checkpoint.checkpoint;

    var stale = good;
    stale.sequence = 3;
    try harness.read(&sim, stale);
    try testing.expectError(error.CheckpointCorrupt, harness.checkpoint.result);

    var wrong_total = good;
    wrong_total.checksum ^= 1;
    try harness.read(&sim, wrong_total);
    try testing.expectError(error.CheckpointCorrupt, harness.checkpoint.result);

    // The second block's first sector holds header and payload bytes only.
    sim.corrupt_sector(@intCast((test_zone_size + test_block_size) / sector_size));
    try harness.read(&sim, good);
    try testing.expectError(error.CheckpointCorrupt, harness.checkpoint.result);
    // Only verified blocks reached the consumer: exactly the first one.
    try testing.expectEqual(@as(usize, payload_capacity(test_block_size)), harness.sink_size);
}

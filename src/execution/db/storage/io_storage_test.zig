//! IoStorage tests: the storage engine end to end over `utilities.io`.
//!
//! - `FlakyIo`: a deterministic in-memory IO double that returns short reads and writes and
//!   transient errors, to exercise resubmission and retry paths.
//! - `SimIo`: the IO simulator's disk, with crashes that keep only fsynced data. Each seed
//!   crashes at a random point and checks recovery to a state between the last acknowledged
//!   and the last submitted commit.
//! - The production backend (kqueue or io_uring) on a real temporary file: format, commit,
//!   checkpoint, close, reopen the file, and replay.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const engine_module = @import("engine.zig");
const checkpoint_module = @import("checkpoint.zig");
const IoStorageType = @import("io_storage.zig").IoStorageType;
const io_root = @import("../../../utilities/io/root.zig");
const io_common = @import("../../../utilities/io/common.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const sector_size = storage.sector_size;
const SimIo = io_root.SimIo;

const body_size_max = 300;
const entries_max = 256;
const state_size = 4096;
/// A snapshot is the entry sequence it covers followed by the state.
const snapshot_size = 8 + state_size;

const config: engine_module.Config = .{
    .journal_size_bytes = 16 * sector_size,
    .checkpoint_zone_size_bytes = 2 * 2 * sector_size,
    .entry_body_size_max = body_size_max,
    .checkpoint_block_size = 2 * sector_size,
};

comptime {
    const capacity = checkpoint_module.payload_capacity(config.checkpoint_block_size);
    assert(snapshot_size <= 2 * capacity);
}

/// A deterministic IO double over one in-memory file. Every read or write transfers a
/// random prefix (often short) or fails transiently; nothing is lost on fsync.
const FlakyIo = struct {
    pub const Fd = u32;
    pub const Completion = struct {
        pub const Fd = u32;
        operation: io_common.Operation(u32) = .none,
        result: io_common.Result(u32) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
    };
    const methods = io_common.Methods(FlakyIo);
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;

    prng: Prng,
    disk: []u8,
    file_size: u64 = 0,
    pending_head: ?*Completion = null,
    pending_count: u32 = 0,
    error_numerator: u32 = 1,
    short_numerator: u32 = 1,

    pub fn enqueue(io: *FlakyIo, completion: *Completion) void {
        assert(completion.next == null);
        completion.next = io.pending_head;
        io.pending_head = completion;
        io.pending_count += 1;
    }

    /// Completes every operation pending at entry, in LIFO order.
    pub fn tick(io: *FlakyIo) error{}!void {
        var head = io.pending_head;
        const count = io.pending_count;
        io.pending_head = null;
        io.pending_count = 0;
        var completed: u32 = 0;
        while (head) |completion| : (completed += 1) {
            assert(completed < count);
            head = completion.next;
            completion.next = null;
            io.perform(completion);
            io_common.complete(Completion, completion);
        }
    }

    fn perform(io: *FlakyIo, completion: *Completion) void {
        const failed = io.prng.chance(io.error_numerator, 8);
        completion.result = switch (completion.operation) {
            .read => |op| .{ .read = if (failed) error.InputOutput else io.do_read(op) },
            .write => |op| .{ .write = if (failed) error.SystemResources else io.do_write(op) },
            .fsync => .{ .fsync = {} },
            else => unreachable,
        };
    }

    fn transfer_size(io: *FlakyIo, length: usize) usize {
        if (!io.prng.chance(io.short_numerator, 2)) return length;
        return @intCast(io.prng.range(1, length));
    }

    pub fn read_now(io: *FlakyIo, fd: Fd, buffer: []u8, offset: u64) io_common.ReadError!usize {
        assert(fd == 0);
        if (io.prng.chance(io.error_numerator, 8)) return error.InputOutput;
        return io.do_read(.{ .buffer = buffer, .offset = offset });
    }

    fn do_read(io: *FlakyIo, op: anytype) usize {
        if (op.offset >= io.file_size) return 0;
        const available: usize = @intCast(io.file_size - op.offset);
        const size = io.transfer_size(@min(op.buffer.len, available));
        @memcpy(op.buffer[0..size], io.disk[@intCast(op.offset)..][0..size]);
        return size;
    }

    fn do_write(io: *FlakyIo, op: anytype) usize {
        const size = io.transfer_size(op.buffer.len);
        @memcpy(io.disk[@intCast(op.offset)..][0..size], op.buffer[0..size]);
        io.file_size = @max(io.file_size, op.offset + size);
        return size;
    }
};

fn apply(state: *[state_size]u8, sequence: u64, body: []const u8) void {
    const start = sequence *% 7919 % state_size;
    for (body, 0..) |byte, index| state[(start + index) % state_size] ^= byte;
    state[sequence % state_size] +%= 1;
}

fn HarnessType(comptime IO: type) type {
    return struct {
        const Harness = @This();
        pub const Storage = IoStorageType(IO);
        const Engine = engine_module.EngineType(Storage);

        io: *IO,
        storage: Storage,
        engine: Engine,
        prng: Prng,
        bodies: [entries_max][body_size_max]u8 = undefined,
        sizes: [entries_max]u32 = undefined,
        submitted: u64 = 0,
        acknowledged: u64 = 0,
        /// State after entry `acknowledged`.
        state: [state_size]u8 = @splat(0),
        phase_done: bool = false,
        commit_pending: bool = false,
        checkpoint_requested: bool = false,
        checkpoints: u32 = 0,
        snapshot: [snapshot_size]u8 = undefined,
        snapshot_position: u32 = 0,
        recovered: [snapshot_size]u8 = undefined,
        recovered_size: u32 = 0,
        recovered_loaded: bool = false,
        recovered_sequence: u64 = 0,
        failure: ?anyerror = null,

        fn create(io: *IO, fd: IO.Fd, seed: u64) !*Harness {
            const self = try testing.allocator.create(Harness);
            errdefer testing.allocator.destroy(self);
            self.* = .{
                .io = io,
                .storage = undefined,
                .engine = undefined,
                .prng = Prng.init(seed),
            };
            try self.attach(fd);
            return self;
        }

        fn destroy(self: *Harness) void {
            self.detach();
            testing.allocator.destroy(self);
        }

        /// Builds a fresh storage and engine on `fd`, as after a process restart.
        fn attach(self: *Harness, fd: IO.Fd) !void {
            const options: @import("io_storage.zig").Options = .{
                .size_bytes = config.size_bytes(),
                .operations_max = 4,
            };
            self.storage = try Storage.init(testing.allocator, self.io, fd, options);
            errdefer self.storage.deinit(testing.allocator);
            self.engine = try Engine.init(testing.allocator, &self.storage, config);
            self.phase_done = false;
            self.commit_pending = false;
            self.checkpoint_requested = false;
        }

        fn detach(self: *Harness) void {
            // A real backend may still be reading into or writing from these buffers (an
            // early error return, e.g. a timeout): freeing them would let the kernel finish
            // into memory another test now owns. Drain first; the simulator drops operations
            // on a crash, so there nothing is in flight that could land later.
            if (IO != SimIo) self.drain();
            self.engine.deinit(testing.allocator);
            self.storage.deinit(testing.allocator);
        }

        fn body(self: *const Harness, sequence: u64) []const u8 {
            assert(sequence >= 1 and sequence <= self.submitted);
            return self.bodies[sequence - 1][0..self.sizes[sequence - 1]];
        }

        fn state_at(self: *const Harness, sequence: u64, out: *[state_size]u8) void {
            out.* = @splat(0);
            var index: u64 = 1;
            while (index <= sequence) : (index += 1) apply(out, index, self.body(index));
        }

        /// One step of the IO world, then one storage tick (which delivers callbacks).
        fn pump(self: *Harness) !void {
            if (IO == SimIo) {
                try self.io.run_for_ns(100 * std.time.ns_per_us);
            } else if (comptime @hasDecl(IO, "run_for_ns")) if (!self.storage.idle()) {
                // Wait for the device, so step bounds count waits, not non-blocking polls
                // (a loaded machine would otherwise exhaust them in seconds).
                try self.io.run_for_ns(20 * std.time.ns_per_us);
            };
            self.storage.tick();
        }

        /// Waits for every operation of a real backend to finish (bounded by wall time).
        fn drain(self: *Harness) void {
            var waits: u32 = 0;
            while (!self.storage.idle()) : (waits += 1) {
                // 1M waits of 20 us: 20 s for a handful of 64 KiB operations.
                if (waits > 1_000_000) @panic("io_storage test: operations never finished");
                self.pump() catch |err| std.debug.panic("io_storage test: drain: {t}", .{err});
            }
            assert(self.storage.idle());
        }

        fn wait_phase(self: *Harness) !void {
            var ticks: u32 = 0;
            while (!self.phase_done) : (ticks += 1) {
                if (ticks > 1_000_000) return error.Timeout;
                try self.pump();
            }
            self.phase_done = false;
        }

        fn wait_idle(self: *Harness) !void {
            var ticks: u32 = 0;
            while (!self.engine.idle() or !self.storage.idle()) : (ticks += 1) {
                if (ticks > 1_000_000) return error.Timeout;
                try self.pump();
            }
            if (self.failure) |err| return err;
        }

        fn on_phase(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            assert(!self.phase_done);
            self.phase_done = true;
        }

        fn on_commit(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.commit_pending);
            assert(self.acknowledged + 1 == self.submitted);
            self.commit_pending = false;
            self.acknowledged += 1;
            apply(&self.state, self.acknowledged, self.body(self.acknowledged));
        }

        fn on_checkpoint(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            _ = engine.checkpoint_result catch {
                self.failure = error.CheckpointFailed;
            };
        }

        fn produce(context: *anyopaque, buffer: []u8) u32 {
            const self: *Harness = @ptrCast(@alignCast(context));
            const remaining = snapshot_size - self.snapshot_position;
            const chunk: u32 = @intCast(@min(remaining, buffer.len));
            @memcpy(buffer[0..chunk], self.snapshot[self.snapshot_position..][0..chunk]);
            self.snapshot_position += chunk;
            return chunk;
        }

        fn format(self: *Harness, format_id: u128) !void {
            self.engine.format(format_id, on_phase);
            try self.wait_phase();
        }

        /// One workload step: maybe checkpoint, maybe commit, then pump the IO.
        fn step(self: *Harness) !void {
            if (self.failure) |err| return err;
            const engine = &self.engine;
            const commit_idle = !self.commit_pending;
            if (commit_idle and engine.checkpoint_phase == .idle and
                (self.checkpoint_requested or self.prng.chance(1, 25)))
            {
                std.mem.writeInt(u64, self.snapshot[0..8], self.acknowledged, .little);
                @memcpy(self.snapshot[8..], &self.state);
                self.snapshot_position = 0;
                const producer: engine_module.Producer = .{ .context = self, .produce = produce };
                try engine.checkpoint(producer, on_checkpoint);
                self.checkpoint_requested = false;
                self.checkpoints += 1;
            } else if (commit_idle and self.submitted < entries_max and self.prng.chance(1, 2)) {
                try self.commit_random();
            }
            try self.pump();
        }

        fn commit_random(self: *Harness) !void {
            assert(self.submitted == self.acknowledged);
            const index = self.submitted;
            const size: u32 = @intCast(self.prng.below(body_size_max + 1));
            self.prng.fill(self.bodies[index][0..size]);
            self.sizes[index] = size;
            var metadata: engine_module.Metadata = @splat(0);
            std.mem.writeInt(u64, metadata[0..8], index + 1, .little);
            const entry = self.bodies[index][0..size];
            const sequence = self.engine.commit(entry, &metadata, on_commit) catch |err| {
                if (err != error.JournalFull) return err;
                self.checkpoint_requested = true;
                return;
            };
            try testing.expectEqual(index + 1, sequence);
            self.submitted += 1;
            self.commit_pending = true;
        }

        /// Runs the workload until `acknowledged_target` commits are durable.
        fn run(self: *Harness, acknowledged_target: u64) !void {
            assert(acknowledged_target <= entries_max);
            var steps: u32 = 0;
            while (self.acknowledged < acknowledged_target) : (steps += 1) {
                if (steps > 1_000_000) return error.Timeout;
                try self.step();
            }
        }

        fn consume_checkpoint(context: *anyopaque, chunk: []const u8) void {
            const self: *Harness = @ptrCast(@alignCast(context));
            assert(!self.recovered_loaded);
            assert(self.recovered_size + chunk.len <= snapshot_size);
            @memcpy(self.recovered[self.recovered_size..][0..chunk.len], chunk);
            self.recovered_size += @intCast(chunk.len);
        }

        fn consume_checkpoint_reset(context: *anyopaque) void {
            const self: *Harness = @ptrCast(@alignCast(context));
            assert(!self.recovered_loaded);
            self.recovered_size = 0;
        }

        fn consume_entry(context: *anyopaque, entry: engine_module.Entry) void {
            const self: *Harness = @ptrCast(@alignCast(context));
            self.check_entry(entry) catch |err| {
                if (self.failure == null) self.failure = err;
            };
        }

        fn check_entry(self: *Harness, entry: engine_module.Entry) !void {
            try self.load_checkpoint();
            try testing.expectEqual(self.recovered_sequence + 1, entry.sequence);
            try testing.expect(entry.sequence <= self.submitted);
            try testing.expectEqualSlices(u8, self.body(entry.sequence), entry.body);
            const sequence = std.mem.readInt(u64, entry.metadata[0..8], .little);
            try testing.expectEqual(entry.sequence, sequence);
            apply(self.recovered[8..], entry.sequence, entry.body);
            self.recovered_sequence = entry.sequence;
        }

        fn load_checkpoint(self: *Harness) !void {
            if (self.recovered_loaded) return;
            self.recovered_loaded = true;
            if (self.recovered_size == 0) {
                @memset(&self.recovered, 0);
            } else {
                try testing.expectEqual(@as(u32, snapshot_size), self.recovered_size);
            }
            self.recovered_sequence = std.mem.readInt(u64, self.recovered[0..8], .little);
            try testing.expect(self.recovered_sequence <= self.submitted);
        }

        /// Opens and checks the recovered state; truncates the model to what survived.
        fn open(self: *Harness) !engine_module.OpenResult {
            self.recovered_size = 0;
            self.recovered_loaded = false;
            self.engine.open(.{
                .context = self,
                .on_checkpoint = consume_checkpoint,
                .on_checkpoint_reset = consume_checkpoint_reset,
                .on_entry = consume_entry,
            }, on_phase);
            try self.wait_phase();
            const result = try self.engine.open_result;
            try self.load_checkpoint();
            if (self.failure) |err| return err;
            const last = result.sequence_last;
            try testing.expectEqual(self.recovered_sequence, last);
            try testing.expect(last >= self.acknowledged);
            try testing.expect(last <= self.submitted);
            var expected: [state_size]u8 = undefined;
            self.state_at(last, &expected);
            try testing.expectEqualSlices(u8, &expected, self.recovered[8..]);
            self.submitted = last;
            self.acknowledged = last;
            self.state = expected;
            return result;
        }
    };
}

/// Format, run a workload with checkpoints, then restart on the same descriptor and replay.
/// Returns the storage stats from before the restart.
fn format_commit_reopen(
    comptime IO: type,
    harness: *HarnessType(IO),
    target: u64,
) !HarnessType(IO).Storage.Stats {
    try harness.format(0x10_57_0001);
    var result = try harness.open();
    try testing.expectEqual(@as(u64, 0), result.sequence_last);
    try harness.run(target);
    try harness.wait_idle();
    try testing.expect(harness.checkpoints > 0);
    const acknowledged = harness.acknowledged;
    const stats = harness.storage.stats;
    const fd = harness.storage.fd;
    harness.detach();
    try harness.attach(fd);
    result = try harness.open();
    try testing.expectEqual(acknowledged, result.sequence_last);
    try testing.expectEqual(engine_module.StopReason.clean, result.journal_stop);
    try testing.expect(!result.superblock_repaired);
    try testing.expect(result.checkpoint.sequence > 0);
    return stats;
}

test "io_storage: engine over flaky io with short reads, short writes, and errors" {
    const disk = try testing.allocator.alloc(u8, config.size_bytes());
    defer testing.allocator.free(disk);
    var io: FlakyIo = .{ .prng = Prng.init(7), .disk = disk };
    const harness = try HarnessType(FlakyIo).create(&io, 0, 7);
    defer harness.destroy();
    const stats = try format_commit_reopen(FlakyIo, harness, 150);
    try testing.expect(stats.short_resubmits > 0);
    try testing.expect(stats.read_retries > 0);
    try testing.expect(stats.write_retries > 0);
    try testing.expect(stats.read_zero_filled_bytes > 0);
}

test "io_storage: unreadable sectors read as zeros after retries" {
    const disk = try testing.allocator.alloc(u8, 4 * sector_size);
    defer testing.allocator.free(disk);
    @memset(disk, 0xaa);
    var io: FlakyIo = .{
        .prng = Prng.init(1),
        .disk = disk,
        .file_size = disk.len,
        .error_numerator = 8,
    };
    const Storage = IoStorageType(FlakyIo);
    var io_storage = try Storage.init(testing.allocator, &io, 0, .{ .size_bytes = disk.len });
    defer io_storage.deinit(testing.allocator);
    const Context = struct {
        read: storage.Read = .{},
        done: bool = false,
        fn on_read(read: *storage.Read) void {
            const context: *@This() = @fieldParentPtr("read", read);
            context.done = true;
        }
    };
    var context: Context = .{};
    var buffer: [sector_size]u8 = @splat(0x55);
    io_storage.read_sectors(Context.on_read, &context.read, &buffer, sector_size);
    try testing.expect(!context.done); // Never delivered from the submit call.
    var ticks: u32 = 0;
    while (!context.done) : (ticks += 1) {
        try testing.expect(ticks < 100);
        io_storage.tick();
    }
    try testing.expect(io_storage.idle());
    try testing.expectEqual(@as(u64, 4), io_storage.stats.read_retries);
    try testing.expect(std.mem.allEqual(u8, &buffer, 0));
}

test "io_storage: pool exhaustion queues operations in order" {
    const disk = try testing.allocator.alloc(u8, 8 * sector_size);
    defer testing.allocator.free(disk);
    var io: FlakyIo = .{ .prng = Prng.init(2), .disk = disk, .error_numerator = 0 };
    const Storage = IoStorageType(FlakyIo);
    var io_storage = try Storage.init(testing.allocator, &io, 0, .{
        .size_bytes = disk.len,
        .operations_max = 2,
    });
    defer io_storage.deinit(testing.allocator);
    const Context = struct {
        writes: [8]storage.Write = @splat(.{}),
        sync: storage.Sync = .{},
        done: u32 = 0,
        synced: bool = false,
        fn on_write(write: *storage.Write) void {
            _ = write;
        }
        fn on_sync(sync: *storage.Sync) void {
            const context: *@This() = @fieldParentPtr("sync", sync);
            context.synced = true;
        }
    };
    var context: Context = .{};
    var buffers: [8][sector_size]u8 = undefined;
    for (&buffers, &context.writes, 0..) |*buffer, *write, index| {
        @memset(buffer, @intCast(index + 1));
        io_storage.write_sectors(Context.on_write, write, buffer, index * sector_size);
    }
    try testing.expectEqual(@as(u32, 6), io_storage.waiting.count);
    var ticks: u32 = 0;
    while (!io_storage.idle()) : (ticks += 1) {
        try testing.expect(ticks < 1000);
        io_storage.tick();
    }
    io_storage.sync(Context.on_sync, &context.sync);
    while (!context.synced) : (ticks += 1) {
        try testing.expect(ticks < 2000);
        io_storage.tick();
    }
    for (buffers, 0..) |buffer, index| {
        try testing.expectEqualSlices(u8, &buffer, disk[index * sector_size ..][0..sector_size]);
    }
}

fn sim_crash_seed(seed: u64) !void {
    var prng = Prng.init(seed);
    var world = try io_root.SimWorld.init(testing.allocator, .{ .seed = seed });
    defer world.deinit();
    var io: SimIo = undefined;
    try io.init(testing.allocator, &world, .{
        .host = io_root.Address.ip4(.{ 10, 0, 0, 1 }, 0),
        .disk = .{
            .files_max = 1,
            .file_size_max = @intCast(config.size_bytes()),
            .read_fault_ppm = @intCast(prng.below(2) * 20_000),
        },
    });
    defer io.deinit();
    const fd = try io.open_file("data", .create);
    const harness = try HarnessType(SimIo).create(&io, fd, prng.int(u64));
    defer harness.destroy();
    try harness.format(0x51_0000 + seed);
    _ = try harness.open();
    var cycle: u32 = 0;
    while (cycle < 3) : (cycle += 1) {
        const crash_step = prng.range(1, 400);
        var step: u64 = 0;
        while (step < crash_step and harness.submitted < entries_max) : (step += 1) {
            try harness.step();
        }
        io.crash(); // Drops pending operations, closes descriptors, loses unsynced data.
        harness.detach();
        try harness.attach(try io.open_file("data", .read_write));
        _ = try harness.open();
    }
}

test "io_storage: engine over the io simulator survives crashes" {
    var seed: u64 = 0;
    while (seed < 16) : (seed += 1) {
        sim_crash_seed(seed) catch |err| {
            std.debug.print("io_storage sim crash: failing seed={d}\n", .{seed});
            return err;
        };
    }
}

test "io_storage: engine over the io simulator, format to reopen" {
    var world = try io_root.SimWorld.init(testing.allocator, .{ .seed = 99 });
    defer world.deinit();
    var io: SimIo = undefined;
    try io.init(testing.allocator, &world, .{
        .host = io_root.Address.ip4(.{ 10, 0, 0, 2 }, 0),
        .disk = .{ .files_max = 1, .file_size_max = @intCast(config.size_bytes()) },
    });
    defer io.deinit();
    const fd = try io.open_file("data", .create);
    const harness = try HarnessType(SimIo).create(&io, fd, 99);
    defer harness.destroy();
    _ = try format_commit_reopen(SimIo, harness, 120);
    try harness.wait_idle();
    try expect_sync_read_equals_async(harness);
}

/// A synchronous read returns what an asynchronous read of the same sectors returns.
fn expect_sync_read_equals_async(harness: anytype) !void {
    const storage_ = &harness.storage;
    const Context = struct {
        read: storage.Read = .{},
        done: bool = false,
        fn on_read(read: *storage.Read) void {
            const context: *@This() = @fieldParentPtr("read", read);
            context.done = true;
        }
    };
    var context: Context = .{};
    var expected: [4 * sector_size]u8 = @splat(0x11);
    var actual: [4 * sector_size]u8 = @splat(0x22);
    storage_.read_sectors(Context.on_read, &context.read, &expected, sector_size);
    var ticks: u32 = 0;
    while (!context.done) : (ticks += 1) {
        try testing.expect(ticks < 10_000);
        try harness.pump();
    }
    try storage_.read_sectors_sync(&actual, sector_size);
    try testing.expectEqualSlices(u8, &expected, &actual);
    try testing.expect(!std.mem.allEqual(u8, &actual, 0)); // The superblock zone was written.
}

fn os_io_init() !io_root.IO {
    if (builtin.os.tag != .linux) return io_root.IO.init();
    // CI sandboxes may forbid io_uring.
    return io_root.IO.init(.{}) catch |err| switch (err) {
        error.IoUringUnavailable => error.SkipZigTest,
        else => err,
    };
}

test "io_storage: engine over the os backend on a real file" {
    const IO = io_root.IO;
    var io = try os_io_init();
    defer io.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.posix.PATH_MAX]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, ".zig-cache/tmp/{s}/data.db", .{tmp.sub_path});
    const fd = try io.open_file(path, .create);
    const harness = try HarnessType(IO).create(&io, fd, 5);
    defer harness.destroy();
    _ = try format_commit_reopen(IO, harness, 40);
    // Restart on a freshly opened descriptor: the data must come from the file.
    try harness.wait_idle();
    const acknowledged = harness.acknowledged;
    harness.detach();
    io.close_now(fd);
    const fd_reopened = try io.open_file(path, .read_write);
    defer io.close_now(fd_reopened);
    try harness.attach(fd_reopened);
    const result = try harness.open();
    try testing.expectEqual(acknowledged, result.sequence_last);
    try harness.wait_idle();
    try expect_sync_read_equals_async(harness);
}

test "io_storage: read_sectors_sync continues short reads, retries errors, zero-fills past EOF" {
    const disk = try testing.allocator.alloc(u8, 8 * sector_size);
    defer testing.allocator.free(disk);
    var prng = Prng.init(3);
    prng.fill(disk);
    var io: FlakyIo = .{
        .prng = Prng.init(4),
        .disk = disk,
        .file_size = 6 * sector_size,
        .error_numerator = 2,
    };
    const Storage = IoStorageType(FlakyIo);
    var io_storage = try Storage.init(testing.allocator, &io, 0, .{
        .size_bytes = disk.len,
        .read_retries_max = 64,
    });
    defer io_storage.deinit(testing.allocator);
    var buffer: [4 * sector_size]u8 = undefined;
    for (0..16) |_| {
        @memset(&buffer, 0x77);
        try io_storage.read_sectors_sync(&buffer, sector_size);
        try testing.expectEqualSlices(u8, disk[sector_size..][0..buffer.len], &buffer);
    }
    try testing.expect(io_storage.stats.short_resubmits > 0);
    try testing.expect(io_storage.stats.read_retries > 0);
    // Past the end of the file: zeros, as the asynchronous read returns.
    try io_storage.read_sectors_sync(&buffer, 4 * sector_size);
    const tail = disk[4 * sector_size ..][0 .. 2 * sector_size];
    try testing.expectEqualSlices(u8, tail, buffer[0 .. 2 * sector_size]);
    try testing.expect(std.mem.allEqual(u8, buffer[2 * sector_size ..], 0));
    try testing.expect(io_storage.idle()); // Nothing went through the completion queue.
    // Every attempt failing: an error, not zeros.
    io.error_numerator = 8;
    try testing.expectError(error.ReadFailed, io_storage.read_sectors_sync(&buffer, 0));
}

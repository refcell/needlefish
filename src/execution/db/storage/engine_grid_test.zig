//! Engine + grid crash tests: no block a recoverable checkpoint references is ever reused.
//!
//! The workload writes grid blocks, releases some, and checkpoints the list of live block
//! references (as the producer's bytes). It crashes at a random tick (mid grid write, mid
//! checkpoint, while paused), sometimes rots the newest checkpoint so open falls back, then
//! reopens and reads back every block the recovered checkpoint names: each must verify
//! (a reused block would fail its reference checksum), and the restored free set must hold
//! each one acquired and not released.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const engine_module = @import("engine.zig");
const grid_module = @import("grid.zig");
const checkpoint_module = @import("checkpoint.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;

const sector_size = storage.sector_size;
const Engine = engine_module.EngineType(SimStorage);
const Reference = grid_module.Reference;

const grid_blocks = 40;
const block_size = 2 * sector_size;
const list_size_max = 8 + grid_blocks * @sizeOf(Reference);

const config: engine_module.Config = .{
    .journal_size_bytes = 16 * sector_size,
    .checkpoint_zone_size_bytes = 4 * block_size,
    .entry_body_size_max = 64,
    .checkpoint_block_size = block_size,
    .grid_block_count = grid_blocks,
};

const List = struct {
    references: [grid_blocks]Reference = undefined,
    count: u32 = 0,

    fn encode(list: *const List, out: []u8) u32 {
        std.mem.writeInt(u64, out[0..8], list.count, .little);
        const bytes = std.mem.sliceAsBytes(list.references[0..list.count]);
        @memcpy(out[8..][0..bytes.len], bytes);
        return @intCast(8 + bytes.len);
    }

    fn decode(list: *List, bytes: []const u8) !void {
        if (bytes.len == 0) {
            list.count = 0; // The empty state at format.
            return;
        }
        const count = std.mem.readInt(u64, bytes[0..8], .little);
        try testing.expect(count <= grid_blocks);
        try testing.expectEqual(8 + count * @sizeOf(Reference), bytes.len);
        list.count = @intCast(count);
        @memcpy(std.mem.sliceAsBytes(list.references[0..list.count]), bytes[8..]);
    }

    fn remove(list: *List, index: u32) Reference {
        assert(index < list.count);
        const reference = list.references[index];
        list.count -= 1;
        list.references[index] = list.references[list.count];
        return reference;
    }
};

const Harness = struct {
    engine: Engine,
    sim: *SimStorage,
    prng: Prng,
    live: List = .{},
    snapshot: [list_size_max]u8 = undefined,
    snapshot_len: u32 = 0,
    snapshot_position: u32 = 0,
    recovered: [list_size_max]u8 = undefined,
    recovered_len: u32 = 0,
    block: []align(sector_size) u8,
    write: Engine.Grid.Write = .{},
    read: Engine.Grid.Read = .{},
    writing: ?Reference = null,
    reading: bool = false,
    phase_done: bool = false,
    pace_blocks: u64 = std.math.maxInt(u64),
    /// False from a checkpoint start until it completes, and after an open that fell back.
    fallback_intact: bool = true,
    checkpoints: u32 = 0,

    fn on_phase(engine: *Engine) void {
        const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
        self.phase_done = true;
    }

    fn on_checkpoint(engine: *Engine) void {
        const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
        _ = engine.checkpoint_result catch unreachable; // The zone fits the list.
        self.fallback_intact = true;
        self.checkpoints += 1;
    }

    fn produce(context: *anyopaque, buffer: []u8) u32 {
        const self: *Harness = @ptrCast(@alignCast(context));
        const remaining = self.snapshot_len - self.snapshot_position;
        const chunk: u32 = @intCast(@min(remaining, buffer.len));
        @memcpy(buffer[0..chunk], self.snapshot[self.snapshot_position..][0..chunk]);
        self.snapshot_position += chunk;
        return chunk;
    }

    fn consume(context: *anyopaque, chunk: []const u8) void {
        const self: *Harness = @ptrCast(@alignCast(context));
        @memcpy(self.recovered[self.recovered_len..][0..chunk.len], chunk);
        self.recovered_len += @intCast(chunk.len);
    }

    fn consume_reset(context: *anyopaque) void {
        const self: *Harness = @ptrCast(@alignCast(context));
        self.recovered_len = 0;
    }

    fn consume_entry(_: *anyopaque, _: engine_module.Entry) void {
        unreachable; // The workload never commits.
    }

    fn consume_entry_ignore(_: *anyopaque, _: []const u8) void {}

    fn reset_ignore(_: *anyopaque) void {}

    fn on_write(write: *Engine.Grid.Write) void {
        const self: *Harness = @alignCast(@fieldParentPtr("write", write));
        self.live.references[self.live.count] = self.writing.?;
        self.live.count += 1;
        self.writing = null;
    }

    fn on_read(read: *Engine.Grid.Read) void {
        const self: *Harness = @alignCast(@fieldParentPtr("read", read));
        self.reading = false;
    }

    fn wait_phase(self: *Harness) !void {
        var ticks: u32 = 0;
        while (!self.phase_done) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            self.sim.tick();
        }
        self.phase_done = false;
    }

    /// One step: maybe write a block, release one, or checkpoint; then one tick.
    fn step(self: *Harness) void {
        const engine = &self.engine;
        const free_set = &engine.free_set.?;
        const choice = self.prng.below(10);
        if (choice < 4 and self.writing == null and free_set.count_free() > 0) {
            self.write_block();
        } else if (choice < 7 and self.live.count > 0) {
            const index: u32 = @intCast(self.prng.below(self.live.count));
            free_set.release(self.live.remove(index).address);
        } else if (choice == 7 and self.writing == null and engine.checkpoint_phase == .idle) {
            // Grid writes a checkpoint names must be complete: none is in flight.
            self.snapshot_len = self.live.encode(&self.snapshot);
            self.snapshot_position = 0;
            const producer: engine_module.Producer = .{ .context = self, .produce = produce };
            engine.checkpoint_paced(producer, self.pace_blocks, on_checkpoint) catch unreachable;
            self.fallback_intact = false;
        } else if (engine.checkpoint_paused()) {
            engine.checkpoint_grant(self.pace_blocks);
        }
        self.sim.tick();
    }

    fn write_block(self: *Harness) void {
        const free_set = &self.engine.free_set.?;
        var reservation = free_set.reserve(1) catch unreachable; // A block is free.
        const address = free_set.acquire(&reservation);
        free_set.forfeit(&reservation);
        const payload_size: u32 = @intCast(self.prng.range(1, block_size - 128));
        self.prng.fill(self.block[grid_module.block_header_size..][0..payload_size]);
        const grid = &self.engine.grid.?;
        const format_id = grid.format_id;
        self.writing = grid_module.seal(self.block, format_id, address, .table_data, payload_size);
        grid.write_block(on_write, &self.write, self.block, address);
    }

    /// Opens and checks every block the recovered checkpoint names.
    fn open(self: *Harness) !engine_module.OpenResult {
        self.recovered_len = 0;
        self.engine.open(.{
            .context = self,
            .on_checkpoint = consume,
            .on_checkpoint_reset = consume_reset,
            .on_entry = consume_entry,
        }, on_phase);
        try self.wait_phase();
        const result = try self.engine.open_result;
        if (result.checkpoint_fallback) self.fallback_intact = false;
        try self.live.decode(self.recovered[0..self.recovered_len]);
        const free_set = &self.engine.free_set.?;
        free_set.assert_invariants();
        const read_buffer = self.block;
        for (self.live.references[0..self.live.count]) |reference| {
            try testing.expect(free_set.is_acquired(reference.address));
            try testing.expect(!free_set.is_released(reference.address));
            self.reading = true;
            const grid = &self.engine.grid.?;
            grid.read_block(on_read, &self.read, read_buffer, reference, .table_data);
            var ticks: u32 = 0;
            while (self.reading) : (ticks += 1) {
                if (ticks > 1000) return error.Timeout;
                self.sim.tick();
            }
            // A reused or overwritten block fails its reference checksum.
            try testing.expect(self.read.payload != null);
        }
        return result;
    }

    fn reinit(self: *Harness) !void {
        self.engine.deinit(testing.allocator);
        self.engine = try .init(testing.allocator, self.sim, config);
        self.writing = null;
        self.reading = false;
        self.phase_done = false;
    }
};

/// Rots the first used sector of the newest checkpoint (its first block header).
fn rot_newest_checkpoint(harness: *Harness) bool {
    const checkpoint = harness.engine.superblock.working.checkpoint;
    if (checkpoint.sequence == 0) return false;
    const offset: usize = @intCast(config.checkpoint_zone_offset(checkpoint.zone));
    harness.sim.durable[offset] ^= 0x10;
    harness.sim.memory[offset] ^= 0x10;
    return true;
}

fn run_seed(seed: u64) !u32 {
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 6)),
    });
    defer sim.deinit(testing.allocator);
    const block = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(block);
    const harness = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(harness);
    harness.* = .{
        .engine = try .init(testing.allocator, &sim, config),
        .sim = &sim,
        .prng = Prng.init(prng.int(u64)),
        .block = block,
    };
    defer harness.engine.deinit(testing.allocator);
    if (prng.chance(1, 2)) harness.pace_blocks = 1;
    harness.engine.format(0xc0de_0000 + seed, Harness.on_phase);
    try harness.wait_phase();
    _ = try harness.open();
    var fallbacks: u32 = 0;
    for (0..6) |_| {
        const crash_tick = prng.range(1, 600);
        for (0..crash_tick) |_| harness.step();
        const fallback_ready = harness.fallback_intact and
            harness.engine.checkpoint_phase == .idle;
        sim.crash();
        const rotten = fallback_ready and prng.chance(1, 3) and rot_newest_checkpoint(harness);
        try harness.reinit();
        const result = try harness.open();
        if (rotten) try testing.expect(result.checkpoint_fallback);
        if (result.checkpoint_fallback) fallbacks += 1;
    }
    try testing.expect(harness.checkpoints > 0);
    return fallbacks;
}

test "engine grid: crashes and checkpoint fallback never reuse a referenced block" {
    var fallbacks: u32 = 0;
    for (0..24) |seed| {
        fallbacks += run_seed(seed) catch |err| {
            std.debug.print("engine grid: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(fallbacks >= 4);
}

test "engine grid: the free set survives reopen and frees after two checkpoints" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.size_bytes(),
        .seed = 1,
    });
    defer sim.deinit(testing.allocator);
    var engine = try Engine.init(testing.allocator, &sim, config);
    defer engine.deinit(testing.allocator);
    const Context = struct {
        fn on_phase(_: *Engine) void {}
        fn on_checkpoint(_: *Engine) void {}
        fn produce(_: *anyopaque, _: []u8) u32 {
            return 0;
        }
    };
    engine.format(9, Context.on_phase);
    try engine_module.tick_until_idle(&sim, &engine, 1000);
    var dummy: u8 = 0;
    const consumer: engine_module.Consumer = .{
        .context = &dummy,
        .on_checkpoint = Harness.consume_entry_ignore,
        .on_checkpoint_reset = Harness.reset_ignore,
        .on_entry = Harness.consume_entry,
    };
    engine.open(consumer, Context.on_phase);
    try engine_module.tick_until_idle(&sim, &engine, 1000);
    const free_set = &engine.free_set.?;
    var reservation = try free_set.reserve(2);
    _ = free_set.acquire(&reservation);
    _ = free_set.acquire(&reservation);
    free_set.forfeit(&reservation);
    free_set.release(1);
    const producer: engine_module.Producer = .{ .context = &dummy, .produce = Context.produce };
    try engine.checkpoint(producer, Context.on_checkpoint);
    try engine_module.tick_until_idle(&sim, &engine, 1000);
    try testing.expect(free_set.is_acquired(1)); // The fallback (empty state) is before it.
    engine.deinit(testing.allocator);
    engine = try Engine.init(testing.allocator, &sim, config);
    engine.open(consumer, Context.on_phase);
    try engine_module.tick_until_idle(&sim, &engine, 1000);
    const reopened = &engine.free_set.?;
    try testing.expect(reopened.is_acquired(1) and reopened.is_released(1));
    try testing.expect(reopened.is_acquired(2) and !reopened.is_released(2));
    try engine.checkpoint(producer, Context.on_checkpoint);
    try engine_module.tick_until_idle(&sim, &engine, 1000);
    try testing.expect(!reopened.is_acquired(1));
    try testing.expect(reopened.is_acquired(2));
}

/// A consumer that pauses after every checkpoint load and resumes when the test says so.
const Pauser = struct {
    engine: Engine,
    sim: *SimStorage,
    phase_done: bool = false,
    pauses: u32 = 0,
    resets: u32 = 0,
    loaded_bytes: u32 = 0,
    checkpoint_done: bool = false,
    produced: bool = false,

    fn on_phase(engine: *Engine) void {
        const self: *Pauser = @alignCast(@fieldParentPtr("engine", engine));
        self.phase_done = true;
    }

    fn on_checkpoint(engine: *Engine) void {
        const self: *Pauser = @alignCast(@fieldParentPtr("engine", engine));
        _ = engine.checkpoint_result catch unreachable; // A few bytes fit the zone.
        self.checkpoint_done = true;
    }

    fn produce(context: *anyopaque, buffer: []u8) u32 {
        const self: *Pauser = @ptrCast(@alignCast(context));
        if (self.produced) return 0;
        self.produced = true;
        buffer[0] = 0xab;
        return 1;
    }

    fn consume(context: *anyopaque, chunk: []const u8) void {
        const self: *Pauser = @ptrCast(@alignCast(context));
        self.loaded_bytes += @intCast(chunk.len);
    }

    fn consume_reset(context: *anyopaque) void {
        const self: *Pauser = @ptrCast(@alignCast(context));
        self.resets += 1;
        self.loaded_bytes = 0;
    }

    fn consume_entry(_: *anyopaque, _: engine_module.Entry) void {}

    fn loaded(context: *anyopaque) void {
        const self: *Pauser = @ptrCast(@alignCast(context));
        assert(self.engine.phase == .opening_paused);
        self.pauses += 1;
    }

    fn open(self: *Pauser) void {
        self.phase_done = false;
        self.engine.open(.{
            .context = self,
            .on_checkpoint = consume,
            .on_checkpoint_reset = consume_reset,
            .on_entry = consume_entry,
            .on_checkpoint_loaded = loaded,
        }, on_phase);
    }

    /// Ticks until the `count`th pause, then checks the engine stays paused meanwhile.
    fn wait_pause(self: *Pauser, count: u32) !void {
        var ticks: u32 = 0;
        while (self.pauses < count) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            self.sim.tick();
        }
        for (0..50) |_| self.sim.tick();
        try testing.expectEqual(Engine.Phase.opening_paused, self.engine.phase);
        try testing.expect(!self.engine.idle());
        try testing.expectEqual(count, self.pauses);
    }

    fn wait(self: *Pauser, flag: *bool) !void {
        var ticks: u32 = 0;
        while (!flag.*) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            self.sim.tick();
        }
        flag.* = false;
    }

    fn checkpoint(self: *Pauser) !void {
        const producer: engine_module.Producer = .{ .context = self, .produce = produce };
        self.produced = false;
        try self.engine.checkpoint(producer, on_checkpoint);
        try self.wait(&self.checkpoint_done);
    }

    fn reinit(self: *Pauser) !void {
        self.engine.deinit(testing.allocator);
        self.engine = try .init(testing.allocator, self.sim, config);
        self.pauses = 0;
        self.resets = 0;
        self.loaded_bytes = 0;
    }
};

test "engine grid: open pauses after the checkpoint; corrupt resumes fall back, then fail" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.size_bytes(),
        .seed = 41,
        .latency_ticks_max = 3,
    });
    defer sim.deinit(testing.allocator);
    const pauser = try testing.allocator.create(Pauser);
    defer testing.allocator.destroy(pauser);
    pauser.* = .{ .engine = try .init(testing.allocator, &sim, config), .sim = &sim };
    defer pauser.engine.deinit(testing.allocator);
    pauser.engine.format(0x9a05e, Pauser.on_phase);
    try pauser.wait(&pauser.phase_done);
    // A fresh file pauses too (no checkpoint, nothing loaded).
    pauser.open();
    try pauser.wait_pause(1);
    try testing.expectEqual(@as(u32, 0), pauser.loaded_bytes);
    pauser.engine.open_resume(.loaded);
    try pauser.wait(&pauser.phase_done);
    _ = try pauser.engine.open_result;
    try pauser.checkpoint();
    try pauser.checkpoint();
    try testing.expect(pauser.engine.superblock.working.has_fallback());

    // The newest checkpoint's data is reported corrupt: the fallback loads and pauses again.
    try pauser.reinit();
    pauser.open();
    try pauser.wait_pause(1);
    const free_set_bytes: u32 = @intCast(pauser.engine.free_set_image.len);
    try testing.expectEqual(@as(u32, 1), pauser.loaded_bytes);
    pauser.engine.open_resume(.corrupt);
    try pauser.wait_pause(2);
    try testing.expectEqual(@as(u32, 1), pauser.resets);
    try testing.expectEqual(@as(u32, 1), pauser.loaded_bytes);
    pauser.engine.open_resume(.loaded);
    try pauser.wait(&pauser.phase_done);
    const result = try pauser.engine.open_result;
    try testing.expect(result.checkpoint_fallback);
    try testing.expect(free_set_bytes > 0);

    // After the fallback there is no distinct fallback: corrupt again fails the open.
    try pauser.reinit();
    pauser.open();
    try pauser.wait_pause(1);
    pauser.engine.open_resume(.corrupt);
    try pauser.wait(&pauser.phase_done);
    try testing.expectError(error.CheckpointCorrupt, pauser.engine.open_result);
    try testing.expectEqual(Engine.Phase.closed, pauser.engine.phase);
}

//! Engine tests, including the lane's crash-safety guarantee: a seeded fault-injection run
//! over many seeds. Each seed drives a random workload of commits and checkpoints against a
//! model, crashes at a random tick (losing, keeping, or tearing unsynced sectors), sometimes
//! rots one superblock copy or one sector of the newest checkpoint, reopens, and checks that
//! the recovered state is exactly the model state after a prefix of the submitted entries
//! that includes every acknowledged one.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const engine_module = @import("engine.zig");
const superblock_module = @import("superblock.zig");
const checkpoint_module = @import("checkpoint.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;

const sector_size = storage.sector_size;
const Engine = engine_module.EngineType(SimStorage);
const Metadata = engine_module.Metadata;

const body_size_max = 600;
const entries_max = 2048;
/// The model state: a byte array every entry mixes its body into.
const state_size = 20_000;
/// A snapshot is the entry sequence it covers followed by the state.
const snapshot_size = 8 + state_size;

const config: engine_module.Config = .{
    .journal_size_bytes = 32 * sector_size,
    .checkpoint_zone_size_bytes = 4 * 2 * sector_size,
    .entry_body_size_max = body_size_max,
    .checkpoint_block_size = 2 * sector_size,
};

comptime {
    const capacity = checkpoint_module.payload_capacity(config.checkpoint_block_size);
    assert(snapshot_size <= 4 * capacity);
}

fn apply(state: *[state_size]u8, sequence: u64, body: []const u8) void {
    const start = sequence *% 7919 % state_size;
    for (body, 0..) |byte, index| state[(start + index) % state_size] ^= byte;
    state[sequence % state_size] +%= 1;
}

fn metadata_for(sequence: u64, body: []const u8) Metadata {
    var metadata: Metadata = @splat(0);
    std.mem.writeInt(u64, metadata[0..8], sequence, .little);
    std.mem.writeInt(u128, metadata[8..24], engine_module.chain_anchor(body.len), .little);
    return metadata;
}

const Model = struct {
    bodies: [entries_max][body_size_max]u8 = undefined,
    sizes: [entries_max + 1]u32 = undefined,
    /// Entries 1..submitted have been handed to `commit`.
    submitted: u64 = 0,
    /// Entries 1..acknowledged had their commit callback fire.
    acknowledged: u64 = 0,
    /// State after entry `acknowledged`.
    state: [state_size]u8 = @splat(0),

    fn body(model: *const Model, sequence: u64) []const u8 {
        assert(sequence >= 1 and sequence <= model.submitted);
        return model.bodies[sequence - 1][0..model.sizes[sequence - 1]];
    }

    /// The state after entries 1..sequence, recomputed from scratch.
    fn state_at(model: *const Model, sequence: u64, out: *[state_size]u8) void {
        assert(sequence <= model.submitted);
        out.* = @splat(0);
        var index: u64 = 1;
        while (index <= sequence) : (index += 1) apply(out, index, model.body(index));
    }
};

const Harness = struct {
    engine: Engine,
    sim: *SimStorage,
    prng: Prng,
    model: Model = .{},
    phase_done: bool = false,
    commit_sequence: u64 = 0,
    checkpoint_requested: bool = false,
    snapshot: [snapshot_size]u8 = undefined,
    snapshot_position: u32 = 0,
    // Recovery side.
    recovered: [snapshot_size]u8 = undefined,
    recovered_size: u32 = 0,
    recovered_loaded: bool = false,
    recovered_sequence: u64 = 0,
    scratch: [state_size]u8 = undefined,
    failure: ?anyerror = null,
    /// The superblock's fallback checkpoint is known intact: false from a checkpoint start
    /// (it overwrites the fallback zone) until a checkpoint completes, and after an open that
    /// fell back (no distinct fallback is left).
    fallback_intact: bool = true,
    /// Checkpoint blocks granted at a checkpoint start and per acknowledged commit
    /// (incremental checkpoints); `maxInt` writes checkpoints unpaced.
    pace_blocks: u64 = std.math.maxInt(u64),
    /// Times a paced checkpoint paused at a chunk boundary.
    pauses: u64 = 0,
    was_paused: bool = false,

    fn on_phase(engine: *Engine) void {
        const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
        assert(!self.phase_done);
        self.phase_done = true;
    }

    fn on_commit(engine: *Engine) void {
        const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
        assert(self.commit_sequence == self.model.acknowledged + 1);
        self.model.acknowledged = self.commit_sequence;
        apply(&self.model.state, self.commit_sequence, self.model.body(self.commit_sequence));
        self.commit_sequence = 0;
        if (self.pace_blocks != std.math.maxInt(u64)) engine.checkpoint_grant(self.pace_blocks);
    }

    fn on_checkpoint(engine: *Engine) void {
        const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
        _ = engine.checkpoint_result catch {
            self.failure = error.CheckpointFailed;
            return;
        };
        self.fallback_intact = true;
    }

    fn produce(context: *anyopaque, buffer: []u8) u32 {
        const self: *Harness = @ptrCast(@alignCast(context));
        const remaining = snapshot_size - self.snapshot_position;
        const chunk: u32 = @intCast(@min(remaining, buffer.len, self.prng.range(1, 9000)));
        @memcpy(buffer[0..chunk], self.snapshot[self.snapshot_position..][0..chunk]);
        self.snapshot_position += chunk;
        return chunk;
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

    /// Every replayed entry must be exactly the next submitted entry.
    fn check_entry(self: *Harness, entry: engine_module.Entry) !void {
        try self.load_checkpoint();
        try testing.expectEqual(self.recovered_sequence + 1, entry.sequence);
        try testing.expect(entry.sequence <= self.model.submitted);
        try testing.expectEqualSlices(u8, self.model.body(entry.sequence), entry.body);
        const metadata = metadata_for(entry.sequence, entry.body);
        try testing.expectEqualSlices(u8, &metadata, entry.metadata);
        const state = self.recovered[8..];
        apply(state, entry.sequence, entry.body);
        self.recovered_sequence = entry.sequence;
    }

    /// Decodes the recovered checkpoint (or the empty state) and checks it against the model.
    fn load_checkpoint(self: *Harness) !void {
        if (self.recovered_loaded) return;
        self.recovered_loaded = true;
        if (self.recovered_size == 0) {
            @memset(&self.recovered, 0);
        } else {
            try testing.expectEqual(@as(u32, snapshot_size), self.recovered_size);
        }
        self.recovered_sequence = std.mem.readInt(u64, self.recovered[0..8], .little);
        try testing.expect(self.recovered_sequence <= self.model.submitted);
        self.model.state_at(self.recovered_sequence, &self.scratch);
        try testing.expectEqualSlices(u8, &self.scratch, self.recovered[8..]);
        try testing.expectEqual(self.recovered_sequence + 1, self.engine.open_start.sequence);
    }

    fn wait_phase(self: *Harness) !void {
        var ticks: u32 = 0;
        while (!self.phase_done) : (ticks += 1) {
            if (ticks > 1_000_000) return error.Timeout;
            self.sim.tick();
        }
        self.phase_done = false;
    }

    fn format(self: *Harness) !void {
        self.engine.format(0xfeed_0001, on_phase);
        try self.wait_phase();
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
        if (result.checkpoint_fallback) self.fallback_intact = false;
        try self.load_checkpoint();
        if (self.failure) |err| return err;
        const last = result.sequence_last;
        try testing.expectEqual(self.recovered_sequence, last);
        try testing.expect(last >= self.model.acknowledged);
        try testing.expect(last <= self.model.submitted);
        self.model.state_at(last, &self.scratch);
        try testing.expectEqualSlices(u8, &self.scratch, self.recovered[8..]);
        self.model.submitted = last;
        self.model.acknowledged = last;
        self.model.state = self.scratch;
        return result;
    }

    /// One workload step: maybe commit, maybe checkpoint, then one storage tick.
    fn step(self: *Harness) !void {
        if (self.failure) |err| return err;
        const engine = &self.engine;
        const commit_idle = engine.commit_callback == null;
        if (commit_idle and engine.checkpoint_phase == .idle and
            (self.checkpoint_requested or self.prng.chance(1, 60)))
        {
            try self.checkpoint_start();
            self.checkpoint_requested = false;
        } else if (commit_idle and self.model.submitted < entries_max and
            self.prng.chance(1, 3))
        {
            try self.commit_random();
        } else if (self.model.submitted == entries_max) {
            // No more commits will grant: let a paced checkpoint finish.
            engine.checkpoint_grant(std.math.maxInt(u64));
        }
        self.sim.tick();
        const paused = engine.checkpoint_paused();
        if (paused and !self.was_paused) self.pauses += 1;
        self.was_paused = paused;
    }

    fn commit_random(self: *Harness) !void {
        assert(self.model.submitted == self.model.acknowledged);
        const index = self.model.submitted;
        const size: u32 = @intCast(switch (self.prng.below(3)) {
            0 => self.prng.below(16),
            else => self.prng.below(body_size_max + 1),
        });
        self.prng.fill(self.model.bodies[index][0..size]);
        self.model.sizes[index] = size;
        const body = self.model.bodies[index][0..size];
        const metadata = metadata_for(index + 1, body);
        const sequence = self.engine.commit(body, &metadata, on_commit) catch |err| switch (err) {
            error.JournalFull => {
                self.checkpoint_requested = true;
                // A paced checkpoint must finish to free the journal.
                self.engine.checkpoint_grant(std.math.maxInt(u64));
                return;
            },
            else => return err,
        };
        try testing.expectEqual(index + 1, sequence);
        self.model.submitted += 1;
        self.commit_sequence = sequence;
    }

    fn checkpoint_start(self: *Harness) !void {
        self.snapshot_take();
        const producer: engine_module.Producer = .{ .context = self, .produce = produce };
        try self.engine.checkpoint_paced(producer, self.pace_blocks, on_checkpoint);
        self.fallback_intact = false;
    }

    /// Commits `count` random entries, each durable before the next.
    fn commit_durable(self: *Harness, count: u32) !void {
        for (0..count) |_| {
            try self.commit_random();
            try testing.expect(self.commit_sequence != 0); // The journal had room.
            try engine_module.tick_until_idle(self.sim, &self.engine, 10_000);
        }
    }

    /// Takes a checkpoint of everything acknowledged and waits for it.
    fn checkpoint_durable(self: *Harness) !void {
        try self.checkpoint_start();
        try engine_module.tick_until_idle(self.sim, &self.engine, 100_000);
        if (self.failure) |err| return err;
        try testing.expect(self.fallback_intact);
    }

    fn snapshot_take(self: *Harness) void {
        std.mem.writeInt(u64, self.snapshot[0..8], self.model.acknowledged, .little);
        @memcpy(self.snapshot[8..], &self.model.state);
        self.snapshot_position = 0;
    }

    fn reinit(self: *Harness) !void {
        self.engine.deinit(testing.allocator);
        self.engine = try .init(testing.allocator, self.sim, config);
        self.phase_done = false;
        self.commit_sequence = 0;
        self.checkpoint_requested = false;
        self.was_paused = false;
    }
};

/// The sectors holding the payload of `checkpoint` (each block's used sectors), in order.
fn checkpoint_sector_count(checkpoint: engine_module.Checkpoint) u32 {
    assert(checkpoint.size_bytes > 0);
    const block_size = config.checkpoint_block_size;
    const capacity = checkpoint_module.payload_capacity(block_size);
    const blocks = checkpoint_module.block_count(checkpoint.size_bytes, block_size);
    assert(blocks >= 1);
    const full_sectors = block_size / sector_size;
    const last_payload = checkpoint.size_bytes - (blocks - 1) * capacity;
    const last_sectors = storage.sector_ceil(checkpoint_module.block_header_size + last_payload) /
        sector_size;
    return @intCast((blocks - 1) * full_sectors + last_sectors);
}

/// The storage sector of the `index`th used sector of `checkpoint`.
fn checkpoint_sector(checkpoint: engine_module.Checkpoint, index: u32) u32 {
    assert(index < checkpoint_sector_count(checkpoint));
    const block_sectors: u32 = config.checkpoint_block_size / sector_size;
    const block = index / block_sectors;
    const sector_in_block = index % block_sectors;
    const offset = config.checkpoint_zone_offset(checkpoint.zone) +
        @as(u64, block) * config.checkpoint_block_size + @as(u64, sector_in_block) * sector_size;
    return @intCast(offset / sector_size);
}

/// Bit rot in the first byte of `sector`, which in a used checkpoint sector is always a
/// checksummed header or payload byte (never block padding).
fn rot_sector(sim: *SimStorage, sector: u32) void {
    const offset = @as(usize, sector) * sector_size;
    sim.durable[offset] ^= 0x10;
    sim.memory[offset] ^= 0x10;
}

/// Rots one random used sector of the newest checkpoint; false if there is none.
fn corrupt_newest_checkpoint(harness: *Harness, prng: *Prng) bool {
    const checkpoint = harness.engine.superblock.working.checkpoint;
    if (checkpoint.sequence == 0 or checkpoint.size_bytes == 0) return false;
    const index: u32 = @intCast(prng.below(checkpoint_sector_count(checkpoint)));
    rot_sector(harness.sim, checkpoint_sector(checkpoint, index));
    return true;
}

fn sim_create(seed: u64) !SimStorage {
    return SimStorage.init(testing.allocator, .{ .size_bytes = config.size_bytes(), .seed = seed });
}

fn harness_create(sim: *SimStorage, seed: u64) !*Harness {
    const harness = try testing.allocator.create(Harness);
    harness.* = .{
        .engine = try .init(testing.allocator, sim, config),
        .sim = sim,
        .prng = Prng.init(seed),
    };
    return harness;
}

fn harness_destroy(harness: *Harness) void {
    harness.engine.deinit(testing.allocator);
    testing.allocator.destroy(harness);
}

test "engine: format, commit, checkpoint, reopen" {
    var sim = try sim_create(1);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 1);
    defer harness_destroy(harness);

    try testing.expectError(error.SuperBlockMissing, harness.open());
    try harness.reinit();
    try harness.format();
    var result = try harness.open();
    try testing.expectEqual(@as(u64, 0), result.sequence_last);
    try testing.expectEqual(@as(u64, 0), result.checkpoint.sequence);

    var checkpoints: u32 = 0;
    var steps: u32 = 0;
    while (harness.model.acknowledged < 300) : (steps += 1) {
        try testing.expect(steps < 100_000);
        const before = harness.engine.checkpoint_phase;
        try harness.step();
        if (before == .idle and harness.engine.checkpoint_phase != .idle) checkpoints += 1;
    }
    try engine_module.tick_until_idle(&sim, &harness.engine, 10_000);
    try testing.expect(checkpoints > 5);
    const acknowledged = harness.model.acknowledged;
    const metadata = harness.engine.commit_metadata;

    try harness.reinit();
    result = try harness.open();
    try testing.expectEqual(acknowledged, result.sequence_last);
    // The bytes after the last entry are left over from an older lap: a header (clean end)
    // or a body sector, which the scan cannot tell from a torn header. Never a bad body.
    try testing.expect(result.journal_stop != .body_corrupt);
    try testing.expect(!result.superblock_repaired);
    try testing.expect(result.checkpoint.sequence > 0);
    try testing.expectEqualSlices(u8, &metadata, &harness.engine.commit_metadata);
}

test "engine: layout mismatch is refused" {
    var sim = try sim_create(2);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 2);
    defer harness_destroy(harness);
    try harness.format();
    harness.engine.deinit(testing.allocator);
    var other = config;
    other.entry_body_size_max -= 1;
    harness.engine = try .init(testing.allocator, &sim, other);
    try testing.expectError(error.LayoutMismatch, harness.open());
}

test "engine: one rotten superblock copy is survived and repaired" {
    var sim = try sim_create(3);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 3);
    defer harness_destroy(harness);
    try harness.format();
    _ = try harness.open();
    for (0..4) |copy| {
        var steps: u32 = 0;
        while (steps < 400) : (steps += 1) try harness.step();
        try engine_module.tick_until_idle(&sim, &harness.engine, 10_000);
        const acknowledged = harness.model.acknowledged;
        sim.corrupt_sector(@intCast(copy));
        try harness.reinit();
        const result = try harness.open();
        try testing.expectEqual(acknowledged, result.sequence_last);
        try testing.expect(result.superblock_repaired);
        for (1..4) |other| {
            const bytes = sim.durable_sector(@intCast(other));
            try testing.expectEqualSlices(u8, sim.durable_sector(0), bytes);
        }
    }
}

test "engine: journal body corruption stops replay and is reported" {
    var sim = try sim_create(4);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 4);
    defer harness_destroy(harness);
    try harness.format();
    _ = try harness.open();
    var bodies: [3][body_size_max]u8 = undefined;
    for (&bodies, 0..) |*body, index| {
        harness.prng.fill(body);
        harness.model.bodies[index] = body.*;
        harness.model.sizes[index] = body_size_max;
        harness.model.submitted += 1;
        harness.commit_sequence = index + 1;
        const metadata = metadata_for(index + 1, body);
        _ = try harness.engine.commit(body, &metadata, Harness.on_commit);
        try engine_module.tick_until_idle(&sim, &harness.engine, 10_000);
    }
    // Entry 2's body sector: journal start + entry 1 (2 sectors) + entry 2 header.
    // Flip one durable body byte (bit rot inside the checksummed bytes, not the padding).
    const offset: usize = @intCast(config.journal_offset() + 3 * sector_size + 17);
    sim.durable[offset] ^= 0x20;
    sim.memory[offset] ^= 0x20;
    try harness.reinit();
    harness.model.acknowledged = 1; // The rotten entries are lost; recovery must stop at 1.
    const result = try harness.open();
    try testing.expectEqual(@as(u64, 1), result.sequence_last);
    try testing.expectEqual(engine_module.StopReason.body_corrupt, result.journal_stop);
}

/// Formats and builds two durable checkpoints with entries after each, so the newest
/// checkpoint has a real (non-empty) fallback in the other zone.
fn setup_two_checkpoints(harness: *Harness) !void {
    try harness.format();
    _ = try harness.open();
    try harness.commit_durable(6);
    try harness.checkpoint_durable();
    try harness.commit_durable(5);
    try harness.checkpoint_durable();
    try harness.commit_durable(4);
    const working = &harness.engine.superblock.working;
    try testing.expect(working.has_fallback());
    try testing.expect(working.checkpoint_previous.sequence > 0);
    try testing.expectEqual(@as(u32, 0), harness.sim.unsynced_sector_count());
}

test "engine: any rotten sector of the newest checkpoint falls back to the previous one" {
    var sim = try sim_create(5);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 5);
    defer harness_destroy(harness);
    try setup_two_checkpoints(harness);
    const acknowledged = harness.model.acknowledged;
    const newest = harness.engine.superblock.working.checkpoint;
    const previous = harness.engine.superblock.working.checkpoint_previous;
    const image = try testing.allocator.dupe(u8, sim.durable);
    defer testing.allocator.free(image);

    const sectors = checkpoint_sector_count(newest);
    try testing.expect(sectors >= 3);
    for (0..sectors) |index| {
        @memcpy(sim.durable, image);
        @memcpy(sim.memory, image);
        rot_sector(&sim, checkpoint_sector(newest, @intCast(index)));
        try harness.reinit();
        const result = try harness.open();
        try testing.expect(result.checkpoint_fallback);
        try testing.expectEqual(previous.sequence, result.checkpoint.sequence);
        try testing.expectEqual(acknowledged, result.sequence_last);
        try testing.expectEqual(engine_module.StopReason.clean, result.journal_stop);
        // The fallback is now the newest checkpoint, and there is no other.
        const working = &harness.engine.superblock.working;
        try testing.expectEqual(previous.sequence, working.checkpoint.sequence);
        try testing.expect(!working.has_fallback());
    }
    // The next checkpoint overwrites the rotten zone, and reopening needs no fallback.
    try harness.commit_durable(2);
    try harness.checkpoint_durable();
    const working = &harness.engine.superblock.working;
    try testing.expectEqual(newest.zone, working.checkpoint.zone);
    try testing.expectEqual(previous.zone, working.checkpoint_previous.zone);
    try harness.reinit();
    const result = try harness.open();
    try testing.expect(!result.checkpoint_fallback);
    try testing.expectEqual(acknowledged + 2, result.sequence_last);
    try testing.expectEqual(@as(u64, 0), result.entries_replayed);
}

test "engine: rotten first checkpoint falls back to the empty state and the whole journal" {
    var sim = try sim_create(6);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 6);
    defer harness_destroy(harness);
    try harness.format();
    _ = try harness.open();
    try harness.commit_durable(6);
    try harness.checkpoint_durable();
    try harness.commit_durable(3);
    const newest = harness.engine.superblock.working.checkpoint;
    try testing.expect(harness.engine.superblock.working.has_fallback());
    rot_sector(&sim, checkpoint_sector(newest, 0));
    try harness.reinit();
    var result = try harness.open();
    try testing.expect(result.checkpoint_fallback);
    try testing.expectEqual(@as(u64, 0), result.checkpoint.sequence);
    try testing.expectEqual(@as(u64, 9), result.entries_replayed);
    try testing.expectEqual(@as(u64, 9), result.sequence_last);
    // Commits and checkpoints continue; a clean reopen sees all of it.
    try harness.commit_durable(2);
    try harness.checkpoint_durable();
    try harness.reinit();
    result = try harness.open();
    try testing.expect(!result.checkpoint_fallback);
    try testing.expectEqual(@as(u64, 11), result.sequence_last);
}

test "engine: rotten newest checkpoint and rotten fallback is CheckpointCorrupt" {
    var sim = try sim_create(7);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 7);
    defer harness_destroy(harness);
    try setup_two_checkpoints(harness);
    const working = harness.engine.superblock.working;
    rot_sector(&sim, checkpoint_sector(working.checkpoint, 1));
    rot_sector(&sim, checkpoint_sector(working.checkpoint_previous, 0));
    try harness.reinit();
    try testing.expectError(error.CheckpointCorrupt, harness.open());
}

test "engine: fallback whose retained journal is rotten is CheckpointCorrupt" {
    var sim = try sim_create(8);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 8);
    defer harness_destroy(harness);
    try harness.format();
    _ = try harness.open();
    try harness.commit_durable(6);
    try harness.checkpoint_durable();
    try harness.commit_durable(3);
    const newest = harness.engine.superblock.working.checkpoint;
    rot_sector(&sim, checkpoint_sector(newest, 0));
    // Entry 1's header: replay from the empty state stops before the checkpoint's coverage.
    sim.corrupt_sector(@intCast(config.journal_offset() / sector_size));
    try harness.reinit();
    try testing.expectError(error.CheckpointCorrupt, harness.open());
}

const Pacing = enum { unpaced, paced };

fn run_fault_seed(seed: u64, pacing: Pacing) !u32 {
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 8)),
        .read_fault_numerator = @intCast(prng.below(2)),
        .read_fault_denominator = 200,
    });
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, prng.int(u64));
    defer harness_destroy(harness);
    // The snapshot spans 3 blocks: 1 or 2 per chunk pauses once or twice per checkpoint.
    if (pacing == .paced) harness.pace_blocks = prng.range(1, 2);
    try harness.format();
    _ = try harness.open();
    var fallbacks: u32 = 0;
    var cycle: u32 = 0;
    while (cycle < 4) : (cycle += 1) {
        try run_until_crash_point(harness, &prng, pacing);
        // A checkpoint in flight is overwriting the fallback zone: rotting the newest zone
        // too would be a double fault.
        const fallback_ready = harness.fallback_intact and
            harness.engine.checkpoint_phase == .idle;
        sim.crash();
        if (prng.chance(1, 4)) sim.corrupt_sector(@intCast(prng.below(4)));
        const rotten = fallback_ready and prng.chance(1, 2) and
            corrupt_newest_checkpoint(harness, &prng);
        try harness.reinit();
        const result = try harness.open();
        if (result.checkpoint_fallback) fallbacks += 1;
        // Rot in the newest zone always forces the fallback.
        if (rotten) try testing.expect(result.checkpoint_fallback);
    }
    return fallbacks;
}

/// Steps to a random tick; when paced, half the time instead to a random chunk boundary
/// (the checkpoint paused after its `k`th chunk, nothing of it named by a superblock yet).
fn run_until_crash_point(harness: *Harness, prng: *Prng, pacing: Pacing) !void {
    const crash_tick = prng.range(1, 1500);
    const at_boundary = pacing == .paced and prng.chance(1, 2);
    // Drawn only when paced, so unpaced seeds replay their original workloads.
    const pauses_target = if (at_boundary) harness.pauses + prng.range(1, 6) else 0;
    var tick: u64 = 0;
    while (tick < crash_tick or at_boundary) : (tick += 1) {
        try harness.step();
        if (at_boundary and harness.pauses >= pauses_target and harness.was_paused) {
            assert(harness.engine.checkpoint_paused());
            return;
        }
        if (tick >= 20_000) return error.NoChunkBoundary;
    }
}

test "engine: paced checkpoint writes in chunks and resumes on grant" {
    var sim = try sim_create(0x9ace);
    defer sim.deinit(testing.allocator);
    const harness = try harness_create(&sim, 0x9ace);
    defer harness_destroy(harness);
    try harness.format();
    _ = try harness.open();
    try harness.commit_durable(3);
    harness.snapshot_take();
    const producer: engine_module.Producer = .{ .context = harness, .produce = Harness.produce };
    try harness.engine.checkpoint_paced(producer, 1, Harness.on_checkpoint);
    const blocks = checkpoint_module.block_count(snapshot_size, config.checkpoint_block_size);
    try testing.expect(blocks >= 3);
    var chunk: u64 = 1;
    while (chunk < blocks) : (chunk += 1) {
        var ticks: u32 = 0;
        while (!harness.engine.checkpoint_paused()) : (ticks += 1) {
            if (ticks > 1_000) return error.Timeout;
            sim.tick();
        }
        try testing.expectEqual(chunk, harness.engine.checkpoint_io.block_index);
        // Paused: no superblock names the new checkpoint yet.
        try testing.expectEqual(@as(u64, 0), harness.engine.superblock.working.checkpoint.sequence);
        harness.engine.checkpoint_grant(1);
        try testing.expect(!harness.engine.checkpoint_paused());
    }
    try engine_module.tick_until_idle(&sim, &harness.engine, 10_000);
    if (harness.failure) |err| return err;
    try testing.expectEqual(@as(u64, 1), harness.engine.superblock.working.checkpoint.sequence);
    try harness.reinit();
    const result = try harness.open();
    try testing.expectEqual(@as(u64, 0), result.entries_replayed);
}

test "engine: seeded crashes mid paced checkpoint at chunk boundaries" {
    var fallbacks: u32 = 0;
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        fallbacks += run_fault_seed(seed, .paced) catch |err| {
            std.debug.print("engine paced fault injection: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(fallbacks >= 8);
}

test "engine: seeded crash and corruption fault injection" {
    var fallbacks: u32 = 0;
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        fallbacks += run_fault_seed(seed, .unpaced) catch |err| {
            std.debug.print("engine fault injection: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(fallbacks >= 16);
}

//! Engine tests, including the lane's crash-safety guarantee: a seeded fault-injection run
//! over many seeds. Each seed drives a random workload of commits and checkpoints against a
//! model, crashes at a random tick (losing, keeping, or tearing unsynced sectors), sometimes
//! rots one superblock copy, reopens, and checks that the recovered state is exactly the
//! model state after a prefix of the submitted entries that includes every acknowledged one.

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
        const start = self.engine.superblock.working.journal_start;
        try testing.expectEqual(self.recovered_sequence + 1, start.sequence);
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
            .on_entry = consume_entry,
        }, on_phase);
        try self.wait_phase();
        const result = try self.engine.open_result;
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
            self.snapshot_take();
            const producer: engine_module.Producer = .{ .context = self, .produce = produce };
            try engine.checkpoint(producer, on_checkpoint);
            self.checkpoint_requested = false;
        } else if (commit_idle and self.model.submitted < entries_max and
            self.prng.chance(1, 3))
        {
            try self.commit_random();
        }
        self.sim.tick();
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
                return;
            },
            else => return err,
        };
        try testing.expectEqual(index + 1, sequence);
        self.model.submitted += 1;
        self.commit_sequence = sequence;
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
    }
};

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
    try testing.expectEqual(engine_module.StopReason.clean, result.journal_stop);
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

fn run_fault_seed(seed: u64) !void {
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
    try harness.format();
    _ = try harness.open();
    var cycle: u32 = 0;
    while (cycle < 4) : (cycle += 1) {
        const crash_tick = prng.range(1, 1500);
        var tick: u64 = 0;
        while (tick < crash_tick) : (tick += 1) try harness.step();
        sim.crash();
        if (prng.chance(1, 4)) sim.corrupt_sector(@intCast(prng.below(4)));
        try harness.reinit();
        _ = try harness.open();
    }
}

test "engine: seeded crash and corruption fault injection" {
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        run_fault_seed(seed) catch |err| {
            std.debug.print("engine fault injection: failing seed={d}\n", .{seed});
            return err;
        };
    }
}

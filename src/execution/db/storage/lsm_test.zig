//! LSM tree tests: differential against a `std.AutoHashMap` model, crash recovery over the
//! engine, and coverage-guided fuzzing of the same workload and of the checkpoint decoder.
//!
//! The workload commits batches of puts and deletes through the engine journal (applying each
//! batch to the tree as it is submitted, as the database applies a block), grants the tree a
//! compaction budget per durable commit, forces memtable swaps, checkpoints (the tree's bytes
//! are the checkpoint), and looks keys up against the model. A crash at a random tick lands
//! mid flush, mid merge, mid checkpoint, or between them; sometimes the newest checkpoint is
//! rotted so open falls back. Open decodes the tree, scans its tables during the engine's
//! open pause, and replays the journal into the memtable; then every key of the universe
//! must read as the model at the recovered sequence.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const engine_module = @import("engine.zig");
const table_module = @import("table.zig");
const lsm = @import("lsm.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

const sector_size = storage.sector_size;
const Engine = engine_module.EngineType(SimStorage);
const BlockCache = table_module.BlockCache;

const block_size = 2 * sector_size;
const grid_blocks = 256;
const ops_per_commit_max = 8;
const op_size = 13;
const body_size_max = 4 + ops_per_commit_max * op_size;

const engine_config: engine_module.Config = .{
    .journal_size_bytes = 16 * sector_size,
    .checkpoint_zone_size_bytes = 6 * block_size,
    .entry_body_size_max = body_size_max,
    .checkpoint_block_size = block_size,
    .grid_block_count = grid_blocks,
};

/// The journal holds at most 8 entries (one header sector + one body sector each), so replay
/// writes at most 64 entries into the memtable.
const tree_config: lsm.Config = .{
    .block_size = block_size,
    .block_count = grid_blocks,
    .memtable_entries_max = 128,
    .flush_entries_min = 32,
    .replay_entries_max = 64,
    .table_records_max = 384,
    .level0_tables_max = 2,
    .levels_count = 3,
    .growth_factor = 4,
};

const zone_size = engine_config.checkpoint_zone_size_bytes;

const Op = struct { sequence: u64, key: u32, seed: u64, delete: bool };

const Counts = struct {
    crashes_flush: u32 = 0,
    crashes_merge: u32 = 0,
    crashes_checkpoint: u32 = 0,
    fallbacks: u32 = 0,
    merges: u64 = 0,
    flushes: u64 = 0,
    lookups_table: u64 = 0,
    orphans_released: u64 = 0,
    filter_negatives: u64 = 0,
};

fn HarnessType(comptime key_size: u32, comptime value_size: u32) type {
    return struct {
        const Harness = @This();
        const Tree = lsm.TreeType(SimStorage, key_size, value_size);
        const Key = Tree.Key;
        const Value = Tree.Value;

        engine: Engine,
        sim: *SimStorage,
        cache: BlockCache,
        tree: Tree,
        prng: Prng,
        universe: u32,
        log: []Op,
        log_len: u32 = 0,
        /// The model after every op applied so far (`model_at` of the newest sequence).
        current: std.AutoHashMap(u32, u64),
        snapshot: []u8,
        snapshot_len: u32 = 0,
        snapshot_position: u32 = 0,
        recovered: []u8,
        recovered_len: u32 = 0,
        budget: u64 = 4,
        pace_blocks: u64 = std.math.maxInt(u64),
        phase_done: bool = false,
        lookup_done: bool = false,
        /// False from a checkpoint start until it completes, and after an open that fell back.
        fallback_intact: bool = true,
        checkpoints: u32 = 0,
        counts: Counts = .{},

        fn create(sim: *SimStorage, seed: u64, universe: u32, log_max: u32) !*Harness {
            const self = try testing.allocator.create(Harness);
            errdefer testing.allocator.destroy(self);
            self.* = .{
                .engine = try .init(testing.allocator, sim, engine_config),
                .sim = sim,
                .cache = undefined,
                .tree = undefined,
                .prng = Prng.init(seed),
                .universe = universe,
                .log = try testing.allocator.alloc(Op, log_max),
                .current = .init(testing.allocator),
                .snapshot = try testing.allocator.alloc(u8, zone_size),
                .recovered = try testing.allocator.alloc(u8, zone_size),
            };
            try self.tree_init();
            return self;
        }

        fn destroy(self: *Harness) void {
            self.tree.deinit(testing.allocator);
            self.cache.deinit(testing.allocator);
            self.engine.deinit(testing.allocator);
            testing.allocator.free(self.log);
            self.current.deinit();
            testing.allocator.free(self.snapshot);
            testing.allocator.free(self.recovered);
            testing.allocator.destroy(self);
        }

        fn tree_init(self: *Harness) !void {
            self.cache = try BlockCache.init(testing.allocator, block_size, 16);
            errdefer self.cache.deinit(testing.allocator);
            var config = tree_config;
            config.memtable_entries_max = tree_config.memtable_entries_max;
            self.tree = try Tree.init(testing.allocator, &self.engine.grid.?, &self.cache, config);
            assert(self.tree.checkpoint_size_max() + self.engine.free_set_image.len <=
                engine_config.checkpoint_zone_size_bytes);
        }

        /// A crash: fresh engine, cache, and tree over the same storage.
        fn reinit(self: *Harness) !void {
            self.tree.deinit(testing.allocator);
            self.cache.deinit(testing.allocator);
            self.engine.deinit(testing.allocator);
            self.engine = try .init(testing.allocator, self.sim, engine_config);
            try self.tree_init();
            self.phase_done = false;
            self.lookup_done = false;
        }

        fn key_of(index: u32) Key {
            var key: Key = undefined;
            for (0..key_size / 8) |chunk| {
                // 64-byte keys share their first half per 16 indices (account ++ slot).
                const source: u64 = if (key_size == 64 and chunk < 4) index / 16 else index;
                const word = std.hash.Wyhash.hash(chunk, std.mem.asBytes(&source));
                std.mem.writeInt(u64, key[chunk * 8 ..][0..8], word, .little);
            }
            return key;
        }

        fn value_of(seed: u64) Value {
            var value: Value = undefined;
            for (0..value_size / 8) |chunk| {
                const word = if (chunk == 0)
                    seed
                else
                    std.hash.Wyhash.hash(chunk, std.mem.asBytes(&seed));
                std.mem.writeInt(u64, value[chunk * 8 ..][0..8], word, .little);
            }
            return value;
        }

        /// The model after every logged op at or below `sequence`.
        fn model_at(self: *const Harness, sequence: u64) !std.AutoHashMap(u32, u64) {
            var model = std.AutoHashMap(u32, u64).init(testing.allocator);
            errdefer model.deinit();
            for (self.log[0..self.log_len]) |op| {
                if (op.sequence > sequence) continue;
                if (op.delete) _ = model.remove(op.key) else try model.put(op.key, op.seed);
            }
            return model;
        }

        // Engine callbacks.

        fn on_phase(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            self.phase_done = true;
        }

        fn on_commit(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            self.tree.compact(self.budget);
        }

        fn on_checkpoint(engine: *Engine) void {
            const self: *Harness = @alignCast(@fieldParentPtr("engine", engine));
            _ = engine.checkpoint_result catch unreachable; // The zone fits the tree's max.
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

        fn consume_loaded(context: *anyopaque) void {
            const self: *Harness = @ptrCast(@alignCast(context));
            self.tree.bind(&self.engine.grid.?, &self.engine.free_set.?);
            self.tree.open_decode(self.recovered[0..self.recovered_len]) catch {
                return self.engine.open_resume(.corrupt);
            };
            self.tree.open_scan(on_scan);
        }

        fn on_scan(tree: *Tree) void {
            const self: *Harness = @alignCast(@fieldParentPtr("tree", tree));
            self.engine.open_resume(switch (tree.scan_outcome) {
                .loaded => .loaded,
                .corrupt => .corrupt,
            });
        }

        fn consume_entry(context: *anyopaque, entry: engine_module.Entry) void {
            const self: *Harness = @ptrCast(@alignCast(context));
            const count = std.mem.readInt(u32, entry.body[0..4], .little);
            for (0..count) |index| {
                const op = decode_op(entry.body[4 + index * op_size ..][0..op_size]);
                const key = key_of(op.key);
                const value = value_of(op.seed);
                // The replay reserve covers every entry the journal holds.
                self.tree.put_replay(&key, if (op.delete) null else &value) catch unreachable;
            }
        }

        fn on_lookup(tree: *Tree) void {
            const self: *Harness = @alignCast(@fieldParentPtr("tree", tree));
            self.lookup_done = true;
        }

        // Workload.

        fn wait(self: *Harness, flag: *bool) !void {
            var ticks: u32 = 0;
            while (!flag.*) : (ticks += 1) {
                if (ticks > 100_000) return error.Timeout;
                self.sim.tick();
            }
            flag.* = false;
        }

        fn lookup(self: *Harness, index: u32) !?u64 {
            const key = key_of(index);
            if (self.tree.lookup(&key, on_lookup) == .pending) {
                self.counts.lookups_table += 1;
                try self.wait(&self.lookup_done);
            }
            const found = try self.tree.lookup_result;
            if (!found) return null;
            const seed = std.mem.readInt(u64, self.tree.lookup_value[0..8], .little);
            try testing.expectEqualSlices(u8, &value_of(seed), &self.tree.lookup_value);
            return seed;
        }

        /// Submits one batch of ops as a journal entry and applies it to the tree.
        fn commit(self: *Harness, count: u32, ops: *[ops_per_commit_max]Op) void {
            assert(count >= 1 and count <= ops_per_commit_max);
            if (self.tree.capacity_free() < count) {
                // Busy: an empty commit still paces compaction.
                self.tree.compact(self.budget);
                return;
            }
            var body: [body_size_max]u8 = undefined;
            std.mem.writeInt(u32, body[0..4], count, .little);
            for (ops[0..count], 0..) |op, index| {
                encode_op(body[4 + index * op_size ..][0..op_size], op);
            }
            const metadata: engine_module.Metadata = @splat(0);
            const length = 4 + count * op_size;
            const sequence = self.engine.commit(body[0..length], &metadata, on_commit) catch |err| {
                assert(err == error.JournalFull);
                return;
            };
            for (ops[0..count]) |*op| {
                op.sequence = sequence;
                const key = key_of(op.key);
                const value = value_of(op.seed);
                self.tree.put(&key, if (op.delete) null else &value) catch unreachable; // Room.
                self.log[self.log_len] = op.*;
                self.log_len += 1;
                if (op.delete) {
                    _ = self.current.remove(op.key);
                } else {
                    self.current.put(op.key, op.seed) catch unreachable; // Test-sized.
                }
            }
        }

        fn checkpoint(self: *Harness) void {
            assert(self.engine.checkpoint_phase == .idle and self.engine.commit_callback == null);
            // The snapshot point: the tree's bytes and the free set's, with no tick between.
            self.snapshot_len = self.tree.checkpoint_encode(self.snapshot);
            self.snapshot_position = 0;
            const producer: engine_module.Producer = .{ .context = self, .produce = produce };
            const pace = self.pace_blocks;
            // No checkpoint or commit is running (asserted above).
            self.engine.checkpoint_paced(producer, pace, on_checkpoint) catch unreachable;
            self.fallback_intact = false;
        }

        /// One workload step chosen by `choice`, then one tick.
        fn step(self: *Harness, choice: u64, argument: u64) !void {
            const engine = &self.engine;
            var prng = Prng.init(argument);
            const idle_commit = engine.commit_callback == null;
            if (choice < 9 and idle_commit and self.log_len + ops_per_commit_max <= self.log.len) {
                var ops: [ops_per_commit_max]Op = undefined;
                const count: u32 = @intCast(prng.range(1, ops_per_commit_max));
                for (ops[0..count]) |*op| op.* = .{
                    .sequence = 0,
                    .key = @intCast(prng.below(self.universe)),
                    .seed = prng.int(u64),
                    .delete = prng.chance(1, 4),
                };
                self.commit(count, &ops);
            } else if (choice == 9 and idle_commit and engine.checkpoint_phase == .idle) {
                self.checkpoint();
            } else if (choice == 10) {
                _ = self.tree.swap();
            } else if (choice == 11) {
                const index: u32 = @intCast(prng.below(self.universe));
                try testing.expectEqual(self.current.get(index), try self.lookup(index));
            } else if (engine.checkpoint_paused()) {
                engine.checkpoint_grant(self.pace_blocks);
            }
            self.sim.tick();
        }

        /// Opens, then checks every key against the model at the recovered sequence (and drops
        /// the ops of commits the crash lost).
        fn open(self: *Harness) !engine_module.OpenResult {
            self.recovered_len = 0;
            self.engine.open(.{
                .context = self,
                .on_checkpoint = consume,
                .on_checkpoint_reset = consume_reset,
                .on_entry = consume_entry,
                .on_checkpoint_loaded = consume_loaded,
            }, on_phase);
            try self.wait(&self.phase_done);
            const result = try self.engine.open_result;
            if (result.checkpoint_fallback) self.fallback_intact = false;
            self.engine.free_set.?.assert_invariants();
            var kept: u32 = 0;
            for (self.log[0..self.log_len]) |op| {
                if (op.sequence > result.sequence_last) continue;
                self.log[kept] = op;
                kept += 1;
            }
            self.log_len = kept;
            self.current.deinit();
            self.current = try self.model_at(result.sequence_last);
            try self.check_all(result.sequence_last);
            return result;
        }

        fn check_all(self: *Harness, sequence: u64) !void {
            var model = try self.model_at(sequence);
            defer model.deinit();
            var index: u32 = 0;
            while (index < self.universe) : (index += 1) {
                const actual = try self.lookup(index);
                testing.expectEqual(model.get(index), actual) catch |err| {
                    std.debug.print("lsm: key {d} at sequence {d}\n", .{ index, sequence });
                    return err;
                };
            }
        }

        /// Counts what the crash interrupts, for the coverage assertions.
        fn note_crash(self: *Harness) void {
            const compaction = &self.tree.compaction;
            if (compaction.active and compaction.kind == .flush) self.counts.crashes_flush += 1;
            if (compaction.active and compaction.kind == .merge) self.counts.crashes_merge += 1;
            if (self.engine.checkpoint_phase != .idle) self.counts.crashes_checkpoint += 1;
            self.counts.merges += self.tree.stats.merges;
            self.counts.flushes += self.tree.stats.flushes;
            self.counts.orphans_released += self.tree.stats.orphans_released;
            self.counts.filter_negatives += self.tree.stats.filter_negatives;
        }

        /// Rots the newest checkpoint's first block header, forcing the fallback.
        fn rot_newest_checkpoint(self: *Harness) bool {
            const checkpoint_newest = self.engine.superblock.working.checkpoint;
            if (checkpoint_newest.sequence == 0) return false;
            const zone = checkpoint_newest.zone;
            const offset: usize = @intCast(engine_config.checkpoint_zone_offset(zone));
            self.sim.durable[offset] ^= 0x10;
            self.sim.memory[offset] ^= 0x10;
            return true;
        }

        fn format_and_open(self: *Harness, format_id: u128) !void {
            self.engine.format(format_id, on_phase);
            try self.wait(&self.phase_done);
            _ = try self.open();
        }
    };
}

fn encode_op(out: *[op_size]u8, op: Op) void {
    std.mem.writeInt(u32, out[0..4], op.key, .little);
    std.mem.writeInt(u64, out[4..12], op.seed, .little);
    out[12] = @intFromBool(op.delete);
}

fn decode_op(bytes: *const [op_size]u8) Op {
    return .{
        .sequence = 0,
        .key = std.mem.readInt(u32, bytes[0..4], .little),
        .seed = std.mem.readInt(u64, bytes[4..12], .little),
        .delete = bytes[12] != 0,
    };
}

/// Weighted workload choices: mostly commits, some checkpoints, swaps, and lookups.
fn choice_of(prng: *Prng) u64 {
    return switch (prng.below(32)) {
        0...17 => 0,
        18, 19 => 9,
        20, 21 => 10,
        22...24 => 11,
        else => 12,
    };
}

const CrashHarness = HarnessType(32, 8);

fn run_crash_seed(seed: u64, counts: *Counts) !void {
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 4)),
    });
    defer sim.deinit(testing.allocator);
    const harness = try CrashHarness.create(&sim, prng.int(u64), 300, 16_384);
    defer harness.destroy();
    harness.budget = prng.range(1, 8);
    if (prng.chance(1, 2)) harness.pace_blocks = 1;
    try harness.format_and_open(0x15a0_0000 + seed);
    for (0..5) |_| {
        const crash_tick = prng.range(100, 500);
        for (0..crash_tick) |_| try harness.step(choice_of(&prng), prng.int(u64));
        const fallback_ready = harness.fallback_intact and
            harness.engine.checkpoint_phase == .idle;
        harness.note_crash();
        sim.crash();
        const rotten = fallback_ready and prng.chance(1, 3) and harness.rot_newest_checkpoint();
        try harness.reinit();
        const result = try harness.open();
        if (rotten) try testing.expect(result.checkpoint_fallback);
        if (result.checkpoint_fallback) harness.counts.fallbacks += 1;
    }
    try testing.expect(harness.checkpoints > 0);
    counts.crashes_flush += harness.counts.crashes_flush;
    counts.crashes_merge += harness.counts.crashes_merge;
    counts.crashes_checkpoint += harness.counts.crashes_checkpoint;
    counts.fallbacks += harness.counts.fallbacks;
    counts.merges += harness.counts.merges;
    counts.flushes += harness.counts.flushes;
    counts.orphans_released += harness.counts.orphans_released;
    counts.filter_negatives += harness.counts.filter_negatives;
    counts.lookups_table += harness.counts.lookups_table;
}

test "lsm: crashes mid flush, merge, and checkpoint, and fallbacks recover the model" {
    var counts: Counts = .{};
    for (0..24) |seed| {
        run_crash_seed(seed, &counts) catch |err| {
            std.debug.print("lsm crash: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(counts.crashes_flush > 0);
    try testing.expect(counts.crashes_merge > 0);
    try testing.expect(counts.crashes_checkpoint > 0);
    try testing.expect(counts.fallbacks >= 4);
    try testing.expect(counts.merges > 0);
    try testing.expect(counts.orphans_released > 0);
    try testing.expect(counts.filter_negatives > 0);
    try testing.expect(counts.lookups_table > 0);
}

/// Clean reopens: tick until nothing is in flight, then crash (only unsynced grid writes of
/// no consequence are lost); every committed op must be recovered.
fn run_differential(comptime key_size: u32, comptime value_size: u32, seed: u64) !Counts {
    const Harness = HarnessType(key_size, value_size);
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = seed,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, prng.int(u64), 400, 16_384);
    defer harness.destroy();
    harness.budget = prng.range(2, 8);
    try harness.format_and_open(0xd1ff_0000 + seed);
    for (0..3) |_| {
        for (0..600) |_| try harness.step(choice_of(&prng), prng.int(u64));
        var ticks: u32 = 0;
        while (!harness.engine.idle() or harness.tree.compaction.io_pending) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            sim.tick();
        }
        try harness.check_all(std.math.maxInt(u64));
        const sequence_last = harness.engine.sequence_last();
        harness.counts.merges += harness.tree.stats.merges;
        harness.counts.flushes += harness.tree.stats.flushes;
        sim.crash();
        try harness.reinit();
        const result = try harness.open();
        try testing.expectEqual(sequence_last, result.sequence_last);
    }
    return harness.counts;
}

test "lsm: differential vs a hash map model, 32-byte keys, with checkpoint and reopen" {
    var merges: u64 = 0;
    for (0..4) |seed| merges += (try run_differential(32, 8, seed)).merges;
    try testing.expect(merges > 0);
}

test "lsm: differential vs a hash map model, 64-byte keys (account ++ slot)" {
    var merges: u64 = 0;
    for (0..3) |seed| merges += (try run_differential(64, 32, 100 + seed)).merges;
    try testing.expect(merges > 0);
}

/// Puts keys `first..first + count` (normal puts or journal replay puts).
const PutMode = enum { live, replay };

fn put_keys(
    comptime Harness: type,
    tree: *Harness.Tree,
    first: u32,
    count: u32,
    mode: PutMode,
) !void {
    assert(count > 0);
    for (first..first + count) |index| {
        const key = Harness.key_of(@intCast(index));
        const value = Harness.value_of(index);
        switch (mode) {
            .live => try tree.put(&key, &value),
            .replay => try tree.put_replay(&key, &value),
        }
    }
}

// The known replay-reserve gap: an open whose replay filled the mutable memtable into the
// reserve while a flush was pending, then a checkpoint before the first swap. The next
// replay must still fit `replay_entries_max` distinct new keys.
test "lsm: a checkpoint after a replay into the reserve leaves a full reserve" {
    const Harness = HarnessType(32, 8);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = 7,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 7, 400, 16);
    defer harness.destroy();
    try harness.format_and_open(0x9a70_0001);
    const tree = &harness.tree;
    const reserve = tree_config.replay_entries_max;
    // A live checkpoint: a flush pending, the mutable memtable at the normal limit.
    try put_keys(Harness, tree, 0, tree_config.flush_entries_min, .live);
    try testing.expect(tree.swap());
    try put_keys(Harness, tree, 1000, tree.capacity_free(), .live);
    try testing.expectEqual(@as(u32, 0), tree.capacity_free());
    var length = tree.checkpoint_encode(harness.snapshot);
    // Open: replay fills the reserve (the flush cannot run before the engine is ready).
    try tree.open_decode(harness.snapshot[0..length]);
    try put_keys(Harness, tree, 2000, reserve, .replay);
    try testing.expectEqual(tree_config.memtable_entries_max, tree.mutable_memtable().count);
    try testing.expect(tree.immutable_memtable().count > 0);
    // The next checkpoint waits until the pending flush installs (the reserve is restored).
    try testing.expect(!tree.checkpoint_ready());
    const flushes = tree.stats.flushes;
    tree.compact(std.math.maxInt(u64));
    var ticks: u32 = 0;
    while (!tree.checkpoint_ready() or tree.compaction.active) : (ticks += 1) {
        if (ticks > 100_000) return error.Timeout;
        sim.tick();
    }
    try testing.expectEqual(flushes + 1, tree.stats.flushes);
    // Then an open whose replay writes a full reserve of new keys.
    length = tree.checkpoint_encode(harness.snapshot);
    try tree.open_decode(harness.snapshot[0..length]);
    try put_keys(Harness, tree, 3000, reserve, .replay);
}

fn fuzz_workload(_: void, smith: *std.testing.Smith) anyerror!void {
    const Harness = HarnessType(32, 8);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = smith.value(u64),
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, smith.value(u64), 64, 4096);
    defer harness.destroy();
    harness.budget = smith.valueRangeAtMost(u64, 1, 8);
    try harness.format_and_open(0xf022);
    var steps: u32 = 0;
    while (!smith.eos() and steps < 400) : (steps += 1) {
        const choice = smith.valueRangeAtMost(u64, 0, 13);
        if (choice == 13) {
            sim.crash();
            try harness.reinit();
            _ = try harness.open();
            continue;
        }
        try harness.step(choice, smith.value(u64));
    }
    sim.crash();
    try harness.reinit();
    _ = try harness.open();
}

test "lsm: fuzz the workload with crashes against the model" {
    try fuzz.run({}, fuzz_workload, .{ .iterations = 24, .input_size_max = 4096 });
}

const DecodeContext = struct {
    const Tree = lsm.TreeType(SimStorage, 32, 8);

    sim: SimStorage,
    grid: Tree.Grid,
    cache: BlockCache,
    tree: Tree,
    sample: []u8,
    sample_len: u32,
    out: []u8,
};

/// Raw bytes, or (first byte odd) a valid checkpoint with bytes flipped: either way, what
/// decodes must re-encode to the same bytes.
fn fuzz_decode(context: *DecodeContext, bytes: []const u8) anyerror!void {
    const tree = &context.tree;
    var input: [2048]u8 = undefined;
    var length: usize = @min(bytes.len, input.len);
    @memcpy(input[0..length], bytes[0..length]);
    if (bytes.len > 0 and bytes[0] % 2 == 1) {
        length = context.sample_len;
        @memcpy(input[0..length], context.sample[0..length]);
        var index: usize = 1;
        while (index + 1 < bytes.len) : (index += 2) {
            input[bytes[index] * length / 256] ^= bytes[index + 1];
        }
    }
    tree.open_decode(input[0..length]) catch return;
    const encoded = tree.checkpoint_encode(context.out);
    if (length > 0) try testing.expectEqualSlices(u8, input[0..length], context.out[0..encoded]);
    tree.reset();
}

test "lsm: fuzz the checkpoint decoder" {
    const context = try testing.allocator.create(DecodeContext);
    defer testing.allocator.destroy(context);
    context.sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = grid_blocks * block_size,
        .seed = 1,
    });
    defer context.sim.deinit(testing.allocator);
    context.grid = .init(&context.sim, .{
        .zone_offset = 0,
        .block_size = block_size,
        .block_count = grid_blocks,
    });
    context.cache = try BlockCache.init(testing.allocator, block_size, 16);
    defer context.cache.deinit(testing.allocator);
    context.tree = try .init(testing.allocator, &context.grid, &context.cache, tree_config);
    defer context.tree.deinit(testing.allocator);
    context.out = try testing.allocator.alloc(u8, context.tree.checkpoint_size_max());
    defer testing.allocator.free(context.out);
    context.sample = try testing.allocator.alloc(u8, context.tree.checkpoint_size_max());
    defer testing.allocator.free(context.sample);
    // A valid sample: both memtables with values and tombstones (no tables: those need blocks).
    var prng = Prng.init(5);
    for (0..40) |index| {
        if (index == 20) try testing.expect(context.tree.swap());
        var key: [32]u8 = undefined;
        prng.fill(&key);
        const value = std.mem.toBytes(prng.int(u64));
        try context.tree.put(&key, if (index % 5 == 0) null else &value);
    }
    context.sample_len = context.tree.checkpoint_encode(context.sample);
    context.tree.reset();
    try fuzz.run_bytes(context, fuzz_decode, .{ .iterations = 512, .input_size_max = 2048 });
}

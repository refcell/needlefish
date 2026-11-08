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
const lsm_bulk = @import("lsm_bulk.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");
const build_options = @import("build_options");

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

fn tree_config_with(memtable_entries_max: u32, table_records_max: u32) lsm.Config {
    var config = tree_config;
    config.memtable_entries_max = memtable_entries_max;
    config.table_records_max = table_records_max;
    return config;
}

/// A harness shape: key and value sizes, value mode, tree config, and engine sizes.
const Spec = struct {
    key_size: u32,
    value_size: u32,
    variable: bool = false,
    tree: lsm.Config = tree_config,
    grid_blocks: u64 = grid_blocks,
    zone_blocks: u64 = engine_config.checkpoint_zone_size_bytes / block_size,
    cache_blocks: u32 = 16,
    /// The tree's filters and block lists start as 0xff bytes, not zeros (`tree_init`).
    poison: bool = false,

    fn engine(comptime spec: Spec) engine_module.Config {
        var config = engine_config;
        config.grid_block_count = spec.grid_blocks;
        config.checkpoint_zone_size_bytes = spec.zone_blocks * block_size;
        return config;
    }
};

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
    /// Synchronous block reads (`get` missing the block cache).
    reads_sync: u64 = 0,
    merges_last: u64 = 0,
    cuts_overlap: u64 = 0,
    /// Merge output tables overlapping more than `growth_factor` tables of the level below.
    cut_violations: u64 = 0,
};

fn HarnessType(comptime spec: Spec) type {
    return struct {
        const Harness = @This();
        const key_size = spec.key_size;
        const value_size = spec.value_size;
        const engine_config_spec = spec.engine();
        const zone_size = engine_config_spec.checkpoint_zone_size_bytes;
        const Tree = if (spec.variable)
            lsm.TreeVariableType(SimStorage, key_size, value_size)
        else
            lsm.TreeType(SimStorage, key_size, value_size);
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
        /// Keys `0..base` were bulk-loaded with their index as the value seed.
        base: u32 = 0,
        counts: Counts = .{},

        fn create(sim: *SimStorage, seed: u64, universe: u32, log_max: u32) !*Harness {
            const self = try testing.allocator.create(Harness);
            errdefer testing.allocator.destroy(self);
            self.* = .{
                .engine = try .init(testing.allocator, sim, engine_config_spec),
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
            self.cache = try BlockCache.init(testing.allocator, block_size, spec.cache_blocks);
            errdefer self.cache.deinit(testing.allocator);
            var config = spec.tree;
            config.block_count = spec.grid_blocks;
            self.tree = try Tree.init(testing.allocator, &self.engine.grid.?, &self.cache, config);
            if (spec.poison) {
                // Init does not zero them: a tree must never read one it did not set. All
                // ones is the worst case for both: a filter that rules out no key, and block
                // addresses past the grid.
                @memset(self.tree.filters, std.math.maxInt(u32));
                @memset(self.tree.slot_blocks, std.math.maxInt(u64));
            }
            assert(self.tree.checkpoint_size_max() + self.engine.free_set_image.len <=
                engine_config_spec.checkpoint_zone_size_bytes);
            self.tree.install_callback = on_install;
        }

        /// Checks every merge output against the cut rule: it overlaps at most
        /// `growth_factor` tables of the level below its output.
        fn on_install(tree: *Tree) void {
            const self: *Harness = @alignCast(@fieldParentPtr("tree", tree));
            const compaction = &tree.compaction;
            if (compaction.kind != .merge) return;
            const below = compaction.level_out + 1;
            if (below == tree.config.levels_count) return;
            for (compaction.outputs[0..compaction.output_count]) |slot| {
                const info = &tree.slot_infos[slot];
                _, const count = tree.level_overlap(below, &info.key_min, &info.key_max);
                if (count > tree.config.growth_factor) self.counts.cut_violations += 1;
            }
        }

        /// A crash: fresh engine, cache, and tree over the same storage.
        fn reinit(self: *Harness) !void {
            self.tree.deinit(testing.allocator);
            self.cache.deinit(testing.allocator);
            self.engine.deinit(testing.allocator);
            self.engine = try .init(testing.allocator, self.sim, engine_config_spec);
            try self.tree_init();
            self.phase_done = false;
            self.lookup_done = false;
        }

        fn key_of(index: u32) Key {
            var words: [(key_size + 7) / 8 * 8]u8 = undefined;
            for (0..words.len / 8) |chunk| {
                // Keys of 64 bytes and more share their first half per 16 indices (account ++
                // slot, account ++ path).
                const source: u64 = if (key_size >= 64 and chunk < 4) index / 16 else index;
                const word = std.hash.Wyhash.hash(chunk, std.mem.asBytes(&source));
                std.mem.writeInt(u64, words[chunk * 8 ..][0..8], word, .little);
            }
            return words[0..key_size].*;
        }

        /// The value length for `seed`: fixed trees their value size; variable trees often
        /// the largest value (so tables fill blocks), else any length from 1.
        fn value_length(seed: u64) u32 {
            if (!spec.variable) return value_size;
            const mixed = std.hash.Wyhash.hash(7, std.mem.asBytes(&seed));
            if (mixed % 8 < 3) return value_size;
            return @intCast(1 + (mixed >> 8) % value_size);
        }

        fn value_of(seed: u64) Value {
            var value: Value = @splat(0);
            var words: [(value_size + 7) / 8 * 8]u8 = undefined;
            for (0..words.len / 8) |chunk| {
                const word = if (chunk == 0)
                    seed
                else
                    std.hash.Wyhash.hash(chunk, std.mem.asBytes(&seed));
                std.mem.writeInt(u64, words[chunk * 8 ..][0..8], word, .little);
            }
            const length = value_length(seed);
            @memcpy(value[0..length], words[0..length]);
            return value;
        }

        /// What `Tree.put` takes for the value of `seed` (in `value`), or null for a delete.
        fn value_in(value: *const Value, seed: u64, delete: bool) ?Tree.ValueIn {
            if (delete) return null;
            if (spec.variable) return value[0..value_length(seed)];
            return value;
        }

        /// The model after every logged op at or below `sequence`.
        fn model_at(self: *const Harness, sequence: u64) !std.AutoHashMap(u32, u64) {
            var model = std.AutoHashMap(u32, u64).init(testing.allocator);
            errdefer model.deinit();
            // Bulk-loaded keys `0..base` hold their index, below every logged op.
            try model.ensureTotalCapacity(self.base);
            var index: u32 = 0;
            while (index < self.base) : (index += 1) model.putAssumeCapacity(index, index);
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
                const in = value_in(&value, op.seed, op.delete);
                self.tree.put_replay(&key, in) catch unreachable;
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

        /// Looks `index` up and checks it reads as `expected` (the seed of its value, or null
        /// when absent): presence, length, and every value byte.
        /// The synchronous `get` must agree, before the lookup and while it reads.
        fn expect_lookup(self: *Harness, index: u32, expected: ?u64) !void {
            const key = key_of(index);
            try expect_value(expected, try self.tree.get(&key));
            if (self.tree.lookup(&key, on_lookup) == .pending) {
                self.counts.lookups_table += 1;
                try expect_value(expected, try self.tree.get(&key));
                try self.wait(&self.lookup_done);
            }
            const found = try self.tree.lookup_result;
            try expect_value(expected, if (found) self.tree.lookup_bytes() else null);
        }

        fn expect_value(expected: ?u64, actual: ?[]const u8) !void {
            const seed = expected orelse return testing.expect(actual == null);
            const bytes = actual orelse return error.TestExpectedValue;
            const value = value_of(seed);
            try testing.expectEqualSlices(u8, value[0..value_length(seed)], bytes);
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
                const in = value_in(&value, op.seed, op.delete);
                self.tree.put(&key, in) catch unreachable; // Room.
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
            } else if (choice == 9 and idle_commit and engine.checkpoint_phase == .idle and
                self.tree.checkpoint_ready())
            {
                // As the database does: no checkpoint until the replay reserve is restored.
                self.checkpoint();
            } else if (choice == 10) {
                _ = self.tree.swap();
            } else if (choice == 11) {
                const index: u32 = @intCast(prng.below(self.universe));
                try self.expect_lookup(index, self.current.get(index));
            } else if (engine.checkpoint_paused()) {
                engine.checkpoint_grant(self.pace_blocks);
            }
            self.sim.tick();
        }

        /// Opens, then checks every key against the model at the recovered sequence (and drops
        /// the ops of commits the crash lost).
        fn open(self: *Harness) !engine_module.OpenResult {
            const result = try self.open_engine();
            try self.check_all(result.sequence_last);
            return result;
        }

        /// Opens and rebuilds the model at the recovered sequence, without reading keys.
        fn open_engine(self: *Harness) !engine_module.OpenResult {
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
            return result;
        }

        fn check_all(self: *Harness, sequence: u64) !void {
            var model = try self.model_at(sequence);
            defer model.deinit();
            var index: u32 = 0;
            while (index < self.universe) : (index += 1) {
                self.expect_lookup(index, model.get(index)) catch |err| {
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
            self.counts.merges_last += self.tree.stats.merges_last;
            self.counts.cuts_overlap += self.tree.stats.cuts_overlap;
        }

        const Loader = lsm_bulk.BulkLoaderType(Tree);
        const Load = struct {
            loader: Loader,
            done: bool = false,

            fn on_done(loader: *Loader) void {
                const load: *Load = @alignCast(@fieldParentPtr("loader", loader));
                load.done = true;
            }
        };

        fn key_less(keys: []const Key, a: u32, b: u32) bool {
            return std.mem.order(u8, &keys[a], &keys[b]) == .lt;
        }

        /// Bulk-loads keys `0..base` (value seed: the index) in key order into the empty tree.
        fn bulk_load(self: *Harness, base: u32) !void {
            assert(base > 0 and base <= self.universe and self.base == 0);
            const keys = try testing.allocator.alloc(Key, base);
            defer testing.allocator.free(keys);
            const order = try testing.allocator.alloc(u32, base);
            defer testing.allocator.free(order);
            for (keys, order, 0..) |*key, *position, index| {
                key.* = key_of(@intCast(index));
                position.* = @intCast(index);
            }
            std.mem.sortUnstable(u32, order, @as([]const Key, keys), key_less);
            var load: Load = .{ .loader = try Loader.init(testing.allocator, &self.tree) };
            defer load.loader.deinit(testing.allocator);
            load.loader.begin();
            // A repeated key and a smaller key are refused, and nothing is taken.
            if (base > 1) {
                try self.bulk_append(&load.loader, keys, order[0..2]);
                for (order[0..2]) |index| {
                    const value = value_of(index);
                    const refused = value_in(&value, index, false).?;
                    const result = load.loader.append(&keys[index], refused);
                    try testing.expectError(error.KeyOrder, result);
                }
                try self.bulk_append(&load.loader, keys, order[2..]);
            } else try self.bulk_append(&load.loader, keys, order);
            load.loader.finish(Load.on_done);
            try self.wait(&load.done);
            try load.loader.result;
            try testing.expect(!self.tree.bulk_active);
            self.base = base;
            var index: u32 = 0;
            while (index < base) : (index += 1) try self.current.put(index, index);
        }

        fn bulk_append(
            self: *Harness,
            loader: *Loader,
            keys: []const Key,
            order: []const u32,
        ) !void {
            for (order) |index| {
                const value = value_of(index);
                const in = value_in(&value, index, false).?;
                var ticks: u32 = 0;
                while (true) : (ticks += 1) {
                    if (ticks > 1000) return error.Timeout;
                    loader.append(&keys[index], in) catch |err| switch (err) {
                        error.Busy => {
                            self.sim.tick();
                            continue;
                        },
                        else => return err,
                    };
                    break;
                }
            }
        }

        /// Checkpoints and ticks until the checkpoint is durable.
        fn checkpoint_wait(self: *Harness) !void {
            const checkpoints = self.checkpoints;
            self.checkpoint();
            var ticks: u32 = 0;
            while (self.checkpoints == checkpoints) : (ticks += 1) {
                if (ticks > 1_000_000) return error.Timeout;
                if (self.engine.checkpoint_paused()) self.engine.checkpoint_grant(self.pace_blocks);
                self.sim.tick();
            }
        }

        /// Rots the newest checkpoint's first block header, forcing the fallback.
        fn rot_newest_checkpoint(self: *Harness) bool {
            const checkpoint_newest = self.engine.superblock.working.checkpoint;
            if (checkpoint_newest.sequence == 0) return false;
            const zone = checkpoint_newest.zone;
            const offset: usize = @intCast(engine_config_spec.checkpoint_zone_offset(zone));
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

/// Poisoned: the crash test also proves the tree never reads a filter or block list it did
/// not set (a slot's filter all ones would rule out nothing: no filter negatives).
const CrashHarness = HarnessType(.{ .key_size = 32, .value_size = 8, .poison = true });

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
fn run_differential(comptime spec: Spec, seed: u64) !Counts {
    const Harness = HarnessType(spec);
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = spec.engine().size_bytes(),
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
    harness.counts.reads_sync = sim.stats.reads_sync;
    return harness.counts;
}

test "lsm: differential vs a hash map model, 32-byte keys, with checkpoint and reopen" {
    var merges: u64 = 0;
    var reads_sync: u64 = 0;
    const spec: Spec = .{ .key_size = 32, .value_size = 8 };
    for (0..4) |seed| {
        const counts = try run_differential(spec, seed);
        merges += counts.merges;
        reads_sync += counts.reads_sync;
    }
    try testing.expect(merges > 0);
    try testing.expect(reads_sync > 0);
}

test "lsm: differential vs a hash map model, 64-byte keys (account ++ slot)" {
    var merges: u64 = 0;
    const spec: Spec = .{ .key_size = 64, .value_size = 32 };
    for (0..3) |seed| merges += (try run_differential(spec, 100 + seed)).merges;
    try testing.expect(merges > 0);
}

/// 65-byte keys (account ++ branch path) with values of 1..120 bytes.
const spec_variable: Spec = .{
    .key_size = 65,
    .value_size = 120,
    .variable = true,
    .zone_blocks = 12,
};

test "lsm: differential vs a hash map model, 65-byte keys, variable-length values" {
    var merges: u64 = 0;
    for (0..4) |seed| merges += (try run_differential(spec_variable, 200 + seed)).merges;
    try testing.expect(merges > 0);
}

/// Flushes `count` keys into level 0 and returns the slot of a level-0 table.
fn flush_keys(comptime Harness: type, harness: *Harness, count: u32) !u32 {
    const tree = &harness.tree;
    try put_keys(Harness, tree, 0, count, .live);
    try testing.expect(tree.swap());
    tree.compact(std.math.maxInt(u64));
    var ticks: u32 = 0;
    while (!tree.compaction_idle()) : (ticks += 1) {
        if (ticks > 100_000) return error.Timeout;
        harness.sim.tick();
    }
    try testing.expect(tree.level_count[0] > 0);
    return tree.level_list(0)[0];
}

test "lsm: get reports a rotted table block as corrupt and faults the tree" {
    const Harness = HarnessType(.{ .key_size = 32, .value_size = 8 });
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = 21,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 21, 64, 16);
    defer harness.destroy();
    try harness.format_and_open(0x2077_0001);
    const tree = &harness.tree;
    const slot = try flush_keys(Harness, harness, 60);
    // Healthy first: every key reads, through the grid (the cache holds nothing yet).
    for (0..60) |index| {
        try Harness.expect_value(index, try tree.get(&Harness.key_of(@intCast(index))));
    }
    try testing.expect(sim.stats.reads_sync > 0);
    // Rot the first data block, and drop the cached copy (a cold block).
    const address = tree.table_blocks(slot)[1];
    const rotten: usize = @intCast(harness.engine.grid.?.offset_of(address) + 200);
    sim.durable[rotten] ^= 0x20;
    sim.memory[rotten] ^= 0x20;
    @memset(harness.cache.addresses, 0);
    const key_min = tree.slot_infos[slot].key_min;
    try testing.expectError(error.Corrupt, tree.get(&key_min));
    try testing.expect(tree.fault);
    // Sticky: other keys past the memtables, and async lookups, report it too.
    try testing.expectError(error.Corrupt, tree.get(&Harness.key_of(1)));
    try testing.expectEqual(lsm.Status.done, tree.lookup(&key_min, Harness.on_lookup));
    try testing.expectError(error.Corrupt, tree.lookup_result);
    // The memtables still serve their keys.
    try put_keys(Harness, tree, 100, 1, .live);
    try Harness.expect_value(100, try tree.get(&Harness.key_of(100)));
}

test "lsm: get retries transient read faults" {
    const Harness = HarnessType(.{ .key_size = 32, .value_size = 8 });
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = engine_config.size_bytes(),
        .seed = 22,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 22, 64, 16);
    defer harness.destroy();
    try harness.format_and_open(0x2077_0002);
    const tree = &harness.tree;
    _ = try flush_keys(Harness, harness, 60);
    sim.options.read_fault_numerator = 100; // 10% of reads flip a bit.
    for (0..60) |index| {
        @memset(harness.cache.addresses, 0);
        try Harness.expect_value(index, try tree.get(&Harness.key_of(@intCast(index))));
    }
    try testing.expect(sim.stats.read_faults > 0);
    try testing.expect(harness.engine.grid.?.stats.read_retries > 0);
    try testing.expect(!tree.fault);
}

test "lsm: differential with tables smaller than a memtable (multi-table flushes)" {
    const config = comptime tree_config_with(128, 48);
    var flushes: u64 = 0;
    const fixed: Spec = .{ .key_size = 32, .value_size = 8, .tree = config };
    for (0..2) |seed| flushes += (try run_differential(fixed, 300 + seed)).flushes;
    const variable = comptime blk: {
        var spec = spec_variable;
        spec.tree = config;
        break :blk spec;
    };
    for (0..2) |seed| flushes += (try run_differential(variable, 400 + seed)).flushes;
    try testing.expect(flushes > 0);
}

/// Puts `count` keys, flushes them, and checks the level-0 tables the flush cut: within the
/// record and data block limits, covering every record, and the keys read back.
fn run_flush_cut(comptime spec: Spec, count: u32) !void {
    const Harness = HarnessType(spec);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = spec.engine().size_bytes(),
        .seed = 11,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 11, count, 16);
    defer harness.destroy();
    try harness.format_and_open(0xc070_0000 + spec.key_size);
    const tree = &harness.tree;
    try put_keys(Harness, tree, 0, count, .live);
    try testing.expect(tree.swap());
    tree.compact(std.math.maxInt(u64));
    var ticks: u32 = 0;
    while (!tree.compaction_idle()) : (ticks += 1) {
        if (ticks > 100_000) return error.Timeout;
        sim.tick();
    }
    const layout = tree.layout;
    var records: u64 = 0;
    var cut_blocks: u32 = 0;
    var cut_records: u32 = 0;
    try testing.expect(tree.level_count[0] >= 2);
    try testing.expect(tree.level_count[0] <= layout.tables_max[0]);
    for (tree.level_list(0)) |slot| {
        const info = &tree.slot_infos[slot];
        try testing.expect(info.record_count <= spec.tree.table_records_max);
        try testing.expect(info.data_block_count <= layout.data_blocks_max);
        if (info.data_block_count == layout.data_blocks_max) cut_blocks += 1;
        if (info.record_count == spec.tree.table_records_max) cut_records += 1;
        records += info.record_count;
    }
    try testing.expectEqual(@as(u64, count), records);
    // Fixed trees cut by records; large variable values cut by data blocks first.
    if (spec.variable) try testing.expect(cut_blocks > 0) else try testing.expect(cut_records > 0);
    var index: u32 = 0;
    while (index < count) : (index += 1) try harness.expect_lookup(index, index);
}

test "lsm: a flush writes several level-0 tables, cut by records or by data blocks" {
    // Room for several level-0 tables, so no merge follows the flush.
    const fixed = comptime blk: {
        var config = tree_config_with(128, 48);
        config.level0_tables_max = 8;
        break :blk config;
    };
    try run_flush_cut(.{ .key_size = 32, .value_size = 8, .tree = fixed, .zone_blocks = 24 }, 64);
    // Values up to 1000 bytes: a table of 4096 records would need more data blocks than an
    // index block names, so the flush cuts at a full index block.
    const variable = comptime blk: {
        var config = tree_config_with(1024, 4096);
        config.level0_tables_max = 8;
        break :blk config;
    };
    try run_flush_cut(.{
        .key_size = 65,
        .value_size = 1000,
        .variable = true,
        .tree = variable,
        .grid_blocks = 1024,
        .zone_blocks = 290,
    }, 960);
}

/// A tree for bulk loads: a last level of ~21 bulk-loaded tables (room for 38) right below
/// level 1, whose tables (merged from level 0's random keys) each span the whole key space.
/// Without the grandparent cut a level-1 merge into the last level would rewrite every table
/// there, which no job may (`tables_max`), so `start` panics ("the last level is full").
const spec_bulk: Spec = .{
    .key_size = 32,
    .value_size = 8,
    .tree = .{
        .block_size = block_size,
        .block_count = 2048,
        .memtable_entries_max = 128,
        .flush_entries_min = 32,
        .replay_entries_max = 64,
        .table_records_max = 384,
        .level0_tables_max = 2,
        .levels_count = 3,
        .growth_factor = 8,
    },
    .grid_blocks = 2048,
    .zone_blocks = 8,
    .cache_blocks = 1024,
};

/// 1M keys (slow tests): 4096-record tables, three levels with growth 128, so level 1 (2048
/// records) merges straight into the ~245-table last level within the run.
const spec_bulk_large: Spec = .{
    .key_size = 32,
    .value_size = 8,
    .tree = .{
        .block_size = block_size,
        .block_count = 16_384,
        .memtable_entries_max = 1024,
        .flush_entries_min = 256,
        .replay_entries_max = 64,
        .table_records_max = 4096,
        .level0_tables_max = 2,
        .levels_count = 3,
        .growth_factor = 128,
    },
    .grid_blocks = 16_384,
    .zone_blocks = 32,
    .cache_blocks = 2048,
};

const BulkRun = struct {
    base: u32,
    rounds: u32,
    steps: u32,
    /// The last level holds more tables than one merge may rewrite (the panic shape).
    wide: bool = false,
    /// Compaction blocks granted per commit (0: random, 2 to 8).
    budget: u64 = 0,
};

/// Bulk-loads keys `0..base`, checkpoints, then runs rounds of random puts and deletes over
/// the same keys with compaction and checkpoints, each round ending in a crash and a reopen
/// that checks every key against the model.
fn run_bulk(comptime spec: Spec, seed: u64, run: BulkRun) !Counts {
    const Harness = HarnessType(spec);
    var prng = Prng.init(seed);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = spec.engine().size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 3)),
    });
    defer sim.deinit(testing.allocator);
    const log_max = run.rounds * run.steps * ops_per_commit_max;
    const harness = try Harness.create(&sim, prng.int(u64), run.base, log_max);
    defer harness.destroy();
    harness.budget = if (run.budget > 0) run.budget else prng.range(2, 8);
    try harness.format_and_open(0xb01c_0000 + seed);
    try harness.bulk_load(run.base);
    const last = spec.tree.levels_count - 1;
    // More tables than a merge may rewrite with the level it reads from.
    const count = harness.tree.level_count[last];
    if (run.wide) try testing.expect(2 * count + 1 > harness.tree.layout.tables_max[last]);
    try harness.checkpoint_wait();
    var round: u32 = 0;
    while (round < run.rounds) : (round += 1) {
        for (0..run.steps) |_| try harness.step(choice_of(&prng), prng.int(u64));
        harness.note_crash();
        sim.crash();
        try harness.reinit();
        const result = try harness.open();
        try testing.expect(!result.checkpoint_fallback);
    }
    harness.counts.reads_sync = sim.stats.reads_sync;
    return harness.counts;
}

fn expect_bulk_counts(counts: Counts) !void {
    // Merges reached the bulk-loaded last level, their outputs were cut at grandparent
    // overlap, and no output overlaps more than `growth_factor` tables below it.
    try testing.expect(counts.merges_last > 0);
    try testing.expect(counts.cuts_overlap > 0);
    try testing.expectEqual(@as(u64, 0), counts.cut_violations);
}

test "lsm: bulk load, then puts, deletes, merges into the last level, crashes, reopens" {
    var total: Counts = .{};
    for (0..3) |seed| {
        const counts = run_bulk(spec_bulk, 500 + seed, .{
            .base = 8000,
            .rounds = 4,
            .steps = 2500,
            .wide = true,
        }) catch |err| {
            std.debug.print("lsm bulk: failing seed={d}\n", .{500 + seed});
            return err;
        };
        total.merges += counts.merges;
        total.merges_last += counts.merges_last;
        total.cuts_overlap += counts.cuts_overlap;
        total.cut_violations += counts.cut_violations;
    }
    try expect_bulk_counts(total);
}

test "lsm: bulk load 1M records, then rounds of writes with crashes (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const counts = try run_bulk(spec_bulk_large, 600, .{
        .base = 1_000_000,
        .rounds = 3,
        .steps = 30_000,
        // A merge into the last level rewrites up to `growth_factor` tables of 24 blocks.
        .budget = 128,
    });
    try expect_bulk_counts(counts);
}

/// 65-byte keys, values up to 1000 bytes: tables cut by data blocks.
const spec_bulk_variable: Spec = .{
    .key_size = 65,
    .value_size = 1000,
    .variable = true,
    .tree = .{
        .block_size = block_size,
        .block_count = 1024,
        .memtable_entries_max = 64,
        .flush_entries_min = 16,
        .replay_entries_max = 8,
        .table_records_max = 4096,
        .level0_tables_max = 2,
        .levels_count = 3,
        .growth_factor = 8,
    },
    .grid_blocks = 1024,
    .zone_blocks = 64,
    .cache_blocks = 64,
};

test "lsm: bulk load of variable values cuts tables by data blocks, then TreeFull" {
    const Harness = HarnessType(spec_bulk_variable);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = spec_bulk_variable.engine().size_bytes(),
        .seed = 41,
        .latency_ticks_max = 3,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 41, 1500, 16);
    defer harness.destroy();
    try harness.format_and_open(0xb01c_0041);
    try harness.bulk_load(1500);
    const tree = &harness.tree;
    const last = spec_bulk_variable.tree.levels_count - 1;
    var records: u64 = 0;
    var cut_blocks: u32 = 0;
    for (tree.level_list(last)) |slot| {
        const info = &tree.slot_infos[slot];
        try testing.expect(info.data_block_count <= tree.layout.data_blocks_max);
        if (info.data_block_count == tree.layout.data_blocks_max) cut_blocks += 1;
        records += info.record_count;
    }
    try testing.expectEqual(@as(u64, 1500), records);
    try testing.expect(cut_blocks > 0);
    var index: u32 = 0;
    while (index < 1500) : (index += 1) try harness.expect_lookup(index, index);
    try harness.checkpoint_wait();
    try harness.reinit();
    _ = try harness.open();
    // A load past the last level's slots fails, sticky, and still finishes.
    tree.reset();
    var load: Harness.Load = .{ .loader = try Harness.Loader.init(testing.allocator, tree) };
    defer load.loader.deinit(testing.allocator);
    load.loader.begin();
    var key: Harness.Key = @splat(0);
    var value: Harness.Value = @splat(0xab);
    var failed = false;
    var appended: u32 = 0;
    while (appended < 1_000_000 and !failed) : (appended += 1) {
        std.mem.writeInt(u32, key[0..4], appended, .big);
        load.loader.append(&key, &value) catch |err| switch (err) {
            error.Busy => sim.tick(),
            error.TreeFull, error.NoSpace => failed = true,
            else => return err,
        };
    }
    try testing.expect(failed and load.loader.stats.busy > 0);
    load.loader.finish(Harness.Load.on_done);
    try harness.wait(&load.done);
    try testing.expect(!tree.bulk_active);
    _ = load.loader.result catch return;
    return error.TestExpectedError;
}

test "lsm: a rotted last-level block is found by get, not by open" {
    const Harness = HarnessType(spec_bulk);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = spec_bulk.engine().size_bytes(),
        .seed = 31,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 31, 3000, 16);
    defer harness.destroy();
    try harness.format_and_open(0xb01c_0031);
    try harness.bulk_load(3000);
    try harness.checkpoint_wait();
    const tree = &harness.tree;
    const last = spec_bulk.tree.levels_count - 1;
    const slots = tree.level_list(last);
    try testing.expect(slots.len >= 4);
    const slot = slots[slots.len / 2];
    const key_rotten = tree.slot_infos[slot].key_min;
    const key_healthy = tree.slot_infos[slots[0]].key_max;
    const address = tree.table_blocks(slot)[1];
    const rotten: usize = @intCast(harness.engine.grid.?.offset_of(address) + 200);
    sim.durable[rotten] ^= 0x08;
    sim.memory[rotten] ^= 0x08;
    sim.crash();
    try harness.reinit();
    // Open does not read the last level: it loads the checkpoint (no fallback, no fault).
    const reads = sim.stats.reads;
    const result = try harness.open_engine();
    try testing.expect(!result.checkpoint_fallback);
    try testing.expect(!harness.tree.fault);
    try testing.expectEqual(@as(u32, @intCast(slots.len)), harness.tree.level_count[last]);
    try testing.expect(sim.stats.reads - reads < 64); // Not one read per loaded block.
    // The healthy table reads; the rotted block is reported, and faults the tree.
    try testing.expect(try harness.tree.get(&key_healthy) != null);
    try testing.expectError(error.Corrupt, harness.tree.get(&key_rotten));
    try testing.expect(harness.tree.fault);
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
        const in = Harness.value_in(&value, index, false);
        switch (mode) {
            .live => try tree.put(&key, in),
            .replay => try tree.put_replay(&key, in),
        }
    }
}

// The known replay-reserve gap: an open whose replay filled the mutable memtable into the
// reserve while a flush was pending, then a checkpoint before the first swap. The next
// replay must still fit `replay_entries_max` distinct new keys.
test "lsm: a checkpoint after a replay into the reserve leaves a full reserve" {
    const Harness = HarnessType(.{ .key_size = 32, .value_size = 8 });
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
    const Harness = HarnessType(.{ .key_size = 32, .value_size = 8 });
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

fn DecodeContextType(comptime Tree: type) type {
    return struct {
        const Context = @This();

        sim: SimStorage,
        grid: Tree.Grid,
        cache: BlockCache,
        tree: Tree,
        sample: []u8,
        sample_len: u32,
        out: []u8,

        /// Raw bytes, or (first byte odd) a valid checkpoint with bytes flipped: either way,
        /// what decodes must re-encode to the same bytes.
        fn fuzz_decode(context: *Context, bytes: []const u8) anyerror!void {
            const tree = &context.tree;
            var input: [8192]u8 = undefined;
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
            if (length > 0) {
                try testing.expectEqualSlices(u8, input[0..length], context.out[0..encoded]);
            }
            tree.reset();
        }

        fn run(seed: u64) !void {
            const context = try testing.allocator.create(Context);
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
            const tree = &context.tree;
            tree.* = try .init(testing.allocator, &context.grid, &context.cache, tree_config);
            defer tree.deinit(testing.allocator);
            context.out = try testing.allocator.alloc(u8, tree.checkpoint_size_max());
            defer testing.allocator.free(context.out);
            context.sample = try testing.allocator.alloc(u8, tree.checkpoint_size_max());
            defer testing.allocator.free(context.sample);
            // A valid sample: both memtables with values (of random lengths in a variable
            // tree) and tombstones (no tables: those need blocks).
            var prng = Prng.init(seed);
            for (0..40) |index| {
                if (index == 20) try testing.expect(tree.swap());
                var key: Tree.Key = undefined;
                prng.fill(&key);
                var value: Tree.Value = undefined;
                prng.fill(&value);
                const length = if (Tree.variable) prng.range(1, 48) else Tree.value_bytes;
                const in: Tree.ValueIn = if (Tree.variable) value[0..length] else &value;
                try tree.put(&key, if (index % 5 == 0) null else in);
            }
            context.sample_len = tree.checkpoint_encode(context.sample);
            assert(context.sample_len <= 8192);
            tree.reset();
            // The sample itself decodes (so flipped samples reach the deep checks).
            try tree.open_decode(context.sample[0..context.sample_len]);
            tree.reset();
            const options: fuzz.Options = .{ .iterations = 512, .input_size_max = 2048 };
            try fuzz.run_bytes(context, fuzz_decode, options);
        }
    };
}

test "lsm: fuzz the checkpoint decoder" {
    try DecodeContextType(lsm.TreeType(SimStorage, 32, 8)).run(5);
}

test "lsm: fuzz the checkpoint decoder, 65-byte keys and variable-length values" {
    try DecodeContextType(lsm.TreeVariableType(SimStorage, 65, 120)).run(6);
}

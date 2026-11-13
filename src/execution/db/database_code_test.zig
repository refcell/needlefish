//! Database tests for code tables on the grid (disk state phase 1d).
//!
//! - Crash recovery: seeded workloads of blocks that deploy codes of random sizes (some too
//!   long for a table, kept in the image), side branches, reorgs, and checkpoints, with a
//!   short table list so rewrites happen. Each cycle crashes at a random tick, mid flush,
//!   mid rewrite, or mid checkpoint, sometimes rots the newest checkpoint (fallback), then
//!   reopens and checks the head, the state root, and every code byte for byte against the
//!   live run at the recovered entry.
//! - Differential: the same seeded blocks on a grid database and a grid-less one (and one
//!   whose grid is too small to flush) give the same heads, roots, and codes, live and
//!   after reopen; the grid's checkpoint image is smaller.
//! - Compatibility: a grid-less file with version 2 superblocks opens unchanged without a
//!   grid and is refused (`LayoutMismatch`) with one.
//! - Rot in a table block only the newest checkpoint names falls back to the older one.
//! - Pinned mode (`Config.code_pin_bytes`, codes out of RAM, phase 1e): the crash recovery
//!   and the differential again, with codes read back from their tables through a block
//!   cache of one set (16 blocks, so codes are evicted and read again) into a pin buffer of
//!   a few codes (so pins run out). Between steps the harness reads random codes, keeps
//!   every slice until it releases the pins, and checks each again right before: a pin
//!   that does not last until the release shows (safe builds overwrite released pins). Its
//!   checkpoints are byte for byte the resident mode's. A rotten table block fails the read
//!   of its codes only, and a rewrite that meets it aborts without changing a table.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const drive = @import("database_test.zig").drive;
const storage = @import("storage/storage.zig");
const superblock_module = @import("storage/superblock.zig");
const checkpoint_module = @import("storage/checkpoint.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const code_store_module = @import("code_store.zig");
const keccak256 = @import("../trie/node.zig").keccak256;
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = database.Hash;
const HeadInfo = database.HeadInfo;
const BlockInput = database.BlockInput;
const Overlay = overlay_module.Overlay;
const State = state_module.State;
const Database = database.DatabaseType(SimStorage);
const sector_size = storage.sector_size;

const block_size: u32 = 2 * sector_size;
/// Longest code a table holds at this block size; longer ones stay in the image.
const table_value_max: u32 = block_size - 128 - 8 - 4 - 32;

const config_grid: database.Config = .{
    .engine = .{
        .journal_size_bytes = 192 * sector_size,
        .checkpoint_zone_size_bytes = 128 * block_size,
        .entry_body_size_max = 6 * sector_size,
        .checkpoint_block_size = block_size,
        .grid_block_count = 320,
    },
    .state = .{
        .accounts_max = 64,
        .storage_slots_max = 512,
        .codes_max = 256,
        .code_bytes_max = 512 * 1024,
        .account_nodes_max = 1024,
        .storage_nodes_max = 8192,
    },
    .chain = .{
        .blocks_max = 24,
        .bytes_max = 160 * 1024,
        .transactions_max = 128,
        .canonical_max = 64,
        .reorg_depth_max = 16,
    },
    .changeset = .{
        .accounts_max = 64,
        .storage_max = 256,
        .codes_max = 4,
        .code_bytes_max = 16 * 1024,
    },
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 1024 * 1024,
    .code_tables_max = 4,
    .code_flush_bytes_min = 0,
};

/// Codes out of RAM: a few codes pinned at once, one cache set.
const config_pinned: database.Config = blk: {
    var config = config_grid;
    config.code_pin_bytes = 3 * table_value_max;
    config.code_pins_max = 6;
    config.code_cache_blocks = 16;
    break :blk config;
};

const config_plain: database.Config = blk: {
    var config = config_grid;
    config.engine.grid_block_count = 0;
    break :blk config;
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 64,
    .slots_max = 256,
    .codes_max = 4,
};

const addresses_max = 32;
const sequences_max = 64 * 1024;
const known_blocks_max = 64;
/// Build-time caps well below the state's, so blocks applied later (reorgs) still fit.
const codes_cap = 160;
const code_bytes_cap = 256 * 1024;

fn address_of(index: u64) state_module.Address {
    var address: state_module.Address = @splat(0x22);
    address[0] = @intCast(index);
    return address;
}

fn hash_of(id: u32, salt: u8) Hash {
    var hash: Hash = @splat(salt);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

/// Order-independent summary of a state's code set, without the `leaked` codes.
const Digest = struct {
    count: u32 = 0,
    xor: Hash = @splat(0),

    fn of(state: *const State, leaked: *const Leaked) Digest {
        var digest: Digest = .{};
        var keys = state.code_table.keyIterator();
        while (keys.next()) |key| {
            if (leaked.contains(key.*)) continue;
            digest.count += 1;
            for (&digest.xor, key) |*byte, other| byte.* ^= other;
        }
        return digest;
    }

    fn eql(a: Digest, b: Digest) bool {
        return a.count == b.count and std.mem.eql(u8, &a.xor, &b.xor);
    }
};

/// Codes an executed block put into the state (`Overlay.insert_code` writes through to it)
/// whose commit then failed (`Busy`): never journaled, so a restart may not have them. No
/// account references them; the database behaves the same with or without the grid.
const Leaked = std.AutoHashMapUnmanaged(Hash, void);

const held_max = 12;
const Held = struct { hash: Hash, code: []const u8 };

const PinnedCounts = struct {
    /// Codes read from a table (not from the arena) and found intact.
    reads_table: u64 = 0,
    /// Reads refused for want of a pin (then released and read again).
    pins_full: u64 = 0,
    /// Table codes read after a rewrite re-pointed them, before any reopen.
    reads_after_rewrite: u64 = 0,
    /// Rewrites that read codes held in tables only.
    rewrites_from_tables: u64 = 0,
};

const Harness = struct {
    db: Database,
    sim: *SimStorage,
    prng: Prng,
    /// The pinned reads' own randomness: the blocks stay those of any other mode's harness.
    read_prng: Prng,
    overlay: Overlay,
    config: database.Config,
    heads: []HeadInfo,
    digests: []Digest,
    submitted: u64 = 0,
    known: [known_blocks_max]Hash = undefined,
    known_len: u32 = 0,
    block_id_next: u32 = 0,
    header_buffer: [64]u8 = undefined,
    code_buffer: [table_value_max + 200]u8 = undefined,
    /// Every code ever deployed, by hash (owned copies).
    model: std.AutoHashMapUnmanaged(Hash, []u8) = .empty,
    leaked: Leaked = .empty,
    fallback_intact: bool = true,
    checkpoints_seen: u64 = 0,
    /// Pinned mode: codes read since the last release, each with the slice returned.
    held: [held_max]Held = undefined,
    held_len: u32 = 0,
    pinned: PinnedCounts = .{},
    rewrite_seen: bool = false,
    /// Pinned mode: read random codes between steps.
    random_reads: bool = true,

    fn create(sim: *SimStorage, seed: u64, config: database.Config) !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        const heads = try testing.allocator.alloc(HeadInfo, sequences_max + 1);
        errdefer testing.allocator.free(heads);
        const digests = try testing.allocator.alloc(Digest, sequences_max + 1);
        errdefer testing.allocator.free(digests);
        heads[0] = .{};
        digests[0] = .{};
        self.* = .{
            .db = try Database.init(testing.allocator, sim, config),
            .sim = sim,
            .prng = Prng.init(seed),
            .read_prng = Prng.init(seed ^ 0x9e37_79b9),
            .overlay = undefined,
            .config = config,
            .heads = heads,
            .digests = digests,
        };
        self.overlay = try Overlay.init(testing.allocator, &self.db.state, overlay_config);
        return self;
    }

    fn destroy(self: *Harness) void {
        var codes = self.model.valueIterator();
        while (codes.next()) |code| testing.allocator.free(code.*);
        self.model.deinit(testing.allocator);
        self.leaked.deinit(testing.allocator);
        self.overlay.deinit(testing.allocator);
        self.db.deinit(testing.allocator);
        testing.allocator.free(self.digests);
        testing.allocator.free(self.heads);
        testing.allocator.destroy(self);
    }

    fn tick_until(self: *Harness, comptime done: fn (*const Database) bool) !void {
        return drive.tick_until(&self.db, self.sim, done);
    }

    const not_formatting = drive.not_formatting;
    const not_opening = drive.not_opening;
    const idle = drive.idle;

    fn format(self: *Harness, format_id: u128) !void {
        self.db.format(format_id);
        try self.tick_until(not_formatting);
        try self.open();
        for (0..8) |index| {
            try self.overlay.set_account(address_of(index), .{ .balance = 1000 + index });
            try self.overlay.set_storage(address_of(index), 1, index + 1);
        }
        var input = self.block_input(@splat(0), 0);
        const commit = try self.db.execute_and_commit(&self.overlay, &input);
        try self.record(commit.sequence);
        self.remember(input.hash);
        try self.tick_until(idle);
    }

    fn open(self: *Harness) !void {
        return drive.open(&self.db, self.sim);
    }

    fn reopen(self: *Harness) !void {
        // The pinned slices die with the database (a crash, or a clean close).
        self.held_len = 0;
        self.rewrite_seen = false;
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, self.sim, self.config);
        self.checkpoints_seen = 0;
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    fn record(self: *Harness, sequence: u64) !void {
        if (sequence == self.submitted) return;
        try testing.expectEqual(self.submitted + 1, sequence);
        try testing.expect(sequence <= sequences_max);
        self.heads[sequence] = self.db.head_info;
        self.digests[sequence] = self.digest();
        self.submitted = sequence;
    }

    fn digest(self: *const Harness) Digest {
        return Digest.of(&self.db.state, &self.leaked);
    }

    fn remember(self: *Harness, hash: Hash) void {
        self.known[self.block_id_next % known_blocks_max] = hash;
        self.known_len = @min(self.known_len + 1, known_blocks_max);
    }

    fn block_input(self: *Harness, parent_hash: Hash, number: u64) BlockInput {
        const id = self.block_id_next;
        self.block_id_next += 1;
        const header_len = 8 + id % 40;
        for (self.header_buffer[0..header_len], 0..) |*byte, index| {
            byte.* = @truncate(id *% 131 +% index);
        }
        return .{
            .hash = hash_of(id, 0xcc),
            .parent_hash = parent_hash,
            .number = number,
            .timestamp = number * 2,
            .header = self.header_buffer[0..header_len],
            .body = "body",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
    }

    /// A fresh random code: mostly small, sometimes too long for a table.
    fn deploy_code(self: *Harness) !Hash {
        const length: u32 = if (self.prng.chance(1, 25))
            @intCast(self.prng.range(table_value_max + 1, table_value_max + 150))
        else
            @intCast(self.prng.range(1, 1500));
        return self.deploy_code_sized(length);
    }

    fn deploy_code_sized(self: *Harness, length: u32) !Hash {
        assert(length > 0 and length <= self.code_buffer.len);
        const code = self.code_buffer[0..length];
        self.prng.fill(code);
        const hash = try self.overlay.insert_code(code);
        const entry = try self.model.getOrPut(testing.allocator, hash);
        if (!entry.found_existing) entry.value_ptr.* = try testing.allocator.dupe(u8, code);
        return hash;
    }

    fn room_for_code(self: *const Harness) bool {
        const state = &self.db.state;
        return state.code_table.count() < codes_cap and state.code_bytes_total < code_bytes_cap;
    }

    fn is_pinned(self: *const Harness) bool {
        return self.config.code_pin_bytes > 0;
    }

    /// Pinned mode: reads a random code of the state and keeps its slice until the release.
    fn read_random_code(self: *Harness) !void {
        const state = &self.db.state;
        const count = state.code_table.count();
        if (count == 0) return;
        var codes = state.code_table.iterator();
        var entry = codes.next().?;
        for (0..self.read_prng.below(count)) |_| entry = codes.next().?;
        const hash = entry.key_ptr.*;
        const table = entry.value_ptr.table;
        if (self.held_len == held_max) try self.release_codes();
        const store = &self.db.code_store.?;
        const pins_full = store.stats.pins_full;
        const code = state.code_by_hash(hash) orelse code: {
            // Every pin taken: the only refusal a healthy table may give.
            try testing.expectEqual(pins_full + 1, store.stats.pins_full);
            self.pinned.pins_full += 1;
            try self.release_codes();
            break :code state.code_by_hash(hash) orelse return error.CodeUnreadable;
        };
        const expected = self.model.get(hash) orelse return error.UnknownCode;
        try testing.expectEqualSlices(u8, expected, code);
        self.held[self.held_len] = .{ .hash = hash, .code = code };
        self.held_len += 1;
        if (table == 0) return;
        self.pinned.reads_table += 1;
        if (self.rewrites() > 0) self.pinned.reads_after_rewrite += 1;
    }

    /// Every slice read since the last release still holds its code; then releases.
    fn release_codes(self: *Harness) !void {
        for (self.held[0..self.held_len]) |held| {
            const expected = self.model.get(held.hash) orelse return error.UnknownCode;
            try testing.expectEqualSlices(u8, expected, held.code);
        }
        self.held_len = 0;
        self.db.codes_release();
    }

    fn random_writes(self: *Harness) !void {
        for (0..self.prng.range(1, 4)) |_| {
            const address = address_of(self.prng.below(addresses_max));
            var info = self.overlay.basic(address) orelse state_module.AccountInfo{};
            info.nonce += 1;
            info.balance = self.prng.int(u64);
            if (self.prng.chance(1, 3) and self.room_for_code()) {
                info.code_hash = try self.deploy_code();
            }
            try self.overlay.set_account(address, info);
            for (0..self.prng.below(4)) |_| {
                const slot = self.prng.below(8);
                try self.overlay.set_storage(address, slot, self.prng.int(u64));
            }
        }
    }

    fn random_known(self: *Harness) ?Hash {
        if (self.known_len == 0) return null;
        const hash = self.known[self.prng.below(self.known_len)];
        if (self.db.chain.meta(hash) == null) return null;
        return hash;
    }

    fn try_set_head(self: *Harness, hash: Hash) !void {
        const sequence = self.db.set_head(hash) catch |err| switch (err) {
            error.Busy, error.ReorgTooDeep, error.UnknownBlock, error.UnknownParent => return,
            else => return err,
        };
        try self.record(sequence);
    }

    fn new_block(self: *Harness) !void {
        if (self.prng.chance(1, 5)) {
            if (self.random_known()) |parent| try self.try_set_head(parent);
        }
        const head = self.db.head_info;
        self.overlay.discard();
        try self.random_writes();
        var input = self.block_input(head.hash, head.number + 1);
        const commit = self.db.execute_and_commit(&self.overlay, &input) catch |err| switch (err) {
            // A block whose codes outgrow one changeset is dropped like a refused one.
            error.Busy, error.UnknownParent, error.ChangesetFull => {
                return self.leak_overlay_codes();
            },
            else => return err,
        };
        try self.record(commit.sequence);
        self.remember(input.hash);
    }

    fn leak_overlay_codes(self: *Harness) !void {
        for (self.overlay.new_codes[0..self.overlay.new_codes_len]) |hash| {
            try self.leaked.put(testing.allocator, hash, {});
        }
    }

    fn step(self: *Harness) !void {
        if (self.db.phase == .failed) return error.DatabaseFailed;
        if (self.is_pinned() and self.random_reads) try self.step_reads();
        const roll = self.prng.below(100);
        if (roll < 3) {
            self.db.request_checkpoint();
        } else if (roll < 10) {
            if (self.random_known()) |hash| try self.try_set_head(hash);
        } else if (roll < 50) {
            try self.new_block();
        }
        if (self.db.checkpoint_error) |err| return err;
        self.sim.tick();
        self.track();
    }

    fn step_reads(self: *Harness) !void {
        const store = &self.db.code_store.?;
        if (store.flushing() and store.flush_rewrite and self.db.state.codes_in_tables > 0) {
            if (!self.rewrite_seen) self.pinned.rewrites_from_tables += 1;
            self.rewrite_seen = true;
        } else self.rewrite_seen = false;
        for (0..self.read_prng.below(3)) |_| try self.read_random_code();
        if (self.read_prng.chance(1, 8)) try self.release_codes();
    }

    fn track(self: *Harness) void {
        if (self.db.checkpoints_completed != self.checkpoints_seen) {
            self.checkpoints_seen = self.db.checkpoints_completed;
            self.fallback_intact = true;
        }
        if (self.db.engine.checkpoint_phase != .idle) self.fallback_intact = false;
    }

    fn rot_newest_checkpoint(self: *Harness) bool {
        const checkpoint = self.db.engine.superblock.working.checkpoint;
        if (checkpoint.sequence == 0 or checkpoint.size_bytes == 0) return false;
        const blocks = checkpoint_module.block_count(checkpoint.size_bytes, block_size);
        const block = self.prng.below(blocks);
        const zone = self.config.engine.checkpoint_zone_offset(checkpoint.zone);
        const offset: usize = @intCast(zone + block * block_size);
        self.sim.durable[offset] ^= 0x04;
        self.sim.memory[offset] ^= 0x04;
        return true;
    }

    /// Head, root, and codes equal the live run's after the recovered entry.
    fn check_recovered(self: *Harness, acknowledged: u64) !void {
        const recovered = self.db.submitted_sequence;
        try testing.expect(recovered >= acknowledged);
        try testing.expect(recovered <= self.submitted);
        try testing.expect(self.db.head_info.eql(self.heads[recovered]));
        if (self.db.head_info.present) {
            try testing.expectEqual(self.db.head_info.state_root, try self.db.state.state_root());
        }
        const got = self.digest();
        try testing.expect(got.eql(self.digests[recovered]));
        try self.check_code_bytes();
        self.submitted = recovered;
    }

    /// Every code in the state equals the deployed bytes, and the tables cover the arena.
    fn check_code_bytes(self: *Harness) !void {
        const state = &self.db.state;
        try self.release_codes();
        var codes = state.code_table.iterator();
        while (codes.next()) |entry| {
            // Pinned mode: one code pinned at a time.
            self.db.codes_release();
            const code = state.code_by_hash(entry.key_ptr.*) orelse return error.CodeUnreadable;
            const expected = self.model.get(entry.key_ptr.*) orelse return error.UnknownCode;
            try testing.expectEqualSlices(u8, expected, code);
            try testing.expectEqualSlices(u8, entry.key_ptr, &keccak256(code));
        }
        if (self.db.code_store) |*store| {
            try testing.expect(store.arena_flushed <= state.code_arena_len);
            try testing.expect(store.tables.count <= self.config.code_tables_max);
        }
    }

    fn rewrites(self: *const Harness) u64 {
        const store = &(self.db.code_store orelse return 0);
        return store.stats.rewrites;
    }
};

fn sim_create(config: database.Config, seed: u64, latency_ticks_max: u32) !SimStorage {
    return SimStorage.init(testing.allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = seed,
        .latency_ticks_max = latency_ticks_max,
    });
}

const CrashPoint = enum { tick, mid_flush, mid_rewrite, mid_checkpoint };

const Counts = struct {
    hits: [4]u32 = @splat(0),
    fallbacks: u32 = 0,
    opens_with_tables: u32 = 0,
    rewrites: u64 = 0,
    oversize_codes: u32 = 0,
    pinned: PinnedCounts = .{},
    cache_evictions: u64 = 0,

    /// Takes the harness's pinned counts (they restart after this).
    fn add_pinned(counts: *Counts, harness: *Harness) void {
        counts.pinned.reads_table += harness.pinned.reads_table;
        counts.pinned.pins_full += harness.pinned.pins_full;
        counts.pinned.reads_after_rewrite += harness.pinned.reads_after_rewrite;
        counts.pinned.rewrites_from_tables += harness.pinned.rewrites_from_tables;
        harness.pinned = .{};
        const store = &harness.db.code_store.?;
        if (store.cache) |*cache| counts.cache_evictions += cache.stats.evictions;
    }
};

fn at_crash_point(harness: *const Harness, point: CrashPoint) bool {
    const db = &harness.db;
    const store = &db.code_store.?;
    return switch (point) {
        .tick => false,
        .mid_flush => store.flushing(),
        .mid_rewrite => store.flushing() and store.flush_rewrite,
        .mid_checkpoint => db.engine.checkpoint_phase != .idle,
    };
}

/// Steps until the crash point is reached (or a random tick for `.tick`); true on a hit.
fn run_until(harness: *Harness, prng: *Prng, point: CrashPoint) !bool {
    const steps_max: u64 = if (point == .tick) prng.range(1, 600) else 1500;
    var steps: u64 = 0;
    while (steps < steps_max) : (steps += 1) {
        try harness.step();
        if (point != .tick and at_crash_point(harness, point)) {
            // Somewhere inside the operation, not always at its first tick.
            for (0..prng.below(4)) |_| {
                if (!at_crash_point(harness, point)) break;
                harness.sim.tick();
            }
            return at_crash_point(harness, point);
        }
    }
    return point == .tick;
}

fn run_crash_seed(seed: u64, base: database.Config, counts: *Counts) !void {
    var prng = Prng.init(seed);
    var config = base;
    config.code_tables_max = @intCast(prng.range(4, 5));
    if (seed % 2 == 1) config.checkpoint_bytes_per_commit = @intCast(prng.range(1, 3) * block_size);
    var sim = try sim_create(config, seed, @intCast(prng.range(1, 6)));
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, prng.int(u64), config);
    defer harness.destroy();
    try harness.format(0xc0de_0000 + seed);
    for (0..3) |_| {
        const point: CrashPoint = @fromBackingInt(@intCast(prng.below(4)));
        if (try run_until(harness, &prng, point)) counts.hits[@backingInt(point)] += 1;
        counts.rewrites += harness.rewrites(); // A reopened database counts from zero.
        harness.track();
        const acknowledged = harness.db.durable_sequence;
        const fallback_ready = harness.fallback_intact;
        sim.crash();
        const rotten = fallback_ready and prng.chance(1, 3) and harness.rot_newest_checkpoint();
        try harness.reopen();
        const result = try harness.db.engine.open_result;
        if (rotten) try testing.expect(result.checkpoint_fallback);
        if (result.checkpoint_fallback) {
            harness.fallback_intact = false;
            counts.fallbacks += 1;
        }
        if (harness.db.code_store.?.tables.count > 0) counts.opens_with_tables += 1;
        try harness.check_recovered(acknowledged);
        counts.add_pinned(harness);
    }
    var codes = harness.db.state.code_table.valueIterator();
    while (codes.next()) |code| counts.oversize_codes += @intFromBool(code.len > table_value_max);
}

test "database codes: seeded crashes mid flush, rewrite, and checkpoint keep every code" {
    var counts: Counts = .{};
    for (0..24) |seed| {
        run_crash_seed(seed, config_grid, &counts) catch |err| {
            std.debug.print("database codes crash recovery: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_flush)] >= 4);
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_rewrite)] >= 2);
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_checkpoint)] >= 4);
    try testing.expect(counts.fallbacks >= 4);
    try testing.expect(counts.opens_with_tables >= 36);
    try testing.expect(counts.rewrites >= 6);
    try testing.expect(counts.oversize_codes > 0);
}

test "database codes: pinned mode, seeded crashes keep every code readable from its table" {
    var counts: Counts = .{};
    for (0..24) |seed| {
        run_crash_seed(seed, config_pinned, &counts) catch |err| {
            std.debug.print("database codes pinned crash recovery: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_flush)] >= 4);
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_rewrite)] >= 2);
    try testing.expect(counts.hits[@backingInt(CrashPoint.mid_checkpoint)] >= 4);
    try testing.expect(counts.fallbacks >= 4);
    try testing.expect(counts.opens_with_tables >= 36);
    try testing.expect(counts.rewrites >= 6);
    try testing.expect(counts.oversize_codes > 0);
    try testing.expect(counts.pinned.reads_table >= 1000);
    try testing.expect(counts.pinned.pins_full > 0);
    try testing.expect(counts.pinned.rewrites_from_tables >= 4);
    try testing.expect(counts.pinned.reads_after_rewrite > 0);
    try testing.expect(counts.cache_evictions > 0);
}

// Differential: grid vs grid-less, in lockstep.

/// Runs `steps` steps, each followed by a full drain, so both databases decide alike.
fn run_lockstep(harnesses: []const *Harness, steps: u32) !void {
    for (0..steps) |_| {
        for (harnesses) |harness| {
            try harness.step();
            try harness.tick_until(Harness.idle);
        }
        const first = harnesses[0];
        for (harnesses[1..]) |other| {
            try testing.expectEqual(first.submitted, other.submitted);
            try testing.expect(first.db.head_info.eql(other.db.head_info));
            try testing.expect(first.digest().eql(other.digest()));
        }
    }
}

test "database codes: grid, grid-less, a too-small grid, and pinned agree on every block" {
    var configs = [_]database.Config{ config_grid, config_plain, config_grid, config_pinned };
    configs[2].engine.grid_block_count = 6;
    var sims: [4]SimStorage = undefined;
    var harnesses: [4]*Harness = undefined;
    for (&configs, &sims, &harnesses, 0..) |*config, *sim, *harness, index| {
        sim.* = try sim_create(config.*, 0xd1ff + index, 3);
        harness.* = try Harness.create(sim, 0x5eed, config.*);
        try harness.*.format(0xd1ff);
    }
    defer for (&sims, harnesses) |*sim, harness| {
        harness.destroy();
        sim.deinit(testing.allocator);
    };
    var totals: code_store_module.Stats = .{};
    var no_space: u64 = 0;
    for (0..8) |_| {
        try run_lockstep(&harnesses, 250);
        for (harnesses) |harness| {
            harness.db.request_checkpoint();
            try harness.tick_until(Harness.idle);
        }
        // Stats count from zero after a reopen: sum them first.
        totals.flushes += harnesses[0].db.code_store.?.stats.flushes;
        totals.rewrites += harnesses[0].db.code_store.?.stats.rewrites;
        no_space += harnesses[2].db.code_store.?.stats.flushes_no_space;
        // Codes out of RAM change nothing on disk: the same checkpoint, byte for byte.
        const checkpoint_grid = harnesses[0].db.engine.superblock.working.checkpoint;
        const checkpoint_pinned = harnesses[3].db.engine.superblock.working.checkpoint;
        try testing.expectEqual(checkpoint_grid.checksum, checkpoint_pinned.checksum);
        try testing.expectEqual(checkpoint_grid.size_bytes, checkpoint_pinned.size_bytes);
        for (harnesses) |harness| {
            try harness.reopen();
            try harness.check_code_bytes();
        }
        try run_lockstep(&harnesses, 0);
    }
    try testing.expect(harnesses[3].db.state.codes_in_tables > 0);
    try testing.expect(totals.flushes >= 8 and totals.rewrites > 0);
    try testing.expect(no_space > 0);
    const image_grid = harnesses[0].db.engine.superblock.working.checkpoint.size_bytes;
    const image_plain = harnesses[1].db.engine.superblock.working.checkpoint.size_bytes;
    try testing.expect(image_grid * 2 < image_plain);
}

// Compatibility and rot.

test "database codes: a grid-less v2 file opens without a grid, is refused with one" {
    // Sized for the grid layout too, so the refused open can be tried on the same storage.
    var sim = try sim_create(config_grid, 0x2f11e, 2);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 0x2f11e, config_plain);
    defer harness.destroy();
    try harness.format(0x2f11e);
    for (0..300) |_| try harness.step();
    try harness.tick_until(Harness.idle);
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    for (0..60) |_| try harness.step();
    try harness.tick_until(Harness.idle);
    const head = harness.db.head_info;
    const digest = harness.digest();
    // Rewrite every superblock copy as version 2 (the layout has no grid).
    for (0..superblock_module.copy_count) |copy| {
        const offset = copy * sector_size;
        const bytes = sim.durable[offset..][0..sector_size];
        var superblock = std.mem.bytesToValue(superblock_module.SuperBlock, bytes);
        try testing.expectEqual(@as(u32, 3), superblock.version);
        superblock.version = 2;
        superblock.checksum = superblock.compute_checksum();
        @memcpy(bytes, std.mem.asBytes(&superblock));
        @memcpy(sim.memory[offset..][0..sector_size], bytes);
    }
    harness.config = config_grid;
    try testing.expectError(error.LayoutMismatch, harness.reopen());
    harness.config = config_plain;
    try harness.reopen();
    try testing.expect(head.eql(harness.db.head_info));
    try testing.expect(harness.digest().eql(digest));
    try harness.check_code_bytes();
    try testing.expect(harness.db.code_store == null);
}

test "database codes: rot in a table only the newest checkpoint names falls back" {
    var config = config_grid;
    config.code_tables_max = 16; // No rewrite: the older checkpoint keeps its own tables.
    var sim = try sim_create(config, 0x4071, 2);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 0x4071, config);
    defer harness.destroy();
    try harness.format(0x4071);
    for (0..2) |_| {
        for (0..300) |_| try harness.step();
        try harness.tick_until(Harness.idle);
        harness.db.request_checkpoint();
        try harness.tick_until(Harness.idle);
    }
    // One more code, flushed into a table by the newest checkpoint only.
    harness.overlay.discard();
    const head = harness.db.head_info;
    try harness.overlay.set_account(address_of(1), .{
        .code_hash = try harness.deploy_code_sized(700),
    });
    var input = harness.block_input(head.hash, head.number + 1);
    try harness.record((try harness.db.execute_and_commit(&harness.overlay, &input)).sequence);
    try harness.tick_until(Harness.idle);
    const store = &harness.db.code_store.?;
    const tables_before = store.tables.count;
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    try testing.expectEqual(tables_before + 1, store.tables.count);
    try testing.expect(harness.db.engine.superblock.working.has_fallback());
    const live_head = harness.db.head_info;
    const live_digest = harness.digest();
    // Rot a payload byte of the newest table's first data block.
    const last = store.tables.count - 1;
    const address = store.tables.blocks[@as(usize, last) * store.blocks_per_table + 1];
    const offset: usize = @intCast(config.engine.grid_offset() + (address - 1) * block_size + 130);
    sim.durable[offset] ^= 0x01;
    sim.memory[offset] ^= 0x01;
    try harness.reopen();
    try testing.expect((try harness.db.engine.open_result).checkpoint_fallback);
    try testing.expect(live_head.eql(harness.db.head_info));
    try testing.expect(harness.digest().eql(live_digest));
    try harness.check_code_bytes();
}

test "database codes: pinned, a rotten table block fails its own codes only; a rewrite aborts" {
    var sim = try sim_create(config_pinned, 0x7077, 2);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 0x7077, config_pinned);
    defer harness.destroy();
    harness.random_reads = false;
    try harness.format(0x7077);
    for (0..300) |_| try harness.step();
    try harness.tick_until(Harness.idle);
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    try harness.reopen();
    const store = &harness.db.code_store.?;
    try testing.expect(store.tables.count > 0);
    // Rot the last payload byte of the first table's first data block (a byte of its last
    // code; the block is not cached: just opened).
    const address = store.tables.blocks[1];
    const block: usize = @intCast(config_pinned.engine.grid_offset() + (address - 1) * block_size);
    const payload_size = std.mem.readInt(u32, sim.memory[block + 48 ..][0..4], .little);
    const offset = block + 128 + payload_size - 1;
    sim.durable[offset] ^= 0x01;
    sim.memory[offset] ^= 0x01;
    const state = &harness.db.state;
    var failed: u32 = 0;
    var codes = state.code_table.iterator();
    while (codes.next()) |entry| {
        harness.db.codes_release();
        const expected = harness.model.get(entry.key_ptr.*).?;
        if (state.code_by_hash(entry.key_ptr.*)) |code| {
            try testing.expectEqualSlices(u8, expected, code);
        } else {
            // Only codes of the rotten table fail (its first block's).
            try testing.expectEqual(@as(u32, 1), entry.value_ptr.table);
            failed += 1;
        }
    }
    try testing.expect(failed > 0);
    try testing.expectEqual(@as(u64, failed), store.stats.read_faults);
    // Blocks and checkpoints go on until a rewrite meets the rotten codes and aborts.
    const tables: u32 = store.tables.count;
    const first = store.tables.infos[0];
    var steps: u32 = 0;
    while (store.stats.flush_faults == 0) : (steps += 1) {
        if (steps == 20_000) return error.NoRewrite;
        try harness.step();
    }
    try harness.tick_until(Harness.idle);
    try testing.expect(store.fault);
    try testing.expectEqual(@as(u64, 0), store.stats.rewrites);
    try testing.expect(store.tables.count >= tables);
    try testing.expectEqual(first, store.tables.infos[0]);
    // Later checkpoints carry the new codes in their image; blocks go on.
    for (0..200) |_| try harness.step();
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    try testing.expect(harness.db.checkpoint_error == null);
}

/// Room for more code than one table holds, so a rewrite writes several tables.
const config_pinned_wide: database.Config = blk: {
    var config = config_pinned;
    config.state.codes_max = 1024;
    config.state.code_bytes_max = 2 * 1024 * 1024;
    config.engine.grid_block_count = database.code_grid_block_count(config.state, block_size);
    config.code_tables_max = Database.CodeStore.tables_max_min(
        block_size,
        config.state.codes_max,
        config.state.code_bytes_max,
    );
    break :blk config;
};

test "database codes: pinned, a rewrite into several tables re-points every code" {
    const config = config_pinned_wide;
    var sim = try sim_create(config, 0x9e90, 2);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 0x9e90, config);
    defer harness.destroy();
    harness.random_reads = false;
    try harness.format(0x9e90);
    var deployed: u32 = 0;
    var reopened = false;
    while (harness.rewrites() == 0) : (deployed += 1) {
        if (deployed == 2000) return error.NoRewrite;
        // Four codes a block, a checkpoint (one flush, one table) every four blocks.
        const head = harness.db.head_info;
        harness.overlay.discard();
        for (0..4) |index| {
            const length: u32 = @intCast(harness.prng.range(2000, 3900));
            const code_hash = try harness.deploy_code_sized(length);
            try harness.overlay.set_account(address_of(index), .{ .code_hash = code_hash });
        }
        var input = harness.block_input(head.hash, head.number + 1);
        const commit = try harness.db.execute_and_commit(&harness.overlay, &input);
        try harness.record(commit.sequence);
        try harness.tick_until(Harness.idle);
        if (deployed % 4 != 3) continue;
        harness.db.request_checkpoint();
        try harness.tick_until(Harness.idle);
        // Halfway, a reopen: from then on the older codes are held in tables only.
        const store = &harness.db.code_store.?;
        if (!reopened and store.tables.count * 2 >= config.code_tables_max) {
            try harness.reopen();
            reopened = true;
        }
    }
    try testing.expect(reopened);
    const store = &harness.db.code_store.?;
    try testing.expect(store.tables.count >= 2);
    try testing.expect(harness.db.state.codes_in_tables >= 64);
    // Before any reopen: every code reads back through the table it now points at.
    try harness.check_code_bytes();
    try testing.expect(store.stats.reads >= harness.db.state.codes_in_tables);
}

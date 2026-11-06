//! Database tests for the flat trees (disk state phase 2b, `Config.flat_trees`).
//!
//! Seeded differential: random blocks over a small address and slot universe, side branches
//! and reorgs (the trees get the unwound changesets' old values), and checkpoints, with a
//! flush threshold low enough that the trees flush and merge. At the end of the live run,
//! after a checkpoint and clean reopen, and after each crash at a random tick and reopen,
//! every account and slot `State` holds equals the tree lookup, and every key ever written
//! (a superset of the trees' keys: every tree key comes from a changeset) is absent from the
//! trees when `State` does not hold it, so every tree entry exists in `State`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const storage = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const flat_trees_module = @import("flat_trees.zig");
const keccak256 = @import("../trie/node.zig").keccak256;
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = database.Hash;
const HeadInfo = database.HeadInfo;
const BlockInput = database.BlockInput;
const Overlay = overlay_module.Overlay;
const Address = state_module.Address;
const SlotKey = state_module.SlotKey;
const Database = database.DatabaseType(SimStorage);
const FlatTrees = Database.FlatTrees;
const sector_size = storage.sector_size;

const block_size: u32 = 4 * sector_size;

const config_flat: database.Config = .{
    .engine = .{
        .journal_size_bytes = 48 * sector_size,
        .checkpoint_zone_size_bytes = 32 * block_size,
        .entry_body_size_max = 2 * sector_size,
        .checkpoint_block_size = block_size,
        .grid_block_count = 256,
    },
    .state = .{
        .accounts_max = 64,
        .storage_slots_max = 512,
        .codes_max = 4,
        .code_bytes_max = 4096,
        .account_nodes_max = 1024,
        .storage_nodes_max = 8192,
    },
    .chain = .{
        .blocks_max = 16,
        .bytes_max = 32 * 1024,
        .transactions_max = 64,
        .canonical_max = 64,
        .reorg_depth_max = 8,
    },
    .changeset = .{
        .accounts_max = 16,
        .storage_max = 32,
        .codes_max = 1,
        .code_bytes_max = 1024,
    },
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 1024 * 1024,
    .flat_trees = true,
    .flat_flush_entries_min = 24,
    .flat_cache_blocks = 16,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 16,
    .slots_max = 32,
    .codes_max = 1,
};

const addresses_max = 24;
const slots_per_address = 6;
const sequences_max = 8 * 1024;
const known_blocks_max = 32;
const ticks_max = 200_000;

fn address_of(index: u64) Address {
    var address: Address = @splat(0x33);
    address[0] = @intCast(index);
    return address;
}

fn hash_of(id: u32) Hash {
    var hash: Hash = @splat(0xdd);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

const Harness = struct {
    db: Database,
    sim: *SimStorage,
    prng: Prng,
    overlay: Overlay,
    config: database.Config,
    heads: []HeadInfo,
    submitted: u64 = 0,
    known: [known_blocks_max]Hash = undefined,
    known_len: u32 = 0,
    block_id_next: u32 = 0,
    header_buffer: [48]u8 = undefined,

    fn create(sim: *SimStorage, seed: u64, config: database.Config) !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        const heads = try testing.allocator.alloc(HeadInfo, sequences_max + 1);
        errdefer testing.allocator.free(heads);
        heads[0] = .{};
        self.* = .{
            .db = try Database.init(testing.allocator, sim, config),
            .sim = sim,
            .prng = Prng.init(seed),
            .overlay = undefined,
            .config = config,
            .heads = heads,
        };
        self.overlay = try Overlay.init(testing.allocator, &self.db.state, overlay_config);
        return self;
    }

    fn destroy(self: *Harness) void {
        self.overlay.deinit(testing.allocator);
        self.db.deinit(testing.allocator);
        testing.allocator.free(self.heads);
        testing.allocator.destroy(self);
    }

    fn tick_until(self: *Harness, comptime done: fn (*const Database) bool) !void {
        var ticks: u32 = 0;
        while (!done(&self.db)) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.sim.tick();
        }
    }

    fn not_formatting(db: *const Database) bool {
        return db.phase != .formatting;
    }

    fn not_opening(db: *const Database) bool {
        return db.phase != .opening;
    }

    fn idle(db: *const Database) bool {
        return db.idle();
    }

    fn format(self: *Harness, format_id: u128) !void {
        self.db.format(format_id);
        try self.tick_until(not_formatting);
        try self.open();
        for (0..4) |index| {
            try self.overlay.set_account(address_of(index), .{ .balance = 100 + index });
            try self.overlay.set_storage(address_of(index), 1, index + 1);
        }
        var input = self.block_input(@splat(0), 0);
        const commit = try self.db.execute_and_commit(&self.overlay, &input);
        try self.record(commit.sequence);
        self.remember(input.hash);
        try self.tick_until(idle);
    }

    fn open(self: *Harness) !void {
        self.db.open();
        try self.tick_until(not_opening);
        if (self.db.open_error) |err| return err;
        try testing.expectEqual(database.Phase.ready, self.db.phase);
    }

    fn reopen(self: *Harness) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, self.sim, self.config);
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    fn record(self: *Harness, sequence: u64) !void {
        if (sequence == self.submitted) return;
        try testing.expectEqual(self.submitted + 1, sequence);
        try testing.expect(sequence <= sequences_max);
        self.heads[sequence] = self.db.head_info;
        self.submitted = sequence;
    }

    fn remember(self: *Harness, hash: Hash) void {
        self.known[self.block_id_next % known_blocks_max] = hash;
        self.known_len = @min(self.known_len + 1, known_blocks_max);
    }

    fn block_input(self: *Harness, parent_hash: Hash, number: u64) BlockInput {
        const id = self.block_id_next;
        self.block_id_next += 1;
        const header_len = 8 + id % 32;
        for (self.header_buffer[0..header_len], 0..) |*byte, index| {
            byte.* = @truncate(id *% 131 +% index);
        }
        return .{
            .hash = hash_of(id),
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

    /// Account updates and slot writes; a slot set to zero is a delete (a tombstone).
    fn random_writes(self: *Harness) !void {
        for (0..self.prng.range(1, 4)) |_| {
            const address = address_of(self.prng.below(addresses_max));
            var info = self.overlay.basic(address) orelse state_module.AccountInfo{};
            info.nonce += 1;
            info.balance = self.prng.int(u64);
            try self.overlay.set_account(address, info);
            for (0..self.prng.below(4)) |_| {
                const slot = self.prng.below(slots_per_address);
                const value: u256 = if (self.prng.chance(1, 4)) 0 else self.prng.int(u64);
                try self.overlay.set_storage(address, slot, value);
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
            error.Busy, error.UnknownParent => return self.overlay.discard(),
            else => return err,
        };
        try self.record(commit.sequence);
        self.remember(input.hash);
    }

    fn step(self: *Harness) !void {
        if (self.db.phase == .failed) return error.DatabaseFailed;
        const roll = self.prng.below(100);
        if (roll < 3) {
            self.db.request_checkpoint();
        } else if (roll < 10) {
            if (self.random_known()) |hash| try self.try_set_head(hash);
        } else if (roll < 55) {
            try self.new_block();
        }
        if (self.db.checkpoint_error) |err| return err;
        self.sim.tick();
    }

    /// Requests a checkpoint and drives it (unpaced) until it is written and all is idle.
    fn checkpoint(self: *Harness) !void {
        self.db.request_checkpoint();
        var ticks: u32 = 0;
        while (!checkpoint_settled(&self.db)) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.db.checkpoint_flush();
            self.sim.tick();
        }
        if (self.db.checkpoint_error) |err| return err;
    }

    fn run(self: *Harness, steps: u64) !void {
        for (0..steps) |_| try self.step();
    }

    fn on_lookup(comptime Tree: type) Tree.Callback {
        return struct {
            fn callback(_: *Tree) void {}
        }.callback;
    }

    /// Looks `key` up in `tree`, ticking until a pending lookup completes.
    fn lookup(self: *Harness, tree: anytype, key: anytype) !?@TypeOf(tree.lookup_value) {
        const Tree = @TypeOf(tree.*);
        if (tree.lookup(key, on_lookup(Tree)) == .pending) {
            var ticks: u32 = 0;
            while (tree.lookup_active) : (ticks += 1) {
                if (ticks >= ticks_max) return error.Timeout;
                self.sim.tick();
            }
        }
        const found = try tree.lookup_result;
        return if (found) tree.lookup_value else null;
    }

    /// Every touched account and slot: the tree holds exactly what `State` holds.
    fn check_flat(self: *Harness) !void {
        const trees = &self.db.flat.?;
        const state = &self.db.state;
        for (0..addresses_max) |index| {
            const address = address_of(index);
            const key = keccak256(&address);
            const value = try self.lookup(&trees.accounts, &key);
            const expected = state.basic(address);
            try testing.expectEqual(expected != null, value != null);
            if (value) |bytes| {
                try testing.expect(flat_trees_module.account_decode(&bytes).eql(expected.?));
            }
            for (0..slots_per_address) |slot| {
                const slot_key = flat_trees_module.storage_key(&key, slot);
                const word = try self.lookup(&trees.storage, &slot_key);
                const expected_word = state.storage(address, slot);
                const got: u256 = if (word) |bytes| std.mem.readInt(u256, &bytes, .big) else 0;
                try testing.expectEqual(expected_word, got);
                // A stored zero would be a live entry State does not hold.
                if (word != null) try testing.expect(got != 0);
            }
        }
    }

    fn check_recovered(self: *Harness, acknowledged: u64) !void {
        const recovered = self.db.submitted_sequence;
        try testing.expect(recovered >= acknowledged);
        try testing.expect(recovered <= self.submitted);
        try testing.expect(self.db.head_info.eql(self.heads[recovered]));
        self.submitted = recovered;
        try self.check_flat();
    }
};

const Counts = struct {
    flushes: u64 = 0,
    merges: u64 = 0,
    opens_with_tables: u32 = 0,
};

fn count(harness: *const Harness, counts: *Counts) void {
    const trees = &harness.db.flat.?;
    counts.flushes += trees.accounts.stats.flushes + trees.storage.stats.flushes;
    counts.merges += trees.accounts.stats.merges + trees.storage.stats.merges;
}

fn run_seed(seed: u64, counts: *Counts) !void {
    var prng = Prng.init(seed);
    var config = config_flat;
    if (seed % 2 == 1) config.checkpoint_bytes_per_commit = @intCast(prng.range(1, 3) * block_size);
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 4)),
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, prng.int(u64), config);
    defer harness.destroy();
    try harness.format(0xf1a7_0000 + seed);
    try harness.run(prng.range(200, 400));
    try harness.check_flat();
    // Checkpoint, then a clean reopen from it.
    try harness.checkpoint();
    count(harness, counts);
    try harness.reopen();
    try harness.check_recovered(harness.submitted);
    for (0..3) |_| {
        try harness.run(prng.range(1, 300));
        count(harness, counts);
        const acknowledged = harness.db.durable_sequence;
        sim.crash();
        try harness.reopen();
        if (harness.db.flat.?.storage.level_count[0] > 0) counts.opens_with_tables += 1;
        try harness.check_recovered(acknowledged);
    }
}

fn checkpoint_settled(db: *const Database) bool {
    return !db.checkpoint_wanted and db.engine.checkpoint_phase == .idle and db.idle();
}

test "database flat trees: seeded blocks, reorgs, checkpoints, and crashes match State" {
    var counts: Counts = .{};
    for (0..6) |seed| {
        run_seed(seed, &counts) catch |err| {
            std.debug.print("database flat trees: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(counts.flushes >= 40);
    try testing.expect(counts.merges >= 6);
    try testing.expect(counts.opens_with_tables >= 8);
}

test "database flat trees: a checkpoint written without flat trees is refused with them" {
    var config_off = config_flat;
    config_off.flat_trees = false;
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config_flat.engine.size_bytes(),
        .seed = 9,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 9, config_off);
    defer harness.destroy();
    try harness.format(0xf1a7_ffff);
    try harness.run(60);
    try harness.checkpoint();
    harness.config = config_flat;
    try testing.expectError(error.CheckpointInvalid, harness.reopen());
    harness.config = config_off;
    try harness.reopen();
}

/// Fills `tree` into its replay reserve with a flush pending, as an open whose replay used
/// the reserve leaves it: tombstones of fresh random keys (absent from `State`, so the trees
/// still match it).
fn fill_reserve(tree: *FlatTrees.StorageTree, prng: *Prng) !void {
    assert(!tree.compaction.active);
    const limit = tree.config.memtable_entries_max - tree.config.replay_entries_max;
    var key: [flat_trees_module.storage_key_size]u8 = undefined;
    if (tree.immutable_memtable().count == 0) {
        prng.fill(&key);
        try tree.put_replay(&key, null);
        try testing.expect(tree.swap());
    }
    var puts: u32 = 0;
    while (tree.mutable_memtable().count <= limit) : (puts += 1) {
        assert(puts <= tree.config.memtable_entries_max);
        prng.fill(&key);
        try tree.put_replay(&key, null);
    }
    assert(tree.immutable_memtable().count > 0);
}

test "database flat trees: a checkpoint waits until a replay-filled reserve is restored" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config_flat.engine.size_bytes(),
        .seed = 11,
        .latency_ticks_max = 2,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 11, config_flat);
    defer harness.destroy();
    try harness.format(0xf1a7_0011);
    try harness.run(150);
    try harness.checkpoint();
    try harness.reopen();
    try harness.tick_until(Harness.idle);
    const trees = &harness.db.flat.?;
    try fill_reserve(&trees.storage, &harness.prng);
    try testing.expect(!trees.checkpoint_ready());
    const checkpoints = harness.db.checkpoints_completed;
    const flushes = trees.storage.stats.flushes;
    try harness.checkpoint();
    try testing.expectEqual(checkpoints + 1, harness.db.checkpoints_completed);
    try testing.expect(trees.storage.stats.flushes > flushes);
    try testing.expect(trees.checkpoint_ready());
    try harness.check_flat();
    try harness.reopen();
    try harness.check_recovered(harness.submitted);
    for (0..2) |_| {
        try harness.run(200);
        const acknowledged = harness.db.durable_sequence;
        sim.crash();
        try harness.reopen();
        try harness.check_recovered(acknowledged);
    }
}

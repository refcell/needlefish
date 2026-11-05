//! Database tests: the entry codec (fuzzed), checkpoint-then-reopen equality, and the lane's
//! durability guarantee under fault injection. Each seed runs a random workload of blocks with
//! random state writes, side branches, reorgs, and checkpoints over `SimStorage`, crashes at
//! random ticks, sometimes rots the newest checkpoint, reopens, and checks that the recovered
//! head and state root equal the live values after some entry between the last acknowledged
//! one and the last submitted one.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const engine_module = @import("storage/engine.zig");
const storage = @import("storage/storage.zig");
const checkpoint_module = @import("storage/checkpoint.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = database.Hash;
const HeadInfo = database.HeadInfo;
const BlockInput = database.BlockInput;
const Overlay = overlay_module.Overlay;
const Database = database.DatabaseType(SimStorage);
const sector_size = storage.sector_size;

const config: database.Config = .{
    .engine = .{
        .journal_size_bytes = 96 * sector_size,
        .checkpoint_zone_size_bytes = 48 * sector_size,
        .entry_body_size_max = 2 * sector_size,
        .checkpoint_block_size = 4 * sector_size,
    },
    .state = .{
        .accounts_max = 64,
        .storage_slots_max = 512,
        .codes_max = 8,
        .code_bytes_max = 2048,
        .account_nodes_max = 1024,
        .storage_nodes_max = 8192,
    },
    .chain = .{
        .blocks_max = 24,
        .bytes_max = 48 * 1024,
        .transactions_max = 128,
        .canonical_max = 64,
        .reorg_depth_max = 16,
    },
    .changeset = .{
        .accounts_max = 64,
        .storage_max = 256,
        .codes_max = 4,
        .code_bytes_max = 1024,
    },
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 160 * 1024,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 64,
    .slots_max = 256,
    .codes_max = 4,
};

const addresses_max = 32;
const slots_per_account = 8;
const sequences_max = 16 * 1024;
const known_blocks_max = 64;
const ticks_max = 200_000;

fn address_of(index: u64) state_module.Address {
    var address: state_module.Address = @splat(0x11);
    address[0] = @intCast(index);
    return address;
}

fn hash_of(id: u32, salt: u8) Hash {
    var hash: Hash = @splat(salt);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

const codes = [_][]const u8{ "\x60\x00\x60\x00", "\x60\x01\x56", "\x5b\x5b\x00", "\x33\xff" };

const Harness = struct {
    db: Database,
    sim: *SimStorage,
    prng: Prng,
    overlay: Overlay,
    /// `heads[s]` is the live head after entry `s` (0: freshly formatted).
    heads: []HeadInfo,
    submitted: u64 = 0,
    known: [known_blocks_max]Hash = undefined,
    known_len: u32 = 0,
    block_id_next: u32 = 0,
    header_buffer: [64]u8 = undefined,
    transactions: [3]Hash = undefined,
    /// The engine's fallback checkpoint is known intact: false while a checkpoint runs (it
    /// overwrites the fallback zone) and after an open that fell back, true once a
    /// checkpoint completes.
    fallback_intact: bool = true,
    checkpoints_seen: u64 = 0,

    fn create(sim: *SimStorage, seed: u64) !*Harness {
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

    /// Formats, opens, and commits a genesis block.
    fn format(self: *Harness, format_id: u128) !void {
        self.db.format(format_id);
        try self.tick_until(not_formatting);
        try self.open();
        try testing.expectEqual(@as(u64, 0), self.db.submitted_sequence);
        try testing.expect(!self.db.head_info.present);
        for (0..8) |index| {
            try self.overlay.set_account(address_of(index), .{ .balance = 1000 + index });
            try self.overlay.set_storage(address_of(index), 1, index + 1);
        }
        var input = self.block_input(@splat(0), 0);
        const commit = try self.db.execute_and_commit(&self.overlay, &input);
        try self.record(commit.sequence, self.db.head_info);
        self.remember(input.hash);
        try self.tick_until(idle);
        try testing.expectEqual(self.submitted, self.db.durable_sequence);
    }

    fn open(self: *Harness) !void {
        self.db.open();
        try self.tick_until(not_opening);
        if (self.db.open_error) |err| return err;
        try testing.expectEqual(database.Phase.ready, self.db.phase);
    }

    /// Simulates a restart: a fresh database value over the same storage.
    fn reopen(self: *Harness) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, self.sim, config);
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    fn record(self: *Harness, sequence: u64, info: HeadInfo) !void {
        if (sequence == self.submitted) return; // A no-op: nothing was journaled.
        try testing.expectEqual(self.submitted + 1, sequence);
        try testing.expect(sequence <= sequences_max);
        self.heads[sequence] = info;
        self.submitted = sequence;
        try testing.expect(self.submitted <= self.db.submitted_sequence);
    }

    fn remember(self: *Harness, hash: Hash) void {
        self.known[self.block_id_next % known_blocks_max] = hash;
        self.known_len = @min(self.known_len + 1, known_blocks_max);
    }

    /// A block input with a fresh id; the changeset is filled by `execute_and_commit`.
    fn block_input(self: *Harness, parent_hash: Hash, number: u64) BlockInput {
        const id = self.block_id_next;
        self.block_id_next += 1;
        const header_len = 8 + id % 40;
        for (self.header_buffer[0..header_len], 0..) |*byte, index| {
            byte.* = @truncate(id *% 131 +% index);
        }
        for (&self.transactions, 0..) |*transaction, index| {
            transaction.* = hash_of(id, @intCast(0xa0 + index));
        }
        return .{
            .hash = hash_of(id, 0xbb),
            .parent_hash = parent_hash,
            .number = number,
            .timestamp = number * 2,
            .header = self.header_buffer[0..header_len],
            .body = "body",
            .receipts = if (id % 2 == 0) "receipts" else "",
            .transaction_hashes = self.transactions[0 .. id % 4],
            .changeset = "",
        };
    }

    fn random_writes(self: *Harness) !void {
        const accounts = self.prng.range(1, 4);
        for (0..accounts) |_| {
            const address = address_of(self.prng.below(addresses_max));
            const roll = self.prng.below(20);
            if (roll == 0) {
                try self.overlay.set_account(address, null);
                continue;
            }
            var info = self.overlay.basic(address) orelse state_module.AccountInfo{};
            info.nonce += 1;
            info.balance = self.prng.int(u64);
            if (roll == 1) {
                info.code_hash = try self.overlay.insert_code(codes[self.prng.below(4)]);
            }
            try self.overlay.set_account(address, info);
            for (0..self.prng.below(5)) |_| {
                const slot = self.prng.below(slots_per_account);
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

    /// Moves the head; errors that leave the database unchanged are skipped.
    fn try_set_head(self: *Harness, hash: Hash) !bool {
        const sequence = self.db.set_head(hash) catch |err| switch (err) {
            error.Busy, error.ReorgTooDeep, error.UnknownBlock, error.UnknownParent => {
                return false;
            },
            else => return err,
        };
        try self.record(sequence, self.db.head_info);
        return true;
    }

    /// Builds a block on the head or (a side branch) on another stored block.
    fn new_block(self: *Harness) !void {
        if (self.prng.chance(3, 10)) {
            const parent = self.random_known() orelse return;
            if (!try self.try_set_head(parent)) return;
        }
        const head = self.db.head_info;
        self.overlay.discard();
        try self.random_writes();
        var input = self.block_input(head.hash, head.number + 1);
        if (self.prng.chance(1, 5)) return self.insert_then_set_head(&input);
        const commit = self.db.execute_and_commit(&self.overlay, &input) catch |err| switch (err) {
            // Busy, or the parent is the oldest block and this insert would evict it.
            error.Busy, error.UnknownParent => return,
            else => return err,
        };
        try self.record(commit.sequence, self.db.head_info);
        try testing.expectEqual(commit.state_root, self.db.head_info.state_root);
        self.remember(input.hash);
    }

    /// The standalone path: a `block` entry, then (usually) a separate `head` entry.
    fn insert_then_set_head(self: *Harness, input: *BlockInput) !void {
        const head = self.db.head_info;
        const built = &self.db.changeset_built;
        try self.overlay.build_changeset(built);
        self.overlay.discard();
        if (built.encoded_length() > self.db.changeset_buffer.len) return;
        input.changeset = built.encode(self.db.changeset_buffer);
        const sequence = self.db.insert_block(input) catch |err| switch (err) {
            error.Busy, error.UnknownParent, error.BlockTooLarge => return,
            else => return err,
        };
        try self.record(sequence, head);
        try testing.expect(head.eql(self.db.head_info));
        self.remember(input.hash);
        if (self.prng.chance(2, 3)) _ = try self.try_set_head(input.hash);
    }

    fn step(self: *Harness) !void {
        if (self.db.phase == .failed) return error.DatabaseFailed;
        assert(self.db.phase == .ready);
        const roll = self.prng.below(100);
        if (roll < 2) {
            self.db.request_checkpoint();
        } else if (roll < 10) {
            if (self.random_known()) |hash| _ = try self.try_set_head(hash);
        } else if (roll < 45) {
            try self.new_block();
        }
        if (self.db.checkpoint_error) |err| return err;
        self.sim.tick();
        self.track_fallback();
    }

    fn track_fallback(self: *Harness) void {
        if (self.db.checkpoints_completed != self.checkpoints_seen) {
            self.checkpoints_seen = self.db.checkpoints_completed;
            self.fallback_intact = true;
        }
        if (self.db.engine.checkpoint_phase != .idle) self.fallback_intact = false;
    }

    /// Rots one checkpoint block header of the newest checkpoint; false if there is none.
    fn rot_newest_checkpoint(self: *Harness) bool {
        const checkpoint = self.db.engine.superblock.working.checkpoint;
        if (checkpoint.sequence == 0 or checkpoint.size_bytes == 0) return false;
        const block_size = config.engine.checkpoint_block_size;
        const blocks = checkpoint_module.block_count(checkpoint.size_bytes, block_size);
        const block = self.prng.below(blocks);
        const offset = config.engine.checkpoint_zone_offset(checkpoint.zone) + block * block_size;
        // The first byte of a block header is checksummed: the block can no longer verify.
        self.sim.durable[@intCast(offset)] ^= 0x04;
        self.sim.memory[@intCast(offset)] ^= 0x04;
        return true;
    }

    /// Crash, restart, and check the recovered head against the live history. With `.rot`,
    /// also rot the newest checkpoint when its fallback is intact.
    fn crash_and_check(self: *Harness, rot_checkpoint: enum { keep, rot }) !void {
        const acknowledged = self.db.durable_sequence;
        self.track_fallback();
        const fallback_ready = self.fallback_intact;
        self.sim.crash();
        const rotten = rot_checkpoint == .rot and fallback_ready and self.rot_newest_checkpoint();
        try self.reopen();
        const fallback = (try self.db.engine.open_result).checkpoint_fallback;
        if (rotten) try testing.expect(fallback);
        if (fallback) self.fallback_intact = false;
        const recovered = self.db.submitted_sequence;
        try testing.expect(recovered >= acknowledged);
        try testing.expect(recovered <= self.submitted);
        try testing.expect(self.db.head_info.eql(self.heads[recovered]));
        if (self.db.head_info.present) {
            try testing.expectEqual(self.db.head_info.state_root, try self.db.state.state_root());
            const head = self.db.chain.head().?;
            try testing.expectEqual(self.db.head_info.number, head.number);
        }
        self.submitted = recovered;
    }
};

fn sim_create(seed: u64, prng: *Prng) !SimStorage {
    return SimStorage.init(testing.allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 6)),
    });
}

fn run_crash_seed(seed: u64) !u32 {
    var prng = Prng.init(seed);
    var sim = try sim_create(seed, &prng);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, prng.int(u64));
    defer harness.destroy();
    try harness.format(0xd8_0000 + seed);
    var fallbacks: u32 = 0;
    var cycle: u32 = 0;
    while (cycle < 4) : (cycle += 1) {
        const crash_tick = prng.range(1, 1200);
        var tick: u64 = 0;
        while (tick < crash_tick) : (tick += 1) try harness.step();
        try harness.crash_and_check(if (prng.chance(1, 2)) .rot else .keep);
        if ((try harness.db.engine.open_result).checkpoint_fallback) fallbacks += 1;
    }
    try testing.expect(harness.db.chain.block_count() > 0);
    return fallbacks;
}

test "database: seeded crash recovery matches a point between acknowledged and submitted" {
    var fallbacks: u32 = 0;
    var seed: u64 = 0;
    while (seed < 24) : (seed += 1) {
        fallbacks += run_crash_seed(seed) catch |err| {
            std.debug.print("database crash recovery: failing seed={d}\n", .{seed});
            return err;
        };
    }
    // Rotten newest checkpoints were recovered through the fallback.
    try testing.expect(fallbacks >= 8);
}

test "database: rotten newest checkpoint reopens to the live state via the fallback" {
    var prng = Prng.init(0xfa11);
    var sim = try sim_create(9, &prng);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 9);
    defer harness.destroy();
    try harness.format(0xfa11);
    for (0..2) |_| {
        var steps: u32 = 0;
        while (steps < 300) : (steps += 1) try harness.step();
        try harness.tick_until(Harness.idle);
        harness.db.request_checkpoint();
        try harness.tick_until(Harness.idle);
    }
    var steps: u32 = 0;
    while (steps < 100) : (steps += 1) try harness.step();
    try harness.tick_until(Harness.idle);
    try testing.expect(harness.db.engine.superblock.working.has_fallback());
    try testing.expect(harness.rot_newest_checkpoint());
    try check_equal_after_reopen(harness);
    const result = try harness.db.engine.open_result;
    try testing.expect(result.checkpoint_fallback);
    try testing.expect(result.entries_replayed > 0);
    // Work continues and a later clean reopen needs no fallback.
    steps = 0;
    while (steps < 100) : (steps += 1) try harness.step();
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    try check_equal_after_reopen(harness);
    try testing.expect(!(try harness.db.engine.open_result).checkpoint_fallback);
}

fn check_equal_after_reopen(harness: *Harness) !void {
    const head = harness.db.head_info;
    const blocks = harness.db.chain.block_count();
    var balances: [addresses_max]?state_module.AccountInfo = undefined;
    for (&balances, 0..) |*info, index| info.* = harness.db.state.basic(address_of(index));
    const sequence = harness.db.submitted_sequence;
    try harness.reopen();
    try testing.expect(head.eql(harness.db.head_info));
    try testing.expectEqual(sequence, harness.db.submitted_sequence);
    try testing.expectEqual(blocks, harness.db.chain.block_count());
    for (balances, 0..) |expected, index| {
        const actual = harness.db.state.basic(address_of(index));
        try testing.expectEqual(expected == null, actual == null);
        if (expected) |info| try testing.expect(info.eql(actual.?));
    }
    try testing.expectEqualSlices(
        u8,
        &harness.db.chain.head().?.hash,
        &harness.db.chain.canonical_hash(head.number).?,
    );
}

test "database: checkpoint then reopen equals the live state" {
    var prng = Prng.init(0xc0de);
    var sim = try sim_create(7, &prng);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 7);
    defer harness.destroy();
    try harness.format(0xc0de);
    var steps: u32 = 0;
    while (steps < 600) : (steps += 1) try harness.step();
    try harness.tick_until(Harness.idle);
    const completed = harness.db.checkpoints_completed;
    harness.db.request_checkpoint();
    try harness.tick_until(Harness.idle);
    try testing.expectEqual(completed + 1, harness.db.checkpoints_completed);
    try check_equal_after_reopen(harness);
    const replayed = (try harness.db.engine.open_result).entries_replayed;
    try testing.expectEqual(@as(u64, 0), replayed);
    // Entries after the checkpoint replay on top of it.
    steps = 0;
    while (steps < 50) : (steps += 1) try harness.step();
    try harness.tick_until(Harness.idle);
    try check_equal_after_reopen(harness);
}

// Entry codec.

fn check_roundtrip(body: []const u8) !void {
    const entry = database.decode_entry(body) catch return;
    var buffer: [4096]u8 = undefined;
    const encoded = switch (entry) {
        .block => |*input| database.encode_block(input, &buffer),
        .head => |*hash| database.encode_head(hash, &buffer),
        .block_and_head => |*input| database.encode_block_and_head(input, &buffer),
    };
    try testing.expectEqualSlices(u8, body, encoded);
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var body: [1024]u8 = undefined;
    const length = smith.slice(&body);
    try check_roundtrip(body[0..length]);
}

test "database: std.testing.fuzz entry decoder" {
    try std.testing.fuzz({}, fuzz_decode, .{});
}

test "database: seeded entry fuzz: valid roundtrip, mutations are rejected or canonical" {
    var prng = Prng.init(0xe417);
    var payload: [600]u8 = undefined;
    var hashes: [4]Hash = undefined;
    var buffer: [2048]u8 = undefined;
    var mutated: [2048]u8 = undefined;
    for (0..2000) |round| {
        prng.fill(&payload);
        for (&hashes) |*hash| prng.fill(hash);
        var input: BlockInput = .{
            .hash = hashes[0],
            .parent_hash = hashes[1],
            .number = prng.int(u64),
            .timestamp = prng.int(u64),
            .header = payload[0..prng.range(1, 100)],
            .body = payload[100..][0..prng.below(100)],
            .receipts = payload[200..][0..prng.below(100)],
            .transaction_hashes = hashes[0..prng.below(5)],
            .changeset = payload[300..][0..prng.below(300)],
        };
        const encoded = switch (round % 5) {
            0 => database.encode_head(&input.hash, &buffer),
            1 => database.encode_block_and_head(&input, &buffer),
            else => database.encode_block(&input, &buffer),
        };
        try check_roundtrip(encoded);
        const decoded = try database.decode_entry(encoded);
        try testing.expectEqual(round % 5 == 1, decoded == .block_and_head);
        switch (decoded) {
            .block, .block_and_head => |decoded_input| {
                try testing.expectEqual(input.number, decoded_input.number);
                try testing.expectEqualSlices(u8, input.changeset, decoded_input.changeset);
                input = decoded_input;
            },
            .head => |hash| try testing.expectEqualSlices(u8, &input.hash, &hash),
        }
        @memcpy(mutated[0..encoded.len], encoded);
        var length = encoded.len;
        switch (prng.below(3)) {
            0 => mutated[prng.below(length)] ^= @as(u8, 1) << @intCast(prng.below(8)),
            1 => length = prng.below(length),
            else => {
                mutated[length] = prng.int(u8);
                length += 1;
                try testing.expectError(error.InvalidEntry, database.decode_entry(
                    mutated[0..length],
                ));
            },
        }
        try check_roundtrip(mutated[0..length]);
    }
}

test "database: metadata encodes the head and is zero without one" {
    const empty = database.metadata_encode(.{});
    for (empty) |byte| try testing.expectEqual(@as(u8, 0), byte);
    const info: HeadInfo = .{
        .present = true,
        .number = 9,
        .hash = @splat(1),
        .state_root = @splat(2),
    };
    const metadata = database.metadata_encode(info);
    try testing.expectEqual(@as(u8, 1), metadata[0]);
    try testing.expectEqual(@as(u64, 9), std.mem.readInt(u64, metadata[8..16], .little));
    try testing.expectEqualSlices(u8, &info.state_root, metadata[48..80]);
}

test "database: operations before open and on unknown blocks are refused" {
    var prng = Prng.init(3);
    var sim = try sim_create(3, &prng);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 3);
    defer harness.destroy();
    try testing.expectError(error.NotReady, harness.db.set_head(@splat(1)));
    try harness.format(3);
    try testing.expectError(error.UnknownBlock, harness.db.set_head(@splat(1)));
    var input = harness.block_input(@splat(0xee), 5);
    input.changeset = harness.db.changeset_buffer[0..0];
    try testing.expectError(error.UnknownParent, harness.db.insert_block(&input));
    const head = harness.db.head_info;
    try testing.expectError(error.ParentNotHead, harness.db.execute_and_commit(
        &harness.overlay,
        &input,
    ));
    try testing.expect(head.eql(harness.db.head_info));
}

test "database: execute_and_commit journals one entry with one sync" {
    var prng = Prng.init(11);
    var sim = try sim_create(11, &prng);
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim, 11);
    defer harness.destroy();
    try harness.format(11);
    try testing.expectEqual(@as(u64, 1), harness.db.durable_sequence);
    for (0..4) |_| {
        const head = harness.db.head_info;
        const syncs_before = sim.stats.syncs;
        try harness.overlay.set_storage(address_of(1), 2, head.number + 7);
        var input = harness.block_input(head.hash, head.number + 1);
        const commit = try harness.db.execute_and_commit(&harness.overlay, &input);
        try testing.expectEqual(head.number + 1, harness.db.head_info.number);
        try testing.expectEqual(harness.db.submitted_sequence, commit.sequence);
        try harness.record(commit.sequence, harness.db.head_info);
        try harness.tick_until(Harness.idle);
        try testing.expectEqual(commit.sequence, harness.db.durable_sequence);
        try testing.expectEqual(syncs_before + 1, sim.stats.syncs);
    }
    try check_equal_after_reopen(harness);
}

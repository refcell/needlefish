//! Database-owned history tests: a seeded workload of blocks, side branches, reorgs, and
//! crash/reopen over `SimStorage` with `Config.history` on. At checkpoints of the run,
//! `proof_at` at every block of the window must verify against that block's recorded state
//! root and equal the proof of the database's own `State` unwound to that block. After a
//! crash and reopen at a random point the window is rebuilt from the retained blocks: it
//! reaches back as far as the window and retention allow, and its proofs equal the proofs
//! served before the crash. A full store drops history (counted in `history_drops`) and
//! rebuilds it at the head without failing any commit.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const storage = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const history = @import("history.zig");
const proof_set = @import("proof_set.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = database.Hash;
const BlockInput = database.BlockInput;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const StateTrie = trie.StateTrie;
const Database = database.DatabaseType(SimStorage);
const sector_size = storage.sector_size;

const addresses_max = 24;
const slots_max = 6;
const window_blocks = 6;
const roots_max = 512;
const known_max = 32;
const ticks_max = 200_000;

const history_config: history.Config = .{
    .window_blocks = window_blocks,
    .paths_max = 8192,
    .small_versions_max = 8192,
    .large_versions_max = 2048,
    .prune_per_commit = 512,
};

const base_config: database.Config = .{
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
    .history = history_config,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 64,
    .slots_max = 256,
    .codes_max = 4,
};

fn address_of(index: u64) state_module.Address {
    var address: state_module.Address = @splat(0x33);
    address[0] = @intCast(index);
    return address;
}

fn hash_of(id: u32) Hash {
    var hash: Hash = @splat(0xcd);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

const all_slots: [slots_max]u256 = .{ 0, 1, 2, 3, 4, 5 };

/// Proof buffers are large; one set lives on the heap.
const Proofs = struct {
    account: StateTrie.AccountProof = .{},
    storage: [slots_max]StateTrie.StorageProof = undefined,
    values: [slots_max]u256 = undefined,
    live_account: StateTrie.AccountProof = .{},
    live_storage: StateTrie.StorageProof = .{},
    multi_account: StateTrie.AccountProof = .{},
    filled: StateTrie.StorageProof = .{},
    set_storage: proof_set.Storage(2 * slots_max) = undefined,
};

/// Every slot, then every slot again in reverse (duplicates, unsorted).
const multi_slots: [2 * slots_max]u256 = blk: {
    var slots: [2 * slots_max]u256 = undefined;
    for (all_slots, 0..) |slot, index| {
        slots[index] = slot;
        slots[2 * slots_max - 1 - index] = slot;
    }
    break :blk slots;
};

fn expect_same_proof(expected: anytype, got: anytype) !void {
    try testing.expectEqual(expected.count, got.count);
    var index: u32 = 0;
    while (index < expected.count) : (index += 1) {
        try testing.expectEqualSlices(u8, expected.node_at(index), got.node_at(index));
    }
}

fn verify(root: Hash, key: *const Hash, proof: anytype) !?[]const u8 {
    var nodes: [proof.ends.len][]const u8 = undefined;
    for (nodes[0..proof.count], 0..) |*slot, index| slot.* = proof.node_at(@intCast(index));
    return trie.verify_proof(root, key, nodes[0..proof.count]);
}

const RootEntry = struct { hash: Hash, root: Hash };
const DigestEntry = struct { hash: Hash, digest: u64 };

const Harness = struct {
    sim: SimStorage,
    db: Database,
    overlay: Overlay,
    changeset: Changeset,
    prng: Prng,
    proofs: *Proofs,
    config: database.Config,
    /// State root of every block ever committed (test-side record, by hash).
    roots: [roots_max]RootEntry = undefined,
    roots_len: u32 = 0,
    known: [known_max]Hash = undefined,
    known_len: u32 = 0,
    block_id_next: u32 = 0,
    header: [16]u8 = undefined,
    /// Proof digests of the window's blocks taken before a crash, by block hash.
    digests: [window_blocks]DigestEntry = undefined,
    digests_len: u32 = 0,

    fn create(seed: u64, config: database.Config) !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        self.* = .{
            .sim = undefined,
            .db = undefined,
            .overlay = undefined,
            .changeset = undefined,
            .prng = Prng.init(seed),
            .proofs = undefined,
            .config = config,
        };
        self.sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = config.engine.size_bytes(),
            .seed = seed,
        });
        errdefer self.sim.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, &self.sim, config);
        errdefer self.db.deinit(testing.allocator);
        self.overlay = try Overlay.init(testing.allocator, &self.db.state, overlay_config);
        errdefer self.overlay.deinit(testing.allocator);
        self.changeset = try Changeset.init(testing.allocator, config.changeset);
        errdefer self.changeset.deinit(testing.allocator);
        self.proofs = try testing.allocator.create(Proofs);
        self.proofs.* = .{};
        return self;
    }

    fn destroy(self: *Harness) void {
        testing.allocator.destroy(self.proofs);
        self.changeset.deinit(testing.allocator);
        self.overlay.deinit(testing.allocator);
        self.db.deinit(testing.allocator);
        self.sim.deinit(testing.allocator);
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

    fn open(self: *Harness) !void {
        self.db.open();
        try self.tick_until(not_opening);
        if (self.db.open_error) |err| return err;
        try testing.expectEqual(database.Phase.ready, self.db.phase);
    }

    /// Formats, opens, and commits a genesis block with a few accounts.
    fn format(self: *Harness) !void {
        self.db.format(0x4157_0000);
        try self.tick_until(not_formatting);
        try self.open();
        for (0..6) |index| {
            try self.overlay.set_account(address_of(index), .{ .balance = 100 + index });
            try self.overlay.set_storage(address_of(index), 1, index + 1);
        }
        try self.commit(@splat(0), 0);
    }

    /// Crash (pending writes may be lost) and reopen over the same storage.
    fn crash_and_reopen(self: *Harness) !void {
        self.sim.crash();
        try self.reopen(self.config);
    }

    /// Reopens over the same storage with `config` (the caller crashed or drained it).
    fn reopen(self: *Harness, config: database.Config) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, &self.sim, config);
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    /// `reopen` with the snapshot and history rebuild done by `load_mode`.
    fn reopen_with(self: *Harness, config: database.Config, mode: database.LoadMode) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, &self.sim, config);
        self.db.load_mode = mode;
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    /// Everything a load path could change, as one digest: the head, the state root, every
    /// account and `has_storage`, the history window and usage, and the proofs of every
    /// address at every block of the window.
    fn reopen_digest(self: *Harness) !u64 {
        var hasher = std.hash.Wyhash.init(0);
        const head = self.db.head_info;
        hasher.update(&head.hash);
        hasher.update(&head.state_root);
        hasher.update(&try self.db.state.state_root());
        for (0..addresses_max) |index| {
            const address = address_of(index);
            hasher.update(&.{@intFromBool(self.db.state.has_storage(address))});
            const entry = self.db.state.account(address) orelse continue;
            hasher.update(std.mem.asBytes(&entry.info.nonce));
            hasher.update(std.mem.asBytes(&entry.info.balance));
            hasher.update(std.mem.asBytes(&entry.storage_slots));
        }
        const store = if (self.db.history) |*store| store else return hasher.final();
        hasher.update(&.{@intFromBool(self.db.history_off)});
        const window = store.window() orelse return hasher.final();
        const usage = store.usage();
        const fields = [_]u64{
            window.oldest,        window.head,       usage.paths, usage.small_versions,
            usage.large_versions, usage.prune_queue, usage.bytes,
        };
        hasher.update(std.mem.sliceAsBytes(&fields));
        var number = window.oldest;
        while (number <= window.head) : (number += 1) {
            hasher.update(std.mem.asBytes(&try self.proof_digest_all(number)));
        }
        return hasher.final();
    }

    /// `proof_digest` over every address.
    fn proof_digest_all(self: *Harness, number: u64) !u64 {
        const proofs = self.proofs;
        var hasher = std.hash.Wyhash.init(number);
        for (0..addresses_max) |index| {
            const account = try self.db.proof_at(
                number,
                address_of(index),
                &all_slots,
                &proofs.account,
                &proofs.storage,
                &proofs.values,
            );
            hasher.update(&.{@intFromBool(account != null)});
            for (0..proofs.account.count) |node| {
                hasher.update(proofs.account.node_at(@intCast(node)));
            }
            for (&proofs.storage, &proofs.values) |*proof, value| {
                for (0..proof.count) |node| hasher.update(proof.node_at(@intCast(node)));
                hasher.update(std.mem.asBytes(&value));
            }
        }
        return hasher.final();
    }

    fn root_of(self: *const Harness, hash: Hash) Hash {
        for (self.roots[0..self.roots_len]) |entry| {
            if (std.mem.eql(u8, &entry.hash, &hash)) return entry.root;
        }
        unreachable; // Every committed block is recorded.
    }

    /// Executes the overlay's writes as a child of `parent` (the head) and commits it.
    fn commit(self: *Harness, parent: Hash, number: u64) !void {
        const id = self.block_id_next;
        self.block_id_next += 1;
        std.mem.writeInt(u128, &self.header, id, .little);
        const input: BlockInput = .{
            .hash = hash_of(id),
            .parent_hash = parent,
            .number = number,
            .timestamp = number * 2,
            .header = &self.header,
            .body = "b",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
        const result = try self.db.execute_and_commit(&self.overlay, &input);
        assert(self.roots_len < roots_max);
        self.roots[self.roots_len] = .{ .hash = input.hash, .root = result.state_root };
        self.roots_len += 1;
        self.known[id % known_max] = input.hash;
        self.known_len = @min(self.known_len + 1, known_max);
        try self.tick_until(idle);
    }

    fn random_writes(self: *Harness) !void {
        for (0..self.prng.range(1, 5)) |_| {
            const address = address_of(self.prng.below(addresses_max));
            if (self.prng.chance(1, 12)) {
                try self.overlay.set_account(address, null);
                continue;
            }
            var info = self.overlay.basic(address) orelse state_module.AccountInfo{};
            info.nonce += 1;
            info.balance = self.prng.int(u64);
            try self.overlay.set_account(address, info);
            if (self.prng.chance(1, 10)) try self.overlay.wipe_storage(address);
            for (0..self.prng.below(4)) |_| {
                const value: u256 = if (self.prng.chance(1, 4)) 0 else self.prng.int(u64);
                try self.overlay.set_storage(address, self.prng.below(slots_max), value);
            }
        }
    }

    /// Moves the head to a random stored block; false when the move is refused.
    fn reorg(self: *Harness) !bool {
        if (self.known_len == 0) return false;
        const hash = self.known[self.prng.below(self.known_len)];
        if (self.db.chain.meta(hash) == null) return false;
        _ = self.db.set_head(hash) catch |err| switch (err) {
            error.ReorgTooDeep, error.UnknownBlock, error.UnknownParent => return false,
            else => return err,
        };
        try self.tick_until(idle);
        return true;
    }

    fn step(self: *Harness) !void {
        try testing.expectEqual(database.Phase.ready, self.db.phase);
        if (self.prng.chance(1, 5) and try self.reorg()) return;
        try self.build();
    }

    /// Builds one block of random writes on the head.
    fn build(self: *Harness) !void {
        const head = self.db.head_info;
        self.overlay.discard();
        try self.random_writes();
        self.commit(head.hash, head.number + 1) catch |err| switch (err) {
            // The parent is the oldest retained block and this insert would evict it.
            error.UnknownParent => self.overlay.discard(),
            else => return err,
        };
    }

    /// History at `number` equals the live state (which holds block `number`).
    fn expect_matches_live(self: *Harness, number: u64, address_index: u64) !void {
        const db = &self.db;
        const proofs = self.proofs;
        const root = self.root_of(db.chain.canonical_hash(number).?);
        try testing.expectEqual(root, try db.state.state_root());
        try testing.expectEqual(root, try db.history.?.state_root_at(number));
        const address = address_of(address_index);
        const address_hash = trie.node.keccak256(&address);
        const account = try db.proof_at(
            number,
            address,
            &all_slots,
            &proofs.account,
            &proofs.storage,
            &proofs.values,
        );
        try db.state.state_trie.prove_account(address_hash, &proofs.live_account);
        try expect_same_proof(&proofs.live_account, &proofs.account);
        const info = db.state.basic(address);
        try testing.expectEqual(info != null, account != null);
        const proven = try verify(root, &address_hash, &proofs.account);
        try testing.expectEqual(info != null, proven != null);
        if (info) |expected| {
            try testing.expectEqual(expected.nonce, account.?.nonce);
            try testing.expectEqual(expected.balance, account.?.balance);
        }
        const storage_root = if (account) |found| found.storage_root else trie.empty_root;
        try testing.expectEqual(db.state.state_trie.storage_root(address_hash), storage_root);
        for (all_slots, 0..) |slot, index| {
            var slot_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot_bytes, slot, .big);
            const slot_hash = trie.node.keccak256(&slot_bytes);
            db.state.state_trie.prove_storage(address_hash, slot_hash, &proofs.live_storage);
            try expect_same_proof(&proofs.live_storage, &proofs.storage[index]);
            try testing.expectEqual(db.state.storage(address, slot), proofs.values[index]);
            const value = try verify(storage_root, &slot_hash, &proofs.storage[index]);
            try testing.expectEqual(proofs.values[index] != 0, value != null);
        }
        try self.expect_multi_matches(number, address, account);
        try self.expect_range_matches(number, address_hash);
    }

    /// `storage_range_at(number)` equals the live trie (which holds block `number`): the head
    /// from the live trie, older blocks from history.
    fn expect_range_matches(self: *Harness, number: u64, address_hash: Hash) !void {
        const db = &self.db;
        var live_out: [slots_max + 1]trie.StorageEntry = undefined;
        var got_out: [slots_max + 1]trie.StorageEntry = undefined;
        var start: Hash = @splat(0);
        if (self.prng.chance(1, 2)) self.prng.fill(&start);
        const max: u32 = @intCast(self.prng.below(slots_max + 2));
        const live_trie = &db.state.state_trie;
        const live = live_trie.storage_range(address_hash, start, max, &live_out) catch |err| {
            const got = db.storage_range_at(number, address_hash, start, max, &got_out);
            try testing.expectError(err, got);
            return;
        };
        const got = try db.storage_range_at(number, address_hash, start, max, &got_out);
        try testing.expectEqual(live.count, got.count);
        try testing.expectEqual(live.next, got.next);
        const expected = live_out[0..live.count];
        try testing.expectEqualSlices(trie.StorageEntry, expected, got_out[0..got.count]);
    }

    /// `proofs_at` (one storage walk) equals the `proof_at` results just computed.
    fn expect_multi_matches(
        self: *Harness,
        number: u64,
        address: state_module.Address,
        account: ?history.AccountState,
    ) !void {
        const proofs = self.proofs;
        var set = proofs.set_storage.set();
        const multi = try self.db.proofs_at(
            number,
            address,
            &multi_slots,
            &proofs.multi_account,
            &set,
        );
        try testing.expectEqual(account, multi);
        try expect_same_proof(&proofs.account, &proofs.multi_account);
        for (multi_slots, 0..) |slot, index| {
            const single = @as(usize, @intCast(slot));
            set.fill(@intCast(index), &proofs.filled);
            try expect_same_proof(&proofs.storage[single], &proofs.filled);
            try testing.expectEqual(proofs.values[single], set.value(@intCast(index)));
        }
    }

    fn load_changeset(self: *Harness, number: u64) !void {
        const view = self.db.chain.block(self.db.chain.canonical_hash(number).?).?;
        try self.changeset.decode(view.changeset);
    }

    /// Checks every block of the window by unwinding the database's state down to the
    /// oldest (or as far as retained changesets reach), then re-applies the changesets back
    /// to the head.
    fn sweep(self: *Harness) !void {
        const head = self.db.head_info;
        const window = self.db.history.?.window().?;
        try testing.expectEqual(head.number, window.head);
        try testing.expect(window.head - window.oldest < window_blocks);
        const floor = @max(window.oldest, self.expected_oldest(window_blocks));
        var number = window.head;
        var steps: u32 = 0;
        while (steps < window_blocks) : (steps += 1) {
            for (0..3) |_| try self.expect_matches_live(number, self.prng.below(addresses_max));
            if (number == floor) break;
            try self.load_changeset(number);
            try self.db.state.unwind(&self.changeset);
            number -= 1;
        }
        try testing.expectEqual(floor, number);
        while (number < head.number) {
            number += 1;
            try self.load_changeset(number);
            try self.db.state.apply(&self.changeset);
        }
        try testing.expectEqual(head.state_root, try self.db.state.state_root());
    }

    /// A digest of `proof_at(number)` for every third address: proof nodes, values, account.
    fn proof_digest(self: *Harness, number: u64) !u64 {
        const proofs = self.proofs;
        var hasher = std.hash.Wyhash.init(number);
        var index: u64 = 0;
        while (index < addresses_max) : (index += 3) {
            const account = try self.db.proof_at(
                number,
                address_of(index),
                &all_slots,
                &proofs.account,
                &proofs.storage,
                &proofs.values,
            );
            hasher.update(&.{@intFromBool(account != null)});
            for (0..proofs.account.count) |node| {
                hasher.update(proofs.account.node_at(@intCast(node)));
            }
            for (&proofs.storage, &proofs.values) |*proof, value| {
                for (0..proof.count) |node| hasher.update(proof.node_at(@intCast(node)));
                hasher.update(std.mem.asBytes(&value));
            }
        }
        return hasher.final();
    }

    /// Records the proof digest of every block of the window (before a crash).
    fn record_digests(self: *Harness) !void {
        const window = self.db.history.?.window().?;
        assert(window.head - window.oldest < window_blocks);
        self.digests_len = 0;
        var number = window.oldest;
        while (number <= window.head) : (number += 1) {
            self.digests[self.digests_len] = .{
                .hash = self.db.chain.canonical_hash(number).?,
                .digest = try self.proof_digest(number),
            };
            self.digests_len += 1;
        }
    }

    /// The window `open` must rebuild: back to `head - window + 1`, stopping above the
    /// newest canonical block without a retained changeset (genesis is never unwound).
    fn expected_oldest(self: *const Harness, window: u32) u64 {
        const head = self.db.head_info.number;
        const lowest = head -| (window - 1);
        var number = head;
        while (number > lowest) : (number -= 1) {
            const hash = self.db.chain.canonical_hash(number) orelse return number;
            if (self.db.chain.block(hash) == null) return number;
        }
        return lowest;
    }

    /// After a reopen: the window is the expected one, every block of it that was in the
    /// window before the crash serves the same proofs, and the rest verify (`sweep`).
    fn check_rebuilt(self: *Harness) !u32 {
        const head = self.db.head_info;
        const window = self.db.history.?.window().?;
        try testing.expectEqual(head.number, window.head);
        try testing.expectEqual(self.expected_oldest(window_blocks), window.oldest);
        try testing.expectEqual(head.state_root, try self.db.state.state_root());
        var matched: u32 = 0;
        for (self.digests[0..self.digests_len]) |entry| {
            const meta = self.db.chain.meta(entry.hash) orelse continue;
            if (meta.number < window.oldest or meta.number > window.head) continue;
            if (!self.db.chain.is_canonical(entry.hash)) continue;
            try testing.expectEqual(entry.digest, try self.proof_digest(meta.number));
            matched += 1;
        }
        try self.sweep();
        return matched;
    }
};

fn run_seed(seed: u64, config: database.Config) !void {
    const h = try Harness.create(seed, config);
    defer h.destroy();
    try h.format();
    var window_full = false;
    var matched: u32 = 0;
    var cycle: u32 = 0;
    while (cycle < 3) : (cycle += 1) {
        const rounds = h.prng.range(4, 30);
        for (0..rounds) |round| {
            try h.step();
            if (round % 6 == 5) try h.sweep();
            const window = h.db.history.?.window().?;
            if (window.head - window.oldest + 1 == window_blocks) window_full = true;
        }
        try h.record_digests();
        const head = h.db.head_info;
        try h.crash_and_reopen();
        // Commits waited for durability: the head and root survive the crash.
        try testing.expect(head.eql(h.db.head_info));
        matched += try h.check_rebuilt();
    }
    // Without the rebuild the window restarts at the head; the head is the same.
    try h.tick_until(Harness.idle);
    const head = h.db.head_info;
    var no_rebuild = config;
    no_rebuild.history_rebuild_on_open = false;
    try h.reopen(no_rebuild);
    try testing.expect(head.eql(h.db.head_info));
    const window = h.db.history.?.window().?;
    try testing.expectEqual(head.number, window.oldest);
    try testing.expectEqual(head.number, window.head);
    try testing.expect(window_full);
    try testing.expect(matched > 0);
    try testing.expectEqual(@as(u64, 0), h.db.history_drops);
    try testing.expect(!h.db.history_off);
}

test "database history: proofs at every block of the window across reorgs and reopen" {
    // Two seeds keep Debug runtime low; raise the count locally for deeper runs.
    for (0..2) |seed| run_seed(0xd8_4157 + seed, base_config) catch |err| {
        std.debug.print("database history: failing seed={d}\n", .{seed});
        return err;
    };
}

test "database history: a reopen rebuilds only the blocks retention keeps" {
    var config = base_config;
    // Fewer retained blocks than the window: the rebuilt window is bounded by retention.
    config.chain.blocks_max = 4;
    config.chain.reorg_depth_max = 3;
    run_seed(0x4e7a_10, config) catch |err| {
        std.debug.print("database history: failing retention seed\n", .{});
        return err;
    };
}

test "database history: without history a reopen serves only the head" {
    var config = base_config;
    config.history = null;
    const h = try Harness.create(0x0ff0, config);
    defer h.destroy();
    try h.format();
    for (0..8) |_| try h.build();
    const head = h.db.head_info;
    try h.crash_and_reopen();
    try testing.expect(head.eql(h.db.head_info));
    try testing.expect(h.db.history == null);
    try testing.expectEqual(head.state_root, try h.db.state.state_root());
    try testing.expectError(error.HistoryUnavailable, h.db.proof_at(
        head.number - 1,
        address_of(1),
        &.{},
        &h.proofs.account,
        &.{},
        &.{},
    ));
    var set = h.proofs.set_storage.set();
    const proofs_at = h.db.proofs_at(head.number, address_of(1), &.{}, &h.proofs.account, &set);
    try testing.expectError(error.HistoryUnavailable, proofs_at);
    // Storage ranges: the head from the live trie, older blocks need history.
    var out: [slots_max]trie.StorageEntry = undefined;
    const address_hash = trie.node.keccak256(&address_of(1));
    const zero: Hash = @splat(0);
    const live = try h.db.state.state_trie.storage_range(address_hash, zero, slots_max, &out);
    const at_head = try h.db.storage_range_at(head.number, address_hash, zero, slots_max, &out);
    try testing.expectEqual(live, at_head);
    const older = h.db.storage_range_at(head.number - 1, address_hash, zero, 1, &out);
    try testing.expectError(error.HistoryUnavailable, older);
}

test "database history: a full store drops history and the database stays healthy" {
    var config = base_config;
    // No pruning before the window fills, and room for only a few blocks of versions.
    config.history = .{
        .window_blocks = 64,
        .paths_max = 512,
        .small_versions_max = 192,
        .large_versions_max = 48,
        .prune_per_commit = 0,
    };
    const h = try Harness.create(0xf011, config);
    defer h.destroy();
    try h.format();
    var steps: u32 = 0;
    while (steps < 60) : (steps += 1) try h.step();
    try testing.expect(h.db.history_drops > 0);
    try testing.expect(!h.db.history_off);
    try testing.expectEqual(database.Phase.ready, h.db.phase);
    const head = h.db.head_info;
    try testing.expectEqual(head.state_root, try h.db.state.state_root());
    try testing.expectEqual(head.number, h.db.history.?.window().?.head);
    for (0..4) |index| try h.expect_matches_live(head.number, index);
    // The journal is intact: a reopen recovers the same head.
    try h.crash_and_reopen();
    try testing.expect(head.eql(h.db.head_info));
}

test "database history: without room for the state, history is off and the head is live" {
    var config = base_config;
    config.history = .{
        .window_blocks = 4,
        .paths_max = 4,
        .small_versions_max = 4,
        .large_versions_max = 4,
        .prune_per_commit = 4,
    };
    const h = try Harness.create(0x0ff, config);
    defer h.destroy();
    try h.format();
    for (0..3) |_| try h.build();
    try testing.expect(h.db.history_off);
    try testing.expectEqual(database.Phase.ready, h.db.phase);
    const head = h.db.head_info.number;
    const account = try h.db.proof_at(
        head,
        address_of(1),
        &all_slots,
        &h.proofs.account,
        &h.proofs.storage,
        &h.proofs.values,
    );
    try testing.expect(account != null);
    const address = address_of(1);
    const address_hash = trie.node.keccak256(&address);
    const root = h.db.head_info.state_root;
    try testing.expect(try verify(root, &address_hash, &h.proofs.account) != null);
    try testing.expectError(error.HistoryUnavailable, h.db.proof_at(
        head - 1,
        address_of(1),
        &.{},
        &h.proofs.account,
        &.{},
        &.{},
    ));
}

/// Under a byte budget: the window ends at the head, fits the budget, and the block below
/// its oldest is out of window. Returns whether the budget kept the window short.
fn expect_budget_window(h: *Harness, bytes_max: u64) !bool {
    const head = h.db.head_info.number;
    const store = &h.db.history.?;
    const window = store.window().?;
    try testing.expectEqual(head, window.head);
    try testing.expect(store.usage().bytes <= bytes_max);
    try testing.expect(window.oldest >= h.expected_oldest(window_blocks));
    if (window.oldest == 0) return false;
    var out: [1]trie.StorageEntry = undefined;
    const address_hash = trie.node.keccak256(&address_of(1));
    const zero: Hash = @splat(0);
    const range = h.db.storage_range_at(window.oldest - 1, address_hash, zero, 1, &out);
    try testing.expectError(error.BlockOutOfWindow, range);
    try testing.expectError(error.BlockOutOfWindow, h.db.proof_at(
        window.oldest - 1,
        address_of(1),
        &.{},
        &h.proofs.account,
        &.{},
        &.{},
    ));
    return window.oldest > h.expected_oldest(window_blocks);
}

test "database history: a byte budget shrinks the window, also when rebuilt on open" {
    var config = base_config;
    // The state grows to ~40 KiB of nodes and a full window to ~60 KiB.
    const bytes_max: u64 = 52 * 1024;
    config.history.?.bytes_max = bytes_max;
    const h = try Harness.create(0xb0d9, config);
    defer h.destroy();
    try h.format();
    var shrunk = false;
    var cycle: u32 = 0;
    while (cycle < 3) : (cycle += 1) {
        for (0..40) |round| {
            try h.step();
            if (try expect_budget_window(h, bytes_max)) shrunk = true;
            if (round % 8 == 7) try h.sweep();
        }
        const head = h.db.head_info;
        try h.crash_and_reopen();
        try testing.expect(head.eql(h.db.head_info));
        if (try expect_budget_window(h, bytes_max)) shrunk = true;
        try h.sweep();
    }
    try testing.expect(shrunk);
    // Shrinking is not a drop: history was never discarded.
    try testing.expectEqual(@as(u64, 0), h.db.history_drops);
    try testing.expect(!h.db.history_off);
}

/// Crashes at random points of a seeded workload and reopens the same storage three times:
/// with the incremental (reference) load path, then the bulk path, then the bulk path on
/// rehash threads. All three must recover identical state, window, usage, and proofs.
fn run_load_differential(seed: u64, config: database.Config) !void {
    const h = try Harness.create(seed, config);
    defer h.destroy();
    try h.format();
    var cycle: u32 = 0;
    while (cycle < 3) : (cycle += 1) {
        for (0..h.prng.range(4, 30)) |_| try h.step();
        try h.crash_and_reopen();
        try h.reopen_with(config, .incremental);
        const expected = try h.reopen_digest();
        try h.reopen_with(config, .bulk);
        try testing.expectEqual(expected, try h.reopen_digest());
        var threaded = config;
        threaded.state.rehash_threads = 2;
        try h.reopen_with(threaded, .bulk);
        try testing.expectEqual(expected, try h.reopen_digest());
        try h.reopen_with(config, .bulk);
    }
}

test "database history: bulk and incremental reopen recover the same state and history" {
    const budget = blk: {
        var config = base_config;
        config.history.?.bytes_max = 52 * 1024;
        break :blk config;
    };
    const no_history = blk: {
        var config = base_config;
        config.history = null;
        break :blk config;
    };
    const configs = [_]database.Config{ base_config, budget, no_history };
    for (configs, 0..) |config, index| {
        for (0..2) |seed| {
            const seed_full = 0x10ad_0000 + 16 * index + seed;
            run_load_differential(seed_full, config) catch |err| {
                std.debug.print("load differential: failing seed={d}\n", .{seed_full});
                return err;
            };
        }
    }
}

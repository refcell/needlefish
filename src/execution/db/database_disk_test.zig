//! Database disk mode (disk-state import plan step 8, `Config.disk_state`), on `SimStorage`.
//!
//! Differential: the same random blocks go to a disk-mode database and to an in-memory one
//! (no grid, no flat trees: the oracle). Blocks are executed through `Overlay` and committed
//! with `execute_and_commit`, or applied (`Overlay.commit`, so `State.apply` writes the trees)
//! and committed with `commit_applied`; side branches and reorgs go through `set_head`; disk
//! checkpoints (version 5), clean reopens, and crashes at random ticks follow (the oracle
//! then moves to the recovered head). After every block and head move, the head's state root
//! and every account (info, has-storage) and slot of the address universe read the same from
//! both. Wiping an account with storage is refused in disk mode (`Unsupported`) and the block
//! is dropped from both. A tiny branch flush trigger (below one block's branch writes) and the
//! smallest replay reserve the config allows exercise the operation room and the admission.
//!
//! Prefetch (`prefetch.zig`): before many steps the disk database prefetches a random mix of
//! keys (accounts and slots of the address universe, absent and random keys, branch records
//! at random hangs, keys of the wrong tree), sometimes left running across the next blocks,
//! checkpoints and crashes: every comparison with the oracle holds all the same.
//!
//! Imported start: a random state bulk-imported into the four trees, made head N with no
//! stored block (`import_head`), checkpointed, reopened (clean or after a crash), and compared
//! with the oracle given that state as its first block; then random blocks on top. A wrong
//! import root is refused, and a checkpoint whose root record does not hash to the head's
//! state root does not open.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const storage = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const branch_record = @import("branch_record.zig");
const disk_state_test = @import("disk_state_test.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const node_keccak = @import("../trie/node.zig").keccak256;

const Hash = database.Hash;
const HeadInfo = database.HeadInfo;
const BlockInput = database.BlockInput;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Database = database.DatabaseType(SimStorage);
const FlatTrees = Database.FlatTrees;
const sector_size = storage.sector_size;

const block_size: u32 = 4 * sector_size;
const addresses_max = 24;
const slots_per_address = 6;
const sequences_max = 16 * 1024;
const known_blocks_max = 32;
const ticks_max = 200_000;
const record_writes_max = 64;
const reorg_depth_max = 4;

const changeset_config: changeset_module.Config = .{
    .accounts_max = 32,
    .storage_max = 160,
    .codes_max = 1,
    .code_bytes_max = 1024,
};

const config_disk: database.Config = .{
    .engine = .{
        // Large enough that the branch-write admission, not the journal, asks for checkpoints.
        .journal_size_bytes = 256 * sector_size,
        .checkpoint_zone_size_bytes = 512 * block_size,
        .entry_body_size_max = 8 * sector_size,
        .checkpoint_block_size = block_size,
        .grid_block_count = 2048,
    },
    // Disk mode keeps only codes and block hashes in RAM.
    .state = .{
        .accounts_max = 4,
        .storage_slots_max = 4,
        .codes_max = 4,
        .code_bytes_max = 4096,
        .account_nodes_max = 64,
        .storage_nodes_max = 64,
    },
    .chain = .{
        .blocks_max = 16,
        .bytes_max = 256 * 1024,
        .transactions_max = 64,
        .canonical_max = 64,
        .reorg_depth_max = reorg_depth_max,
    },
    .changeset = changeset_config,
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 8 * 1024 * 1024,
    .flat_trees = true,
    .flat_flush_entries_min = 24,
    .flat_cache_blocks = 32,
    .flat_accounts_max = 256,
    .flat_slots_max = 4096,
    .flat_account_branches_max = 256,
    .flat_storage_branches_max = 4096,
    // Below one block's branch writes: a move fits only through the operation room.
    .flat_branch_flush_entries_min = 4,
    .flat_prefetch_keys_max = 48,
    .flat_prefetch_reads_max = 3,
    .disk_state = .{
        .trie_nodes_max = 1 << 13,
        .storage_tries_max = 64,
        .memo_entries_max = 1 << 13,
        .memo_bytes_max = 2 * 1024 * 1024,
        .record_writes_max = record_writes_max,
        .record_write_bytes_max = record_writes_max * branch_record.value_bytes_max,
        // The smallest the config allows: one largest move.
        .replay_record_writes_max = record_writes_max * (2 * reorg_depth_max + 1),
    },
};

/// The oracle: state in RAM, no grid. Retains and reorgs deeper than the disk database, so
/// it reaches every head the disk database recovers.
const config_memory: database.Config = .{
    .engine = .{
        .journal_size_bytes = 256 * sector_size,
        .checkpoint_zone_size_bytes = 64 * block_size,
        .entry_body_size_max = 8 * sector_size,
        .checkpoint_block_size = block_size,
        .grid_block_count = 0,
    },
    .state = .{
        .accounts_max = 64,
        .storage_slots_max = 512,
        .codes_max = 4,
        .code_bytes_max = 4096,
        .account_nodes_max = 2048,
        .storage_nodes_max = 8192,
    },
    .chain = .{
        .blocks_max = 64,
        .bytes_max = 1024 * 1024,
        .transactions_max = 256,
        .canonical_max = 256,
        .reorg_depth_max = 48,
    },
    .changeset = changeset_config,
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 1024 * 1024,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 32,
    .slots_max = 160,
    .codes_max = 1,
};

fn address_of(index: u64) Address {
    var address: Address = @splat(0x44);
    address[0] = @intCast(index);
    return address;
}

fn hash_of(id: u32) Hash {
    var hash: Hash = @splat(0xd1);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

/// One database with its overlay, pinned (the overlay points into it).
const Node = struct {
    db: Database,
    sim: *SimStorage,
    overlay: Overlay,
    config: database.Config,

    fn init(self: *Node, sim: *SimStorage, config: database.Config) !void {
        self.* = .{
            .db = try Database.init(testing.allocator, sim, config),
            .sim = sim,
            .overlay = undefined,
            .config = config,
        };
        errdefer self.db.deinit(testing.allocator);
        self.overlay = try Overlay.init(testing.allocator, &self.db.state, overlay_config);
    }

    fn deinit(self: *Node) void {
        self.overlay.deinit(testing.allocator);
        self.db.deinit(testing.allocator);
    }

    fn tick_until(self: *Node, comptime done: fn (*const Database) bool) !void {
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

    fn settled(db: *const Database) bool {
        return !db.checkpoint_wanted and db.engine.checkpoint_phase == .idle and db.idle();
    }

    fn format(self: *Node, format_id: u128) !void {
        self.db.format(format_id);
        try self.tick_until(not_formatting);
        try self.open();
    }

    fn open(self: *Node) !void {
        self.db.open();
        try self.tick_until(not_opening);
        if (self.db.open_error) |err| return err;
        try testing.expectEqual(database.Phase.ready, self.db.phase);
    }

    fn reopen(self: *Node) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, self.sim, self.config);
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    /// Requests a checkpoint and drives it (unpaced) until it is written and all is idle.
    fn checkpoint(self: *Node) !void {
        self.db.request_checkpoint();
        var ticks: u32 = 0;
        while (!settled(&self.db)) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.db.checkpoint_flush();
            self.sim.tick();
        }
        if (self.db.checkpoint_error) |err| return err;
    }

    /// `execute_and_commit`, ticking while busy (the oracle must take every block).
    fn commit_retry(self: *Node, input: *const BlockInput) !database.Commit {
        var ticks: u32 = 0;
        while (true) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            return self.db.execute_and_commit(&self.overlay, input) catch |err| switch (err) {
                error.Busy => {
                    self.sim.tick();
                    continue;
                },
                else => return err,
            };
        }
    }

    fn set_head_retry(self: *Node, hash: Hash) !void {
        var ticks: u32 = 0;
        while (true) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            _ = self.db.set_head(hash) catch |err| switch (err) {
                error.Busy => {
                    self.sim.tick();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    /// The journal has room for a largest entry with half the zone to spare.
    fn journal_roomy(self: *const Node) bool {
        const journal = &self.db.engine.journal;
        const used = journal.head - journal.tail + self.db.journal_bytes_pending;
        return self.db.queue_count == 0 and used * 2 <= journal.config.zone_size_bytes;
    }
};

const Op = union(enum) {
    account: struct { address: Address, info: ?AccountInfo },
    slot: struct { address: Address, slot: u64, value: u256 },
};

/// The imported start's whole state is one oracle block.
const ops_max = addresses_max * (1 + slots_per_address);

const Counts = struct {
    blocks: u64 = 0,
    blocks_applied: u64 = 0,
    head_moves: u64 = 0,
    wipes_refused: u64 = 0,
    /// Committed blocks that destroy an account (without storage).
    destroyed: u64 = 0,
    crashes: u64 = 0,
    record_writes_max: u64 = 0,
    admission_busy: u64 = 0,
    branch_flushes: u64 = 0,
    imports: u64 = 0,
    stored_alone: u64 = 0,
    /// Prefetches started, and blocks they read into the cache.
    prefetches: u64 = 0,
    prefetch_reads: u64 = 0,
};

const Harness = struct {
    disk: Node,
    memory: Node,
    disk_sim: *SimStorage,
    memory_sim: *SimStorage,
    prng: Prng,
    heads: []HeadInfo,
    submitted: u64 = 0,
    known: [known_blocks_max]Hash = undefined,
    known_len: u32 = 0,
    block_id_next: u32 = 0,
    header_buffer: [48]u8 = undefined,
    ops: [ops_max]Op = undefined,
    ops_len: u32 = 0,
    /// The block destroys an account that has storage (disk mode refuses it).
    wipes_storage: bool = false,
    destroys: bool = false,
    changeset: Changeset,
    changeset_buffer: []u8,
    counts: *Counts,

    fn create(
        disk_sim: *SimStorage,
        memory_sim: *SimStorage,
        seed: u64,
        counts: *Counts,
    ) !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        const heads = try testing.allocator.alloc(HeadInfo, sequences_max + 1);
        errdefer testing.allocator.free(heads);
        heads[0] = .{};
        var changeset = try Changeset.init(testing.allocator, changeset_config);
        errdefer changeset.deinit(testing.allocator);
        const buffer = try testing.allocator.alloc(u8, config_disk.engine.entry_body_size_max);
        errdefer testing.allocator.free(buffer);
        self.* = .{
            .disk = undefined,
            .memory = undefined,
            .disk_sim = disk_sim,
            .memory_sim = memory_sim,
            .prng = Prng.init(seed),
            .heads = heads,
            .changeset = changeset,
            .changeset_buffer = buffer,
            .counts = counts,
        };
        try self.disk.init(disk_sim, config_disk);
        errdefer self.disk.deinit();
        try self.memory.init(memory_sim, config_memory);
        return self;
    }

    fn destroy(self: *Harness) void {
        self.count_trees();
        self.memory.deinit();
        self.disk.deinit();
        testing.allocator.free(self.changeset_buffer);
        self.changeset.deinit(testing.allocator);
        testing.allocator.free(self.heads);
        testing.allocator.destroy(self);
    }

    fn count_trees(self: *Harness) void {
        const trees = &self.disk.db.flat.?;
        self.counts.branch_flushes += trees.account_branches.stats.flushes +
            trees.storage_branches.stats.flushes;
        self.counts.admission_busy += self.disk.db.disk_admission_busy;
        self.counts.prefetch_reads += trees.prefetch.?.stats.reads;
    }

    /// Starts a prefetch of random keys, right and wrong, and ticks it a random number of
    /// times (it may outlive this step: later blocks, checkpoints and crashes meet it).
    fn prefetch(self: *Harness) void {
        const trees = &self.disk.db.flat.?;
        const prefetch_state = trees.prefetch.?;
        if (prefetch_state.running) return;
        prefetch_state.clear();
        for (0..self.prng.range(1, 48)) |_| {
            const address_hash = node_keccak(&address_of(self.prng.below(addresses_max + 4)));
            var slot_bytes: [32]u8 = @splat(0);
            slot_bytes[31] = @intCast(self.prng.below(slots_per_address + 2));
            const slot_hash = node_keccak(&slot_bytes);
            var random: Hash = undefined;
            self.prng.fill(&random);
            var hang: [6]u8 = undefined;
            for (&hang) |*nibble| nibble.* = @intCast(self.prng.below(16));
            const depth: usize = @intCast(self.prng.below(hang.len + 1));
            switch (self.prng.below(9)) {
                0, 1 => prefetch_state.add_account(&address_hash),
                7 => prefetch_state.add_path(&address_hash, &slot_hash),
                8 => prefetch_state.add_path(null, &address_hash),
                2, 3 => prefetch_state.add_slot(&address_hash, &slot_hash),
                4 => prefetch_state.add_branch(&address_hash, hang[0..depth]),
                5 => prefetch_state.add_branch(null, hang[0..depth]),
                else => prefetch_state.add_slot(&random, &address_hash),
            }
        }
        prefetch_state.start(trees);
        self.counts.prefetches += 1;
        for (0..self.prng.below(12)) |_| self.disk_sim.tick();
    }

    fn format(self: *Harness, seed: u64) !void {
        try self.disk.format(0xd15c_d000 + seed);
        try self.memory.format(0x3e30_0000 + seed);
    }

    fn record(self: *Harness, sequence: u64) !void {
        if (sequence == self.submitted) return;
        try testing.expectEqual(self.submitted + 1, sequence);
        try testing.expect(sequence <= sequences_max);
        self.heads[sequence] = self.disk.db.head_info;
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
            byte.* = @truncate(id *% 157 +% index);
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

    fn add_op(self: *Harness, op: Op) !void {
        assert(self.ops_len < ops_max);
        self.ops[self.ops_len] = op;
        self.ops_len += 1;
        try apply_op(&self.disk.overlay, op);
    }

    fn apply_op(overlay: *Overlay, op: Op) !void {
        switch (op) {
            .account => |account| try overlay.set_account(account.address, account.info),
            .slot => |slot| try overlay.set_storage(slot.address, slot.slot, slot.value),
        }
    }

    /// Random writes into the disk overlay (recorded for the oracle): account updates and
    /// creations, slot writes (zero deletes), storage-only changes, destructions (with or
    /// without storage, sometimes recreated in the same block).
    fn random_ops(self: *Harness) !void {
        self.ops_len = 0;
        self.wipes_storage = false;
        self.destroys = false;
        for (0..self.prng.range(1, 4)) |_| {
            const address = address_of(self.prng.below(addresses_max));
            const existing = self.disk.overlay.basic(address);
            const has_storage = self.disk.db.state.has_storage(address);
            // Mostly destroy accounts without storage: disk mode refuses the others.
            const destroy_chance: u64 = if (has_storage) 40 else 4;
            if (existing != null and self.prng.chance(1, destroy_chance)) {
                if (has_storage) self.wipes_storage = true;
                try self.add_op(.{ .account = .{ .address = address, .info = null } });
                self.destroys = true;
                if (self.prng.chance(1, 2)) continue;
            }
            const current = self.disk.overlay.basic(address);
            if (current == null or self.prng.chance(2, 3)) {
                var info = current orelse AccountInfo{};
                info.nonce += 1;
                info.balance = self.prng.int(u64);
                try self.add_op(.{ .account = .{ .address = address, .info = info } });
            }
            // Half the new accounts start without storage (destroyable in disk mode).
            const slot_writes = if (current == null and self.prng.chance(1, 2))
                0
            else
                self.prng.below(5);
            for (0..slot_writes) |_| {
                const value: u256 = if (self.prng.chance(1, 4)) 0 else self.prng.int(u64);
                try self.add_op(.{ .slot = .{
                    .address = address,
                    .slot = self.prng.below(slots_per_address),
                    .value = value,
                } });
            }
        }
    }

    fn random_known(self: *Harness) ?Hash {
        if (self.known_len == 0) return null;
        const hash = self.known[self.prng.below(self.known_len)];
        if (self.disk.db.chain.meta(hash) == null) return null;
        return hash;
    }

    fn try_set_head(self: *Harness, hash: Hash) !void {
        const sequence = self.disk.db.set_head(hash) catch |err| switch (err) {
            error.Busy, error.ReorgTooDeep, error.UnknownBlock, error.UnknownParent => return,
            else => return err,
        };
        try self.record(sequence);
        try self.memory.set_head_retry(hash);
        self.counts.head_moves += 1;
        try self.check_equal();
    }

    /// Whether `commit_applied` of a new child of the head cannot fail after the state moved:
    /// the journal has room, and the head is the newest stored block (so the insert's
    /// evictions never take the parent).
    fn applied_path_safe(self: *Harness) bool {
        const db = &self.disk.db;
        if (!self.disk.journal_roomy()) return false;
        const count = db.chain.block_count();
        if (count < 3) return false;
        const capacity: u32 = @intCast(db.chain.slots.len);
        const newest = &db.chain.slots[(db.chain.slot_head + count - 1) % capacity];
        return std.mem.eql(u8, &newest.meta.hash, &db.head_info.hash);
    }

    /// Commits the disk overlay's block; false when it was refused (nothing changed).
    fn commit_disk(self: *Harness, input: *BlockInput) !bool {
        const db = &self.disk.db;
        if (self.prng.chance(1, 2) and self.applied_path_safe()) {
            db.hold_checkpoints(true);
            defer db.hold_checkpoints(false);
            const root = self.disk.overlay.commit(&self.changeset) catch |err| switch (err) {
                error.Busy => return false,
                error.Unsupported => return self.refused_wipe(),
                else => return err,
            };
            input.changeset = self.changeset.encode(self.changeset_buffer);
            const commit = try db.commit_applied(input);
            try testing.expectEqualSlices(u8, &root, &commit.state_root);
            try self.record(commit.sequence);
            self.counts.blocks_applied += 1;
        } else {
            const commit = db.execute_and_commit(&self.disk.overlay, input) catch |err|
                switch (err) {
                    error.Busy, error.UnknownParent => {
                        try self.stored_alone(input);
                        return false;
                    },
                    error.Unsupported => return self.refused_wipe(),
                    else => return err,
                };
            try self.record(commit.sequence);
        }
        try testing.expect(!self.wipes_storage);
        self.counts.destroyed += @intFromBool(self.destroys);
        const writes = db.disk.?.record_writes_len;
        self.counts.record_writes_max = @max(self.counts.record_writes_max, writes);
        return true;
    }

    /// A head move refused after the insert (room, admission) journals the block alone: the
    /// head stays, and the oracle stores the block too (a later `set_head` may pick it).
    fn stored_alone(self: *Harness, input: *const BlockInput) !void {
        const db = &self.disk.db;
        while (self.submitted < db.submitted_sequence) {
            self.submitted += 1;
            self.heads[self.submitted] = db.head_info;
        }
        const view = db.chain.block(input.hash) orelse return;
        var stored = input.*;
        stored.changeset = view.changeset;
        var ticks: u32 = 0;
        while (true) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            _ = self.memory.db.insert_block(&stored) catch |err| switch (err) {
                error.Busy => {
                    self.memory_sim.tick();
                    continue;
                },
                else => return err,
            };
            break;
        }
        self.remember(input.hash);
        self.counts.stored_alone += 1;
    }

    fn refused_wipe(self: *Harness) !bool {
        try testing.expect(self.wipes_storage);
        self.counts.wipes_refused += 1;
        return false;
    }

    fn new_block(self: *Harness) !void {
        if (self.prng.chance(1, 5)) {
            if (self.random_known()) |parent| try self.try_set_head(parent);
        }
        const head = self.disk.db.head_info;
        self.disk.overlay.discard();
        try self.random_ops();
        var input = self.block_input(head.hash, head.number + 1);
        const committed = try self.commit_disk(&input);
        self.disk.overlay.discard();
        if (!committed) return;
        try self.commit_memory(&input);
        self.remember(input.hash);
        self.counts.blocks += 1;
    }

    /// The same block on the oracle: the same writes, the same root.
    fn commit_memory(self: *Harness, input: *const BlockInput) !void {
        self.memory.overlay.discard();
        for (self.ops[0..self.ops_len]) |op| try apply_op(&self.memory.overlay, op);
        const commit = try self.memory.commit_retry(input);
        try testing.expectEqualSlices(u8, &self.disk.db.head_info.state_root, &commit.state_root);
        try self.check_equal();
    }

    /// The disk database reads exactly what the oracle reads at the same head.
    fn check_equal(self: *Harness) !void {
        const disk = &self.disk.db;
        const memory = &self.memory.db;
        try testing.expect(disk.phase == .ready and memory.phase == .ready);
        try testing.expectEqualSlices(u8, &memory.head_info.hash, &disk.head_info.hash);
        try testing.expectEqualSlices(u8, &memory.head_info.state_root, &disk.head_info.state_root);
        const root = try disk.state.state_root();
        try testing.expectEqualSlices(u8, &disk.head_info.state_root, &root);
        for (0..addresses_max) |index| {
            const address = address_of(index);
            const expected = memory.state.basic(address);
            const got = disk.state.basic(address);
            try testing.expectEqual(expected != null, got != null);
            if (expected) |info| try testing.expect(info.eql(got.?));
            const has_storage = memory.state.has_storage(address);
            try testing.expectEqual(has_storage, disk.state.has_storage(address));
            if (disk.state.account(address)) |entry| {
                try testing.expectEqual(has_storage, entry.storage_slots > 0);
            }
            for (0..slots_per_address) |slot| {
                const word = memory.state.storage(address, slot);
                try testing.expectEqual(word, disk.state.storage(address, slot));
            }
        }
        try testing.expect(!disk.disk.?.fault);
    }

    fn step(self: *Harness) !void {
        if (self.disk.db.phase == .failed) return error.DatabaseFailed;
        if (self.disk.db.phase == .ready and self.prng.chance(1, 4)) self.prefetch();
        const roll = self.prng.below(100);
        if (roll < 3) {
            self.disk.db.request_checkpoint();
        } else if (roll < 10) {
            if (self.random_known()) |hash| try self.try_set_head(hash);
        } else if (roll < 60) {
            try self.new_block();
        }
        if (self.disk.db.checkpoint_error) |err| return err;
        self.disk_sim.tick();
        self.memory_sim.tick();
    }

    fn run(self: *Harness, steps: u64) !void {
        for (0..steps) |_| try self.step();
    }

    /// The disk database reopened at `acknowledged` or later; the oracle follows its head.
    fn check_recovered(self: *Harness, acknowledged: u64) !void {
        const recovered = self.disk.db.submitted_sequence;
        try testing.expect(recovered >= acknowledged);
        try testing.expect(recovered <= self.submitted);
        try testing.expect(self.disk.db.head_info.eql(self.heads[recovered]));
        self.submitted = recovered;
        const head = self.disk.db.head_info.hash;
        if (!std.mem.eql(u8, &self.memory.db.head_info.hash, &head)) {
            try self.memory.set_head_retry(head);
        }
        try self.check_equal();
    }

    fn crash(self: *Harness) !void {
        self.count_trees();
        const acknowledged = self.disk.db.durable_sequence;
        self.disk_sim.crash();
        try self.disk.reopen();
        try self.check_recovered(acknowledged);
        self.counts.crashes += 1;
    }

    fn clean_reopen(self: *Harness) !void {
        try self.disk.checkpoint();
        self.count_trees();
        try self.disk.reopen();
        try self.check_recovered(self.submitted);
    }

    /// Genesis: the same accounts with storage on both.
    fn commit_genesis(self: *Harness) !void {
        self.ops_len = 0;
        for (0..4) |index| {
            const info: AccountInfo = .{ .balance = 100 + index };
            try self.add_op(.{ .account = .{ .address = address_of(index), .info = info } });
            try self.add_op(.{ .slot = .{
                .address = address_of(index),
                .slot = 1,
                .value = index + 1,
            } });
        }
        var input = self.block_input(@splat(0), 0);
        const commit = try self.disk.db.execute_and_commit(&self.disk.overlay, &input);
        try self.record(commit.sequence);
        try self.commit_memory(&input);
        self.remember(input.hash);
    }

    /// Random blocks, a clean reopen, then crashes at random ticks.
    fn exercise(self: *Harness, prng: *Prng) !void {
        try self.run(prng.range(150, 300));
        try self.clean_reopen();
        for (0..3) |_| {
            try self.run(prng.range(1, 200));
            try self.crash();
        }
    }
};

fn sims(seed: u64, prng: *Prng) !struct { SimStorage, SimStorage } {
    var disk_sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config_disk.engine.size_bytes(),
        .seed = seed,
        .latency_ticks_max = @intCast(prng.range(1, 4)),
    });
    errdefer disk_sim.deinit(testing.allocator);
    const memory_sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config_memory.engine.size_bytes(),
        .seed = seed + 1000,
    });
    return .{ disk_sim, memory_sim };
}

fn run_seed(seed: u64, counts: *Counts) !void {
    var prng = Prng.init(0xd15c_0008 + seed);
    var disk_sim, var memory_sim = try sims(seed, &prng);
    defer disk_sim.deinit(testing.allocator);
    defer memory_sim.deinit(testing.allocator);
    const harness = try Harness.create(&disk_sim, &memory_sim, prng.int(u64), counts);
    defer harness.destroy();
    try harness.format(seed);
    try harness.commit_genesis();
    try harness.exercise(&prng);
}

test "database disk mode: seeded blocks, reorgs, checkpoints, crashes match in-memory" {
    var counts: Counts = .{};
    for (0..6) |seed| {
        run_seed(seed, &counts) catch |err| {
            std.debug.print("database disk mode: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expect(counts.blocks >= 300);
    try testing.expect(counts.blocks_applied >= 20);
    try testing.expect(counts.head_moves >= 30);
    try testing.expect(counts.wipes_refused >= 3);
    try testing.expect(counts.destroyed >= 10);
    try testing.expect(counts.crashes == 18);
    // One block's branch writes exceed the flush trigger: they fit by the operation room.
    try testing.expect(counts.record_writes_max > config_disk.flat_branch_flush_entries_min);
    try testing.expect(counts.branch_flushes >= 20);
    try testing.expect(counts.admission_busy >= 1);
    try testing.expect(counts.prefetches >= 100 and counts.prefetch_reads >= 100);
}

// Imported start.

/// A random state over the address universe (most addresses, most with storage).
fn random_model(prng: *Prng, model: *disk_state_test.Model) !void {
    for (0..addresses_max) |index| {
        if (prng.chance(1, 4)) continue;
        var account: disk_state_test.ModelAccount = .{
            .address = address_of(index),
            .info = .{ .nonce = prng.below(9), .balance = prng.int(u64) },
        };
        for (0..slots_per_address) |slot| {
            if (prng.chance(1, 2)) continue;
            try account.slots.append(model.arena, .{ .slot = slot, .value = prng.int(u64) | 1 });
        }
        try model.accounts.append(model.arena, account);
    }
}

var bulk_finished: bool = false;

fn on_bulk_finished(_: *FlatTrees) void {
    bulk_finished = true;
}

fn bulk_retry(node_disk: *Node, comptime append: anytype, args: anytype) !void {
    var ticks: u32 = 0;
    while (true) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        @call(.auto, append, args) catch |err| switch (err) {
            error.Busy => {
                node_disk.sim.tick();
                node_disk.db.flat.?.bulk_poll();
                continue;
            },
            else => return err,
        };
        return;
    }
}

/// The importer's path: the four trees by bulk load.
fn bulk_load(node_disk: *Node, built: *const disk_state_test.Built) !void {
    const trees = &node_disk.db.flat.?;
    try trees.bulk_begin(testing.allocator);
    for (built.accounts.items) |*entry| {
        try bulk_retry(node_disk, FlatTrees.bulk_append_account, .{
            trees, &entry.key, &entry.account,
        });
    }
    for (built.slots.items) |*entry| {
        try bulk_retry(node_disk, FlatTrees.bulk_append_slot, .{
            trees, entry.key[0..32], entry.key[32..64], entry.word,
        });
    }
    for (built.records.accounts.items) |*record| {
        try bulk_retry(node_disk, FlatTrees.bulk_append_account_branch, .{
            trees, record.key[0..33], record.value,
        });
    }
    for (built.records.storage.items) |*record| {
        try bulk_retry(node_disk, FlatTrees.bulk_append_storage_branch, .{
            trees, record.key[0..65], record.value,
        });
    }
    bulk_finished = false;
    trees.bulk_finish(on_bulk_finished);
    var ticks: u32 = 0;
    while (!bulk_finished) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        node_disk.sim.tick();
        trees.bulk_poll();
    }
    try trees.bulk_end(testing.allocator);
}

const import_number: u64 = 1_000_000;

/// Imports the model into the disk database as head `import_number` (codes none, the 256
/// block hashes before it), and gives the oracle the same state as its first block.
fn import_start(
    harness: *Harness,
    model: *const disk_state_test.Model,
    built: *const disk_state_test.Built,
) !void {
    const disk = &harness.disk;
    try bulk_load(disk, built);
    for (0..state_module.block_hashes_max) |offset| {
        const number = import_number - offset;
        disk.db.state.set_block_hash(number, hash_of(@intCast(0x8000_0000 - offset)));
    }
    const head_hash = hash_of(0x8000_0000);
    const meta: database.BlockMeta = .{
        .hash = head_hash,
        .parent_hash = hash_of(0x7fff_ffff),
        .number = import_number,
        .timestamp = import_number * 2,
    };
    // A root the trees do not hold is refused, nothing changed.
    var wrong = built.root;
    wrong[31] ^= 1;
    try testing.expectError(error.StateCorrupt, disk.db.import_head(meta, wrong));
    try testing.expect(!disk.db.head_info.present);
    const sequence = try disk.db.import_head(meta, built.root);
    try harness.record(sequence);
    try disk.checkpoint();
    // The oracle: the whole state as one block with the same hash.
    harness.ops_len = 0;
    for (model.accounts.items) |*account| {
        try harness.add_op(.{ .account = .{ .address = account.address, .info = account.info } });
        for (account.slots.items) |slot| {
            try harness.add_op(.{ .slot = .{
                .address = account.address,
                .slot = @intCast(slot.slot),
                .value = slot.value,
            } });
        }
    }
    disk.overlay.discard();
    var input = harness.block_input(meta.parent_hash, import_number);
    input.hash = head_hash;
    input.timestamp = meta.timestamp;
    try harness.commit_memory(&input);
    try testing.expectEqualSlices(u8, &built.root, &harness.memory.db.head_info.state_root);
    harness.counts.imports += 1;
}

fn run_import(seed: u64, counts: *Counts) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = Prng.init(0x1e90_0008 + seed);
    var disk_sim, var memory_sim = try sims(seed + 100, &prng);
    defer disk_sim.deinit(testing.allocator);
    defer memory_sim.deinit(testing.allocator);
    const harness = try Harness.create(&disk_sim, &memory_sim, prng.int(u64), counts);
    defer harness.destroy();
    try harness.format(100 + seed);
    var model: disk_state_test.Model = .{ .arena = arena };
    try random_model(&prng, &model);
    const built = try disk_state_test.build_state(arena, &model);
    try import_start(harness, &model, &built);
    // Durable after its checkpoint: a crash or a clean reopen opens head N, no stored block.
    if (seed % 2 == 0) try harness.crash() else try harness.clean_reopen();
    try testing.expectEqual(@as(u32, 0), harness.disk.db.chain.block_count());
    try testing.expectEqual(import_number, harness.disk.db.head_info.number);
    for (0..state_module.block_hashes_max) |offset| {
        const number = import_number - offset;
        const hash = hash_of(@intCast(0x8000_0000 - offset));
        try testing.expectEqualSlices(u8, &hash, &harness.disk.db.state.block_hash(number).?);
    }
    try harness.exercise(&prng);
}

test "database disk mode: an imported head N with no stored block, then blocks on top" {
    var counts: Counts = .{};
    for (0..4) |seed| {
        run_import(seed, &counts) catch |err| {
            std.debug.print("database disk mode import: failing seed={d}\n", .{seed});
            return err;
        };
    }
    try testing.expectEqual(@as(u64, 4), counts.imports);
    try testing.expect(counts.blocks >= 200);
}

test "database disk mode: a checkpoint whose root record is not the head's root does not open" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var counts: Counts = .{};
    var prng = Prng.init(0xbad_0008);
    var disk_sim, var memory_sim = try sims(77, &prng);
    defer disk_sim.deinit(testing.allocator);
    defer memory_sim.deinit(testing.allocator);
    const harness = try Harness.create(&disk_sim, &memory_sim, 77, &counts);
    defer harness.destroy();
    try harness.format(77);
    var model: disk_state_test.Model = .{ .arena = arena };
    try random_model(&prng, &model);
    const built = try disk_state_test.build_state(arena, &model);
    try import_start(harness, &model, &built);
    try harness.disk.reopen();
    try harness.check_recovered(harness.submitted);
    // Flip a byte of the root record's first child reference, then checkpoint the memtable.
    const trees = &harness.disk.db.flat.?;
    const original = try arena.dupe(u8, (try trees.get_branch(null, &.{})).?);
    var record: branch_record.Record = undefined;
    try branch_record.decode(original, &record);
    try testing.expect(!branch_record.is_leaf_root(&record));
    const bad = try arena.dupe(u8, original);
    bad[1 + (record.extension_len + 1) / 2 + 4 + 1] ^= 1;
    const root_key = branch_record.path_key(&.{});
    try trees.account_branches.put(&root_key, bad);
    try harness.disk.checkpoint();
    try testing.expectError(error.CheckpointInvalid, harness.disk.reopen());
}

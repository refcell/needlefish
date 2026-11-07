//! DiskState differential (disk-state import plan step 7), on `SimStorage`.
//!
//! Each seed builds a random state (addresses and slots ground so their hashes share 1-3
//! leading nibbles: deep branches and extensions; slots from a small shared universe, so
//! storage tries of different accounts are often equal), and bulk-imports it into the four
//! flat trees through the import path: `StateRootBuilder` with a record sink streams the
//! branch records, its accounts and slots stream the leaves, and the bulk loaders write them.
//! Then random blocks: account creations, updates, destructions (every slot listed), slot
//! inserts, updates and deletes, storage-only changes, emptied storage tries; unwinds of the
//! last blocks; checkpoints with and without a reopen; crashes between blocks (the trees
//! return to the last checkpoint and the model unwinds to it). Compaction runs between
//! blocks, so reads also cross flushes and merges.
//!
//! After every block: the DiskState root equals an in-memory `StateTrie` given the same
//! changes and a fresh streaming build of the model; every account, slot, and branch record
//! key ever present or written reads back exactly as a fresh bulk build of the post-state
//! writes it (absent when the build has none), which catches stale and missing records.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const storage = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const flat_trees_module = @import("flat_trees.zig");
const branch_record = @import("branch_record.zig");
const record_test = @import("branch_record_test.zig");
const disk_state = @import("disk_state.zig");
const state_root_module = @import("../import/state_root.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const node = trie.node;
const Hash = node.Hash;
const Nibbles = trie.Nibbles;
const StateTrie = trie.StateTrie;
const Address = changeset_module.Address;
const AccountInfo = changeset_module.AccountInfo;
const Changeset = changeset_module.Changeset;
const Database = database.DatabaseType(SimStorage);
const FlatTrees = Database.FlatTrees;
const DiskState = disk_state.DiskStateType(FlatTrees);
const Account = flat_trees_module.Account;
const Derived = record_test.Derived;
const sector_size = storage.sector_size;

const block_size: u32 = 4 * sector_size;
const ticks_max = 200_000;
/// Slots an account grows to at most (a destruction lists them all in one changeset).
const account_slots_max = 40;

const config: database.Config = .{
    .engine = .{
        .journal_size_bytes = 48 * sector_size,
        .checkpoint_zone_size_bytes = 512 * block_size,
        .entry_body_size_max = 2 * sector_size,
        .checkpoint_block_size = block_size,
        .grid_block_count = 2048,
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
    .checkpoint_staging_bytes = 8 * 1024 * 1024,
    .flat_trees = true,
    .flat_flush_entries_min = 64,
    .flat_cache_blocks = 32,
    .flat_accounts_max = 512,
    .flat_slots_max = 8192,
    .flat_account_branches_max = 512,
    .flat_storage_branches_max = 8192,
    // A block's branch puts per tree must stay below this (the memtable holds twice it).
    .flat_branch_flush_entries_min = 128,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = 32,
    .storage_max = 256,
    .codes_max = 1,
    .code_bytes_max = 64,
};

const disk_config: disk_state.Config = .{
    .trie_nodes_max = 1 << 14,
    .storage_tries_max = 64,
    .memo_entries_max = 1 << 14,
    .memo_bytes_max = 4 * 1024 * 1024,
    .record_writes_max = 1024,
    .record_write_bytes_max = 1024 * branch_record.value_bytes_max,
    .changeset = changeset_config,
};

const reference_config: trie.state_trie.Config = .{
    .accounts_max = 256,
    .account_nodes_max = 1 << 13,
    .storage_nodes_max = 1 << 15,
};

const Harness = struct {
    db: Database,
    sim: *SimStorage,
    overlay: overlay_module.Overlay,
    header: [16]u8 = @splat(0x5a),

    fn create(sim: *SimStorage) !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        self.* = .{
            .db = try Database.init(testing.allocator, sim, config),
            .sim = sim,
            .overlay = undefined,
        };
        self.overlay = try overlay_module.Overlay.init(testing.allocator, &self.db.state, .{
            .accounts_max = 4,
            .slots_max = 4,
            .codes_max = 1,
        });
        return self;
    }

    fn destroy(self: *Harness) void {
        self.overlay.deinit(testing.allocator);
        self.db.deinit(testing.allocator);
        testing.allocator.destroy(self);
    }

    fn trees(self: *Harness) *FlatTrees {
        return &self.db.flat.?;
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

    fn settled(db: *const Database) bool {
        return !db.checkpoint_wanted and db.engine.checkpoint_phase == .idle and db.idle();
    }

    fn open(self: *Harness) !void {
        self.db.open();
        try self.tick_until(not_opening);
        if (self.db.open_error) |err| return err;
        try testing.expectEqual(database.Phase.ready, self.db.phase);
    }

    fn reopen(self: *Harness) !void {
        self.db.deinit(testing.allocator);
        self.db = try Database.init(testing.allocator, self.sim, config);
        self.overlay.discard();
        self.overlay.base = &self.db.state;
        try self.open();
    }

    /// A head with no state changes: a checkpoint needs one, and it writes nothing.
    fn commit_genesis(self: *Harness) !void {
        const input: database.BlockInput = .{
            .hash = @splat(0xdd),
            .parent_hash = @splat(0),
            .number = 0,
            .timestamp = 0,
            .header = &self.header,
            .body = "body",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
        _ = try self.db.execute_and_commit(&self.overlay, &input);
        try self.tick_until(idle);
    }

    fn checkpoint(self: *Harness) !void {
        try self.tick_until(idle);
        self.db.request_checkpoint();
        var ticks: u32 = 0;
        while (!settled(&self.db)) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.db.checkpoint_flush();
            self.sim.tick();
        }
        if (self.db.checkpoint_error) |err| return err;
    }
};

// The model: the state as accounts by address, the source of every changeset.

const Slot = struct { slot: u256, value: u256 };

const ModelAccount = struct {
    address: Address,
    info: AccountInfo,
    slots: std.ArrayList(Slot) = .empty,

    fn slot_index(self: *const ModelAccount, slot: u256) ?usize {
        for (self.slots.items, 0..) |entry, index| {
            if (entry.slot == slot) return index;
        }
        return null;
    }
};

const Model = struct {
    arena: std.mem.Allocator,
    accounts: std.ArrayList(ModelAccount) = .empty,

    fn find(self: *const Model, address: *const Address) ?usize {
        for (self.accounts.items, 0..) |*account, index| {
            if (std.mem.eql(u8, &account.address, address)) return index;
        }
        return null;
    }
};

const Counts = struct {
    blocks: u64 = 0,
    unwinds: u64 = 0,
    checkpoints: u64 = 0,
    reopens: u64 = 0,
    crashes: u64 = 0,
    destroyed: u64 = 0,
    storage_only: u64 = 0,
    emptied: u64 = 0,
    record_puts: u64 = 0,
    record_tombstones: u64 = 0,
    extension_puts: u64 = 0,
    leaf_root_puts: u64 = 0,
};

fn nibble_at(hash: *const Hash, index: usize) u8 {
    const byte = hash[index / 2];
    return if (index % 2 == 0) byte >> 4 else byte & 0x0f;
}

fn prefix_matches(a: *const Hash, b: *const Hash, nibbles: u64) bool {
    for (0..nibbles) |index| {
        if (nibble_at(a, index) != nibble_at(b, index)) return false;
    }
    return true;
}

fn slot_hash(slot: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return node.keccak256(&bytes);
}

/// A new address; half the time its hash shares 1-3 leading nibbles with an account's.
fn new_address(prng: *Prng, model: *const Model) Address {
    const accounts = model.accounts.items;
    var target: ?Hash = null;
    if (accounts.len > 0 and prng.chance(1, 2)) {
        target = node.keccak256(&accounts[prng.below(accounts.len)].address);
    }
    const nibbles = prng.range(1, 3);
    var address: Address = undefined;
    var tries: u32 = 0;
    while (true) : (tries += 1) {
        prng.fill(&address);
        if (model.find(&address) != null) continue;
        const goal = target orelse return address;
        if (tries >= 1 << 14) return address;
        if (prefix_matches(&node.keccak256(&address), &goal, nibbles)) return address;
    }
}

/// A slot not in `taken`: from a small universe shared by every account, or ground so its
/// hash shares 1-2 leading nibbles with a taken slot's.
fn new_slot(prng: *Prng, taken: []const u256) ?u256 {
    var tries: u32 = 0;
    const target: ?Hash = if (taken.len > 0 and prng.chance(1, 2))
        slot_hash(taken[prng.below(taken.len)])
    else
        null;
    const nibbles = prng.range(1, 2);
    while (tries < 1 << 12) : (tries += 1) {
        const slot: u256 = if (target == null) prng.below(24) else prng.int(u64);
        if (std.mem.indexOfScalar(u256, taken, slot) != null) continue;
        const goal = target orelse return slot;
        if (prefix_matches(&slot_hash(slot), &goal, nibbles)) return slot;
    }
    return null;
}

fn random_value(prng: *Prng) u256 {
    if (prng.chance(3, 4)) return prng.range(1, 255);
    return @as(u256, prng.int(u64)) << 128 | 1;
}

fn random_info(prng: *Prng) AccountInfo {
    var info: AccountInfo = .{ .nonce = prng.below(100), .balance = prng.int(u64) };
    if (prng.chance(1, 3)) prng.fill(&info.code_hash);
    return info;
}

fn slot_list(account: *const ModelAccount, out: []u256) []u256 {
    for (account.slots.items, out[0..account.slots.items.len]) |entry, *slot| slot.* = entry.slot;
    return out[0..account.slots.items.len];
}

fn random_state(prng: *Prng, model: *Model, seed: u64) !void {
    const count = if (seed % 4 == 0) prng.range(0, 2) else prng.range(4, 40);
    for (0..count) |_| {
        const address = new_address(prng, model);
        var account: ModelAccount = .{ .address = address, .info = random_info(prng) };
        var slots: u64 = prng.range(2, 16);
        if (prng.chance(1, 4)) slots = if (prng.chance(1, 3)) 0 else 1;
        var taken: [account_slots_max]u256 = undefined;
        for (0..slots) |_| {
            const slot = new_slot(prng, slot_list(&account, &taken)) orelse continue;
            try account.slots.append(model.arena, .{ .slot = slot, .value = random_value(prng) });
        }
        try model.accounts.append(model.arena, account);
    }
}

// Blocks.

fn create_account(prng: *Prng, address: Address, cs: *Changeset) !void {
    try cs.add_account(.{ .address = address, .old = null, .new = random_info(prng) });
    var taken: [8]u256 = undefined;
    var taken_len: usize = 0;
    for (0..prng.below(6)) |_| {
        const slot = new_slot(prng, taken[0..taken_len]) orelse continue;
        taken[taken_len] = slot;
        taken_len += 1;
        try cs.add_storage(.{
            .address = address,
            .slot = slot,
            .old = 0,
            .new = random_value(prng),
        });
    }
}

fn destroy_account(account: *const ModelAccount, cs: *Changeset) !void {
    try cs.add_account(.{ .address = account.address, .old = account.info, .new = null });
    for (account.slots.items) |entry| {
        try cs.add_storage(.{
            .address = account.address,
            .slot = entry.slot,
            .old = entry.value,
            .new = 0,
        });
    }
}

/// Slot changes of an existing account: updates, deletes, inserts, or emptying it.
/// Returns how many it added.
fn change_slots(prng: *Prng, account: *const ModelAccount, cs: *Changeset, counts: *Counts) !u32 {
    const slots = account.slots.items;
    if (slots.len > 0 and prng.chance(1, 10)) {
        for (slots) |entry| {
            try cs.add_storage(.{
                .address = account.address,
                .slot = entry.slot,
                .old = entry.value,
                .new = 0,
            });
        }
        counts.emptied += 1;
        return @intCast(slots.len);
    }
    var taken: [account_slots_max + 8]u256 = undefined;
    const existing_len = slots.len;
    _ = slot_list(account, &taken);
    var touched: [8]u256 = undefined;
    var touched_len: usize = 0;
    var added: u32 = 0;
    for (0..prng.below(5)) |_| {
        if (existing_len > 0 and prng.chance(1, 2)) {
            const entry = slots[prng.below(existing_len)];
            if (std.mem.indexOfScalar(u256, touched[0..touched_len], entry.slot) != null) continue;
            var value: u256 = if (prng.chance(1, 3)) 0 else random_value(prng);
            if (value == entry.value) value = 0;
            touched[touched_len] = entry.slot;
            touched_len += 1;
            try cs.add_storage(.{
                .address = account.address,
                .slot = entry.slot,
                .old = entry.value,
                .new = value,
            });
            added += 1;
            continue;
        }
        const count = existing_len + touched_len;
        if (existing_len >= account_slots_max) continue;
        @memcpy(taken[existing_len..count], touched[0..touched_len]);
        const slot = new_slot(prng, taken[0..count]) orelse continue;
        touched[touched_len] = slot;
        touched_len += 1;
        try cs.add_storage(.{
            .address = account.address,
            .slot = slot,
            .old = 0,
            .new = random_value(prng),
        });
        added += 1;
    }
    return added;
}

fn change_account(
    prng: *Prng,
    account: *const ModelAccount,
    cs: *Changeset,
    counts: *Counts,
) !void {
    const roll = prng.below(10);
    if (roll == 0) {
        counts.destroyed += 1;
        return destroy_account(account, cs);
    }
    const slots = try change_slots(prng, account, cs, counts);
    if (roll < 5 or slots == 0) {
        var info = account.info;
        info.nonce += 1;
        info.balance = prng.int(u64);
        try cs.add_account(.{ .address = account.address, .old = account.info, .new = info });
    } else {
        counts.storage_only += 1;
    }
}

fn random_block(prng: *Prng, model: *const Model, cs: *Changeset, counts: *Counts) !void {
    cs.clear();
    var touched: [6]Address = undefined;
    var touched_len: usize = 0;
    for (0..prng.range(1, touched.len)) |_| {
        const accounts = model.accounts.items;
        const address = if (accounts.len > 0 and prng.chance(3, 4))
            accounts[prng.below(accounts.len)].address
        else
            new_address(prng, model);
        var seen = false;
        for (touched[0..touched_len]) |*other| seen = seen or std.mem.eql(u8, other, &address);
        if (seen) continue;
        touched[touched_len] = address;
        touched_len += 1;
        if (model.find(&address)) |index| {
            try change_account(prng, &accounts[index], cs, counts);
        } else {
            try create_account(prng, address, cs);
        }
    }
    cs.sort();
}

fn trie_account(info: AccountInfo) trie.Account {
    return .{ .nonce = info.nonce, .balance = info.balance, .code_hash = info.code_hash };
}

/// Moves the model and the reference trie by `cs` (forward, or back to its old values).
fn apply_model(model: *Model, reference: *StateTrie, cs: *const Changeset, forward: bool) !void {
    for (cs.account_changes()) |*change| {
        const target = if (forward) change.new else change.old;
        const hash = node.keccak256(&change.address);
        const found = model.find(&change.address);
        if (target) |info| {
            if (found) |index| {
                model.accounts.items[index].info = info;
            } else {
                const created: ModelAccount = .{ .address = change.address, .info = info };
                try model.accounts.append(model.arena, created);
            }
            try reference.set_account(hash, trie_account(info));
        } else {
            try testing.expect(found != null);
            _ = model.accounts.swapRemove(found.?);
            try reference.delete_account(hash);
        }
    }
    for (cs.storage_changes()) |*change| {
        const target = if (forward) change.new else change.old;
        const index = model.find(&change.address) orelse {
            // A removed account's slots all go to zero with it.
            try testing.expectEqual(@as(u256, 0), target);
            continue;
        };
        const account = &model.accounts.items[index];
        const found = account.slot_index(change.slot);
        if (target == 0) {
            if (found) |slot_index| _ = account.slots.swapRemove(slot_index);
        } else if (found) |slot_index| {
            account.slots.items[slot_index].value = target;
        } else {
            try account.slots.append(model.arena, .{ .slot = change.slot, .value = target });
        }
        const hash = node.keccak256(&change.address);
        try reference.set_storage(hash, slot_hash(change.slot), target);
    }
}

// The fresh bulk build: what an import of the model's state writes.

const AccountEntry = struct { key: Hash, account: Account };
const SlotEntry = struct { key: [64]u8, word: u256 };

const Built = struct {
    root: Hash,
    accounts: std.ArrayList(AccountEntry) = .empty,
    slots: std.ArrayList(SlotEntry) = .empty,
    records: record_test.RecordSets = .{},
};

const RecordCollector = struct {
    arena: std.mem.Allocator,
    sets: *record_test.RecordSets,
    failed: bool = false,

    fn emit(
        context: *anyopaque,
        owner: ?*const Hash,
        hang: []const u8,
        branch: *const trie.BranchNode,
    ) void {
        const self: *RecordCollector = @ptrCast(@alignCast(context));
        self.add(owner, hang, branch) catch {
            self.failed = true;
        };
    }

    fn add(
        self: *RecordCollector,
        owner: ?*const Hash,
        hang: []const u8,
        branch: *const trie.BranchNode,
    ) !void {
        var buffer: [branch_record.value_bytes_max]u8 = undefined;
        const value = try self.arena.dupe(u8, branch_record.encode(branch, &buffer));
        const key = if (owner) |hash|
            try self.arena.dupe(u8, &branch_record.storage_key(hash, hang))
        else
            try self.arena.dupe(u8, &branch_record.path_key(hang));
        const list = if (owner == null) &self.sets.accounts else &self.sets.storage;
        try list.append(self.arena, .{ .key = key, .value = value });
    }
};

const HashedSlot = struct {
    hash: Hash,
    value: u256,

    fn less(_: void, a: HashedSlot, b: HashedSlot) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

const HashedAccount = struct {
    hash: Hash,
    info: AccountInfo,
    slots: []HashedSlot,

    fn less(_: void, a: HashedAccount, b: HashedAccount) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

fn hashed_accounts(arena: std.mem.Allocator, model: *const Model) ![]HashedAccount {
    const out = try arena.alloc(HashedAccount, model.accounts.items.len);
    for (model.accounts.items, out) |*account, *entry| {
        const slots = try arena.alloc(HashedSlot, account.slots.items.len);
        for (account.slots.items, slots) |slot, *hashed| {
            hashed.* = .{ .hash = slot_hash(slot.slot), .value = slot.value };
        }
        std.mem.sort(HashedSlot, slots, {}, HashedSlot.less);
        const hash = node.keccak256(&account.address);
        entry.* = .{ .hash = hash, .info = account.info, .slots = slots };
    }
    std.mem.sort(HashedAccount, out, {}, HashedAccount.less);
    return out;
}

/// Streams the model's state through `StateRootBuilder` with a record sink, as an import
/// does: records, account records (with storage roots), and slots, each list sorted.
fn build_state(arena: std.mem.Allocator, model: *const Model) !Built {
    const accounts = try hashed_accounts(arena, model);
    const builder = try arena.create(state_root_module.StateRootBuilder);
    builder.* = .{};
    var built: Built = .{ .root = undefined };
    var collector: RecordCollector = .{ .arena = arena, .sets = &built.records };
    const sinks = try arena.create(state_root_module.RecordSinks);
    sinks.* = .{ .target = .{ .context = &collector, .emit = RecordCollector.emit } };
    builder.set_record_sink(sinks);
    for (accounts) |*entry| {
        try builder.begin_account(&entry.hash, trie_account(entry.info));
        for (entry.slots) |*slot| {
            try builder.add_slot(&slot.hash, slot.value);
            try built.slots.append(arena, .{
                .key = flat_trees_module.storage_key_hashed(&entry.hash, &slot.hash),
                .word = slot.value,
            });
        }
        const storage_root = try builder.end_account();
        try built.accounts.append(arena, .{
            .key = entry.hash,
            .account = .{ .info = entry.info, .storage_root = storage_root },
        });
    }
    built.root = try builder.root();
    try testing.expect(!collector.failed);
    return built;
}

var bulk_finished: bool = false;

fn on_bulk_finished(_: *FlatTrees) void {
    bulk_finished = true;
}

fn bulk_retry(harness: *Harness, comptime append: anytype, args: anytype) !void {
    var ticks: u32 = 0;
    while (true) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        @call(.auto, append, args) catch |err| switch (err) {
            error.Busy => {
                harness.sim.tick();
                harness.trees().bulk_poll();
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn bulk_load(harness: *Harness, built: *const Built) !void {
    const trees = harness.trees();
    try trees.bulk_begin(testing.allocator);
    for (built.accounts.items) |*entry| {
        try bulk_retry(harness, FlatTrees.bulk_append_account, .{
            trees, &entry.key, &entry.account,
        });
    }
    for (built.slots.items) |*entry| {
        try bulk_retry(harness, FlatTrees.bulk_append_slot, .{
            trees, entry.key[0..32], entry.key[32..64], entry.word,
        });
    }
    for (built.records.accounts.items) |*record| {
        try bulk_retry(harness, FlatTrees.bulk_append_account_branch, .{
            trees, record.key[0..33], record.value,
        });
    }
    for (built.records.storage.items) |*record| {
        try bulk_retry(harness, FlatTrees.bulk_append_storage_branch, .{
            trees, record.key[0..65], record.value,
        });
    }
    bulk_finished = false;
    trees.bulk_finish(on_bulk_finished);
    var ticks: u32 = 0;
    while (!bulk_finished) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        harness.sim.tick();
        trees.bulk_poll();
    }
    try trees.bulk_end(testing.allocator);
}

// Every key ever present or written, and the check against a fresh build.

/// A record key: 0 ++ path key (zero-padded) for the account trie, 1 ++ storage key.
const RecordKey = [1 + branch_record.storage_key_bytes]u8;

fn record_key(tree_key: []const u8) RecordKey {
    var key: RecordKey = @splat(0);
    assert(tree_key.len == branch_record.path_key_bytes or
        tree_key.len == branch_record.storage_key_bytes);
    key[0] = @intFromBool(tree_key.len == branch_record.storage_key_bytes);
    @memcpy(key[1..][0..tree_key.len], tree_key);
    return key;
}

const Universe = struct {
    accounts: std.AutoHashMapUnmanaged(Hash, void) = .empty,
    slots: std.AutoHashMapUnmanaged([64]u8, void) = .empty,
    records: std.AutoHashMapUnmanaged(RecordKey, void) = .empty,

    fn add_built(self: *Universe, arena: std.mem.Allocator, built: *const Built) !void {
        for (built.accounts.items) |entry| try self.accounts.put(arena, entry.key, {});
        for (built.slots.items) |entry| try self.slots.put(arena, entry.key, {});
        for (built.records.accounts.items) |record| {
            try self.records.put(arena, record_key(record.key), {});
        }
        for (built.records.storage.items) |record| {
            try self.records.put(arena, record_key(record.key), {});
        }
    }

    /// The last `apply`'s record writes; counts their kinds.
    fn add_writes(
        self: *Universe,
        arena: std.mem.Allocator,
        disk: *const DiskState,
        counts: *Counts,
    ) !void {
        for (disk.last_record_writes()) |*write| {
            const key = if (write.owner) |*owner|
                record_key(&branch_record.storage_key(owner, write.hang.slice()))
            else
                record_key(&branch_record.path_key(write.hang.slice()));
            try self.records.put(arena, key, {});
            const value = disk.record_value(write) orelse {
                counts.record_tombstones += 1;
                continue;
            };
            counts.record_puts += 1;
            var record: branch_record.Record = undefined;
            try branch_record.decode(value, &record);
            if (record.extension_len > 0) counts.extension_puts += 1;
            if (branch_record.is_leaf_root(&record)) counts.leaf_root_puts += 1;
        }
    }
};

fn check(
    harness: *Harness,
    disk: *DiskState,
    built: *const Built,
    reference: *StateTrie,
    universe: *const Universe,
) !void {
    try testing.expect(!disk.fault);
    try testing.expectEqualSlices(u8, &built.root, &disk.root());
    try testing.expectEqualSlices(u8, &try reference.root(), &disk.root());
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var accounts: std.AutoHashMapUnmanaged(Hash, Account) = .empty;
    for (built.accounts.items) |entry| try accounts.put(arena, entry.key, entry.account);
    var it_accounts = universe.accounts.keyIterator();
    while (it_accounts.next()) |key| {
        const got = disk.account(key);
        const want = accounts.get(key.*);
        try testing.expectEqual(want == null, got == null);
        if (want) |account| try testing.expect(account.eql(got.?));
    }
    var slots: std.AutoHashMapUnmanaged([64]u8, u256) = .empty;
    for (built.slots.items) |entry| try slots.put(arena, entry.key, entry.word);
    var it_slots = universe.slots.keyIterator();
    while (it_slots.next()) |key| {
        const got = disk.storage(key[0..32], key[32..64]);
        try testing.expectEqual(slots.get(key.*) orelse 0, got);
    }
    var records: std.AutoHashMapUnmanaged(RecordKey, []const u8) = .empty;
    for (built.records.accounts.items) |record| {
        try records.put(arena, record_key(record.key), record.value);
    }
    for (built.records.storage.items) |record| {
        try records.put(arena, record_key(record.key), record.value);
    }
    var it_records = universe.records.keyIterator();
    while (it_records.next()) |key| {
        const owned = key[0] == 1;
        const path_key = if (owned) key[33..66] else key[1..34];
        const hang = try branch_record.decode_path_key(path_key);
        const owner: ?*const Hash = if (owned) key[1..33] else null;
        const got = try harness.trees().get_branch(owner, hang.slice());
        const want = records.get(key.*);
        try testing.expectEqual(want == null, got == null);
        if (want) |value| try testing.expectEqualSlices(u8, value, got.?);
    }
    try testing.expect(!disk.fault);
}

/// `disk.apply`, compacting and ticking while the memtables lack room.
fn apply_block(harness: *Harness, disk: *DiskState, cs: *const Changeset, forward: bool) !void {
    var ticks: u32 = 0;
    while (true) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        disk.apply(cs, forward) catch |err| switch (err) {
            error.Busy => {
                harness.trees().compact(64);
                harness.sim.tick();
                continue;
            },
            else => return err,
        };
        return;
    }
}

const Run = struct {
    harness: *Harness,
    arena: std.mem.Allocator,
    prng: Prng,
    model: Model,
    reference: StateTrie,
    disk: DiskState,
    universe: Universe = .{},
    changeset: Changeset,
    /// Encoded changesets of the applied blocks, oldest first (for unwinds).
    applied: std.ArrayList([]const u8) = .empty,
    checkpoint_depth: usize = 0,
    checkpoint_root: Hash,
    counts: *Counts,

    fn forward(self: *Run) !void {
        try random_block(&self.prng, &self.model, &self.changeset, self.counts);
        try apply_block(self.harness, &self.disk, &self.changeset, true);
        try self.universe.add_writes(self.arena, &self.disk, self.counts);
        try apply_model(&self.model, &self.reference, &self.changeset, true);
        const bytes = try self.arena.alloc(u8, self.changeset.encoded_length());
        try self.applied.append(self.arena, self.changeset.encode(bytes));
        self.counts.blocks += 1;
    }

    /// Unwinds the newest block: through DiskState too (`disk`), or the model only (the
    /// trees already lost it in a crash).
    fn unwind(self: *Run, disk: bool) !void {
        const bytes = self.applied.pop().?;
        try self.changeset.decode(bytes);
        if (disk) {
            try apply_block(self.harness, &self.disk, &self.changeset, false);
            try self.universe.add_writes(self.arena, &self.disk, self.counts);
            self.counts.unwinds += 1;
        }
        try apply_model(&self.model, &self.reference, &self.changeset, false);
    }

    fn checkpoint(self: *Run, reopen: bool) !void {
        try self.harness.checkpoint();
        self.checkpoint_depth = self.applied.items.len;
        self.checkpoint_root = self.disk.root();
        self.counts.checkpoints += 1;
        if (reopen) {
            try self.harness.reopen();
            self.rebind();
            self.counts.reopens += 1;
        }
    }

    /// Crash between blocks: the trees return to the last checkpoint, so does the model.
    fn crash(self: *Run) !void {
        self.harness.sim.crash();
        try self.harness.reopen();
        while (self.applied.items.len > self.checkpoint_depth) try self.unwind(false);
        self.rebind();
        self.counts.crashes += 1;
    }

    fn rebind(self: *Run) void {
        self.disk.trees = self.harness.trees();
        self.disk.set_root(self.checkpoint_root);
    }

    fn step(self: *Run) !void {
        const roll = self.prng.below(100);
        if (roll < 6) {
            try self.checkpoint(self.prng.chance(1, 2));
        } else if (roll < 10) {
            try self.crash();
        } else if (roll < 24 and self.applied.items.len > self.checkpoint_depth) {
            const depth = self.applied.items.len - self.checkpoint_depth;
            for (0..self.prng.range(1, @min(3, depth))) |_| try self.unwind(true);
        } else {
            try self.forward();
        }
        try self.finish();
    }

    fn finish(self: *Run) !void {
        // Compaction between blocks: later reads cross flushes and merges.
        self.harness.trees().compact(4);
        for (0..self.prng.below(8)) |_| self.harness.sim.tick();
        const built = try build_state(self.arena, &self.model);
        try self.universe.add_built(self.arena, &built);
        try check(self.harness, &self.disk, &built, &self.reference, &self.universe);
    }
};

/// A formatted, opened database whose trees hold the model's state by bulk import, with a
/// genesis head, checkpointed.
fn setup(harness: *Harness, arena: std.mem.Allocator, model: *const Model, seed: u64) !Built {
    harness.db.format(0xd15c_0000 + seed);
    try harness.tick_until(Harness.not_formatting);
    try harness.open();
    const built = try build_state(arena, model);
    try bulk_load(harness, &built);
    try harness.commit_genesis();
    try harness.checkpoint();
    return built;
}

fn run_seed(seed: u64, blocks: u32, counts: *Counts) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = seed,
        .latency_ticks_max = 3,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim);
    defer harness.destroy();
    var run: Run = .{
        .harness = harness,
        .arena = arena,
        .prng = Prng.init(0xd15c_57a7 + seed),
        .model = .{ .arena = arena },
        .reference = try StateTrie.init(testing.allocator, reference_config),
        .disk = undefined,
        .changeset = try Changeset.init(testing.allocator, changeset_config),
        .checkpoint_root = undefined,
        .counts = counts,
    };
    defer run.changeset.deinit(testing.allocator);
    defer run.reference.deinit(testing.allocator);
    try random_state(&run.prng, &run.model, seed);
    for (run.model.accounts.items) |*account| {
        const hash = node.keccak256(&account.address);
        try run.reference.set_account(hash, trie_account(account.info));
        for (account.slots.items) |slot| {
            try run.reference.set_storage(hash, slot_hash(slot.slot), slot.value);
        }
    }
    const built = try setup(harness, arena, &run.model, seed);
    run.checkpoint_root = built.root;
    run.disk = try DiskState.init(testing.allocator, harness.trees(), built.root, disk_config);
    defer run.disk.deinit(testing.allocator);
    try run.universe.add_built(arena, &built);
    try check(harness, &run.disk, &built, &run.reference, &run.universe);
    for (0..blocks) |index| {
        // At least one checkpoint with a reopen and one crash per seed.
        if (index == blocks / 4) {
            try run.checkpoint(true);
            try run.finish();
        }
        if (index == blocks / 2) {
            try run.crash();
            try run.finish();
        }
        try run.step();
    }
}

test "disk state: seeded blocks, unwinds, checkpoints, crashes match a fresh bulk build" {
    var counts: Counts = .{};
    for (0..8) |seed| {
        run_seed(seed, 40, &counts) catch |err| {
            std.debug.print("disk state: failing seed={d}\n", .{seed});
            return err;
        };
    }
    // The workload reaches the cases that matter.
    try testing.expect(counts.blocks >= 150);
    try testing.expect(counts.unwinds >= 20);
    try testing.expect(counts.crashes >= 8 and counts.reopens >= 8);
    try testing.expect(counts.destroyed >= 10 and counts.emptied >= 5);
    try testing.expect(counts.storage_only >= 20);
    try testing.expect(counts.record_tombstones >= 20);
    try testing.expect(counts.extension_puts >= 10);
    try testing.expect(counts.leaf_root_puts >= 10);
}

test "disk state: a record off its reference is Corrupt; an unlisted wipe is Unsupported" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 77,
        .latency_ticks_max = 3,
    });
    defer sim.deinit(testing.allocator);
    const harness = try Harness.create(&sim);
    defer harness.destroy();
    var prng = Prng.init(0xd15c_bad0);
    var model: Model = .{ .arena = arena };
    // Seed 1 makes a state of several accounts: the root record is a branch.
    try random_state(&prng, &model, 1);
    try testing.expect(model.accounts.items.len >= 4);
    const built = try setup(harness, arena, &model, 77);
    var disk = try DiskState.init(testing.allocator, harness.trees(), built.root, disk_config);
    defer disk.deinit(testing.allocator);
    var changeset = try Changeset.init(testing.allocator, changeset_config);
    defer changeset.deinit(testing.allocator);
    const trees = harness.trees();
    const root_key = branch_record.path_key(&.{});
    const original = try arena.dupe(u8, (try trees.get_branch(null, &.{})).?);
    var record: branch_record.Record = undefined;
    try branch_record.decode(original, &record);
    try testing.expect(!branch_record.is_leaf_root(&record));
    // Flip a byte of the first child reference: the branch no longer hashes to the root.
    const bad = try arena.dupe(u8, original);
    bad[1 + (record.extension_len + 1) / 2 + 4 + 1] ^= 1;
    try trees.account_branches.put(&root_key, bad);
    const account = &model.accounts.items[0];
    var info = account.info;
    info.nonce += 1;
    try changeset.add_account(.{ .address = account.address, .old = account.info, .new = info });
    try testing.expectError(error.Corrupt, disk.apply(&changeset, true));
    try testing.expectEqualSlices(u8, &built.root, &disk.root());
    try trees.account_branches.put(&root_key, original);
    // A destroyed account with storage whose slots the changeset does not list.
    for (model.accounts.items) |*wiped| {
        if (wiped.slots.items.len == 0) continue;
        changeset.clear();
        try changeset.add_account(.{ .address = wiped.address, .old = wiped.info, .new = null });
        try testing.expectError(error.Unsupported, disk.apply(&changeset, true));
        break;
    } else return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &built.root, &disk.root());
    // Restored, the update applies.
    changeset.clear();
    try changeset.add_account(.{ .address = account.address, .old = account.info, .new = info });
    try disk.apply(&changeset, true);
    try testing.expect(!std.mem.eql(u8, &built.root, &disk.root()));
    try testing.expect(disk.basic(&node.keccak256(&account.address)).?.eql(info));
}

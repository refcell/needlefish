//! World state for the node: the trie-db lane's `db.State` (flat account/storage/code
//! tables for EVM reads, mirrored into a `StateTrie` for roots and proofs) behind the evm
//! `Database` interface, plus a 256-entry block hash ring.
//!
//! `commit` folds one block's journaled evm `State` into an `Overlay`, which turns it into
//! a canonical `Changeset` and applies it. The encoded changesets of the last blocks stay
//! in a bounded byte ring, so `rollback` can unwind them: a block whose roots do not
//! match, or a reorg to a recent ancestor. The same changesets are what the durable
//! database journals.
//!
//! `put_account`/`put_storage` (genesis and tests) write the tables directly, outside any
//! block, and are not undoable.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const state_trie = @import("../trie/state_trie.zig");
const db_module = @import("../db/root.zig");

const Address = evm.primitives.Address;
const Hash = [32]u8;
const keccak256 = evm.primitives.keccak256;
const State = db_module.State;
const Overlay = db_module.Overlay;
const Changeset = db_module.Changeset;

pub const Config = struct {
    trie: state_trie.Config = .{
        .accounts_max = 1 << 16,
        .account_nodes_max = 1 << 18,
        .storage_nodes_max = 1 << 19,
    },
    /// Nonzero storage slots held in the flat table.
    storage_slots_max: u32 = 1 << 18,
    code_bytes_max: u32 = 64 << 20,
    codes_max: u32 = 1 << 14,
    /// Accounts, slots and new codes one block may change.
    block_accounts_max: u32 = 1 << 14,
    block_slots_max: u32 = 1 << 16,
    block_codes_max: u32 = 1 << 10,
    block_code_bytes_max: u32 = 4 << 20,
    /// Encoded changesets kept for rollback, by bytes and by blocks.
    undo_bytes_max: u32 = 32 << 20,
    undo_blocks_max: u32 = 1024,
};

pub const Error = db_module.overlay.Error || error{ CodeStoreFull, UndoUnavailable };

const UndoRecord = struct { offset: u32, len: u32 };

pub const StateDb = struct {
    /// Heap-pinned: owned (`init`) or borrowed from a durable database (`init_shared`).
    state: *State,
    owns_state: bool,
    overlay: Overlay,
    changeset: Changeset,
    undo_bytes: []u8,
    undo_records: []UndoRecord,
    /// Ring of the newest records: `[undo_tail, undo_tail + undo_count)`.
    undo_tail: u32 = 0,
    undo_count: u32 = 0,
    undo_write: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !StateDb {
        assert(config.codes_max > 0 and config.code_bytes_max > 0);
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = try State.init(allocator, state_config(config));
        errdefer state.deinit(allocator);
        var db = try init_shared(allocator, config, state);
        db.owns_state = true;
        return db;
    }

    /// The `db.State` layout this config describes.
    pub fn state_config(config: Config) db_module.state.Config {
        return .{
            .accounts_max = config.trie.accounts_max,
            .storage_slots_max = config.storage_slots_max,
            .codes_max = config.codes_max,
            .code_bytes_max = config.code_bytes_max,
            .account_nodes_max = config.trie.account_nodes_max,
            .storage_nodes_max = config.trie.storage_nodes_max,
        };
    }

    /// Execution over a state owned elsewhere (the durable database); `state` outlives
    /// the StateDb.
    pub fn init_shared(allocator: std.mem.Allocator, config: Config, state: *State) !StateDb {
        assert(config.undo_blocks_max > 0 and config.undo_bytes_max > 0);
        var overlay = try Overlay.init(allocator, state, .{
            .accounts_max = config.block_accounts_max,
            .slots_max = config.block_slots_max,
            .codes_max = config.block_codes_max,
        });
        errdefer overlay.deinit(allocator);
        var changeset = try Changeset.init(allocator, .{
            .accounts_max = config.block_accounts_max,
            .storage_max = config.block_slots_max,
            .codes_max = config.block_codes_max,
            .code_bytes_max = config.block_code_bytes_max,
        });
        errdefer changeset.deinit(allocator);
        const undo_bytes = try allocator.alloc(u8, config.undo_bytes_max);
        errdefer allocator.free(undo_bytes);
        const undo_records = try allocator.alloc(UndoRecord, config.undo_blocks_max);
        return .{
            .state = state,
            .owns_state = false,
            .overlay = overlay,
            .changeset = changeset,
            .undo_bytes = undo_bytes,
            .undo_records = undo_records,
        };
    }

    pub fn deinit(db: *StateDb, allocator: std.mem.Allocator) void {
        allocator.free(db.undo_records);
        allocator.free(db.undo_bytes);
        db.changeset.deinit(allocator);
        db.overlay.deinit(allocator);
        if (db.owns_state) {
            db.state.deinit(allocator);
            allocator.destroy(db.state);
        }
        db.* = undefined;
    }

    /// The evm `Database` over committed state.
    pub fn database(db: *StateDb) evm.state.Database {
        return db_module.evm_backend.database(db.state);
    }

    /// The state trie, for proofs and storage roots.
    pub fn trie(db: *StateDb) *state_trie.StateTrie {
        return &db.state.state_trie;
    }

    pub fn code(db: *const StateDb, code_hash: Hash) ?[]const u8 {
        return db.state.code_by_hash(code_hash);
    }

    pub fn get_storage(db: *const StateDb, address: Address, slot: u256) u256 {
        return db.state.storage(address, slot);
    }

    pub fn get_account(db: *const StateDb, address: Address) ?state_trie.Account {
        const info = db.state.basic(address) orelse return null;
        return .{ .nonce = info.nonce, .balance = info.balance, .code_hash = info.code_hash };
    }

    /// Records a canonical block hash for BLOCKHASH (last 256 blocks).
    pub fn set_block_hash(db: *StateDb, number: u64, hash: Hash) void {
        db.state.set_block_hash(number, hash);
    }

    /// Genesis allocation: create or replace an account, storing its code.
    pub fn put_account(
        db: *StateDb,
        address: Address,
        balance: u256,
        nonce: u64,
        bytes: []const u8,
    ) Error!void {
        const stored = db.state.insert_code(bytes) catch return error.CodeStoreFull;
        const code_hash = if (bytes.len == 0) evm.primitives.keccak_empty else stored.hash;
        const info: db_module.AccountInfo = .{
            .nonce = nonce,
            .balance = balance,
            .code_hash = code_hash,
        };
        const table = &db.state.account_table;
        if (!table.contains(address) and table.count() == db.state.config.accounts_max) {
            return error.StateFull;
        }
        table.putAssumeCapacity(address, info);
        try db.state.state_trie.set_account(keccak256(&address), .{
            .nonce = nonce,
            .balance = balance,
            .code_hash = code_hash,
        });
    }

    /// Genesis storage of an existing account.
    pub fn put_storage(db: *StateDb, address: Address, slot: u256, value: u256) Error!void {
        assert(db.state.account_table.contains(address));
        const key: db_module.state.SlotKey = .{ .address = address, .slot = slot };
        const table = &db.state.storage_table;
        if (value == 0) {
            _ = table.remove(key);
        } else {
            if (!table.contains(key) and table.count() == db.state.config.storage_slots_max) {
                return error.StateFull;
            }
            table.putAssumeCapacity(key, value);
        }
        try db.state.state_trie.set_storage(keccak256(&address), slot_key(slot), value);
    }

    pub fn root(db: *StateDb) Error!Hash {
        return db.state.state_root();
    }

    /// Applies every change cached in `state` during a block, then empties the cache.
    pub fn commit(db: *StateDb, evm_state: *evm.State) Error!void {
        assert(db.overlay.base == db.state);
        assert(db.overlay.accounts.count() == 0);
        errdefer db.overlay.discard();
        try db_module.evm_backend.commit_evm(evm_state, &db.overlay);
        _ = try db.overlay.commit(&db.changeset);
        db.undo_push();
        evm_state.accounts.clearRetainingCapacity();
        evm_state.slots.clearRetainingCapacity();
        evm_state.code_store_len = 0;
    }

    /// Saves the encoded changeset just applied; evicts the oldest records for room. A
    /// changeset larger than the ring drops all undo history.
    fn undo_push(db: *StateDb) void {
        const size = db.changeset.encoded_length();
        const capacity: u32 = @intCast(db.undo_bytes.len);
        if (size > capacity) {
            db.undo_count = 0;
            db.undo_write = 0;
            return;
        }
        const len: u32 = @intCast(size);
        if (db.undo_write + len > capacity) db.undo_write = 0;
        // FIFO eviction until no live record overlaps the target range (bounded by the
        // record count).
        while (db.undo_count > 0) {
            const full = db.undo_count == db.undo_records.len;
            if (!full and !db.undo_overlaps(db.undo_write, len)) break;
            db.undo_tail = (db.undo_tail + 1) % @as(u32, @intCast(db.undo_records.len));
            db.undo_count -= 1;
        }
        const encoded = db.changeset.encode(db.undo_bytes[db.undo_write..][0..len]);
        assert(encoded.len == len);
        const slot = (db.undo_tail + db.undo_count) % @as(u32, @intCast(db.undo_records.len));
        db.undo_records[slot] = .{ .offset = db.undo_write, .len = len };
        db.undo_count += 1;
        db.undo_write += len;
        assert(db.undo_count <= db.undo_records.len);
    }

    fn undo_overlaps(db: *const StateDb, offset: u32, len: u32) bool {
        const records: u32 = @intCast(db.undo_records.len);
        for (0..db.undo_count) |index| {
            const record = db.undo_records[(db.undo_tail + @as(u32, @intCast(index))) % records];
            if (record.offset < offset + len and offset < record.offset + record.len) return true;
        }
        return false;
    }

    /// Forgets every saved changeset (the state moved by other means, e.g. the durable
    /// database's head move).
    pub fn clear_undo(db: *StateDb) void {
        db.undo_count = 0;
        db.undo_write = 0;
        assert(db.undo_depth() == 0);
    }

    /// How many of the most recent commits `rollback` can revert.
    pub fn undo_depth(db: *const StateDb) u32 {
        return db.undo_count;
    }

    /// The changeset of the most recent commit `rollback` can revert (for the journal).
    pub fn last_changeset(db: *const StateDb) ?[]const u8 {
        if (db.undo_count == 0) return null;
        const record = db.undo_records[db.newest_index()];
        return db.undo_bytes[record.offset..][0..record.len];
    }

    fn newest_index(db: *const StateDb) u32 {
        assert(db.undo_count > 0);
        const records: u32 = @intCast(db.undo_records.len);
        return (db.undo_tail + db.undo_count - 1) % records;
    }

    /// Reverts the most recent committed block.
    pub fn rollback(db: *StateDb) Error!void {
        if (db.undo_count == 0) return error.UndoUnavailable;
        const record = db.undo_records[db.newest_index()];
        db.changeset.decode(db.undo_bytes[record.offset..][0..record.len]) catch unreachable;
        try db.state.unwind(&db.changeset);
        db.undo_count -= 1;
        db.undo_write = record.offset;
    }
};

fn slot_key(slot: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return keccak256(&bytes);
}

const testing = std.testing;

fn small_config() Config {
    return .{
        .trie = .{ .accounts_max = 64, .account_nodes_max = 512, .storage_nodes_max = 512 },
        .storage_slots_max = 256,
        .code_bytes_max = 4096,
        .codes_max = 16,
        .block_accounts_max = 64,
        .block_slots_max = 256,
        .block_codes_max = 16,
        .block_code_bytes_max = 4096,
        .undo_bytes_max = 1 << 16,
        .undo_blocks_max = 64,
    };
}

const small_limits: evm.state.Limits = .{
    .accounts_max = 64,
    .slots_max = 256,
    .transient_slots_max = 16,
    .journal_entries_max = 1024,
    .logs_max = 16,
    .log_data_bytes_max = 1024,
    .code_bytes_max = 4096,
};

fn test_address(n: u8) Address {
    var a: Address = @splat(0);
    a[19] = n;
    return a;
}

test "state_db: empty root and genesis root are order independent" {
    var a = try StateDb.init(testing.allocator, small_config());
    defer a.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &@import("../trie/node.zig").empty_root, &(try a.root()));
    var b = try StateDb.init(testing.allocator, small_config());
    defer b.deinit(testing.allocator);
    try a.put_account(test_address(1), 100, 0, &.{});
    try a.put_account(test_address(2), 5, 1, &.{ 0x60, 0x00 });
    try a.put_storage(test_address(2), 7, 9);
    try b.put_account(test_address(2), 5, 1, &.{ 0x60, 0x00 });
    try b.put_storage(test_address(2), 7, 9);
    try b.put_account(test_address(1), 100, 0, &.{});
    try testing.expectEqualSlices(u8, &(try a.root()), &(try b.root()));
    try testing.expectEqualSlices(u8, &.{ 0x60, 0x00 }, a.code(keccak256(&.{ 0x60, 0x00 })).?);
}

test "state_db: commit of evm state matches direct writes" {
    var db = try StateDb.init(testing.allocator, small_config());
    defer db.deinit(testing.allocator);
    try db.put_account(test_address(1), 1_000, 0, &.{});
    var state = try evm.State.init(testing.allocator, db.database(), small_limits);
    defer state.deinit(testing.allocator);
    state.begin_transaction();
    const from_account = try state.load(test_address(1));
    const to_account = try state.load(test_address(2));
    _ = try state.transfer(from_account, to_account, 400);
    try state.set_nonce(from_account, 1);
    try state.touch(to_account);
    const access = try state.storage_access(to_account, 3);
    try state.storage_write(to_account, access.slot, 77);
    state.finalize_transaction(.prague);
    try db.commit(&state);
    try testing.expectEqual(@as(u32, 0), state.accounts.count());

    var expected = try StateDb.init(testing.allocator, small_config());
    defer expected.deinit(testing.allocator);
    try expected.put_account(test_address(1), 600, 1, &.{});
    try expected.put_account(test_address(2), 400, 0, &.{});
    try expected.put_storage(test_address(2), 3, 77);
    try testing.expectEqualSlices(u8, &(try expected.root()), &(try db.root()));
    try testing.expectEqual(@as(u256, 77), db.get_storage(test_address(2), 3));
}

test "state_db: block hash ring" {
    var db = try StateDb.init(testing.allocator, small_config());
    defer db.deinit(testing.allocator);
    const h: Hash = @splat(0xab);
    db.set_block_hash(300, h);
    try testing.expectEqualSlices(u8, &h, &(try db.database().block_hash(300)));
    try testing.expectEqualSlices(u8, &@as(Hash, @splat(0)), &(try db.database().block_hash(44)));
}

/// Applies random balance/nonce/storage changes as one block through the evm State.
fn random_block(prng: *Prng, db: *StateDb, state: *evm.State) !void {
    state.begin_transaction();
    const changes = prng.range(1, 6);
    for (0..changes) |_| {
        const account = try state.load(test_address(@intCast(prng.below(8))));
        try state.set_balance(account, prng.below(1000) + 1);
        try state.set_nonce(account, prng.below(5));
        try state.touch(account);
        if (prng.chance(1, 2)) {
            const access = try state.storage_access(account, prng.below(4));
            try state.storage_write(account, access.slot, prng.below(3));
        }
    }
    state.finalize_transaction(.prague);
    try db.commit(state);
}

fn rollback_scenario(prng: *Prng) !void {
    var config = small_config();
    config.undo_bytes_max = 2048;
    config.undo_blocks_max = 8;
    var db = try StateDb.init(testing.allocator, config);
    defer db.deinit(testing.allocator);
    var state = try evm.State.init(testing.allocator, db.database(), small_limits);
    defer state.deinit(testing.allocator);
    var roots: [16]Hash = undefined;
    roots[0] = try db.root();
    const blocks = prng.range(1, 15);
    for (1..blocks + 1) |index| {
        try random_block(prng, &db, &state);
        roots[index] = try db.root();
    }
    var index = blocks;
    while (db.undo_depth() > 0) : (index -= 1) {
        try db.rollback();
        try testing.expectEqualSlices(u8, &roots[index - 1], &(try db.root()));
    }
    try testing.expectError(error.UndoUnavailable, db.rollback());
}

const Prng = @import("../../testing/prng.zig").Prng;

test "state_db: rollback restores previous roots" {
    var prng = Prng.init(0x5d);
    for (0..32) |_| try rollback_scenario(&prng);
}

fn fuzz_rollback(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try rollback_scenario(&prng);
}

test "state_db: fuzz rollback" {
    try testing.fuzz({}, fuzz_rollback, .{});
}

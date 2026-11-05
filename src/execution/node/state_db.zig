//! In-memory world state for the node: the evm `Database` backend over the trie lane's
//! `StateTrie`, a fixed-size code store and a 256-entry block hash ring. `commit` folds
//! one block's journaled evm `State` (dirty accounts, wiped storage, dirty slots, new
//! code) into the trie and resets the cache for the next block.
//!
//! Persistence arrives with the trie-db storage engine; until then the node keeps state
//! in memory (enough for the devnet).
//!
//! Every commit also records an undo journal (previous account and slot values) in a
//! bounded ring, so the last blocks can be rolled back: a block whose roots do not
//! match, or a reorg to a recent ancestor.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const state_trie = @import("../trie/state_trie.zig");

const Address = evm.primitives.Address;
const Hash = [32]u8;
const keccak256 = evm.primitives.keccak256;
const AccountInfo = evm.state.AccountInfo;

pub const Config = struct {
    trie: state_trie.Config = .{
        .accounts_max = 1 << 16,
        .account_nodes_max = 1 << 18,
        .storage_nodes_max = 1 << 19,
    },
    code_bytes_max: u32 = 64 << 20,
    codes_max: u32 = 1 << 14,
    undo_entries_max: u32 = 1 << 18,
};

pub const Error = state_trie.Error || error{ CodeStoreFull, UndoUnavailable };

const CodeRef = struct { offset: u32, len: u32 };

const Undo = union(enum) {
    /// First entry of every committed block.
    block,
    account: struct { key: Hash, previous: ?state_trie.Account },
    slot: struct { key: Hash, slot_hash: Hash, previous: u256 },
};
const block_hash_window = 256;

pub const StateDb = struct {
    trie: state_trie.StateTrie,
    codes: std.AutoHashMapUnmanaged(Hash, CodeRef),
    codes_max: u32,
    code_bytes: []u8,
    code_len: u32 = 0,
    block_hashes: [block_hash_window]Hash = undefined,
    block_numbers: [block_hash_window]?u64 = @splat(null),
    undo: []Undo,
    /// Monotonic ring positions: entries `[undo_tail, undo_head)` are live.
    undo_head: u64 = 0,
    undo_tail: u64 = 0,
    /// Committed blocks whose undo entries are complete and still in the ring.
    undo_blocks: u32 = 0,
    /// The block being committed lost undo entries (ring overflow or a storage wipe).
    undo_lost: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) !StateDb {
        assert(config.codes_max > 0);
        assert(config.code_bytes_max > 0);
        var trie = try state_trie.StateTrie.init(allocator, config.trie);
        errdefer trie.deinit(allocator);
        var codes: std.AutoHashMapUnmanaged(Hash, CodeRef) = .empty;
        try codes.ensureTotalCapacity(allocator, config.codes_max);
        errdefer codes.deinit(allocator);
        const code_bytes = try allocator.alloc(u8, config.code_bytes_max);
        errdefer allocator.free(code_bytes);
        assert(config.undo_entries_max > 1);
        const undo = try allocator.alloc(Undo, config.undo_entries_max);
        return .{
            .undo = undo,
            .trie = trie,
            .codes = codes,
            .codes_max = config.codes_max,
            .code_bytes = code_bytes,
        };
    }

    pub fn deinit(db: *StateDb, allocator: std.mem.Allocator) void {
        allocator.free(db.undo);
        allocator.free(db.code_bytes);
        db.codes.deinit(allocator);
        db.trie.deinit(allocator);
        db.* = undefined;
    }

    pub fn database(db: *StateDb) evm.state.Database {
        return .{ .context = db, .vtable = &vtable };
    }

    const vtable: evm.state.Database.VTable = .{
        .basic = basic,
        .code_by_hash = code_by_hash,
        .storage = storage,
        .block_hash = block_hash,
    };

    fn from(context: *anyopaque) *StateDb {
        return @ptrCast(@alignCast(context));
    }

    fn basic(context: *anyopaque, address: Address) evm.state.Error!?AccountInfo {
        const account = from(context).trie.get_account(keccak256(&address)) orelse return null;
        return .{
            .balance = account.balance,
            .nonce = account.nonce,
            .code_hash = account.code_hash,
        };
    }

    fn code_by_hash(context: *anyopaque, code_hash: Hash) evm.state.Error![]const u8 {
        return from(context).code(code_hash) orelse error.DatabaseFailure;
    }

    fn storage(context: *anyopaque, address: Address, slot: u256) evm.state.Error!u256 {
        return from(context).get_storage(address, slot);
    }

    fn block_hash(context: *anyopaque, number: u64) evm.state.Error!Hash {
        const db = from(context);
        const index = number % block_hash_window;
        if (db.block_numbers[index] != number) return @splat(0);
        return db.block_hashes[index];
    }

    pub fn code(db: *const StateDb, code_hash: Hash) ?[]const u8 {
        if (std.mem.eql(u8, &code_hash, &evm.primitives.keccak_empty)) return &.{};
        const ref = db.codes.get(code_hash) orelse return null;
        return db.code_bytes[ref.offset..][0..ref.len];
    }

    pub fn get_storage(db: *const StateDb, address: Address, slot: u256) u256 {
        return db.trie.get_storage(keccak256(&address), slot_key(slot));
    }

    pub fn get_account(db: *const StateDb, address: Address) ?state_trie.Account {
        return db.trie.get_account(keccak256(&address));
    }

    /// Records a canonical block hash for BLOCKHASH (last 256 blocks).
    pub fn set_block_hash(db: *StateDb, number: u64, hash: Hash) void {
        db.block_numbers[number % block_hash_window] = number;
        db.block_hashes[number % block_hash_window] = hash;
    }

    /// Genesis allocation: create or replace an account, storing its code.
    pub fn put_account(
        db: *StateDb,
        address: Address,
        balance: u256,
        nonce: u64,
        bytes: []const u8,
    ) Error!void {
        const code_hash = try db.store_code(bytes);
        try db.trie.set_account(keccak256(&address), .{
            .nonce = nonce,
            .balance = balance,
            .code_hash = code_hash,
        });
    }

    pub fn put_storage(db: *StateDb, address: Address, slot: u256, value: u256) Error!void {
        try db.trie.set_storage(keccak256(&address), slot_key(slot), value);
    }

    pub fn root(db: *StateDb) Error!Hash {
        return db.trie.root();
    }

    fn store_code(db: *StateDb, bytes: []const u8) Error!Hash {
        if (bytes.len == 0) return evm.primitives.keccak_empty;
        const code_hash = keccak256(bytes);
        if (db.codes.contains(code_hash)) return code_hash;
        if (db.codes.count() == db.codes_max) return error.CodeStoreFull;
        if (bytes.len > db.code_bytes.len - db.code_len) return error.CodeStoreFull;
        @memcpy(db.code_bytes[db.code_len..][0..bytes.len], bytes);
        const ref: CodeRef = .{ .offset = db.code_len, .len = @intCast(bytes.len) };
        db.codes.putAssumeCapacityNoClobber(code_hash, ref);
        db.code_len += @intCast(bytes.len);
        return code_hash;
    }

    /// Applies every change cached in `state` during a block, then empties the cache.
    pub fn commit(db: *StateDb, state: *evm.State) Error!void {
        db.undo_begin_block();
        var accounts = state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty) continue;
            const key = keccak256(&account.address);
            db.undo_push(.{ .account = .{ .key = key, .previous = db.trie.get_account(key) } });
            if (!account.in_database) {
                try db.trie.delete_account(key);
                continue;
            }
            if (account.info.has_code() and !db.codes.contains(account.info.code_hash)) {
                // New code is always cached on the account (set during this block).
                const stored = try db.store_code(account.info.code.?);
                assert(std.mem.eql(u8, &stored, &account.info.code_hash));
            }
            try db.trie.set_account(key, .{
                .nonce = account.info.nonce,
                .balance = account.info.balance,
                .code_hash = account.info.code_hash,
            });
            if (account.storage_cleared) {
                const had_storage = !std.mem.eql(u8, &db.trie.storage_root(key), &empty_root);
                if (had_storage) db.undo_lost = true;
                try db.trie.wipe_storage(key);
            }
        }
        try db.commit_slots(state);
        db.undo_end_block();
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        state.code_store_len = 0;
    }

    fn undo_begin_block(db: *StateDb) void {
        db.undo_lost = false;
        db.undo_push(.block);
    }

    fn undo_end_block(db: *StateDb) void {
        if (db.undo_lost) {
            // A block without full undo cannot be reverted, nor can anything before it.
            db.undo_tail = db.undo_head;
            db.undo_blocks = 0;
        } else {
            db.undo_blocks += 1;
        }
        assert(db.undo_head - db.undo_tail <= db.undo.len);
    }

    fn undo_push(db: *StateDb, entry: Undo) void {
        if (db.undo_lost) return;
        if (db.undo_head - db.undo_tail == db.undo.len) db.undo_evict_oldest();
        if (db.undo_lost) return;
        db.undo[db.undo_head % db.undo.len] = entry;
        db.undo_head += 1;
    }

    /// Drops the oldest committed block's entries; marks loss if only the current is left.
    fn undo_evict_oldest(db: *StateDb) void {
        if (db.undo_blocks == 0) {
            db.undo_lost = true;
            return;
        }
        assert(db.undo[db.undo_tail % db.undo.len] == .block);
        db.undo_tail += 1;
        while (db.undo[db.undo_tail % db.undo.len] != .block) db.undo_tail += 1;
        db.undo_blocks -= 1;
        assert(db.undo_tail < db.undo_head);
    }

    /// How many of the most recent commits `rollback` can revert.
    pub fn undo_depth(db: *const StateDb) u32 {
        return db.undo_blocks;
    }

    /// Reverts the most recent committed block.
    pub fn rollback(db: *StateDb) Error!void {
        if (db.undo_blocks == 0) return error.UndoUnavailable;
        assert(db.undo_head > db.undo_tail);
        while (true) {
            db.undo_head -= 1;
            switch (db.undo[db.undo_head % db.undo.len]) {
                .block => break,
                .slot => |slot| try db.trie.set_storage(slot.key, slot.slot_hash, slot.previous),
                .account => |account| if (account.previous) |previous| {
                    try db.trie.set_account(account.key, previous);
                } else {
                    try db.trie.delete_account(account.key);
                },
            }
            assert(db.undo_head > db.undo_tail);
        }
        db.undo_blocks -= 1;
    }

    fn commit_slots(db: *StateDb, state: *evm.State) Error!void {
        var slots = state.slots.iterator();
        while (slots.next()) |kv| {
            if (!kv.value_ptr.dirty) continue;
            const account = state.accounts.getPtr(kv.key_ptr.address) orelse continue;
            if (!account.in_database) continue;
            // Writes from before a storage wipe belong to a dead incarnation.
            if (kv.value_ptr.epoch != account.storage_epoch) continue;
            const key = keccak256(&kv.key_ptr.address);
            const slot_hash = slot_key(kv.key_ptr.slot);
            const previous = db.trie.get_storage(key, slot_hash);
            db.undo_push(.{ .slot = .{
                .key = key,
                .slot_hash = slot_hash,
                .previous = previous,
            } });
            try db.trie.set_storage(key, slot_hash, kv.value_ptr.present);
        }
    }
};

const empty_root = @import("../trie/node.zig").empty_root;

fn slot_key(slot: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return keccak256(&bytes);
}

const testing = std.testing;

fn small_config() Config {
    return .{
        .trie = .{ .accounts_max = 64, .account_nodes_max = 512, .storage_nodes_max = 512 },
        .code_bytes_max = 4096,
        .codes_max = 16,
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
    config.undo_entries_max = 64;
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

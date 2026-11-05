//! State provider: committed state plus a block overlay for pending execution.
//!
//! `State` holds the committed world state in flat hash tables (fast reads for the EVM) and
//! mirrors every change into a `StateTrie` for the state root. Reads follow revm's `Database`
//! shape: `basic`, `storage`, `code_by_hash`, `block_hash`.
//!
//! `Overlay` collects the writes of one pending block on top of a `State`. Reads see the
//! overlay first. `commit` turns the overlay into a canonical `Changeset` (old and new values),
//! applies it, and returns the new state root; `State.unwind` applies a changeset backward for
//! reorgs. Wiping an account's storage in the overlay is O(1): each account carries an epoch,
//! and overlay slots written under an older epoch are ignored.
//!
//! All tables are sized at init from `Config` and never grow.

const std = @import("std");
const assert = std.debug.assert;

const changeset_module = @import("changeset.zig");
const trie = @import("../trie/root.zig");
const node = trie.node;

pub const Address = changeset_module.Address;
pub const Hash = changeset_module.Hash;
pub const AccountInfo = changeset_module.AccountInfo;
pub const Changeset = changeset_module.Changeset;

pub const Config = struct {
    accounts_max: u32,
    storage_slots_max: u32,
    codes_max: u32,
    code_bytes_max: u32,
    account_nodes_max: u32,
    storage_nodes_max: u32,
};

pub const Error = error{ StateFull, CodeFull } || trie.state_trie.Error;

pub const SlotKey = struct {
    address: Address,
    slot: u256,
};

const CodeRef = struct { offset: u32, len: u32 };

const BlockHashEntry = struct { number: u64, hash: Hash, valid: bool };

/// How many recent block hashes BLOCKHASH can see.
pub const block_hashes_max = 256;

fn slot_key_hash(slot: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return node.keccak256(&bytes);
}

fn trie_account(info: AccountInfo) trie.Account {
    return .{ .nonce = info.nonce, .balance = info.balance, .code_hash = info.code_hash };
}

pub const State = struct {
    account_table: std.AutoHashMapUnmanaged(Address, AccountInfo),
    storage_table: std.AutoHashMapUnmanaged(SlotKey, u256),
    code_table: std.AutoHashMapUnmanaged(Hash, CodeRef),
    code_arena: []u8,
    code_arena_len: u32 = 0,
    block_hashes: [block_hashes_max]BlockHashEntry = @splat(.{
        .number = 0,
        .hash = @splat(0),
        .valid = false,
    }),
    state_trie: trie.StateTrie,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) !State {
        var account_table: std.AutoHashMapUnmanaged(Address, AccountInfo) = .empty;
        try account_table.ensureTotalCapacity(allocator, config.accounts_max);
        errdefer account_table.deinit(allocator);
        var storage_table: std.AutoHashMapUnmanaged(SlotKey, u256) = .empty;
        try storage_table.ensureTotalCapacity(allocator, config.storage_slots_max);
        errdefer storage_table.deinit(allocator);
        var code_table: std.AutoHashMapUnmanaged(Hash, CodeRef) = .empty;
        try code_table.ensureTotalCapacity(allocator, config.codes_max);
        errdefer code_table.deinit(allocator);
        const code_arena = try allocator.alloc(u8, config.code_bytes_max);
        errdefer allocator.free(code_arena);
        const state_trie = try trie.StateTrie.init(allocator, .{
            .accounts_max = config.accounts_max,
            .account_nodes_max = config.account_nodes_max,
            .storage_nodes_max = config.storage_nodes_max,
        });
        return .{
            .account_table = account_table,
            .storage_table = storage_table,
            .code_table = code_table,
            .code_arena = code_arena,
            .state_trie = state_trie,
            .config = config,
        };
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.state_trie.deinit(allocator);
        allocator.free(self.code_arena);
        self.code_table.deinit(allocator);
        self.storage_table.deinit(allocator);
        self.account_table.deinit(allocator);
        self.* = undefined;
    }

    pub fn basic(self: *const State, address: Address) ?AccountInfo {
        return self.account_table.get(address);
    }

    pub fn storage(self: *const State, address: Address, slot: u256) u256 {
        return self.storage_table.get(.{ .address = address, .slot = slot }) orelse 0;
    }

    pub fn code_by_hash(self: *const State, hash: Hash) ?[]const u8 {
        if (std.mem.eql(u8, &hash, &node.empty_code_hash)) return &.{};
        const code = self.code_table.get(hash) orelse return null;
        return self.code_arena[code.offset..][0..code.len];
    }

    pub fn block_hash(self: *const State, number: u64) ?Hash {
        const entry = &self.block_hashes[number % block_hashes_max];
        if (!entry.valid or entry.number != number) return null;
        return entry.hash;
    }

    pub fn set_block_hash(self: *State, number: u64, hash: Hash) void {
        self.block_hashes[number % block_hashes_max] = .{
            .number = number,
            .hash = hash,
            .valid = true,
        };
        assert(self.block_hash(number) != null);
    }

    /// Stores `code` by hash. Returns whether it was new. Code is content-addressed and
    /// immutable, so unwinding a block keeps it.
    pub fn insert_code(self: *State, code: []const u8) Error!struct { hash: Hash, new: bool } {
        const hash = node.keccak256(code);
        if (code.len == 0 or self.code_table.contains(hash)) return .{ .hash = hash, .new = false };
        if (self.code_table.count() == self.config.codes_max) return error.CodeFull;
        if (self.code_arena_len + code.len > self.code_arena.len) return error.CodeFull;
        const offset = self.code_arena_len;
        @memcpy(self.code_arena[offset..][0..code.len], code);
        self.code_arena_len += @intCast(code.len);
        self.code_table.putAssumeCapacityNoClobber(hash, .{
            .offset = offset,
            .len = @intCast(code.len),
        });
        return .{ .hash = hash, .new = true };
    }

    pub fn state_root(self: *State) Error!Hash {
        return self.state_trie.root();
    }

    /// Applies a block forward.
    pub fn apply(self: *State, changeset: *const Changeset) Error!void {
        try self.apply_direction(changeset, true);
        for (0..changeset.codes_len) |index| {
            _ = try self.insert_code(changeset.code(@intCast(index)));
        }
    }

    /// Reverts a block: applies its changeset backward.
    pub fn unwind(self: *State, changeset: *const Changeset) Error!void {
        try self.apply_direction(changeset, false);
    }

    /// Fails before any change if the tables or tries could overflow.
    fn check_capacity(self: *const State, changeset: *const Changeset) Error!void {
        const accounts = changeset.accounts_len;
        const slots = changeset.storage_len;
        if (self.account_table.count() + accounts > self.config.accounts_max) {
            return error.StateFull;
        }
        if (self.storage_table.count() + slots > self.config.storage_slots_max) {
            return error.StateFull;
        }
        const per_insert = 3;
        if (self.state_trie.accounts.free_count < per_insert * accounts) return error.StateFull;
        if (self.state_trie.storage.free_count < per_insert * slots) return error.StateFull;
    }

    /// Order matters: accounts that exist afterwards first, then storage (its account still
    /// exists in the trie), then removed accounts.
    fn apply_direction(self: *State, changeset: *const Changeset, forward: bool) Error!void {
        try self.check_capacity(changeset);
        for (changeset.account_changes()) |*change| {
            const target = if (forward) change.new else change.old;
            const info = target orelse continue;
            self.account_table.putAssumeCapacity(change.address, info);
            try self.state_trie.set_account(node.keccak256(&change.address), trie_account(info));
        }
        for (changeset.storage_changes()) |*change| {
            const target = if (forward) change.new else change.old;
            const key: SlotKey = .{ .address = change.address, .slot = change.slot };
            if (target == 0) {
                _ = self.storage_table.remove(key);
            } else {
                // Nonzero storage only lives under an account that exists at this point.
                assert(self.account_table.contains(change.address));
                self.storage_table.putAssumeCapacity(key, target);
            }
            const address_hash = node.keccak256(&change.address);
            try self.state_trie.set_storage(address_hash, slot_key_hash(change.slot), target);
        }
        for (changeset.account_changes()) |*change| {
            const target = if (forward) change.new else change.old;
            if (target != null) continue;
            _ = self.account_table.remove(change.address);
            try self.state_trie.delete_account(node.keccak256(&change.address));
        }
    }
};

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
const keccak = @import("../../common/crypto/keccak.zig");
const node = trie.node;

pub const Address = changeset_module.Address;
pub const Hash = changeset_module.Hash;
pub const AccountInfo = changeset_module.AccountInfo;
pub const Changeset = changeset_module.Changeset;
const StorageChange = changeset_module.StorageChange;

pub const Config = struct {
    accounts_max: u32,
    storage_slots_max: u32,
    codes_max: u32,
    code_bytes_max: u32,
    account_nodes_max: u32,
    storage_nodes_max: u32,
    /// Storage-rehash worker threads (`StateTrie.Config.rehash_threads`); zero for DST.
    rehash_threads: u32 = 0,
};

pub const Error = error{ StateFull, CodeFull } || trie.state_trie.Error;

pub const SlotKey = struct {
    address: Address,
    slot: u256,
};

const CodeRef = struct { offset: u32, len: u32 };

const BlockHashEntry = struct { number: u64, hash: Hash, valid: bool };

/// Slots of one account written to the trie per account lookup in `State.apply`.
const slots_chunk_max = 64;

/// How many recent block hashes BLOCKHASH can see.
pub const block_hashes_max = 256;

/// keccak256 of each key; a full chunk of `keccak.batch_width` keys of one length goes through
/// the SIMD batch (about half the cost per key on NEON), a shorter tail is hashed singly.
fn hash_keys(comptime length: usize, keys: []const [length]u8, out: []Hash) void {
    assert(keys.len == out.len);
    assert(keys.len <= keccak.batch_width);
    if (keys.len == keccak.batch_width) {
        var inputs: [keccak.batch_width][]const u8 = undefined;
        for (&inputs, keys) |*input, *key| input.* = key;
        keccak.keccak256_batch(&inputs, out[0..keccak.batch_width]);
    } else {
        for (keys, out) |*key, *hash| hash.* = node.keccak256(key);
    }
}

fn hash_addresses(changes: []const changeset_module.AccountChange, out: []Hash) void {
    assert(changes.len <= keccak.batch_width);
    var keys: [keccak.batch_width]Address = undefined;
    for (keys[0..changes.len], changes) |*key, *change| key.* = change.address;
    hash_keys(20, keys[0..changes.len], out);
}

fn hash_slots(changes: []const StorageChange, out: []Hash) void {
    assert(changes.len <= keccak.batch_width);
    var keys: [keccak.batch_width][32]u8 = undefined;
    for (keys[0..changes.len], changes) |*key, *change| {
        std.mem.writeInt(u256, key, change.slot, .big);
    }
    hash_keys(32, keys[0..changes.len], out);
}

fn trie_account(info: AccountInfo) trie.Account {
    return .{ .nonce = info.nonce, .balance = info.balance, .code_hash = info.code_hash };
}

/// A committed account and how many nonzero slots it holds in `State.storage_table`. The count
/// answers `has_storage` (EIP-7610 create collisions) with the account lookup itself, instead
/// of keccak256(address) and a `StateTrie` lookup. Every path that adds or removes a slot
/// (`apply`, `unwind`, `put_storage`, snapshot load) keeps it equal to the trie's view:
/// `storage_slots > 0` exactly when `StateTrie.has_storage(keccak256(address))`.
pub const AccountEntry = struct {
    info: AccountInfo,
    storage_slots: u32 = 0,

    comptime {
        // The count rides in the info's alignment padding: one 16-byte step at most.
        assert(@sizeOf(AccountEntry) <= @sizeOf(AccountInfo) + 16);
    }
};

pub const State = struct {
    account_table: std.AutoHashMapUnmanaged(Address, AccountEntry),
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
        var account_table: std.AutoHashMapUnmanaged(Address, AccountEntry) = .empty;
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
            .rehash_threads = config.rehash_threads,
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
        const entry = self.account_table.get(address) orelse return null;
        return entry.info;
    }

    /// The account with its storage slot count, in one table lookup.
    pub fn account(self: *const State, address: Address) ?AccountEntry {
        return self.account_table.get(address);
    }

    /// True when the account holds at least one nonzero storage slot.
    pub fn has_storage(self: *const State, address: Address) bool {
        const entry = self.account_table.get(address) orelse return false;
        assert(entry.storage_slots <= self.storage_table.count());
        return entry.storage_slots > 0;
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

    /// Writes one account directly (genesis), outside any changeset. Keeps its storage.
    pub fn put_account(self: *State, address: Address, info: AccountInfo) Error!void {
        const table = &self.account_table;
        if (!table.contains(address) and table.count() == self.config.accounts_max) {
            return error.StateFull;
        }
        const result = table.getOrPutAssumeCapacity(address);
        if (!result.found_existing) result.value_ptr.* = .{ .info = info };
        result.value_ptr.info = info;
        try self.state_trie.set_account(node.keccak256(&address), trie_account(info));
        assert(table.contains(address));
    }

    /// Writes one storage slot of an existing account directly (genesis); zero deletes it.
    pub fn put_storage(self: *State, address: Address, slot: u256, value: u256) Error!void {
        const entry = self.account_table.getPtr(address) orelse return error.UnknownAccount;
        const key: SlotKey = .{ .address = address, .slot = slot };
        if (value != 0 and !self.storage_table.contains(key) and
            self.storage_table.count() == self.config.storage_slots_max)
        {
            return error.StateFull;
        }
        self.set_slot(entry, key, value);
        var slot_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_bytes, slot, .big);
        try self.state_trie.set_storage(
            node.keccak256(&address),
            node.keccak256(&slot_bytes),
            value,
        );
    }

    /// Sets one slot in `storage_table` (zero removes it) and keeps the account's slot count.
    /// `entry` is `key.address`'s account; the table must have room for an insert.
    fn set_slot(self: *State, entry: *AccountEntry, key: SlotKey, value: u256) void {
        assert(entry.storage_slots <= self.storage_table.count());
        if (value == 0) {
            if (self.storage_table.remove(key)) {
                assert(entry.storage_slots > 0);
                entry.storage_slots -= 1;
            }
        } else {
            const result = self.storage_table.getOrPutAssumeCapacity(key);
            if (!result.found_existing) entry.storage_slots += 1;
            result.value_ptr.* = value;
        }
        assert(entry.storage_slots <= self.storage_table.count());
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
        const accounts = changeset.account_changes();
        var address_hashes: [keccak.batch_width]Hash = undefined;
        var start: usize = 0;
        while (start < accounts.len) : (start += keccak.batch_width) {
            const chunk = accounts[start..@min(accounts.len, start + keccak.batch_width)];
            hash_addresses(chunk, address_hashes[0..chunk.len]);
            for (chunk, address_hashes[0..chunk.len]) |*change, address_hash| {
                const target = if (forward) change.new else change.old;
                const info = target orelse continue;
                const result = self.account_table.getOrPutAssumeCapacity(change.address);
                if (!result.found_existing) result.value_ptr.* = .{ .info = info };
                result.value_ptr.info = info;
                try self.state_trie.set_account(address_hash, trie_account(info));
            }
        }
        try self.apply_storage(changeset.storage_changes(), forward);
        for (accounts) |*change| {
            const target = if (forward) change.new else change.old;
            if (target != null) continue;
            const removed = self.account_table.fetchRemove(change.address);
            // Removing an account drops its trie storage too; the changeset already removed
            // its slots from the table (a destroyed account's slots are all recorded).
            if (removed) |entry| assert(entry.value.storage_slots == 0);
            try self.state_trie.delete_account(node.keccak256(&change.address));
        }
    }

    /// Storage changes are sorted by address: each run of one address's slots is hashed
    /// (address once, slot keys `keccak.batch_width` at a time) and written to the trie with
    /// one account lookup per `slots_chunk_max` slots.
    fn apply_storage(self: *State, changes: []const StorageChange, forward: bool) Error!void {
        var slot_hashes: [slots_chunk_max]Hash = undefined;
        var values: [slots_chunk_max]u256 = undefined;
        var start: usize = 0;
        while (start < changes.len) {
            const address = &changes[start].address;
            var end = start + 1;
            while (end < changes.len and end - start < slots_chunk_max and
                std.mem.eql(u8, &changes[end].address, address)) end += 1;
            const run = changes[start..end];
            // Storage only changes under an account that exists at this point (removed
            // accounts go after storage); the trie rejects it otherwise.
            const entry = self.account_table.getPtr(address.*) orelse return error.UnknownAccount;
            for (run, values[0..run.len]) |*change, *value| {
                value.* = if (forward) change.new else change.old;
                assert(std.mem.eql(u8, &change.address, address));
                const key: SlotKey = .{ .address = change.address, .slot = change.slot };
                self.set_slot(entry, key, value.*);
            }
            var hashed: usize = 0;
            while (hashed < run.len) : (hashed += keccak.batch_width) {
                const chunk_end = @min(run.len, hashed + keccak.batch_width);
                hash_slots(run[hashed..chunk_end], slot_hashes[hashed..chunk_end]);
            }
            const address_hash = node.keccak256(address);
            try self.state_trie.set_storage_slots(
                address_hash,
                slot_hashes[0..run.len],
                values[0..run.len],
            );
            start = end;
        }
    }
};

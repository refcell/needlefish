//! State trie: the account trie plus one storage trie per account, with an incremental root.
//!
//! Keys are hashed (secure trie): callers pass `keccak256(address)` and `keccak256(slot)`.
//! Every storage trie shares one node pool, so memory is sized once for the whole state.
//! Writes only mark accounts dirty. `root` then rehashes the storage tries of dirty accounts,
//! re-encodes those accounts, applies them to the account trie in sorted key order (adjacent
//! paths share cached nodes and cache lines), and rehashes only the dirty paths.

const std = @import("std");
const assert = std.debug.assert;

const rlp = @import("../../common/rlp/root.zig");
const node = @import("node.zig");
const trie_module = @import("trie.zig");
const Hash = node.Hash;

/// Longest account encoding: list header, nonce, balance, storage root, code hash.
pub const account_rlp_bytes_max = 2 + 9 + 33 + 33 + 33;
const AccountTrie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 112 });
const StorageTrie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });

comptime {
    assert(account_rlp_bytes_max <= 112);
}

pub const Account = struct {
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: Hash = node.empty_code_hash,
};

pub const Config = struct {
    accounts_max: u32,
    account_nodes_max: u32,
    storage_nodes_max: u32,
    /// Accounts touched between flushes. A full list flushes early; it never fails.
    dirty_accounts_max: u32 = 4096,
};

pub const Error = error{ TrieFull, AccountsFull, UnknownAccount };

/// Writes `rlp([nonce, balance, storage_root, code_hash])` into `out`.
pub fn encode_account(account: *const Account, storage_root: *const Hash, out: []u8) []u8 {
    assert(out.len >= account_rlp_bytes_max);
    const payload = rlp.int_length(account.nonce) + rlp.int_length(account.balance) + 33 + 33;
    var encoder = rlp.Encoder.init(out);
    encoder.list_header(payload);
    encoder.int(account.nonce);
    encoder.int(account.balance);
    encoder.bytes(storage_root);
    encoder.bytes(&account.code_hash);
    assert(encoder.written().len == rlp.list_length(payload));
    return encoder.written();
}

/// Writes the storage leaf value `rlp(value)`; `value` must be nonzero.
pub fn encode_storage_value(value: u256, out: *[33]u8) []u8 {
    assert(value != 0);
    var encoder = rlp.Encoder.init(out);
    encoder.int(value);
    return encoder.written();
}

pub const StateTrie = struct {
    const Entry = struct {
        account: Account,
        storage_root: StorageTrie.NodeIndex,
        dirty: bool,
    };

    accounts: AccountTrie,
    storage: StorageTrie,
    entries: std.AutoHashMapUnmanaged(Hash, Entry),
    accounts_max: u32,
    dirty: []Hash,
    dirty_len: u32 = 0,
    /// Storage roots of dirty accounts, rehashed together so their nodes share hash batches.
    storage_roots: []StorageTrie.NodeIndex,

    pub fn init(allocator: std.mem.Allocator, config: Config) !StateTrie {
        assert(config.accounts_max > 0);
        assert(config.dirty_accounts_max > 0);
        var accounts = try AccountTrie.init(allocator, config.account_nodes_max);
        errdefer accounts.deinit(allocator);
        var storage = try StorageTrie.init(allocator, config.storage_nodes_max);
        errdefer storage.deinit(allocator);
        var entries: std.AutoHashMapUnmanaged(Hash, Entry) = .empty;
        try entries.ensureTotalCapacity(allocator, config.accounts_max);
        errdefer entries.deinit(allocator);
        const dirty = try allocator.alloc(Hash, config.dirty_accounts_max);
        errdefer allocator.free(dirty);
        const storage_roots = try allocator.alloc(StorageTrie.NodeIndex, config.dirty_accounts_max);
        return .{
            .accounts = accounts,
            .storage = storage,
            .entries = entries,
            .accounts_max = config.accounts_max,
            .dirty = dirty,
            .storage_roots = storage_roots,
        };
    }

    pub fn deinit(self: *StateTrie, allocator: std.mem.Allocator) void {
        allocator.free(self.storage_roots);
        allocator.free(self.dirty);
        self.entries.deinit(allocator);
        self.storage.deinit(allocator);
        self.accounts.deinit(allocator);
        self.* = undefined;
    }

    pub fn account_count(self: *const StateTrie) u32 {
        return self.entries.count();
    }

    pub fn get_account(self: *const StateTrie, address_hash: Hash) ?Account {
        const entry = self.entries.getPtr(address_hash) orelse return null;
        return entry.account;
    }

    /// True when the account has a non-empty storage trie (EIP-7610 create collision check).
    pub fn has_storage(self: *const StateTrie, address_hash: Hash) bool {
        const entry = self.entries.getPtr(address_hash) orelse return false;
        return entry.storage_root != StorageTrie.none;
    }

    pub fn get_storage(self: *const StateTrie, address_hash: Hash, slot_hash: Hash) u256 {
        const entry = self.entries.getPtr(address_hash) orelse return 0;
        const value = self.storage.get_in(entry.storage_root, &slot_hash) orelse return 0;
        return decode_storage_value(value);
    }

    fn decode_storage_value(value: []const u8) u256 {
        assert(value.len >= 1 and value.len <= 33);
        if (value.len == 1) {
            assert(value[0] > 0 and value[0] < 0x80);
            return value[0];
        }
        assert(value[0] == 0x80 + value.len - 1);
        var result: u256 = 0;
        for (value[1..]) |byte| result = (result << 8) | byte;
        assert(result >= 0x80);
        return result;
    }

    fn mark_dirty(self: *StateTrie, address_hash: Hash, entry: ?*Entry) Error!void {
        if (entry) |e| {
            if (e.dirty) return;
        }
        // Flushing changes only entry values, never the map layout, so `entry` stays valid.
        if (self.dirty_len == self.dirty.len) try self.flush();
        if (entry) |e| e.dirty = true;
        assert(self.dirty_len < self.dirty.len);
        self.dirty[self.dirty_len] = address_hash;
        self.dirty_len += 1;
    }

    /// Creates the account or replaces its nonce, balance, and code hash. Storage is kept.
    pub fn set_account(self: *StateTrie, address_hash: Hash, account: Account) Error!void {
        if (self.entries.getPtr(address_hash)) |entry| {
            entry.account = account;
            return self.mark_dirty(address_hash, entry);
        }
        if (self.entries.count() == self.accounts_max) return error.AccountsFull;
        const result = self.entries.getOrPutAssumeCapacity(address_hash);
        assert(!result.found_existing);
        result.value_ptr.* = .{
            .account = account,
            .storage_root = StorageTrie.none,
            .dirty = false,
        };
        return self.mark_dirty(address_hash, result.value_ptr);
    }

    /// Removes the account and all of its storage.
    pub fn delete_account(self: *StateTrie, address_hash: Hash) Error!void {
        const entry = self.entries.getPtr(address_hash) orelse return;
        self.storage.free_tree(&entry.storage_root);
        assert(self.entries.remove(address_hash));
        return self.mark_dirty(address_hash, null);
    }

    /// Sets one storage slot; zero deletes it. The account must exist.
    pub fn set_storage(
        self: *StateTrie,
        address_hash: Hash,
        slot_hash: Hash,
        value: u256,
    ) Error!void {
        return self.set_storage_slots(address_hash, &.{slot_hash}, &.{value});
    }

    /// Sets several storage slots of one account (zero deletes), with one account lookup.
    /// Same result as `set_storage` per slot, in order. The account must exist.
    pub fn set_storage_slots(
        self: *StateTrie,
        address_hash: Hash,
        slot_hashes: []const Hash,
        values: []const u256,
    ) Error!void {
        assert(slot_hashes.len == values.len);
        assert(slot_hashes.len > 0);
        const entry = self.entries.getPtr(address_hash) orelse return error.UnknownAccount;
        // Marked first: if a later slot fails with `TrieFull`, the earlier slots are already
        // written and must still be rehashed. A flush here leaves `entry` valid.
        try self.mark_dirty(address_hash, entry);
        for (slot_hashes, values) |*slot_hash, value| {
            if (value == 0) {
                _ = self.storage.delete_in(&entry.storage_root, slot_hash);
            } else {
                var buffer: [33]u8 = undefined;
                const encoded = encode_storage_value(value, &buffer);
                try self.storage.put_in(&entry.storage_root, slot_hash, encoded);
            }
        }
        assert(entry.dirty);
    }

    /// Clears every storage slot of the account (self-destruct, or re-creation).
    pub fn wipe_storage(self: *StateTrie, address_hash: Hash) Error!void {
        const entry = self.entries.getPtr(address_hash) orelse return error.UnknownAccount;
        self.storage.free_tree(&entry.storage_root);
        return self.mark_dirty(address_hash, entry);
    }

    pub fn storage_root(self: *StateTrie, address_hash: Hash) Hash {
        const entry = self.entries.getPtr(address_hash) orelse return node.empty_root;
        return self.storage.root_hash_of(entry.storage_root);
    }

    fn hash_less_than(_: void, a: Hash, b: Hash) bool {
        return std.mem.order(u8, &a, &b) == .lt;
    }

    /// Rehashes the storage tries of the sorted `dirty` accounts in one batched pass.
    fn update_storage_caches(self: *StateTrie, dirty: []const Hash) void {
        assert(dirty.len <= self.storage_roots.len);
        var count: u32 = 0;
        for (dirty, 0..) |address_hash, index| {
            if (index > 0 and std.mem.eql(u8, &dirty[index - 1], &address_hash)) continue;
            const entry = self.entries.getPtr(address_hash) orelse continue;
            if (entry.storage_root == StorageTrie.none) continue;
            self.storage_roots[count] = entry.storage_root;
            count += 1;
        }
        assert(count <= dirty.len);
        self.storage.update_caches(self.storage_roots[0..count]);
    }

    /// Applies every dirty account to the account trie without hashing the account trie.
    pub fn flush(self: *StateTrie) Error!void {
        const dirty = self.dirty[0..self.dirty_len];
        // Duplicates are equal bytes, so an unstable sort is exact.
        std.sort.pdq(Hash, dirty, {}, hash_less_than);
        self.update_storage_caches(dirty);
        for (dirty, 0..) |address_hash, index| {
            if (index > 0 and std.mem.eql(u8, &dirty[index - 1], &address_hash)) continue;
            const entry = self.entries.getPtr(address_hash) orelse {
                _ = self.accounts.delete(&address_hash);
                continue;
            };
            entry.dirty = false;
            const root_hash = self.storage.root_hash_of(entry.storage_root);
            var buffer: [account_rlp_bytes_max]u8 = undefined;
            const encoded = encode_account(&entry.account, &root_hash, &buffer);
            try self.accounts.put(&address_hash, encoded);
        }
        self.dirty_len = 0;
    }

    /// The state root after all writes so far.
    pub fn root(self: *StateTrie) Error!Hash {
        try self.flush();
        assert(self.dirty_len == 0);
        return self.accounts.root_hash();
    }

    /// Largest full encoding of one account-trie node and one storage-trie node.
    pub const account_node_bytes_max = AccountTrie.node_bytes_max;
    pub const storage_node_bytes_max = StorageTrie.node_bytes_max;

    /// One trie node reported by `visit_nodes`.
    pub const NodeVisit = struct {
        /// Null for the account trie, else the address hash owning the storage trie.
        owner: ?Hash,
        /// Nibbles from the trie root to the node.
        path: []const u8,
        encoding: []const u8,
    };

    /// Starts recording rehashed nodes in both pools (see `TrieType.track_changes`).
    pub fn track_changes(self: *StateTrie, allocator: std.mem.Allocator) !void {
        try self.accounts.track_changes(allocator);
        try self.storage.track_changes(allocator);
        assert(self.accounts.changed.len > 0 and self.storage.changed.len > 0);
    }

    /// Calls `visitor.visit(NodeVisit)` for account-trie nodes (see `TrieType.visit_nodes`)
    /// and, after each visited account leaf, for that account's storage-trie nodes. A storage
    /// trie that changed changes its account leaf, so walking only changed account nodes still
    /// reaches every changed storage node. Call `root()` first.
    pub fn visit_nodes(
        self: *StateTrie,
        mode: trie_module.VisitMode,
        visitor: anytype,
    ) !void {
        assert(self.dirty_len == 0);
        const account_root = self.accounts.root;
        assert(account_root == AccountTrie.none or self.accounts.cache[account_root].len > 0);
        const Storage = struct {
            owner: Hash,
            inner: @TypeOf(visitor),
            pub fn visit(wrapper: @This(), visit_info: trie_module.Visit) !void {
                try wrapper.inner.visit(NodeVisit{
                    .owner = wrapper.owner,
                    .path = visit_info.path,
                    .encoding = visit_info.encoding,
                });
            }
        };
        const Accounts = struct {
            state: *StateTrie,
            mode: trie_module.VisitMode,
            inner: @TypeOf(visitor),
            pub fn visit(wrapper: @This(), visit_info: trie_module.Visit) !void {
                try wrapper.inner.visit(NodeVisit{
                    .owner = null,
                    .path = visit_info.path,
                    .encoding = visit_info.encoding,
                });
                if (visit_info.leaf_key.len == 0) return;
                assert(visit_info.leaf_key.len == 64);
                var address_hash: Hash = undefined;
                for (&address_hash, 0..) |*byte, index| {
                    const high = visit_info.leaf_key[2 * index];
                    byte.* = high << 4 | visit_info.leaf_key[2 * index + 1];
                }
                // After a flush every account leaf has an entry and every entry a leaf.
                const entry = wrapper.state.entries.getPtr(address_hash) orelse unreachable;
                const storage: Storage = .{ .owner = address_hash, .inner = wrapper.inner };
                try wrapper.state.storage.visit_nodes(entry.storage_root, wrapper.mode, storage);
            }
        };
        const accounts: Accounts = .{ .state = self, .mode = mode, .inner = visitor };
        try self.accounts.visit_nodes(self.accounts.root, mode, accounts);
    }

    pub const AccountProof = AccountTrie.Proof;
    pub const StorageProof = StorageTrie.Proof;

    /// Account proof against `root()`; flushes pending writes first.
    pub fn prove_account(self: *StateTrie, address_hash: Hash, proof: *AccountProof) Error!void {
        try self.flush();
        self.accounts.prove(&address_hash, proof);
    }

    /// Storage proof against the account's storage root.
    pub fn prove_storage(
        self: *StateTrie,
        address_hash: Hash,
        slot_hash: Hash,
        proof: *StorageProof,
    ) void {
        var root_index = StorageTrie.none;
        if (self.entries.getPtr(address_hash)) |entry| root_index = entry.storage_root;
        self.storage.prove_in(root_index, &slot_hash, proof);
    }

    /// Hashed siblings along an account's path (see `TrieType.visit_siblings_in`).
    pub fn visit_account_siblings(self: *StateTrie, address_hash: Hash, visitor: anytype) !void {
        try self.flush();
        assert(self.dirty_len == 0);
        try self.accounts.visit_siblings_in(self.accounts.root, &address_hash, visitor);
    }

    /// Hashed siblings along a slot's path in the account's storage trie.
    pub fn visit_storage_siblings(
        self: *StateTrie,
        address_hash: Hash,
        slot_hash: Hash,
        visitor: anytype,
    ) !void {
        const entry = self.entries.getPtr(address_hash) orelse return;
        try self.storage.visit_siblings_in(entry.storage_root, &slot_hash, visitor);
    }
};

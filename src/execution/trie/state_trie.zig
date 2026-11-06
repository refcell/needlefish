//! State trie: the account trie plus one storage trie per account, with an incremental root.
//!
//! Keys are hashed (secure trie): callers pass `keccak256(address)` and `keccak256(slot)`.
//! Every storage trie shares one node pool, so memory is sized once for the whole state.
//! Writes only mark accounts dirty. `root` then rehashes the storage tries of dirty accounts,
//! re-encodes those accounts, applies them to the account trie in sorted key order (adjacent
//! paths share cached nodes and cache lines), and rehashes only the dirty paths.
//! With `Config.rehash_threads` > 0 the dirty storage tries are hashed on a static thread
//! pool (`rehash_pool.zig`), bit-identical to the serial path; zero (DST) stays serial.

const std = @import("std");
const assert = std.debug.assert;

const rlp = @import("../../common/rlp/root.zig");
const node = @import("node.zig");
const trie_module = @import("trie.zig");
const rehash_pool = @import("rehash_pool.zig");
const Hash = node.Hash;

/// Longest account encoding: list header, nonce, balance, storage root, code hash.
pub const account_rlp_bytes_max = 2 + 9 + 33 + 33 + 33;
const AccountTrie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 112 });
const StorageTrie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });
const RehashPool = rehash_pool.RehashPool;

/// Upper bound on `Config.rehash_threads`.
pub const rehash_threads_max = rehash_pool.threads_max;
/// Chunks per thread (caller included) in a parallel rehash: enough that a late or slow
/// thread takes fewer, few enough that each chunk still fills hash batches.
const rehash_chunks_per_thread = 4;
/// Flushes with fewer dirty storage nodes rehash on the calling thread: waking the workers
/// costs more than it saves. Results do not depend on it.
pub const rehash_parallel_nodes_min_default = 1024;

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
    /// Worker threads that rehash dirty storage tries in `flush`, besides the caller. Zero
    /// (DST, the simulator) keeps everything on the calling thread. Roots are identical for
    /// any count.
    rehash_threads: u32 = 0,
    /// Fewer dirty storage nodes than this rehash serially even with workers (tests set 0).
    rehash_parallel_nodes_min: u32 = rehash_parallel_nodes_min_default,
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
    /// End offset of each storage root's dirty nodes in `storage.order` (parallel rehash).
    storage_root_ends: []u32,
    /// Workers for the parallel storage rehash; null when `rehash_threads` is zero.
    rehash_pool: ?*RehashPool,
    rehash_parallel_nodes_min: u32,
    /// Bulk load: storage tries built but not hashed yet (their roots in `storage_roots`).
    bulk_roots_len: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !StateTrie {
        assert(config.accounts_max > 0);
        assert(config.dirty_accounts_max > 0);
        assert(config.rehash_threads <= rehash_threads_max);
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
        errdefer allocator.free(storage_roots);
        const storage_root_ends = try allocator.alloc(u32, config.dirty_accounts_max);
        errdefer allocator.free(storage_root_ends);
        var pool: ?*RehashPool = null;
        if (config.rehash_threads > 0) {
            const created = try allocator.create(RehashPool);
            errdefer allocator.destroy(created);
            try created.init(config.rehash_threads);
            pool = created;
        }
        return .{
            .accounts = accounts,
            .storage = storage,
            .entries = entries,
            .accounts_max = config.accounts_max,
            .dirty = dirty,
            .storage_roots = storage_roots,
            .storage_root_ends = storage_root_ends,
            .rehash_pool = pool,
            .rehash_parallel_nodes_min = config.rehash_parallel_nodes_min,
        };
    }

    pub fn deinit(self: *StateTrie, allocator: std.mem.Allocator) void {
        if (self.rehash_pool) |pool| {
            pool.deinit();
            allocator.destroy(pool);
        }
        allocator.free(self.storage_root_ends);
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
        self.hash_storage_roots(self.storage_roots[0..count]);
    }

    /// Rehashes the storage tries `roots` together, on the pool when there is one.
    fn hash_storage_roots(self: *StateTrie, roots: []const StorageTrie.NodeIndex) void {
        assert(roots.len <= self.storage_roots.len);
        if (self.rehash_pool) |pool| {
            self.update_storage_caches_parallel(pool, roots);
        } else {
            self.storage.update_caches(roots);
        }
        for (roots) |index| assert(self.storage.cache[index].len > 0);
    }

    /// Collects the dirty storage nodes once, splits them at trie boundaries into chunks of
    /// about equal node count, and hashes the chunks on the pool.
    fn update_storage_caches_parallel(
        self: *StateTrie,
        pool: *RehashPool,
        roots: []const StorageTrie.NodeIndex,
    ) void {
        assert(roots.len <= self.storage_root_ends.len);
        const ends = self.storage_root_ends[0..roots.len];
        const total = self.storage.collect_dirty_split(roots, ends);
        const order = self.storage.order[0..total];
        if (total == 0 or total < self.rehash_parallel_nodes_min) {
            if (total > 0) self.storage.hash_collected(order);
            return;
        }
        var ranges: [rehash_pool.chunks_max][]u64 = undefined;
        const chunks = (pool.thread_count + 1) * rehash_chunks_per_thread;
        const parts = @min(chunks, rehash_pool.chunks_max);
        split_ranges(order, ends, ranges[0..parts]);
        pool.run(&self.storage, ranges[0..parts]);
    }

    /// Splits `order` into `ranges.len` contiguous ranges of about `order.len / ranges.len`
    /// nodes each, cut only at the trie boundaries `ends` (sorted end offsets).
    fn split_ranges(order: []u64, ends: []const u32, ranges: [][]u64) void {
        assert(ranges.len > 0);
        assert(ends.len == 0 or ends[ends.len - 1] == order.len);
        const total: u64 = order.len;
        var root_index: usize = 0;
        var start: u32 = 0;
        for (ranges, 0..) |*range, part| {
            var end: u32 = @intCast(order.len);
            if (part + 1 < ranges.len) {
                const target = total * (part + 1) / ranges.len;
                while (root_index < ends.len and ends[root_index] < target) root_index += 1;
                end = if (root_index < ends.len) ends[root_index] else end;
                end = @max(end, start);
            }
            range.* = order[start..end];
            start = end;
        }
        assert(start == order.len);
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

    /// Removes every account and slot; pools and buffers are kept.
    pub fn clear(self: *StateTrie) void {
        self.accounts.clear();
        self.storage.clear();
        self.entries.clearRetainingCapacity();
        self.dirty_len = 0;
        self.bulk_roots_len = 0;
        assert(self.accounts.root == AccountTrie.none and self.entries.count() == 0);
    }

    // Bulk load (`db.State.build_trie`): `bulk_add_account` every account of an empty trie,
    // `bulk_storage` each account's sorted slots, then `bulk_finish` with the sorted address
    // hashes. Each trie is built from sorted keys (`TrieType.build_sorted`); nothing goes
    // through the dirty list. The result equals `set_account` / `set_storage` of every entry.

    /// An account added by `bulk_add_account`, as `bulk_finish` takes them. The entry
    /// pointer stays valid through the bulk load: the entries map never grows (its capacity
    /// is reserved at init) and nothing is removed.
    pub const BulkAccount = extern struct {
        address_hash: Hash,
        entry: *Entry,
    };

    /// Adds an account to a trie under bulk load without marking it dirty.
    pub fn bulk_add_account(
        self: *StateTrie,
        address_hash: Hash,
        account: Account,
    ) Error!BulkAccount {
        assert(self.accounts.root == AccountTrie.none);
        assert(self.dirty_len == 0);
        if (self.entries.count() == self.accounts_max) return error.AccountsFull;
        const result = self.entries.getOrPutAssumeCapacity(address_hash);
        assert(!result.found_existing);
        result.value_ptr.* = .{
            .account = account,
            .storage_root = StorageTrie.none,
            .dirty = false,
        };
        return .{ .address_hash = address_hash, .entry = result.value_ptr };
    }

    /// Builds the storage trie of a `bulk_add_account` account from `count` sorted slots:
    /// `source.key(i)` is the slot hash, `source.value(i, buffer)` its `encode_storage_value`.
    /// Built tries are hashed `storage_roots.len` at a time (on the rehash pool if any).
    pub fn bulk_storage(
        self: *StateTrie,
        address_hash: Hash,
        source: anytype,
        count: u32,
    ) Error!void {
        assert(self.accounts.root == AccountTrie.none);
        assert(count > 0);
        const entry = self.entries.getPtr(address_hash) orelse return error.UnknownAccount;
        assert(entry.storage_root == StorageTrie.none);
        try self.storage.build_sorted(&entry.storage_root, source, count);
        assert(entry.storage_root != StorageTrie.none);
        if (self.bulk_roots_len == self.storage_roots.len) self.bulk_hash_storage();
        self.storage_roots[self.bulk_roots_len] = entry.storage_root;
        self.bulk_roots_len += 1;
    }

    fn bulk_hash_storage(self: *StateTrie) void {
        assert(self.bulk_roots_len <= self.storage_roots.len);
        self.hash_storage_roots(self.storage_roots[0..self.bulk_roots_len]);
        self.bulk_roots_len = 0;
    }

    /// Hashes the remaining storage tries and builds the account trie from every added
    /// account (`accounts`, exactly those `bulk_add_account` returned, sorted by hash).
    pub fn bulk_finish(self: *StateTrie, accounts: []align(1) const BulkAccount) Error!void {
        assert(self.accounts.root == AccountTrie.none);
        assert(accounts.len == self.entries.count());
        self.bulk_hash_storage();
        const BulkAccounts = struct {
            state: *StateTrie,
            accounts: []align(1) const BulkAccount,

            pub fn key(bulk: *const @This(), index: u32) *const Hash {
                return &bulk.accounts[index].address_hash;
            }

            pub fn value(bulk: *const @This(), index: u32, buffer: []u8) []const u8 {
                const entry = bulk.accounts[index].entry;
                const root_hash = bulk.state.storage.root_hash_of(entry.storage_root);
                return encode_account(&entry.account, &root_hash, buffer);
            }
        };
        const source: BulkAccounts = .{ .state = self, .accounts = accounts };
        const count: u32 = @intCast(accounts.len);
        try self.accounts.build_sorted(&self.accounts.root, &source, count);
        assert(self.dirty_len == 0 and self.bulk_roots_len == 0);
        if (self.rehash_pool) |pool| {
            if (count > 0) self.bulk_hash_accounts(pool);
        }
    }

    /// After a bulk build every account-trie node is dirty: hashes the subtries two levels
    /// down on the pool (chunks of whole subtries, as for storage tries), then the top
    /// levels on the caller. Bit-identical to `root` hashing it all serially.
    fn bulk_hash_accounts(self: *StateTrie, pool: *RehashPool) void {
        assert(self.accounts.root != AccountTrie.none);
        var subtries: [AccountTrie.subtries_max]AccountTrie.NodeIndex = undefined;
        const count = self.accounts.subtries(self.accounts.root, &subtries);
        if (count > self.storage_root_ends.len) return; // Too few ends: `root` hashes it.
        const ends = self.storage_root_ends[0..count];
        const total = self.accounts.collect_dirty_split(subtries[0..count], ends);
        const order = self.accounts.order[0..total];
        if (total < self.rehash_parallel_nodes_min) {
            if (total > 0) self.accounts.hash_collected(order);
        } else {
            var ranges: [rehash_pool.chunks_max][]u64 = undefined;
            const chunks = (pool.thread_count + 1) * rehash_chunks_per_thread;
            const parts = @min(chunks, rehash_pool.chunks_max);
            split_ranges(order, ends, ranges[0..parts]);
            pool.run(&self.accounts, ranges[0..parts]);
        }
        for (subtries[0..count]) |index| assert(self.accounts.cache[index].len > 0);
        _ = self.accounts.root_hash();
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
        /// The node's reference in its parent (hash, or the encoding when short).
        reference: []const u8,
        kind: trie_module.VisitKind,
        /// Branch: one bit per non-empty child slot; 0 otherwise.
        branch_mask: u16,
    };

    /// Starts recording rehashed nodes in both pools (see `TrieType.track_changes`).
    pub fn track_changes(self: *StateTrie, allocator: std.mem.Allocator) !void {
        try self.accounts.track_changes(allocator);
        try self.storage.track_changes(allocator);
        assert(self.accounts.changed.len > 0 and self.storage.changed.len > 0);
    }

    /// Clears the change marks of both pools (see `TrieType.clear_changes`).
    pub fn clear_changes(self: *StateTrie) void {
        assert(self.dirty_len == 0);
        self.accounts.clear_changes();
        self.storage.clear_changes();
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
                    .reference = visit_info.reference,
                    .kind = visit_info.kind,
                    .branch_mask = visit_info.branch_mask,
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
                    .reference = visit_info.reference,
                    .kind = visit_info.kind,
                    .branch_mask = visit_info.branch_mask,
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

    /// The account trie nodes of many keys in one walk (`TrieType.visit_paths_in`).
    pub fn visit_account_paths(
        self: *StateTrie,
        targets: []const trie_module.PathTarget,
        visitor: anytype,
    ) !void {
        try self.flush();
        assert(self.dirty_len == 0);
        try self.accounts.visit_paths_in(self.accounts.root, targets, visitor);
    }

    /// The nodes of many slots of the account's storage trie in one walk; nothing when the
    /// account has no storage (as `prove_storage`).
    pub fn visit_storage_paths(
        self: *StateTrie,
        address_hash: Hash,
        targets: []const trie_module.PathTarget,
        visitor: anytype,
    ) !void {
        const entry = self.entries.getPtr(address_hash) orelse return;
        try self.storage.visit_paths_in(entry.storage_root, targets, visitor);
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

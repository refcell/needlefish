//! Disk state: the state root and the flat trees kept up to date block by block over a full
//! state on disk (disk-state import plan, Q4 and step 7). The four flat trees (`flat_trees.zig`)
//! hold every account record (with its storage root), every slot, and every branch record
//! (`branch_record.zig`) of the account trie and of each storage trie, exactly as a bulk import
//! writes them; nothing of the state lives in RAM between blocks except the root.
//!
//! Per block (`apply`, forward or unwind): a `SparseState` starts from the current root and
//! applies the changeset (a destroyed account's storage slot by slot, so its records are seen).
//! Nodes it needs resolve through a `Fallback` backed by a per-block locator memo: hash -> how
//! to rebuild its preimage, either a branch record at (owner, hang) via `get_branch` or a leaf
//! at (owner, key, depth) from `get_account`/`get_slot`. Resolving a record registers its
//! children and the branch below its extension; resolving an account leaf registers its storage
//! root. Every synthesized preimage must hash to the hash asked for (else `error.Corrupt`).
//!
//! Write-back: the root computation streams every node it hashes into the memo too (the
//! sparse `Sink`), so both the pre-state and the post-state trie can be read by reference. A
//! walk descends both tries together, nibble by nibble, wherever their references differ
//! (equal references at equal positions are equal subtries and are skipped). At each position
//! a record hangs in the post-state it is written; where one hung only in the pre-state, a
//! tombstone. Positions come from the walk, never from the memo, so equal subtries under two
//! owners (or two paths) share memo entries without confusing their records; leaf keys are the
//! walk's path plus the leaf's own suffix. Then accounts (new info and storage root, including
//! accounts whose only change is storage; a removed account is a tombstone) and slots (zero is
//! a tombstone) are written. Every read happens before the first write, and nothing is written
//! unless every put fits the memtables (`error.Busy`: compact and retry).
//!
//! Reads for the evm path (`basic`, `account`, `storage`) are synchronous point lookups. A read
//! error sets a sticky `fault`: reads then return absent / zero and `apply` fails with
//! `error.Corrupt`, so no block commits over a state that could not be read.
//!
//! Modes (`mode`): live puts keep the trees' replay reserves free (`Tree.put`); during journal
//! replay after open (no compaction yet) puts may use them (`Tree.put_replay`). Either way
//! nothing is written unless every put of the block fits.
//!
//! Wipes: a destroyed account whose storage is not spelled out slot by slot in the changeset is
//! `error.Unsupported` (post-Cancun only an account created in the same block can be destroyed,
//! and its storage is in the changeset).

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const witness = @import("witness.zig");
const changeset_module = @import("changeset.zig");
const flat_trees_module = @import("flat_trees.zig");
const branch_record = @import("branch_record.zig");
const record_cache_module = @import("record_cache.zig");

const node = trie.node;
const sparse = trie.sparse;
const state_trie = trie.state_trie;
const Nibbles = trie.Nibbles;
const RlpNode = node.RlpNode;
const Hash = node.Hash;
const Record = branch_record.Record;
const Changeset = changeset_module.Changeset;
const AccountInfo = changeset_module.AccountInfo;
const Address = changeset_module.Address;
const SparseState = witness.SparseState;
const AccountState = @import("history.zig").AccountState;
const RecordCache = record_cache_module.RecordCache;

/// Record cache entries when a config names none (~4.6 MiB).
pub const record_cache_entries_default: u32 = 4096;

pub const Account = flat_trees_module.Account;

pub const Error = error{
    /// A read failed, a record or leaf is missing or does not hash to its reference.
    Corrupt,
    /// A per-block bound (sparse pool, memo, record writes) is too small for this block.
    Full,
    /// The memtables lack room for this block's puts: compact and retry.
    Busy,
    /// A destroyed account with storage not listed slot by slot.
    Unsupported,
};

pub const Config = struct {
    /// Sparse trie pool shared by the account trie and every storage trie of one block.
    trie_nodes_max: u32,
    /// Storage tries one block opens.
    storage_tries_max: u32,
    /// Locator memo entries and preimage bytes per block.
    memo_entries_max: u32,
    memo_bytes_max: u32,
    /// Branch record puts and tombstones per block, and their value bytes.
    record_writes_max: u32,
    record_write_bytes_max: u32,
    /// Capacity of the scratch changeset an unwind applies (the stored changeset reversed).
    changeset: changeset_module.Config,
    /// Records kept across blocks by top-node hash and hang (`record_cache.zig`), ~1.1 KiB
    /// each: a block's walk takes the top of every trie it touches from here.
    record_cache_entries: u32 = record_cache_entries_default,
    /// Account records and slots one block reads at most through the read memo (more read
    /// the trees every time).
    read_memo_accounts_max: u32 = 4096,
    read_memo_slots_max: u32 = 16 * 1024,
};

/// How to rebuild a node's preimage. Content-addressed: equal hashes have equal preimages,
/// so any one locator of a hash serves every place it occurs.
const Locator = union(enum) {
    /// Known only by its bytes: hashed by the root computation, or synthesized with the
    /// extension above it.
    bytes_only,
    /// The top node (extension, else branch; or a leaf-root record's leaf) of a record.
    record: struct { owner: ?Hash, hang: Nibbles },
    /// A leaf `depth` nibbles down: its path is `key`'s nibbles from `depth` on.
    leaf: struct { owner: ?Hash, key: Hash, depth: u8 },
};

const Entry = struct {
    locator: Locator,
    bytes_start: u32 = 0,
    /// 0: not built yet.
    bytes_len: u32 = 0,
};

/// One side of the walk at a position: the node there (`ref`, length 0 for none), the nibbles
/// of its path already behind the position, and whether it hangs off a branch (or is a root)
/// rather than sitting below an extension.
const Cursor = struct {
    ref: RlpNode = .{},
    offset: u8 = 0,
    hangs: bool = false,

    fn is_none(self: *const Cursor) bool {
        return self.ref.len == 0;
    }

    fn eql(a: *const Cursor, b: *const Cursor) bool {
        if (a.ref.len != b.ref.len or a.offset != b.offset or a.hangs != b.hangs) return false;
        return std.mem.eql(u8, a.ref.bytes[0..a.ref.len], b.ref.bytes[0..b.ref.len]);
    }

    fn root(hash: *const Hash) Cursor {
        if (std.mem.eql(u8, hash, &node.empty_root)) return .{};
        return .{ .ref = RlpNode.from_hash(hash.*), .hangs = true };
    }
};

/// Reads a monotonic clock for `Stats` phase times (the caller's, through its IO).
pub const Clock = struct {
    context: *anyopaque,
    now_ns: *const fn (context: *anyopaque) u64,
};

/// Counters since init (and, under a `Clock`, summed phase times of successful applies).
pub const Stats = struct {
    /// Successful `apply` calls.
    blocks: u64 = 0,
    /// Branch records resolved by hash, how many of them read the branch trees, and how
    /// many the record cache answered.
    records_resolved: u64 = 0,
    record_reads: u64 = 0,
    record_cache_hits: u64 = 0,
    /// Leaves resolved by hash (each reads the account or storage tree).
    leaves_resolved: u64 = 0,
    /// Account and slot point reads of the trees (evm reads, leaves, pre-state roots), and
    /// reads the read memo answered instead.
    account_reads: u64 = 0,
    slot_reads: u64 = 0,
    read_memo_hits: u64 = 0,
    /// Branch-record puts and tombstones written.
    record_writes: u64 = 0,
    /// Sparse trie updates with node resolution, the root hash, the record diff and
    /// account collection, and the puts.
    update_ns: u64 = 0,
    root_ns: u64 = 0,
    diff_ns: u64 = 0,
    write_ns: u64 = 0,
};

const Frame = struct { depth: u8, nibble: u8, pre: Cursor, post: Cursor };
/// The walk is depth-first: at most sixteen pending siblings per level.
const frames_max = 64 * 16 + 1;

/// A branch-record put (`value_len > 0`) or tombstone, keyed as its tree keys it.
pub const RecordWrite = struct {
    /// Storage trie owner; null for the account trie.
    owner: ?Hash,
    hang: Nibbles,
    value_start: u32,
    value_len: u32,
};

const AccountWrite = struct {
    key: Hash,
    value: ?[flat_trees_module.account_value_size]u8,
};

/// Largest leaf encoding: a 64-nibble path (33-byte hex prefix) and an account value.
const leaf_bytes_max = 3 + 34 + 2 + state_trie.account_rlp_bytes_max;

comptime {
    assert(leaf_bytes_max <= 3 + 34 + 2 + sparse.value_bytes_max);
    assert(frames_max == 1025);
}

pub fn DiskStateType(comptime FlatTrees: type) type {
    return struct {
        const Self = @This();

        trees: *FlatTrees,
        config: Config,
        state_root: Hash,
        sparse_state: SparseState,
        /// Verified records across blocks (content-addressed: never stale).
        record_cache: RecordCache,
        memo: std.AutoHashMapUnmanaged(Hash, Entry) = .empty,
        /// The account records and slots read since the last write-back (or `set_root`),
        /// as the trees hold them: every tree write goes through `apply`, which clears it.
        read_accounts: std.AutoHashMapUnmanaged(Hash, ?Account) = .empty,
        read_slots: std.AutoHashMapUnmanaged([flat_trees_module.storage_key_size]u8, u256) =
            .empty,
        memo_bytes: []u8,
        memo_bytes_len: u32 = 0,
        frames: []Frame,
        /// This block's branch-record writes (valid until the next `apply`).
        record_writes: []RecordWrite,
        record_writes_len: u32 = 0,
        record_bytes: []u8,
        record_bytes_len: u32 = 0,
        swapped: Changeset,
        /// This block's account records (a null value removes the account).
        account_writes: []AccountWrite,
        account_writes_len: u32 = 0,
        /// Live puts, or journal replay puts (`FlatTrees.Mode`).
        mode: FlatTrees.Mode = .live,
        /// Sticky: a tree read failed.
        fault: bool = false,
        /// This block: a preimage could not be built or did not hash to its reference.
        corrupt: bool = false,
        /// This block: the memo ran out of entries or bytes.
        memo_full: bool = false,
        stats: Stats = .{},
        /// Times `apply`'s phases into `stats` when set.
        clock: ?Clock = null,

        pub fn init(
            allocator: std.mem.Allocator,
            trees: *FlatTrees,
            state_root: Hash,
            config: Config,
        ) !Self {
            assert(config.memo_entries_max > 0 and config.memo_bytes_max > 0);
            assert(config.record_writes_max > 0);
            assert(config.record_cache_entries >= record_cache_module.ways);
            var sparse_state = try SparseState.init(allocator, .{
                .nodes_max = 1,
                .node_bytes_max = 1,
                .codes_max = 1,
                .code_bytes_max = 1,
                .headers_max = 1,
                .trie_nodes_max = config.trie_nodes_max,
                .storage_tries_max = config.storage_tries_max,
            });
            errdefer sparse_state.deinit(allocator);
            sparse_state.delete_destroyed_storage = true;
            var memo: std.AutoHashMapUnmanaged(Hash, Entry) = .empty;
            try memo.ensureTotalCapacity(allocator, config.memo_entries_max);
            errdefer memo.deinit(allocator);
            var read_accounts: std.AutoHashMapUnmanaged(Hash, ?Account) = .empty;
            try read_accounts.ensureTotalCapacity(allocator, config.read_memo_accounts_max);
            errdefer read_accounts.deinit(allocator);
            var read_slots: @FieldType(Self, "read_slots") = .empty;
            try read_slots.ensureTotalCapacity(allocator, config.read_memo_slots_max);
            errdefer read_slots.deinit(allocator);
            const memo_bytes = try allocator.alloc(u8, config.memo_bytes_max);
            errdefer allocator.free(memo_bytes);
            const frames = try allocator.alloc(Frame, frames_max);
            errdefer allocator.free(frames);
            const record_writes = try allocator.alloc(RecordWrite, config.record_writes_max);
            errdefer allocator.free(record_writes);
            const record_bytes = try allocator.alloc(u8, config.record_write_bytes_max);
            errdefer allocator.free(record_bytes);
            const account_writes = try allocator.alloc(
                AccountWrite,
                config.changeset.accounts_max + config.changeset.storage_max,
            );
            errdefer allocator.free(account_writes);
            var swapped = try Changeset.init(allocator, config.changeset);
            errdefer swapped.deinit(allocator);
            const record_cache = try RecordCache.init(allocator, config.record_cache_entries);
            return .{
                .record_cache = record_cache,
                .read_accounts = read_accounts,
                .read_slots = read_slots,
                .account_writes = account_writes,
                .trees = trees,
                .config = config,
                .state_root = state_root,
                .sparse_state = sparse_state,
                .memo = memo,
                .memo_bytes = memo_bytes,
                .frames = frames,
                .record_writes = record_writes,
                .record_bytes = record_bytes,
                .swapped = swapped,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.record_cache.deinit(allocator);
            self.swapped.deinit(allocator);
            allocator.free(self.account_writes);
            allocator.free(self.record_bytes);
            allocator.free(self.record_writes);
            allocator.free(self.frames);
            allocator.free(self.memo_bytes);
            self.memo.deinit(allocator);
            self.read_slots.deinit(allocator);
            self.read_accounts.deinit(allocator);
            self.sparse_state.deinit(allocator);
            self.* = undefined;
        }

        /// The state root after every `apply` so far.
        pub fn root(self: *const Self) Hash {
            return self.state_root;
        }

        /// Rebinds to trees reopened at a checkpoint whose state root is `state_root`.
        pub fn set_root(self: *Self, state_root: Hash) void {
            self.state_root = state_root;
            self.fault = false;
            // The trees may have moved (a reopen, a crash, an import): forget their reads.
            self.forget_reads();
            assert(std.mem.eql(u8, &self.state_root, &state_root));
        }

        // Reads (synchronous point lookups through the read memo; a failure faults the
        // state and is not remembered).

        pub fn account(self: *Self, address_hash: *const Hash) ?Account {
            if (self.read_accounts.get(address_hash.*)) |record| {
                self.stats.read_memo_hits += 1;
                return record;
            }
            self.stats.account_reads += 1;
            const record = self.trees.get_account(address_hash) catch {
                self.fault = true;
                return null;
            };
            if (self.read_accounts.count() < self.config.read_memo_accounts_max) {
                self.read_accounts.putAssumeCapacityNoClobber(address_hash.*, record);
            }
            return record;
        }

        /// Empties the read memo: the trees are about to change, or did.
        fn forget_reads(self: *Self) void {
            self.read_accounts.clearRetainingCapacity();
            self.read_slots.clearRetainingCapacity();
            assert(self.read_accounts.count() == 0 and self.read_slots.count() == 0);
        }

        pub fn basic(self: *Self, address_hash: *const Hash) ?AccountInfo {
            const record = self.account(address_hash) orelse return null;
            return record.info;
        }

        /// The slot word, 0 when absent.
        pub fn storage(self: *Self, address_hash: *const Hash, slot_hash: *const Hash) u256 {
            const key = flat_trees_module.storage_key_hashed(address_hash, slot_hash);
            if (self.read_slots.get(key)) |word| {
                self.stats.read_memo_hits += 1;
                return word;
            }
            self.stats.slot_reads += 1;
            const word = self.trees.get_slot(address_hash, slot_hash) catch {
                self.fault = true;
                return 0;
            };
            if (self.read_slots.count() < self.config.read_memo_slots_max) {
                self.read_slots.putAssumeCapacityNoClobber(key, word);
            }
            return word;
        }

        /// Checks that the state root resolves: the root record (and for a leaf root, its
        /// leaf) rebuilds a node hashing to the root; for the empty root, no root record.
        /// `error.Corrupt` otherwise (a checkpoint whose trees do not hold its root).
        pub fn check_root(self: *Self) Error!void {
            if (self.fault) return error.Corrupt;
            if (std.mem.eql(u8, &self.state_root, &node.empty_root)) {
                const record = self.trees.get_branch(null, &.{}) catch {
                    self.fault = true;
                    return error.Corrupt;
                };
                if (record != null) return error.Corrupt;
                return;
            }
            self.begin_block();
            const bytes = fallback_node(self, &self.state_root);
            if (bytes == null or self.fault or self.corrupt or self.memo_full) {
                return error.Corrupt;
            }
            assert(std.mem.eql(u8, &node.keccak256(bytes.?), &self.state_root));
        }

        /// What `verify_leaf` read through the trie.
        pub const Leaf = struct { account: ?AccountState, word: u256 };

        /// Reads the account at `address_hash` (and the slot at `slot_hash`) through the
        /// trie from the root: every node is rebuilt from branch records and flat leaves and
        /// checked against the hash its parent names, so a missing or wrong record on the
        /// path is `error.Corrupt` (an import's self-check). Writes nothing; starts a fresh
        /// walk, as a block does.
        pub fn verify_leaf(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: ?*const Hash,
        ) Error!Leaf {
            if (self.fault) return error.Corrupt;
            self.begin_block();
            const leaf_account = self.sparse_state.account_hashed(address_hash) catch |err| {
                return self.sparse_error(err);
            };
            var word: u256 = 0;
            if (slot_hash) |slot| {
                word = self.sparse_state.storage_hashed(address_hash, slot) catch |err| {
                    return self.sparse_error(err);
                };
            }
            if (self.fault or self.corrupt) return error.Corrupt;
            if (self.memo_full) return error.Full;
            assert(leaf_account != null or word == 0);
            return .{ .account = leaf_account, .word = word };
        }

        /// The records `apply` wrote for the last block (puts and tombstones), for tests.
        pub fn last_record_writes(self: *const Self) []const RecordWrite {
            return self.record_writes[0..self.record_writes_len];
        }

        pub fn record_value(self: *const Self, write: *const RecordWrite) ?[]const u8 {
            if (write.value_len == 0) return null;
            return self.record_bytes[write.value_start..][0..write.value_len];
        }

        // Apply.

        /// Moves the state by one block: `changeset` forward, or backward (`forward` false:
        /// its old values). On error nothing was written and the root is unchanged.
        pub fn apply(self: *Self, changeset: *const Changeset, forward: bool) Error!void {
            if (self.fault) return error.Corrupt;
            const applied = if (forward) changeset else try self.reverse(changeset);
            try self.check_wipes(applied);
            const start_ns = self.now_ns();
            self.begin_block();
            self.sparse_state.apply(applied) catch |err| return self.sparse_error(err);
            const updated_ns = self.now_ns();
            const new_root = self.sparse_state.state_root();
            if (self.memo_full) return error.Full;
            if (self.fault or self.corrupt) return error.Corrupt;
            const rooted_ns = self.now_ns();
            self.record_writes_len = 0;
            self.record_bytes_len = 0;
            try self.diff(null, &self.state_root, &new_root);
            try self.diff_storage(applied);
            try self.collect_accounts(applied);
            try self.reserve(applied);
            const diffed_ns = self.now_ns();
            // Every read of this block happened above: the memo now names the old values.
            self.forget_reads();
            self.write_accounts();
            self.write_slots(applied);
            self.write_records();
            self.state_root = new_root;
            assert(!self.fault and !self.corrupt);
            const stats = &self.stats;
            stats.blocks += 1;
            stats.record_writes += self.record_writes_len;
            stats.update_ns += updated_ns -| start_ns;
            stats.root_ns += rooted_ns -| updated_ns;
            stats.diff_ns += diffed_ns -| rooted_ns;
            stats.write_ns += self.now_ns() -| diffed_ns;
        }

        fn now_ns(self: *const Self) u64 {
            const clock = self.clock orelse return 0;
            return clock.now_ns(clock.context);
        }

        fn sparse_error(self: *Self, err: witness.Error) Error {
            if (self.fault or self.corrupt) return error.Corrupt;
            if (self.memo_full) return error.Full;
            return switch (err) {
                error.SparseFull, error.WitnessFull, error.KeysFull => error.Full,
                else => error.Corrupt,
            };
        }

        /// `changeset` with old and new swapped (same keys, so still sorted).
        fn reverse(self: *Self, changeset: *const Changeset) Error!*const Changeset {
            self.swapped.clear();
            for (changeset.account_changes()) |change| {
                self.swapped.add_account(.{
                    .address = change.address,
                    .old = change.new,
                    .new = change.old,
                }) catch return error.Full;
            }
            for (changeset.storage_changes()) |change| {
                self.swapped.add_storage(.{
                    .address = change.address,
                    .slot = change.slot,
                    .old = change.new,
                    .new = change.old,
                }) catch return error.Full;
            }
            assert(self.swapped.accounts_len == changeset.accounts_len);
            assert(self.swapped.storage_len == changeset.storage_len);
            return &self.swapped;
        }

        /// A destroyed account with storage must list its slots (a wipe is not scanned).
        fn check_wipes(self: *Self, changeset: *const Changeset) Error!void {
            const storage_changes = changeset.storage_changes();
            var storage_index: usize = 0;
            for (changeset.account_changes()) |*change| {
                while (storage_index < storage_changes.len and std.mem.order(
                    u8,
                    &storage_changes[storage_index].address,
                    &change.address,
                ) == .lt) storage_index += 1;
                if (change.new != null) continue;
                const listed = storage_index < storage_changes.len and
                    std.mem.eql(u8, &storage_changes[storage_index].address, &change.address);
                if (listed) continue;
                const record = self.account(&node.keccak256(&change.address)) orelse continue;
                if (!std.mem.eql(u8, &record.storage_root, &node.empty_root)) {
                    return error.Unsupported;
                }
            }
            if (self.fault) return error.Corrupt;
        }

        fn begin_block(self: *Self) void {
            self.memo.clearRetainingCapacity();
            self.memo_bytes_len = 0;
            self.corrupt = false;
            self.memo_full = false;
            self.sparse_state.reset(self.state_root, .{ .number = 0, .hash = @splat(0) });
            self.sparse_state.set_fallback(.{
                .context = self,
                .node = fallback_node,
                .code = fallback_code,
                .block_hash = fallback_block_hash,
            });
            self.sparse_state.trie.sink = .{ .context = self, .add = sink_add };
            if (!std.mem.eql(u8, &self.state_root, &node.empty_root)) {
                self.register(&self.state_root, .{ .record = .{ .owner = null, .hang = .{} } });
            }
            assert(self.memo.count() <= 1);
        }

        // The memo.

        /// Adds a locator for `hash` unless it has one (content-addressed: any one serves).
        fn register(self: *Self, hash: *const Hash, locator: Locator) void {
            if (self.memo.contains(hash.*)) return;
            if (self.memo.count() >= self.config.memo_entries_max) {
                self.memo_full = true;
                return;
            }
            self.memo.putAssumeCapacityNoClobber(hash.*, .{ .locator = locator });
        }

        /// Stores `bytes` as `hash`'s preimage (once) and returns the stored copy.
        fn store_bytes(self: *Self, hash: *const Hash, bytes: []const u8) ?[]const u8 {
            assert(bytes.len > 0);
            self.register(hash, .bytes_only);
            const entry = self.memo.getPtr(hash.*) orelse return null;
            if (entry.bytes_len > 0) return self.entry_bytes(entry);
            if (self.memo_bytes.len - self.memo_bytes_len < bytes.len) {
                self.memo_full = true;
                return null;
            }
            entry.bytes_start = self.memo_bytes_len;
            entry.bytes_len = @intCast(bytes.len);
            @memcpy(self.memo_bytes[self.memo_bytes_len..][0..bytes.len], bytes);
            self.memo_bytes_len += @intCast(bytes.len);
            return self.entry_bytes(entry);
        }

        fn entry_bytes(self: *const Self, entry: *const Entry) []const u8 {
            assert(entry.bytes_len > 0);
            return self.memo_bytes[entry.bytes_start..][0..entry.bytes_len];
        }

        /// `sparse.Sink`: every node the root computation hashes (the post-state's new nodes).
        fn sink_add(context: *anyopaque, hash: *const Hash, bytes: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context));
            _ = self.store_bytes(hash, bytes);
        }

        fn fallback_node(context: *anyopaque, hash: *const Hash) ?[]const u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            const entry = self.memo.get(hash.*) orelse {
                self.corrupt = true;
                return null;
            };
            if (entry.bytes_len > 0) return self.entry_bytes(&entry);
            switch (entry.locator) {
                .bytes_only => {
                    self.corrupt = true;
                    return null;
                },
                .record => |record| {
                    return self.resolve_record(owner_of(&record.owner), record.hang.slice(), hash);
                },
                .leaf => |leaf| {
                    return self.resolve_leaf(owner_of(&leaf.owner), &leaf.key, leaf.depth, hash);
                },
            }
        }

        fn fallback_code(_: *anyopaque, _: *const Hash) ?[]const u8 {
            return null;
        }

        fn fallback_block_hash(_: *anyopaque, _: u64) ?Hash {
            return null;
        }

        fn owner_of(owner: *const ?Hash) ?*const Hash {
            if (owner.*) |*hash| return hash;
            return null;
        }

        /// The preimage of the record hanging at `hang`'s top node; it must hash to `want`.
        fn resolve_record(
            self: *Self,
            owner: ?*const Hash,
            hang: []const u8,
            want: *const Hash,
        ) ?[]const u8 {
            self.stats.records_resolved += 1;
            var value_buffer: [branch_record.value_bytes_max]u8 = undefined;
            const cached = self.record_cache.get(want, hang);
            const value = if (cached) |bytes| value: {
                self.stats.record_cache_hits += 1;
                @memcpy(value_buffer[0..bytes.len], bytes);
                break :value value_buffer[0..bytes.len];
            } else self.read_record(owner, hang) orelse return null;
            var record: Record = undefined;
            branch_record.decode(value, &record) catch return self.fail();
            branch_record.validate_path(hang, &record) catch return self.fail();
            if (branch_record.is_leaf_root(&record)) {
                assert(hang.len == 0);
                return self.resolve_leaf(owner, &record.leaf_keys[0], 0, want);
            }
            var branch_buffer: [branch_record.branch_bytes_max]u8 = undefined;
            const branch_bytes = branch_record.branch_encoding(&record, &branch_buffer);
            const branch_ref = RlpNode.from_rlp(branch_bytes);
            var extension_buffer: [branch_record.extension_encoding_bytes_max]u8 = undefined;
            const top = if (record.extension_len == 0)
                branch_bytes
            else
                branch_record.extension_encoding(&record, &branch_ref, &extension_buffer);
            if (cached == null) {
                if (!std.mem.eql(u8, &node.keccak256(top), want)) return self.fail();
                self.record_cache.put(want, hang, value);
            } else if (std.debug.runtime_safety) {
                // Cached records were verified (or built from hashed nodes) when cached.
                assert(std.mem.eql(u8, &node.keccak256(top), want));
            }
            const stored = self.store_bytes(want, top) orelse return null;
            if (record.extension_len > 0 and branch_ref.is_hash()) {
                _ = self.store_bytes(&branch_ref.root_hash(), branch_bytes) orelse return null;
            }
            self.register_children(owner, hang, &record);
            return stored;
        }

        /// The record bytes at (`owner`, `hang`) from the branch trees (null: faulted or
        /// missing, flagged).
        fn read_record(self: *Self, owner: ?*const Hash, hang: []const u8) ?[]const u8 {
            self.stats.record_reads += 1;
            const value = self.trees.get_branch(owner, hang) catch {
                self.fault = true;
                return null;
            } orelse {
                self.corrupt = true;
                return null;
            };
            assert(value.len >= 1 and value.len <= branch_record.value_bytes_max);
            return value;
        }

        fn fail(self: *Self) ?[]const u8 {
            self.corrupt = true;
            return null;
        }

        /// Locators for the record's hashed children: records below, leaves by key.
        fn register_children(
            self: *Self,
            owner: ?*const Hash,
            hang: []const u8,
            record: *const Record,
        ) void {
            var path = Nibbles.from_nibbles(hang);
            path.append(record.extension_slice());
            assert(path.len < 64);
            const owner_value: ?Hash = if (owner) |hash| hash.* else null;
            var child: u32 = 0;
            var leaf: u32 = 0;
            var nibble: u8 = 0;
            while (nibble < 16) : (nibble += 1) {
                const bit = @as(u16, 1) << @intCast(nibble);
                if (record.state_mask & bit == 0) continue;
                const ref = &record.children[child];
                child += 1;
                const is_record = record.tree_mask & bit != 0;
                const key = if (is_record) null else &record.leaf_keys[leaf];
                if (!is_record) leaf += 1;
                // Embedded children are decoded from their parent's bytes.
                if (!ref.is_hash()) continue;
                if (key) |leaf_key| {
                    self.register(&ref.root_hash(), .{ .leaf = .{
                        .owner = owner_value,
                        .key = leaf_key.*,
                        .depth = path.len + 1,
                    } });
                } else {
                    var child_hang = path;
                    child_hang.push(nibble);
                    self.register(&ref.root_hash(), .{ .record = .{
                        .owner = owner_value,
                        .hang = child_hang,
                    } });
                }
            }
            assert(child == record.child_count() and leaf == record.leaf_count());
        }

        /// The leaf of `key` at `depth` (its value from the flat trees); must hash to `want`.
        /// An account leaf registers its storage root.
        fn resolve_leaf(
            self: *Self,
            owner: ?*const Hash,
            key: *const Hash,
            depth: u8,
            want: *const Hash,
        ) ?[]const u8 {
            assert(depth < 64);
            self.stats.leaves_resolved += 1;
            var value_buffer: [state_trie.account_rlp_bytes_max]u8 = undefined;
            var value: []const u8 = undefined;
            if (owner) |owner_hash| {
                const word = self.storage(owner_hash, key);
                if (self.fault) return null;
                if (word == 0) return self.fail();
                value = state_trie.encode_storage_value(word, value_buffer[0..33]);
            } else {
                const record = self.account(key) orelse {
                    if (self.fault) return null;
                    return self.fail();
                };
                const info: trie.Account = .{
                    .nonce = record.info.nonce,
                    .balance = record.info.balance,
                    .code_hash = record.info.code_hash,
                };
                value = state_trie.encode_account(&info, &record.storage_root, &value_buffer);
                if (!std.mem.eql(u8, &record.storage_root, &node.empty_root)) {
                    self.register(&record.storage_root, .{ .record = .{
                        .owner = key.*,
                        .hang = .{},
                    } });
                }
            }
            const path = Nibbles.from_bytes(key);
            var leaf_buffer: [leaf_bytes_max]u8 = undefined;
            var sink: node.BufferSink = .{ .buffer = &leaf_buffer };
            node.encode_leaf(&sink, path.slice()[depth..], value);
            const bytes = sink.result();
            if (!std.mem.eql(u8, &node.keccak256(bytes), want)) return self.fail();
            return self.store_bytes(want, bytes);
        }

        // The walk.

        /// The node at `ref`, decoded: from its inline bytes, its memo bytes, or (a leaf known
        /// only by its locator) its path alone.
        fn view(self: *const Self, ref: *const RlpNode) Error!sparse.Decoded {
            assert(ref.len > 0);
            if (!ref.is_hash()) return sparse.decode_node(ref.slice()) catch error.Corrupt;
            const entry = self.memo.get(ref.root_hash()) orelse return error.Corrupt;
            if (entry.bytes_len > 0) {
                return sparse.decode_node(self.entry_bytes(&entry)) catch error.Corrupt;
            }
            switch (entry.locator) {
                .leaf => |leaf| {
                    const key = Nibbles.from_bytes(&leaf.key);
                    return .{
                        .kind = .leaf,
                        .path = Nibbles.from_nibbles(key.slice()[leaf.depth..]),
                    };
                },
                .record, .bytes_only => return error.Corrupt,
            }
        }

        /// Whether `ref` is a leaf, and its path: `view`, except that a record never resolved
        /// (an untouched child of a changed branch) is known to be one by its locator.
        fn child_view(self: *const Self, ref: *const RlpNode) Error!sparse.Decoded {
            if (ref.is_hash()) {
                const entry = self.memo.get(ref.root_hash()) orelse return error.Corrupt;
                if (entry.bytes_len == 0 and entry.locator == .record) return .{ .kind = .branch };
            }
            return self.view(ref);
        }

        /// Steps a cursor whose extension path is all behind it onto the branch below.
        fn normalize(self: *const Self, cursor: *Cursor) Error!void {
            if (cursor.is_none()) return;
            const current = try self.view(&cursor.ref);
            if (current.kind != .extension or cursor.offset < current.path.len) return;
            assert(cursor.offset == current.path.len);
            cursor.* = .{ .ref = current.children[0] };
            assert(!cursor.is_none());
        }

        fn child_cursor(cursor: *const Cursor, current: ?*const sparse.Decoded, nibble: u8) Cursor {
            const decoded = current orelse return .{};
            switch (decoded.kind) {
                .leaf => return .{},
                .extension => {
                    assert(cursor.offset < decoded.path.len);
                    if (decoded.path.data[cursor.offset] != nibble) return .{};
                    return .{ .ref = cursor.ref, .offset = cursor.offset + 1 };
                },
                .branch => {
                    assert(cursor.offset == 0);
                    const child = decoded.children[nibble];
                    if (child.len == 0) return .{};
                    return .{ .ref = child, .hangs = true };
                },
            }
        }

        /// Writes the records of the trie (`owner`) that differ between the two roots.
        fn diff(
            self: *Self,
            owner: ?Hash,
            pre_root: *const Hash,
            post_root: *const Hash,
        ) Error!void {
            if (std.mem.eql(u8, pre_root, post_root)) return;
            self.frames[0] = .{
                .depth = 0,
                .nibble = 0,
                .pre = Cursor.root(pre_root),
                .post = Cursor.root(post_root),
            };
            var frames_len: u32 = 1;
            var path: [64]u8 = undefined;
            var steps: u64 = 0;
            while (frames_len > 0) : (steps += 1) {
                // Each position is visited once; positions lie on paths of memo nodes.
                assert(steps <= 64 * 16 * (@as(u64, self.memo.count()) + 1));
                frames_len -= 1;
                var frame = self.frames[frames_len];
                if (frame.depth > 0) path[frame.depth - 1] = frame.nibble;
                const position = path[0..frame.depth];
                try self.normalize(&frame.pre);
                try self.normalize(&frame.post);
                if (frame.pre.eql(&frame.post)) continue;
                const pre = if (frame.pre.is_none()) null else try self.view(&frame.pre.ref);
                const post = if (frame.post.is_none()) null else try self.view(&frame.post.ref);
                try self.diff_position(owner, position, &frame, opt(&pre), opt(&post));
                if (!descends(opt(&pre)) and !descends(opt(&post))) continue;
                if (frame.depth == 64) return error.Corrupt;
                var nibble: u8 = 16;
                while (nibble > 0) {
                    nibble -= 1;
                    const pre_child = child_cursor(&frame.pre, opt(&pre), nibble);
                    const post_child = child_cursor(&frame.post, opt(&post), nibble);
                    if (pre_child.eql(&post_child)) continue;
                    assert(frames_len < self.frames.len);
                    self.frames[frames_len] = .{
                        .depth = frame.depth + 1,
                        .nibble = nibble,
                        .pre = pre_child,
                        .post = post_child,
                    };
                    frames_len += 1;
                }
            }
        }

        fn opt(decoded: *const ?sparse.Decoded) ?*const sparse.Decoded {
            if (decoded.*) |*value| return value;
            return null;
        }

        /// Only extensions and branches have records below them (leaves end the path).
        fn descends(decoded: ?*const sparse.Decoded) bool {
            const value = decoded orelse return false;
            return value.kind != .leaf;
        }

        /// Whether the cursor's node is a record's top at `position`.
        fn is_record_top(
            position: []const u8,
            cursor: *const Cursor,
            decoded: ?*const sparse.Decoded,
        ) bool {
            const value = decoded orelse return false;
            if (cursor.offset != 0) return false;
            if (!cursor.hangs and position.len > 0) return false;
            // A leaf is a record (a leaf root) only as a whole trie.
            return value.kind != .leaf or position.len == 0;
        }

        /// The record write at `position`: the post-state's record, else a tombstone where
        /// only the pre-state had one. The cursors differ, so a record in both differs too.
        fn diff_position(
            self: *Self,
            owner: ?Hash,
            position: []const u8,
            frame: *const Frame,
            pre: ?*const sparse.Decoded,
            post: ?*const sparse.Decoded,
        ) Error!void {
            const pre_record = is_record_top(position, &frame.pre, pre);
            if (is_record_top(position, &frame.post, post)) {
                var record: Record = .{};
                try self.build_record(position, post.?, &record);
                branch_record.validate_path(position, &record) catch return error.Corrupt;
                var buffer: [branch_record.value_bytes_max]u8 = undefined;
                const value = branch_record.encode(&record, &buffer);
                // The post-state's top node, hashed by the root computation: the next block
                // resolves it from the cache (embedded nodes are never resolved by hash).
                if (frame.post.ref.is_hash()) {
                    self.record_cache.put(&frame.post.ref.root_hash(), position, value);
                }
                return self.add_write(owner, position, value);
            }
            if (pre_record) return self.add_write(owner, position, null);
        }

        fn build_record(
            self: *const Self,
            position: []const u8,
            top: *const sparse.Decoded,
            record: *Record,
        ) Error!void {
            switch (top.kind) {
                .leaf => {
                    assert(position.len == 0);
                    if (top.path.len != 64) return error.Corrupt;
                    var key: Hash = undefined;
                    _ = top.path.pack(&key);
                    record.* = branch_record.leaf_root(&key);
                },
                .extension => {
                    record.extension_len = top.path.len;
                    @memcpy(record.extension[0..top.path.len], top.path.slice());
                    const branch = try self.view(&top.children[0]);
                    if (branch.kind != .branch) return error.Corrupt;
                    var path = Nibbles.from_nibbles(position);
                    if (path.len + top.path.len >= 64) return error.Corrupt;
                    path.append(top.path.slice());
                    try self.fill_branch(path.slice(), &branch, record);
                },
                .branch => try self.fill_branch(position, top, record),
            }
        }

        /// Masks, child references, and leaf keys (the branch path, the nibble, the leaf's
        /// own path) of the branch at `branch_path`.
        fn fill_branch(
            self: *const Self,
            branch_path: []const u8,
            branch: *const sparse.Decoded,
            record: *Record,
        ) Error!void {
            assert(branch.kind == .branch);
            if (branch_path.len >= 64) return error.Corrupt;
            var child: u32 = 0;
            var leaf: u32 = 0;
            for (&branch.children, 0..) |*ref, nibble| {
                if (ref.len == 0) continue;
                const bit = @as(u16, 1) << @intCast(nibble);
                record.state_mask |= bit;
                record.children[child] = ref.*;
                child += 1;
                const decoded = try self.child_view(ref);
                if (decoded.kind != .leaf) {
                    record.tree_mask |= bit;
                    continue;
                }
                if (branch_path.len + 1 + decoded.path.len != 64) return error.Corrupt;
                var key = Nibbles.from_nibbles(branch_path);
                key.push(@intCast(nibble));
                key.append(decoded.path.slice());
                _ = key.pack(&record.leaf_keys[leaf]);
                leaf += 1;
            }
            if (child < 2) return error.Corrupt;
            assert(leaf == record.leaf_count());
        }

        fn add_write(
            self: *Self,
            owner: ?Hash,
            position: []const u8,
            value: ?[]const u8,
        ) Error!void {
            if (self.record_writes_len == self.record_writes.len) return error.Full;
            const bytes = value orelse &.{};
            if (self.record_bytes.len - self.record_bytes_len < bytes.len) return error.Full;
            @memcpy(self.record_bytes[self.record_bytes_len..][0..bytes.len], bytes);
            self.record_writes[self.record_writes_len] = .{
                .owner = owner,
                .hang = Nibbles.from_nibbles(position),
                .value_start = self.record_bytes_len,
                .value_len = @intCast(bytes.len),
            };
            self.record_writes_len += 1;
            self.record_bytes_len += @intCast(bytes.len);
        }

        /// Diffs the storage trie of every address with storage changes (destroyed ones end
        /// empty). Pre-state roots come from the account tree (no write happened yet).
        fn diff_storage(self: *Self, changeset: *const Changeset) Error!void {
            const changes = changeset.storage_changes();
            var start: usize = 0;
            while (start < changes.len) {
                const address = &changes[start].address;
                var end = start + 1;
                while (end < changes.len and std.mem.eql(u8, &changes[end].address, address)) {
                    end += 1;
                }
                start = end;
                const address_hash = node.keccak256(address);
                const pre = self.account(&address_hash);
                if (self.fault) return error.Corrupt;
                const pre_root = if (pre) |record| record.storage_root else node.empty_root;
                const post_root = self.sparse_state.account_storage_root(address.*) catch {
                    return error.Corrupt;
                };
                try self.diff(address_hash, &pre_root, &post_root);
            }
            assert(start == changes.len);
        }

        /// Every put fits the memtables, or nothing is written.
        fn reserve(self: *Self, changeset: *const Changeset) Error!void {
            var account_branches: u32 = 0;
            for (self.last_record_writes()) |*write| {
                account_branches += @intFromBool(write.owner == null);
            }
            const storage_branches = self.record_writes_len - account_branches;
            const accounts = changeset.accounts_len + changeset.storage_len;
            const fits = accounts <= self.room(&self.trees.accounts) and
                changeset.storage_len <= self.room(&self.trees.storage) and
                account_branches <= self.room(&self.trees.account_branches) and
                storage_branches <= self.room(&self.trees.storage_branches);
            if (!fits) return error.Busy;
        }

        fn room(self: *const Self, tree: anytype) u32 {
            return switch (self.mode) {
                .live => tree.capacity_free(),
                .replay => tree.replay_capacity_free(),
            };
        }

        /// A reserved put (`reserve` counted it), live or replay.
        fn put(self: *const Self, tree: anytype, key: anytype, value: anytype) void {
            const result = switch (self.mode) {
                .live => tree.put(key, value),
                .replay => tree.put_replay(key, value),
            };
            // Reserved by `reserve`: the tree has room for every put of the block.
            result catch unreachable;
        }

        /// The post-state record of every address with an account or storage change: new
        /// info and storage root from the sparse trie, a tombstone for a removed account.
        /// Collected before any write: a read after a write could see the post-state.
        fn collect_accounts(self: *Self, changeset: *const Changeset) Error!void {
            const accounts = changeset.account_changes();
            const changes = changeset.storage_changes();
            var account_index: usize = 0;
            var storage_index: usize = 0;
            self.account_writes_len = 0;
            var steps: usize = 0;
            while (account_index < accounts.len or storage_index < changes.len) : (steps += 1) {
                assert(steps <= accounts.len + changes.len);
                var address: Address = undefined;
                if (storage_index == changes.len or (account_index < accounts.len and std.mem.order(
                    u8,
                    &accounts[account_index].address,
                    &changes[storage_index].address,
                ) != .gt)) {
                    address = accounts[account_index].address;
                    account_index += 1;
                } else {
                    address = changes[storage_index].address;
                }
                while (storage_index < changes.len and
                    std.mem.eql(u8, &changes[storage_index].address, &address)) storage_index += 1;
                try self.collect_account(&address);
            }
            assert(self.account_writes_len <= accounts.len + changes.len);
        }

        fn collect_account(self: *Self, address: *const Address) Error!void {
            if (self.account_writes_len == self.account_writes.len) return error.Full;
            const write = &self.account_writes[self.account_writes_len];
            write.key = node.keccak256(address);
            write.value = null;
            const info = self.sparse_state.basic(address.*) catch return error.Corrupt;
            if (info) |account_info| {
                const storage_root = self.sparse_state.account_storage_root(address.*) catch {
                    return error.Corrupt;
                };
                write.value = flat_trees_module.account_encode(&account_info, &storage_root);
            }
            self.account_writes_len += 1;
            if (self.fault or self.corrupt) return error.Corrupt;
        }

        fn write_accounts(self: *Self) void {
            for (self.account_writes[0..self.account_writes_len]) |*write| {
                const value = if (write.value) |*bytes| bytes else null;
                // Reserved: `reserve` counted a put per account and per storage entry.
                self.put(&self.trees.accounts, &write.key, value);
            }
        }

        fn write_slots(self: *Self, changeset: *const Changeset) void {
            var address_hash: Hash = undefined;
            var address_last: ?Address = null;
            for (changeset.storage_changes()) |*change| {
                const same = if (address_last) |last|
                    std.mem.eql(u8, &last, &change.address)
                else
                    false;
                if (!same) {
                    address_hash = node.keccak256(&change.address);
                    address_last = change.address;
                }
                const key = flat_trees_module.storage_key(&address_hash, change.slot);
                var value: [flat_trees_module.storage_value_size]u8 = undefined;
                std.mem.writeInt(u256, &value, change.new, .big);
                const value_pointer = if (change.new == 0) null else &value;
                self.put(&self.trees.storage, &key, value_pointer);
            }
        }

        fn write_records(self: *Self) void {
            for (self.last_record_writes()) |*write| {
                const value = self.record_value(write);
                if (write.owner) |*owner| {
                    const key = branch_record.storage_key(owner, write.hang.slice());
                    self.put(&self.trees.storage_branches, &key, value);
                } else {
                    const key = branch_record.path_key(write.hang.slice());
                    self.put(&self.trees.account_branches, &key, value);
                }
            }
        }
    };
}

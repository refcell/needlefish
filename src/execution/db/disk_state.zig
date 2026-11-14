//! Disk state: the state root and the flat trees kept up to date block by block over a full
//! state on disk (disk-state import plan, Q4 and step 7). The four flat trees (`flat_trees.zig`)
//! hold every account record (with its storage root), every slot, and every branch record
//! (`branch_record.zig`) of the account trie and of each storage trie, exactly as a bulk import
//! writes them; nothing of the state lives in RAM between blocks except the root and caches.
//!
//! Per block (`apply`, forward or unwind): a `SparseState` at the current root applies the
//! changeset (a destroyed account's storage slot by slot, so its records are seen).
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
//! Carry: a walk (`apply`, `verify_leaf`) that succeeded leaves the sparse trie and the memo at
//! the root, so the next walk starts on them (the trie's upper levels stay resolved) while
//! they are small (`carry_ready`); else, and after `set_root`, it starts fresh. Carrying is
//! safe because a memo entry's bytes are content-addressed and every resolution hashes to its
//! reference, and a locator never outlives its record unresolved: a record or leaf changes
//! only where the walk resolved it, which stores its bytes, and bytes win over locators.
//! A carried walk that fails anyway (memo full, say) is redone fresh, which is the oracle.
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
const lazy = @import("../../utilities/lazy_alloc/root.zig");

const trie = @import("../trie/root.zig");
const witness = @import("witness.zig");
const changeset_module = @import("changeset.zig");
const flat_trees_module = @import("flat_trees.zig");
const branch_record = @import("branch_record.zig");
const record_cache_module = @import("record_cache.zig");
const digest_table = @import("digest_table.zig");

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

/// A node of the walk as `sparse.decode_layout` reads it: its child references stay in
/// `source` (memo bytes, or the inline reference it came from), never copied out whole.
const View = struct {
    layout: sparse.Layout,
    /// Empty for a leaf known only by its locator (no children).
    source: []const u8 = &.{},

    /// The child reference at `nibble` (slot 0 of an extension); length 0 for none.
    fn child_ref(self: *const View, nibble: u8) RlpNode {
        assert(nibble < 16);
        const offset = self.layout.child_offsets[nibble];
        if (offset == 0) return .{};
        assert(self.layout.kind != .leaf and offset < self.source.len);
        return sparse.child_ref_at(self.source, offset);
    }
};

/// A hash map keyed by keccak digests, or by a concatenation of them (a storage key: owner
/// and slot hash): the keys' words are uniform already, so their first words are the hash.
fn DigestMap(comptime Key: type, comptime Value: type) type {
    comptime assert(@sizeOf(Key) % 32 == 0 and @sizeOf(Key) > 0);
    const load_percentage = std.hash_map.default_max_load_percentage;
    return std.HashMapUnmanaged(Key, Value, DigestContext(Key), load_percentage);
}

fn DigestContext(comptime Key: type) type {
    return struct {
        pub fn hash(_: @This(), key: Key) u64 {
            var result: u64 = 0;
            var offset: usize = 0;
            while (offset < key.len) : (offset += 32) {
                result ^= std.mem.readInt(u64, key[offset..][0..8], .little);
            }
            return result;
        }

        pub fn eql(_: @This(), a: Key, b: Key) bool {
            return std.mem.eql(u8, &a, &b);
        }
    };
}

/// Reads a monotonic clock for `Stats` phase times (the caller's, through its IO).
pub const Clock = struct {
    context: *anyopaque,
    now_ns: *const fn (context: *anyopaque) u64,
};

/// Counters since init (and, under a `Clock`, summed phase times of successful applies).
pub const Stats = struct {
    /// Successful `apply` calls, how many started on the trie the walk before left (carry),
    /// and carried walks that failed and were redone fresh.
    blocks: u64 = 0,
    blocks_carried: u64 = 0,
    carry_retries: u64 = 0,
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
    /// With history capture: the record before the block (`old_len` 0: none).
    old_start: u32 = 0,
    old_len: u32 = 0,
};

pub const AccountWrite = struct {
    key: Hash,
    value: ?[flat_trees_module.account_value_size]u8,
    /// With history capture: the account record before the block (null: absent).
    old: ?[flat_trees_module.account_value_size]u8 = null,
};

/// An older state for `prove_at`: per key, the value it had then when that differs from
/// the trees' (`value`, null for absent), else `trees`. `failed` (the history could not be
/// read) makes the walk `error.Corrupt`, never a fault of the head state.
pub const Overlay = struct {
    context: *anyopaque,
    lookup: *const fn (context: *anyopaque, kind: OverlayKind, key: []const u8) OverlayValue,
};

pub const OverlayKind = enum { account, slot, account_branch, storage_branch };
pub const OverlayValue = union(enum) { trees, value: ?[]const u8, failed };

/// History capture (`capture_enable`): every successful apply also keeps the value each
/// written account record and branch record had before the block, for an archive of
/// reverse diffs. It never fails a block: a pre-state record it cannot rebuild marks the
/// block's capture `failed` instead.
pub const Capture = struct {
    old_bytes: []u8,
    old_bytes_len: u32 = 0,
    /// Successful forward applies since `capture_enable`; the capture describes the last.
    sequence: u64 = 0,
    forward: bool = false,
    failed: bool = false,
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
        memo: digest_table.DigestTableType(Entry),
        /// The account records and slots read since the last write-back (or `set_root`),
        /// as the trees hold them: every tree write goes through `apply`, which clears it.
        read_accounts: DigestMap(Hash, ?Account) = .empty,
        read_slots: DigestMap([flat_trees_module.storage_key_size]u8, u256) =
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
        capture: ?Capture = null,
        /// Set only between `view_begin` and `view_end`: reads see the overlay's state.
        overlay: ?Overlay = null,
        /// The head's root while a view is open.
        head_root: Hash = @splat(0),
        /// The sparse trie and the memo hold `state_root` from the last successful walk.
        carried: bool = false,
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
            var memo = try digest_table.DigestTableType(Entry).init(
                allocator,
                config.memo_entries_max,
            );
            errdefer memo.deinit(allocator);
            var read_accounts: DigestMap(Hash, ?Account) = .empty;
            try read_accounts.ensureTotalCapacity(allocator, config.read_memo_accounts_max);
            errdefer read_accounts.deinit(allocator);
            var read_slots: @FieldType(Self, "read_slots") = .empty;
            try read_slots.ensureTotalCapacity(allocator, config.read_memo_slots_max);
            errdefer read_slots.deinit(allocator);
            const memo_bytes = try lazy.alloc(allocator, u8, config.memo_bytes_max);
            errdefer lazy.free(allocator, memo_bytes);
            const frames = try allocator.alloc(Frame, frames_max);
            errdefer allocator.free(frames);
            const record_writes = try lazy.alloc(allocator, RecordWrite, config.record_writes_max);
            errdefer lazy.free(allocator, record_writes);
            const record_bytes = try lazy.alloc(allocator, u8, config.record_write_bytes_max);
            errdefer lazy.free(allocator, record_bytes);
            const account_writes = try lazy.alloc(
                allocator,
                AccountWrite,
                config.changeset.accounts_max + config.changeset.storage_max,
            );
            errdefer lazy.free(allocator, account_writes);
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
            if (self.capture) |*capture| lazy.free(allocator, capture.old_bytes);
            self.record_cache.deinit(allocator);
            self.swapped.deinit(allocator);
            lazy.free(allocator, self.account_writes);
            lazy.free(allocator, self.record_bytes);
            lazy.free(allocator, self.record_writes);
            allocator.free(self.frames);
            lazy.free(allocator, self.memo_bytes);
            self.memo.deinit(allocator);
            self.read_slots.deinit(allocator);
            self.read_accounts.deinit(allocator);
            self.sparse_state.deinit(allocator);
            self.* = undefined;
        }

        /// Starts keeping pre-state values on every apply (see `Capture`).
        pub fn capture_enable(self: *Self, allocator: std.mem.Allocator) !void {
            assert(self.capture == null);
            const old_bytes = try lazy.alloc(allocator, u8, self.config.record_write_bytes_max);
            self.capture = .{ .old_bytes = old_bytes };
            assert(self.capture.?.sequence == 0);
        }

        /// The account records the last apply wrote (with `old` under capture).
        pub fn last_account_writes(self: *const Self) []const AccountWrite {
            return self.account_writes[0..self.account_writes_len];
        }

        /// The record `write` replaced, under capture (null: none, or no capture).
        pub fn record_old(self: *const Self, write: *const RecordWrite) ?[]const u8 {
            const capture = &(self.capture orelse return null);
            if (write.old_len == 0) return null;
            assert(write.old_start + write.old_len <= capture.old_bytes_len);
            return capture.old_bytes[write.old_start..][0..write.old_len];
        }

        /// The state root after every `apply` so far.
        pub fn root(self: *const Self) Hash {
            return self.state_root;
        }

        /// Rebinds to trees reopened at a checkpoint whose state root is `state_root`.
        pub fn set_root(self: *Self, state_root: Hash) void {
            self.state_root = state_root;
            self.fault = false;
            self.carried = false;
            // The trees may have moved (a reopen, a crash, an import): forget their reads.
            self.forget_reads();
            assert(std.mem.eql(u8, &self.state_root, &state_root));
        }

        // Reads (synchronous point lookups through the read memo; a failure faults the
        // state and is not remembered).

        pub fn account(self: *Self, address_hash: *const Hash) ?Account {
            if (self.overlay) |overlay| {
                switch (overlay.lookup(overlay.context, .account, address_hash)) {
                    .trees => {},
                    .failed => {
                        self.corrupt = true;
                        return null;
                    },
                    .value => |value| {
                        const bytes = value orelse return null;
                        if (bytes.len != flat_trees_module.account_value_size) {
                            self.corrupt = true;
                            return null;
                        }
                        return flat_trees_module.account_decode(
                            bytes[0..flat_trees_module.account_value_size],
                        );
                    },
                }
                // Not remembered: the read memo holds the head state only.
                return self.trees.get_account(address_hash) catch {
                    self.fault = true;
                    return null;
                };
            }
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
            if (self.overlay) |overlay| {
                switch (overlay.lookup(overlay.context, .slot, &key)) {
                    .trees => {},
                    .failed => {
                        self.corrupt = true;
                        return 0;
                    },
                    .value => |value| {
                        const bytes = value orelse return 0;
                        if (bytes.len != 32) {
                            self.corrupt = true;
                            return 0;
                        }
                        return std.mem.readInt(u256, bytes[0..32], .big);
                    },
                }
                return self.trees.get_slot(address_hash, slot_hash) catch {
                    self.fault = true;
                    return 0;
                };
            }
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
            self.begin_block(false);
            const bytes = fallback_node(self, &self.state_root);
            if (bytes == null or self.fault or self.corrupt or self.memo_full) {
                return error.Corrupt;
            }
            assert(std.mem.eql(u8, &node.keccak256(bytes.?), &self.state_root));
        }

        /// Reads (`account`, `storage`, `prove`, ...) see an older state from now until
        /// `view_end`: the trie from `state_root`, every key through `overlay`. The head
        /// state is untouched: the walks start fresh, and the next block starts fresh too
        /// (nothing of the older state is carried or remembered). No `apply` meanwhile.
        pub fn view_begin(self: *Self, state_root: Hash, overlay: Overlay) void {
            assert(self.overlay == null);
            self.forget_reads();
            self.overlay = overlay;
            self.head_root = self.state_root;
            self.state_root = state_root;
            self.carried = false;
            assert(self.overlay != null);
        }

        pub fn view_end(self: *Self) void {
            assert(self.overlay != null);
            self.overlay = null;
            self.state_root = self.head_root;
            self.carried = false;
            self.corrupt = false;
            self.forget_reads();
            assert(self.overlay == null);
        }

        /// `prove` inside a `view_begin` .. `view_end` of `state_root` and `overlay`.
        pub fn prove_at(
            self: *Self,
            state_root: Hash,
            overlay: Overlay,
            address_hash: *const Hash,
            slot_hash: ?*const Hash,
            account_proof: anytype,
            storage_proof: anytype,
        ) Error!Leaf {
            if (self.fault) return error.Corrupt;
            self.view_begin(state_root, overlay);
            defer self.view_end();
            return self.prove(address_hash, slot_hash, account_proof, storage_proof);
        }

        /// What `verify_leaf` read through the trie.
        pub const Leaf = struct { account: ?AccountState, word: u256 };

        /// Reads the account at `address_hash` (and the slot at `slot_hash`) through the
        /// trie from the root: every node is rebuilt from branch records and flat leaves and
        /// checked against the hash its parent names, so a missing or wrong record on the
        /// path is `error.Corrupt` (an import's self-check). Writes nothing; walks as a block
        /// does (on the carried trie when there is one).
        pub fn verify_leaf(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: ?*const Hash,
        ) Error!Leaf {
            if (self.fault) return error.Corrupt;
            const carry = self.carry_ready();
            return self.read_leaf(address_hash, slot_hash, carry) catch |err| {
                if (!carry or self.fault) return err;
                self.stats.carry_retries += 1;
                return self.read_leaf(address_hash, slot_hash, false);
            };
        }

        fn read_leaf(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: ?*const Hash,
            carry: bool,
        ) Error!Leaf {
            self.begin_block(carry);
            // Reads only resolve nodes: a walk that succeeds leaves the trie at the root.
            self.carried = false;
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
            self.carried = true;
            return .{ .account = leaf_account, .word = word };
        }

        /// `eth_getProof` at the current root: `verify_leaf`'s walk (every node rebuilt and
        /// checked against its parent's hash), then the hashed nodes on the account's path into
        /// `account_proof` and, with `slot_hash`, on the slot's path into `storage_proof`
        /// (`trie.Proof` layout: root first; untouched without `slot_hash`). An absent key gets
        /// its exclusion proof; an absent account an empty storage proof. Writes nothing;
        /// only between blocks.
        pub fn prove(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: ?*const Hash,
            account_proof: anytype,
            storage_proof: anytype,
        ) Error!Leaf {
            const leaf = try self.verify_leaf(address_hash, slot_hash);
            try self.collect_proof(&self.state_root, address_hash, account_proof);
            if (slot_hash) |slot| {
                const owner = leaf.account orelse AccountState{
                    .nonce = 0,
                    .balance = 0,
                    .storage_root = node.empty_root,
                    .code_hash = node.empty_code_hash,
                };
                try self.collect_proof(&owner.storage_root, slot, storage_proof);
            }
            assert(account_proof.count > 0 or std.mem.eql(u8, &self.state_root, &node.empty_root));
            return leaf;
        }

        /// The hashed nodes from `root` along `key`, from the memo the walk just filled.
        fn collect_proof(
            self: *const Self,
            trie_root: *const Hash,
            key: *const Hash,
            proof: anytype,
        ) Error!void {
            proof.count = 0;
            if (std.mem.eql(u8, trie_root, &node.empty_root)) return;
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var ref = RlpNode.from_hash(trie_root.*);
            var depth: u32 = 0;
            while (depth < proof.ends.len) : (depth += 1) {
                var bytes = ref.slice();
                if (ref.is_hash()) {
                    const entry = self.memo.get_ptr(ref.bytes[1..33]) orelse {
                        return error.Corrupt;
                    };
                    if (entry.bytes_len == 0) return error.Corrupt;
                    bytes = self.entry_bytes(entry);
                    const start = if (proof.count == 0) 0 else proof.ends[proof.count - 1];
                    if (start + bytes.len > proof.buffer.len) return error.Full;
                    @memcpy(proof.buffer[start..][0..bytes.len], bytes);
                    proof.ends[proof.count] = @intCast(start + bytes.len);
                    proof.count += 1;
                }
                const decoded = sparse.decode_node(bytes) catch return error.Corrupt;
                switch (decoded.kind) {
                    .leaf => return,
                    .extension => {
                        const extension = decoded.path.slice();
                        if (!std.mem.startsWith(u8, rest, extension)) return;
                        rest = rest[extension.len..];
                        ref = decoded.children[0];
                    },
                    .branch => {
                        if (rest.len == 0) return;
                        ref = decoded.children[rest[0]];
                        if (ref.len == 0) return;
                        rest = rest[1..];
                    },
                }
            }
            return error.Corrupt; // Deeper than any key: a cycle of forged references.
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
            assert(self.overlay == null);
            if (self.fault) return error.Corrupt;
            const applied = if (forward) changeset else try self.reverse(changeset);
            try self.check_wipes(applied);
            const carry = self.carry_ready();
            self.apply_walk(applied, carry) catch |err| {
                // Busy is retried by the caller (fresh: the trie moved); a fault is final.
                if (!carry or err == error.Busy or self.fault) return err;
                self.stats.carry_retries += 1;
                return self.apply_walk(applied, false);
            };
        }

        fn apply_walk(self: *Self, applied: *const Changeset, carry: bool) Error!void {
            const start_ns = self.now_ns();
            self.begin_block(carry);
            // The trie moves to the post-state: carried again only once written back.
            self.carried = false;
            self.sparse_state.apply(applied) catch |err| return self.sparse_error(err);
            const updated_ns = self.now_ns();
            const new_root = self.sparse_state.state_root();
            if (self.memo_full) return error.Full;
            if (self.fault or self.corrupt) return error.Corrupt;
            const rooted_ns = self.now_ns();
            self.record_writes_len = 0;
            self.record_bytes_len = 0;
            if (self.capture) |*capture| {
                capture.old_bytes_len = 0;
                capture.failed = false;
            }
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
            self.carried = true;
            assert(!self.fault and !self.corrupt);
            if (self.capture) |*capture| {
                capture.forward = applied != &self.swapped;
                capture.sequence += 1;
            }
            const stats = &self.stats;
            stats.blocks += 1;
            stats.blocks_carried += @intFromBool(carry);
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

        /// Whether the next walk can start on the trie and memo the last one left: they hold
        /// the root and are small enough (else a fresh walk empties them). The memo stays at
        /// a sixteenth of its bounds: past that its lookups miss the CPU caches, and the
        /// record diff (thousands of lookups a block) costs more than carrying saves.
        fn carry_ready(self: *Self) bool {
            if (!self.carried) return false;
            const trie_nodes = &self.sparse_state.trie;
            const roomy = self.memo.count() <= self.config.memo_entries_max / 16 and
                self.memo_bytes_len <= self.memo_bytes.len / 16 and
                trie_nodes.free_count >= trie_nodes.nodes.len / 2 and
                self.sparse_state.storage_roots.count() <= self.config.storage_tries_max / 2;
            if (!roomy) return false;
            // Clean after a successful walk: the root hash is the cached one, not recomputed.
            return std.mem.eql(u8, &self.sparse_state.state_root(), &self.state_root);
        }

        /// Starts a walk at `state_root`: on the carried trie and memo (`carry`, which
        /// `carry_ready` allowed), else on empty ones.
        fn begin_block(self: *Self, carry: bool) void {
            self.corrupt = false;
            self.memo_full = false;
            if (carry) {
                assert(self.carried);
                assert(self.memo.count() > 0 or
                    std.mem.eql(u8, &self.state_root, &node.empty_root));
                return;
            }
            self.carried = false;
            self.memo.clear();
            self.memo_bytes_len = 0;
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
            _ = self.register_entry(hash, locator);
        }

        /// `register`, returning `hash`'s entry (null: absent and the memo is full).
        fn register_entry(self: *Self, hash: *const Hash, locator: Locator) ?*Entry {
            assert(self.memo.capacity() == self.config.memo_entries_max);
            const result = self.memo.get_or_put(hash) orelse {
                self.memo_full = true;
                return null;
            };
            if (!result.found_existing) result.value_ptr.* = .{ .locator = locator };
            assert(self.memo.count() <= self.config.memo_entries_max);
            return result.value_ptr;
        }

        /// Stores `bytes` as `hash`'s preimage (once) and returns the stored copy.
        fn store_bytes(self: *Self, hash: *const Hash, bytes: []const u8) ?[]const u8 {
            assert(bytes.len > 0);
            const entry = self.register_entry(hash, .bytes_only) orelse return null;
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
            const entry = self.memo.get_ptr(hash) orelse {
                self.corrupt = true;
                return null;
            };
            if (entry.bytes_len > 0) return self.entry_bytes(entry);
            // A copy, though entries never move: resolving adds entries.
            const locator = entry.locator;
            switch (locator) {
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
            // A cached value is decoded in place: nothing below touches the record cache
            // before the decode is done.
            const cached = self.record_cache.get(want, hang);
            if (cached != null) self.stats.record_cache_hits += 1;
            const value = cached orelse (self.read_record(owner, hang) orelse return null);
            var record: Record = undefined;
            branch_record.decode(value, &record) catch return self.fail();
            if (cached == null) {
                branch_record.validate_path(hang, &record) catch return self.fail();
            } else if (std.debug.runtime_safety) {
                // Cached records were validated at this hang (or built at it) when cached.
                branch_record.validate_path(hang, &record) catch unreachable;
            }
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
            if (self.overlay) |overlay| {
                var key_buffer: [branch_record.storage_key_bytes]u8 = undefined;
                var key: []const u8 = undefined;
                var kind: OverlayKind = undefined;
                if (owner) |hash| {
                    key_buffer = branch_record.storage_key(hash, hang);
                    key = key_buffer[0..];
                    kind = .storage_branch;
                } else {
                    key_buffer[0..branch_record.path_key_bytes].* = branch_record.path_key(hang);
                    key = key_buffer[0..branch_record.path_key_bytes];
                    kind = .account_branch;
                }
                switch (overlay.lookup(overlay.context, kind, key)) {
                    .trees => {},
                    .failed => return self.fail(),
                    .value => |value| {
                        const bytes = value orelse return self.fail();
                        if (bytes.len == 0 or bytes.len > branch_record.value_bytes_max) {
                            return self.fail();
                        }
                        return bytes;
                    },
                }
            }
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

        /// The node at `ref` (its reference bytes), decoded in place: from its inline bytes,
        /// its memo bytes, or (a leaf known only by its locator) its path alone.
        fn view(self: *const Self, ref: []const u8) Error!View {
            assert(ref.len > 0 and ref.len <= 33);
            var source = ref;
            if (ref.len == 33) {
                const entry = self.memo.get_ptr(ref[1..33]) orelse return error.Corrupt;
                if (entry.bytes_len == 0) return view_locator(&entry.locator);
                source = self.entry_bytes(entry);
            }
            const layout = sparse.decode_layout(source) catch return error.Corrupt;
            assert(layout.kind != .leaf or layout.path.len <= sparse.key_nibbles);
            return .{ .layout = layout, .source = source };
        }

        /// A node without bytes: only a leaf locator says what it is.
        fn view_locator(locator: *const Locator) Error!View {
            switch (locator.*) {
                .leaf => |*leaf| {
                    assert(leaf.depth < 64);
                    const key = Nibbles.from_bytes(&leaf.key);
                    return .{ .layout = .{
                        .kind = .leaf,
                        .path = Nibbles.from_nibbles(key.slice()[leaf.depth..]),
                    } };
                },
                .record, .bytes_only => return error.Corrupt,
            }
        }

        /// Whether the child at `ref` is a leaf, and then its path into `path`: `view`,
        /// except that a record never resolved (an untouched child of a changed branch) is
        /// known to be one by its locator.
        fn child_leaf(self: *const Self, ref: []const u8, path: *Nibbles) Error!bool {
            assert(ref.len > 0 and ref.len <= 33);
            if (ref.len == 33) {
                const entry = self.memo.get_ptr(ref[1..33]) orelse return error.Corrupt;
                if (entry.bytes_len == 0 and entry.locator == .record) return false;
            }
            const child = try self.view(ref);
            if (child.layout.kind != .leaf) return false;
            path.* = child.layout.path;
            return true;
        }

        /// Steps a cursor whose extension path is all behind it onto the branch below.
        /// Returns the cursor's node when the cursor stayed on it (null: none, or stepped).
        fn normalize(self: *const Self, cursor: *Cursor) Error!?View {
            if (cursor.is_none()) return null;
            const current = try self.view(cursor.ref.slice());
            if (current.layout.kind != .extension) return current;
            if (cursor.offset < current.layout.path.len) return current;
            assert(cursor.offset == current.layout.path.len);
            // Built aside: the child's bytes may lie in the cursor's own (inline) reference.
            const child = current.child_ref(0);
            cursor.* = .{ .ref = child };
            assert(!cursor.is_none());
            return null;
        }

        fn child_cursor(cursor: *const Cursor, current: ?*const View, nibble: u8) Cursor {
            const decoded = current orelse return .{};
            switch (decoded.layout.kind) {
                .leaf => return .{},
                .extension => {
                    assert(cursor.offset < decoded.layout.path.len);
                    if (decoded.layout.path.data[cursor.offset] != nibble) return .{};
                    return .{ .ref = cursor.ref, .offset = cursor.offset + 1 };
                },
                .branch => {
                    assert(cursor.offset == 0);
                    const child = decoded.child_ref(nibble);
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
                // Each side's node is decoded once: `normalize` hands it back unless it
                // stepped below an extension.
                var pre = try self.normalize(&frame.pre);
                var post = try self.normalize(&frame.post);
                if (frame.pre.eql(&frame.post)) continue;
                if (pre == null and !frame.pre.is_none()) {
                    pre = try self.view(frame.pre.ref.slice());
                }
                if (post == null and !frame.post.is_none()) {
                    post = try self.view(frame.post.ref.slice());
                }
                try self.diff_position(owner, position, &frame, opt(&pre), opt(&post));
                if (!descends(opt(&pre)) and !descends(opt(&post))) continue;
                if (frame.depth == 64) return error.Corrupt;
                frames_len = self.push_children(&frame, opt(&pre), opt(&post), frames_len);
            }
        }

        /// Pushes the frames of the children where the two sides differ, nibble 15 first.
        fn push_children(
            self: *Self,
            frame: *const Frame,
            pre: ?*const View,
            post: ?*const View,
            frames_len_start: u32,
        ) u32 {
            assert(frame.depth < 64);
            var frames_len = frames_len_start;
            var nibble: u8 = 16;
            while (nibble > 0) {
                nibble -= 1;
                const pre_child = child_cursor(&frame.pre, pre, nibble);
                const post_child = child_cursor(&frame.post, post, nibble);
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
            assert(frames_len - frames_len_start <= 16);
            return frames_len;
        }

        fn opt(decoded: *const ?View) ?*const View {
            if (decoded.*) |*value| return value;
            return null;
        }

        /// Only extensions and branches have records below them (leaves end the path).
        fn descends(decoded: ?*const View) bool {
            const value = decoded orelse return false;
            return value.layout.kind != .leaf;
        }

        /// Whether the cursor's node is a record's top at `position`.
        fn is_record_top(
            position: []const u8,
            cursor: *const Cursor,
            decoded: ?*const View,
        ) bool {
            const value = decoded orelse return false;
            if (cursor.offset != 0) return false;
            if (!cursor.hangs and position.len > 0) return false;
            // A leaf is a record (a leaf root) only as a whole trie.
            return value.layout.kind != .leaf or position.len == 0;
        }

        /// The record write at `position`: the post-state's record, else a tombstone where
        /// only the pre-state had one. The cursors differ, so a record in both differs too.
        fn diff_position(
            self: *Self,
            owner: ?Hash,
            position: []const u8,
            frame: *const Frame,
            pre: ?*const View,
            post: ?*const View,
        ) Error!void {
            const pre_record = is_record_top(position, &frame.pre, pre);
            const old = if (pre_record) self.capture_record(position, pre.?) else null;
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
                return self.add_write(owner, position, value, old);
            }
            if (pre_record) return self.add_write(owner, position, null, old);
        }

        /// Under capture: the pre-state record at `position` into the capture's bytes.
        fn capture_record(
            self: *Self,
            position: []const u8,
            top: *const View,
        ) ?OldRange {
            const capture = &(self.capture orelse return null);
            if (capture.failed) return null;
            var record: Record = .{};
            self.build_record(position, top, &record) catch {
                capture.failed = true;
                return null;
            };
            branch_record.validate_path(position, &record) catch {
                capture.failed = true;
                return null;
            };
            var buffer: [branch_record.value_bytes_max]u8 = undefined;
            const value = branch_record.encode(&record, &buffer);
            assert(value.len > 0);
            if (capture.old_bytes.len - capture.old_bytes_len < value.len) {
                capture.failed = true;
                return null;
            }
            const start = capture.old_bytes_len;
            @memcpy(capture.old_bytes[start..][0..value.len], value);
            capture.old_bytes_len += @intCast(value.len);
            return .{ .start = start, .len = @intCast(value.len) };
        }

        const OldRange = struct { start: u32, len: u32 };

        fn build_record(
            self: *const Self,
            position: []const u8,
            top: *const View,
            record: *Record,
        ) Error!void {
            const layout = &top.layout;
            switch (layout.kind) {
                .leaf => {
                    assert(position.len == 0);
                    if (layout.path.len != 64) return error.Corrupt;
                    var key: Hash = undefined;
                    _ = layout.path.pack(&key);
                    record.* = branch_record.leaf_root(&key);
                },
                .extension => {
                    record.extension_len = layout.path.len;
                    @memcpy(record.extension[0..layout.path.len], layout.path.slice());
                    const child = top.child_ref(0);
                    const branch = try self.view(child.slice());
                    if (branch.layout.kind != .branch) return error.Corrupt;
                    var path = Nibbles.from_nibbles(position);
                    if (path.len + layout.path.len >= 64) return error.Corrupt;
                    path.append(layout.path.slice());
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
            branch: *const View,
            record: *Record,
        ) Error!void {
            assert(branch.layout.kind == .branch);
            if (branch_path.len >= 64) return error.Corrupt;
            var child: u32 = 0;
            var leaf: u32 = 0;
            for (branch.layout.child_offsets, 0..) |offset, nibble| {
                if (offset == 0) continue;
                const bit = @as(u16, 1) << @intCast(nibble);
                record.state_mask |= bit;
                record.children[child] = sparse.child_ref_at(branch.source, offset);
                const ref = &record.children[child];
                child += 1;
                var suffix: Nibbles = undefined;
                if (!try self.child_leaf(ref.slice(), &suffix)) {
                    record.tree_mask |= bit;
                    continue;
                }
                if (branch_path.len + 1 + suffix.len != 64) return error.Corrupt;
                var key = Nibbles.from_nibbles(branch_path);
                key.push(@intCast(nibble));
                key.append(suffix.slice());
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
            old: ?OldRange,
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
                .old_start = if (old) |range| range.start else 0,
                .old_len = if (old) |range| range.len else 0,
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
            write.old = null;
            if (self.capture != null) {
                // The trees still hold the pre-state: no write happened yet this block.
                if (self.account(&write.key)) |pre| {
                    write.old = flat_trees_module.account_encode(&pre.info, &pre.storage_root);
                }
            }
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

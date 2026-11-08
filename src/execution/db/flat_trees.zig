//! Flat trees: the LSM trees of flat state on the grid (disk state phase 2b; `Config.flat_trees`).
//! `Database` shadow-writes every committed changeset into the account and storage trees;
//! `State`'s flat hash tables stay the source of truth, and the trees are derived data that
//! must equal them. The two branch-record trees are written by a bulk import and by
//! `DiskState` (`disk_state.zig`), which also writes accounts and slots in disk mode.
//!
//! - Account tree: key keccak256(address) (32 B), value the account record (104 B: nonce u64
//!   big-endian, balance u256 big-endian, code hash, storage root; the empty trie root for an
//!   account without storage), so a record is a whole account-trie leaf and answers EIP-7610's
//!   "has storage". A removed account is a tombstone.
//! - Storage tree: key keccak256(address) ++ keccak256(slot) (64 B), value the slot word
//!   (32 B big-endian); a zero value is a tombstone (a zero slot does not exist).
//! - Account-branch tree: key `branch_record.path_key` (33 B), value a branch record
//!   (`branch_record.encode`, 6..`branch_record.value_bytes_max` bytes).
//! - Storage-branch tree: key `branch_record.storage_key` (65 B: owner ++ path key), same
//!   values.
//!
//! Writes: a head move writes each unwound changeset's old values, then each applied
//! changeset's new values (`write`), right after `State` moved by that changeset; changesets
//! carry absolute values, so the trees end equal to `State`. Account records also carry the
//! storage root, so every address whose storage changed gets a record (taken from `State`)
//! even when its account info did not change. A live head move first checks that the mutable
//! memtables have room for every put it can make (`reserve`, counts from the encoded
//! changeset headers: an account put per account entry and per storage entry at most);
//! without room it paces compaction once more and the operation returns `error.Busy` before
//! any change. Journal replay after open writes through `put_replay` into the replay reserve.
//!
//! Replay reserve (`tree_config`): replay after open cannot compact (no grid IO before the
//! engine is ready), so every distinct key replay writes must fit one memtable's reserve.
//! Each such key comes from a changeset entry in the journal or in a retained block (an
//! account record from an account entry or from a storage entry of its address), and an
//! entry is at least `account_put_bytes_min` (or `storage_put_bytes_min`) encoded bytes, so
//! (journal bytes + retained chain bytes) / entry bytes bounds it. The branch trees get no
//! replay reserve unless in disk mode (`Database.Config.disk_state`, where `DiskState` writes
//! them): then `branch_replay_entries`, which the database's admission keeps the journal
//! within, and `branch_operation_entries` of room for one head move.
//!
//! Sizes: key limits are `u64` and independent of `State.Config` (which sizes RAM tables), and
//! tables are cut at one index block's worth of records (`table_records_cap`), independent of
//! the memtable size: a flush may write several level-0 tables.
//!
//! Bulk import (`bulk_begin`..`bulk_end`): one sorted stream per tree into empty trees, straight
//! into their last levels (`lsm_bulk.zig`); nothing is durable until the next checkpoint.
//! Point reads (`get_account`, `get_slot`, `get_branch`) are synchronous (`Tree.get`).
//!
//! Checkpoint (inside the database checkpoint): length-prefixed tree bytes of the account,
//! storage, account-branch, and storage-branch trees, in that order (`lsm.zig`'s manifest,
//! memtables, and orphans). Open decodes them in the engine's open pause and scans every tree
//! (`open_scan`) before the snapshot loads.

const std = @import("std");
const assert = std.debug.assert;

const lsm = @import("storage/lsm.zig");
const lsm_bulk = @import("storage/lsm_bulk.zig");
const table_module = @import("storage/table.zig");
const free_set_module = @import("storage/free_set.zig");
const changeset_module = @import("changeset.zig");
const branch_record = @import("branch_record.zig");
const prefetch_module = @import("prefetch.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const node = @import("../trie/node.zig");

const Changeset = changeset_module.Changeset;
const AccountInfo = changeset_module.AccountInfo;
const Address = changeset_module.Address;
const Hash = changeset_module.Hash;
const FreeSet = free_set_module.FreeSet;
const BlockCache = table_module.BlockCache;

pub const account_key_size: u32 = 32;
pub const account_value_size: u32 = 8 + 32 + 32 + 32;
pub const storage_key_size: u32 = 64;
pub const storage_value_size: u32 = 32;
pub const account_branch_key_size: u32 = branch_record.path_key_bytes;
pub const storage_branch_key_size: u32 = branch_record.storage_key_bytes;
pub const branch_value_size_max: u32 = branch_record.value_bytes_max;
/// Encoded bytes of one side of a changeset account entry (nonce, balance, code hash).
const changeset_account_side_bytes: u32 = 8 + 32 + 32;
/// Smallest encoded changeset entry per put: an account change with one side, a slot change.
pub const account_put_bytes_min: u32 = 20 + 1 + changeset_account_side_bytes;
pub const storage_put_bytes_min: u32 = 20 + 3 * 32;

comptime {
    assert(account_value_size == 104);
    assert(account_branch_key_size == 33 and storage_branch_key_size == 65);
    assert(storage_put_bytes_min > account_put_bytes_min);
}

/// An account record: the account and its storage root.
pub const Account = struct {
    info: AccountInfo,
    storage_root: Hash,

    pub fn eql(a: Account, b: Account) bool {
        return a.info.eql(b.info) and std.mem.eql(u8, &a.storage_root, &b.storage_root);
    }
};

pub const Config = struct {
    block_size: u32,
    /// Grid blocks (addresses `1..block_count`).
    block_count: u64,
    /// Journal bytes and retained chain bytes: the replay reserve's bound.
    journal_bytes: u64,
    chain_bytes: u64,
    /// Largest journal entry body: with `chain_bytes`, the most one head move writes.
    entry_body_bytes: u64,
    /// Live keys per tree at most: they size the levels (not RAM tables).
    accounts_max: u64,
    slots_max: u64,
    account_branches_max: u64,
    storage_branches_max: u64,
    /// Mutable memtable entries at which the account and storage trees flush.
    flush_entries_min: u32,
    /// Mutable memtable entries at which a branch tree flushes (its memtables hold twice as
    /// many; entries are up to ~1.1 KiB of static memory each). Level sizes grow from it, so
    /// it bounds the keys a tree can hold: 8 x it x 8^6 (1024: ~2.1B keys, 4096: ~8.6B).
    branch_flush_entries_min: u32,
    /// Disk mode: branch puts one live head move makes at most (normal puts always fit below
    /// the flush trigger, so a refused move clears once the memtables swap), and branch puts
    /// a journal replay may make (its reserve). Zero without disk mode.
    branch_operation_entries: u32 = 0,
    branch_replay_entries: u32 = 0,
    /// Blocks of the block cache every tree's reads share.
    cache_blocks: u32,
    /// Keys one prefetch names and reads it keeps in flight (`prefetch.zig`); 0: none.
    prefetch_keys_max: u32 = 0,
    prefetch_reads_max: u32 = 0,
};

/// Records one table of `Tree` holds within one index block when values are their largest
/// (the most a table may be cut at; `lsm.zig` `layout_of`).
pub fn table_records_cap(comptime Tree: type, block_size: u32) u32 {
    const room = Tree.Table.data_room(block_size);
    const full = room / (Tree.key_bytes + Tree.value_bytes + 4);
    assert(full >= 1);
    const index_capacity = Tree.Table.index_capacity(block_size);
    assert(index_capacity >= 2);
    return (index_capacity - 1) * full;
}

/// Levels for a tree whose level 1 holds `level1_records`: the last level holds at least
/// twice the live keys (a full last level is a config error); each level up to it is
/// `growth_factor` times the one before.
fn levels_for(level1_records: u64, keys_max: u64, growth_factor: u32) u32 {
    assert(level1_records > 0 and growth_factor >= 2);
    const target = 2 *| keys_max;
    var levels: u32 = 2;
    var capacity: u64 = level1_records;
    while (capacity < target and levels < lsm.levels_max) : (levels += 1) {
        capacity *|= growth_factor;
    }
    assert(capacity >= target);
    return levels;
}

/// The tree config for keys whose changeset entries are at least `put_bytes_min` bytes and
/// that hold at most `keys_max` live keys; tables hold at most `records_cap` records.
pub fn tree_config(
    config: Config,
    put_bytes_min: u32,
    keys_max: u64,
    records_cap: u32,
) lsm.Config {
    assert(put_bytes_min > 0 and config.flush_entries_min > 0);
    assert(records_cap > 0);
    const replay = (config.journal_bytes + config.chain_bytes) / put_bytes_min + 1;
    const operation = (config.chain_bytes + config.entry_body_bytes) / put_bytes_min + 1;
    // Normal puts stop at `flush_entries_min + operation`: below the flush trigger a head
    // move always fits, and at it the memtables swap once the pending flush is done.
    const memtable = config.flush_entries_min + operation + replay;
    assert(memtable < std.math.maxInt(u32) / 4);
    const level0_tables_max: u32 = 4;
    const growth_factor: u32 = 8;
    return .{
        .block_size = config.block_size,
        .block_count = config.block_count,
        .memtable_entries_max = @intCast(memtable),
        .flush_entries_min = config.flush_entries_min,
        .replay_entries_max = @intCast(replay),
        .table_records_max = @intCast(@min(memtable, records_cap)),
        .level0_tables_max = level0_tables_max,
        .levels_count = levels_for(level0_tables_max * memtable, keys_max, growth_factor),
        .growth_factor = growth_factor,
    };
}

/// The tree config of a branch tree: twice the flush trigger, plus (disk mode) one head move's
/// branch puts and the replay reserve. Normal puts stop at `2 x flush + operation`: below the
/// flush trigger more than `operation` entries are always free, so a move refused for room
/// fits once the memtables swap.
pub fn branch_tree_config(config: Config, keys_max: u64, records_cap: u32) lsm.Config {
    assert(config.branch_flush_entries_min > 0 and records_cap > 0);
    const memtable: u64 = 2 * @as(u64, config.branch_flush_entries_min) +
        config.branch_operation_entries + config.branch_replay_entries;
    assert(memtable < std.math.maxInt(u32) / 4);
    const level0_tables_max: u32 = 4;
    const growth_factor: u32 = 8;
    return .{
        .block_size = config.block_size,
        .block_count = config.block_count,
        .memtable_entries_max = @intCast(memtable),
        .flush_entries_min = config.branch_flush_entries_min,
        .replay_entries_max = config.branch_replay_entries,
        .table_records_max = @intCast(@min(memtable, records_cap)),
        .level0_tables_max = level0_tables_max,
        .levels_count = levels_for(level0_tables_max * memtable, keys_max, growth_factor),
        .growth_factor = growth_factor,
    };
}

pub fn account_encode(info: *const AccountInfo, storage_root: *const Hash) [account_value_size]u8 {
    var out: [account_value_size]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], info.nonce, .big);
    std.mem.writeInt(u256, out[8..40], info.balance, .big);
    out[40..72].* = info.code_hash;
    out[72..104].* = storage_root.*;
    assert(std.mem.eql(u8, out[72..104], storage_root));
    return out;
}

pub fn account_decode(bytes: *const [account_value_size]u8) Account {
    return .{
        .info = .{
            .nonce = std.mem.readInt(u64, bytes[0..8], .big),
            .balance = std.mem.readInt(u256, bytes[8..40], .big),
            .code_hash = bytes[40..72].*,
        },
        .storage_root = bytes[72..104].*,
    };
}

pub fn storage_key(address_hash: *const Hash, slot: u256) [storage_key_size]u8 {
    var slot_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &slot_bytes, slot, .big);
    return storage_key_hashed(address_hash, &node.keccak256(&slot_bytes));
}

pub fn storage_key_hashed(address_hash: *const Hash, slot_hash: *const Hash) [storage_key_size]u8 {
    var key: [storage_key_size]u8 = undefined;
    key[0..32].* = address_hash.*;
    key[32..64].* = slot_hash.*;
    return key;
}

pub const Puts = struct {
    accounts: u64 = 0,
    storage: u64 = 0,
    account_branches: u64 = 0,
    storage_branches: u64 = 0,
};

pub const Stats = struct {
    /// Head moves refused for memtable room (`reserve`).
    busy: u64 = 0,
    puts_accounts: u64 = 0,
    puts_storage: u64 = 0,
    /// Account records written for an address whose only change was storage.
    puts_storage_only_accounts: u64 = 0,
};

/// The trees' fields, in checkpoint and scan order.
const tree_names = [_][]const u8{ "accounts", "storage", "account_branches", "storage_branches" };
pub const tree_count: u32 = tree_names.len;

pub fn FlatTreesType(comptime Storage: type) type {
    return struct {
        const Self = @This();

        pub const AccountTree = lsm.TreeType(Storage, account_key_size, account_value_size);
        pub const StorageTree = lsm.TreeType(Storage, storage_key_size, storage_value_size);
        pub const AccountBranchTree = lsm.TreeVariableType(
            Storage,
            account_branch_key_size,
            branch_value_size_max,
        );
        pub const StorageBranchTree = lsm.TreeVariableType(
            Storage,
            storage_branch_key_size,
            branch_value_size_max,
        );
        pub const Grid = AccountTree.Grid;
        pub const Callback = *const fn (*Self) void;
        pub const ScanOutcome = lsm.ScanOutcome;
        pub const Mode = enum { live, replay };
        pub const BulkError = lsm_bulk.Error;
        pub const Bulk = BulkType(Self);
        pub const Prefetch = prefetch_module.PrefetchType(Self);

        cache: *BlockCache,
        accounts: AccountTree,
        storage: StorageTree,
        account_branches: AccountBranchTree,
        storage_branches: StorageBranchTree,
        /// The running bulk import's loaders (`bulk_begin`..`bulk_end`), boxed: they must not
        /// move while loading.
        bulk: ?*Bulk = null,
        /// Reads a set of keys' blocks into the cache ahead of their point reads; null
        /// unless configured. Boxed: its grid reads point into it.
        prefetch: ?*Prefetch = null,
        /// The callback's context, set by the owner before a scan.
        owner: ?*anyopaque = null,
        scan_callback: ?Callback = null,
        /// Fires after any tree installs a compaction job while the owner waits for
        /// `checkpoint_ready` (`checkpoint_prepare`).
        install_callback: ?Callback = null,
        scan_outcome: ScanOutcome = .loaded,
        stats: Stats = .{},

        /// `grid` is used for its block size here; `bind` names the engine's grid and free
        /// set before the open scan (the owner moves after init, so the cache is boxed).
        pub fn init(allocator: std.mem.Allocator, grid: *Grid, config: Config) !Self {
            assert(config.block_size == grid.config.block_size);
            assert(config.cache_blocks > 0);
            const block_size = config.block_size;
            const cache = try allocator.create(BlockCache);
            errdefer allocator.destroy(cache);
            cache.* = try BlockCache.init(allocator, block_size, config.cache_blocks);
            errdefer cache.deinit(allocator);
            const configs = tree_configs(config);
            var accounts = try AccountTree.init(allocator, grid, cache, configs.accounts);
            errdefer accounts.deinit(allocator);
            var storage = try StorageTree.init(allocator, grid, cache, configs.storage);
            errdefer storage.deinit(allocator);
            var account_branches =
                try AccountBranchTree.init(allocator, grid, cache, configs.account_branches);
            errdefer account_branches.deinit(allocator);
            var storage_branches =
                try StorageBranchTree.init(allocator, grid, cache, configs.storage_branches);
            errdefer storage_branches.deinit(allocator);
            assert((config.prefetch_keys_max == 0) == (config.prefetch_reads_max == 0));
            const prefetch = if (config.prefetch_keys_max == 0) null else try Prefetch.create(
                allocator,
                .{ .keys_max = config.prefetch_keys_max, .reads_max = config.prefetch_reads_max },
                block_size,
            );
            return .{
                .prefetch = prefetch,
                .cache = cache,
                .accounts = accounts,
                .storage = storage,
                .account_branches = account_branches,
                .storage_branches = storage_branches,
            };
        }

        pub const TreeConfigs = struct {
            accounts: lsm.Config,
            storage: lsm.Config,
            account_branches: lsm.Config,
            storage_branches: lsm.Config,
        };

        /// The four trees' configs (`init` builds them from these).
        pub fn tree_configs(config: Config) TreeConfigs {
            const block_size = config.block_size;
            const configs: TreeConfigs = .{
                .accounts = tree_config(
                    config,
                    account_put_bytes_min,
                    config.accounts_max,
                    table_records_cap(AccountTree, block_size),
                ),
                .storage = tree_config(
                    config,
                    storage_put_bytes_min,
                    config.slots_max,
                    table_records_cap(StorageTree, block_size),
                ),
                .account_branches = branch_tree_config(
                    config,
                    config.account_branches_max,
                    table_records_cap(AccountBranchTree, block_size),
                ),
                .storage_branches = branch_tree_config(
                    config,
                    config.storage_branches_max,
                    table_records_cap(StorageBranchTree, block_size),
                ),
            };
            assert(configs.accounts.block_size == block_size);
            assert(configs.storage_branches.block_size == block_size);
            return configs;
        }

        /// `checkpoint_size_max` of trees with `config`, without building them (sizing a
        /// database's checkpoint staging before `init`).
        pub fn checkpoint_size_max_of(config: Config) u64 {
            const configs = tree_configs(config);
            var size: u64 = 4 * tree_count;
            size += AccountTree.checkpoint_size_max_of(configs.accounts);
            size += StorageTree.checkpoint_size_max_of(configs.storage);
            size += AccountBranchTree.checkpoint_size_max_of(configs.account_branches);
            size += StorageBranchTree.checkpoint_size_max_of(configs.storage_branches);
            assert(size > 4 * tree_count);
            return size;
        }

        /// Frees memory. Grid IO may be in flight only if the storage dropped it (crash).
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.bulk) |bulk| bulk.destroy(allocator);
            if (self.prefetch) |prefetch| prefetch.destroy(allocator);
            inline for (tree_names) |name| @field(self, name).deinit(allocator);
            self.cache.deinit(allocator);
            allocator.destroy(self.cache);
            self.* = undefined;
        }

        pub fn bind(self: *Self, grid: *Grid, free_set: *FreeSet) void {
            assert(self.scan_callback == null);
            assert(self.bulk == null);
            inline for (tree_names) |name| @field(self, name).bind(grid, free_set);
        }

        /// Empty trees (a fresh database).
        pub fn reset(self: *Self) void {
            assert(self.scan_callback == null);
            assert(self.bulk == null);
            inline for (tree_names) |name| @field(self, name).reset();
        }

        /// No grid IO in flight and no lookup pending (the owner may be freed).
        pub fn idle(self: *const Self) bool {
            if (self.bulk) |bulk| if (!bulk.idle()) return false;
            if (self.prefetch) |prefetch| if (!prefetch.idle()) return false;
            inline for (tree_names) |name| {
                const tree = &@field(self, name);
                if (tree.compaction.io_pending or tree.lookup_active) return false;
            }
            return true;
        }

        /// One commit's compaction budget for every tree; none while a bulk import runs.
        pub fn compact(self: *Self, blocks: u64) void {
            assert(blocks > 0);
            if (self.bulk != null) return;
            inline for (tree_names) |name| @field(self, name).compact(blocks);
        }

        /// Puts a head move's changesets can make (at most: the encoded entry counts; every
        /// storage entry may add its address's account record).
        pub fn puts_add(puts: *Puts, encoded: []const u8) changeset_module.Error!void {
            const counts = try Changeset.encoded_counts(encoded);
            puts.accounts += @as(u64, counts.accounts) + counts.storage;
            puts.storage += counts.storage;
        }

        /// Room check before a live head move: without room every tree gets one more
        /// compaction grant (so a stalled swap or flush moves on) and the move is refused.
        pub fn reserve(self: *Self, puts: Puts, blocks: u64) error{Busy}!void {
            assert(blocks > 0);
            assert(self.bulk == null);
            const fits = puts.accounts <= self.accounts.capacity_free() and
                puts.storage <= self.storage.capacity_free() and
                puts.account_branches <= self.account_branches.capacity_free() and
                puts.storage_branches <= self.storage_branches.capacity_free();
            if (fits) return;
            self.stats.busy += 1;
            self.compact(blocks);
            return error.Busy;
        }

        /// Writes the values `changeset` leaves (`forward`) or the ones it replaced, right
        /// after `State` moved by it: `source` is that state, read for account records of
        /// storage-only addresses (`basic(Address) ?AccountInfo`) and for every record's
        /// storage root (`storage_root(*const Hash) Hash`, by address hash). Live writes were
        /// reserved (`reserve`); replay writes use the replay reserve, and `error.Busy` there
        /// means the reserve was sized too small (open fails).
        pub fn write(
            self: *Self,
            changeset: *const Changeset,
            forward: bool,
            mode: Mode,
            source: anytype,
        ) error{Busy}!void {
            assert(self.bulk == null);
            const accounts_before = self.stats.puts_accounts;
            const storage_before = self.stats.puts_storage;
            const only_before = self.stats.puts_storage_only_accounts;
            try self.write_accounts(changeset.account_changes(), forward, mode, source);
            try self.write_storage(changeset.storage_changes(), forward, mode);
            try self.write_storage_only_accounts(changeset, mode, source);
            const only = self.stats.puts_storage_only_accounts - only_before;
            assert(only <= changeset.storage_len);
            assert(self.stats.puts_accounts == accounts_before + changeset.accounts_len + only);
            assert(self.stats.puts_storage == storage_before + changeset.storage_len);
        }

        fn write_accounts(
            self: *Self,
            changes: []const changeset_module.AccountChange,
            forward: bool,
            mode: Mode,
            source: anytype,
        ) error{Busy}!void {
            var hashes: [keccak.batch_width]Hash = undefined;
            var start: usize = 0;
            while (start < changes.len) : (start += keccak.batch_width) {
                const chunk = changes[start..@min(changes.len, start + keccak.batch_width)];
                hash_addresses(chunk, hashes[0..chunk.len]);
                for (chunk, hashes[0..chunk.len]) |*change, *key| {
                    const target = if (forward) change.new else change.old;
                    if (target) |info| {
                        const value = account_encode(&info, &source.storage_root(key));
                        try put(AccountTree, &self.accounts, key, &value, mode);
                    } else {
                        try put(AccountTree, &self.accounts, key, null, mode);
                    }
                    self.stats.puts_accounts += 1;
                }
            }
            assert(start >= changes.len);
        }

        /// Storage changes are sorted by address: the address hash is computed once per run.
        fn write_storage(
            self: *Self,
            changes: []const changeset_module.StorageChange,
            forward: bool,
            mode: Mode,
        ) error{Busy}!void {
            var slot_hashes: [keccak.batch_width]Hash = undefined;
            var address_hash: Hash = undefined;
            var address_last: ?Address = null;
            var start: usize = 0;
            while (start < changes.len) : (start += keccak.batch_width) {
                const chunk = changes[start..@min(changes.len, start + keccak.batch_width)];
                hash_slots(chunk, slot_hashes[0..chunk.len]);
                for (chunk, slot_hashes[0..chunk.len]) |*change, *slot_hash| {
                    const same = if (address_last) |last|
                        std.mem.eql(u8, &last, &change.address)
                    else
                        false;
                    if (!same) {
                        address_hash = node.keccak256(&change.address);
                        address_last = change.address;
                    }
                    const key = storage_key_hashed(&address_hash, slot_hash);
                    const word = if (forward) change.new else change.old;
                    if (word == 0) {
                        try put(StorageTree, &self.storage, &key, null, mode);
                    } else {
                        var value: [storage_value_size]u8 = undefined;
                        std.mem.writeInt(u256, &value, word, .big);
                        try put(StorageTree, &self.storage, &key, &value, mode);
                    }
                    self.stats.puts_storage += 1;
                }
            }
            assert(start >= changes.len);
        }

        /// An account record for every address with storage changes but no account change:
        /// its storage root changed. Both lists are sorted by address (one merge pass).
        fn write_storage_only_accounts(
            self: *Self,
            changeset: *const Changeset,
            mode: Mode,
            source: anytype,
        ) error{Busy}!void {
            const accounts = changeset.account_changes();
            const changes = changeset.storage_changes();
            var account_index: usize = 0;
            var start: usize = 0;
            while (start < changes.len) {
                const address = &changes[start].address;
                var end = start + 1;
                while (end < changes.len and std.mem.eql(u8, &changes[end].address, address)) {
                    end += 1;
                }
                start = end;
                while (account_index < accounts.len and
                    std.mem.order(u8, &accounts[account_index].address, address) == .lt)
                {
                    account_index += 1;
                }
                if (account_index < accounts.len and
                    std.mem.eql(u8, &accounts[account_index].address, address)) continue;
                // Storage changes only under an account that exists afterwards: a removed
                // account has an account change.
                const info = source.basic(address.*).?;
                const key = node.keccak256(address);
                const value = account_encode(&info, &source.storage_root(&key));
                try put(AccountTree, &self.accounts, &key, &value, mode);
                self.stats.puts_accounts += 1;
                self.stats.puts_storage_only_accounts += 1;
            }
            assert(start == changes.len);
        }

        fn put(
            comptime Tree: type,
            tree: *Tree,
            key: *const Tree.Key,
            value: ?*const Tree.Value,
            mode: Mode,
        ) error{Busy}!void {
            switch (mode) {
                .live => try tree.put(key, value),
                .replay => try tree.put_replay(key, value),
            }
        }

        // Synchronous point reads (`Tree.get`: blocking grid reads). A block that fails to
        // verify returns `error.Corrupt` and faults its tree.

        /// The account record of `address_hash`, or null when absent.
        pub fn get_account(self: *Self, address_hash: *const Hash) lsm.Error!?Account {
            const bytes = try self.accounts.get(address_hash) orelse return null;
            assert(bytes.len == account_value_size);
            return account_decode(bytes[0..account_value_size]);
        }

        /// The slot word (0 when absent).
        pub fn get_slot(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: *const Hash,
        ) lsm.Error!u256 {
            const key = storage_key_hashed(address_hash, slot_hash);
            const bytes = try self.storage.get(&key) orelse return 0;
            assert(bytes.len == storage_value_size);
            const word = std.mem.readInt(u256, bytes[0..32], .big);
            // A zero slot is a tombstone, never a stored value.
            if (word == 0) return error.Corrupt;
            return word;
        }

        /// The branch record bytes hanging at `hang` (nibbles) in the account trie (`owner`
        /// null) or in `owner`'s storage trie; null when absent. Valid until the next read of
        /// that tree; decode with `branch_record.decode`.
        pub fn get_branch(
            self: *Self,
            owner: ?*const Hash,
            hang: []const u8,
        ) lsm.Error!?[]const u8 {
            assert(hang.len <= branch_record.hang_nibbles_max);
            const bytes = if (owner) |hash| bytes: {
                const key = branch_record.storage_key(hash, hang);
                break :bytes try self.storage_branches.get(&key);
            } else bytes: {
                const key = branch_record.path_key(hang);
                break :bytes try self.account_branches.get(&key);
            };
            if (bytes) |value| assert(value.len >= 1 and value.len <= branch_value_size_max);
            return bytes;
        }

        // Bulk import: one sorted stream per tree into empty trees (`lsm_bulk.zig`).

        /// Starts a bulk import into all four trees, which must be empty (bound, nothing
        /// running). Compaction pauses until `bulk_end`; do not checkpoint before it.
        pub fn bulk_begin(self: *Self, allocator: std.mem.Allocator) !void {
            assert(self.bulk == null);
            assert(self.scan_callback == null);
            self.bulk = try Bulk.create(allocator, self);
            assert(self.bulk.?.trees == self);
        }

        /// Appends an account record; address hashes strictly ascending.
        pub fn bulk_append_account(
            self: *Self,
            address_hash: *const Hash,
            account: *const Account,
        ) BulkError!void {
            const value = account_encode(&account.info, &account.storage_root);
            return self.bulk.?.accounts.append(address_hash, &value);
        }

        /// Appends a non-zero slot; keys (address hash, slot hash) strictly ascending.
        pub fn bulk_append_slot(
            self: *Self,
            address_hash: *const Hash,
            slot_hash: *const Hash,
            word: u256,
        ) BulkError!void {
            assert(word != 0);
            const key = storage_key_hashed(address_hash, slot_hash);
            var value: [storage_value_size]u8 = undefined;
            std.mem.writeInt(u256, &value, word, .big);
            return self.bulk.?.storage.append(&key, &value);
        }

        /// Appends an account-trie branch record (`branch_record.encode`) at its path key
        /// (`branch_record.path_key`); keys strictly ascending (post-order).
        pub fn bulk_append_account_branch(
            self: *Self,
            key: *const [account_branch_key_size]u8,
            value: []const u8,
        ) BulkError!void {
            assert(value.len >= 1 and value.len <= branch_value_size_max);
            return self.bulk.?.account_branches.append(key, value);
        }

        /// Appends a storage-trie branch record at its key (`branch_record.storage_key`).
        pub fn bulk_append_storage_branch(
            self: *Self,
            key: *const [storage_branch_key_size]u8,
            value: []const u8,
        ) BulkError!void {
            assert(value.len >= 1 and value.len <= branch_value_size_max);
            return self.bulk.?.storage_branches.append(key, value);
        }

        /// Resumes loads stalled on another writer's free-set reservation (after ticking).
        pub fn bulk_poll(self: *Self) void {
            const bulk = self.bulk.?;
            inline for (tree_names) |name| {
                const loader = &@field(bulk, name);
                if (loader.active) loader.poll();
            }
        }

        /// Writes what every loader has staged; `callback` fires once all four tables lists
        /// are installed or failed (maybe before this returns). Then call `bulk_end`.
        pub fn bulk_finish(self: *Self, callback: Callback) void {
            const bulk = self.bulk.?;
            assert(bulk.callback == null and bulk.pending == 0);
            bulk.callback = callback;
            bulk.pending = tree_count;
            inline for (tree_names) |name| {
                @field(bulk, name).finish(Bulk.on_loaded(name));
            }
        }

        /// Frees the loaders after `bulk_finish` called back; returns the first failure.
        pub fn bulk_end(self: *Self, allocator: std.mem.Allocator) BulkError!void {
            const bulk = self.bulk.?;
            assert(bulk.pending == 0 and bulk.idle());
            var failure: ?BulkError = null;
            inline for (tree_names) |name| {
                const loader = &@field(bulk, name);
                assert(!loader.active);
                loader.result catch |err| {
                    if (failure == null) failure = err;
                };
            }
            bulk.destroy(allocator);
            self.bulk = null;
            inline for (tree_names) |name| assert(!@field(self, name).bulk_active);
            if (failure) |err| return err;
        }

        // Checkpoint: per tree (in `tree_names` order) u32 length + the tree's bytes.

        pub fn checkpoint_size_max(self: *const Self) u64 {
            var size: u64 = 4 * tree_count;
            inline for (tree_names) |name| size += @field(self, name).checkpoint_size_max();
            return size;
        }

        pub fn checkpoint_size(self: *Self) u64 {
            var size: u64 = 4 * tree_count;
            inline for (tree_names) |name| size += @field(self, name).checkpoint_size();
            return size;
        }

        /// Writes every tree's checkpoint bytes (at the engine checkpoint's snapshot point).
        pub fn checkpoint_encode(self: *Self, out: []u8) u32 {
            assert(self.bulk == null);
            const size = self.checkpoint_size();
            assert(out.len >= size);
            var offset: usize = 0;
            inline for (tree_names) |name| {
                const length = @field(self, name).checkpoint_encode(out[offset + 4 ..]);
                std.mem.writeInt(u32, out[offset..][0..4], length, .little);
                offset += 4 + length;
            }
            assert(offset == size);
            return @intCast(size);
        }

        /// Loads every tree from the checkpoint bytes at the start of `bytes`; returns the
        /// bytes consumed. `open_scan` then verifies the tables.
        pub fn open_decode(self: *Self, bytes: []const u8) error{InvalidCheckpoint}!u32 {
            assert(self.scan_callback == null);
            assert(self.bulk == null);
            var offset: u32 = 0;
            inline for (tree_names, 0..) |name, index| {
                const tree_bytes = length_prefixed(bytes, offset) catch |err| {
                    self.reset_first(index);
                    return err;
                };
                @field(self, name).open_decode(tree_bytes) catch |err| {
                    self.reset_first(index);
                    return err;
                };
                offset += @intCast(4 + tree_bytes.len);
            }
            assert(offset <= bytes.len);
            return offset;
        }

        /// Resets the trees before tree `count` (an open that failed part way).
        fn reset_first(self: *Self, count: u32) void {
            assert(count < tree_count);
            inline for (tree_names, 0..) |name, index| {
                if (index < count) @field(self, name).reset();
            }
        }

        fn length_prefixed(bytes: []const u8, offset: u32) error{InvalidCheckpoint}![]const u8 {
            if (bytes.len < offset + 4) return error.InvalidCheckpoint;
            const length = std.mem.readInt(u32, bytes[offset..][0..4], .little);
            if (length == 0) return error.InvalidCheckpoint; // A tree writes its header.
            if (bytes.len - offset - 4 < length) return error.InvalidCheckpoint;
            return bytes[offset + 4 ..][0..length];
        }

        /// Every tree leaves the next replay a full reserve if checkpointed now (`lsm.zig`).
        pub fn checkpoint_ready(self: *Self) bool {
            assert(self.bulk == null);
            inline for (tree_names) |name| {
                if (!@field(self, name).checkpoint_ready()) return false;
            }
            return true;
        }

        /// Not `checkpoint_ready` (an open's replay filled into the reserve while a flush was
        /// pending): lifts compaction pacing until the next commit regrants it, so the pending
        /// flush installs without commits; `callback` fires after each install.
        pub fn checkpoint_prepare(self: *Self, callback: Callback) void {
            assert(self.owner != null);
            assert(!self.checkpoint_ready());
            self.install_callback = callback;
            inline for (tree_names) |name| {
                @field(self, name).install_callback = on_installed(name);
            }
            self.compact(std.math.maxInt(u64));
        }

        fn on_installed(comptime name: []const u8) @FieldType(Self, name).Callback {
            const Tree = @FieldType(Self, name);
            return struct {
                fn callback(tree: *Tree) void {
                    const self: *Self = @alignCast(@fieldParentPtr(name, tree));
                    assert(!tree.compaction.active);
                    if (self.install_callback) |installed| installed(self);
                }
            }.callback;
        }

        /// Scans the trees in `tree_names` order; the callback fires with `scan_outcome`
        /// (`.corrupt` on the first table that fails to verify).
        pub fn open_scan(self: *Self, callback: Callback) void {
            assert(self.scan_callback == null);
            assert(self.owner != null);
            self.scan_callback = callback;
            self.scan_outcome = .loaded;
            self.scan_from(0);
        }

        /// Scans tree `first` (its callback scans the next); done after the last.
        fn scan_from(self: *Self, first: u32) void {
            assert(self.scan_callback != null);
            assert(first <= tree_count);
            inline for (tree_names, 0..) |name, index| {
                if (index == first) return @field(self, name).open_scan(on_scanned(name, index));
            }
            self.scan_done(.loaded);
        }

        fn on_scanned(
            comptime name: []const u8,
            comptime index: u32,
        ) @FieldType(Self, name).Callback {
            const Tree = @FieldType(Self, name);
            return struct {
                fn callback(tree: *Tree) void {
                    const self: *Self = @alignCast(@fieldParentPtr(name, tree));
                    assert(self.scan_callback != null);
                    if (tree.scan_outcome == .corrupt) return self.scan_done(.corrupt);
                    self.scan_from(index + 1);
                }
            }.callback;
        }

        fn scan_done(self: *Self, outcome: ScanOutcome) void {
            const callback = self.scan_callback.?;
            self.scan_callback = null;
            self.scan_outcome = outcome;
            callback(self);
        }
    };
}

/// The four bulk loaders of a `FlatTrees` import, one per tree (field names as the trees').
fn BulkType(comptime Trees: type) type {
    return struct {
        const Bulk = @This();

        trees: *Trees,
        accounts: lsm_bulk.BulkLoaderType(Trees.AccountTree),
        storage: lsm_bulk.BulkLoaderType(Trees.StorageTree),
        account_branches: lsm_bulk.BulkLoaderType(Trees.AccountBranchTree),
        storage_branches: lsm_bulk.BulkLoaderType(Trees.StorageBranchTree),
        /// Loaders that have not called back since `bulk_finish`.
        pending: u32 = 0,
        callback: ?Trees.Callback = null,

        /// Allocates the loaders and begins a load on every (empty) tree.
        fn create(allocator: std.mem.Allocator, trees: *Trees) !*Bulk {
            const bulk = try allocator.create(Bulk);
            errdefer allocator.destroy(bulk);
            bulk.trees = trees;
            bulk.pending = 0;
            bulk.callback = null;
            bulk.accounts = try .init(allocator, &trees.accounts);
            errdefer bulk.accounts.deinit(allocator);
            bulk.storage = try .init(allocator, &trees.storage);
            errdefer bulk.storage.deinit(allocator);
            bulk.account_branches = try .init(allocator, &trees.account_branches);
            errdefer bulk.account_branches.deinit(allocator);
            bulk.storage_branches = try .init(allocator, &trees.storage_branches);
            inline for (tree_names) |name| @field(bulk, name).begin();
            inline for (tree_names) |name| assert(@field(trees, name).bulk_active);
            return bulk;
        }

        fn destroy(bulk: *Bulk, allocator: std.mem.Allocator) void {
            inline for (tree_names) |name| @field(bulk, name).deinit(allocator);
            allocator.destroy(bulk);
        }

        /// No loader has a block write in flight.
        fn idle(bulk: *const Bulk) bool {
            inline for (tree_names) |name| {
                if (@field(bulk, name).io_pending) return false;
            }
            return true;
        }

        fn on_loaded(comptime name: []const u8) @FieldType(Bulk, name).Callback {
            const Loader = @FieldType(Bulk, name);
            return struct {
                fn callback(loader: *Loader) void {
                    const bulk: *Bulk = @alignCast(@fieldParentPtr(name, loader));
                    assert(bulk.pending > 0 and !loader.active);
                    bulk.pending -= 1;
                    if (bulk.pending > 0) return;
                    const done = bulk.callback.?;
                    bulk.callback = null;
                    done(bulk.trees);
                }
            }.callback;
        }
    };
}

fn hash_addresses(changes: []const changeset_module.AccountChange, out: []Hash) void {
    assert(changes.len == out.len);
    assert(changes.len <= keccak.batch_width);
    if (changes.len == keccak.batch_width) {
        var inputs: [keccak.batch_width][]const u8 = undefined;
        for (&inputs, changes) |*input, *change| input.* = &change.address;
        keccak.keccak256_batch(&inputs, out[0..keccak.batch_width]);
    } else {
        for (changes, out) |*change, *hash| hash.* = node.keccak256(&change.address);
    }
}

fn hash_slots(changes: []const changeset_module.StorageChange, out: []Hash) void {
    assert(changes.len == out.len);
    assert(changes.len <= keccak.batch_width);
    var keys: [keccak.batch_width][32]u8 = undefined;
    for (keys[0..changes.len], changes) |*key, *change| {
        std.mem.writeInt(u256, key, change.slot, .big);
    }
    if (changes.len == keccak.batch_width) {
        var inputs: [keccak.batch_width][]const u8 = undefined;
        for (&inputs, &keys) |*input, *key| input.* = key;
        keccak.keccak256_batch(&inputs, out[0..keccak.batch_width]);
    } else {
        for (keys[0..changes.len], out) |*key, *hash| hash.* = node.keccak256(key);
    }
}

test "flat trees: account records round trip and storage keys concatenate hashes" {
    const info: AccountInfo = .{ .nonce = 7, .balance = 1 << 200, .code_hash = @splat(0xab) };
    const root: Hash = @splat(0x5c);
    const encoded = account_encode(&info, &root);
    const decoded = account_decode(&encoded);
    try std.testing.expect(decoded.eql(.{ .info = info, .storage_root = root }));
    try std.testing.expect(!decoded.eql(.{ .info = info, .storage_root = node.empty_root }));
    const address_hash: Hash = @splat(0x11);
    const key = storage_key(&address_hash, 5);
    try std.testing.expectEqualSlices(u8, &address_hash, key[0..32]);
    var slot_bytes: [32]u8 = @splat(0);
    slot_bytes[31] = 5;
    try std.testing.expectEqualSlices(u8, &node.keccak256(&slot_bytes), key[32..64]);
}

test "flat trees: key limits beyond State's sizes and a large journal give valid layouts" {
    const Trees = FlatTreesType(@import("storage/sim_storage.zig").SimStorage);
    const block_size: u32 = 64 * 1024;
    // A 64 MiB journal and 32 MiB of retained blocks: a replay reserve of ~868k storage
    // entries, more than one index block of records (tables are cut below the memtable).
    const config: Config = .{
        .block_size = block_size,
        .block_count = 8 * 1024 * 1024,
        .journal_bytes = 64 * 1024 * 1024,
        .chain_bytes = 32 * 1024 * 1024,
        .entry_body_bytes = 4 * 1024 * 1024,
        .accounts_max = 300_000_000,
        .slots_max = 3_000_000_000,
        .account_branches_max = 120_000_000,
        .storage_branches_max = 1_200_000_000,
        .flush_entries_min = 16 * 1024,
        // Levels grow from the memtable size (8 levels at most): ~1.2B records need 4k.
        .branch_flush_entries_min = 4 * 1024,
        .cache_blocks = 64,
    };
    const cap = table_records_cap(Trees.StorageTree, block_size);
    const storage = tree_config(config, storage_put_bytes_min, config.slots_max, cap);
    try std.testing.expect(storage.memtable_entries_max > cap);
    try std.testing.expectEqual(cap, storage.table_records_max);
    const layout = Trees.StorageTree.layout_of(storage);
    const last = storage.levels_count - 1;
    try std.testing.expect(layout.capacity[last] >= 2 * config.slots_max);
    const branches = branch_tree_config(
        config,
        config.storage_branches_max,
        table_records_cap(Trees.StorageBranchTree, block_size),
    );
    try std.testing.expectEqual(@as(u32, 0), branches.replay_entries_max);
    const branch_layout = Trees.StorageBranchTree.layout_of(branches);
    try std.testing.expect(branch_layout.capacity[branches.levels_count - 1] >=
        2 * config.storage_branches_max);
}

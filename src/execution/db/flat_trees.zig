//! Flat trees: the account and storage LSM trees `Database` shadow-writes every committed
//! changeset into (disk state phase 2b, first step; `Config.flat_trees`). `State`'s flat
//! hash tables stay the source of truth; the trees are derived data that must equal them.
//!
//! - Account tree: key keccak256(address) (32 B), value the account (72 B: nonce u64
//!   big-endian, balance u256 big-endian, code hash); a removed account is a tombstone.
//! - Storage tree: key keccak256(address) ++ keccak256(slot) (64 B), value the slot word
//!   (32 B big-endian); a zero value is a tombstone (a zero slot does not exist).
//!
//! Writes: a head move writes each unwound changeset's old values, then each applied
//! changeset's new values (`write`); changesets carry absolute values, so the trees end equal
//! to `State`. A live head move first checks that both mutable memtables have room for every
//! put it can make (`reserve`, counts from the encoded changeset headers); without room it
//! paces compaction once more and the operation returns `error.Busy` before any change.
//! Journal replay after open writes through `put_replay` into the replay reserve.
//!
//! Replay reserve (`tree_config`): replay after open cannot compact (no grid IO before the
//! engine is ready), so every distinct key replay writes must fit one memtable's reserve.
//! Each such key comes from a changeset entry in the journal or in a retained block, and an
//! entry is at least `account_put_bytes_min` (or `storage_put_bytes_min`) encoded bytes, so
//! (journal bytes + retained chain bytes) / entry bytes bounds it.
//!
//! Checkpoint (inside the database checkpoint): length-prefixed account tree bytes, then
//! storage tree bytes (`lsm.zig`'s manifest, memtables, and orphans). Open decodes them in the
//! engine's open pause and scans both trees (`open_scan`) before the snapshot loads.

const std = @import("std");
const assert = std.debug.assert;

const lsm = @import("storage/lsm.zig");
const table_module = @import("storage/table.zig");
const free_set_module = @import("storage/free_set.zig");
const changeset_module = @import("changeset.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const node = @import("../trie/node.zig");

const Changeset = changeset_module.Changeset;
const AccountInfo = changeset_module.AccountInfo;
const Hash = changeset_module.Hash;
const FreeSet = free_set_module.FreeSet;
const BlockCache = table_module.BlockCache;

pub const account_key_size: u32 = 32;
pub const account_value_size: u32 = 8 + 32 + 32;
pub const storage_key_size: u32 = 64;
pub const storage_value_size: u32 = 32;
/// Smallest encoded changeset entry per put: an account change with one side, a slot change.
pub const account_put_bytes_min: u32 = 20 + 1 + account_value_size;
pub const storage_put_bytes_min: u32 = 20 + 3 * 32;

pub const Config = struct {
    block_size: u32,
    /// Grid blocks (addresses `1..block_count`).
    block_count: u64,
    /// Journal bytes and retained chain bytes: the replay reserve's bound.
    journal_bytes: u64,
    chain_bytes: u64,
    /// Largest journal entry body: with `chain_bytes`, the most one head move writes.
    entry_body_bytes: u64,
    accounts_max: u32,
    slots_max: u32,
    /// Mutable memtable entries at which a tree flushes.
    flush_entries_min: u32,
    /// Blocks of the block cache both trees' lookups share.
    cache_blocks: u32,
};

/// The tree config for keys whose changeset entries are at least `put_bytes_min` bytes and
/// that hold at most `keys_max` live keys.
pub fn tree_config(config: Config, put_bytes_min: u32, keys_max: u32) lsm.Config {
    assert(put_bytes_min > 0 and config.flush_entries_min > 0);
    const replay = (config.journal_bytes + config.chain_bytes) / put_bytes_min + 1;
    const operation = (config.chain_bytes + config.entry_body_bytes) / put_bytes_min + 1;
    // Normal puts stop at `flush_entries_min + operation`: below the flush trigger a head
    // move always fits, and at it the memtables swap once the pending flush is done.
    const memtable = config.flush_entries_min + operation + replay;
    assert(memtable < std.math.maxInt(u32) / 4);
    const level0_tables_max: u32 = 4;
    // The last level holds at least twice the live keys (a full last level is a config
    // error); each level up to it is `growth_factor` times the one before.
    var levels: u32 = 2;
    var capacity: u64 = level0_tables_max * memtable;
    while (capacity < 2 * @as(u64, keys_max) and levels < lsm.levels_max) : (levels += 1) {
        capacity *= 8;
    }
    assert(capacity >= 2 * @as(u64, keys_max));
    return .{
        .block_size = config.block_size,
        .block_count = config.block_count,
        .memtable_entries_max = @intCast(memtable),
        .flush_entries_min = config.flush_entries_min,
        .replay_entries_max = @intCast(replay),
        .table_records_max = @intCast(memtable),
        .level0_tables_max = level0_tables_max,
        .levels_count = levels,
        .growth_factor = 8,
    };
}

pub fn account_encode(info: *const AccountInfo) [account_value_size]u8 {
    var out: [account_value_size]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], info.nonce, .big);
    std.mem.writeInt(u256, out[8..40], info.balance, .big);
    out[40..72].* = info.code_hash;
    return out;
}

pub fn account_decode(bytes: *const [account_value_size]u8) AccountInfo {
    return .{
        .nonce = std.mem.readInt(u64, bytes[0..8], .big),
        .balance = std.mem.readInt(u256, bytes[8..40], .big),
        .code_hash = bytes[40..72].*,
    };
}

pub fn storage_key(address_hash: *const Hash, slot: u256) [storage_key_size]u8 {
    var slot_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &slot_bytes, slot, .big);
    var key: [storage_key_size]u8 = undefined;
    key[0..32].* = address_hash.*;
    key[32..64].* = node.keccak256(&slot_bytes);
    return key;
}

pub const Puts = struct { accounts: u64 = 0, storage: u64 = 0 };

pub const Stats = struct {
    /// Head moves refused for memtable room (`reserve`).
    busy: u64 = 0,
    puts_accounts: u64 = 0,
    puts_storage: u64 = 0,
};

pub fn FlatTreesType(comptime Storage: type) type {
    return struct {
        const Self = @This();

        pub const AccountTree = lsm.TreeType(Storage, account_key_size, account_value_size);
        pub const StorageTree = lsm.TreeType(Storage, storage_key_size, storage_value_size);
        pub const Grid = AccountTree.Grid;
        pub const Callback = *const fn (*Self) void;
        pub const ScanOutcome = lsm.ScanOutcome;
        pub const Mode = enum { live, replay };

        cache: *BlockCache,
        accounts: AccountTree,
        storage: StorageTree,
        /// The callback's context, set by the owner before a scan.
        owner: ?*anyopaque = null,
        scan_callback: ?Callback = null,
        /// Fires after either tree installs a compaction job while the owner waits for
        /// `checkpoint_ready` (`checkpoint_prepare`).
        install_callback: ?Callback = null,
        scan_outcome: ScanOutcome = .loaded,
        stats: Stats = .{},

        /// `grid` is used for its block size here; `bind` names the engine's grid and free
        /// set before the open scan (the owner moves after init, so the cache is boxed).
        pub fn init(allocator: std.mem.Allocator, grid: *Grid, config: Config) !Self {
            assert(config.block_size == grid.config.block_size);
            assert(config.cache_blocks > 0);
            const cache = try allocator.create(BlockCache);
            errdefer allocator.destroy(cache);
            cache.* = try BlockCache.init(allocator, config.block_size, config.cache_blocks);
            errdefer cache.deinit(allocator);
            const account_config = tree_config(config, account_put_bytes_min, config.accounts_max);
            var accounts = try AccountTree.init(allocator, grid, cache, account_config);
            errdefer accounts.deinit(allocator);
            const storage_config = tree_config(config, storage_put_bytes_min, config.slots_max);
            const storage = try StorageTree.init(allocator, grid, cache, storage_config);
            return .{ .cache = cache, .accounts = accounts, .storage = storage };
        }

        /// Frees memory. Grid IO may be in flight only if the storage dropped it (crash).
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.storage.deinit(allocator);
            self.accounts.deinit(allocator);
            self.cache.deinit(allocator);
            allocator.destroy(self.cache);
            self.* = undefined;
        }

        pub fn bind(self: *Self, grid: *Grid, free_set: *FreeSet) void {
            assert(self.scan_callback == null);
            self.accounts.bind(grid, free_set);
            self.storage.bind(grid, free_set);
        }

        /// Empty trees (a fresh database).
        pub fn reset(self: *Self) void {
            assert(self.scan_callback == null);
            self.accounts.reset();
            self.storage.reset();
        }

        /// No grid IO in flight and no lookup pending (the owner may be freed).
        pub fn idle(self: *const Self) bool {
            if (self.accounts.compaction.io_pending or self.storage.compaction.io_pending) {
                return false;
            }
            return !self.accounts.lookup_active and !self.storage.lookup_active;
        }

        /// One commit's compaction budget for both trees.
        pub fn compact(self: *Self, blocks: u64) void {
            assert(blocks > 0);
            self.accounts.compact(blocks);
            self.storage.compact(blocks);
        }

        /// Puts a head move's changesets can make (at most: the encoded entry counts).
        pub fn puts_add(puts: *Puts, encoded: []const u8) changeset_module.Error!void {
            const counts = try Changeset.encoded_counts(encoded);
            puts.accounts += counts.accounts;
            puts.storage += counts.storage;
        }

        /// Room check before a live head move: without room both trees get one more
        /// compaction grant (so a stalled swap or flush moves on) and the move is refused.
        pub fn reserve(self: *Self, puts: Puts, blocks: u64) error{Busy}!void {
            assert(blocks > 0);
            const accounts_free = self.accounts.capacity_free();
            const storage_free = self.storage.capacity_free();
            if (puts.accounts <= accounts_free and puts.storage <= storage_free) return;
            self.stats.busy += 1;
            self.compact(blocks);
            return error.Busy;
        }

        /// Writes the values `changeset` leaves (`forward`) or the ones it replaced. Live
        /// writes were reserved (`reserve`); replay writes use the replay reserve, and
        /// `error.Busy` there means the reserve was sized too small (open fails).
        pub fn write(
            self: *Self,
            changeset: *const Changeset,
            forward: bool,
            mode: Mode,
        ) error{Busy}!void {
            const accounts_before = self.stats.puts_accounts;
            try self.write_accounts(changeset.account_changes(), forward, mode);
            try self.write_storage(changeset.storage_changes(), forward, mode);
            assert(self.stats.puts_accounts == accounts_before + changeset.accounts_len);
        }

        fn write_accounts(
            self: *Self,
            changes: []const changeset_module.AccountChange,
            forward: bool,
            mode: Mode,
        ) error{Busy}!void {
            var hashes: [keccak.batch_width]Hash = undefined;
            var start: usize = 0;
            while (start < changes.len) : (start += keccak.batch_width) {
                const chunk = changes[start..@min(changes.len, start + keccak.batch_width)];
                hash_addresses(chunk, hashes[0..chunk.len]);
                for (chunk, hashes[0..chunk.len]) |*change, *key| {
                    const target = if (forward) change.new else change.old;
                    if (target) |info| {
                        const value = account_encode(&info);
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
            var address_last: ?changeset_module.Address = null;
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
                    var key: [storage_key_size]u8 = undefined;
                    key[0..32].* = address_hash;
                    key[32..64].* = slot_hash.*;
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

        // Checkpoint: u32 length + account tree bytes, u32 length + storage tree bytes.

        pub fn checkpoint_size_max(self: *const Self) u64 {
            return 8 + @as(u64, self.accounts.checkpoint_size_max()) +
                self.storage.checkpoint_size_max();
        }

        pub fn checkpoint_size(self: *Self) u64 {
            return 8 + @as(u64, self.accounts.checkpoint_size()) + self.storage.checkpoint_size();
        }

        /// Writes both trees' checkpoint bytes (at the engine checkpoint's snapshot point).
        pub fn checkpoint_encode(self: *Self, out: []u8) u32 {
            const size = self.checkpoint_size();
            assert(out.len >= size);
            const accounts_len = self.accounts.checkpoint_encode(out[4..]);
            std.mem.writeInt(u32, out[0..4], accounts_len, .little);
            const offset = 4 + accounts_len;
            const storage_len = self.storage.checkpoint_encode(out[offset + 4 ..]);
            std.mem.writeInt(u32, out[offset..][0..4], storage_len, .little);
            assert(offset + 4 + storage_len == size);
            return @intCast(size);
        }

        /// Loads both trees from the checkpoint bytes at the start of `bytes`; returns the
        /// bytes consumed. `open_scan` then verifies every table.
        pub fn open_decode(self: *Self, bytes: []const u8) error{InvalidCheckpoint}!u32 {
            assert(self.scan_callback == null);
            const accounts = try length_prefixed(bytes, 0);
            self.accounts.open_decode(accounts) catch |err| return err;
            const offset: u32 = @intCast(4 + accounts.len);
            const storage = try length_prefixed(bytes, offset);
            self.storage.open_decode(storage) catch |err| {
                self.accounts.reset();
                return err;
            };
            const consumed: u32 = @intCast(offset + 4 + storage.len);
            assert(consumed <= bytes.len);
            return consumed;
        }

        fn length_prefixed(bytes: []const u8, offset: u32) error{InvalidCheckpoint}![]const u8 {
            if (bytes.len < offset + 4) return error.InvalidCheckpoint;
            const length = std.mem.readInt(u32, bytes[offset..][0..4], .little);
            if (length == 0) return error.InvalidCheckpoint; // A tree writes its header.
            if (bytes.len - offset - 4 < length) return error.InvalidCheckpoint;
            return bytes[offset + 4 ..][0..length];
        }

        /// Both trees leave the next replay a full reserve if checkpointed now (`lsm.zig`).
        pub fn checkpoint_ready(self: *Self) bool {
            return self.accounts.checkpoint_ready() and self.storage.checkpoint_ready();
        }

        /// Not `checkpoint_ready` (an open's replay filled into the reserve while a flush was
        /// pending): lifts compaction pacing until the next commit regrants it, so the pending
        /// flush installs without commits; `callback` fires after each install.
        pub fn checkpoint_prepare(self: *Self, callback: Callback) void {
            assert(self.owner != null);
            assert(!self.checkpoint_ready());
            self.install_callback = callback;
            self.accounts.install_callback = on_accounts_installed;
            self.storage.install_callback = on_storage_installed;
            self.compact(std.math.maxInt(u64));
        }

        fn on_accounts_installed(tree: *AccountTree) void {
            const self: *Self = @alignCast(@fieldParentPtr("accounts", tree));
            assert(!tree.compaction.active);
            if (self.install_callback) |callback| callback(self);
        }

        fn on_storage_installed(tree: *StorageTree) void {
            const self: *Self = @alignCast(@fieldParentPtr("storage", tree));
            assert(!tree.compaction.active);
            if (self.install_callback) |callback| callback(self);
        }

        /// Scans the account tree, then the storage tree; the callback fires with
        /// `scan_outcome` (`.corrupt` on the first table that fails to verify).
        pub fn open_scan(self: *Self, callback: Callback) void {
            assert(self.scan_callback == null);
            assert(self.owner != null);
            self.scan_callback = callback;
            self.scan_outcome = .loaded;
            self.accounts.open_scan(on_accounts_scanned);
        }

        fn on_accounts_scanned(tree: *AccountTree) void {
            const self: *Self = @alignCast(@fieldParentPtr("accounts", tree));
            assert(self.scan_callback != null);
            if (tree.scan_outcome == .corrupt) return self.scan_done(.corrupt);
            self.storage.open_scan(on_storage_scanned);
        }

        fn on_storage_scanned(tree: *StorageTree) void {
            const self: *Self = @alignCast(@fieldParentPtr("storage", tree));
            assert(self.scan_callback != null);
            self.scan_done(tree.scan_outcome);
        }

        fn scan_done(self: *Self, outcome: ScanOutcome) void {
            const callback = self.scan_callback.?;
            self.scan_callback = null;
            self.scan_outcome = outcome;
            callback(self);
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

test "flat trees: account values round trip and storage keys concatenate hashes" {
    const info: AccountInfo = .{ .nonce = 7, .balance = 1 << 200, .code_hash = @splat(0xab) };
    const encoded = account_encode(&info);
    try std.testing.expect(account_decode(&encoded).eql(info));
    const address_hash: Hash = @splat(0x11);
    const key = storage_key(&address_hash, 5);
    try std.testing.expectEqualSlices(u8, &address_hash, key[0..32]);
    var slot_bytes: [32]u8 = @splat(0);
    slot_bytes[31] = 5;
    try std.testing.expectEqualSlices(u8, &node.keccak256(&slot_bytes), key[32..64]);
}

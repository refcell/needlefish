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
const address_map = @import("address_map.zig");
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

pub const CodeRef = struct { offset: u32, len: u32 };

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

/// A slot in `State.build_trie`'s scratch; grouped by address, each group by slot hash.
const SlotRecord = extern struct {
    address: Address,
    slot_hash: Hash,
    value: [32]u8,

    comptime {
        assert(@sizeOf(SlotRecord) == 84 and @alignOf(SlotRecord) == 1);
    }

    /// Address, then slot hash.
    fn less_than(_: void, a: SlotRecord, b: SlotRecord) bool {
        const a_high = std.mem.readInt(u64, a.address[0..8], .big);
        const b_high = std.mem.readInt(u64, b.address[0..8], .big);
        if (a_high != b_high) return a_high < b_high;
        switch (std.mem.order(u8, a.address[8..], b.address[8..])) {
            .lt => return true,
            .gt => return false,
            .eq => return hash_less_than({}, a.slot_hash, b.slot_hash),
        }
    }

    /// Groups records by address (not in address order): a byte of the address's hash.
    fn bucket(record: *align(1) const SlotRecord) u8 {
        return @truncate(std.hash.Wyhash.hash(0, &record.address) >> 56);
    }

    /// One account's run, as a `TrieType.build_sorted` source.
    const Source = struct {
        records: []align(1) const SlotRecord,

        pub fn key(source: *const Source, index: u32) *const Hash {
            return &source.records[index].slot_hash;
        }

        pub fn value(source: *const Source, index: u32, buffer: *[33]u8) []const u8 {
            const word = std.mem.readInt(u256, &source.records[index].value, .big);
            return trie.state_trie.encode_storage_value(word, buffer);
        }
    };
};

/// Byte order of two hashes (the first word decides all but about 2^-64 of pairs).
fn hash_less_than(_: void, a: Hash, b: Hash) bool {
    const a_high = std.mem.readInt(u64, a[0..8], .big);
    const b_high = std.mem.readInt(u64, b[0..8], .big);
    if (a_high != b_high) return a_high < b_high;
    return std.mem.order(u8, a[8..], b[8..]) == .lt;
}

const BulkAccount = trie.state_trie.StateTrie.BulkAccount;

comptime {
    // A snapshot spends 92 bytes per account: its bytes are always enough scratch.
    assert(@sizeOf(BulkAccount) <= 20 + 8 + 32 + 32);
}

fn account_less_than(_: void, a: BulkAccount, b: BulkAccount) bool {
    return hash_less_than({}, a.address_hash, b.address_hash);
}

/// The hash's first byte: buckets in byte order, so bucketed and sorted is sorted.
fn account_bucket(account: *align(1) const BulkAccount) u8 {
    return account.address_hash[0];
}

/// Sorts `items` in place: one in-place counting pass into 256 buckets by `bucket_of`
/// (American flag sort), then each bucket by `less_than`. Equal items share a bucket, so
/// equal keys end up adjacent; the result is sorted when `bucket_of` is monotonic with
/// `less_than`. Each small bucket sorts in cache, where one large pdq over 1M 32-byte keys
/// spent most of its time on cache misses.
fn sort_bucketed(
    comptime T: type,
    items: []align(1) T,
    comptime bucket_of: fn (*align(1) const T) u8,
    comptime less_than: fn (void, T, T) bool,
) void {
    var counts: [256]usize = @splat(0);
    for (items) |*item| counts[bucket_of(item)] += 1;
    var next: [256]usize = undefined;
    var ends: [256]usize = undefined;
    var offset: usize = 0;
    for (&next, &ends, counts) |*bucket_next, *bucket_end, count| {
        bucket_next.* = offset;
        offset += count;
        bucket_end.* = offset;
    }
    assert(offset == items.len);
    // Every swap puts one item into its bucket for good: at most `items.len` swaps.
    var swaps: usize = 0;
    for (0..256) |bucket| {
        while (next[bucket] < ends[bucket]) {
            const target = bucket_of(&items[next[bucket]]);
            if (target == bucket) {
                next[bucket] += 1;
                continue;
            }
            assert(swaps < items.len);
            swaps += 1;
            const moved = items[next[target]];
            items[next[target]] = items[next[bucket]];
            items[next[bucket]] = moved;
            next[target] += 1;
        }
    }
    // `items` may be unaligned (scratch bytes): sort through indices.
    const Context = struct {
        items: []align(1) T,

        pub fn lessThan(context: @This(), a: usize, b: usize) bool {
            return less_than({}, context.items[a], context.items[b]);
        }

        pub fn swap(context: @This(), a: usize, b: usize) void {
            const item = context.items[a];
            context.items[a] = context.items[b];
            context.items[b] = item;
        }
    };
    var start: usize = 0;
    for (ends) |end| {
        std.sort.pdqContext(start, end, Context{ .items = items });
        start = end;
    }
    assert(start == items.len);
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
    account_table: address_map.Map(AccountEntry),
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
    /// The tables moved without the trie (`unwind_tables`) until `rebuild_trie`.
    trie_stale: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) !State {
        var account_table: address_map.Map(AccountEntry) = .empty;
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

    /// Drops every code (an open that must discard the codes it loaded). Only before any
    /// account is loaded: no account may reference a dropped code.
    pub fn reset_codes(self: *State) void {
        assert(self.account_table.count() == 0);
        self.code_table.clearRetainingCapacity();
        self.code_arena_len = 0;
        assert(self.code_table.count() == 0);
    }

    pub fn state_root(self: *State) Error!Hash {
        assert(!self.trie_stale);
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

    /// Scratch bytes `build_trie` needs: one 84-byte slot record per slot and one 40-byte
    /// `BulkAccount` per account. Never more than the snapshot of the same tables.
    pub fn build_trie_scratch_bytes(self: *const State) u64 {
        return @as(u64, self.storage_table.count()) * @sizeOf(SlotRecord) +
            @as(u64, self.account_table.count()) * @sizeOf(BulkAccount);
    }

    /// Builds the state trie of the flat tables (snapshot load) in bulk: every key hashed in
    /// SIMD batches, the slots grouped by account and sorted by slot hash and each storage
    /// trie built from them in one pass, hashed together (on the rehash pool when
    /// configured), then the account trie built from the sorted address hashes and hashed
    /// (`StateTrie.bulk_*`). Same tries and root as `put_account` / `put_storage` of every
    /// entry. `scratch` holds the sorted keys (`build_trie_scratch_bytes`). On error the
    /// state must be discarded.
    pub fn build_trie(self: *State, scratch: []u8) Error!void {
        assert(!self.trie_stale);
        assert(self.state_trie.account_count() == 0);
        assert(scratch.len >= self.build_trie_scratch_bytes());
        const slot_bytes = @as(usize, self.storage_table.count()) * @sizeOf(SlotRecord);
        const account_bytes = @as(usize, self.account_table.count()) * @sizeOf(BulkAccount);
        const records = std.mem.bytesAsSlice(SlotRecord, scratch[0..slot_bytes]);
        const accounts = std.mem.bytesAsSlice(BulkAccount, scratch[slot_bytes..][0..account_bytes]);
        try self.build_accounts(accounts);
        self.fill_slot_records(records);
        sort_bucketed(SlotRecord, records, SlotRecord.bucket, SlotRecord.less_than);
        try self.build_storage(records);
        sort_bucketed(BulkAccount, accounts, account_bucket, account_less_than);
        try self.state_trie.bulk_finish(accounts);
        assert(self.state_trie.account_count() == self.account_table.count());
    }

    /// `build_trie_scratch_bytes` at full tables: enough scratch for any `rebuild_trie`.
    pub fn build_trie_scratch_bytes_max(config: Config) u64 {
        return @as(u64, config.storage_slots_max) * @sizeOf(SlotRecord) +
            @as(u64, config.accounts_max) * @sizeOf(BulkAccount);
    }

    /// Drops the state trie and builds it again from the flat tables (`build_trie`), after
    /// `unwind_tables`: one O(state) bulk build instead of a trie update per unwound entry.
    pub fn rebuild_trie(self: *State, scratch: []u8) Error!void {
        assert(scratch.len >= self.build_trie_scratch_bytes());
        self.state_trie.clear();
        self.trie_stale = false;
        try self.build_trie(scratch);
        assert(self.state_trie.account_count() == self.account_table.count());
    }

    /// Reverts a block in the flat tables only, leaving the trie stale until `rebuild_trie`
    /// (no reads of the root, applies, or unwinds in between). Same tables as `unwind`.
    /// Fails before any change if the tables could overflow.
    pub fn unwind_tables(self: *State, changeset: *const Changeset) Error!void {
        const accounts = changeset.account_changes();
        if (self.account_table.count() + accounts.len > self.config.accounts_max) {
            return error.StateFull;
        }
        if (self.storage_table.count() + changeset.storage_len > self.config.storage_slots_max) {
            return error.StateFull;
        }
        self.trie_stale = true;
        // The order of `apply_direction`: accounts that exist afterwards, storage, removals.
        for (accounts) |*change| {
            const info = change.old orelse continue;
            const result = self.account_table.getOrPutAssumeCapacity(change.address);
            if (!result.found_existing) result.value_ptr.* = .{ .info = info };
            result.value_ptr.info = info;
        }
        for (changeset.storage_changes()) |*change| {
            const entry = self.account_table.getPtr(change.address) orelse {
                return error.UnknownAccount;
            };
            const key: SlotKey = .{ .address = change.address, .slot = change.slot };
            self.set_slot(entry, key, change.old);
        }
        for (accounts) |*change| {
            if (change.old != null) continue;
            const removed = self.account_table.fetchRemove(change.address);
            if (removed) |entry| assert(entry.value.storage_slots == 0);
        }
        assert(self.trie_stale);
    }

    /// Adds every account to the trie (no storage yet), listing each in `accounts`.
    fn build_accounts(self: *State, accounts: []align(1) BulkAccount) Error!void {
        assert(accounts.len == self.account_table.count());
        var iterator = self.account_table.iterator();
        var keys: [keccak.batch_width]Address = undefined;
        var infos: [keccak.batch_width]trie.Account = undefined;
        var done: usize = 0;
        while (done < accounts.len) {
            const chunk = @min(keccak.batch_width, accounts.len - done);
            for (keys[0..chunk], infos[0..chunk]) |*key, *trie_entry| {
                // `chunk` entries remain: the table holds `accounts.len`.
                const entry = iterator.next() orelse unreachable;
                key.* = entry.key_ptr.*;
                trie_entry.* = trie_account(entry.value_ptr.info);
            }
            var out: [keccak.batch_width]Hash = undefined;
            hash_keys(20, keys[0..chunk], out[0..chunk]);
            for (out[0..chunk], infos[0..chunk], 0..) |address_hash, trie_entry, index| {
                const added = try self.state_trie.bulk_add_account(address_hash, trie_entry);
                accounts[done + index] = added;
            }
            done += chunk;
        }
        assert(iterator.next() == null);
    }

    /// One record per slot: address, keccak256(slot), and value (big-endian).
    fn fill_slot_records(self: *const State, records: []align(1) SlotRecord) void {
        assert(records.len == self.storage_table.count());
        var iterator = self.storage_table.iterator();
        var keys: [keccak.batch_width][32]u8 = undefined;
        var done: usize = 0;
        while (done < records.len) {
            const chunk = @min(keccak.batch_width, records.len - done);
            for (keys[0..chunk], records[done..][0..chunk]) |*key, *record| {
                // `chunk` entries remain: the table holds `records.len`.
                const entry = iterator.next() orelse unreachable;
                std.mem.writeInt(u256, key, entry.key_ptr.slot, .big);
                record.address = entry.key_ptr.address;
                std.mem.writeInt(u256, &record.value, entry.value_ptr.*, .big);
            }
            var out: [keccak.batch_width]Hash = undefined;
            hash_keys(32, keys[0..chunk], out[0..chunk]);
            for (records[done..][0..chunk], out[0..chunk]) |*record, slot_hash| {
                record.slot_hash = slot_hash;
            }
            done += chunk;
        }
        assert(iterator.next() == null);
    }

    /// Builds each account's storage trie from its run of the grouped records.
    fn build_storage(self: *State, records: []align(1) const SlotRecord) Error!void {
        var start: usize = 0;
        while (start < records.len) {
            const address = &records[start].address;
            var end = start + 1;
            while (end < records.len and std.mem.eql(u8, &records[end].address, address)) {
                end += 1;
            }
            const source: SlotRecord.Source = .{ .records = records[start..end] };
            const count: u32 = @intCast(end - start);
            try self.state_trie.bulk_storage(node.keccak256(address), &source, count);
            start = end;
        }
        assert(start == records.len);
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
        assert(!self.trie_stale);
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

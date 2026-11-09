//! Journaled world state: a block-lifetime cache over a `Database` backend.
//!
//! - Every map is sized at init; inserting past capacity is `error.StateFull`, a fatal
//!   block error (never a silent consensus difference). No rehash ever happens, so
//!   `*Account` and `*Slot` pointers are stable for the lifetime of the state.
//! - Warmth (EIP-2929) and tx-start storage values (EIP-2200) are stamped with the
//!   transaction id, so starting a transaction is O(1).
//! - Storage incarnations: wiping storage (SELFDESTRUCT, contract creation) bumps the
//!   account's `storage_epoch`; slots cached for an older epoch are stale. Epoch 0
//!   means storage is backed by the database.
//! - Every revertible change appends a 64-byte journal entry; `revert` undoes them.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;
const B256 = primitives.B256;

pub const Error = error{ DatabaseFailure, StateFull };

pub const AccountInfo = struct {
    balance: u256 = 0,
    nonce: u64 = 0,
    code_hash: B256 = primitives.keccak_empty,
    /// Code if already known; otherwise loaded through `Database.code_by_hash`.
    code: ?[]const u8 = null,
    /// The database holds non-empty storage for this account (storage root is not the
    /// empty root). Needed for the EIP-7610 creation collision rule.
    has_storage: bool = false,

    pub fn is_empty(info: *const AccountInfo) bool {
        return info.nonce == 0 and info.balance == 0 and
            std.mem.eql(u8, &info.code_hash, &primitives.keccak_empty);
    }

    pub fn has_code(info: *const AccountInfo) bool {
        return !std.mem.eql(u8, &info.code_hash, &primitives.keccak_empty);
    }
};

/// The storage backend (trie-db lane, or `MemoryDatabase` in tests). Returned code
/// slices must stay valid for the lifetime of the `State`.
pub const Database = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        basic: *const fn (context: *anyopaque, address: Address) Error!?AccountInfo,
        code_by_hash: *const fn (context: *anyopaque, code_hash: B256) Error![]const u8,
        storage: *const fn (context: *anyopaque, address: Address, slot: u256) Error!u256,
        block_hash: *const fn (context: *anyopaque, number: u64) Error!B256,
    };

    pub fn basic(database: Database, address: Address) Error!?AccountInfo {
        return database.vtable.basic(database.context, address);
    }
    pub fn code_by_hash(database: Database, code_hash: B256) Error![]const u8 {
        return database.vtable.code_by_hash(database.context, code_hash);
    }
    pub fn storage(database: Database, address: Address, slot: u256) Error!u256 {
        return database.vtable.storage(database.context, address, slot);
    }
    pub fn block_hash(database: Database, number: u64) Error!B256 {
        return database.vtable.block_hash(database.context, number);
    }
};

pub const Account = struct {
    address: Address,
    info: AccountInfo,
    /// Present in the database (or committed by an earlier transaction this block).
    in_database: bool,
    /// Touched in the current transaction (EIP-161). Journaled.
    touched: bool = false,
    self_destructed: bool = false,
    /// Changed during this block; part of the commit output.
    dirty: bool = false,
    /// Storage was wiped this block; the database must drop its old storage.
    storage_cleared: bool = false,
    warm_tx: u32 = 0,
    created_tx: u32 = 0,
    storage_epoch: u32 = 0,

    /// Whether the account counts as "empty/non-existent" for the given fork:
    /// EIP-161 empty from Spurious Dragon, otherwise absent from the state.
    pub fn is_empty_for(account: *const Account, comptime fork: Fork) bool {
        if (fork.at_least(.spurious_dragon)) return account.info.is_empty();
        return !account.in_database and !account.touched;
    }
};

pub const StorageKey = struct { address: Address, slot: u256 };

/// An address as three little-endian words (bytes 0..8, 8..16 and 16..20), each read with one
/// load. Bit-casting `[20]u8` to `u160` compiled to twenty byte loads per hash and compare.
const AddressWords = struct {
    low: u64,
    middle: u64,
    high: u32,

    inline fn of(address: *const Address) AddressWords {
        return .{
            .low = std.mem.readInt(u64, address[0..8], .little),
            .middle = std.mem.readInt(u64, address[8..16], .little),
            .high = std.mem.readInt(u32, address[16..20], .little),
        };
    }

    inline fn fold(words: AddressWords) u64 {
        const multiplier = StorageKeyContext.multiplier;
        const folded = (words.low ^ words.middle) *% multiplier;
        return (folded ^ words.high) *% multiplier;
    }

    inline fn eql(a: AddressWords, b: AddressWords) bool {
        return a.low == b.low and a.middle == b.middle and a.high == b.high;
    }
};

/// Storage-slot map context. `AutoContext` streams the key's fields through wyhash and
/// compares bytes element-wise; together that was ~40% of an SSTORE/SLOAD loop. This
/// folds the key's 64-bit limbs and finishes with the murmur3 `fmix64` avalanche, and
/// compares the key as words. Like the unseeded wyhash it replaces, it is not
/// keyed: probe lengths stay bounded by the gas needed to create each slot.
pub const StorageKeyContext = struct {
    const multiplier: u64 = 0x9e37_79b9_7f4a_7c15;

    pub inline fn hash(_: StorageKeyContext, key: StorageKey) u64 {
        var folded = AddressWords.of(&key.address).fold();
        inline for (0..4) |limb| {
            folded = (folded ^ @as(u64, @truncate(key.slot >> (limb * 64)))) *% multiplier;
        }
        return fmix64(folded);
    }

    pub inline fn eql(_: StorageKeyContext, a: StorageKey, b: StorageKey) bool {
        if (a.slot != b.slot) return false;
        return AddressWords.of(&a.address).eql(AddressWords.of(&b.address));
    }

    fn fmix64(value: u64) u64 {
        var x = value;
        x ^= x >> 33;
        x *%= 0xff51_afd7_ed55_8ccd;
        x ^= x >> 33;
        x *%= 0xc4ce_b9fe_1a85_ec53;
        x ^= x >> 33;
        return x;
    }
};

/// Account map context: the 20-byte address folded into one 64-bit word and avalanched,
/// compared as words. `AutoContext` hashes the bytes through wyhash and compares them
/// element-wise.
pub const AddressContext = struct {
    pub inline fn hash(_: AddressContext, address: Address) u64 {
        return StorageKeyContext.fmix64(AddressWords.of(&address).fold());
    }

    pub inline fn eql(_: AddressContext, a: Address, b: Address) bool {
        return AddressWords.of(&a).eql(AddressWords.of(&b));
    }
};

pub fn AddressMap(comptime V: type) type {
    return std.HashMapUnmanaged(
        Address,
        V,
        AddressContext,
        std.hash_map.default_max_load_percentage,
    );
}

pub fn StorageKeyMap(comptime V: type) type {
    return std.HashMapUnmanaged(
        StorageKey,
        V,
        StorageKeyContext,
        std.hash_map.default_max_load_percentage,
    );
}

pub const Slot = struct {
    present: u256,
    /// Value at the start of the transaction `original_tx` (EIP-2200 "original").
    original: u256,
    original_tx: u32,
    warm_tx: u32 = 0,
    epoch: u32,
    /// Changed this block relative to the database.
    dirty: bool = false,
};

pub const Log = struct {
    address: Address,
    topics: [4]B256,
    topic_count: u8,
    data: []const u8,

    pub fn topic_slice(log: *const Log) []const B256 {
        return log.topics[0..log.topic_count];
    }
};

pub const Limits = struct {
    accounts_max: u32 = 1 << 16,
    slots_max: u32 = 1 << 18,
    /// TSTORE costs 100 gas, so a 2^24-gas transaction can write ~2^17 slots.
    transient_slots_max: u32 = 1 << 18,
    journal_entries_max: u32 = 1 << 20,
    logs_max: u32 = 1 << 14,
    /// Log data per transaction; LOG costs 8 gas per byte, so this bounds gas / 8.
    log_data_bytes_max: u32 = 64 << 20,
    /// Bytes of contract code deployed within one block.
    code_bytes_max: u32 = 1 << 24,

    /// Headroom for entries no transaction pays for: system calls (beacon root, history
    /// storage), the L1 attributes deposit, fee vaults, and unmetered EIP-8130 writes.
    pub const unmetered_headroom: u32 = 1 << 13;

    /// Account and slot tables sized for one block of `gas_limit`, for a `State` that is
    /// reset at least once per block. Every distinct slot costs at least 1900 gas (an
    /// EIP-2930 storage key; a cold SLOAD/SSTORE costs more) and every distinct account at
    /// least 2400 (an EIP-2930 address; cold access and intrinsic gas cost more). Smaller
    /// tables than the defaults keep lookups in cache. Never exceeds the defaults.
    pub fn for_block_gas(gas_limit: u64) Limits {
        const defaults = Limits{};
        const slots = gas_limit / 1900 + unmetered_headroom;
        const accounts = gas_limit / 2400 + unmetered_headroom;
        const limits = Limits{
            .slots_max = @intCast(@min(
                std.math.ceilPowerOfTwoAssert(u64, slots),
                defaults.slots_max,
            )),
            .accounts_max = @intCast(@min(
                std.math.ceilPowerOfTwoAssert(u64, accounts),
                defaults.accounts_max,
            )),
        };
        assert(limits.slots_max >= @min(slots, defaults.slots_max));
        assert(limits.accounts_max >= @min(accounts, defaults.accounts_max));
        return limits;
    }
};

test "state: limits for a block cover its gas and never exceed the defaults" {
    const base_block = Limits.for_block_gas(37_500_000);
    try std.testing.expect(base_block.slots_max >= 37_500_000 / 1900);
    try std.testing.expectEqual(@as(u32, 1 << 15), base_block.slots_max);
    try std.testing.expectEqual(@as(u32, 1 << 15), base_block.accounts_max);
    const huge = Limits.for_block_gas(1 << 40);
    try std.testing.expectEqual(Limits{}, huge);
    const empty = Limits.for_block_gas(0);
    try std.testing.expectEqual(Limits.unmetered_headroom, empty.slots_max);
}

/// Zero-length placeholder while a `replace_code` undo pair is half applied.
const undo_code_placeholder = [_]u8{0};

const EntryKind = enum(u8) {
    account_warmed,
    account_touched,
    balance,
    nonce,
    code_set,
    /// `replace_code` undo pair: `code_restore_pointer` (old hash, old pointer) is recorded
    /// first, `code_restore_length` (old length) second, so undo sees the length first.
    code_restore_pointer,
    code_restore_length,
    account_created,
    self_destructed,
    slot_value,
    slot_incarnation,
    slot_warmed,
    transient,
};

/// One undo record. `target` is a stable `*Account`, `*Slot`, or `*u256`.
const Entry = struct {
    word: u256,
    target: usize,
    extra: u64,
    kind: EntryKind,
};

comptime {
    assert(@sizeOf(Entry) <= 64);
}

pub const Checkpoint = struct {
    journal_len: u32,
    logs_len: u32,
    log_data_len: u32,
};

/// Addresses that are warm in every transaction of a fork without a state load: active
/// precompiles (0x01..0x1f by bit, P256 at 0x100) and the implemented native singletons.
pub const StaticWarm = struct {
    /// Bit `n` set: the precompile at address `n` is active.
    precompiles: u32 = 0,
    p256: bool = false,
    natives: []const Address = &.{},

    pub fn contains(warm: *const StaticWarm, address: Address) bool {
        if (std.mem.allEqual(u8, address[0..18], 0)) {
            const number = std.mem.readInt(u16, address[18..20], .big);
            if (number < 32) return (warm.precompiles >> @intCast(number)) & 1 == 1;
            if (number == 0x100) return warm.p256;
        }
        assert(warm.natives.len <= 16);
        for (warm.natives) |native| {
            if (std.mem.eql(u8, &native, &address)) return true;
        }
        return false;
    }
};

pub const State = struct {
    database: Database,
    limits: Limits,
    accounts: AddressMap(Account) = .empty,
    slots: StorageKeyMap(Slot) = .empty,
    transient: StorageKeyMap(u256) = .empty,
    journal: []Entry,
    journal_len: u32 = 0,
    logs: []Log,
    logs_len: u32 = 0,
    log_data: []u8,
    log_data_len: u32 = 0,
    code_store: []u8,
    code_store_len: u32 = 0,
    /// Current transaction id; starts at 1 so a zero stamp is never current.
    tx_id: u32 = 1,
    /// Addresses warm in the current transaction without being loaded (precompiles and
    /// native singletons, EIP-2929); consulted only when an account's stamp is stale.
    static_warm: StaticWarm = .{},

    pub fn init(allocator: std.mem.Allocator, database: Database, limits: Limits) !State {
        var state = State{
            .database = database,
            .limits = limits,
            .journal = try allocator.alloc(Entry, limits.journal_entries_max),
            .logs = try allocator.alloc(Log, limits.logs_max),
            .log_data = try allocator.alloc(u8, limits.log_data_bytes_max),
            .code_store = try allocator.alloc(u8, limits.code_bytes_max),
        };
        errdefer state.deinit(allocator);
        try state.accounts.ensureTotalCapacity(allocator, limits.accounts_max);
        try state.slots.ensureTotalCapacity(allocator, limits.slots_max);
        try state.transient.ensureTotalCapacity(allocator, limits.transient_slots_max);
        return state;
    }

    pub fn deinit(state: *State, allocator: std.mem.Allocator) void {
        state.accounts.deinit(allocator);
        state.slots.deinit(allocator);
        state.transient.deinit(allocator);
        allocator.free(state.journal);
        allocator.free(state.logs);
        allocator.free(state.log_data);
        allocator.free(state.code_store);
        state.* = undefined;
    }

    /// Drop every cached account and slot and point at a new database (new block or
    /// test case), keeping all allocations.
    pub fn reset(state: *State, database: Database) void {
        state.database = database;
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        // As in `begin_transaction`: an empty map has no tombstones, so skip the memset.
        if (state.transient.count() > 0) state.transient.clearRetainingCapacity();
        state.journal_len = 0;
        state.logs_len = 0;
        state.log_data_len = 0;
        state.code_store_len = 0;
        state.tx_id = 1;
        state.static_warm = .{};
        assert(state.accounts.count() == 0);
    }

    // ---------------------------------------------------------------- transactions

    pub fn begin_transaction(state: *State) void {
        assert(state.tx_id < std.math.maxInt(u32));
        state.tx_id += 1;
        state.static_warm = .{};
        state.journal_len = 0;
        state.logs_len = 0;
        state.log_data_len = 0;
        // Entries are never removed (reverts restore values in place), so an empty map
        // has no tombstones; skip the capacity-sized metadata memset (most transactions
        // never TSTORE).
        if (state.transient.count() > 0) state.transient.clearRetainingCapacity();
        assert(state.transient.count() == 0);
    }

    pub fn checkpoint(state: *const State) Checkpoint {
        return .{
            .journal_len = state.journal_len,
            .logs_len = state.logs_len,
            .log_data_len = state.log_data_len,
        };
    }

    /// Undo every change made since `point`, newest first.
    pub fn revert(state: *State, point: Checkpoint) void {
        assert(point.journal_len <= state.journal_len);
        assert(point.logs_len <= state.logs_len);
        while (state.journal_len > point.journal_len) {
            state.journal_len -= 1;
            undo(state, state.journal[state.journal_len]);
        }
        state.logs_len = point.logs_len;
        state.log_data_len = point.log_data_len;
    }

    fn undo(state: *State, entry: Entry) void {
        switch (entry.kind) {
            .account_warmed => account_at(entry).warm_tx = 0,
            .account_touched => account_at(entry).touched = false,
            .balance => account_at(entry).info.balance = entry.word,
            .nonce => account_at(entry).info.nonce = entry.extra,
            .code_set => {
                const account = account_at(entry);
                account.info.code_hash = primitives.keccak_empty;
                account.info.code = &.{};
            },
            .code_restore_length => {
                const account = account_at(entry);
                // Stash the length in the slice until the pointer entry restores it; the
                // placeholder is never read.
                const length: usize = @intCast(entry.extra);
                account.info.code = @as([*]const u8, &undo_code_placeholder)[0..length];
            },
            .code_restore_pointer => {
                const account = account_at(entry);
                const stash = account.info.code.?;
                const length = stash.len;
                assert(length == 0 or stash.ptr == @as([*]const u8, &undo_code_placeholder));
                account.info.code = if (length == 0)
                    &.{}
                else
                    @as([*]const u8, @ptrFromInt(@as(usize, @intCast(entry.extra))))[0..length];
                account.info.code_hash = primitives.u256_to_b256(entry.word);
            },
            .account_created => {
                const account = account_at(entry);
                account.created_tx = @truncate(entry.extra);
                account.storage_epoch = @truncate(entry.extra >> 32);
            },
            .self_destructed => account_at(entry).self_destructed = false,
            .slot_value => slot_at(entry).present = entry.word,
            .slot_incarnation => {
                const slot = slot_at(entry);
                slot.original = entry.word;
                slot.original_tx = @truncate(entry.extra);
                slot.epoch = @truncate(entry.extra >> 32);
            },
            .slot_warmed => slot_at(entry).warm_tx = 0,
            .transient => @as(*u256, @ptrFromInt(entry.target)).* = entry.word,
        }
        _ = state;
    }

    fn account_at(entry: Entry) *Account {
        return @ptrFromInt(entry.target);
    }

    fn slot_at(entry: Entry) *Slot {
        return @ptrFromInt(entry.target);
    }

    fn record(state: *State, kind: EntryKind, target: usize, word: u256, extra: u64) Error!void {
        if (state.journal_len == state.journal.len) return error.StateFull;
        state.journal[state.journal_len] = .{
            .kind = kind,
            .target = target,
            .word = word,
            .extra = extra,
        };
        state.journal_len += 1;
    }

    // ---------------------------------------------------------------- accounts

    /// The cached account, loading it from the database on first use. Does not warm.
    pub fn load(state: *State, address: Address) Error!*Account {
        if (state.accounts.getPtr(address)) |account| return account;
        if (state.accounts.count() >= state.limits.accounts_max) return error.StateFull;
        const info = try state.database.basic(address);
        const entry = state.accounts.getOrPutAssumeCapacity(address);
        assert(!entry.found_existing);
        entry.value_ptr.* = .{
            .address = address,
            .info = info orelse .{},
            .in_database = info != null,
        };
        return entry.value_ptr;
    }

    pub const Access = struct { account: *Account, is_cold: bool };

    /// Load and warm an account (EIP-2929), reporting whether it was cold.
    pub fn access(state: *State, address: Address) Error!Access {
        const account = try state.load(address);
        const is_cold = account.warm_tx != state.tx_id and !state.static_warm.contains(address);
        if (is_cold) {
            try state.record(.account_warmed, @intFromPtr(account), 0, 0);
            account.warm_tx = state.tx_id;
        }
        return .{ .account = account, .is_cold = is_cold };
    }

    pub fn is_warm(state: *State, address: Address) bool {
        if (state.static_warm.contains(address)) return true;
        const account = state.accounts.getPtr(address) orelse return false;
        return account.warm_tx == state.tx_id;
    }

    pub fn code(state: *State, account: *Account) Error![]const u8 {
        if (account.info.code) |bytes| return bytes;
        const bytes: []const u8 = if (account.info.has_code())
            try state.database.code_by_hash(account.info.code_hash)
        else
            &.{};
        account.info.code = bytes;
        return bytes;
    }

    pub fn touch(state: *State, account: *Account) Error!void {
        if (account.touched) return;
        try state.record(.account_touched, @intFromPtr(account), 0, 0);
        account.touched = true;
    }

    pub fn set_balance(state: *State, account: *Account, balance: u256) Error!void {
        try state.record(.balance, @intFromPtr(account), account.info.balance, 0);
        account.info.balance = balance;
        account.dirty = true;
    }

    pub fn set_nonce(state: *State, account: *Account, nonce: u64) Error!void {
        try state.record(.nonce, @intFromPtr(account), 0, account.info.nonce);
        account.info.nonce = nonce;
        account.dirty = true;
    }

    /// Move `value` wei. Returns false (and changes nothing) if `from` cannot pay.
    pub fn transfer(state: *State, from: *Account, to: *Account, value: u256) Error!bool {
        if (from.info.balance < value) return false;
        try state.touch(from);
        try state.touch(to);
        if (value == 0 or from == to) return true;
        try state.set_balance(from, from.info.balance - value);
        // Total supply is far below 2^256, so the receiving balance cannot overflow.
        try state.set_balance(to, to.info.balance + value);
        return true;
    }

    /// Mark `account` as created by CREATE/CREATE2 in this transaction: fresh storage,
    /// EIP-6780 "created in same transaction", and nonce 1 from Spurious Dragon.
    pub fn create_account(state: *State, account: *Account, comptime fork: Fork) Error!void {
        assert(!account.info.has_code());
        const extra = @as(u64, account.created_tx) | (@as(u64, account.storage_epoch) << 32);
        try state.record(.account_created, @intFromPtr(account), 0, extra);
        account.created_tx = state.tx_id;
        account.storage_epoch = state.next_epoch(account);
        account.dirty = true;
        try state.touch(account);
        if (fork.at_least(.spurious_dragon)) try state.set_nonce(account, 1);
    }

    fn next_epoch(state: *const State, account: *const Account) u32 {
        _ = state;
        assert(account.storage_epoch < std.math.maxInt(u32));
        return account.storage_epoch + 1;
    }

    /// Store deployed code for a contract created in this transaction.
    pub fn set_code(state: *State, account: *Account, bytes: []const u8) Error!void {
        assert(!account.info.has_code());
        const stored = try state.store_code(bytes);
        try state.record(.code_set, @intFromPtr(account), 0, 0);
        account.info.code = stored;
        account.info.code_hash = primitives.keccak256(stored);
        account.dirty = true;
    }

    /// Journaled overwrite of existing code (EIP-8130 delegation installs, which may
    /// replace an earlier delegation indicator or clear it).
    pub fn replace_code(state: *State, account: *Account, bytes: []const u8) Error!void {
        const previous = try state.code(account);
        const previous_pointer: u64 = if (previous.len == 0) 0 else @intFromPtr(previous.ptr);
        const previous_hash = primitives.b256_to_u256(account.info.code_hash);
        const target = @intFromPtr(account);
        try state.record(.code_restore_pointer, target, previous_hash, previous_pointer);
        try state.record(.code_restore_length, @intFromPtr(account), 0, previous.len);
        try state.set_code_unjournaled(account, bytes);
        assert(account.info.code.?.len == bytes.len);
    }

    /// Set code outside the journal (EIP-7702 delegations at transaction start).
    pub fn set_code_unjournaled(state: *State, account: *Account, bytes: []const u8) Error!void {
        const stored = try state.store_code(bytes);
        account.info.code = stored;
        account.info.code_hash = if (stored.len == 0)
            primitives.keccak_empty
        else
            primitives.keccak256(stored);
        account.dirty = true;
    }

    fn store_code(state: *State, bytes: []const u8) Error![]const u8 {
        if (state.code_store.len - state.code_store_len < bytes.len) return error.StateFull;
        const stored = state.code_store[state.code_store_len..][0..bytes.len];
        @memcpy(stored, bytes);
        state.code_store_len += @intCast(bytes.len);
        return stored;
    }

    pub const SelfDestruct = struct {
        had_value: bool,
        target_empty: bool,
        target_cold: bool,
        previously_destroyed: bool,
    };

    /// SELFDESTRUCT `address` sending its balance to `target`. From Cancun (EIP-6780)
    /// the account is only destroyed when it was created in this transaction.
    pub fn self_destruct(
        state: *State,
        comptime fork: Fork,
        address: Address,
        target: Address,
    ) Error!SelfDestruct {
        const target_access = try state.access(target);
        const target_account = target_access.account;
        const account = try state.load(address);
        const balance = account.info.balance;
        const result = SelfDestruct{
            .had_value = balance != 0,
            .target_empty = target_account.is_empty_for(fork),
            .target_cold = target_access.is_cold,
            .previously_destroyed = account.self_destructed,
        };
        const destroys = fork.before(.cancun) or account.created_tx == state.tx_id;
        if (account != target_account) {
            try state.touch(target_account);
            try state.set_balance(target_account, target_account.info.balance + balance);
        }
        if (destroys or account != target_account) try state.set_balance(account, 0);
        if (destroys and !account.self_destructed) {
            try state.record(.self_destructed, @intFromPtr(account), 0, 0);
            account.self_destructed = true;
        }
        try state.touch(account);
        return result;
    }

    // ---------------------------------------------------------------- storage

    /// The cached slot for the current incarnation and transaction. Does not warm.
    fn slot_for(state: *State, account: *Account, slot: u256) Error!*Slot {
        const key = StorageKey{ .address = account.address, .slot = slot };
        if (state.slots.getPtr(key)) |cached| {
            if (cached.epoch != account.storage_epoch) {
                try state.reincarnate(account, cached, slot);
            } else if (cached.original_tx != state.tx_id) {
                cached.original = cached.present;
                cached.original_tx = state.tx_id;
            }
            return cached;
        }
        if (state.slots.count() >= state.limits.slots_max) return error.StateFull;
        const value = if (account.storage_epoch == 0)
            try state.database.storage(account.address, slot)
        else
            0;
        const entry = state.slots.getOrPutAssumeCapacity(key);
        entry.value_ptr.* = .{
            .present = value,
            .original = value,
            .original_tx = state.tx_id,
            .epoch = account.storage_epoch,
        };
        return entry.value_ptr;
    }

    /// Re-read a slot cached for another storage incarnation. Journaled, because
    /// reverting a creation restores the older incarnation.
    fn reincarnate(state: *State, account: *Account, slot: *Slot, key_slot: u256) Error!void {
        const extra = @as(u64, slot.original_tx) | (@as(u64, slot.epoch) << 32);
        try state.record(.slot_incarnation, @intFromPtr(slot), slot.original, extra);
        try state.record(.slot_value, @intFromPtr(slot), slot.present, 0);
        const value = if (account.storage_epoch == 0)
            try state.database.storage(account.address, key_slot)
        else
            0;
        slot.present = value;
        slot.original = value;
        slot.original_tx = state.tx_id;
        slot.epoch = account.storage_epoch;
    }

    /// Present value of a slot without warming it, for system reads (OP L1Block fees).
    pub fn storage_value(state: *State, address: Address, slot: u256) Error!u256 {
        const account = try state.load(address);
        const cached = try state.slot_for(account, slot);
        assert(cached.epoch == account.storage_epoch);
        return cached.present;
    }

    pub const SlotAccess = struct { slot: *Slot, is_cold: bool };

    /// Load and warm a storage slot of `account`.
    pub fn storage_access(state: *State, account: *Account, slot: u256) Error!SlotAccess {
        const cached = try state.slot_for(account, slot);
        const is_cold = cached.warm_tx != state.tx_id;
        if (is_cold) {
            try state.record(.slot_warmed, @intFromPtr(cached), 0, 0);
            cached.warm_tx = state.tx_id;
        }
        return .{ .slot = cached, .is_cold = is_cold };
    }

    pub fn storage_write(state: *State, account: *Account, slot: *Slot, value: u256) Error!void {
        if (slot.present == value) return;
        try state.record(.slot_value, @intFromPtr(slot), slot.present, 0);
        slot.present = value;
        slot.dirty = true;
        account.dirty = true;
    }

    pub fn transient_load(state: *State, address: Address, slot: u256) u256 {
        return state.transient.get(.{ .address = address, .slot = slot }) orelse 0;
    }

    pub fn transient_store(state: *State, address: Address, slot: u256, value: u256) Error!void {
        const key = StorageKey{ .address = address, .slot = slot };
        const existing = state.transient.getPtr(key);
        if (existing == null and value == 0) return;
        const pointer = existing orelse blk: {
            if (state.transient.count() >= state.limits.transient_slots_max) {
                return error.StateFull;
            }
            const entry = state.transient.getOrPutAssumeCapacity(key);
            entry.value_ptr.* = 0;
            break :blk entry.value_ptr;
        };
        try state.record(.transient, @intFromPtr(pointer), pointer.*, 0);
        pointer.* = value;
    }

    // ---------------------------------------------------------------- logs

    pub fn log(
        state: *State,
        address: Address,
        topics: []const B256,
        data: []const u8,
    ) Error!void {
        assert(topics.len <= 4);
        if (state.logs_len == state.logs.len) return error.StateFull;
        if (state.log_data.len - state.log_data_len < data.len) return error.StateFull;
        const stored = state.log_data[state.log_data_len..][0..data.len];
        @memcpy(stored, data);
        state.log_data_len += @intCast(data.len);
        var entry = Log{
            .address = address,
            .topics = undefined,
            .topic_count = @intCast(topics.len),
            .data = stored,
        };
        @memcpy(entry.topics[0..topics.len], topics);
        state.logs[state.logs_len] = entry;
        state.logs_len += 1;
    }

    pub fn transaction_logs(state: *const State) []const Log {
        return state.logs[0..state.logs_len];
    }

    // ---------------------------------------------------------------- finalize

    /// End-of-transaction rules: destroy self-destructed accounts, clear touched empty
    /// accounts (EIP-161) or persist touched ones (pre-Spurious Dragon).
    pub fn finalize_transaction(state: *State, comptime fork: Fork) void {
        for (state.journal[0..state.journal_len]) |entry| {
            switch (entry.kind) {
                .self_destructed => state.destroy(account_at(entry)),
                .account_touched => {
                    const account = account_at(entry);
                    account.touched = false;
                    if (account.self_destructed) continue;
                    if (fork.at_least(.spurious_dragon) and account.info.is_empty()) {
                        if (account.in_database or account.dirty) state.destroy(account);
                    } else {
                        account.in_database = true;
                        account.dirty = true;
                    }
                },
                else => {},
            }
        }
        state.journal_len = 0;
    }

    fn destroy(state: *State, account: *Account) void {
        account.info = .{ .code = &.{} };
        account.self_destructed = false;
        account.touched = false;
        account.in_database = false;
        account.dirty = true;
        account.storage_cleared = true;
        account.storage_epoch = state.next_epoch(account);
    }

    pub fn block_hash(state: *State, number: u64) Error!B256 {
        return state.database.block_hash(number);
    }
};

test "state: static warm set by address" {
    const natives = [_]Address{@splat(0x42)};
    const warm = StaticWarm{ .precompiles = 0b110, .p256 = true, .natives = &natives };
    var address: Address = @splat(0);
    try std.testing.expect(!warm.contains(address));
    address[19] = 1;
    try std.testing.expect(warm.contains(address));
    address[19] = 3;
    try std.testing.expect(!warm.contains(address));
    address[18] = 1;
    address[19] = 0;
    try std.testing.expect(warm.contains(address)); // 0x100.
    address[0] = 1;
    try std.testing.expect(!warm.contains(address)); // Not a small address.
    try std.testing.expect(warm.contains(natives[0]));
    const empty = StaticWarm{};
    try std.testing.expect(!empty.contains(natives[0]));
}

test "state: entry is compact" {
    try std.testing.expect(@sizeOf(Entry) <= 64);
}

test "state: storage key context agrees with byte equality and spreads keys" {
    var prng = std.Random.DefaultPrng.init(0x5107);
    const context = StorageKeyContext{};
    var buckets: [64]u32 = @splat(0);
    var iteration: u32 = 0;
    while (iteration < 4096) : (iteration += 1) {
        var address: Address = undefined;
        prng.random().bytes(&address);
        const key = StorageKey{ .address = address, .slot = prng.random().int(u256) };
        var other = key;
        switch (prng.random().uintLessThan(u8, 3)) {
            0 => {},
            1 => other.address[prng.random().uintLessThan(usize, 20)] +%= 1,
            else => other.slot +%= @as(u256, 1) << prng.random().int(u8),
        }
        const same = std.mem.eql(u8, &key.address, &other.address) and key.slot == other.slot;
        try std.testing.expectEqual(same, context.eql(key, other));
        if (same) try std.testing.expectEqual(context.hash(key), context.hash(other));
        // Sequential slots of one contract (the common layout) must not cluster.
        const sequential = StorageKey{ .address = address, .slot = iteration };
        buckets[context.hash(sequential) >> 58] += 1;
    }
    for (buckets) |count| try std.testing.expect(count > 16 and count < 128);
}

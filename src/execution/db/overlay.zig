//! Block overlay: the pending writes of one block on top of a committed `State`.
//!
//! The EVM executes a block against an `Overlay`. Reads check the overlay first, then fall
//! through to the state. `commit` converts the overlay into a canonical changeset, applies it
//! to the state, and returns the new state root; `discard` drops it (a failed payload build).
//!
//! Wipes are O(1): each overlay account has an epoch that a wipe bumps, and a slot written
//! under an older epoch reads as absent. Only `commit` of a wiped account scans the committed
//! storage table for that account's slots, which happens at most once per wiped account (in
//! disk mode a wiped account must have no committed storage: see `add_wiped_slots`).

const std = @import("std");
const assert = std.debug.assert;

const state_module = @import("state.zig");
const address_map = @import("address_map.zig");
const changeset_module = @import("changeset.zig");
const State = state_module.State;
const SlotKey = state_module.SlotKey;
const Address = state_module.Address;
const Hash = state_module.Hash;
const AccountInfo = state_module.AccountInfo;
const Changeset = changeset_module.Changeset;

pub const Config = struct {
    accounts_max: u32,
    slots_max: u32,
    codes_max: u32,
};

pub const Error = error{OverlayFull} || state_module.Error || changeset_module.Error;

const OverlayAccount = struct {
    /// The account's new info; meaningful only when `info_set`. Null means destroyed.
    info: ?AccountInfo = null,
    info_set: bool = false,
    /// Committed storage is cleared at commit.
    wiped: bool = false,
    epoch: u32 = 0,
};

const OverlaySlot = struct { value: u256, epoch: u32 };

pub const Overlay = struct {
    base: *State,
    accounts: address_map.Map(OverlayAccount),
    slots: std.AutoHashMapUnmanaged(SlotKey, OverlaySlot),
    new_codes: []Hash,
    new_codes_len: u32 = 0,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, base: *State, config: Config) !Overlay {
        var accounts: address_map.Map(OverlayAccount) = .empty;
        try accounts.ensureTotalCapacity(allocator, config.accounts_max);
        errdefer accounts.deinit(allocator);
        var slots: std.AutoHashMapUnmanaged(SlotKey, OverlaySlot) = .empty;
        try slots.ensureTotalCapacity(allocator, config.slots_max);
        errdefer slots.deinit(allocator);
        const new_codes = try allocator.alloc(Hash, config.codes_max);
        return .{
            .base = base,
            .accounts = accounts,
            .slots = slots,
            .new_codes = new_codes,
            .config = config,
        };
    }

    pub fn deinit(self: *Overlay, allocator: std.mem.Allocator) void {
        allocator.free(self.new_codes);
        self.slots.deinit(allocator);
        self.accounts.deinit(allocator);
        self.* = undefined;
    }

    /// Drops every pending write. Capacity is kept.
    pub fn discard(self: *Overlay) void {
        self.accounts.clearRetainingCapacity();
        self.slots.clearRetainingCapacity();
        self.new_codes_len = 0;
        assert(self.accounts.count() == 0 and self.slots.count() == 0);
    }

    pub fn basic(self: *const Overlay, address: Address) ?AccountInfo {
        if (self.accounts.get(address)) |account| {
            if (account.info_set) return account.info;
        }
        return self.base.basic(address);
    }

    pub fn storage(self: *const Overlay, address: Address, slot: u256) u256 {
        const account = self.accounts.get(address) orelse OverlayAccount{};
        if (self.slots.get(.{ .address = address, .slot = slot })) |entry| {
            if (entry.epoch == account.epoch) return entry.value;
        }
        if (account.wiped) return 0;
        return self.base.storage(address, slot);
    }

    pub fn code_by_hash(self: *const Overlay, hash: Hash) ?[]const u8 {
        return self.base.code_by_hash(hash);
    }

    pub fn code_known(self: *const Overlay, hash: Hash) bool {
        return self.base.code_known(hash);
    }

    pub fn block_hash(self: *const Overlay, number: u64) ?Hash {
        return self.base.block_hash(number);
    }

    fn account_entry(self: *Overlay, address: Address) Error!*OverlayAccount {
        if (self.accounts.getPtr(address)) |account| return account;
        if (self.accounts.count() == self.config.accounts_max) return error.OverlayFull;
        const result = self.accounts.getOrPutAssumeCapacity(address);
        assert(!result.found_existing);
        result.value_ptr.* = .{};
        return result.value_ptr;
    }

    /// Sets the account's info. Null destroys it, which also clears its storage.
    pub fn set_account(self: *Overlay, address: Address, info: ?AccountInfo) Error!void {
        const account = try self.account_entry(address);
        account.info = info;
        account.info_set = true;
        if (info == null) {
            account.wiped = true;
            account.epoch += 1;
        }
    }

    pub fn set_storage(self: *Overlay, address: Address, slot: u256, value: u256) Error!void {
        const epoch = if (self.accounts.get(address)) |account| account.epoch else 0;
        const key: SlotKey = .{ .address = address, .slot = slot };
        if (!self.slots.contains(key) and self.slots.count() == self.config.slots_max) {
            return error.OverlayFull;
        }
        self.slots.putAssumeCapacity(key, .{ .value = value, .epoch = epoch });
        assert(self.storage(address, slot) == value);
    }

    /// Clears all storage of the account, committed and pending.
    pub fn wipe_storage(self: *Overlay, address: Address) Error!void {
        const account = try self.account_entry(address);
        account.wiped = true;
        account.epoch += 1;
    }

    /// Stores contract code; returns its hash.
    pub fn insert_code(self: *Overlay, code: []const u8) Error!Hash {
        if (self.new_codes_len == self.new_codes.len) return error.OverlayFull;
        const result = try self.base.insert_code(code);
        if (result.new) {
            self.new_codes[self.new_codes_len] = result.hash;
            self.new_codes_len += 1;
        }
        return result.hash;
    }

    /// Fills `changeset` with the overlay's effect on the base state, in canonical order.
    pub fn build_changeset(self: *const Overlay, changeset: *Changeset) Error!void {
        changeset.clear();
        var accounts = self.accounts.iterator();
        while (accounts.next()) |entry| {
            const address = entry.key_ptr.*;
            const account = entry.value_ptr;
            const old = self.base.basic(address);
            const new = if (account.info_set) account.info else old;
            if (!info_equal(old, new)) {
                try changeset.add_account(.{ .address = address, .old = old, .new = new });
            }
            if (account.wiped) try self.add_wiped_slots(changeset, address);
        }
        var slots = self.slots.iterator();
        while (slots.next()) |entry| {
            const key = entry.key_ptr.*;
            const account = self.accounts.get(key.address) orelse OverlayAccount{};
            if (entry.value_ptr.epoch != account.epoch) continue;
            const old = self.base.storage(key.address, key.slot);
            // Committed slots of a wiped account were recorded by `add_wiped_slots`.
            if (account.wiped and old != 0) continue;
            if (old == entry.value_ptr.value) continue;
            try changeset.add_storage(.{
                .address = key.address,
                .slot = key.slot,
                .old = old,
                .new = entry.value_ptr.value,
            });
        }
        for (self.new_codes[0..self.new_codes_len]) |hash| {
            try changeset.add_code(self.base.code_by_hash(hash).?);
        }
        changeset.sort();
        try self.add_set_codes(changeset);
    }

    /// Lists the code of every account change that sets one, when the base holds it in its
    /// arena (not in a table only) and it is not listed yet. A code the base already knows
    /// is not new, but it may not be durable: a block that executed and was then rolled back
    /// (a payload with a bad state root) leaves its codes in the arena without any journal
    /// entry, so a block reusing such a code must carry it, or a restart before the next
    /// checkpoint loses it.
    fn add_set_codes(self: *const Overlay, changeset: *Changeset) Error!void {
        const codes_before = changeset.codes_len;
        for (changeset.account_changes()) |*change| {
            const new = change.new orelse continue;
            if (change.old) |old| {
                if (std.mem.eql(u8, &old.code_hash, &new.code_hash)) continue;
            }
            const code = self.base.code_in_arena(new.code_hash) orelse continue;
            if (changeset_has_code(changeset, code)) continue;
            try changeset.add_code(code);
        }
        assert(changeset.codes_len >= codes_before);
    }

    /// Records every committed slot of a wiped account, with its final overlay value.
    ///
    /// Disk mode cannot list an account's slots (no in-memory table, and the trees are point
    /// lookups only), so wiping an account whose storage root is not empty is
    /// `error.Unsupported` and the block is rejected. After Cancun this never rejects a valid
    /// block: SELFDESTRUCT destroys only an account created in the same transaction
    /// (EIP-6780), and a CREATE onto an address with storage fails (EIP-7610), so a wiped
    /// account never has committed storage; its slots written this block are in `slots`.
    fn add_wiped_slots(self: *const Overlay, changeset: *Changeset, address: Address) Error!void {
        if (self.base.disk != null) {
            if (self.base.has_storage(address)) return error.Unsupported;
            assert(self.base.storage_table.count() == 0);
            return;
        }
        var iterator = self.base.storage_table.iterator();
        while (iterator.next()) |entry| {
            if (!std.mem.eql(u8, &entry.key_ptr.address, &address)) continue;
            const slot = entry.key_ptr.slot;
            const new = self.storage(address, slot);
            if (new == entry.value_ptr.*) continue;
            try changeset.add_storage(.{
                .address = address,
                .slot = slot,
                .old = entry.value_ptr.*,
                .new = new,
            });
        }
    }

    /// Applies the overlay to the base state and returns the new state root. The overlay is
    /// empty afterwards; `changeset` keeps the block's changes for the journal and reorgs.
    pub fn commit(self: *Overlay, changeset: *Changeset) Error!Hash {
        try self.build_changeset(changeset);
        try self.base.apply(changeset);
        self.discard();
        return self.base.state_root();
    }
};

/// One account of a hashed write batch: its account trie key, and its info after the block
/// (null: absent).
pub const HashedAccountWrite = struct { key: Hash, info: ?AccountInfo };

/// One slot of a hashed write batch: the account's and the slot's trie keys, and the word
/// after the block (zero: absent).
pub const HashedSlotWrite = struct { key: Hash, slot: Hash, value: u256 };

/// A block's writes in hashed key space, as post-block values: `accounts` ascending by key,
/// `slots` by key then slot, no key (or key and slot) twice. `codes`: the codes the block
/// deploys (an evm block's `insert_code`s), each nonempty; `build_hashed_changeset` does not
/// read them (`StateDb.commit_hashed` lists them).
pub const HashedWrites = struct {
    accounts: []const HashedAccountWrite,
    slots: []const HashedSlotWrite,
    codes: []const []const u8 = &.{},
};

/// The hashed-key counterpart of `Overlay.build_changeset`: fills `changeset` (a hashed
/// changeset, `Changeset.hashed`) with the effect of `writes` on the state `reader` reads,
/// old values from it, writes that change nothing dropped. `reader` has `Error`,
/// `account(key) Error!?AccountInfo` and `storage(key, slot) Error!u256`. As in every
/// changeset, the committed slots of a destroyed or wiped account must be written (to zero)
/// one by one: disk mode cannot list them.
pub fn build_hashed_changeset(
    reader: anytype,
    writes: HashedWrites,
    changeset: *Changeset,
) (@TypeOf(reader).Error || changeset_module.Error)!void {
    changeset.clear_hashed();
    var account_index: usize = 0;
    var slot_index: usize = 0;
    while (account_index < writes.accounts.len or slot_index < writes.slots.len) {
        const key = next_hashed_owner(writes, account_index, slot_index);
        if (account_index < writes.accounts.len and
            std.mem.eql(u8, &writes.accounts[account_index].key, &key))
        {
            const write = &writes.accounts[account_index];
            account_index += 1;
            const old = try reader.account(&key);
            if (!info_equal(old, write.info)) {
                const address = try changeset.hashed_owner(&key);
                try changeset.add_account(.{ .address = address, .old = old, .new = write.info });
            }
        }
        while (slot_index < writes.slots.len and
            std.mem.eql(u8, &writes.slots[slot_index].key, &key))
        {
            const write = &writes.slots[slot_index];
            slot_index += 1;
            const old = try reader.storage(&key, &write.slot);
            if (old == write.value) continue;
            const address = try changeset.hashed_owner(&key);
            const slot = std.mem.readInt(u256, &write.slot, .big);
            try changeset.add_storage(.{
                .address = address,
                .slot = slot,
                .old = old,
                .new = write.value,
            });
        }
    }
    // Owners were named in ascending key order, slots within an owner too: sorted already.
    changeset.sort();
    assert(changeset.hashed);
    assert(changeset.keys_len <= writes.accounts.len + writes.slots.len);
}

/// The smallest key not yet merged of either list.
fn next_hashed_owner(writes: HashedWrites, account_index: usize, slot_index: usize) Hash {
    assert(account_index < writes.accounts.len or slot_index < writes.slots.len);
    if (account_index == writes.accounts.len) return writes.slots[slot_index].key;
    if (slot_index == writes.slots.len) return writes.accounts[account_index].key;
    const a = &writes.accounts[account_index].key;
    const b = &writes.slots[slot_index].key;
    return if (std.mem.order(u8, a, b) == .gt) b.* else a.*;
}

/// Whether `changeset` lists `code` (a block lists few codes; most differ in length).
fn changeset_has_code(changeset: *const Changeset, code: []const u8) bool {
    assert(code.len > 0);
    for (0..changeset.codes_len) |index| {
        if (std.mem.eql(u8, changeset.code(@intCast(index)), code)) return true;
    }
    return false;
}

fn info_equal(a: ?AccountInfo, b: ?AccountInfo) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}

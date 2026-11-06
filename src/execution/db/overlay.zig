//! Block overlay: the pending writes of one block on top of a committed `State`.
//!
//! The EVM executes a block against an `Overlay`. Reads check the overlay first, then fall
//! through to the state. `commit` converts the overlay into a canonical changeset, applies it
//! to the state, and returns the new state root; `discard` drops it (a failed payload build).
//!
//! Wipes are O(1): each overlay account has an epoch that a wipe bumps, and a slot written
//! under an older epoch reads as absent. Only `commit` of a wiped account scans the committed
//! storage table for that account's slots, which happens at most once per wiped account.

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
    }

    /// Records every committed slot of a wiped account, with its final overlay value.
    fn add_wiped_slots(self: *const Overlay, changeset: *Changeset, address: Address) Error!void {
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

fn info_equal(a: ?AccountInfo, b: ?AccountInfo) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}

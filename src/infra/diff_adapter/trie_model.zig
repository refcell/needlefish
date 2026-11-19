//! The trie mode's model of the request's state: every account (by trie key) with its info
//! and its nonzero slots, moved by the protocol's ops (`apply`). It gives each block's
//! writes as post-block values in hashed key space (`writes`, for the hashed-key entry
//! point), the slots a wipe or delete clears (the database cannot list them), and the
//! `hash-builder` variant: the root of the whole state from scratch with `HashBuilder`.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const trie_request = @import("trie_request.zig");

const Hash = [32]u8;
const AccountInfo = db.AccountInfo;
const Op = trie_request.Op;
const HashedWrites = db.overlay.HashedWrites;
const HashedAccountWrite = db.overlay.HashedAccountWrite;
const HashedSlotWrite = db.overlay.HashedSlotWrite;
const Slots = std.AutoArrayHashMapUnmanaged(Hash, u256);

pub const Account = struct {
    info: AccountInfo,
    slots: Slots = .empty,
};

pub const SlotRef = struct { key: Hash, slot: Hash };

/// The keys and slots a run of ops wrote, including every slot a wipe or delete cleared.
pub const Touched = struct {
    accounts: std.AutoArrayHashMapUnmanaged(Hash, void) = .empty,
    slots: std.AutoArrayHashMapUnmanaged(SlotRef, void) = .empty,
};

pub const Error = error{ OutOfMemory, StorageOfAbsentAccount };

pub const Model = struct {
    /// Lives in the request's arena.
    arena: std.mem.Allocator,
    accounts: std.AutoArrayHashMapUnmanaged(Hash, Account) = .empty,

    /// Applies `ops` in order, recording what they touch in `touched`.
    pub fn apply(model: *Model, ops: []const Op, touched: *Touched) Error!void {
        for (ops) |*op| {
            try touched.accounts.put(model.arena, op.key, {});
            switch (op.kind) {
                .account => {
                    const entry = try model.accounts.getOrPut(model.arena, op.key);
                    if (!entry.found_existing) entry.value_ptr.* = .{ .info = op.info };
                    entry.value_ptr.info = op.info;
                },
                .storage => {
                    const entry = model.accounts.getPtr(op.key) orelse
                        return error.StorageOfAbsentAccount;
                    try touched.slots.put(model.arena, .{ .key = op.key, .slot = op.slot }, {});
                    if (op.value == 0) {
                        _ = entry.slots.swapRemove(op.slot);
                    } else {
                        try entry.slots.put(model.arena, op.slot, op.value);
                    }
                },
                .wipe => {
                    const entry = model.accounts.getPtr(op.key) orelse continue;
                    try model.touch_slots(op.key, entry, touched);
                    entry.slots.clearRetainingCapacity();
                },
                .delete => {
                    const entry = model.accounts.getPtr(op.key) orelse continue;
                    try model.touch_slots(op.key, entry, touched);
                    assert(model.accounts.swapRemove(op.key));
                },
            }
        }
    }

    fn touch_slots(model: *Model, key: Hash, entry: *const Account, touched: *Touched) Error!void {
        for (entry.slots.keys()) |slot| {
            try touched.slots.put(model.arena, .{ .key = key, .slot = slot }, {});
        }
    }

    pub fn find(model: *const Model, key: *const Hash) ?*const Account {
        return model.accounts.getPtr(key.*);
    }

    /// The post-state values of everything `touched` names, sorted as `HashedWrites` wants.
    pub fn writes(model: *const Model, touched: *const Touched) Error!HashedWrites {
        const accounts = try model.arena.alloc(HashedAccountWrite, touched.accounts.count());
        for (touched.accounts.keys(), accounts) |key, *write| {
            const current = model.accounts.getPtr(key);
            write.* = .{ .key = key, .info = if (current) |entry| entry.info else null };
        }
        std.mem.sort(HashedAccountWrite, accounts, {}, account_less_than);
        const slots = try model.arena.alloc(HashedSlotWrite, touched.slots.count());
        for (touched.slots.keys(), slots) |ref, *write| {
            var value: u256 = 0;
            if (model.accounts.getPtr(ref.key)) |entry| value = entry.slots.get(ref.slot) orelse 0;
            write.* = .{ .key = ref.key, .slot = ref.slot, .value = value };
        }
        std.mem.sort(HashedSlotWrite, slots, {}, slot_less_than);
        assert(accounts.len == touched.accounts.count());
        return .{ .accounts = accounts, .slots = slots };
    }

    /// `hash-builder`: the storage root of the account at `key` from scratch (the empty
    /// root when it is absent or has no storage).
    pub fn storage_root(model: *const Model, key: *const Hash) Error!Hash {
        const entry = model.accounts.getPtr(key.*) orelse return trie.empty_root;
        const slots = try model.arena.dupe(Hash, entry.slots.keys());
        std.mem.sort(Hash, slots, {}, hash_less_than);
        var builder: trie.HashBuilder = .init();
        var values: [2][33]u8 = undefined;
        for (slots, 0..) |slot, index| {
            const word = entry.slots.get(slot).?;
            assert(word != 0);
            const value = trie.state_trie.encode_storage_value(word, &values[index % 2]);
            builder.add_leaf(trie.Nibbles.from_bytes(&slot).slice(), value);
        }
        return builder.root();
    }

    /// `hash-builder`: the state root of the whole state from scratch.
    pub fn state_root(model: *const Model) Error!Hash {
        const keys = try model.arena.dupe(Hash, model.accounts.keys());
        std.mem.sort(Hash, keys, {}, hash_less_than);
        var builder: trie.HashBuilder = .init();
        var values: [2][trie.state_trie.account_rlp_bytes_max]u8 = undefined;
        for (keys, 0..) |key, index| {
            const entry = model.accounts.getPtr(key).?;
            const root = try model.storage_root(&key);
            const leaf: trie.Account = .{
                .nonce = entry.info.nonce,
                .balance = entry.info.balance,
                .code_hash = entry.info.code_hash,
            };
            const value = trie.state_trie.encode_account(&leaf, &root, &values[index % 2]);
            builder.add_leaf(trie.Nibbles.from_bytes(&key).slice(), value);
        }
        return builder.root();
    }
};

fn hash_less_than(_: void, a: Hash, b: Hash) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn account_less_than(_: void, a: HashedAccountWrite, b: HashedAccountWrite) bool {
    return hash_less_than({}, a.key, b.key);
}

fn slot_less_than(_: void, a: HashedSlotWrite, b: HashedSlotWrite) bool {
    return switch (std.mem.order(u8, &a.key, &b.key)) {
        .lt => true,
        .gt => false,
        .eq => hash_less_than({}, a.slot, b.slot),
    };
}

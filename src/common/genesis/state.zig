//! Genesis state commitment: account RLP, storage roots and the state root, built with
//! the trie lane's streaming `HashBuilder` over keccak-hashed, sorted keys.
//!
//! Runs once at startup, so it allocates scratch for sorting from the given allocator
//! and frees it before returning.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const trie = @import("../../execution/trie/root.zig");
const B256 = primitives.B256;
const Address = primitives.Address;

pub const StorageSlot = struct { key: B256, value: u256 };

pub const Account = struct {
    address: Address,
    balance: u256 = 0,
    nonce: u64 = 0,
    code: []const u8 = &.{},
    storage: []const StorageSlot = &.{},
};

/// The account leaf value: rlp([nonce, balance, storage_root, code_hash]).
pub const AccountState = struct {
    nonce: u64,
    balance: u256,
    storage_root: B256,
    code_hash: B256,

    /// Upper bound of the encoding: header + 9 + 33 + 33 + 33.
    pub const encoded_length_max = 3 + 9 + 33 + 33 + 33;
};

const Leaf = struct {
    key: B256,
    value: [AccountState.encoded_length_max]u8,
    value_length: u8,

    fn less_than(_: void, a: Leaf, b: Leaf) bool {
        return std.mem.order(u8, &a.key.bytes, &b.key.bytes) == .lt;
    }
};

/// Root of a secure trie over `leaves` (keys already hashed). Sorts in place.
fn root_of(leaves: []Leaf) B256 {
    std.mem.sort(Leaf, leaves, {}, Leaf.less_than);
    var builder = trie.HashBuilder.init();
    for (leaves, 0..) |*leaf, index| {
        if (index > 0) assert(!leaves[index - 1].key.eql(leaf.key));
        const path = trie.Nibbles.from_bytes(&leaf.key.bytes);
        builder.add_leaf(path.slice(), leaf.value[0..leaf.value_length]);
    }
    return .{ .bytes = builder.root() };
}

pub const Error = std.mem.Allocator.Error || error{DuplicateKey};

/// Storage root: keccak(slot key) -> rlp(value), zero values omitted.
pub fn storage_root(allocator: std.mem.Allocator, slots: []const StorageSlot) Error!B256 {
    const leaves = try allocator.alloc(Leaf, slots.len);
    defer allocator.free(leaves);
    var count: usize = 0;
    for (slots) |slot| {
        if (slot.value == 0) continue;
        leaves[count].key = primitives.keccak256(&slot.key.bytes);
        const encoded = rlp.encode_to(&leaves[count].value, slot.value);
        leaves[count].value_length = @intCast(encoded.len);
        count += 1;
    }
    try check_unique(leaves[0..count]);
    return root_of(leaves[0..count]);
}

fn check_unique(leaves: []Leaf) Error!void {
    std.mem.sort(Leaf, leaves, {}, Leaf.less_than);
    for (1..@max(leaves.len, 1)) |index| {
        if (leaves[index - 1].key.eql(leaves[index].key)) return error.DuplicateKey;
    }
}

pub fn account_state(allocator: std.mem.Allocator, account: Account) Error!AccountState {
    return .{
        .nonce = account.nonce,
        .balance = account.balance,
        .storage_root = try storage_root(allocator, account.storage),
        .code_hash = primitives.keccak256(account.code),
    };
}

/// State root: keccak(address) -> rlp(account state).
pub fn state_root(allocator: std.mem.Allocator, accounts: []const Account) Error!B256 {
    const leaves = try allocator.alloc(Leaf, accounts.len);
    defer allocator.free(leaves);
    for (accounts, leaves) |account, *leaf| {
        leaf.key = primitives.keccak256(&account.address.bytes);
        const state = try account_state(allocator, account);
        const encoded = rlp.encode_to(&leaf.value, state);
        leaf.value_length = @intCast(encoded.len);
    }
    try check_unique(leaves);
    return root_of(leaves);
}

const testing = std.testing;

test "state: empty roots" {
    try testing.expect((try state_root(testing.allocator, &.{})).eql(primitives.empty_root_hash));
    const zero_slot = [_]StorageSlot{.{ .key = .zero, .value = 0 }};
    const root = try storage_root(testing.allocator, &zero_slot);
    try testing.expect(root.eql(primitives.empty_root_hash));
}

test "state: duplicate accounts rejected" {
    const accounts = [_]Account{ .{ .address = .zero }, .{ .address = .zero } };
    try testing.expectError(error.DuplicateKey, state_root(testing.allocator, &accounts));
}

test "state: order independent" {
    var accounts: [8]Account = undefined;
    for (&accounts, 0..) |*account, index| {
        account.* = .{ .address = .zero, .balance = index * 1000 + 1 };
        account.address.bytes[19] = @intCast(index);
    }
    const a = try state_root(testing.allocator, &accounts);
    std.mem.reverse(Account, &accounts);
    const b = try state_root(testing.allocator, &accounts);
    try testing.expect(a.eql(b));
}

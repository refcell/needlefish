//! Differential tests for `StateTrie`: random account and storage writes, checked against a
//! from-scratch root built by the streaming `HashBuilder` over a plain reference model.

const std = @import("std");
const testing = std.testing;

const node = @import("node.zig");
const proof_module = @import("proof.zig");
const state = @import("state_trie.zig");
const HashBuilder = @import("hash_builder.zig").HashBuilder;
const Nibbles = @import("nibbles.zig").Nibbles;
const Prng = @import("../../testing/prng.zig").Prng;
const Hash = node.Hash;

const slots_max = 16;
const accounts_max = 64;

const ModelAccount = struct {
    live: bool = false,
    account: state.Account = .{},
    slots: [slots_max]u256 = @splat(0),
};

/// Address and slot hashes come from small indices so writes collide often.
fn index_hash(tag: u8, index: u64) Hash {
    var input: [9]u8 = undefined;
    input[0] = tag;
    std.mem.writeInt(u64, input[1..9], index, .big);
    return node.keccak256(&input);
}

const Sorted = struct {
    hash: Hash,
    index: u32,

    fn less_than(_: void, a: Sorted, b: Sorted) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

fn model_storage_root(account: *const ModelAccount) Hash {
    var sorted: [slots_max]Sorted = undefined;
    var count: u32 = 0;
    for (account.slots, 0..) |value, index| {
        if (value == 0) continue;
        sorted[count] = .{ .hash = index_hash('s', index), .index = @intCast(index) };
        count += 1;
    }
    std.mem.sort(Sorted, sorted[0..count], {}, Sorted.less_than);
    var values: [slots_max][33]u8 = undefined;
    var builder = HashBuilder.init();
    for (sorted[0..count], 0..) |entry, position| {
        const encoded = state.encode_storage_value(account.slots[entry.index], &values[position]);
        builder.add_leaf(Nibbles.from_bytes(&entry.hash).slice(), encoded);
    }
    return builder.root();
}

fn model_root(model: *const [accounts_max]ModelAccount) Hash {
    var sorted: [accounts_max]Sorted = undefined;
    var count: u32 = 0;
    for (model, 0..) |*account, index| {
        if (!account.live) continue;
        sorted[count] = .{ .hash = index_hash('a', index), .index = @intCast(index) };
        count += 1;
    }
    std.mem.sort(Sorted, sorted[0..count], {}, Sorted.less_than);
    var values: [accounts_max][state.account_rlp_bytes_max]u8 = undefined;
    var builder = HashBuilder.init();
    for (sorted[0..count], 0..) |entry, position| {
        const account = &model[entry.index];
        const storage_root = model_storage_root(account);
        const encoded = state.encode_account(&account.account, &storage_root, &values[position]);
        builder.add_leaf(Nibbles.from_bytes(&entry.hash).slice(), encoded);
    }
    return builder.root();
}

fn random_operation(
    prng: *Prng,
    trie: *state.StateTrie,
    model: *[accounts_max]ModelAccount,
) !void {
    const index = prng.below(accounts_max);
    const address_hash = index_hash('a', index);
    const account = &model[index];
    switch (prng.below(10)) {
        0...2 => {
            const value: state.Account = .{
                .nonce = prng.below(4),
                .balance = if (prng.chance(1, 2)) prng.int(u256) else prng.below(300),
                .code_hash = if (prng.chance(1, 3))
                    index_hash('c', index)
                else
                    node.empty_code_hash,
            };
            try trie.set_account(address_hash, value);
            account.live = true;
            account.account = value;
        },
        3 => {
            try trie.delete_account(address_hash);
            account.* = .{};
        },
        4 => {
            if (!account.live) return;
            try trie.wipe_storage(address_hash);
            account.slots = @splat(0);
        },
        else => {
            if (!account.live) return;
            const slot = prng.below(slots_max);
            const value: u256 = switch (prng.below(4)) {
                0 => 0,
                1 => prng.below(0x100),
                else => prng.int(u256),
            };
            try trie.set_storage(address_hash, index_hash('s', slot), value);
            account.slots[slot] = value;
        },
    }
}

test "state trie: empty state has the empty root" {
    var trie = try state.StateTrie.init(testing.allocator, .{
        .accounts_max = 4,
        .account_nodes_max = 16,
        .storage_nodes_max = 16,
    });
    defer trie.deinit(testing.allocator);
    try testing.expectEqual(node.empty_root, try trie.root());
}

test "state trie: seeded differential against a from-scratch root" {
    var prng = Prng.init(0x57a7e);
    var trie = try state.StateTrie.init(testing.allocator, .{
        .accounts_max = accounts_max,
        .account_nodes_max = accounts_max * 4,
        .storage_nodes_max = accounts_max * slots_max * 3,
        .dirty_accounts_max = 7, // Small, so early flushes are exercised.
    });
    defer trie.deinit(testing.allocator);
    var model: [accounts_max]ModelAccount = @splat(.{});
    var step: u32 = 0;
    while (step < 3000) : (step += 1) {
        try random_operation(&prng, &trie, &model);
        if (prng.chance(1, 40)) try testing.expectEqual(model_root(&model), try trie.root());
    }
    try testing.expectEqual(model_root(&model), try trie.root());
    // Reads agree with the model.
    for (&model, 0..) |*account, index| {
        const address_hash = index_hash('a', index);
        const got = trie.get_account(address_hash);
        try testing.expectEqual(account.live, got != null);
        for (account.slots, 0..) |value, slot| {
            try testing.expectEqual(value, trie.get_storage(address_hash, index_hash('s', slot)));
        }
    }
}

test "state trie: account and storage proofs verify against the state root" {
    var prng = Prng.init(12);
    var trie = try state.StateTrie.init(testing.allocator, .{
        .accounts_max = accounts_max,
        .account_nodes_max = accounts_max * 4,
        .storage_nodes_max = accounts_max * slots_max * 3,
    });
    defer trie.deinit(testing.allocator);
    var model: [accounts_max]ModelAccount = @splat(.{});
    for (0..800) |_| try random_operation(&prng, &trie, &model);
    const state_root = try trie.root();
    const account_proof = try testing.allocator.create(state.StateTrie.AccountProof);
    defer testing.allocator.destroy(account_proof);
    const storage_proof = try testing.allocator.create(state.StateTrie.StorageProof);
    defer testing.allocator.destroy(storage_proof);
    var nodes: [200][]const u8 = undefined;
    for (&model, 0..) |*account, index| {
        const address_hash = index_hash('a', index);
        try trie.prove_account(address_hash, account_proof);
        for (0..account_proof.count) |i| nodes[i] = account_proof.node_at(@intCast(i));
        const account_nodes = nodes[0..account_proof.count];
        const leaf = try proof_module.verify(state_root, &address_hash, account_nodes);
        try testing.expectEqual(account.live, leaf != null);
        if (!account.live) continue;
        const storage_root = trie.storage_root(address_hash);
        const slot_hash = index_hash('s', prng.below(slots_max));
        trie.prove_storage(address_hash, slot_hash, storage_proof);
        for (0..storage_proof.count) |i| nodes[i] = storage_proof.node_at(@intCast(i));
        const storage_nodes = nodes[0..storage_proof.count];
        const value = try proof_module.verify(storage_root, &slot_hash, storage_nodes);
        try testing.expectEqual(trie.get_storage(address_hash, slot_hash) != 0, value != null);
    }
}

test "state trie: storage requires an existing account" {
    var trie = try state.StateTrie.init(testing.allocator, .{
        .accounts_max = 1,
        .account_nodes_max = 8,
        .storage_nodes_max = 8,
    });
    defer trie.deinit(testing.allocator);
    const missing = index_hash('a', 1);
    try testing.expectError(error.UnknownAccount, trie.set_storage(missing, missing, 1));
    try trie.set_account(index_hash('a', 2), .{});
    try testing.expectError(error.AccountsFull, trie.set_account(index_hash('a', 3), .{}));
}

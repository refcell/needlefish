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

test "state trie: set_storage_slots matches per-slot writes" {
    var prng = Prng.init(0x5107);
    const config: state.Config = .{
        .accounts_max = 4,
        .account_nodes_max = 64,
        .storage_nodes_max = 4 * slots_max * 3,
        .dirty_accounts_max = 2,
    };
    var single = try state.StateTrie.init(testing.allocator, config);
    defer single.deinit(testing.allocator);
    var batched = try state.StateTrie.init(testing.allocator, config);
    defer batched.deinit(testing.allocator);
    for (0..4) |index| {
        try single.set_account(index_hash('a', index), .{ .nonce = index });
        try batched.set_account(index_hash('a', index), .{ .nonce = index });
    }
    var slot_hashes: [8]Hash = undefined;
    var values: [8]u256 = undefined;
    for (0..300) |_| {
        const address_hash = index_hash('a', prng.below(4));
        const count = 1 + prng.below(slot_hashes.len);
        // Repeated slots and zeros (deletes) inside one call: later writes win.
        for (slot_hashes[0..count], values[0..count]) |*slot_hash, *value| {
            slot_hash.* = index_hash('s', prng.below(slots_max));
            value.* = if (prng.chance(1, 3)) 0 else prng.int(u256);
            try single.set_storage(address_hash, slot_hash.*, value.*);
        }
        try batched.set_storage_slots(address_hash, slot_hashes[0..count], values[0..count]);
        if (prng.chance(1, 10)) try testing.expectEqual(try single.root(), try batched.root());
    }
    try testing.expectEqual(try single.root(), try batched.root());
}

/// Serial (`rehash_threads = 0`) and parallel tries fed the same random blocks.
const RehashPair = struct {
    serial: state.StateTrie,
    parallel: state.StateTrie,
    models: [2][accounts_max]ModelAccount = @splat(@splat(.{})),

    fn init(pair: *RehashPair, threads: u32, nodes_min: u32, dirty_max: u32) !void {
        var config: state.Config = .{
            .accounts_max = accounts_max,
            .account_nodes_max = accounts_max * 4,
            .storage_nodes_max = accounts_max * slots_max * 3,
            .dirty_accounts_max = dirty_max,
        };
        pair.* = .{ .serial = undefined, .parallel = undefined };
        pair.serial = try state.StateTrie.init(testing.allocator, config);
        errdefer pair.serial.deinit(testing.allocator);
        config.rehash_threads = threads;
        config.rehash_parallel_nodes_min = nodes_min;
        pair.parallel = try state.StateTrie.init(testing.allocator, config);
        errdefer pair.parallel.deinit(testing.allocator);
        try pair.serial.track_changes(testing.allocator);
        try pair.parallel.track_changes(testing.allocator);
    }

    fn deinit(pair: *RehashPair) void {
        pair.parallel.deinit(testing.allocator);
        pair.serial.deinit(testing.allocator);
    }

    /// One block of `operations` random writes (deletions and wipes included) on both
    /// tries, then both roots, every cached node reference, and the change marks agree.
    fn block(pair: *RehashPair, seed: u64, operations: u32) !void {
        var prng_serial = Prng.init(seed);
        var prng_parallel = Prng.init(seed);
        for (0..operations) |_| {
            try random_operation(&prng_serial, &pair.serial, &pair.models[0]);
            try random_operation(&prng_parallel, &pair.parallel, &pair.models[1]);
        }
        const root = try pair.serial.root();
        try testing.expectEqual(root, try pair.parallel.root());
        const serial = &pair.serial.storage;
        const parallel = &pair.parallel.storage;
        try testing.expectEqual(serial.free_count, parallel.free_count);
        for (serial.nodes, parallel.nodes, 0..) |*a, *b, index| {
            try testing.expectEqual(a.kind, b.kind);
            if (a.kind == .free) continue;
            const want = &serial.cache[index];
            const got = &parallel.cache[index];
            try testing.expectEqual(want.len, got.len);
            if (want.len > 0) try testing.expectEqualSlices(u8, want.slice(), got.slice());
        }
        try testing.expectEqualSlices(u64, serial.changed, parallel.changed);
    }
};

test "state trie: parallel storage rehash matches serial (seeded differential)" {
    var prng = Prng.init(0x9a4a11e1);
    // Forced parallel on every flush (also the early flushes of a small dirty list), and
    // the default threshold with blocks big enough to cross it now and then.
    const setups = [_][3]u32{ .{ 4, 0, 4096 }, .{ 4, 0, 5 }, .{ 3, 0, 64 }, .{ 4, 64, 4096 } };
    for (setups) |setup| {
        const pair = try testing.allocator.create(RehashPair);
        defer testing.allocator.destroy(pair);
        try pair.init(setup[0], setup[1], setup[2]);
        defer pair.deinit();
        for (0..60) |_| try pair.block(prng.int(u64), @intCast(1 + prng.below(400)));
        try testing.expectEqual(model_root(&pair.models[1]), try pair.parallel.root());
    }
}

fn fuzz_parallel_rehash(_: void, smith: *testing.Smith) anyerror!void {
    var input: [64]u8 = undefined;
    const length = smith.slice(&input);
    if (length < 9) return;
    const pair = try testing.allocator.create(RehashPair);
    defer testing.allocator.destroy(pair);
    const threads: u32 = 1 + input[0] % 4;
    try pair.init(threads, 0, 2 + input[0] / 4 % 16);
    defer pair.deinit();
    var at: usize = 1;
    while (at + 8 <= length) : (at += 8) {
        const seed = std.mem.readInt(u64, input[at..][0..8], .little);
        try pair.block(seed, @intCast(1 + seed % 300));
    }
}

test "state trie: fuzz parallel storage rehash against serial" {
    try testing.fuzz({}, fuzz_parallel_rehash, .{});
}

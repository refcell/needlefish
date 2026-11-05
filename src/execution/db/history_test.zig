//! Historical proofs store tests: proofs from history at every block of the window equal the
//! proofs of a live `State` moved back to that block (random workloads with reorgs), window
//! edges, capacity, and fuzzed node/value decoders.

const std = @import("std");
const testing = std.testing;

const history = @import("history.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Hash = state_module.Hash;
const StateTrie = trie.StateTrie;

const addresses_max = 24;
const slots_max = 12;
const blocks_total = 32;
const window_blocks = 10;

const state_config: state_module.Config = .{
    .accounts_max = 64,
    .storage_slots_max = addresses_max * slots_max,
    .codes_max = 64,
    .code_bytes_max = 64 * 64,
    .account_nodes_max = 512,
    .storage_nodes_max = 4096,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = addresses_max,
    .storage_max = addresses_max * slots_max,
    .codes_max = 64,
    .code_bytes_max = 64 * 64,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = addresses_max,
    .slots_max = addresses_max * slots_max,
    .codes_max = 64,
};

const history_config: history.Config = .{
    .window_blocks = window_blocks,
    .paths_max = 16384,
    .small_versions_max = 8192,
    .large_versions_max = 2048,
};

/// Address `index`; `addresses_max` itself is never written (exclusion proofs).
fn address_of(index: usize) Address {
    var address: Address = @splat(0x22);
    address[19] = @intCast(index);
    return address;
}

fn random_write(prng: *Prng, overlay: *Overlay) !void {
    const index = prng.below(addresses_max);
    const address = address_of(index);
    switch (prng.below(12)) {
        0...3 => {
            var info: AccountInfo = .{ .nonce = prng.below(8), .balance = prng.below(1 << 40) };
            if (prng.chance(1, 4)) {
                const kind: u8 = @intCast(prng.below(8));
                const code: [8]u8 = @splat(kind);
                info.code_hash = try overlay.insert_code(code[0 .. kind + 1]);
            }
            try overlay.set_account(address, info);
        },
        4 => try overlay.set_account(address, null),
        5 => {
            if (overlay.basic(address) == null) return;
            try overlay.wipe_storage(address);
        },
        else => {
            if (overlay.basic(address) == null) return;
            const slot = prng.below(slots_max);
            const shift: u8 = @intCast(prng.below(256));
            const value: u256 = if (prng.chance(1, 3)) 0 else prng.int(u256) >> shift;
            try overlay.set_storage(address, slot, value);
        },
    }
}

/// Proof buffers are large; the tests keep one set on the heap.
const Proofs = struct {
    live_account: StateTrie.AccountProof = .{},
    history_account: StateTrie.AccountProof = .{},
    live_storage: StateTrie.StorageProof = .{},
    history_storage: [slots_max]StateTrie.StorageProof = undefined,
    values: [slots_max]u256 = undefined,
};

fn expect_same_proof(live: anytype, got: anytype) !void {
    try testing.expectEqual(live.count, got.count);
    var index: u32 = 0;
    while (index < live.count) : (index += 1) {
        try testing.expectEqualSlices(u8, live.node_at(index), got.node_at(index));
    }
}

fn verify(root: Hash, key: *const Hash, proof: anytype) !?[]const u8 {
    var nodes: [proof.ends.len][]const u8 = undefined;
    for (nodes[0..proof.count], 0..) |*slot, index| slot.* = proof.node_at(@intCast(index));
    return trie.verify_proof(root, key, nodes[0..proof.count]);
}

const all_slots: [slots_max]u256 = blk: {
    var slots: [slots_max]u256 = undefined;
    for (&slots, 0..) |*slot, index| slot.* = index;
    break :blk slots;
};

/// History at `number` must equal the live `state`, which holds block `number`.
fn expect_matches_live(
    store: *const history.Store,
    state: *State,
    number: u64,
    address_index: usize,
    proofs: *Proofs,
) !void {
    const root = try state.state_root();
    try testing.expectEqual(root, try store.state_root_at(number));
    const address = address_of(address_index);
    const address_hash = trie.node.keccak256(&address);
    const account = try store.get_proof(
        number,
        address,
        &all_slots,
        &proofs.history_account,
        &proofs.history_storage,
        &proofs.values,
    );
    try state.state_trie.prove_account(address_hash, &proofs.live_account);
    try expect_same_proof(&proofs.live_account, &proofs.history_account);
    const proven = try verify(root, &address_hash, &proofs.history_account);
    const info = state.basic(address);
    try testing.expectEqual(info != null, account != null);
    try testing.expectEqual(info != null, proven != null);
    if (info) |expected| {
        try testing.expectEqual(expected.nonce, account.?.nonce);
        try testing.expectEqual(expected.balance, account.?.balance);
        try testing.expectEqual(expected.code_hash, account.?.code_hash);
        const storage_root = state.state_trie.storage_root(address_hash);
        try testing.expectEqual(storage_root, account.?.storage_root);
    }
    const storage_root = if (account) |found| found.storage_root else trie.empty_root;
    for (all_slots, 0..) |slot, index| {
        var slot_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_bytes, slot, .big);
        const slot_hash = trie.node.keccak256(&slot_bytes);
        state.state_trie.prove_storage(address_hash, slot_hash, &proofs.live_storage);
        try expect_same_proof(&proofs.live_storage, &proofs.history_storage[index]);
        try testing.expectEqual(state.storage(address, slot), proofs.values[index]);
        const value = try verify(storage_root, &slot_hash, &proofs.history_storage[index]);
        try testing.expectEqual(proofs.values[index] != 0, value != null);
    }
}

const Harness = struct {
    state: State,
    overlay: Overlay,
    store: history.Store,
    changesets: [blocks_total + 1]Changeset,
    proofs: *Proofs,

    /// Sets up in place: `overlay` keeps a pointer to `state`.
    fn init(self: *Harness) !void {
        self.state = try State.init(testing.allocator, state_config);
        errdefer self.state.deinit(testing.allocator);
        try self.state.state_trie.track_changes(testing.allocator);
        self.overlay = try Overlay.init(testing.allocator, &self.state, overlay_config);
        errdefer self.overlay.deinit(testing.allocator);
        self.store = try history.Store.init(testing.allocator, history_config);
        errdefer self.store.deinit(testing.allocator);
        for (&self.changesets) |*c| c.* = try Changeset.init(testing.allocator, changeset_config);
        self.proofs = try testing.allocator.create(Proofs);
        self.proofs.* = .{};
    }

    fn deinit(self: *Harness) void {
        testing.allocator.destroy(self.proofs);
        for (&self.changesets) |*c| c.deinit(testing.allocator);
        self.store.deinit(testing.allocator);
        self.overlay.deinit(testing.allocator);
        self.state.deinit(testing.allocator);
    }

    fn commit(self: *Harness, prng: *Prng, number: u64) !void {
        for (0..prng.range(1, 30)) |_| try random_write(prng, &self.overlay);
        const root = try self.overlay.commit(&self.changesets[number]);
        try self.store.commit_block(&self.state.state_trie, number);
        try testing.expectEqual(root, try self.store.state_root_at(number));
    }

    fn reorg(self: *Harness, prng: *Prng, head: u64) !u64 {
        const oldest = self.store.window().?.oldest;
        const depth = prng.range(1, head - oldest);
        var height = head;
        while (height > head - depth) : (height -= 1) {
            try self.state.unwind(&self.changesets[height]);
        }
        try self.store.unwind_to(height);
        return height;
    }
};

fn run_seed(seed: u64) !void {
    var prng = Prng.init(seed);
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    for (0..40) |_| try random_write(&prng, &harness.overlay);
    _ = try harness.overlay.commit(&harness.changesets[0]);
    try harness.store.reset(&harness.state.state_trie, 0);
    var head: u64 = 0;
    for (0..blocks_total) |_| {
        const oldest = harness.store.window().?.oldest;
        if (head > oldest and prng.chance(1, 5)) {
            head = try harness.reorg(&prng, head);
        } else {
            head += 1;
            try harness.commit(&prng, head);
        }
        const index = prng.below(addresses_max + 1);
        try expect_matches_live(&harness.store, &harness.state, head, index, harness.proofs);
    }
    // Sweep: every block of the window against the state unwound to it.
    const window = harness.store.window().?;
    try testing.expectEqual(head, window.head);
    try testing.expect(window.head - window.oldest + 1 <= window_blocks);
    var number = window.head;
    while (true) : (number -= 1) {
        for (0..addresses_max + 1) |index| {
            try expect_matches_live(&harness.store, &harness.state, number, index, harness.proofs);
        }
        if (number == window.oldest) break;
        try harness.state.unwind(&harness.changesets[number]);
    }
}

test "history: proofs at every block of the window match an unwound state" {
    // Two seeds keep Debug runtime low; the long fuzz run covers more.
    for (0..2) |seed| try run_seed(0x415700 + seed);
}

test "history: window edges and errors" {
    var prng = Prng.init(0xed6e);
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var proof: StateTrie.AccountProof = .{};
    const address = address_of(1);
    try testing.expectError(error.NotInitialized, harness.store.prove_account(0, address, &proof));
    try testing.expectError(error.NotInitialized, harness.store.unwind_to(0));
    for (0..20) |_| try random_write(&prng, &harness.overlay);
    _ = try harness.overlay.commit(&harness.changesets[0]);
    // Start the window at block 5: earlier blocks were never recorded.
    try harness.store.reset(&harness.state.state_trie, 5);
    const store = &harness.store;
    try testing.expectError(error.BlockOutOfWindow, store.prove_account(4, address, &proof));
    try testing.expectError(error.BlockOutOfWindow, store.prove_account(6, address, &proof));
    try testing.expectError(error.NotNextBlock, store.commit_block(&harness.state.state_trie, 7));
    var head: u64 = 5;
    while (head < 5 + window_blocks + 3) {
        head += 1;
        try harness.commit(&prng, head);
    }
    const window = harness.store.window().?;
    try testing.expectEqual(head - window_blocks + 1, window.oldest);
    try testing.expectError(
        error.BlockOutOfWindow,
        harness.store.prove_account(window.oldest - 1, address, &proof),
    );
    _ = try harness.store.prove_account(window.oldest, address, &proof);
    try testing.expectError(error.BlockOutOfWindow, harness.store.unwind_to(window.oldest - 1));
    try testing.expectError(error.BlockOutOfWindow, harness.store.unwind_to(head + 1));
    try expect_matches_live(&harness.store, &harness.state, head, 1, harness.proofs);
}

test "history: a full store refuses the block and keeps its head" {
    var prng = Prng.init(0xf011);
    var state = try State.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    try state.state_trie.track_changes(testing.allocator);
    var overlay = try Overlay.init(testing.allocator, &state, overlay_config);
    defer overlay.deinit(testing.allocator);
    var changeset = try Changeset.init(testing.allocator, changeset_config);
    defer changeset.deinit(testing.allocator);
    for (0..20) |_| try random_write(&prng, &overlay);
    _ = try overlay.commit(&changeset);
    var store = try history.Store.init(testing.allocator, .{
        .window_blocks = 4,
        .paths_max = 4096,
        .small_versions_max = state.state_trie.accounts.node_count() +
            state.state_trie.storage.node_count() + 2,
        .large_versions_max = 64,
    });
    defer store.deinit(testing.allocator);
    try store.reset(&state.state_trie, 0);
    for (0..40) |_| try random_write(&prng, &overlay);
    _ = try overlay.commit(&changeset);
    try testing.expectError(error.HistoryFull, store.commit_block(&state.state_trie, 1));
    try testing.expectEqual(@as(u64, 0), store.window().?.head);
    // Block 0 is intact: proofs match the state moved back to it.
    try state.unwind(&changeset);
    const proofs = try testing.allocator.create(Proofs);
    defer testing.allocator.destroy(proofs);
    proofs.* = .{};
    for (0..addresses_max + 1) |index| try expect_matches_live(&store, &state, 0, index, proofs);
}

fn check_decoders(input: []const u8) void {
    var rest: [64]u8 = undefined;
    for (&rest, 0..) |*nibble, index| nibble.* = @intCast((index * 7 + input.len) % 16);
    const tail = rest[@min(input.len, rest.len)..];
    if (history.step_node(input, tail)) |step| switch (step) {
        .found => |value| std.debug.assert(value.len > 0 and value.len < input.len),
        .absent => {},
        .next => |next| std.debug.assert(next.consumed > 0 and next.consumed <= tail.len),
    } else |_| {}
    if (history.decode_account(input)) |account| {
        std.debug.assert(input.len >= 70);
        _ = account;
    } else |_| {}
    if (history.decode_storage_value(input)) |value| {
        std.debug.assert(value != 0);
    } else |_| {}
}

fn fuzz_decoders(_: void, smith: *testing.Smith) anyerror!void {
    var input: [600]u8 = undefined;
    const length = smith.slice(&input);
    check_decoders(input[0..length]);
}

test "history: fuzz node and value decoders" {
    try testing.fuzz({}, fuzz_decoders, .{});
}

test "history: seeded fuzz node and value decoders" {
    var prng = Prng.init(0xdec0);
    // Valid encodings, then random corruptions of them.
    var trie_state = try StateTrie.init(testing.allocator, .{
        .accounts_max = 16,
        .account_nodes_max = 64,
        .storage_nodes_max = 256,
    });
    defer trie_state.deinit(testing.allocator);
    for (0..12) |index| {
        const address_hash = trie.node.keccak256(&address_of(index));
        try trie_state.set_account(address_hash, .{ .nonce = index, .balance = prng.int(u64) });
        try trie_state.set_storage(address_hash, address_hash, prng.int(u256) | 1);
    }
    var proof: StateTrie.AccountProof = .{};
    try trie_state.prove_account(trie.node.keccak256(&address_of(3)), &proof);
    var buffer: [StateTrie.account_node_bytes_max]u8 = undefined;
    for (0..4000) |_| {
        const node_bytes = proof.node_at(@intCast(prng.below(proof.count)));
        @memcpy(buffer[0..node_bytes.len], node_bytes);
        var length = node_bytes.len;
        if (prng.chance(1, 2)) buffer[prng.below(length)] = @truncate(prng.int(u8));
        if (prng.chance(1, 4)) length = prng.below(length + 1);
        if (prng.chance(1, 8)) {
            length = prng.below(buffer.len);
            prng.fill(buffer[0..length]);
        }
        check_decoders(buffer[0..length]);
    }
}

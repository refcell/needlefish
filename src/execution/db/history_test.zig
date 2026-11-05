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
/// Changesets kept for unwinding, indexed by block number; more than any window.
const changesets_ring = 16;
/// Most versions one block of `random_write` workloads writes (checked by the long run).
const block_versions_max = 512;

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
    .prune_per_commit = block_versions_max,
};

fn state_nodes(state: *const State) u32 {
    return state.state_trie.accounts.node_count() + state.state_trie.storage.node_count();
}

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
    changesets: [changesets_ring]Changeset,
    proofs: *Proofs,

    /// Sets up in place: `overlay` keeps a pointer to `state`.
    fn init(self: *Harness, config: history.Config) !void {
        self.state = try State.init(testing.allocator, state_config);
        errdefer self.state.deinit(testing.allocator);
        try self.state.state_trie.track_changes(testing.allocator);
        self.overlay = try Overlay.init(testing.allocator, &self.state, overlay_config);
        errdefer self.overlay.deinit(testing.allocator);
        self.store = try history.Store.init(testing.allocator, config);
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

    fn changeset(self: *Harness, number: u64) *Changeset {
        return &self.changesets[number % changesets_ring];
    }

    fn commit(self: *Harness, prng: *Prng, number: u64) !void {
        try self.commit_writes(prng, number, prng.range(1, 30));
    }

    fn commit_writes(self: *Harness, prng: *Prng, number: u64, writes: u64) !void {
        for (0..writes) |_| try random_write(prng, &self.overlay);
        const root = try self.overlay.commit(self.changeset(number));
        try self.store.commit_block(&self.state.state_trie, number);
        try testing.expectEqual(root, try self.store.state_root_at(number));
    }

    fn reorg(self: *Harness, prng: *Prng, head: u64) !u64 {
        const oldest = self.store.window().?.oldest;
        const depth = prng.range(1, head - oldest);
        var height = head;
        while (height > head - depth) : (height -= 1) {
            try self.state.unwind(self.changeset(height));
        }
        try self.store.unwind_to(height);
        return height;
    }

    /// Checks every block of the window against the state unwound to it (the state ends at
    /// the oldest block), then drains the prune queue and checks that exactly the nodes of
    /// the oldest block's trie remain at or before it (deleted paths are freed).
    fn sweep(self: *Harness) !void {
        try testing.expect(try self.store.check_metadata() > 0);
        const window = self.store.window().?;
        var number = window.head;
        while (true) : (number -= 1) {
            for (0..addresses_max + 1) |index| {
                try expect_matches_live(&self.store, &self.state, number, index, self.proofs);
            }
            if (number == window.oldest) break;
            try self.state.unwind(self.changeset(number));
        }
        _ = self.store.prune_step(self.store.usage().prune_queue);
        try testing.expectEqual(@as(u32, 0), self.store.usage().prune_queue);
        try testing.expectEqual(state_nodes(&self.state), self.store.base_node_count());
        for (0..addresses_max + 1) |index| {
            try expect_matches_live(&self.store, &self.state, number, index, self.proofs);
        }
    }
};

fn run_seed(seed: u64) !void {
    var prng = Prng.init(seed);
    var harness: Harness = undefined;
    try harness.init(history_config);
    defer harness.deinit();
    for (0..40) |_| try random_write(&prng, &harness.overlay);
    _ = try harness.overlay.commit(harness.changeset(0));
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
    const window = harness.store.window().?;
    try testing.expectEqual(head, window.head);
    try testing.expect(window.head - window.oldest + 1 <= window_blocks);
    try harness.sweep();
}

test "history: proofs at every block of the window match an unwound state" {
    // Two seeds keep Debug runtime low; raise the count locally for deeper runs.
    for (0..2) |seed| try run_seed(0x415700 + seed);
}

test "history: window edges and errors" {
    var prng = Prng.init(0xed6e);
    var harness: Harness = undefined;
    try harness.init(history_config);
    defer harness.deinit();
    var proof: StateTrie.AccountProof = .{};
    const address = address_of(1);
    try testing.expectError(error.NotInitialized, harness.store.prove_account(0, address, &proof));
    try testing.expectError(error.NotInitialized, harness.store.unwind_to(0));
    for (0..20) |_| try random_write(&prng, &harness.overlay);
    _ = try harness.overlay.commit(harness.changeset(0));
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
        .prune_per_commit = 64,
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

/// Sized per the `Store` sizing rule: N trie nodes plus `window_blocks` blocks of B versions.
fn sized_config(window: u32, prune_per_commit: u32) history.Config {
    const nodes_max = state_config.account_nodes_max + state_config.storage_nodes_max;
    const bound = nodes_max + window * block_versions_max;
    return .{
        .window_blocks = window,
        .paths_max = bound,
        .small_versions_max = bound,
        .large_versions_max = bound,
        .prune_per_commit = prune_per_commit,
    };
}

fn start(harness: *Harness, prng: *Prng) !void {
    for (0..40) |_| try random_write(prng, &harness.overlay);
    _ = try harness.overlay.commit(harness.changeset(0));
    try harness.store.reset(&harness.state.state_trie, 0);
}

test "history: long run stays within the sizing bound and never fills" {
    const window = 6;
    var prng = Prng.init(0x10e6);
    var harness: Harness = undefined;
    try harness.init(sized_config(window, block_versions_max));
    defer harness.deinit();
    try start(&harness, &prng);
    var nodes_seen: u32 = state_nodes(&harness.state);
    var block_versions_seen: u32 = 0;
    var head: u64 = 0;
    // About 60 windows, with reorgs; every commit must fit (no HistoryFull).
    for (0..360) |_| {
        const oldest = harness.store.window().?.oldest;
        if (head > oldest and prng.chance(1, 6)) {
            head = try harness.reorg(&prng, head);
        } else {
            head += 1;
            try harness.commit(&prng, head);
            block_versions_seen = @max(block_versions_seen, harness.store.head_block_versions());
        }
        nodes_seen = @max(nodes_seen, state_nodes(&harness.state));
        const usage = harness.store.usage();
        // The bound of the sizing rule, with the N and B this run actually reached.
        const bound = nodes_seen + window * block_versions_seen;
        try testing.expect(usage.small_versions + usage.large_versions <= bound);
        try testing.expect(usage.paths <= bound);
        try testing.expect(usage.prune_queue <= block_versions_seen);
        if (head % 4 == 0) {
            const index = prng.below(addresses_max + 1);
            try expect_matches_live(&harness.store, &harness.state, head, index, harness.proofs);
        }
    }
    try testing.expect(block_versions_seen <= block_versions_max);
    try harness.sweep();
}

test "history: prune_step with a budget of one makes progress and keeps proofs" {
    var prng = Prng.init(0x7171);
    var harness: Harness = undefined;
    // No pruning on commit: the queue only shrinks through explicit steps.
    try harness.init(sized_config(4, 0));
    defer harness.deinit();
    try start(&harness, &prng);
    var head: u64 = 0;
    while (head < 24) {
        head += 1;
        try harness.commit(&prng, head);
    }
    const queued = harness.store.usage().prune_queue;
    try testing.expect(queued > 0);
    const used = harness.store.usage().small_versions + harness.store.usage().large_versions;
    var steps: u32 = 0;
    while (harness.store.usage().prune_queue > 0) : (steps += 1) {
        try testing.expectEqual(@as(u32, 1), harness.store.prune_step(1));
        try testing.expectEqual(queued - steps - 1, harness.store.usage().prune_queue);
        if (steps % 64 == 0) {
            const index = prng.below(addresses_max + 1);
            const oldest = harness.store.window().?.oldest;
            _ = try harness.store.state_root_at(oldest);
            try expect_matches_live(&harness.store, &harness.state, head, index, harness.proofs);
        }
    }
    try testing.expectEqual(queued, steps);
    try testing.expectEqual(@as(u32, 0), harness.store.prune_step(1));
    const after = harness.store.usage().small_versions + harness.store.usage().large_versions;
    try testing.expect(after < used);
    try harness.sweep();
}

test "history: a deleted account frees its storage trie paths" {
    var prng = Prng.init(0xde1e);
    var harness: Harness = undefined;
    try harness.init(sized_config(3, block_versions_max));
    defer harness.deinit();
    try start(&harness, &prng);
    const address = address_of(addresses_max - 1);
    const address_hash = trie.node.keccak256(&address);
    try harness.overlay.set_account(address, .{ .nonce = 1, .balance = 7 });
    for (0..slots_max) |slot| try harness.overlay.set_storage(address, slot, slot + 1);
    _ = try harness.overlay.commit(harness.changeset(1));
    try harness.store.commit_block(&harness.state.state_trie, 1);
    try testing.expect(harness.store.contains_path(address_hash, &.{}));
    const paths_before = harness.store.usage().paths;
    try harness.overlay.set_account(address, null);
    _ = try harness.overlay.commit(harness.changeset(2));
    try harness.store.commit_block(&harness.state.state_trie, 2);
    // Empty blocks move the window past the deletion.
    var head: u64 = 2;
    while (head < 6) {
        head += 1;
        try harness.commit_writes(&prng, head, 0);
    }
    _ = harness.store.prune_step(harness.store.usage().prune_queue);
    try testing.expect(!harness.store.contains_path(address_hash, &.{}));
    for (0..16) |nibble| {
        const path = [1]u8{@intCast(nibble)};
        try testing.expect(!harness.store.contains_path(address_hash, &path));
    }
    // At least the storage trie's root plus one node per slot are gone.
    try testing.expect(harness.store.usage().paths + slots_max + 1 <= paths_before);
    try testing.expectEqual(state_nodes(&harness.state), harness.store.base_node_count());
    try harness.sweep();
}

test "history: a full store with a full window refuses the block atomically" {
    var prng = Prng.init(0xa70e);
    var harness: Harness = undefined;
    const window = 3;
    try harness.init(history_config);
    defer harness.deinit();
    for (0..40) |_| try random_write(&prng, &harness.overlay);
    _ = try harness.overlay.commit(harness.changeset(0));
    // Tight capacity: the base nodes plus room for small blocks only.
    const nodes = state_nodes(&harness.state);
    harness.store.deinit(testing.allocator);
    harness.store = try history.Store.init(testing.allocator, .{
        .window_blocks = window,
        .paths_max = nodes + 96,
        .small_versions_max = nodes + 96,
        .large_versions_max = 96,
        .prune_per_commit = 96,
    });
    try harness.store.reset(&harness.state.state_trie, 0);
    var head: u64 = 0;
    while (head < 8) {
        head += 1;
        try harness.commit_writes(&prng, head, 1);
    }
    const before = harness.store.window().?;
    const usage_before = harness.store.usage();
    try testing.expectEqual(@as(u64, window), before.head - before.oldest + 1);
    for (0..12) |index| {
        var info: AccountInfo = .{ .nonce = 9, .balance = prng.below(1 << 40) | 1 };
        info.nonce += index;
        try harness.overlay.set_account(address_of(index), info);
        for (0..6) |slot| try harness.overlay.set_storage(address_of(index), slot, 5);
    }
    _ = try harness.overlay.commit(harness.changeset(head + 1));
    const result = harness.store.commit_block(&harness.state.state_trie, head + 1);
    try testing.expectError(error.HistoryFull, result);
    const after = harness.store.window().?;
    try testing.expectEqual(before.oldest, after.oldest);
    try testing.expectEqual(before.head, after.head);
    try testing.expectEqual(usage_before.paths, harness.store.usage().paths);
    try harness.state.unwind(harness.changeset(head + 1));
    try harness.sweep();
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

/// Window invariants under a byte budget: contiguous, ending at `head`, within both the
/// block window and the budget; the block below the oldest is out of window.
fn expect_budget_window(harness: *Harness, head: u64, bytes_max: u64) !void {
    const window = harness.store.window().?;
    try testing.expectEqual(head, window.head);
    try testing.expect(window.oldest <= window.head);
    try testing.expect(window.head - window.oldest < harness.store.config.window_blocks);
    try testing.expect(harness.store.usage().bytes <= bytes_max);
    if (window.oldest == 0) return;
    var proof: StateTrie.AccountProof = .{};
    try testing.expectError(
        error.BlockOutOfWindow,
        harness.store.prove_account(window.oldest - 1, address_of(1), &proof),
    );
}

test "history: a byte budget shrinks the window instead of dropping history" {
    for (0..2) |seed| {
        var prng = Prng.init(0xb0d9e7 + seed);
        var harness: Harness = undefined;
        try harness.init(sized_config(window_blocks, block_versions_max));
        defer harness.deinit();
        // A state near its largest (every account and slot written), so its growth cannot
        // outrun the budget, then room for it and a few blocks: 10 blocks cannot fit.
        for (0..addresses_max * slots_max) |_| try random_write(&prng, &harness.overlay);
        _ = try harness.overlay.commit(harness.changeset(0));
        try harness.store.reset(&harness.state.state_trie, 0);
        const bytes_max = 2 * harness.store.bytes_used();
        harness.store.config.bytes_max = bytes_max;
        var head: u64 = 0;
        var window_min: u64 = window_blocks;
        for (0..120) |_| {
            const oldest = harness.store.window().?.oldest;
            if (head > oldest and prng.chance(1, 6)) {
                head = try harness.reorg(&prng, head);
            } else {
                head += 1;
                try harness.commit_writes(&prng, head, prng.range(10, 40));
            }
            try expect_budget_window(&harness, head, bytes_max);
            const window = harness.store.window().?;
            const length = window.head - window.oldest + 1;
            if (head > window_blocks) window_min = @min(window_min, length);
            const index = prng.below(addresses_max + 1);
            try expect_matches_live(&harness.store, &harness.state, head, index, harness.proofs);
        }
        try testing.expect(harness.store.window_shrinks > 0);
        try testing.expect(window_min < window_blocks);
        // Every block left in the window still serves proofs equal to the unwound state.
        try harness.sweep();
    }
}

test "history: a state above the byte budget is refused" {
    // The unit sizes docs/PERF.md and the lane decisions quote.
    try testing.expectEqual(@as(u64, 196), history.small_version_bytes);
    try testing.expectEqual(@as(u64, 682), history.large_version_bytes);
    try testing.expectEqual(@as(u64, 84), history.path_bytes);
    var prng = Prng.init(0xb0d9);
    var harness: Harness = undefined;
    try harness.init(sized_config(4, block_versions_max));
    defer harness.deinit();
    try start(&harness, &prng);
    const state_bytes = harness.store.bytes_used();
    // The head state alone does not fit: the commit shrinks to that block and refuses.
    harness.store.config.bytes_max = state_bytes / 2;
    try testing.expectError(error.HistoryFull, harness.commit_writes(&prng, 1, 1));
    const window = harness.store.window().?;
    try testing.expectEqual(window.oldest, window.head);
    // A reset under the same budget keeps no history at all.
    try testing.expectError(error.HistoryFull, harness.store.reset(&harness.state.state_trie, 1));
    try testing.expect(harness.store.window() == null);
    harness.store.config.bytes_max = null;
    try harness.store.reset(&harness.state.state_trie, 1);
    try testing.expectEqual(@as(u64, 1), harness.store.window().?.head);
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

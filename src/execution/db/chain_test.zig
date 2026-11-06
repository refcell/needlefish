//! Chain store tests: random block trees and head switches against a parent-walk model,
//! byte-ring eviction, and a reorg that moves `State` with the blocks' changesets.

const std = @import("std");
const testing = std.testing;

const chain_module = @import("chain.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const ChainStore = chain_module.ChainStore;
const Hash = chain_module.Hash;

fn block_hash(id: u32) Hash {
    var hash: Hash = @splat(0);
    std.mem.writeInt(u32, hash[0..4], id + 1, .big);
    return hash;
}

fn transaction_hash(id: u32, index: u32) Hash {
    var hash: Hash = @splat(0xee);
    std.mem.writeInt(u32, hash[0..4], id, .big);
    std.mem.writeInt(u32, hash[4..8], index, .big);
    return hash;
}

/// Header bytes are a pure function of the block id, so stored bytes can be re-checked.
fn header_bytes(id: u32, out: *[64]u8) []const u8 {
    const length = 8 + id % 50;
    for (out[0..length], 0..) |*byte, index| byte.* = @truncate(id *% 31 +% index);
    return out[0..length];
}

const Node = struct { parent: ?u32, number: u64 };

fn insert_block(store: *ChainStore, nodes: []const Node, id: u32) !void {
    var header: [64]u8 = undefined;
    var transactions: [3]Hash = undefined;
    for (&transactions, 0..) |*t, index| t.* = transaction_hash(id, @intCast(index));
    const parent_hash = if (nodes[id].parent) |p| block_hash(p) else @as(Hash, @splat(0));
    try store.insert(&.{
        .hash = block_hash(id),
        .parent_hash = parent_hash,
        .number = nodes[id].number,
        .timestamp = nodes[id].number * 2,
        .header = header_bytes(id, &header),
        .body = "body",
        .receipts = "receipts",
        .transaction_hashes = transactions[0 .. id % 4],
        .changeset = "",
    });
}

fn check_canonical(store: *const ChainStore, nodes: []const Node, head: u32) !void {
    var current: ?u32 = head;
    while (current) |id| {
        const hash = block_hash(id);
        try testing.expectEqualSlices(u8, &hash, &store.canonical_hash(nodes[id].number).?);
        var header: [64]u8 = undefined;
        try testing.expectEqualSlices(u8, header_bytes(id, &header), store.block(hash).?.header);
        if (id % 4 > 0) {
            const location = store.transaction(transaction_hash(id, 0)).?;
            try testing.expectEqualSlices(u8, &hash, &location.block_hash);
        }
        try testing.expect(store.is_ancestor(hash, block_hash(head)));
        current = nodes[id].parent;
    }
    try testing.expectEqual(@as(?Hash, null), store.canonical_hash(nodes[head].number + 1));
}

test "chain: random block trees and head switches" {
    var prng = Prng.init(0xc4a1);
    const config: chain_module.Config = .{
        .blocks_max = 256,
        .bytes_max = 1 << 16,
        .transactions_max = 1024,
        .canonical_max = 256,
        .reorg_depth_max = 256,
    };
    var store = try ChainStore.init(testing.allocator, config);
    defer store.deinit(testing.allocator);
    var plan = try ChainStore.plan_init(testing.allocator, config);
    defer ChainStore.plan_deinit(testing.allocator, &plan);
    var nodes: [200]Node = undefined;
    nodes[0] = .{ .parent = null, .number = 0 };
    try insert_block(&store, &nodes, 0);
    try store.plan_reorg(block_hash(0), &plan);
    store.set_head(&plan);
    var head: u32 = 0;
    for (1..nodes.len) |index| {
        const id: u32 = @intCast(index);
        // Prefer extending recent blocks so branches grow long enough to reorg.
        const parent: u32 = @intCast(prng.range(if (id > 8) id - 8 else 0, id - 1));
        nodes[id] = .{ .parent = parent, .number = nodes[parent].number + 1 };
        try insert_block(&store, &nodes, id);
        if (!prng.chance(1, 3)) continue;
        const target: u32 = @intCast(prng.range(if (id > 12) id - 12 else 0, id));
        try store.plan_reorg(block_hash(target), &plan);
        // Every unwound block is old canonical, every applied block becomes canonical.
        for (plan.unwind_hashes()) |hash| try testing.expect(store.is_canonical(hash));
        store.set_head(&plan);
        for (plan.unwind_hashes()) |hash| {
            const applied = for (plan.apply_hashes()) |h| {
                if (std.mem.eql(u8, &h, &hash)) break true;
            } else false;
            try testing.expect(applied or !store.is_canonical(hash));
        }
        head = target;
        try testing.expectEqualSlices(u8, &block_hash(head), &store.head().?.hash);
        try check_canonical(&store, &nodes, head);
    }
}

test "chain: byte ring evicts oldest blocks and their transactions" {
    const config: chain_module.Config = .{
        .blocks_max = 64,
        .bytes_max = 600,
        .transactions_max = 64,
        .canonical_max = 64,
        .reorg_depth_max = 8,
    };
    var store = try ChainStore.init(testing.allocator, config);
    defer store.deinit(testing.allocator);
    var nodes: [100]Node = undefined;
    for (&nodes, 0..) |*n, index| {
        n.* = .{ .parent = if (index == 0) null else @intCast(index - 1), .number = index };
    }
    for (0..nodes.len) |index| try insert_block(&store, &nodes, @intCast(index));
    try testing.expect(store.block_count() < nodes.len);
    try testing.expectEqual(@as(?chain_module.BlockMeta, null), store.meta(block_hash(0)));
    try testing.expectEqual(@as(?chain_module.TransactionLocation, null), store.transaction(
        transaction_hash(1, 0),
    ));
    // Every retained block still has intact bytes.
    var retained: u32 = 0;
    for (0..nodes.len) |index| {
        const id: u32 = @intCast(index);
        const view = store.block(block_hash(id)) orelse continue;
        var header: [64]u8 = undefined;
        try testing.expectEqualSlices(u8, header_bytes(id, &header), view.header);
        try testing.expectEqualSlices(u8, "receipts", view.receipts);
        retained += 1;
    }
    try testing.expectEqual(store.block_count(), retained);
    try testing.expect(store.meta(block_hash(99)) != null);
}

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;

/// Executes a fake block: a few balance and storage writes derived from the block id.
fn execute(overlay: *Overlay, id: u32, changeset: *Changeset) !state_module.Hash {
    for (0..4) |index| {
        var address: state_module.Address = @splat(0);
        address[0] = @truncate(id *% 7 +% index);
        try overlay.set_account(address, .{ .nonce = id, .balance = id * 1000 + index });
        try overlay.set_storage(address, index, id + 1);
    }
    return overlay.commit(changeset);
}

test "chain: reorg moves state with stored changesets" {
    const config: chain_module.Config = .{
        .blocks_max = 64,
        .bytes_max = 1 << 18,
        .transactions_max = 64,
        .canonical_max = 64,
        .reorg_depth_max = 16,
    };
    const state_config: state_module.Config = .{
        .accounts_max = 256,
        .storage_slots_max = 1024,
        .codes_max = 4,
        .code_bytes_max = 64,
        .account_nodes_max = 1024,
        .storage_nodes_max = 4096,
    };
    var store = try ChainStore.init(testing.allocator, config);
    defer store.deinit(testing.allocator);
    var plan = try ChainStore.plan_init(testing.allocator, config);
    defer ChainStore.plan_deinit(testing.allocator, &plan);
    var state = try State.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    var overlay = try Overlay.init(testing.allocator, &state, .{
        .accounts_max = 16,
        .slots_max = 64,
        .codes_max = 4,
    });
    defer overlay.deinit(testing.allocator);
    var changeset = try Changeset.init(testing.allocator, .{
        .accounts_max = 16,
        .storage_max = 64,
        .codes_max = 4,
        .code_bytes_max = 64,
    });
    defer changeset.deinit(testing.allocator);
    const buffer = try testing.allocator.alloc(u8, 1 << 14);
    defer testing.allocator.free(buffer);

    // Chain A: blocks 0..6 (ids 0..6). Fork B from block 3: ids 10..13, numbers 4..7.
    var roots: [16]state_module.Hash = undefined;
    var parent_of: [16]?u32 = @splat(null);
    var number_of: [16]u64 = undefined;
    const genesis_root = try state.state_root();
    try store.insert(&.{
        .hash = block_hash(0),
        .parent_hash = @splat(0),
        .number = 0,
        .timestamp = 0,
        .header = "genesis",
        .body = "",
        .receipts = "",
        .transaction_hashes = &.{},
        .changeset = "",
    });
    try store.plan_reorg(block_hash(0), &plan);
    store.set_head(&plan);
    number_of[0] = 0;
    roots[0] = genesis_root;
    const ids_a = [_]u32{ 1, 2, 3, 4, 5, 6 };
    for (ids_a) |id| {
        parent_of[id] = id - 1;
        number_of[id] = id;
        try commit_block(&store, &plan, &overlay, &changeset, buffer, id, id - 1, id, &roots);
    }
    // Build fork B off-canonical: unwind to block 3, execute B, record changesets, then
    // return to chain A, as a node does when it validates a side branch.
    try move_head(&store, &plan, &state, &changeset, block_hash(3));
    try testing.expectEqual(roots[3], try state.state_root());
    var parent: u32 = 3;
    for (10..14) |index| {
        const id: u32 = @intCast(index);
        number_of[id] = number_of[parent] + 1;
        const number = number_of[id];
        try commit_block(&store, &plan, &overlay, &changeset, buffer, id, parent, number, &roots);
        parent = id;
    }
    try move_head(&store, &plan, &state, &changeset, block_hash(6));
    try testing.expectEqual(roots[6], try state.state_root());
    // The reorg: A6 -> B13 unwinds 6, 5, 4 and applies 10..13 purely from changesets.
    try move_head(&store, &plan, &state, &changeset, block_hash(13));
    try testing.expectEqual(@as(u32, 3), plan.unwind_len);
    try testing.expectEqual(@as(u32, 4), plan.apply_len);
    try testing.expectEqual(roots[13], try state.state_root());
    try testing.expectEqual(@as(u64, 7), store.head().?.number);
}

fn commit_block(
    store: *ChainStore,
    plan: *chain_module.ReorgPlan,
    overlay: *Overlay,
    changeset: *Changeset,
    buffer: []u8,
    id: u32,
    parent: u32,
    number: u64,
    roots: *[16]state_module.Hash,
) !void {
    roots[id] = try execute(overlay, id, changeset);
    try store.insert(&.{
        .hash = block_hash(id),
        .parent_hash = block_hash(parent),
        .number = number,
        .timestamp = number * 2,
        .header = "header",
        .body = "",
        .receipts = "",
        .transaction_hashes = &.{},
        .changeset = changeset.encode(buffer),
    });
    try store.plan_reorg(block_hash(id), plan);
    try testing.expectEqual(@as(u32, 0), plan.unwind_len);
    store.set_head(plan);
}

/// Moves state and the canonical head to `target` using stored changesets only.
fn move_head(
    store: *ChainStore,
    plan: *chain_module.ReorgPlan,
    state: *State,
    changeset: *Changeset,
    target: Hash,
) !void {
    try store.plan_reorg(target, plan);
    for (plan.unwind_hashes()) |hash| {
        try changeset.decode(store.block(hash).?.changeset);
        try state.unwind(changeset);
    }
    for (plan.apply_hashes()) |hash| {
        try changeset.decode(store.block(hash).?.changeset);
        try state.apply(changeset);
    }
    store.set_head(plan);
}

test "chain: a first head without its parent stored indexes the parent as canonical" {
    const config: chain_module.Config = .{
        .blocks_max = 8,
        .bytes_max = 1 << 12,
        .transactions_max = 16,
        .canonical_max = 8,
        .reorg_depth_max = 8,
    };
    // A checkpoint's retained blocks 5..7: block 4 (block_hash(4)) is evicted.
    const nodes = [_]Node{
        .{ .parent = null, .number = 0 }, .{ .parent = 0, .number = 1 },
        .{ .parent = 1, .number = 2 },    .{ .parent = 2, .number = 3 },
        .{ .parent = 3, .number = 4 },    .{ .parent = 4, .number = 5 },
        .{ .parent = 5, .number = 6 },    .{ .parent = 6, .number = 7 },
    };
    var store = try ChainStore.init(testing.allocator, config);
    defer store.deinit(testing.allocator);
    var plan = try ChainStore.plan_init(testing.allocator, config);
    defer ChainStore.plan_deinit(testing.allocator, &plan);
    for (5..8) |id| try insert_block(&store, &nodes, @intCast(id));
    try store.plan_reorg(block_hash(7), &plan);
    store.set_head(&plan);
    for (5..8) |id| {
        const hash = block_hash(@intCast(id));
        try testing.expectEqualSlices(u8, &hash, &store.canonical_hash(id).?);
    }
    try testing.expectEqualSlices(u8, &block_hash(4), &store.canonical_hash(4).?);
    try testing.expect(store.meta(block_hash(4)) == null);
    try testing.expectEqual(@as(?Hash, null), store.canonical_hash(3));

    // A head whose block is evicted: the head and its parent are canonical by number.
    var evicted = try ChainStore.init(testing.allocator, config);
    defer evicted.deinit(testing.allocator);
    evicted.restore_evicted_head(.{
        .hash = block_hash(7),
        .parent_hash = block_hash(6),
        .number = 7,
        .timestamp = 14,
    });
    try testing.expectEqualSlices(u8, &block_hash(7), &evicted.canonical_hash(7).?);
    try testing.expectEqualSlices(u8, &block_hash(6), &evicted.canonical_hash(6).?);
    try testing.expectEqual(@as(?Hash, null), evicted.canonical_hash(5));
}

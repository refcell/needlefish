//! `NodeBuilder` tests through the node's `Engine(Chain)` over `SimIo`: an FCU with
//! attributes returns before the build, the zero-delay timer builds and seals, getPayload
//! returns the imported block, which equals a `Chain` build of the same transactions; an
//! early getPayload seals at once; expiry. A seeded + `std.testing.fuzz` model check of
//! FCU / getPayload / time interleavings.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const engine = @import("../../execution/engine/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const io = @import("../../utilities/io/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const node_builder_module = @import("node_builder.zig");

const types = engine.types;
const B256 = primitives.B256;
const Node = fixture.Node;
const NodeBuilder = node_builder_module.NodeBuilder(io.SimIo);
const l2 = &chainspec.ChainSpec.presets.base_devnet;
const ns_per_ms = std.time.ns_per_ms;

const Harness = struct {
    world: io.SimWorld,
    sim: io.SimIo,
    node: *Node,
    builder: NodeBuilder,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.world = try io.SimWorld.init(testing.allocator, .{ .seed = 7 });
        errdefer harness.world.deinit();
        try io.SimIo.init(&harness.sim, testing.allocator, &harness.world, .{
            .host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        errdefer harness.sim.deinit();
        harness.node = try Node.create_for(l2);
        errdefer harness.node.destroy();
        try harness.builder.init(testing.allocator, &harness.sim, &harness.node.chain, .{
            .builder = .{ .transactions_max = 64, .transaction_bytes_max = 1 << 14 },
            .rejection_cache_capacity = 64,
        });
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.builder.deinit(testing.allocator);
        harness.node.destroy();
        harness.sim.deinit();
        harness.world.deinit();
        testing.allocator.destroy(harness);
    }

    fn submit_pool(harness: *Harness, buffers: [][256]u8) !void {
        for (buffers, 0..) |*buffer, n| {
            try fixture.submit(harness.node, @intCast(n % 3 + 1), n / 3, 5, buffer);
        }
    }

    fn forkchoice_updated(
        harness: *Harness,
        head: B256,
        attributes: ?*const payload.PayloadAttributes,
    ) !types.ForkchoiceUpdated {
        const timestamp = if (attributes) |a| a.timestamp else 1;
        const version = types.forkchoice_version(l2, timestamp);
        const choice = fixture.forkchoice(head);
        return harness.node.engine.forkchoice_updated(version, choice, attributes);
    }

    fn get_payload(
        harness: *Harness,
        id: payload.PayloadId,
        timestamp: u64,
    ) types.EngineError!fixture.Chain.Built {
        const version = types.get_payload_version(l2, timestamp);
        const now_ns = harness.world.now_ns;
        const built = harness.node.engine.get_payload(version, id);
        // getPayload never waits: no simulated time passes while it runs.
        assert(harness.world.now_ns == now_ns);
        return built;
    }

    fn service(harness: *Harness) *node_builder_module.Service {
        return &harness.builder.service;
    }
};

fn genesis(harness: *const Harness) B256 {
    return .{ .bytes = harness.node.chain.genesis_hash };
}

/// A `Chain` build of exactly `transactions` on `parent` on a fresh follower node.
fn follower_build(
    attributes: *const payload.PayloadAttributes,
    transactions: []const []const u8,
) !B256 {
    const follower = try Node.create_for(l2);
    defer follower.destroy();
    var forced = attributes.*;
    forced.transactions = transactions;
    forced.no_tx_pool = true;
    const id: payload.PayloadId = @splat(0x99);
    const parent = follower.chain.block(.{ .bytes = follower.chain.genesis_hash }).?;
    try follower.chain.start_build(id, parent, &forced);
    return follower.chain.built(id).?.block_hash;
}

/// The transactions of a stored block, copied out of the chain's record.
fn block_transactions(node: *Node, hash: B256, out: [][]const u8) ![]const []const u8 {
    var record = node.chain.record(hash.bytes) orelse return error.TestUnexpectedResult;
    var count: usize = 0;
    while (!record.transactions.is_empty()) : (count += 1) {
        out[count] = try record.transactions.bytes();
    }
    return out[0..count];
}

test "node builder: FCU returns first, the timer builds, getPayload equals a Chain build" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const attributes = fixture.attributes_l2(2, 0xfe);
    const updated = try harness.forkchoice_updated(genesis(harness), &attributes);
    try testing.expectEqual(types.Status.valid, updated.payload_status.status);
    const id = updated.payload_id.?;
    // The handler only started the job.
    try testing.expectEqual(@as(u64, 0), harness.service().metrics.blocks_sealed.get());
    try testing.expect(harness.node.chain.payload_builder != null);
    harness.world.run_for_ns(ns_per_ms);
    try testing.expectEqual(@as(u64, 1), harness.service().metrics.blocks_sealed.get());
    const built = try harness.get_payload(id, attributes.timestamp);
    try testing.expectEqual(@as(u64, 2), built.timestamp);
    try testing.expect(built.block_value > 0);
    var list: [64][]const u8 = undefined;
    const transactions = try block_transactions(harness.node, built.block_hash, &list);
    try testing.expectEqual(@as(usize, 6), transactions.len);
    const expected = try follower_build(&attributes, transactions);
    try testing.expectEqualSlices(u8, &expected.bytes, &built.block_hash.bytes);
    // A repeated getPayload returns the same block; the block can become head.
    const again = try harness.get_payload(id, attributes.timestamp);
    try testing.expectEqualSlices(u8, &built.block_hash.bytes, &again.block_hash.bytes);
    const head = try harness.forkchoice_updated(built.block_hash, null);
    try testing.expectEqual(types.Status.valid, head.payload_status.status);
    try testing.expectEqualSlices(u8, &built.block_hash.bytes, &harness.node.chain.head_hash());
}

test "node builder: getPayload before the timer seals at once with the forced txs" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const attributes = fixture.attributes_l2(2, 1);
    const updated = try harness.forkchoice_updated(genesis(harness), &attributes);
    const built = try harness.get_payload(updated.payload_id.?, attributes.timestamp);
    try testing.expectEqual(@as(u64, 1), harness.service().metrics.blocks_sealed_early.get());
    var list: [64][]const u8 = undefined;
    const transactions = try block_transactions(harness.node, built.block_hash, &list);
    // The cutoff moved to now: no simulated time passed, so no pool transaction fits.
    try testing.expectEqual(@as(usize, 0), transactions.len);
    // The timer finds no job left.
    harness.world.run_for_ns(ns_per_ms);
    try testing.expectEqual(@as(u64, 1), harness.service().metrics.blocks_sealed.get());
}

test "node builder: an unresolved job expires and getPayload fails" {
    const harness = try Harness.create();
    defer harness.destroy();
    const attributes = fixture.attributes_l2(2, 1);
    const updated = try harness.forkchoice_updated(genesis(harness), &attributes);
    harness.world.run_for_ns(800 * ns_per_ms);
    try testing.expectEqual(@as(u64, 1), harness.service().metrics.jobs_expired.get());
    const result = harness.get_payload(updated.payload_id.?, attributes.timestamp);
    try testing.expectError(error.UnknownPayload, result);
}

const Model = struct {
    id: payload.PayloadId,
    parent: B256,
    timestamp: u64,
    expires_ns: u64,
};

/// One random interleaving against the model; returns the blocks resolved.
fn random_interleaving(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [9][256]u8 = undefined;
    try harness.submit_pool(buffers[0..prng.below(buffers.len + 1)]);
    var head = genesis(harness);
    var head_timestamp: u64 = 0;
    var last_built: ?B256 = null;
    var model: ?Model = null;
    var resolved: u64 = 0;
    for (0..32) |_| {
        switch (prng.below(8)) {
            0, 1 => {
                var attributes = fixture.attributes_l2(head_timestamp + 1 + prng.below(3), 1);
                attributes.suggested_fee_recipient.bytes[0] = @intCast(prng.below(4));
                attributes.no_tx_pool = prng.chance(1, 5);
                const updated = try harness.forkchoice_updated(head, &attributes);
                try testing.expectEqual(types.Status.valid, updated.payload_status.status);
                model = .{
                    .id = updated.payload_id.?,
                    .parent = head,
                    .timestamp = attributes.timestamp,
                    .expires_ns = harness.world.now_ns + 700 * ns_per_ms,
                };
            },
            2, 3 => if (try check_get_payload(harness, prng, &model)) |hash| {
                last_built = hash;
                resolved += 1;
            },
            4 => if (last_built) |hash| {
                const updated = try harness.forkchoice_updated(hash, null);
                try testing.expectEqual(types.Status.valid, updated.payload_status.status);
                head = hash;
                head_timestamp = harness.node.chain.header(hash.bytes).?.timestamp;
            },
            else => {
                harness.world.run_for_ns(prng.below(400 * ns_per_ms));
                const active = model orelse continue;
                if (harness.world.now_ns > active.expires_ns) model = null;
            },
        }
        // At most one active job, and it is the model's.
        const active_id = harness.service().active_id();
        if (model) |m| {
            if (harness.world.now_ns == m.expires_ns and active_id == null) model = null;
        }
        try testing.expectEqual(model != null, active_id != null);
        if (model) |m| try testing.expectEqualSlices(u8, &m.id, &active_id.?);
    }
    return resolved;
}

/// getPayload of the active job (usually) or of an unknown id; returns the built hash.
fn check_get_payload(harness: *Harness, prng: *Prng, model: *?Model) !?B256 {
    const active = model.* orelse {
        const unknown: payload.PayloadId = @splat(0xee);
        try testing.expectError(error.UnknownPayload, harness.get_payload(unknown, 1));
        return null;
    };
    if (prng.chance(1, 4)) {
        const unknown: payload.PayloadId = @splat(0xee);
        try testing.expectError(error.UnknownPayload, harness.get_payload(unknown, 1));
        return null;
    }
    const built = try harness.get_payload(active.id, active.timestamp);
    model.* = null;
    const header = harness.node.chain.header(built.block_hash.bytes).?;
    try testing.expectEqualSlices(u8, &active.parent.bytes, &header.parent_hash.bytes);
    try testing.expectEqual(active.timestamp, header.timestamp);
    try testing.expect(harness.service().active_id() == null);
    return built.block_hash;
}

test "node builder: seeded fuzz of FCU, getPayload and time interleavings" {
    var prng = Prng.init(0xb10c);
    var resolved: u64 = 0;
    for (0..16) |_| resolved += try random_interleaving(&prng);
    try testing.expect(resolved >= 16);
}

fn fuzz_node_builder(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_interleaving(&prng);
}

test "node builder: fuzz" {
    try testing.fuzz({}, fuzz_node_builder, .{});
}

//! Block gossip handler tests: three handlers gossip a signed block end to end; a block
//! from the wrong signer is rejected, not forwarded, and sinks the sender's score.

const std = @import("std");
const handler = @import("handler.zig");
const block = @import("block.zig");
const validity = @import("validity.zig");
const ssz = @import("ssz_payload.zig");
const rpc = @import("rpc.zig");
const peer_id = @import("../peers/peer_id.zig");
const primitives = @import("../../../common/primitives/root.zig");
const consensus_types = @import("../../../common/consensus/root.zig");
const rollup_config = @import("../../protocol/rollup_config.zig");
const secp256k1 = @import("../../../common/crypto/secp256k1/root.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const BlockGossip = handler.BlockGossip;
const ns_per_s = std.time.ns_per_s;
const now_s: u64 = 2_000_000;
const nodes = 3;

const Net = struct {
    rollup: rollup_config.RollupConfig,
    secret: [32]u8,
    gossips: [nodes]*BlockGossip,
    prngs: [nodes]Prng,
    slots: [nodes][nodes]?handler.Slot = @splat(@splat(null)),
    buffer: []u8,
    now_ns: u64 = now_s * ns_per_s,
    tx_storage: [512]u8 = undefined,

    fn init(net: *Net) !void {
        const allocator = std.testing.allocator;
        net.rollup = .{ .l2_chain_id = 8453 };
        net.rollup.upgrades.set(.ecotone, 0);
        net.secret = @splat(0);
        net.secret[31] = 5;
        net.slots = @splat(@splat(null));
        net.now_ns = now_s * ns_per_s;
        const signer: primitives.Address = .{ .bytes = try secp256k1.address(net.secret) };
        net.buffer = try allocator.alloc(u8, 1 << 20);
        for (0..nodes) |index| {
            net.prngs[index] = Prng.init(index + 1);
            net.gossips[index] = try BlockGossip.create(allocator, .{
                .rollup = &net.rollup,
                .unsafe_block_signer = signer,
                .mcache = .{ .entries_max = 64, .arena_bytes = 1 << 20 },
            }, net.prngs[index].random());
        }
        for (0..nodes) |a| for (a + 1..nodes) |b| net.connect(a, b);
    }

    fn deinit(net: *Net) void {
        for (net.gossips) |gossip| gossip.destroy(std.testing.allocator);
        std.testing.allocator.free(net.buffer);
    }

    fn test_peer(index: usize) peer_id.PeerId {
        var bytes: [34]u8 = @splat(@intCast(index + 1));
        bytes[0] = 0x12;
        bytes[1] = 32;
        return peer_id.from_bytes(&bytes) catch unreachable;
    }

    fn connect(net: *Net, a: usize, b: usize) void {
        net.slots[a][b] = net.gossips[a].router.add_peer(test_peer(b), true, null, 0).?;
        net.slots[b][a] = net.gossips[b].router.add_peer(test_peer(a), false, null, 0).?;
    }

    fn flush(net: *Net) !void {
        var rounds: u32 = 0;
        while (rounds < 32) : (rounds += 1) {
            var moved = false;
            for (0..nodes) |a| for (0..nodes) |b| {
                const slot = net.slots[a][b] orelse continue;
                const frame = net.gossips[a].router.drain(slot, net.buffer) orelse continue;
                moved = true;
                const header = (try rpc.frame_decode(frame, rpc.frame_size_max_default)).?;
                const from = net.slots[b][a].?;
                net.gossips[b].on_rpc(from, header.payload, net.now_ns) catch {};
            };
            if (!moved) return;
        }
        return error.NotQuiet;
    }

    fn heartbeat(net: *Net) !void {
        net.now_ns += ns_per_s / 2;
        for (net.gossips) |gossip| gossip.heartbeat(net.now_ns);
        try net.flush();
    }

    fn payload(net: *Net, number: u64) !ssz.ExecutionPayload {
        const deposit: consensus_types.Envelope = .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(@truncate(number)) },
            .from = .zero,
            .to = .create,
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = "needlefish",
        } };
        const encoded = deposit.encode_to(net.tx_storage[256..]);
        var result: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = number,
            .timestamp = now_s,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = ssz.Transactions.encode(net.tx_storage[0..256], &.{encoded}),
        };
        result.block_hash = try validity.block_hash(&net.rollup, &result, beacon_root);
        return result;
    }
};

const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };

test "block gossip: a signed block reaches every node and is delivered once" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..3) |_| try net.heartbeat();
    const value = try net.payload(7);
    _ = try net.gossips[0].publish(net.secret, beacon_root, value, net.now_ns);
    try net.flush();
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (net.gossips[1..]) |gossip| {
        try std.testing.expectEqual(@as(u64, 1), gossip.stats.accepted);
        try std.testing.expectEqual(@as(u64, 1), gossip.stats.versions[2]); // Ecotone: v3.
        try std.testing.expectEqual(@as(u64, 1), gossip.router.stats.message);
        try std.testing.expect(gossip.router.stats.subscribed > 0);
        const envelope = gossip.pop_block(scratch).?;
        try std.testing.expectEqual(@as(u64, 7), envelope.payload.block_number);
        try std.testing.expect(envelope.payload.block_hash.eql(value.block_hash));
        try std.testing.expect(gossip.pop_block(scratch) == null);
    }
}

test "block gossip: wrong signer is rejected, not forwarded, and penalized" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..3) |_| try net.heartbeat();
    var attacker = net.secret;
    attacker[31] = 9;
    const value = try net.payload(8);
    _ = try net.gossips[0].publish(attacker, beacon_root, value, net.now_ns);
    try net.flush();
    for (net.gossips[1..], 1..) |gossip, index| {
        try std.testing.expectEqual(@as(u64, 0), gossip.stats.accepted);
        try std.testing.expectEqual(@as(u64, 1), gossip.stats.rejected);
        const signer = @backingInt(validity.Reason.invalid_signer);
        try std.testing.expectEqual(@as(u64, 1), gossip.stats.failed[signer]);
        try std.testing.expectEqual(@as(u64, 0), gossip.stats.decode_failed);
        _ = index;
    }
    try net.heartbeat();
    const slot = net.slots[1][0].?;
    try std.testing.expect(net.gossips[1].router.peer_score_value(slot) < 0);
}

test "block gossip: old topics retire after their fork leaves the age window" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    const gossip = net.gossips[0];
    // Ecotone (v3) is active from genesis, so v1 and v2 are retired at once.
    try std.testing.expectEqual(@as(u32, 2), gossip.retire_topics(net.now_ns));
    try std.testing.expect(!gossip.router.is_subscribed(gossip.topics[0]));
    try std.testing.expect(!gossip.router.is_subscribed(gossip.topics[1]));
    try std.testing.expect(gossip.router.is_subscribed(gossip.topics[2]));
    try std.testing.expect(gossip.router.is_subscribed(gossip.topics[3]));
    try std.testing.expectEqual(@as(u32, 0), gossip.retire_topics(0));
    var value = try net.payload(9);
    value.version = .v2;
    const result = gossip.publish(net.secret, null, value, net.now_ns);
    try std.testing.expectError(error.NotSubscribed, result);
    try std.testing.expectEqual([4]u64{ 1, 1, 0, 0 }, gossip.stats.retirements);
    try std.testing.expectEqual([4]u64{ 0, 1, 0, 0 }, gossip.stats.blocked_outbound);
}

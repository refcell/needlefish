//! Chain tests over the Engine API: one node builds, a second independent node imports
//! the same payloads; both must agree. Covers pool inclusion and pruning, invalid
//! payloads (state untouched), reorgs (rollback + re-execution) and a seeded fuzz.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const chain_module = @import("chain.zig");
const Executor = @import("executor.zig").Executor;
const StateDb = @import("state_db.zig").StateDb;

const fixture = @import("test_fixture.zig");
const B256 = primitives.B256;
const spec = fixture.spec;
const types = engine_module.types;
const Node = fixture.Node;
const senders = fixture.senders;
const address_of = fixture.address_of;
const build = fixture.build;
const submit = fixture.submit;
const forkchoice = fixture.forkchoice;

/// Imports `hash` from `from` into `to` through newPayload.
fn import(from: *Node, to: *Node, hash: B256) !types.PayloadStatus {
    var transactions: [64][]const u8 = undefined;
    var withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
    const p = from.chain.payload_of(hash.bytes, &transactions, &withdrawals).?;
    const stored = from.chain.record(hash.bytes).?;
    var requests: [2][]const u8 = undefined;
    var requests_decoder = stored.requests;
    var count: usize = 0;
    while (!requests_decoder.is_empty()) : (count += 1) {
        requests[count] = try requests_decoder.bytes();
    }
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = stored.header.parent_beacon_block_root,
        .execution_requests = requests[0..count],
    };
    return to.engine.new_payload(types.new_payload_version(spec, p.timestamp), &p, &params);
}

test "chain: build, import on a second node, pool inclusion and pruning" {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    try testing.expectEqualSlices(u8, &builder.chain.genesis_hash, &follower.chain.genesis_hash);
    var buffers: [2][256]u8 = undefined;
    try submit(builder, 1, 0, 5, &buffers[0]);
    try submit(builder, 1, 1, 7, &buffers[1]);
    const genesis: B256 = .{ .bytes = builder.chain.genesis_hash };
    const hash = try build(builder, genesis, 12, 0xfe);
    const record = builder.chain.record(hash.bytes).?;
    var decoder = record.transactions;
    var included: u32 = 0;
    while (!decoder.is_empty()) : (included += 1) _ = try decoder.bytes();
    try testing.expectEqual(@as(u32, 2), included);
    try testing.expectEqual(@as(u64, 42_000), record.header.gas_used);

    const status = try import(builder, follower, hash);
    try testing.expectEqual(types.Status.valid, status.status);
    const v = types.forkchoice_version(spec, 12);
    _ = try builder.engine.forkchoice_updated(v, forkchoice(hash), null);
    _ = try follower.engine.forkchoice_updated(v, forkchoice(hash), null);
    try testing.expectEqualSlices(u8, &(try builder.db.root()), &(try follower.db.root()));
    try testing.expectEqual(@as(u32, 0), builder.pool.count());
    try testing.expectEqual(@as(u256, 12), follower.db.get_account(address_of(9).bytes).?.balance);
    try testing.expectEqualSlices(u8, &hash.bytes, &follower.chain.store.canonical_hash(1).?);
    var first = record.transactions;
    const tx_hash = primitives.keccak256(try first.bytes()).bytes;
    const location = follower.chain.find_transaction(tx_hash).?;
    try testing.expectEqualSlices(u8, &hash.bytes, &location.block_hash);
    try testing.expectEqual(@as(u32, 0), location.index);
    try testing.expect(follower.chain.find_transaction(@splat(0)) == null);
}

test "chain: tampered payload is invalid and leaves state untouched" {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    const genesis: B256 = .{ .bytes = builder.chain.genesis_hash };
    const hash = try build(builder, genesis, 12, 0xfe);
    var transactions: [64][]const u8 = undefined;
    var withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
    var p = builder.chain.payload_of(hash.bytes, &transactions, &withdrawals).?;
    const before = try follower.db.root();
    // A wrong state root with a matching block hash: only execution can catch it.
    p.state_root = .{ .bytes = @splat(0x11) };
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = .zero,
        .execution_requests = &.{},
    };
    p.block_hash = (try engine_module.block.header_of(spec, &p, &params)).hash();
    const status = try follower.engine.new_payload(.v4, &p, &params);
    try testing.expectEqual(types.Status.invalid, status.status);
    try testing.expectEqualStrings("state root mismatch", status.validation_error.?);
    try testing.expectEqualSlices(u8, &before, &(try follower.db.root()));
    try testing.expectEqual(types.Status.valid, (try import(builder, follower, hash)).status);
}

test "chain: reorg between sibling branches" {
    const node = try Node.create();
    defer node.destroy();
    var buffer: [256]u8 = undefined;
    const genesis: B256 = .{ .bytes = node.chain.genesis_hash };
    try submit(node, 1, 0, 100, &buffer);
    const a1 = try build(node, genesis, 12, 0xaa);
    const a2 = try build(node, a1, 24, 0xaa);
    const b1 = try build(node, genesis, 13, 0xbb);
    const v = types.forkchoice_version(spec, 24);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a2), null);
    const root_a2 = try node.db.root();
    try testing.expectEqual(@as(u256, 100), node.db.get_account(address_of(9).bytes).?.balance);
    _ = try node.engine.forkchoice_updated(v, forkchoice(b1), null);
    try testing.expect(node.db.get_account(address_of(9).bytes) == null);
    try testing.expectEqualSlices(u8, &b1.bytes, &node.chain.store.canonical_hash(1).?);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a2), null);
    try testing.expectEqualSlices(u8, &root_a2, &(try node.db.root()));
}

/// Random builds on random known blocks and random forkchoice moves; a follower imports
/// every block and must agree on every state.
fn random_chain(prng: *Prng) !void {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    var known: [16]B256 = undefined;
    var timestamps: [16]u64 = undefined;
    known[0] = .{ .bytes = builder.chain.genesis_hash };
    timestamps[0] = 0;
    var known_len: usize = 1;
    var nonces: [senders]u64 = @splat(0);
    var buffers: [16][256]u8 = undefined;
    for (1..16) |step| {
        if (prng.chance(1, 2)) {
            const from = prng.below(senders);
            // Nonces may be stale after reorgs; the pool or builder then skips the tx.
            const value = prng.below(100);
            submit(builder, @intCast(from + 1), nonces[from], value, &buffers[step]) catch {};
            nonces[from] += 1;
        }
        const parent = prng.below(known_len);
        const timestamp = timestamps[parent] + prng.range(1, 12);
        const hash = try build(builder, known[parent], timestamp, @intCast(prng.below(4)));
        try testing.expectEqual(types.Status.valid, (try import(builder, follower, hash)).status);
        known[known_len] = hash;
        timestamps[known_len] = timestamp;
        known_len += 1;
        const head = known[prng.below(known_len)];
        const v = types.forkchoice_version(spec, timestamp);
        _ = try builder.engine.forkchoice_updated(v, forkchoice(head), null);
        _ = try follower.engine.forkchoice_updated(v, forkchoice(head), null);
        try testing.expectEqualSlices(u8, &(try builder.db.root()), &(try follower.db.root()));
        const header = builder.chain.header(head.bytes).?;
        try testing.expectEqualSlices(u8, &header.state_root.bytes, &(try builder.db.root()));
    }
}

test "chain: seeded fuzz builder and follower agree" {
    var prng = Prng.init(0xc4a1);
    for (0..3) |_| try random_chain(&prng);
}

fn fuzz_chain(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try random_chain(&prng);
}

test "chain: fuzz" {
    try testing.fuzz({}, fuzz_chain, .{});
}

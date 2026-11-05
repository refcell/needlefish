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
const flz = @import("../../common/flz/root.zig");
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
    const version = types.new_payload_version(to.spec, p.timestamp);
    return to.engine.new_payload(version, &p, &params);
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

test "chain: DA limits admit by tx and cumulative block size" {
    const none: chain_module.DaLimits = .{};
    try testing.expect(none.admits(std.math.maxInt(u64), std.math.maxInt(u64)));
    const limits: chain_module.DaLimits = .{ .tx_bytes_max = 100, .block_bytes_max = 250 };
    try testing.expect(limits.admits(0, 100));
    try testing.expect(!limits.admits(0, 101));
    try testing.expect(limits.admits(150, 100));
    try testing.expect(!limits.admits(151, 100));
    try testing.expect(!limits.admits(std.math.maxInt(u64), 1));
}

fn included_count(node: *Node, hash: B256) !u32 {
    var decoder = node.chain.record(hash.bytes).?.transactions;
    var count: u32 = 0;
    while (!decoder.is_empty()) : (count += 1) _ = try decoder.bytes();
    return count;
}

test "chain: L2 blocks build and import; DA limits gate pool transactions" {
    const l2 = &chainspec.ChainSpec.presets.base_devnet;
    const builder = try Node.create_for(l2);
    defer builder.destroy();
    const follower = try Node.create_for(l2);
    defer follower.destroy();
    var buffers: [3][256]u8 = undefined;
    for (&buffers, 0..) |*buffer, nonce| try submit(builder, 1, nonce, 5, buffer);
    // A plain transfer estimates to ~100 compressed bytes; room for two, not three.
    var selected: [1]*const txpool.Tx = undefined;
    try testing.expectEqual(@as(u32, 1), builder.pool.select(0, &selected));
    const size = flz.estimated_size_bytes(selected[0].raw);
    try testing.expect(size > 0);
    builder.chain.da_limits = .{ .block_bytes_max = 2 * size + size / 2 };
    const genesis: B256 = .{ .bytes = builder.chain.genesis_hash };
    const first = try build(builder, genesis, 2, 0xfe);
    try testing.expectEqual(@as(u32, 2), try included_count(builder, first));
    try testing.expectEqual(types.Status.valid, (try import(builder, follower, first)).status);
    const v = types.forkchoice_version(l2, 2);
    _ = try builder.engine.forkchoice_updated(v, forkchoice(first), null);
    builder.chain.da_limits = .{ .tx_bytes_max = size - 1 };
    const blocked = try build(builder, first, 4, 0xfe);
    try testing.expectEqual(@as(u32, 0), try included_count(builder, blocked));
    builder.chain.da_limits = .{};
    // New attributes (fee recipient), so a new payload ID instead of the cached build.
    const second = try build(builder, first, 4, 0xfd);
    try testing.expectEqual(@as(u32, 1), try included_count(builder, second));
    try testing.expectEqual(types.Status.valid, (try import(builder, follower, second)).status);
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

test "chain: reorg to a lower side block and back restores the number index" {
    const node = try Node.create();
    defer node.destroy();
    var a: [7]B256 = undefined;
    a[0] = .{ .bytes = node.chain.genesis_hash };
    for (1..7) |number| a[number] = try build(node, a[number - 1], 12 * number, 0xaa);
    const b5 = try build(node, a[4], 12 * 5 + 1, 0xbb);
    const v = types.forkchoice_version(spec, 72);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a[6]), null);
    _ = try node.engine.forkchoice_updated(v, forkchoice(b5), null);
    try testing.expectEqualSlices(u8, &b5.bytes, &node.chain.store.canonical_hash(5).?);
    try testing.expect(node.chain.store.canonical_hash(6) == null);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a[6]), null);
    for (a, 0..) |hash, number| {
        try testing.expectEqualSlices(u8, &hash.bytes, &node.chain.store.canonical_hash(number).?);
    }
}

/// The number index maps exactly the head's ancestry.
fn expect_index(node: *Node, head: B256) !void {
    var cursor = node.chain.store.ref(head.bytes).?;
    try testing.expect(node.chain.store.canonical_hash(cursor.number + 1) == null);
    while (true) {
        const indexed = node.chain.store.canonical_hash(cursor.number).?;
        try testing.expectEqualSlices(u8, &cursor.hash, &indexed);
        if (cursor.number == 0) break;
        cursor = node.chain.store.ref(cursor.parent_hash).?;
    }
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
        try expect_index(builder, head);
        try expect_index(follower, head);
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

/// Base devnet with Denim (subsecond blocks) active at genesis.
const denim_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    for (0..@backingInt(chainspec.Upgrade.denim) + 1) |index| result.upgrades[index] = 0;
    break :blk result;
};

const DenimBlock = struct {
    calldata: [2][consensus.base_time.calldata_length]u8 = undefined,
    encoded: [2][256]u8 = undefined,
    transactions: [2][]const u8 = undefined,

    /// A stand-in L1-info deposit, then (when `with_base_time`) the BaseTime deposit
    /// carrying `millis_part`.
    fn build(
        block: *DenimBlock,
        node: *Node,
        parent: B256,
        number: u64,
        timestamp: u64,
        millis_part: u16,
        with_base_time: bool,
    ) !B256 {
        block.calldata[0] = consensus.base_time.encode_calldata(0);
        block.calldata[1] = consensus.base_time.encode_calldata(millis_part);
        var info = consensus.base_time.deposit(number, &block.calldata[0]);
        info.source_hash = .{ .bytes = @splat(@truncate(number)) };
        info.to = .{ .call = address_of(9) };
        const metadata = consensus.base_time.deposit(number, &block.calldata[1]);
        const info_envelope: consensus.Envelope = .{ .deposit = info };
        const metadata_envelope: consensus.Envelope = .{ .deposit = metadata };
        block.transactions[0] = info_envelope.encode_to(&block.encoded[0]);
        block.transactions[1] = metadata_envelope.encode_to(&block.encoded[1]);
        var attrs = fixture.attributes_l2(timestamp, 0xfe);
        attrs.transactions = block.transactions[0..if (with_base_time) 2 else 1];
        attrs.no_tx_pool = true;
        const version = types.forkchoice_version(node.spec, timestamp);
        const updated = try node.engine.forkchoice_updated(version, forkchoice(parent), &attrs);
        try testing.expectEqual(types.Status.valid, updated.payload_status.status);
        const get_version = types.get_payload_version(node.spec, timestamp);
        return (try node.engine.get_payload(get_version, updated.payload_id.?)).block_hash;
    }
};

test "chain: Denim 200 ms blocks share seconds, follow the schedule, carry BaseTime" {
    const builder = try Node.create_for(&denim_spec);
    defer builder.destroy();
    const follower = try Node.create_for(&denim_spec);
    defer follower.destroy();
    const schedule = builder.chain.denim_schedule().?;
    var head: B256 = .{ .bytes = builder.chain.genesis_hash };
    var block: DenimBlock = .{};
    for (1..7) |n| {
        const number: u64 = n;
        const parts = schedule.parts(number);
        try testing.expectEqual(number / 5, parts.seconds);
        const hash = try block.build(builder, head, number, parts.seconds, parts.millis_part, true);
        try testing.expectEqual(types.Status.valid, (try import(builder, follower, hash)).status);
        const v = types.forkchoice_version(&denim_spec, parts.seconds);
        _ = try builder.engine.forkchoice_updated(v, forkchoice(hash), null);
        _ = try follower.engine.forkchoice_updated(v, forkchoice(hash), null);
        head = hash;
    }
    try testing.expectEqual(try builder.db.root(), try follower.db.root());
    // Block 7 is at 1.4 s: a wrong second, a wrong millisecond part, or no BaseTime
    // deposit is invalid on import.
    const cases = [_]struct { timestamp: u64, millis: u16, with: bool, reason: []const u8 }{
        .{ .timestamp = 2, .millis = 400, .with = true, .reason = "timestamp off" },
        .{ .timestamp = 1, .millis = 600, .with = true, .reason = "millisecond part" },
        .{ .timestamp = 1, .millis = 400, .with = false, .reason = "invalid BaseTime" },
    };
    for (cases) |case| {
        const hash = try block.build(builder, head, 7, case.timestamp, case.millis, case.with);
        const status = try import(builder, follower, hash);
        try testing.expectEqual(types.Status.invalid, status.status);
        const message = status.validation_error orelse return error.TestUnexpectedResult;
        try testing.expect(std.mem.indexOf(u8, message, case.reason) != null);
    }
    const good = try block.build(builder, head, 7, 1, 400, true);
    try testing.expectEqual(types.Status.valid, (try import(builder, follower, good)).status);
}

test "chain: equal timestamps are rejected before Denim" {
    const l2 = &chainspec.ChainSpec.presets.base_devnet;
    const node = try Node.create_for(l2);
    defer node.destroy();
    try testing.expect(!l2.timestamp_follows(4, 4));
    try testing.expect(denim_spec.timestamp_follows(4, 4));
    try testing.expect(!denim_spec.timestamp_follows(5, 4));
    const genesis: B256 = .{ .bytes = node.chain.genesis_hash };
    const first = try build(node, genesis, 2, 0xfe);
    const version = types.forkchoice_version(l2, 2);
    _ = try node.engine.forkchoice_updated(version, forkchoice(first), null);
    var attrs = fixture.attributes_l2(2, 0xfe);
    const result = node.engine.forkchoice_updated(version, forkchoice(first), &attrs);
    try testing.expectError(error.InvalidPayloadAttributes, result);
}

fn subsecond_scenario(node: *Node, seed: u64) !void {
    var prng = Prng.init(seed);
    var bytes: [128]u8 = undefined;
    const length = prng.below(bytes.len);
    prng.fill(bytes[0..length]);
    if (length > 0 and prng.chance(1, 2)) bytes[0] = 0x7e;
    const number = 1 + prng.below(64);
    const parts = node.chain.denim_schedule().?.parts(number);
    var header = fixture.genesis_header(@splat(0));
    header.number = number;
    header.timestamp = if (prng.chance(1, 2)) parts.seconds else prng.int(u64);
    const transactions = [_][]const u8{ &.{}, bytes[0..length] };
    const count = prng.below(3);
    const reason = node.chain.check_subsecond(&header, transactions[0..count]);
    // Random bytes never form the exact BaseTime deposit for this block.
    try testing.expect(reason != null);
}

test "chain: seeded fuzz of the subsecond import checks" {
    const node = try Node.create_for(&denim_spec);
    defer node.destroy();
    for (0..512) |seed| try subsecond_scenario(node, seed);
}

fn fuzz_subsecond(node: *Node, smith: *testing.Smith) anyerror!void {
    try subsecond_scenario(node, smith.value(u64));
}

test "chain: fuzz subsecond import checks" {
    const node = try Node.create_for(&denim_spec);
    defer node.destroy();
    try testing.fuzz(node, fuzz_subsecond, .{});
}

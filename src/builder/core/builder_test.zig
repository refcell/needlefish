//! Single-shot block builder tests on an in-memory L2 dev node with an injected clock:
//! attribute transactions first, then pool transactions until the gas budget, the DA budget,
//! the transaction cutoff, or the end of the pool snapshot; one seal; the chain's state back
//! at the parent. The acceptance invariant: the sealed block hash-equals a `Chain` build of
//! the same transaction list. Seeded and `std.testing.fuzz` random pools, budgets, clocks.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const best_txs = @import("best_txs.zig");
const builder_module = @import("builder.zig");

const BlockBuilder = builder_module.BlockBuilder;
const Clock = builder_module.Clock;
const Stop = builder_module.Stop;
const Node = fixture.Node;
const B256 = primitives.B256;
const l2 = &chainspec.ChainSpec.presets.base_devnet;

/// Reads `now`, then advances it by `step_ns` (time passing while a transaction executes).
pub const StepClock = struct {
    now: u64 = 0,
    step_ns: u64 = 0,

    pub fn now_ns(clock: *StepClock) u64 {
        const value = clock.now;
        clock.now += clock.step_ns;
        assert(clock.now >= value);
        return value;
    }
};

/// A node, a rejection cache and a builder, all on the heap (the builder is pinned).
const Harness = struct {
    node: *Node,
    cache: best_txs.RejectionCache,
    builder: BlockBuilder,
    clock: StepClock = .{},

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try Node.create_for(l2);
        errdefer harness.node.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        harness.builder = try BlockBuilder.init(testing.allocator, &harness.cache, .{
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        harness.clock = .{};
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.builder.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.node.destroy();
        testing.allocator.destroy(harness);
    }

    fn genesis(harness: *const Harness) B256 {
        return .{ .bytes = harness.node.chain.genesis_hash };
    }

    fn submit_pool(harness: *Harness, count: usize, buffers: [][256]u8) !void {
        assert(count <= buffers.len);
        for (buffers[0..count], 0..) |*buffer, n| {
            try fixture.submit(harness.node, @intCast(n % 3 + 1), n / 3, 5, buffer);
        }
    }

    /// Starts and builds one job with the harness clock and `cutoff_ns`.
    fn run(harness: *Harness, attributes: *const payload.PayloadAttributes, cutoff_ns: u64) !Stop {
        try harness.builder.start(&harness.node.chain, .{
            .payload_id = @splat(0x42),
            .parent_hash = harness.genesis().bytes,
            .attributes = attributes,
        });
        return harness.builder.build(Clock.of(StepClock, &harness.clock), cutoff_ns);
    }
};

pub fn deposit(buffer: []u8, source: u8) []const u8 {
    const envelope: consensus.Envelope = .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(source) },
        .from = fixture.address_of(7),
        .to = .{ .call = fixture.address_of(8) },
        .mint = 1_000,
        .value = 10,
        .gas_limit = 50_000,
        .is_system_transaction = false,
        .input = &.{},
    } };
    return envelope.encode_to(buffer);
}

/// A `Chain` build of exactly `transactions` on `parent` (attributes forced, no pool).
fn chain_build(
    node: *Node,
    parent: B256,
    attributes: *const payload.PayloadAttributes,
    transactions: []const []const u8,
    id_byte: u8,
) !B256 {
    var forced = attributes.*;
    forced.transactions = transactions;
    forced.no_tx_pool = true;
    const id: payload.PayloadId = @splat(id_byte);
    try node.chain.start_build(id, node.chain.block(parent).?, &forced);
    return node.chain.built(id).?.block_hash;
}

/// The sealed block equals a `Chain` build of its transactions on a fresh follower node,
/// and the builder's chain is back at the parent state.
fn expect_chain_equal(
    harness: *Harness,
    attributes: *const payload.PayloadAttributes,
    root_before: [32]u8,
) !void {
    const follower = try Node.create_for(l2);
    defer follower.destroy();
    const builder = &harness.builder;
    const sealed = builder.sealed_header();
    const transactions = builder.block_transactions();
    const hash = try chain_build(follower, harness.genesis(), attributes, transactions, 0x99);
    try testing.expectEqualSlices(u8, &hash.bytes, &sealed.hash().bytes);
    const header = follower.chain.header(hash.bytes).?;
    try testing.expectEqualSlices(u8, &header.state_root.bytes, &sealed.state_root.bytes);
    try testing.expectEqualSlices(u8, &root_before, &(try harness.node.db.root()));
}

test "builder: attribute transactions first, then the pool; equals a Chain build" {
    const harness = try Harness.create();
    defer harness.destroy();
    var deposit_buffers: [2][256]u8 = undefined;
    const deposits = [_][]const u8{
        deposit(&deposit_buffers[0], 1),
        deposit(&deposit_buffers[1], 2),
    };
    var pool_buffers: [4][256]u8 = undefined;
    try harness.submit_pool(4, &pool_buffers);
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.transactions = &deposits;
    const root_before = try harness.node.db.root();
    try testing.expectEqual(Stop.pool_exhausted, try harness.run(&attributes, 1));
    const transactions = harness.builder.block_transactions();
    try testing.expectEqual(@as(usize, 6), transactions.len);
    try testing.expectEqualSlices(u8, deposits[0], transactions[0]);
    try testing.expectEqualSlices(u8, deposits[1], transactions[1]);
    const sealed = harness.builder.sealed_header();
    try testing.expectEqual(@as(u64, 1), sealed.number);
    try testing.expectEqual(@as(u64, 2), sealed.timestamp);
    try testing.expect(harness.builder.block_value() > 0);
    try expect_chain_equal(harness, &attributes, root_before);
}

test "builder: the gas budget skips transactions that do not fit" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(6, &buffers);
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.gas_limit = 3 * 21_000 + 20_999;
    const root_before = try harness.node.db.root();
    try testing.expectEqual(Stop.pool_exhausted, try harness.run(&attributes, 1));
    try testing.expectEqual(@as(usize, 3), harness.builder.block_transactions().len);
    try testing.expectEqual(@as(u64, 3 * 21_000), harness.builder.sealed_header().gas_used);
    try expect_chain_equal(harness, &attributes, root_before);
}

test "builder: the miner_setGasLimit target caps pool transactions" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(6, &buffers);
    const attributes = fixture.attributes_l2(2, 0xfe);
    // base/base `GasLimitConfig`: the target applies when below the block gas limit.
    harness.node.chain.gas_limit_target = 2 * 21_000 + 20_999;
    const root_before = try harness.node.db.root();
    try testing.expectEqual(Stop.pool_exhausted, try harness.run(&attributes, 1));
    try testing.expectEqual(@as(usize, 2), harness.builder.block_transactions().len);
    try testing.expectEqual(@as(u64, 2 * 21_000), harness.builder.sealed_header().gas_used);
    try expect_chain_equal(harness, &attributes, root_before);
    // A target above the block gas limit is capped by it.
    harness.node.chain.gas_limit_target = attributes.gas_limit.? + 1;
    try testing.expectEqual(Stop.pool_exhausted, try harness.run(&attributes, 1));
    try testing.expectEqual(@as(usize, 6), harness.builder.block_transactions().len);
}

test "builder: the cutoff stops pool transactions; forced transactions always run" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(6, &buffers);
    var deposit_buffer: [256]u8 = undefined;
    const deposits = [_][]const u8{deposit(&deposit_buffer, 3)};
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.transactions = &deposits;
    // Each clock read is 10 ms later; the cutoff at 25 ms admits reads at 0, 10 and 20 ms.
    harness.clock = .{ .now = 0, .step_ns = 10 };
    const root_before = try harness.node.db.root();
    try testing.expectEqual(Stop.cutoff, try harness.run(&attributes, 25));
    try testing.expectEqual(@as(usize, 1 + 3), harness.builder.block_transactions().len);
    try expect_chain_equal(harness, &attributes, root_before);
    // A cutoff already reached (an early getPayload) seals with the forced transactions.
    harness.clock = .{ .now = 100 };
    try testing.expectEqual(Stop.cutoff, try harness.run(&attributes, 100));
    try testing.expectEqual(@as(usize, 1), harness.builder.block_transactions().len);
    try expect_chain_equal(harness, &attributes, root_before);
}

test "builder: no-tx-pool jobs and DA limits" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(3, &buffers);
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.no_tx_pool = true;
    try testing.expectEqual(Stop.no_tx_pool, try harness.run(&attributes, 1));
    try testing.expectEqual(@as(usize, 0), harness.builder.block_transactions().len);
    attributes.no_tx_pool = false;
    harness.node.chain.da_limits = .{ .block_bytes_max = 1 };
    try testing.expectEqual(Stop.pool_exhausted, try harness.run(&attributes, 1));
    try testing.expectEqual(@as(usize, 0), harness.builder.block_transactions().len);
}

test "builder: a bad parent or attribute transaction fails the job" {
    const harness = try Harness.create();
    defer harness.destroy();
    var attributes = fixture.attributes_l2(2, 0xfe);
    const unknown: [32]u8 = @splat(0xab);
    const job: builder_module.Job = .{
        .payload_id = @splat(1),
        .parent_hash = unknown,
        .attributes = &attributes,
    };
    const started = harness.builder.start(&harness.node.chain, job);
    try testing.expectError(error.StateUnavailable, started);
    try testing.expectEqual(builder_module.State.idle, harness.builder.state);
    const garbage = [_][]const u8{&.{ 0x7e, 0x01 }};
    attributes.transactions = &garbage;
    const root_before = try harness.node.db.root();
    if (harness.run(&attributes, 1)) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectEqual(builder_module.State.idle, harness.builder.state);
    try testing.expectEqualSlices(u8, &root_before, &(try harness.node.db.root()));
}

/// One random job: random pool (with nonce gaps and duplicates), deposits, gas limit, DA
/// limit, clock step and cutoff; the sealed block must equal a Chain build of its list.
/// Returns how many pool transactions the block included.
fn random_job(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [24][256]u8 = undefined;
    const pool_count = prng.below(buffers.len);
    for (buffers[0..pool_count]) |*buffer| {
        const from: u8 = @intCast(prng.range(1, fixture.senders));
        fixture.submit(harness.node, from, prng.below(6), prng.below(1_000), buffer) catch {};
    }
    var deposit_buffers: [2][256]u8 = undefined;
    var deposits: [2][]const u8 = undefined;
    const deposit_count = prng.below(deposits.len + 1);
    for (deposits[0..deposit_count], 0..) |*raw, n| {
        raw.* = deposit(&deposit_buffers[n], @intCast(n + 1));
    }
    var attributes = fixture.attributes_l2(2, @intCast(prng.below(256)));
    attributes.transactions = deposits[0..deposit_count];
    attributes.gas_limit = if (prng.chance(1, 4)) 30_000_000 else prng.range(100_000, 600_000);
    attributes.no_tx_pool = prng.chance(1, 8);
    if (prng.chance(1, 3)) harness.node.chain.da_limits = .{ .block_bytes_max = prng.below(2_000) };
    const gas_target = if (prng.chance(1, 4)) prng.range(21_000, 200_000) else 0;
    harness.node.chain.gas_limit_target = gas_target;
    harness.clock = .{ .now = prng.below(100), .step_ns = prng.below(10) };
    const cutoff_ns = prng.below(200);
    const root_before = try harness.node.db.root();
    const stop = try harness.run(&attributes, cutoff_ns);
    const builder = &harness.builder;
    const included = builder.block_transactions().len - deposit_count;
    try testing.expect(builder.sealed_header().gas_used <= attributes.gas_limit.?);
    if (stop == .no_tx_pool) try testing.expectEqual(@as(usize, 0), included);
    if (gas_target != 0 and deposit_count == 0) {
        try testing.expect(builder.sealed_header().gas_used <= gas_target);
    }
    if (stop == .cutoff) try testing.expect(harness.clock.now >= cutoff_ns);
    try expect_chain_equal(harness, &attributes, root_before);
    return included;
}

test "builder: seeded fuzz sealed block equals Chain build" {
    var prng = Prng.init(0xf1a5);
    var included: u64 = 0;
    for (0..24) |_| included += try random_job(&prng);
    // The seeds must exercise pool inclusion, not only empty blocks.
    try testing.expect(included > 24);
}

fn fuzz_builder(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_job(&prng);
}

test "builder: fuzz" {
    try testing.fuzz({}, fuzz_builder, .{});
}

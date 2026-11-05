//! Flashblock generator tests on an in-memory L2 dev node: flashblock 0 contents, deltas
//! that partition the block's transactions, per-flashblock gas budgets, and the backlog's
//! acceptance invariant: every delta's block hash equals a non-flashblocks `Chain` build
//! of the same transaction prefix (so the final sealed block is byte-identical). Seeded
//! and `std.testing.fuzz` random pools and budgets.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const best_txs = @import("best_txs.zig");
const generator_module = @import("generator.zig");

const Generator = generator_module.Generator;
const Flashblock = generator_module.Flashblock;
const Node = fixture.Node;
const B256 = primitives.B256;
const l2 = &chainspec.ChainSpec.presets.base_devnet;

const flashblocks_max = 8;

/// A node, a rejection cache and a generator, all on the heap (the generator is pinned).
const Harness = struct {
    node: *Node,
    cache: best_txs.RejectionCache,
    generator: Generator,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try Node.create_for(l2);
        errdefer harness.node.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        harness.generator = try Generator.init(testing.allocator, &harness.cache, .{
            .flashblocks_max = flashblocks_max,
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.generator.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.node.destroy();
        testing.allocator.destroy(harness);
    }

    fn genesis(harness: *const Harness) B256 {
        return .{ .bytes = harness.node.chain.genesis_hash };
    }
};

fn deposit(buffer: []u8, source: u8) []const u8 {
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

/// Runs a whole job: flashblock 0 then every regular flashblock, into `out`.
fn run_job(
    harness: *Harness,
    attributes: *const payload.PayloadAttributes,
    flashblock_count: u32,
    out: *[flashblocks_max + 1]Flashblock,
) !u32 {
    assert(flashblock_count <= flashblocks_max);
    out[0] = try harness.generator.start(&harness.node.chain, .{
        .payload_id = @splat(0x42),
        .parent_hash = harness.genesis().bytes,
        .attributes = attributes,
        .flashblock_count = flashblock_count,
    });
    var len: u32 = 1;
    while (try harness.generator.next(@intCast(len))) |flashblock| : (len += 1) {
        assert(len <= flashblock_count);
        out[len] = flashblock;
    }
    try testing.expect(len == flashblock_count + 1 or (attributes.no_tx_pool orelse false));
    return len;
}

/// A non-flashblocks build of exactly `transactions` on `parent`.
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

/// Invariants of one job: deltas partition the block's transactions in order, gas used is
/// monotone, pool flashblocks respect their cumulative gas budget, the last delta is the
/// sealed block, every flashblock encodes, and the state is back at the parent.
fn check_job(harness: *Harness, flashblock_list: []const Flashblock, root_before: [32]u8) !void {
    const generator = &harness.generator;
    const all = generator.block_transactions();
    var position: usize = 0;
    var gas_previous: u64 = 0;
    var json_buffer: [1 << 15]u8 = undefined;
    for (flashblock_list, 0..) |flashblock, index| {
        try testing.expectEqual(@as(u64, index), flashblock.index);
        try testing.expectEqual(index == 0, flashblock.base != null);
        try testing.expectEqual(@as(u64, 1), flashblock.metadata.block_number);
        for (flashblock.diff.transactions) |raw| {
            try testing.expectEqualSlices(u8, all[position], raw);
            position += 1;
        }
        try testing.expect(flashblock.diff.gas_used >= gas_previous);
        gas_previous = flashblock.diff.gas_used;
        if (index > 0 and flashblock.diff.transactions.len > 0) {
            const budget = generator.gas_per_batch * index;
            try testing.expect(flashblock.diff.gas_used <= budget);
        }
        _ = try flashblocks.encode_json(flashblock, &json_buffer);
    }
    try testing.expectEqual(all.len, position);
    const last = flashblock_list[flashblock_list.len - 1];
    const sealed = generator.sealed_header();
    try testing.expectEqualSlices(u8, &sealed.hash().bytes, &last.diff.block_hash.bytes);
    try testing.expectEqual(sealed.gas_used, last.diff.gas_used);
    try testing.expectEqualSlices(u8, &root_before, &(try harness.node.db.root()));
}

test "generator: flashblock 0 carries the payload base and the attribute transactions" {
    const harness = try Harness.create();
    defer harness.destroy();
    var deposit_buffers: [2][256]u8 = undefined;
    const deposits = [_][]const u8{
        deposit(&deposit_buffers[0], 1),
        deposit(&deposit_buffers[1], 2),
    };
    var pool_buffer: [256]u8 = undefined;
    try fixture.submit(harness.node, 1, 0, 5, &pool_buffer);
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.transactions = &deposits;
    const root_before = try harness.node.db.root();
    const zero = try harness.generator.start(&harness.node.chain, .{
        .payload_id = @splat(7),
        .parent_hash = harness.genesis().bytes,
        .attributes = &attributes,
        .flashblock_count = 2,
    });
    try testing.expectEqual(@as(u64, 0), zero.index);
    const base = zero.base.?;
    try testing.expectEqualSlices(u8, &harness.genesis().bytes, &base.parent_hash.bytes);
    try testing.expectEqual(@as(u64, 1), base.block_number);
    try testing.expectEqual(@as(u64, 2), base.timestamp);
    try testing.expectEqual(attributes.gas_limit.?, base.gas_limit);
    const recipient = attributes.suggested_fee_recipient.bytes;
    try testing.expectEqualSlices(u8, &recipient, &base.fee_recipient.bytes);
    try testing.expectEqual(@as(usize, 2), zero.diff.transactions.len);
    try testing.expectEqualSlices(u8, deposits[0], zero.diff.transactions[0]);
    try testing.expectEqualSlices(u8, deposits[1], zero.diff.transactions[1]);
    try testing.expect(zero.diff.gas_used > 0);
    try testing.expectEqual(@as(usize, 0), zero.diff.withdrawals.len);
    try testing.expectEqualSlices(u8, &root_before, &(try harness.node.db.root()));
    // The pool transaction arrives in flashblock 1, not 0.
    const one = (try harness.generator.next(1)).?;
    try testing.expectEqual(@as(usize, 1), one.diff.transactions.len);
    try testing.expectEqual(flashblock_id(1, 0), one.metadata.prev_flashblock_id);
    const two = (try harness.generator.next(2)).?;
    try testing.expectEqual(@as(usize, 0), two.diff.transactions.len);
    try testing.expect((try harness.generator.next(3)) == null);
}

fn flashblock_id(block_number: u64, index: u64) flashblocks.FlashblockId {
    return .{ .block_number = block_number, .index = index };
}

test "generator: gas budget splits across flashblocks; every delta matches a Chain build" {
    const harness = try Harness.create();
    defer harness.destroy();
    const follower = try Node.create_for(l2);
    defer follower.destroy();
    var buffers: [6][256]u8 = undefined;
    for (&buffers, 0..) |*buffer, n| {
        try fixture.submit(harness.node, @intCast(n % 3 + 1), n / 3, 5, buffer);
    }
    var attributes = fixture.attributes_l2(2, 0xfe);
    // Three flashblocks of 42_000 gas: two transfers each.
    attributes.gas_limit = 126_000;
    var list: [flashblocks_max + 1]Flashblock = undefined;
    const root_before = try harness.node.db.root();
    const len = try run_job(harness, &attributes, 3, &list);
    try testing.expectEqual(@as(u32, 4), len);
    try check_job(harness, list[0..len], root_before);
    const expected = [_]usize{ 0, 2, 2, 2 };
    var prefix: usize = 0;
    for (list[0..len], expected, 0..) |flashblock, count, index| {
        try testing.expectEqual(count, flashblock.diff.transactions.len);
        try testing.expectEqual(@as(u64, prefix + count) * 21_000, flashblock.diff.gas_used);
        prefix += count;
        // The block as if it ended here, built without flashblocks on another node.
        const all = harness.generator.block_transactions();
        const hash = try chain_build(
            follower,
            harness.genesis(),
            &attributes,
            all[0..prefix],
            @intCast(index + 1),
        );
        try testing.expectEqualSlices(u8, &hash.bytes, &flashblock.diff.block_hash.bytes);
        const header = follower.chain.header(hash.bytes).?;
        const state_root = flashblock.diff.state_root.bytes;
        try testing.expectEqualSlices(u8, &header.state_root.bytes, &state_root);
    }
}

/// One random job: random pool (with nonce gaps and duplicates), deposits, flashblock
/// count, gas limit and DA limit; the final block must equal a Chain build of its list.
/// Returns how many pool transactions the block included.
fn random_job(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [24][256]u8 = undefined;
    const pool_count = prng.below(buffers.len);
    for (buffers[0..pool_count]) |*buffer| {
        const from: u8 = @intCast(prng.range(1, fixture.senders));
        const nonce = prng.below(6);
        const value = prng.below(1_000);
        fixture.submit(harness.node, from, nonce, value, buffer) catch {};
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
    const flashblock_count: u32 = @intCast(prng.below(flashblocks_max + 1));
    var list: [flashblocks_max + 1]Flashblock = undefined;
    const root_before = try harness.node.db.root();
    const len = try run_job(harness, &attributes, flashblock_count, &list);
    try check_job(harness, list[0..len], root_before);
    const hash = try chain_build(
        harness.node,
        harness.genesis(),
        &attributes,
        harness.generator.block_transactions(),
        0x99,
    );
    try testing.expectEqualSlices(u8, &hash.bytes, &list[len - 1].diff.block_hash.bytes);
    return harness.generator.block_transactions().len - deposit_count;
}

test "generator: seeded fuzz final block equals Chain build" {
    var prng = Prng.init(0xf1a5);
    var included: u64 = 0;
    for (0..24) |_| included += try random_job(&prng);
    // The seeds must exercise pool inclusion, not only empty blocks.
    try testing.expect(included > 24);
}

fn fuzz_generator(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_job(&prng);
}

test "generator: fuzz" {
    try testing.fuzz({}, fuzz_generator, .{});
}

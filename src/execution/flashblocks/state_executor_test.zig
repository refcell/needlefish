//! Executor-backed pending state tests. A producer L2 dev node runs the builder's
//! flashblock `Generator`; a consumer node's `Processor(ExecutorState)` re-executes the
//! flashblocks on its canonical (genesis) state. Every flashblock's receipts root and gas
//! used must equal the delta's, and after the producer imports the sealed blocks its
//! canonical state must equal the consumer's pending state on every account and slot the
//! pending blocks changed. The canonical state of the consumer is never written. Seeded
//! and `std.testing.fuzz` random jobs, plus deterministic contract, `eth_call`, rebuild and
//! misuse cases.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const fixture = @import("../node/test_fixture.zig");
const generator_module = @import("../../builder/core/generator.zig");
const best_txs = @import("../../builder/core/best_txs.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const processor_module = @import("processor.zig");
const state_executor = @import("state_executor.zig");

const ExecutorState = state_executor.ExecutorState;
const Processor = processor_module.Processor(ExecutorState);
const Generator = generator_module.Generator;
const Flashblock = generator_module.Flashblock;
const Node = fixture.Node;
const B256 = primitives.B256;
const l2 = &chainspec.ChainSpec.presets.base_devnet;

const flashblocks_max = 6;

const options: state_executor.Options = .{
    .transactions_max = 256,
    .log_bytes_max = 1 << 14,
    .blocks_max = 4,
    .codes_max = 16,
    .code_bytes_max = 1 << 14,
    .accounts_max = 256,
    .slots_max = 1024,
    .executor = .{
        .scratch_bytes = 1 << 20,
        .transactions_max = 64,
        .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
        .limits = .{
            .accounts_max = 256,
            .slots_max = 1024,
            .transient_slots_max = 64,
            .journal_entries_max = 4096,
            .logs_max = 64,
            .log_data_bytes_max = 4096,
            .code_bytes_max = 1 << 16,
        },
    },
};

/// Producer node + generator, consumer node + executor state + processor (heap-pinned).
const Harness = struct {
    producer: *Node,
    consumer: *Node,
    cache: best_txs.RejectionCache,
    generator: Generator,
    builder: *ExecutorState,
    processor: Processor,
    consumer_root: [32]u8,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.producer = try Node.create_for(l2);
        errdefer harness.producer.destroy();
        harness.consumer = try Node.create_for(l2);
        errdefer harness.consumer.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        harness.generator = try Generator.init(testing.allocator, &harness.cache, .{
            .flashblocks_max = flashblocks_max,
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        errdefer harness.generator.deinit(testing.allocator);
        const consumer_db = &harness.consumer.db;
        harness.builder = try ExecutorState.create(testing.allocator, l2, consumer_db, options);
        errdefer harness.builder.destroy(testing.allocator);
        harness.processor = try Processor.init(testing.allocator, .{
            .limits = .{
                .blocks_max = 4,
                .flashblocks_per_block_max = flashblocks_max + 1,
                .transactions_per_block_max = 64,
                .transaction_bytes_per_block_max = 1 << 14,
            },
            .cache = .{ .entries_max = 8, .bytes_max = 1 << 15 },
            .decode_arena_bytes = 1 << 16,
        }, harness.builder);
        harness.consumer_root = try consumer_db.root();
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.processor.deinit(testing.allocator);
        harness.builder.destroy(testing.allocator);
        harness.generator.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.consumer.destroy();
        harness.producer.destroy();
        testing.allocator.destroy(harness);
    }

    fn genesis(harness: *const Harness) B256 {
        return .{ .bytes = harness.producer.chain.genesis_hash };
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

/// Adds a signed EIP-1559 transaction to the producer's pool.
fn submit(
    node: *Node,
    from: u8,
    nonce: u64,
    to: consensus.TxKind,
    input: []const u8,
    gas_limit: u64,
    buffer: []u8,
) !void {
    const tx: consensus.Eip1559 = .{
        .chain_id = node.spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = gas_limit,
        .to = to,
        .value = 0,
        .input = input,
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, fixture.key(from));
    const sender = fixture.address_of(from);
    const account = node.db.get_account(sender.bytes).?;
    _ = try node.pool.add(.{
        .hash = envelope.hash(),
        .sender = sender,
        .nonce = nonce,
        .tx_type = 2,
        .gas_limit = gas_limit,
        .max_fee_per_gas = tx.max_fee_per_gas,
        .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
        .value = 0,
        .raw = envelope.encode_to(buffer),
    }, .{ .nonce = account.nonce, .balance = account.balance });
}

/// Builds block `parent + 1` on the producer, feeding every flashblock to the consumer
/// and checking the consumer's execution against each delta; then the producer imports
/// the sealed block (canonical). Returns the sealed hash.
fn produce_block(
    harness: *Harness,
    parent: B256,
    attributes: *const payload.PayloadAttributes,
    flashblock_count: u32,
    id_byte: u8,
) !B256 {
    var flashblock = try harness.generator.start(&harness.producer.chain, .{
        .payload_id = @splat(id_byte),
        .parent_hash = parent.bytes,
        .attributes = attributes,
        .flashblock_count = flashblock_count,
    });
    var index: u32 = 0;
    while (true) : (index += 1) {
        try testing.expect(index <= flashblock_count);
        try feed(harness, flashblock);
        flashblock = (try harness.generator.next(index + 1)) orelse break;
    }
    var forced = attributes.*;
    forced.transactions = harness.generator.block_transactions();
    forced.no_tx_pool = true;
    const id: payload.PayloadId = @splat(id_byte ^ 0x80);
    const chain = &harness.producer.chain;
    try chain.start_build(id, chain.block(parent).?, &forced);
    const hash = chain.built(id).?.block_hash;
    try testing.expectEqualSlices(u8, &harness.generator.sealed_header().hash().bytes, &hash.bytes);
    _ = try chain.set_forkchoice(fixture.forkchoice(hash));
    return hash;
}

fn feed(harness: *Harness, flashblock: Flashblock) !void {
    const errors_before = harness.processor.stats.processing_errors;
    harness.processor.on_flashblock(flashblock);
    try testing.expectEqual(errors_before, harness.processor.stats.processing_errors);
    const record = harness.builder.latest_block().?;
    try testing.expectEqual(flashblock.metadata.block_number, record.number);
    try testing.expectEqual(flashblock.diff.gas_used, record.gas_used);
    const pending_block = harness.processor.pending.latest().?;
    try testing.expectEqual(pending_block.transaction_count, record.transaction_count);
    const root = try harness.builder.receipts_root(record);
    try testing.expectEqualSlices(u8, &flashblock.diff.receipts_root.bytes, &root);
    for (pending_block.hashes(), 0..) |hash, index| {
        const position = harness.builder.find_transaction(hash).?;
        const executed = harness.builder.transaction_at(position);
        try testing.expectEqual(@as(u32, @intCast(index)), executed.index);
    }
}

/// The consumer's pending state equals the producer's canonical head state on every
/// account and slot the pending blocks changed, and on the test accounts. The consumer's
/// canonical state is untouched.
fn expect_pending_matches_producer(harness: *Harness) !void {
    const builder = harness.builder;
    const producer = &harness.producer.db;
    var accounts = builder.overlay.accounts.keyIterator();
    while (accounts.next()) |address| try expect_account(harness, address.*);
    for (1..10) |n| try expect_account(harness, fixture.address_of(@intCast(n)).bytes);
    var slots = builder.overlay.slots.keyIterator();
    while (slots.next()) |key| {
        const expected = producer.get_storage(key.address, key.slot);
        try testing.expectEqual(expected, builder.storage(key.address, key.slot));
    }
    try testing.expectEqualSlices(u8, &harness.consumer_root, &(try harness.consumer.db.root()));
}

fn expect_account(harness: *Harness, address: [20]u8) !void {
    const expected = harness.producer.db.get_account(address);
    const actual = harness.builder.account(address);
    try testing.expectEqual(expected == null, actual == null);
    const want = expected orelse return;
    const got = actual.?;
    try testing.expectEqual(want.nonce, got.nonce);
    try testing.expectEqual(want.balance, got.balance);
    try testing.expectEqualSlices(u8, &want.code_hash, &got.code_hash);
}

test "state executor: pending transfers match the delta roots and the imported block" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    for (&buffers, 0..) |*buffer, n| {
        try fixture.submit(harness.producer, @intCast(n % 3 + 1), n / 3, 5, buffer);
    }
    var deposit_buffer: [256]u8 = undefined;
    const deposits = [_][]const u8{deposit(&deposit_buffer, 1)};
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.transactions = &deposits;
    attributes.gas_limit = 200_000;
    _ = try produce_block(harness, harness.genesis(), &attributes, 3, 1);
    try testing.expectEqual(@as(u32, 7), harness.builder.latest_block().?.transaction_count);
    try expect_pending_matches_producer(harness);
    // The recipient got 6 x 5 in the pending state only.
    const recipient = fixture.address_of(9).bytes;
    try testing.expectEqual(@as(u256, 30), harness.builder.account(recipient).?.balance);
    try testing.expect(harness.consumer.db.get_account(recipient) == null);
    const sender = harness.builder.account(fixture.address_of(1).bytes).?;
    try testing.expectEqual(@as(u64, 2), sender.nonce);
    // A deposit receipt carries its nonce.
    const first_hash = harness.processor.pending.latest().?.hashes()[0];
    const position = harness.builder.find_transaction(first_hash).?;
    try testing.expect(harness.builder.receipt_at(position).deposit_nonce != null);
}

test "state executor: eth_call sees pending balances; a rebuild reproduces the state" {
    const harness = try Harness.create();
    defer harness.destroy();
    try testing.expect((try harness.builder.call(.{})) == null);
    var buffers: [3][256]u8 = undefined;
    for (&buffers, 0..) |*buffer, n| try fixture.submit(harness.producer, 1, n, 5, buffer);
    const attributes = fixture.attributes_l2(2, 0xfe);
    _ = try produce_block(harness, harness.genesis(), &attributes, 2, 1);
    // Address 9 holds 15 wei only in the pending state.
    const call: state_executor.Call = .{
        .from = fixture.address_of(9).bytes,
        .to = fixture.address_of(8).bytes,
        .gas = 100_000,
        .value = 15,
    };
    const simulated = (try harness.builder.call(call)).?;
    try testing.expect(simulated == .executed and simulated.executed.success);
    var too_much = call;
    too_much.value = 16;
    try testing.expect((try harness.builder.call(too_much)).? == .invalid);
    // The call changed nothing; a canonical notification for an older block rebuilds.
    try expect_pending_matches_producer(harness);
    const resets = harness.builder.stats.resets;
    harness.processor.on_canonical(0, &.{});
    try testing.expect(harness.builder.stats.resets > resets);
    try testing.expectEqual(@as(u32, 3), harness.builder.latest_block().?.transaction_count);
    try expect_pending_matches_producer(harness);
}

// PUSH1 6 PUSH1 12 PUSH1 0 CODECOPY PUSH1 6 PUSH1 0 RETURN || PUSH1 42 PUSH1 0 SSTORE STOP
const init_code = [_]u8{
    0x60, 0x06, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x06, 0x60, 0x00, 0xf3,
    0x60, 0x2a, 0x60, 0x00, 0x55, 0x00,
};

test "state executor: contracts deployed and called across two pending blocks" {
    const harness = try Harness.create();
    defer harness.destroy();
    var create_buffer: [256]u8 = undefined;
    try submit(harness.producer, 2, 0, .create, &init_code, 200_000, &create_buffer);
    const attributes = fixture.attributes_l2(2, 0xfe);
    const first = try produce_block(harness, harness.genesis(), &attributes, 2, 1);
    const contract = primitives.create_address(fixture.address_of(2), 0);
    const code_hash = harness.builder.account(contract.bytes).?.code_hash;
    try testing.expectEqual(@as(usize, 6), harness.builder.code_by_hash(code_hash).?.len);
    try testing.expect(harness.consumer.db.code(code_hash) == null);
    var call_buffer: [256]u8 = undefined;
    try submit(harness.producer, 2, 1, .{ .call = contract }, &.{}, 100_000, &call_buffer);
    const second_attributes = fixture.attributes_l2(4, 0xfd);
    _ = try produce_block(harness, first, &second_attributes, 2, 2);
    try testing.expectEqual(@as(u64, 2), harness.builder.latest_block().?.number);
    try testing.expectEqual(@as(u256, 42), harness.builder.storage(contract.bytes, 0));
    try testing.expectEqual(@as(u256, 0), harness.consumer.db.get_storage(contract.bytes, 0));
    try expect_pending_matches_producer(harness);
}

test "state executor: out-of-order execution fails and a reset restores canonical reads" {
    const harness = try Harness.create();
    defer harness.destroy();
    const builder = harness.builder;
    var buffer: [256]u8 = undefined;
    try fixture.submit(harness.producer, 1, 0, 5, &buffer);
    const attributes = fixture.attributes_l2(2, 0xfe);
    _ = try produce_block(harness, harness.genesis(), &attributes, 1, 1);
    const block = harness.processor.pending.latest().?;
    // Resuming at a position other than the executed count, or skipping a block number.
    try testing.expectError(error.ExecutionFailed, builder.execute(block, 0, 0));
    try testing.expectEqual(@as(u64, 1), builder.stats.failures);
    builder.reset();
    try testing.expect(builder.latest_block() == null);
    try testing.expect(builder.account(fixture.address_of(9).bytes) == null);
    try testing.expectError(error.ExecutionFailed, builder.execute(block, 1, 1));
    try builder.execute(block, 0, block.transaction_count);
    try testing.expectEqual(@as(u256, 5), builder.account(fixture.address_of(9).bytes).?.balance);
}

/// One random run: one or two blocks of random pool transactions, deposits, flashblock
/// counts and gas limits; every delta and the final state must match the producer.
fn random_run(seed: u64) !void {
    var prng = Prng.init(seed);
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [16][256]u8 = undefined;
    var used: usize = 0;
    var parent = harness.genesis();
    const blocks = prng.range(1, 2);
    for (0..blocks) |block_index| {
        const pool_count = prng.below(8);
        for (0..pool_count) |_| {
            if (used == buffers.len) break;
            const from: u8 = @intCast(prng.range(1, fixture.senders));
            const value = prng.below(1_000);
            const nonce = prng.below(6);
            fixture.submit(harness.producer, from, nonce, value, &buffers[used]) catch continue;
            used += 1;
        }
        var deposit_buffers: [2][256]u8 = undefined;
        var deposits: [2][]const u8 = undefined;
        const deposit_count = prng.below(deposits.len + 1);
        for (deposits[0..deposit_count], 0..) |*raw, n| {
            raw.* = deposit(&deposit_buffers[n], @intCast(block_index * 2 + n + 1));
        }
        const timestamp = 2 * (block_index + 1);
        var attributes = fixture.attributes_l2(timestamp, @intCast(prng.below(256)));
        attributes.transactions = deposits[0..deposit_count];
        attributes.gas_limit = if (prng.chance(1, 4)) 30_000_000 else prng.range(100_000, 400_000);
        const count: u32 = @intCast(prng.range(1, flashblocks_max));
        parent = try produce_block(harness, parent, &attributes, count, @intCast(block_index + 1));
        // The canonical genesis again: the processor re-executes every pending block.
        if (prng.chance(1, 3)) harness.processor.on_canonical(0, &.{});
    }
    try expect_pending_matches_producer(harness);
}

test "state executor: seeded random runs match the producer" {
    for (0..6) |seed| try random_run(seed *% 0x9e37_79b9_7f4a_7c15 +% 1);
}

test "state executor: fuzz random runs" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try random_run(smith.value(u64));
        }
    }.run, .{});
}

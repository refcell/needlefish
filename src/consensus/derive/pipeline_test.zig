//! End-to-end derivation pipeline tests: an L1 chain whose batcher transactions carry real
//! frames of zlib channels (singular and span batches, calldata and blobs) is derived from
//! a reset, and the payload attributes are executed by a minimal driver that feeds the
//! derived L2 blocks back into the test chain. A seeded fuzz injects unavailable data and
//! random resets and checks the result is deterministic and matches the clean run.
//! Mirrors base/base `crates/consensus/derive/src/pipeline/core.rs` tests and the driver
//! loop of `crates/consensus/node` (step, reset on reset errors, activate on Holocene).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus_types = @import("../../common/consensus/root.zig");
const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const blob = @import("blob.zig");
const pipeline_module = @import("pipeline.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const TestChain = @import("test_chain.zig").TestChain;
const L1Transaction = @import("providers.zig").L1Transaction;

const Address = primitives.Address;
const Hash = protocol.block.Hash;
const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.SystemConfig;
const SingleBatch = protocol.batch.SingleBatch;
const SpanBatch = protocol.span_batch.SpanBatch;
const Frame = protocol.frame.Frame;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;
const Pipeline = pipeline_module.Pipeline;
const AttributesWithParent = pipeline_module.AttributesWithParent;
const StepResult = pipeline_module.StepResult;
const Error = errors.Error;
const flate = std.compress.flate;

const inbox = Address.init(@splat(0x11));
const batcher = Address.init(@splat(0x22));
const genesis_time: u64 = 1000;
const l1_block_time: u64 = 4;
const l2_block_time: u64 = 2;
/// Ecotone (blob data source) activates at L1 block 3 and L2 block 6.
const ecotone_time: u64 = genesis_time + 3 * l1_block_time;
const system_config: SystemConfig = .{ .batcher_address = batcher, .gas_limit = 30_000_000 };

const tx_a1 = [_]u8{ 0x02, 0xa1, 0x01 };
const tx_a2 = [_]u8{ 0x02, 0xa2, 0x02, 0x03 };
const tx_c5 = [_]u8{ 0x01, 0xc5 };
const tx_c6 = [_]u8{ 0x02, 0xc6, 0x06 };

fn l2_hash(number: u64) Hash {
    var input: [10]u8 = undefined;
    input[0..2].* = "l2".*;
    std.mem.writeInt(u64, input[2..10], number, .big);
    const hash = primitives.keccak256(&input);
    assert(!hash.eql(.zero));
    return hash;
}

fn l2_timestamp(number: u64) u64 {
    return genesis_time + number * l2_block_time;
}

/// A batch for L2 block `number` on top of the deterministic test L2 chain.
fn single(number: u64, epoch: BlockInfo, transactions: []const []const u8) SingleBatch {
    assert(number > 0);
    assert(epoch.timestamp <= l2_timestamp(number));
    return .{
        .parent_hash = l2_hash(number - 1),
        .epoch_num = epoch.number,
        .epoch_hash = epoch.hash,
        .timestamp = l2_timestamp(number),
        .transactions = transactions,
    };
}

fn compress_zlib(arena: Allocator, input: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(arena, 64);
    const window = try arena.alloc(u8, flate.max_window_len);
    var compress = try flate.Compress.init(&output.writer, window, .zlib, .default);
    try compress.writer.writeAll(input);
    try compress.finish();
    return output.toOwnedSlice();
}

/// A channel's decompressed batch stream: RLP-string-wrapped typed batches.
const ChannelBuilder = struct {
    arena: Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn add_typed(builder: *ChannelBuilder, batch_type: u8, encoded: []const u8) !void {
        const typed = try builder.arena.alloc(u8, encoded.len + 1);
        typed[0] = batch_type;
        @memcpy(typed[1..], encoded);
        const length = rlp.bytes_length(typed);
        const out = try builder.bytes.addManyAsSlice(builder.arena, length);
        var encoder = rlp.Encoder.init(out);
        encoder.bytes(typed);
        assert(encoder.written().len == length);
    }

    fn add_single(builder: *ChannelBuilder, batch: SingleBatch) !void {
        const encoded = try builder.arena.alloc(u8, batch.encoded_length());
        _ = batch.encode(encoded);
        try builder.add_typed(@backingInt(protocol.batch.BatchType.single), encoded);
    }

    fn add_span(builder: *ChannelBuilder, singles: []const SingleBatch, first_seq: u64) !void {
        const span = try SpanBatch.from_singular_batches(
            builder.arena,
            singles,
            first_seq,
            genesis_time,
            0,
        );
        const encoded = try span.encode_alloc(builder.arena);
        try builder.add_typed(@backingInt(protocol.batch.BatchType.span), encoded);
    }

    /// Compresses the channel and splits it into `parts` batcher payloads, one frame each
    /// (`derivation version 0 ++ frame`).
    fn payloads(builder: *ChannelBuilder, id: u8, parts: u16) ![]const []const u8 {
        assert(parts > 0);
        const compressed = try compress_zlib(builder.arena, builder.bytes.items);
        assert(compressed.len >= parts);
        const list = try builder.arena.alloc([]const u8, parts);
        const chunk = compressed.len / parts;
        for (list, 0..) |*payload, index| {
            const start = index * chunk;
            const end = if (index + 1 == parts) compressed.len else start + chunk;
            const frame: Frame = .{
                .id = @splat(id),
                .number = @intCast(index),
                .data = compressed[start..end],
                .is_last = index + 1 == parts,
            };
            const out = try builder.arena.alloc(u8, frame.encoded_length() + 1);
            out[0] = 0;
            _ = frame.encode(out[1..]);
            payload.* = out;
        }
        return list;
    }
};

fn calldata_txs(arena: Allocator, payloads: []const []const u8) ![]const L1Transaction {
    const list = try arena.alloc(L1Transaction, payloads.len);
    for (list, payloads) |*tx, payload| {
        tx.* = .{
            .tx_type = L1Transaction.type_eip1559,
            .to = inbox,
            .from = batcher,
            .input = payload,
        };
    }
    assert(list.len == payloads.len);
    return list;
}

/// The L1 chain, rollup config, and L2 genesis shared by every test.
const Scenario = struct {
    arena_state: std.heap.ArenaAllocator,
    chain: TestChain,
    rollup: RollupConfig,
    schedule: L1BlobSchedule = .{},

    fn init(scenario: *Scenario, l1_blocks: u32) void {
        scenario.* = .{
            .arena_state = .init(testing.allocator),
            .chain = TestChain.init(l1_blocks, 0, l1_block_time),
            .rollup = undefined,
        };
        const chain = &scenario.chain;
        scenario.rollup = .{
            .block_time = l2_block_time,
            .max_sequencer_drift = 600,
            .seq_window_size = 4,
            .channel_timeout = 8,
            .batch_inbox_address = inbox,
            .genesis = .{
                .l1 = chain.blocks[0].id(),
                .l2 = .{ .number = 0, .hash = l2_hash(0) },
                .l2_time = genesis_time,
                .system_config = system_config,
            },
        };
        scenario.rollup.upgrades.set(.delta, genesis_time);
        chain.add_l2_block(scenario.genesis());
        chain.add_l2_safe_block(0, .{ .transactions = &.{}, .l1_origin_number = 0 });
        chain.add_system_config(l2_hash(0), system_config);
        assert(chain.blocks[0].timestamp == genesis_time);
    }

    fn deinit(scenario: *Scenario) void {
        scenario.arena_state.deinit();
        scenario.* = undefined;
    }

    fn genesis(scenario: *const Scenario) L2BlockInfo {
        return .{
            .block_info = .{ .hash = l2_hash(0), .number = 0, .timestamp = genesis_time },
            .l1_origin = scenario.chain.blocks[0].id(),
        };
    }

    /// Batches for L2 blocks 1-6: singular batches in L1 block 1, a span batch split over
    /// two calldata frames in L1 block 2, and a blob with singular batches in L1 block 3.
    fn add_batches(scenario: *Scenario) !void {
        const arena = scenario.arena_state.allocator();
        const chain = &scenario.chain;
        const blocks = chain.blocks;
        scenario.rollup.upgrades.set(.ecotone, ecotone_time);
        assert(blocks[3].timestamp == ecotone_time);

        var channel_a: ChannelBuilder = .{ .arena = arena };
        try channel_a.add_single(single(1, blocks[0], &.{&tx_a1}));
        try channel_a.add_single(single(2, blocks[1], &.{&tx_a2}));
        chain.transactions[1] = try calldata_txs(arena, try channel_a.payloads(0xa, 1));

        var channel_b: ChannelBuilder = .{ .arena = arena };
        const span = [_]SingleBatch{ single(3, blocks[1], &.{}), single(4, blocks[2], &.{}) };
        try channel_b.add_span(&span, 1);
        chain.transactions[2] = try calldata_txs(arena, try channel_b.payloads(0xb, 2));

        var channel_c: ChannelBuilder = .{ .arena = arena };
        try channel_c.add_single(single(5, blocks[2], &.{&tx_c5}));
        try channel_c.add_single(single(6, blocks[3], &.{&tx_c6}));
        const payload = (try channel_c.payloads(0xc, 1))[0];
        const encoded = try arena.create(blob.Blob);
        try blob.encode(payload, encoded);
        const blob_list = try arena.alloc(*const blob.Blob, 1);
        blob_list[0] = encoded;
        chain.blob_list[3] = blob_list;
        const hashes = try arena.alloc(Hash, 1);
        hashes[0] = .init(@splat(0x01));
        const txs = try arena.alloc(L1Transaction, 1);
        txs[0] = .{
            .tx_type = L1Transaction.type_eip4844,
            .to = inbox,
            .from = batcher,
            .input = &.{},
            .blob_hashes = hashes,
        };
        chain.transactions[3] = txs;
    }
};

/// One executed L2 block.
const Record = struct {
    block: L2BlockInfo,
    tx_count: u32,
    /// Keccak of the timestamp and every transaction.
    digest: Hash,
    derived_from: u64,
    last_tx: []const u8,

    fn same_block(a: Record, b: Record) bool {
        return a.block.eql(b.block) and a.tx_count == b.tx_count and a.digest.eql(b.digest);
    }
};

fn digest_of(prepared: *const AttributesWithParent) Hash {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    var timestamp: [8]u8 = undefined;
    std.mem.writeInt(u64, &timestamp, prepared.attributes.timestamp, .big);
    hasher.update(&timestamp);
    for (prepared.attributes.transactions) |tx| hasher.update(tx);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return .init(out);
}

fn decode_l1_info(encoded: []const u8) !L1BlockInfo {
    const envelope = try consensus_types.tx.Envelope.decode(encoded);
    try testing.expect(envelope == .deposit);
    return L1BlockInfo.decode_calldata(envelope.deposit.input);
}

fn known_l2_block(chain: *const TestChain, number: u64) ?L2BlockInfo {
    for (chain.l2_blocks[0..chain.l2_block_count]) |info| {
        if (info.block_info.number == number) return info;
    }
    return null;
}

/// A minimal node: steps the pipeline, executes attributes, and answers reset and
/// activation errors with signals, as the base/base derivation actor does.
const Driver = struct {
    arena: Allocator,
    chain: *TestChain,
    pipeline: Pipeline,
    cursor: L2BlockInfo,
    records: std.ArrayList(Record) = .empty,
    pending_reset: ?L2BlockInfo = null,
    pending_activation: bool = false,
    done: bool = false,

    fn init(driver: *Driver, scenario: *Scenario) !void {
        const genesis = scenario.genesis();
        driver.* = .{
            .arena = scenario.arena_state.allocator(),
            .chain = &scenario.chain,
            .pipeline = Pipeline.init(
                testing.allocator,
                &scenario.rollup,
                &scenario.schedule,
                scenario.chain.blocks[0],
            ),
            .cursor = genesis,
            .pending_reset = genesis,
        };
        try driver.records.append(testing.allocator, .{
            .block = genesis,
            .tx_count = 0,
            .digest = .zero,
            .derived_from = 0,
            .last_tx = &.{},
        });
        assert(driver.pipeline.prepared_len() == 0);
    }

    fn deinit(driver: *Driver) void {
        driver.pipeline.deinit();
        driver.records.deinit(testing.allocator);
        driver.* = undefined;
    }

    /// Resets to an earlier executed block, as after an engine reorg.
    fn rewind(driver: *Driver, index: usize) void {
        assert(index < driver.records.items.len);
        driver.records.shrinkRetainingCapacity(index + 1);
        driver.cursor = driver.records.items[index].block;
        driver.pending_reset = driver.cursor;
        assert(driver.cursor.block_info.number == index);
    }

    fn execute(driver: *Driver, prepared: AttributesWithParent) !void {
        var owned = prepared;
        defer owned.deinit(testing.allocator);
        try testing.expect(owned.parent.eql(driver.cursor));
        const transactions = owned.attributes.transactions;
        const info = try decode_l1_info(transactions[0]);
        const number = driver.cursor.block_info.number + 1;
        const block: L2BlockInfo = .{
            .block_info = .{
                .hash = l2_hash(number),
                .number = number,
                .parent_hash = driver.cursor.block_info.hash,
                .timestamp = owned.attributes.timestamp,
            },
            .l1_origin = .{ .number = info.number, .hash = info.block_hash },
            .sequence_number = info.sequence_number,
        };
        if (known_l2_block(driver.chain, number)) |known| {
            try testing.expect(known.eql(block));
        } else {
            const copies = try driver.arena.alloc([]const u8, transactions.len);
            for (copies, transactions) |*copy, tx| copy.* = try driver.arena.dupe(u8, tx);
            driver.chain.add_l2_block(block);
            driver.chain.add_l2_safe_block(number, .{
                .transactions = copies,
                .l1_origin_number = info.number,
            });
        }
        driver.chain.add_system_config(block.block_info.hash, system_config);
        try driver.records.append(testing.allocator, .{
            .block = block,
            .tx_count = @intCast(transactions.len),
            .digest = digest_of(&owned),
            .derived_from = owned.derived_from.?.number,
            .last_tx = try driver.arena.dupe(u8, transactions[transactions.len - 1]),
        });
        driver.cursor = block;
    }

    fn send_signals(driver: *Driver) !bool {
        if (driver.pending_reset) |head| {
            driver.pipeline.signal(driver.chain, driver.chain, .{
                .reset = .{ .l2_safe_head = head },
            }) catch |err| {
                if (errors.kind(err) == .temporary) return false;
                return err;
            };
            driver.pending_reset = null;
            driver.pending_activation = false;
        }
        if (driver.pending_activation) {
            const activation: pipeline_module.Signal = .{
                .activation = .{ .l2_safe_head = driver.cursor },
            };
            try driver.pipeline.signal(driver.chain, driver.chain, activation);
            driver.pending_activation = false;
        }
        assert(driver.pending_reset == null);
        return true;
    }

    fn handle_error(driver: *Driver, err: Error) !void {
        if (err == error.HoloceneActivation) {
            driver.pending_activation = true;
            return;
        }
        switch (errors.kind(err)) {
            .temporary => {},
            .reset => driver.pending_reset = driver.cursor,
            .critical => return err,
        }
        assert(!driver.done);
    }

    /// One driver iteration. `faults` tells whether failures may be injected, so the
    /// end of the L1 chain (`NotFound` on advance) is only trusted without them.
    fn tick(driver: *Driver, faults: bool) !void {
        if (!try driver.send_signals()) return;
        const chain = driver.chain;
        const result = driver.pipeline.step(chain, chain, chain, driver.cursor);
        switch (result) {
            .prepared_attributes => {
                try testing.expect(driver.pipeline.peek() != null);
                while (driver.pipeline.next()) |prepared| try driver.execute(prepared);
            },
            .advanced_origin => {},
            .origin_advance_err => |err| {
                if (err == error.NotFound and !faults) {
                    driver.done = true;
                    return;
                }
                try driver.handle_error(err);
            },
            .step_failed => |err| try driver.handle_error(err),
        }
        assert(driver.pipeline.prepared_len() == 0);
    }

    fn run_to_end(driver: *Driver) !void {
        driver.chain.unavailable_from = std.math.maxInt(u64);
        driver.chain.l2_unavailable = false;
        for (0..10_000) |_| {
            try driver.tick(false);
            if (driver.done) return;
        } else return error.TestUnexpectedResult;
    }
};

/// Blocks derived from 16 L1 blocks: epochs 0-11 (two L2 blocks each) stay within the
/// sequencing window of the last L1 block, so L2 blocks 1-23 are derived.
const expected_blocks = 23;

fn expect_main_sequence(scenario: *const Scenario, records: []const Record) !void {
    try testing.expectEqual(@as(usize, expected_blocks + 1), records.len);
    const user_txs = [_]?[]const u8{ null, &tx_a1, &tx_a2, null, null, &tx_c5, &tx_c6 };
    for (records[1..], 1..) |record, number| {
        const block = record.block;
        try testing.expectEqual(@as(u64, number), block.block_info.number);
        try testing.expectEqual(l2_timestamp(number), block.block_info.timestamp);
        try testing.expect(block.block_info.parent_hash.eql(l2_hash(number - 1)));
        const epoch = scenario.chain.blocks[number / 2];
        try testing.expect(block.l1_origin.eql(epoch.id()));
        try testing.expectEqual(@as(u64, number % 2), block.sequence_number);
        const user_tx = if (number < user_txs.len) user_txs[number] else null;
        if (user_tx) |tx| {
            try testing.expectEqualSlices(u8, tx, record.last_tx);
        } else {
            try testing.expectEqual(@as(u8, 0x7e), record.last_tx[0]);
        }
        // Empty blocks after the batches hold only the L1 info deposit.
        if (number > 6) try testing.expectEqual(@as(u32, 1), record.tx_count);
    }
}

test "pipeline: derives singular, span, and blob batches then forced empty batches" {
    var scenario: Scenario = undefined;
    scenario.init(16);
    defer scenario.deinit();
    try scenario.add_batches();
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    try driver.run_to_end();
    const records = driver.records.items;
    try expect_main_sequence(&scenario, records);
    // Ecotone upgrade transactions land in L2 block 6, between deposit and user tx.
    try testing.expect(records[6].tx_count > 2);
    try testing.expectEqual(@as(u32, 2), records[1].tx_count);
    try testing.expectEqual(@as(u32, 1), records[3].tx_count);
    try testing.expectEqual(@as(u64, 1), records[1].derived_from);
    try testing.expectEqual(@as(u64, 3), records[6].derived_from);
    try testing.expectEqual(@as(u64, 15), driver.pipeline.origin().?.number);
}

test "pipeline: sequencing window expiry derives empty batches" {
    var scenario: Scenario = undefined;
    scenario.init(12);
    defer scenario.deinit();
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    try driver.run_to_end();
    const records = driver.records.items;
    // Epochs 0-7 lie within the window of L1 block 11: L2 blocks 1-15.
    try testing.expectEqual(@as(usize, 16), records.len);
    for (records[1..], 1..) |record, number| {
        try testing.expectEqual(@as(u32, 1), record.tx_count);
        try testing.expectEqual(l2_timestamp(number), record.block.block_info.timestamp);
        try testing.expect(record.block.l1_origin.eql(scenario.chain.blocks[number / 2].id()));
        // Nothing is derived before the window of the first epoch expires.
        try testing.expect(record.derived_from >= 4);
    }
}

test "pipeline: holocene activation mid-chain derives the same blocks" {
    var scenario: Scenario = undefined;
    scenario.init(16);
    defer scenario.deinit();
    try scenario.add_batches();
    scenario.rollup.upgrades.set(.holocene, ecotone_time);
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    try driver.run_to_end();
    try expect_main_sequence(&scenario, driver.records.items);
    try testing.expectEqual(@as(u64, 15), driver.pipeline.origin().?.number);
    try testing.expectEqual(.validator, driver.pipeline.batch_provider.mode);
    try testing.expectEqual(.assembler, driver.pipeline.channel_provider.mode);
}

test "pipeline: signals, peek, and prepared queue bound" {
    var scenario: Scenario = undefined;
    scenario.init(4);
    defer scenario.deinit();
    try scenario.add_batches();
    var pipeline = Pipeline.init(testing.allocator, &scenario.rollup, &scenario.schedule, .{});
    defer pipeline.deinit();
    const chain = &scenario.chain;
    try testing.expect(pipeline.peek() == null and pipeline.next() == null);
    try testing.expect(pipeline.rollup_config() == &scenario.rollup);
    const genesis = scenario.genesis();
    // The L1 origin fetch fails: the reset is retried later.
    chain.unavailable_from = 0;
    const reset: pipeline_module.Signal = .{ .reset = .{ .l2_safe_head = genesis } };
    try testing.expectError(error.NotAvailable, pipeline.signal(chain, chain, reset));
    chain.unavailable_from = std.math.maxInt(u64);
    try pipeline.signal(chain, chain, reset);
    try testing.expectEqual(@as(u64, 0), pipeline.origin().?.number);
    try pipeline.signal(chain, chain, .flush_channel);
    try pipeline.signal(chain, chain, .{ .activation = .{} });

    // A full prepared queue fails the step temporarily without touching the stages.
    pipeline.prepared_count = pipeline_module.prepared_max;
    const full = pipeline.step(chain, chain, chain, genesis);
    try testing.expectEqual(error.PreparedAttributesFull, full.step_failed);
    pipeline.prepared_count = 0;

    // Step until the first attributes are buffered; they stay until drained.
    var prepared_count: u32 = 0;
    for (0..64) |_| {
        switch (pipeline.step(chain, chain, chain, genesis)) {
            .prepared_attributes => prepared_count += 1,
            .advanced_origin => {},
            .step_failed => |err| try testing.expectEqual(.temporary, errors.kind(err)),
            .origin_advance_err => |err| return err,
        }
        if (prepared_count == 1) break;
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 1), pipeline.prepared_len());
    const peeked = pipeline.peek().?;
    try testing.expectEqual(l2_timestamp(1), peeked.attributes.timestamp);
    try testing.expect(peeked.is_last_in_span);
    try testing.expectEqual(@as(u64, 1), peeked.derived_from.?.number);
    // The prepared entry is released by `deinit`.
}

test "pipeline: reset walks back one channel timeout" {
    var scenario: Scenario = undefined;
    scenario.init(16);
    defer scenario.deinit();
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    try driver.run_to_end();
    const head = driver.cursor;
    try testing.expectEqual(@as(u64, 23), head.block_info.number);
    const point = try driver.pipeline.initial_reset(driver.chain, head);
    // Safe head origin 11, channel timeout 8: the first block with origin <= 3.
    try testing.expectEqual(@as(u64, 3), point.l1_origin.number);
    try testing.expectEqual(batcher, point.system_config.batcher_address);
    driver.chain.l2_unavailable = true;
    try testing.expectError(error.NotAvailable, driver.pipeline.initial_reset(driver.chain, head));
}

/// Runs the main scenario with random unavailable data and random resets for `seed`,
/// then finishes without faults. Returns the executed blocks (caller frees).
fn run_with_faults(seed: u64) ![]Record {
    var prng = Prng.init(seed);
    var scenario: Scenario = undefined;
    scenario.init(16);
    defer scenario.deinit();
    try scenario.add_batches();
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    const chain = driver.chain;
    for (0..400) |_| {
        chain.unavailable_from = std.math.maxInt(u64);
        if (prng.chance(1, 3)) {
            const origin = driver.pipeline.origin() orelse BlockInfo{};
            chain.unavailable_from = origin.number + prng.below(3);
        }
        chain.l2_unavailable = prng.chance(1, 8);
        if (prng.chance(1, 40)) driver.rewind(prng.below(driver.records.items.len));
        try driver.tick(true);
    }
    try driver.run_to_end();
    const records = try testing.allocator.dupe(Record, driver.records.items);
    // `last_tx` lives in the scenario arena: clear it before the arena is freed.
    for (records) |*record| record.last_tx = &.{};
    return records;
}

fn run_clean() ![]Record {
    var scenario: Scenario = undefined;
    scenario.init(16);
    defer scenario.deinit();
    try scenario.add_batches();
    var driver: Driver = undefined;
    try driver.init(&scenario);
    defer driver.deinit();
    try driver.run_to_end();
    const records = try testing.allocator.dupe(Record, driver.records.items);
    for (records) |*record| record.last_tx = &.{};
    return records;
}

test "pipeline: seeded fuzz with unavailable data and resets is deterministic" {
    const clean = try run_clean();
    defer testing.allocator.free(clean);
    try testing.expectEqual(@as(usize, expected_blocks + 1), clean.len);
    var seeds = Prng.init(0x5eed_d371);
    for (0..6) |_| {
        const seed = seeds.int(u64);
        const first = try run_with_faults(seed);
        defer testing.allocator.free(first);
        const second = try run_with_faults(seed);
        defer testing.allocator.free(second);
        try testing.expectEqual(first.len, second.len);
        for (first, second) |a, b| {
            try testing.expect(a.same_block(b));
            try testing.expectEqual(a.derived_from, b.derived_from);
        }
        // Faults and resets never change what is derived.
        try testing.expectEqual(clean.len, first.len);
        for (clean, first) |a, b| try testing.expect(a.same_block(b));
    }
}

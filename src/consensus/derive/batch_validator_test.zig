//! Batch validator and batch provider tests, ported from base/base
//! `crates/consensus/derive/src/stages/batch/{batch_validator,batch_provider}.rs`, plus a
//! seeded fuzz over random batch sequences through the stream and provider.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const channel_reader = @import("channel_reader.zig");
const batch_stage = @import("batch_stage.zig");
const stubs = @import("batch_stage_test.zig");
const TestChain = @import("test_chain.zig").TestChain;
const Prng = @import("../../testing/prng.zig").Prng;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SingleBatch = protocol.batch.SingleBatch;
const Element = protocol.span_batch.Element;
const BatchValidator = batch_stage.BatchValidator;
const BatchProvider = batch_stage.BatchProvider;
const BatchStream = batch_stage.BatchStream;
const TestBatches = stubs.TestBatches;
const Entry = stubs.Entry;
const Error = errors.Error;

fn repeat(byte: u8) Hash {
    return .init(@splat(byte));
}

fn last_byte(byte: u8) Hash {
    var bytes: [32]u8 = @splat(0);
    bytes[31] = byte;
    return .init(bytes);
}

fn entry(batch: SingleBatch) Entry {
    return .{ .batch = .{ .single = batch } };
}

fn batch_on(origin: BlockInfo, parent_hash: Hash, timestamp: u64) SingleBatch {
    return .{
        .parent_hash = parent_hash,
        .epoch_num = origin.number,
        .epoch_hash = origin.hash,
        .timestamp = timestamp,
        .transactions = &.{},
    };
}

fn set_l1_blocks(validator: *BatchValidator, blocks: []const BlockInfo) !void {
    validator.l1_blocks.clearRetainingCapacity();
    try validator.l1_blocks.appendSlice(testing.allocator, blocks);
}

fn denim_config() RollupConfig {
    var config: RollupConfig = .{ .block_time = 2 };
    config.upgrades.set(.holocene, 0);
    config.upgrades.set(.denim, 0);
    return config;
}

test "batch validator: origin behind" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    var stub: TestBatches = .{};
    validator.origin = .{ .number = 1 };
    const parent: L2BlockInfo = .{ .l1_origin = .{ .number = 5 } };
    try testing.expectError(error.Eof, validator.next_batch(&stub, &l2, parent));

    // Startup: the origin is behind the parent, so the window is cleared.
    validator.origin = .{ .number = 1 };
    try set_l1_blocks(&validator, &.{.{ .number = 1 }});
    try validator.update_origins(&stub, .{ .l1_origin = .{ .number = 2 } });
    try testing.expectEqual(@as(usize, 0), validator.l1_blocks.items.len);

    // Advance: the new origin is appended.
    stub.block = .{ .number = 2 };
    validator.origin = .{ .number = 1 };
    try set_l1_blocks(&validator, &.{.{ .number = 1 }});
    try validator.update_origins(&stub, .{ .l1_origin = .{ .number = 1 } });
    try testing.expectEqual(@as(usize, 2), validator.l1_blocks.items.len);
}

test "batch validator: advance epoch" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    var stub: TestBatches = .{ .block = .{ .number = 2 } };
    validator.origin = .{ .number = 1 };
    try set_l1_blocks(&validator, &.{.{ .number = 1 }});
    const parent: L2BlockInfo = .{ .l1_origin = .{ .number = 2 } };
    try testing.expectError(error.Eof, validator.next_batch(&stub, &l2, parent));
    try testing.expectEqual(@as(usize, 1), validator.l1_blocks.items.len);
    try testing.expectEqual(@as(u64, 2), validator.l1_blocks.items[0].number);
}

test "batch validator: origin behind drains upstream" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    const default_batch = entry(batch_on(.{}, .zero, 0));
    var stub: TestBatches = .{};
    for (0..5) |_| stub.push(default_batch);
    validator.origin = .{};
    const parent: L2BlockInfo = .{ .l1_origin = .{ .number = 5 } };
    for (0..5) |i| {
        try testing.expectError(error.NotEnoughData, validator.next_batch(&stub, &l2, parent));
        try testing.expectEqual(4 - i, stub.span_buffer_size());
    }
    try testing.expectError(error.Eof, validator.next_batch(&stub, &l2, parent));
}

test "batch validator: l1 origin mismatch and span batch" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    var stub = TestBatches.init(&.{entry(batch_on(.{}, .zero, 0))});
    stub.block = .{ .number = 1 };
    validator.origin = .{};
    try set_l1_blocks(&validator, &.{.{}});
    const mismatched: L2BlockInfo = .{ .l1_origin = .{ .number = 0, .hash = repeat(0xff) } };
    try testing.expectError(error.L1OriginMismatch, validator.next_batch(&stub, &l2, mismatched));

    var span_validator = BatchValidator.init(testing.allocator, &config);
    defer span_validator.deinit();
    const elements = [_]Element{.{}};
    var span_stub = TestBatches.init(&.{.{ .batch = .{ .span = .{ .batches = &elements } } }});
    span_stub.block = .{ .number = 1 };
    span_validator.origin = .{};
    try set_l1_blocks(&span_validator, &.{.{}});
    const parent: L2BlockInfo = .{};
    const span_result = span_validator.next_batch(&span_stub, &l2, parent);
    try testing.expectError(error.InvalidBatchType, span_result);
    try testing.expectError(error.Eof, span_validator.next_batch(&span_stub, &l2, parent));
}

test "batch validator: next batch valid" {
    var config: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 700 };
    config.upgrades.set(.holocene, 0);
    const batch: SingleBatch = .{
        .parent_hash = repeat(1),
        .epoch_num = 2,
        .epoch_hash = .zero,
        .timestamp = 4,
        .transactions = &.{},
    };
    const parent: L2BlockInfo = .{
        .block_info = .{ .number = 1, .hash = repeat(1), .timestamp = 2 },
        .l1_origin = .{ .number = 0 },
    };
    var stub = TestBatches.init(&.{entry(batch)});
    stub.block = .{ .number = 1 };
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    try validator.reset(.{ .number = 1 });
    try validator.l1_blocks.append(testing.allocator, .{ .number = 1 });
    const produced = try validator.next_batch(&stub, &l2, parent);
    try testing.expectEqual(@as(u64, 4), produced.timestamp);
    try testing.expect(produced.parent_hash.eql(repeat(1)));
}

test "batch validator: sequence window expiry" {
    const config: RollupConfig = .{ .seq_window_size = 5 };
    var l2 = TestChain.init(0, 0, 1);
    for ([_]u64{ 0, 1 }) |parent_origin| {
        var validator = BatchValidator.init(testing.allocator, &config);
        defer validator.deinit();
        var stub: TestBatches = .{ .block = .{ .number = 1 } };
        try validator.reset(.{ .number = 1 });
        stub.block.?.number += 6;
        const parent: L2BlockInfo = .{ .l1_origin = .{ .number = parent_origin } };
        if (parent_origin == 0) {
            const batch = try validator.next_batch(&stub, &l2, parent);
            try testing.expectEqual(@as(usize, 0), batch.transactions.len);
            try testing.expectEqual(@as(u64, 1), batch.epoch_num);
        } else {
            try testing.expectError(error.Eof, validator.next_batch(&stub, &l2, parent));
            try testing.expectEqual(@as(u64, 7), validator.l1_blocks.items[0].number);
        }
    }
}

test "batch validator: pre-denim rejects a stale parent after a past batch" {
    const epoch: BlockInfo = .{ .number = 10, .hash = repeat(0x10), .timestamp = 590 };
    const inclusion: BlockInfo = .{ .number = 11, .timestamp = 591 };
    const parent: L2BlockInfo = .{
        .block_info = .{ .number = 600, .hash = repeat(0x60), .timestamp = 600 },
        .l1_origin = epoch.id(),
    };
    const next = batch_on(epoch, repeat(0xaa), 601);
    const past = batch_on(epoch, repeat(0xaa), 600);
    var stub = TestBatches.init(&.{ entry(next), entry(past) });
    stub.block = inclusion;
    var config: RollupConfig = .{
        .block_time = 1,
        .max_sequencer_drift = 700,
        .seq_window_size = 3_600,
    };
    config.upgrades.set(.holocene, 0);
    var l2 = TestChain.init(0, 0, 1);
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    validator.origin = inclusion;
    try set_l1_blocks(&validator, &.{ epoch, inclusion });
    try testing.expectError(error.NotEnoughData, validator.next_batch(&stub, &l2, parent));
    try testing.expect(!stub.flushed);
    try testing.expectError(error.NotEnoughData, validator.next_batch(&stub, &l2, parent));
    try testing.expect(stub.flushed);
}

fn ancestry_case(l2: *TestChain, batch_parent: Hash) !bool {
    const config = denim_config();
    const origin: BlockInfo = .{ .number = 1, .hash = repeat(0x11) };
    const parent: L2BlockInfo = .{ .block_info = .{
        .number = 3,
        .hash = last_byte(0x43),
        .parent_hash = last_byte(0x42),
    } };
    const timestamp = config.l2_block_timestamp(parent.block_info.number + 1);
    var stub = TestBatches.init(&.{entry(batch_on(origin, batch_parent, timestamp))});
    stub.block = origin;
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    validator.origin = origin;
    try set_l1_blocks(&validator, &.{ origin, origin });
    try testing.expectError(error.NotEnoughData, validator.next_batch(&stub, l2, parent));
    return stub.flushed;
}

test "batch validator: denim ancestry ignores another fork at the same height" {
    const other_fork: L2BlockInfo = .{ .block_info = .{
        .number = 1,
        .hash = last_byte(0xaa),
        .parent_hash = last_byte(0x40),
    } };
    const batch_parents = [_]Hash{ other_fork.block_info.hash, last_byte(0x41), last_byte(0x40) };
    const expected = [_]bool{ true, false, false };
    for ([_]bool{ false, true }) |different_number_view| {
        var l2 = TestChain.init(0, 0, 1);
        if (different_number_view) l2.add_l2_block(other_fork);
        for (0..3) |number| {
            const offset: u8 = @intCast(number);
            l2.add_l2_block(.{ .block_info = .{
                .number = number,
                .hash = last_byte(0x40 + offset),
                .parent_hash = last_byte(0x3f + offset),
            } });
        }
        for (batch_parents, expected) |batch_parent, flushed| {
            try testing.expectEqual(flushed, try ancestry_case(&l2, batch_parent));
        }
    }
}

test "batch validator: denim ancestry stops at genesis and the second boundary" {
    const origin: BlockInfo = .{ .number = 1, .hash = repeat(0x11) };
    const cases = [_]struct { offset: u64, flushed: bool }{
        .{ .offset = 0, .flushed = true }, .{ .offset = 1, .flushed = false },
        .{ .offset = 4, .flushed = true }, .{ .offset = 5, .flushed = false },
    };
    var l2 = TestChain.init(0, 0, 1);
    for ([_]u64{ 0, 10 }) |genesis_number| {
        var config = denim_config();
        config.genesis.l2.number = genesis_number;
        for (cases) |case| {
            const number = genesis_number + case.offset;
            const parent: L2BlockInfo = .{ .block_info = .{
                .number = number,
                .hash = repeat(0x33),
                .parent_hash = repeat(0x22),
                .timestamp = config.l2_block_timestamp(number),
            } };
            const timestamp = config.l2_block_timestamp(number + 1);
            var stub = TestBatches.init(&.{entry(batch_on(origin, repeat(0x22), timestamp))});
            stub.block = origin;
            var validator = BatchValidator.init(testing.allocator, &config);
            defer validator.deinit();
            validator.origin = origin;
            try set_l1_blocks(&validator, &.{ origin, origin });
            const result = validator.next_batch(&stub, &l2, parent);
            try testing.expectError(error.NotEnoughData, result);
            try testing.expectEqual(case.flushed, stub.flushed);
        }
    }
}

fn unknown_parent_setup(
    validator: *BatchValidator,
    stub: *TestBatches,
    origin: BlockInfo,
) !L2BlockInfo {
    stub.* = TestBatches.init(&.{entry(batch_on(origin, repeat(0xff), 0))});
    stub.block = origin;
    validator.origin = origin;
    try set_l1_blocks(validator, &.{ origin, origin });
    return .{ .block_info = .{
        .number = 3,
        .hash = repeat(0x33),
        .parent_hash = last_byte(2),
    } };
}

test "batch validator: denim retries, then flushes an unknown parent" {
    const config = denim_config();
    const origin: BlockInfo = .{ .number = 1, .hash = repeat(0x11) };
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    var stub: TestBatches = .{};
    const parent = try unknown_parent_setup(&validator, &stub, origin);
    var l2 = TestChain.init(0, 0, 1);
    try testing.expectError(error.NotFound, validator.next_batch(&stub, &l2, parent));
    try testing.expect(validator.pending_batch != null);
    try testing.expect(validator.pending_batch.?.inclusion_block.eql(origin));
    try testing.expect(!stub.flushed);
    for (0..3) |number| {
        const index: u8 = @intCast(number);
        l2.add_l2_block(.{ .block_info = .{
            .number = number,
            .hash = last_byte(index),
            .parent_hash = last_byte(index -| 1),
        } });
    }
    try testing.expectError(error.NotEnoughData, validator.next_batch(&stub, &l2, parent));
    try testing.expect(validator.pending_batch == null);
    try testing.expect(stub.flushed);
}

test "batch validator: denim does not retry a reset-class ancestry error" {
    const config = denim_config();
    const origin: BlockInfo = .{ .number = 1, .hash = repeat(0x11) };
    var validator = BatchValidator.init(testing.allocator, &config);
    defer validator.deinit();
    var stub: TestBatches = .{};
    const parent = try unknown_parent_setup(&validator, &stub, origin);
    var l2: stubs.ResettingL2 = .{};
    const result = validator.next_batch(&stub, &l2, parent);
    try testing.expectError(error.BlobsUnavailable, result);
    try testing.expectEqual(errors.Kind.reset, errors.kind(error.BlobsUnavailable));
    try testing.expect(validator.pending_batch == null);
}

// ---------------------------------------------------------------------------------------
// BatchProvider

test "batch provider: picks the stage for the origin" {
    var holocene: RollupConfig = .{};
    holocene.upgrades.set(.holocene, 0);
    var provider = BatchProvider.init(testing.allocator, &holocene);
    defer provider.deinit();
    var stub: TestBatches = .{};
    try provider.attempt_update(&stub);
    try testing.expectEqual(.validator, provider.mode);

    const pre: RollupConfig = .{};
    var queue_provider = BatchProvider.init(testing.allocator, &pre);
    defer queue_provider.deinit();
    try queue_provider.attempt_update(&stub);
    try testing.expectEqual(.queue, queue_provider.mode);
    stub.block = null;
    try testing.expectError(error.MissingOrigin, queue_provider.attempt_update(&stub));
}

test "batch provider: transitions carry the l1 window and origin" {
    var config: RollupConfig = .{};
    config.upgrades.set(.holocene, 10);
    var provider = BatchProvider.init(testing.allocator, &config);
    defer provider.deinit();
    var stub: TestBatches = .{};
    try provider.attempt_update(&stub);
    try testing.expectEqual(.queue, provider.mode);
    const block: BlockInfo = .{ .number = 5, .timestamp = 3 };
    provider.queue.origin = block;
    try provider.queue.l1_blocks.append(testing.allocator, block);

    stub.block = .{ .number = 1, .timestamp = 10 };
    try provider.attempt_update(&stub);
    try testing.expectEqual(.validator, provider.mode);
    try testing.expect(provider.validator.origin.?.eql(block));
    try testing.expectEqual(@as(usize, 1), provider.validator.l1_blocks.items.len);
    try testing.expect(provider.validator.l1_blocks.items[0].eql(block));
    try testing.expectEqual(@as(usize, 0), provider.queue.l1_blocks.items.len);

    // Backwards (L1 reorg below Holocene): the window moves, the origin does not.
    stub.block = .{};
    try provider.attempt_update(&stub);
    try testing.expectEqual(.queue, provider.mode);
    try testing.expect(provider.queue.origin == null);
    try testing.expectEqual(@as(usize, 1), provider.queue.l1_blocks.items.len);
    try testing.expectEqual(@as(usize, 0), provider.validator.l1_blocks.items.len);
}

test "batch provider: reset either stage" {
    for ([_]?u64{ null, 0 }) |holocene_time| {
        var config: RollupConfig = .{};
        config.upgrades.set(.holocene, holocene_time);
        var provider = BatchProvider.init(testing.allocator, &config);
        defer provider.deinit();
        var stub: TestBatches = .{};
        try provider.reset(&stub);
        const l1_count = switch (provider.mode) {
            .queue => provider.queue.l1_blocks.items.len,
            .validator => provider.validator.l1_blocks.items.len,
            .unset => unreachable,
        };
        try testing.expectEqual(@as(usize, 1), l1_count);
        try testing.expectEqual(holocene_time != null, provider.mode == .validator);
    }
}

fn set_stage_window(provider: *BatchProvider, origin: BlockInfo, blocks: []const BlockInfo) !void {
    switch (provider.mode) {
        .queue => {
            provider.queue.origin = origin;
            provider.queue.l1_blocks.clearRetainingCapacity();
            try provider.queue.l1_blocks.appendSlice(testing.allocator, blocks);
        },
        .validator => {
            provider.validator.origin = origin;
            try set_l1_blocks(&provider.validator, blocks);
        },
        .unset => unreachable,
    }
}

fn expect_empty_batch(
    config: *const RollupConfig,
    batch: SingleBatch,
    epoch: BlockInfo,
    timestamp: u64,
    l1: []const BlockInfo,
    parent: L2BlockInfo,
    inclusion: BlockInfo,
) !void {
    try testing.expect(batch.epoch().eql(epoch.id()));
    try testing.expectEqual(timestamp, batch.timestamp);
    try testing.expectEqual(@as(usize, 0), batch.transactions.len);
    try testing.expect(batch.check(config, l1, parent, inclusion).eql(.accept));
}

test "batch provider: denim same-second origin forces empty batches" {
    for ([_]bool{ false, true }) |holocene| {
        var config: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 1_800 };
        config.seq_window_size = 2;
        config.genesis.l2_time = 1_898;
        config.upgrades.set(.holocene, if (holocene) 0 else null);
        config.upgrades.set(.denim, 1_902);
        const current: BlockInfo = .{ .number = 10, .hash = repeat(10), .timestamp = 88 };
        const next: BlockInfo = .{
            .number = 11,
            .hash = repeat(11),
            .parent_hash = current.hash,
            .timestamp = 100,
        };
        const later: BlockInfo = .{
            .number = 12,
            .hash = repeat(12),
            .parent_hash = next.hash,
            .timestamp = 112,
        };
        var stub: TestBatches = .{ .block = later };
        var l2 = TestChain.init(0, 0, 1);
        var provider = BatchProvider.init(testing.allocator, &config);
        defer provider.deinit();
        try provider.attempt_update(&stub);
        try set_stage_window(&provider, later, &.{ current, next, later });
        var parent: L2BlockInfo = .{
            .block_info = .{ .number = 4, .timestamp = 1_902, .hash = repeat(42) },
            .l1_origin = current.id(),
        };
        const window = [_]BlockInfo{ current, next };
        for ([_]u8{ 5, 6 }) |number| {
            const batch = try provider.next_batch(&stub, &l2, parent);
            try expect_empty_batch(&config, batch, current, 1_902, &window, parent, later);
            parent.block_info.number = number;
            parent.block_info.hash = repeat(number);
            if (number != 5) continue;
            stub.block = current;
            try provider.reset(&stub);
            stub.block = next;
            try testing.expectError(error.Eof, provider.next_batch(&stub, &l2, parent));
            stub.block = later;
        }
        try testing.expectError(error.Eof, provider.next_batch(&stub, &l2, parent));
        const inclusion: BlockInfo = .{ .number = 13, .timestamp = 124, .hash = later.hash };
        stub.block = inclusion;
        const batch = try provider.next_batch(&stub, &l2, parent);
        try expect_empty_batch(&config, batch, next, 1_903, &window, parent, inclusion);
    }
}

test "batch provider: denim validator skips same-second stale batches" {
    const origin: BlockInfo = .{ .number = 1, .hash = repeat(0x11) };
    const inclusion: BlockInfo = .{
        .number = 2,
        .hash = repeat(0x22),
        .parent_hash = origin.hash,
        .timestamp = 12,
    };
    var config: RollupConfig = .{ .block_time = 2, .seq_window_size = 2 };
    config.upgrades.set(.holocene, 0);
    config.upgrades.set(.denim, 46);
    const parent: L2BlockInfo = .{
        .block_info = .{
            .number = 300,
            .hash = repeat(0x33),
            .parent_hash = last_byte(@truncate(299)),
            .timestamp = config.l2_block_timestamp(300),
        },
        .l1_origin = origin.id(),
    };
    try testing.expectEqual(config.l2_block_timestamp(298), config.l2_block_timestamp(301));
    const timestamp = config.l2_block_timestamp(301);
    const valid = batch_on(origin, parent.block_info.hash, timestamp);
    const stale_298 = batch_on(origin, last_byte(@truncate(297)), timestamp);
    const stale_299 = batch_on(origin, last_byte(@truncate(298)), timestamp);
    var stub = TestBatches.init(&.{ entry(valid), entry(stale_299), entry(stale_298) });
    stub.block = inclusion;
    var l2 = TestChain.init(0, 0, 1);
    for (295..300) |number| {
        l2.add_l2_block(.{ .block_info = .{
            .number = number,
            .hash = last_byte(@truncate(number)),
            .parent_hash = last_byte(@truncate(number - 1)),
        } });
    }
    var provider = BatchProvider.init(testing.allocator, &config);
    defer provider.deinit();
    try provider.attempt_update(&stub);
    try set_stage_window(&provider, inclusion, &.{ origin, inclusion });
    try testing.expectError(error.NotEnoughData, provider.next_batch(&stub, &l2, parent));
    try testing.expectError(error.NotEnoughData, provider.next_batch(&stub, &l2, parent));
    try testing.expect(!stub.flushed);
    const produced = try provider.next_batch(&stub, &l2, parent);
    try testing.expect(produced.parent_hash.eql(valid.parent_hash));
    try testing.expectEqual(timestamp, produced.timestamp);
}

// ---------------------------------------------------------------------------------------
// Seeded fuzz: random batch sequences through the batch stream and provider.

const FuzzWorld = struct {
    config: RollupConfig,
    l1: [8]BlockInfo,
    parent: L2BlockInfo,
    origin_index: usize = 0,

    fn init(prng: *Prng) FuzzWorld {
        var world: FuzzWorld = .{
            .config = .{
                .block_time = 2,
                // A window of one L1 block can leave the validator with only its
                // origin after an epoch advance, a critical error in base/base too.
                .seq_window_size = prng.range(2, 5),
                .max_sequencer_drift = prng.range(0, 20),
            },
            .l1 = undefined,
            .parent = .{},
        };
        world.config.upgrades.set(.delta, 0);
        if (prng.chance(1, 2)) world.config.upgrades.set(.holocene, prng.range(0, 30));
        for (&world.l1, 0..) |*block, i| {
            block.* = .{ .number = i, .hash = repeat(@intCast(i + 1)), .timestamp = i * 6 };
        }
        world.parent = .{
            .block_info = .{ .number = 0, .hash = repeat(0xa0), .timestamp = 0 },
            .l1_origin = world.l1[0].id(),
        };
        return world;
    }

    /// A batch that is valid, or close to valid, for the current parent.
    fn random_batch(world: *const FuzzWorld, prng: *Prng) SingleBatch {
        const next_timestamp = world.config.l2_block_timestamp(world.parent.block_info.number + 1);
        const epoch_index = @min(world.parent.l1_origin.number + prng.below(2), world.l1.len - 1);
        var batch = batch_on(world.l1[epoch_index], world.parent.block_info.hash, next_timestamp);
        if (prng.chance(1, 4)) batch.parent_hash = repeat(prng.int(u8));
        if (prng.chance(1, 4)) batch.timestamp = next_timestamp + 2 * prng.below(3);
        if (prng.chance(1, 8)) batch.timestamp = next_timestamp -| 2;
        return batch;
    }

    /// A span of up to three blocks starting at the next block, in the parent's epoch.
    fn random_span(world: *const FuzzWorld, prng: *Prng, arena: std.mem.Allocator) !Entry {
        var singles: [3]SingleBatch = undefined;
        const count = prng.range(1, singles.len);
        for (singles[0..count], 0..) |*single, i| {
            single.* = world.random_batch(prng);
            single.epoch_num = world.parent.l1_origin.number;
            single.epoch_hash = world.parent.l1_origin.hash;
            const number = world.parent.block_info.number + 1 + i;
            single.timestamp = world.config.l2_block_timestamp(number);
        }
        const span = try protocol.span_batch.SpanBatch.from_singular_batches(
            arena,
            singles[0..count],
            1,
            world.config.genesis.l2_time,
            0,
        );
        return .{ .batch = .{ .span = span } };
    }

    fn advance(world: *FuzzWorld, batch: SingleBatch) !void {
        const next_number = world.parent.block_info.number + 1;
        try testing.expectEqual(world.config.l2_block_timestamp(next_number), batch.timestamp);
        try testing.expect(batch.parent_hash.eql(world.parent.block_info.hash));
        try testing.expect(batch.epoch_num >= world.parent.l1_origin.number);
        world.parent = .{
            .block_info = .{
                .number = next_number,
                .hash = repeat(@truncate(0xa0 + next_number)),
                .parent_hash = world.parent.block_info.hash,
                .timestamp = batch.timestamp,
            },
            .l1_origin = batch.epoch(),
        };
    }
};

fn fuzz_round(prng: *Prng) !u64 {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var world = FuzzWorld.init(prng);
    var advanced: u64 = 0;
    var stub: TestBatches = .{ .block = world.l1[0] };
    var stream = BatchStream.init(testing.allocator, &world.config);
    defer stream.deinit();
    var provider = BatchProvider.init(testing.allocator, &world.config);
    defer provider.deinit();
    var l2 = TestChain.init(0, 0, 1);
    try provider.reset(&stub);
    for (0..64) |_| {
        if (stub.count < stub.entries.len and prng.chance(2, 3)) {
            if (prng.chance(1, 4)) {
                stub.push(try world.random_span(prng, arena_state.allocator()));
            } else {
                stub.push(entry(world.random_batch(prng)));
            }
        }
        if (prng.chance(1, 4) and world.origin_index + 1 < world.l1.len) {
            world.origin_index += 1;
            stub.block = world.l1[world.origin_index];
        }
        const upstream = stream.upstream(stub.reader(), &l2);
        const batch = provider.next_batch(upstream, &l2, world.parent) catch |err| {
            switch (errors.kind(err)) {
                .temporary => continue,
                .reset => {
                    // Like the pipeline, restart from the safe head's L1 origin.
                    world.origin_index = world.parent.l1_origin.number;
                    stub.block = world.l1[world.origin_index];
                    stream.clear();
                    try provider.reset(upstream);
                    continue;
                },
                .critical => return err,
            }
        };
        try world.advance(batch);
        advanced += 1;
    }
    return advanced;
}

test "batch stages: seeded fuzz random batch sequences" {
    var prng = Prng.init(0x42415443);
    var advanced: u64 = 0;
    for (0..300) |_| advanced += try fuzz_round(&prng);
    // The sequences are mostly valid, so the safe head keeps moving.
    try testing.expect(advanced > 1_000);
}

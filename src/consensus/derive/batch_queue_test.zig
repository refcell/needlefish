//! Batch queue tests, ported from base/base
//! `crates/consensus/derive/src/stages/batch/batch_queue.rs`.

const std = @import("std");
const testing = std.testing;

const protocol = @import("../protocol/root.zig");
const channel_reader = @import("channel_reader.zig");
const batch_stage = @import("batch_stage.zig");
const stubs = @import("batch_stage_test.zig");
const TestChain = @import("test_chain.zig").TestChain;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SingleBatch = protocol.batch.SingleBatch;
const Element = protocol.span_batch.Element;
const OwnedBatch = channel_reader.OwnedBatch;
const BatchQueue = batch_stage.BatchQueue;
const TestBatches = stubs.TestBatches;
const Entry = stubs.Entry;

fn single_batch(timestamp: u64) SingleBatch {
    return .{
        .parent_hash = .zero,
        .epoch_num = 0,
        .epoch_hash = .zero,
        .timestamp = timestamp,
        .transactions = &.{},
    };
}

fn owned_single(batch: SingleBatch) OwnedBatch {
    return .{ .arena = .init(testing.allocator), .batch = .{ .single = batch } };
}

fn entry(batch: SingleBatch) Entry {
    return .{ .batch = .{ .single = batch } };
}

/// A queue with `origin` set and `count` default L1 blocks, as the base/base tests do.
fn queue_with_origin(config: *const RollupConfig, count: usize) !BatchQueue {
    var queue = BatchQueue.init(testing.allocator, config);
    queue.origin = .{};
    for (0..count) |_| try queue.l1_blocks.append(testing.allocator, .{});
    return queue;
}

fn push_pending(queue: *BatchQueue, batch: SingleBatch) !void {
    try queue.batches.append(testing.allocator, .{
        .owned = owned_single(batch),
        .inclusion_block = .{},
    });
}

test "batch queue: pop next batch" {
    const config: RollupConfig = .{};
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var spans = [_]SingleBatch{ single_batch(2), single_batch(4) };
    queue.next_spans = &spans;
    const parent: L2BlockInfo = .{ .block_info = .{ .hash = .init(@splat(1)) } };
    const first = queue.pop_next_batch(parent).?;
    try testing.expectEqual(@as(u64, 2), first.timestamp);
    try testing.expect(first.parent_hash.eql(parent.block_info.hash));
    try testing.expectEqual(@as(u64, 4), queue.next_spans[queue.spans_cursor].timestamp);
    const second = queue.pop_next_batch(parent).?;
    try testing.expectEqual(@as(u64, 4), second.timestamp);
    try testing.expect(queue.is_last_in_span());
    try testing.expect(queue.pop_next_batch(parent) == null);
}

test "batch queue: cached span is not emitted at denim" {
    var config: RollupConfig = .{ .block_time = 2 };
    config.upgrades.set(.denim, 6);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var spans = [_]SingleBatch{single_batch(6)};
    queue.next_spans = &spans;
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    const parent: L2BlockInfo = .{ .block_info = .{ .number = 2, .timestamp = 4 } };
    if (queue.next_batch(&stub, &l2, parent)) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expect(queue.is_last_in_span());
}

test "batch queue: reset and flush channel" {
    const config: RollupConfig = .{};
    var queue = try queue_with_origin(&config, 1);
    defer queue.deinit();
    var spans = [_]SingleBatch{single_batch(0)};
    queue.next_spans = &spans;
    try push_pending(&queue, single_batch(0));
    try queue.reset(.{});
    try testing.expect(queue.origin.?.eql(.{}));
    try testing.expectEqual(@as(usize, 0), queue.batches.items.len);
    try testing.expectEqual(@as(usize, 1), queue.l1_blocks.items.len);
    try testing.expect(queue.is_last_in_span());

    queue.next_spans = &spans;
    try push_pending(&queue, single_batch(0));
    queue.flush_channel();
    try testing.expectEqual(@as(usize, 0), queue.batches.items.len);
    try testing.expectEqual(@as(usize, 1), queue.l1_blocks.items.len);
    try testing.expect(queue.is_last_in_span());
}

fn add_one(config: *const RollupConfig, batch: SingleBatch, parent: L2BlockInfo) !usize {
    var queue = try queue_with_origin(config, 2);
    defer queue.deinit();
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    try queue.add_batch(&stub, &l2, owned_single(batch), parent);
    return queue.batches.items.len;
}

test "batch queue: add batch keeps, drops, and ignores" {
    var valid_config: RollupConfig = .{ .max_sequencer_drift = 700 };
    valid_config.genesis.l2_time = 100;
    valid_config.upgrades.set(.holocene, 0);
    const parent_100: L2BlockInfo = .{ .block_info = .{ .timestamp = 100 } };
    const kept = try add_one(&valid_config, single_batch(100), parent_100);
    try testing.expectEqual(@as(usize, 1), kept);

    var holocene: RollupConfig = .{};
    holocene.upgrades.set(.holocene, 0);
    // Holocene drops future batches.
    try testing.expectEqual(@as(usize, 0), try add_one(&holocene, single_batch(100), .{}));

    var drop_config: RollupConfig = .{};
    drop_config.genesis.l2_time = 101;
    const parent_101: L2BlockInfo = .{ .block_info = .{ .timestamp = 101 } };
    const dropped = try add_one(&drop_config, single_batch(100), parent_101);
    try testing.expectEqual(@as(usize, 0), dropped);

    var old_config: RollupConfig = .{ .block_time = 2 };
    old_config.upgrades.set(.holocene, 0);
    try testing.expectEqual(@as(usize, 0), try add_one(&old_config, single_batch(100), parent_101));
}

test "batch queue: derive next batch errors" {
    const config: RollupConfig = .{};
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    var empty_queue = BatchQueue.init(testing.allocator, &config);
    defer empty_queue.deinit();
    const missing = empty_queue.derive_next_batch(&stub, &l2, false, .{});
    try testing.expectError(error.MissingOrigin, missing);

    var queue = try queue_with_origin(&config, 1);
    defer queue.deinit();
    // The parent is ahead of epoch zero: no underflow, an origin mismatch.
    const ahead: L2BlockInfo = .{ .l1_origin = .{ .number = 1 } };
    const mismatch = queue.derive_next_batch(&stub, &l2, false, ahead);
    try testing.expectError(error.L1OriginMismatch, mismatch);
}

test "batch queue: derive next batch without batches" {
    const config: RollupConfig = .{};
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    var queue = try queue_with_origin(&config, 1);
    defer queue.deinit();
    try testing.expectError(error.Eof, queue.derive_next_batch(&stub, &l2, true, .{}));
    try testing.expectError(error.Eof, queue.derive_next_batch(&stub, &l2, false, .{}));
    try testing.expect(queue.is_last_in_span());

    // With a next epoch available and the window expired, the epoch advances.
    try queue.l1_blocks.append(testing.allocator, .{});
    try testing.expectError(error.Eof, queue.derive_next_batch(&stub, &l2, true, .{}));
    try testing.expectEqual(@as(usize, 1), queue.l1_blocks.items.len);
}

test "batch queue: future batches are kept before holocene, dropped after" {
    const pre: RollupConfig = .{};
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    var queue = try queue_with_origin(&pre, 2);
    defer queue.deinit();
    try queue.add_batch(&stub, &l2, owned_single(single_batch(100)), .{});
    try testing.expectEqual(@as(usize, 1), queue.batches.items.len);
    try testing.expectError(error.Eof, queue.derive_next_batch(&stub, &l2, true, .{}));
    try testing.expectEqual(@as(usize, 1), queue.batches.items.len);
    try testing.expect(!stub.flushed);

    var post: RollupConfig = .{};
    post.upgrades.set(.holocene, 0);
    var holocene_queue = try queue_with_origin(&post, 2);
    defer holocene_queue.deinit();
    try push_pending(&holocene_queue, single_batch(100));
    try testing.expectError(error.Eof, holocene_queue.derive_next_batch(&stub, &l2, true, .{}));
    try testing.expectEqual(@as(usize, 0), holocene_queue.batches.items.len);
    try testing.expect(stub.flushed);
}

test "batch queue: undecided batch keeps the rest of the queue" {
    // base/base `test_derive_next_batch_cancellation_preserves_queue`: the span check
    // blocks on the L2 provider; here the provider reports NotAvailable instead.
    var config: RollupConfig = .{ .block_time = 2 };
    config.upgrades.set(.delta, 0);
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    l2.l2_unavailable = true;
    var queue = try queue_with_origin(&config, 1);
    defer queue.deinit();
    try push_pending(&queue, single_batch(8));
    var stale = single_batch(6);
    stale.parent_hash = .init(@splat(1));
    try push_pending(&queue, stale);
    const elements = [_]Element{ .{ .timestamp = 2 }, .{ .timestamp = 6 } };
    try queue.batches.append(testing.allocator, .{
        .owned = .{ .arena = .init(testing.allocator), .batch = .{ .span = .{
            .batches = &elements,
        } } },
        .inclusion_block = .{},
    });
    try push_pending(&queue, single_batch(10));
    const parent: L2BlockInfo = .{ .block_info = .{ .number = 2, .timestamp = 4 } };
    try testing.expectError(error.Eof, queue.derive_next_batch(&stub, &l2, false, parent));
    // The future batch stays, the mismatched one is dropped, the rest is kept.
    const items = queue.batches.items;
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqual(@as(u64, 8), items[0].owned.batch.single.timestamp);
    try testing.expect(items[1].owned.batch == .span);
    try testing.expectEqual(@as(u64, 10), items[2].owned.batch.single.timestamp);
    try testing.expect(stub.flushed);
    for (items) |pending| try testing.expect(pending.keep);
}

test "batch queue: next batch serves and clears cached spans" {
    const config: RollupConfig = .{};
    var stub: TestBatches = .{};
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var spans = [_]SingleBatch{single_batch(0)};
    queue.next_spans = &spans;
    const next = try queue.next_batch(&stub, &l2, .{});
    try testing.expectEqual(@as(u64, 0), next.timestamp);
    try testing.expect(queue.is_last_in_span());

    const slow: RollupConfig = .{ .block_time = 100 };
    var slow_queue = BatchQueue.init(testing.allocator, &slow);
    defer slow_queue.deinit();
    slow_queue.next_spans = &spans;
    var future_stub = TestBatches.init(&.{entry(single_batch(1_000))});
    const cleared = slow_queue.next_batch(&future_stub, &l2, .{});
    try testing.expectError(error.NotEnoughData, cleared);
    try testing.expect(slow_queue.is_last_in_span());
}

test "batch queue: next batch not enough data and origin behind" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var stub = TestBatches.init(&.{entry(single_batch(100))});
    try testing.expectError(error.NotEnoughData, queue.next_batch(&stub, &l2, .{}));
    try testing.expect(queue.is_last_in_span());

    var behind_queue = BatchQueue.init(testing.allocator, &config);
    defer behind_queue.deinit();
    var behind_stub = TestBatches.init(&.{ entry(single_batch(0)), entry(single_batch(0)) });
    const parent: L2BlockInfo = .{ .l1_origin = .{ .number = 10 } };
    const behind = behind_queue.next_batch(&behind_stub, &l2, parent);
    try testing.expectError(error.NotEnoughData, behind);
    try testing.expectEqual(@as(usize, 0), behind_queue.batches.items.len);
    try testing.expectEqual(@as(usize, 0), behind_queue.l1_blocks.items.len);
}

test "batch queue: next batch drops a stale span batch" {
    var config: RollupConfig = .{
        .block_time = 100,
        .max_sequencer_drift = 10_000_000,
        .seq_window_size = 10_000_000,
    };
    config.upgrades.set(.delta, 0);
    config.genesis.l2 = .{ .number = 8, .hash = .init(@splat(0x44)) };
    config.genesis.l2_time = 1_000;
    const parent_timestamp = config.l2_block_timestamp(9);
    const origin_hash: Hash = .init(@splat(0x85));
    const elements = [_]Element{.{ .epoch_num = 20, .timestamp = parent_timestamp }};
    var stub = TestBatches.init(&.{.{ .batch = .{ .span = .{ .batches = &elements } } }});
    stub.block = .{ .number = 20, .timestamp = 0, .hash = origin_hash };
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    const parent: L2BlockInfo = .{
        .block_info = .{ .number = 9, .timestamp = parent_timestamp },
        .l1_origin = .{ .number = 20, .hash = origin_hash },
    };
    try testing.expectError(error.NotEnoughData, queue.next_batch(&stub, &l2, parent));
    try testing.expectEqual(@as(usize, 0), queue.batches.items.len);
    try testing.expect(stub.flushed);
}

test "batch queue: empty batch bytes" {
    const config: RollupConfig = .{};
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var stub = TestBatches.init(&.{entry(single_batch(0))});
    const batch = try queue.next_batch(&stub, &l2, .{});
    try testing.expectEqual(@as(u64, 0), batch.timestamp);
    try testing.expectEqual(@as(usize, 0), batch.transactions.len);
    try testing.expect(queue.returned != null);
}

test "batch queue: accepted span batch is expanded across calls" {
    var config: RollupConfig = .{
        .block_time = 2,
        .seq_window_size = 100,
        .max_sequencer_drift = 100,
    };
    config.upgrades.set(.delta, 0);
    const l1_hash: Hash = .init(@splat(0x33));
    const parent_hash: Hash = .init(@splat(0x11));
    const elements = [_]Element{
        .{ .epoch_num = 1, .timestamp = 2 },
        .{ .epoch_num = 1, .timestamp = 4 },
    };
    const span: protocol.span_batch.SpanBatch = .{
        .batches = &elements,
        .parent_check = parent_hash.bytes[0..20].*,
        .l1_origin_check = l1_hash.bytes[0..20].*,
    };
    var stub = TestBatches.init(&.{.{ .batch = .{ .span = span } }});
    stub.block = .{ .number = 1, .hash = l1_hash };
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    var parent: L2BlockInfo = .{
        .block_info = .{ .hash = parent_hash },
        .l1_origin = .{ .number = 1, .hash = l1_hash },
    };
    const first = try queue.next_batch(&stub, &l2, parent);
    try testing.expectEqual(@as(u64, 2), first.timestamp);
    try testing.expect(first.parent_hash.eql(parent_hash));
    try testing.expect(!queue.is_last_in_span());
    parent.block_info = .{ .number = 1, .timestamp = 2, .hash = .init(@splat(0x22)) };
    const second = try queue.next_batch(&stub, &l2, parent);
    try testing.expectEqual(@as(u64, 4), second.timestamp);
    try testing.expect(second.parent_hash.eql(parent.block_info.hash));
    try testing.expect(queue.is_last_in_span());
}

test "batch queue: reset one L1 block behind the parent's origin converges" {
    // Regression (DST seed 48): a reset point one L1 block behind the safe head's origin
    // (always the case near genesis) left [reset origin, parent origin] in the epoch list,
    // so every step failed L1OriginMismatch and reset again.
    const config: RollupConfig = .{ .block_time = 2 };
    var l2 = TestChain.init(0, 0, 1);
    var queue = BatchQueue.init(testing.allocator, &config);
    defer queue.deinit();
    const reset_origin: BlockInfo = .{ .number = 5, .hash = .{ .bytes = @splat(5) } };
    const next_origin: BlockInfo = .{
        .number = 6,
        .hash = .{ .bytes = @splat(6) },
        .parent_hash = reset_origin.hash,
    };
    try queue.reset(reset_origin);
    var stub = TestBatches.init(&.{});
    stub.block = reset_origin;
    const parent: L2BlockInfo = .{
        .block_info = .{ .number = 3, .timestamp = 6 },
        .l1_origin = next_origin.id(),
    };
    // Upstream is still behind the parent's origin.
    try testing.expectError(error.Eof, queue.next_batch(&stub, &l2, parent));
    stub.block = next_origin;
    for (0..4) |_| {
        const result = queue.next_batch(&stub, &l2, parent);
        if (result) |_| {} else |err| try testing.expect(err != error.L1OriginMismatch);
        try testing.expect(queue.l1_blocks.items[0].eql(next_origin));
    }
}

//! Tests for the batch stages, ported from base/base
//! `crates/consensus/derive/src/stages/batch/*.rs` with equivalent stubs, plus a seeded
//! fuzz over random batch sequences.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const channel_reader = @import("channel_reader.zig");
const batch_stage = @import("batch_stage.zig");
const TestChain = @import("test_chain.zig").TestChain;
const Prng = @import("../../testing/prng.zig").Prng;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SingleBatch = protocol.batch.SingleBatch;
const SpanBatch = protocol.span_batch.SpanBatch;
const Element = protocol.span_batch.Element;
const Batch = channel_reader.Batch;
const OwnedBatch = channel_reader.OwnedBatch;
const BatchStream = batch_stage.BatchStream;
const BatchQueue = batch_stage.BatchQueue;
const BatchValidator = batch_stage.BatchValidator;
const BatchProvider = batch_stage.BatchProvider;
const Error = errors.Error;

pub const Entry = union(enum) { batch: Batch, err: Error };

/// base/base `TestNextBatchProvider`: hands out entries from the end of the list.
/// Batches are borrowed; each handed-out `OwnedBatch` has an empty arena.
pub const TestBatches = struct {
    entries: [16]Entry = undefined,
    count: usize = 0,
    block: ?BlockInfo = .{},
    flushed: bool = false,

    pub fn init(entries: []const Entry) TestBatches {
        var stub: TestBatches = .{};
        for (entries) |entry| stub.push(entry);
        return stub;
    }

    pub fn push(stub: *TestBatches, entry: Entry) void {
        assert(stub.count < stub.entries.len);
        stub.entries[stub.count] = entry;
        stub.count += 1;
    }

    fn pop(stub: *TestBatches) Error!OwnedBatch {
        if (stub.count == 0) return error.Eof;
        stub.count -= 1;
        return switch (stub.entries[stub.count]) {
            .batch => |batch| .{ .arena = .init(testing.allocator), .batch = batch },
            .err => |err| err,
        };
    }

    pub fn next_batch(stub: *TestBatches, _: L2BlockInfo, _: []const BlockInfo) Error!OwnedBatch {
        return stub.pop();
    }

    pub fn flush(stub: *TestBatches) void {
        stub.flushed = true;
    }

    pub fn span_buffer_size(stub: *const TestBatches) usize {
        return stub.count;
    }

    pub fn origin(stub: *const TestBatches) ?BlockInfo {
        return stub.block;
    }

    /// The stub seen as a channel reader (upstream of the batch stream).
    pub fn reader(stub: *TestBatches) TestReader {
        return .{ .stub = stub };
    }
};

pub const TestReader = struct {
    stub: *TestBatches,

    pub fn next_batch(self: TestReader) Error!OwnedBatch {
        return self.stub.pop();
    }

    pub fn flush(self: TestReader) void {
        self.stub.flush();
    }

    pub fn origin(self: TestReader) ?BlockInfo {
        return self.stub.origin();
    }
};

/// An `l2` provider whose every query fails with a reset-class error.
pub const ResettingL2 = struct {
    pub fn l2_block_info_by_number(_: *ResettingL2, _: u64) errors.ProviderError!L2BlockInfo {
        return error.BlobsUnavailable;
    }

    pub fn l2_block_info_by_hash(_: *ResettingL2, _: Hash) errors.ProviderError!L2BlockInfo {
        return error.BlobsUnavailable;
    }

    pub fn l2_block_by_number(
        _: *ResettingL2,
        _: u64,
    ) errors.ProviderError!protocol.span_batch.SafeBlock {
        return error.BlobsUnavailable;
    }
};

fn repeat(byte: u8) Hash {
    return .init(@splat(byte));
}

fn last_byte(byte: u8) Hash {
    var bytes: [32]u8 = @splat(0);
    bytes[31] = byte;
    return .init(bytes);
}

fn prefix20(hash: Hash) [20]u8 {
    return hash.bytes[0..20].*;
}

fn holocene_config() RollupConfig {
    var config: RollupConfig = .{};
    config.upgrades.set(.holocene, 0);
    return config;
}

fn single(timestamp: u64) Entry {
    return .{ .batch = .{ .single = .{
        .parent_hash = .zero,
        .epoch_num = 0,
        .epoch_hash = .zero,
        .timestamp = timestamp,
        .transactions = &.{},
    } } };
}

fn empty_l2() TestChain {
    return TestChain.init(0, 0, 1);
}

// ---------------------------------------------------------------------------------------
// BatchStream

fn owned_span(elements: []const Element) OwnedBatch {
    return .{ .arena = .init(testing.allocator), .batch = .{ .span = .{ .batches = elements } } };
}

test "batch stream: flush and clear" {
    const config = holocene_config();
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var stub: TestBatches = .{};
    const elements = [_]Element{.{ .timestamp = 2 }};
    stream.span = owned_span(&elements);
    stream.flush(stub.reader());
    try testing.expect(stub.flushed);
    try testing.expect(stream.span == null);
    try testing.expectEqual(@as(usize, 0), stream.span_buffer_size());
    stream.span = owned_span(&elements);
    stream.clear();
    try testing.expect(stream.span == null);
}

test "batch stream: inactive stage passes batches through" {
    var config: RollupConfig = .{};
    config.upgrades.set(.holocene, 100);
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var stub = TestBatches.init(&.{single(0)});
    var l2 = empty_l2();
    try testing.expect(!try stream.is_active(stub.reader()));
    var batch = try stream.next_batch(stub.reader(), &l2, .{}, &.{});
    defer batch.deinit();
    try testing.expect(batch.batch == .single);
    // Pre-Holocene flush is a no-op.
    stream.flush(stub.reader());
    try testing.expect(!stub.flushed);
}

fn expect_single(owned: Error!OwnedBatch, epoch: u64, timestamp: u64) !SingleBatch {
    var batch = try owned;
    defer batch.deinit();
    try testing.expectEqual(epoch, batch.batch.single.epoch_num);
    try testing.expectEqual(timestamp, batch.batch.single.timestamp);
    return batch.batch.single;
}

test "batch stream: span buffer" {
    var config: RollupConfig = .{ .block_time = 2 };
    config.upgrades.set(.delta, 0);
    config.upgrades.set(.holocene, 0);
    const elements = [_]Element{
        .{ .epoch_num = 1, .timestamp = 2 },
        .{ .epoch_num = 1, .timestamp = 4 },
    };
    const span: Entry = .{ .batch = .{ .span = .{ .batches = &elements } } };
    const origins = [_]BlockInfo{.{ .number = 1, .timestamp = 12 }};
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var stub = TestBatches.init(&.{span});
    var l2 = empty_l2();
    try testing.expect(try stream.is_active(stub.reader()));
    const reader = stub.reader();
    _ = try expect_single(stream.next_batch(reader, &l2, .{}, &origins), 1, 2);
    try testing.expectEqual(@as(usize, 1), stream.span_buffer_size());
    const parent: L2BlockInfo = .{ .block_info = .{ .hash = repeat(0x11) } };
    const second = try expect_single(stream.next_batch(reader, &l2, parent, &origins), 1, 4);
    try testing.expect(second.parent_hash.eql(parent.block_info.hash));
    try testing.expectError(error.Eof, stream.next_batch(reader, &l2, .{}, &origins));
    try testing.expectEqual(@as(usize, 0), stream.span_buffer_size());
    try testing.expect(stream.span == null);

    // More data re-hydrates the buffer.
    stub.push(span);
    _ = try expect_single(stream.next_batch(reader, &l2, .{}, &origins), 1, 2);
    _ = try expect_single(stream.next_batch(reader, &l2, .{}, &origins), 1, 4);
    try testing.expectError(error.Eof, stream.next_batch(reader, &l2, .{}, &origins));
}

test "batch stream: crossing span stops before the first denim block" {
    var config: RollupConfig = .{ .block_time = 2 };
    config.upgrades.set(.delta, 0);
    config.upgrades.set(.holocene, 0);
    config.upgrades.set(.denim, 6);
    const elements = [_]Element{
        .{ .epoch_num = 1, .timestamp = 2 }, .{ .epoch_num = 1, .timestamp = 4 },
        .{ .epoch_num = 1, .timestamp = 6 }, .{ .epoch_num = 1, .timestamp = 8 },
    };
    const origins = [_]BlockInfo{.{ .number = 1 }};
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var stub = TestBatches.init(&.{.{ .batch = .{ .span = .{ .batches = &elements } } }});
    var l2 = empty_l2();
    const reader = stub.reader();
    _ = try expect_single(stream.next_batch(reader, &l2, .{}, &origins), 1, 2);
    const second_parent: L2BlockInfo = .{ .block_info = .{ .number = 1, .timestamp = 2 } };
    _ = try expect_single(stream.next_batch(reader, &l2, second_parent, &origins), 1, 4);
    const denim_parent: L2BlockInfo = .{ .block_info = .{ .number = 2, .timestamp = 4 } };
    try testing.expectError(
        error.NotEnoughData,
        stream.next_batch(reader, &l2, denim_parent, &origins),
    );
    try testing.expectEqual(@as(usize, 0), stream.span_buffer_size());
    try testing.expect(stream.span == null);
    try testing.expect(stub.flushed);
}

test "batch stream: span extraction error flushes the stage" {
    const parent_hash = repeat(0x11);
    const l1_hash = repeat(0x33);
    var config: RollupConfig = .{ .seq_window_size = 100, .block_time = 10 };
    config.upgrades.set(.delta, 0);
    config.upgrades.set(.holocene, 0);
    config.genesis.l2 = .{ .number = 40, .hash = parent_hash };
    const l1_block: BlockInfo = .{ .number = 10, .timestamp = 5, .hash = l1_hash };
    const l1_blocks = [_]BlockInfo{l1_block};
    const safe_head: L2BlockInfo = .{
        .block_info = .{ .number = 41, .timestamp = 10, .parent_hash = parent_hash },
        .l1_origin = l1_block.id(),
    };
    var l2 = empty_l2();
    l2.add_l2_block(.{
        .block_info = .{ .number = 40, .hash = parent_hash },
        .l1_origin = .{ .number = 9 },
    });
    l2.add_l2_safe_block(41, .{ .transactions = &.{}, .l1_origin_number = 10 });
    const elements = [_]Element{
        .{ .epoch_num = 9, .timestamp = 10 },
        .{ .epoch_num = 9, .timestamp = 20 },
        .{ .epoch_num = 10, .timestamp = 30 },
    };
    const span: SpanBatch = .{
        .batches = &elements,
        .parent_check = prefix20(parent_hash),
        .l1_origin_check = prefix20(l1_hash),
    };
    var stub = TestBatches.init(&.{.{ .batch = .{ .span = span } }});
    stub.block = l1_block;
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    try testing.expectError(
        error.NotEnoughData,
        stream.next_batch(stub.reader(), &l2, safe_head, &l1_blocks),
    );
    try testing.expect(stream.span == null);
    try testing.expectEqual(@as(usize, 0), stream.span_buffer_size());
    try testing.expect(stub.flushed);
}

test "batch stream: single batch passes through when active" {
    const config = holocene_config();
    var entry = single(0);
    entry.batch.single.parent_hash = repeat(0x11);
    var stub = TestBatches.init(&.{entry});
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var l2 = empty_l2();
    var batch = try stream.next_batch(stub.reader(), &l2, .{}, &.{});
    defer batch.deinit();
    try testing.expect(batch.batch.single.parent_hash.eql(repeat(0x11)));
    try testing.expectEqual(@as(usize, 0), stream.span_buffer_size());
    try testing.expect(stream.span == null);
}

test "batch stream: past span batch" {
    var config = holocene_config();
    config.block_time = 2;
    config.upgrades.set(.delta, 0);
    const elements = [_]Element{
        .{ .epoch_num = 1, .timestamp = 2 },
        .{ .epoch_num = 1, .timestamp = 4 },
    };
    const origins = [_]BlockInfo{.{ .number = 1, .timestamp = 12 }};
    var stub = TestBatches.init(&.{.{ .batch = .{ .span = .{ .batches = &elements } } }});
    var stream = BatchStream.init(testing.allocator, &config);
    defer stream.deinit();
    var l2 = empty_l2();
    const parent: L2BlockInfo = .{ .block_info = .{ .number = 10, .timestamp = 100 } };
    try testing.expectError(
        error.NotEnoughData,
        stream.next_batch(stub.reader(), &l2, parent, &origins),
    );
    try testing.expect(!stub.flushed);
}

test {
    _ = @import("batch_queue_test.zig");
    _ = @import("batch_validator_test.zig");
}

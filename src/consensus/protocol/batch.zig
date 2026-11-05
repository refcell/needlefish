//! Batches: the L2 block inputs carried inside channels, and their validity rules.
//!
//! A channel's decompressed data is a sequence of RLP strings; each string holds
//! `batch_type ++ batch`. Singular batches (type 0) are
//! `rlp([parent_hash, epoch_num, epoch_hash, timestamp, [tx, ...]])`.
//! Mirrors base/base `crates/consensus/protocol/src/batch/{type,single,validity}.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const B256 = primitives.B256;
const block = @import("block.zig");
const BlockId = block.BlockId;
const BlockInfo = block.BlockInfo;
const L2BlockInfo = block.L2BlockInfo;
const RollupConfig = @import("rollup_config.zig").RollupConfig;

pub const BatchType = enum(u8) {
    single = 0,
    span = 1,
};

pub const tx_type_eip7702: u8 = 0x04;
pub const tx_type_eip8130: u8 = 0x79;
pub const tx_type_deposit: u8 = 0x7e;

pub const DropReason = enum {
    future_timestamp_holocene,
    past_timestamp_pre_holocene,
    parent_hash_mismatch,
    included_too_late,
    epoch_too_old,
    epoch_too_far_in_future,
    epoch_hash_mismatch,
    same_second_origin_change,
    timestamp_before_l1_origin,
    sequencer_drift_overflow,
    sequencer_drift_exceeded,
    sequencer_drift_not_adopted_next_origin,
    empty_transaction,
    deposit_transaction,
    eip7702_pre_isthmus,
    eip8130_pre_everest,
    non_empty_transition_block,
    span_batch_pre_delta,
    span_batch_post_denim,
    span_batch_no_new_blocks_pre_holocene,
    span_batch_misaligned_timestamp,
    span_batch_not_overlapped_exactly,
    l1_origin_before_safe_head,
    missing_l1_origin,
    overlapped_tx_count_mismatch,
    overlapped_tx_mismatch,
    l2_block_info_extraction_failed,
    overlapped_l1_origin_mismatch,
};

pub const Validity = union(enum) {
    /// Invalid now and in the future (unless L1 reorgs): discard.
    drop: DropReason,
    accept,
    /// More L1 information is needed to decide.
    undecided,
    /// Possibly valid later: keep and check again.
    future,
    /// Holocene: an old batch; drop it without flushing the channel.
    past,

    pub fn is_accept(validity: Validity) bool {
        return validity == .accept;
    }

    pub fn eql(a: Validity, b: Validity) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return a != .drop or a.drop == b.drop;
    }
};

pub const SingleBatch = struct {
    parent_hash: B256,
    epoch_num: u64,
    epoch_hash: B256,
    timestamp: u64,
    /// Opaque EIP-2718 encoded transactions; each borrows the decoded input.
    transactions: []const []const u8,

    pub fn epoch(batch: *const SingleBatch) BlockId {
        return .{ .number = batch.epoch_num, .hash = batch.epoch_hash };
    }

    fn transactions_length(batch: *const SingleBatch) usize {
        var total: usize = 0;
        for (batch.transactions) |tx| total += rlp.bytes_length(tx);
        return total;
    }

    fn payload_length(batch: *const SingleBatch) usize {
        return 33 + rlp.int_length(batch.epoch_num) + 33 + rlp.int_length(batch.timestamp) +
            rlp.list_length(batch.transactions_length());
    }

    /// Length of `rlp(batch)` (without the batch type byte).
    pub fn encoded_length(batch: *const SingleBatch) usize {
        return rlp.list_length(batch.payload_length());
    }

    pub fn encode(batch: *const SingleBatch, out: []u8) []u8 {
        const length = batch.encoded_length();
        assert(out.len >= length);
        var encoder = rlp.Encoder.init(out[0..length]);
        encoder.list_header(batch.payload_length());
        encoder.bytes(&batch.parent_hash.bytes);
        encoder.int(batch.epoch_num);
        encoder.bytes(&batch.epoch_hash.bytes);
        encoder.int(batch.timestamp);
        encoder.list_header(batch.transactions_length());
        for (batch.transactions) |tx| encoder.bytes(tx);
        assert(encoder.written().len == length);
        return out[0..length];
    }

    pub const DecodeError = rlp.Error || Allocator.Error;

    /// Decodes `rlp(batch)` from the front of `input`. Transactions borrow `input`;
    /// the transaction slice list is allocated and owned by the caller.
    pub fn decode(allocator: Allocator, input: []const u8) DecodeError!SingleBatch {
        var outer = rlp.Decoder.init(input);
        var fields = try outer.list();
        const parent_hash = try fields.fixed(32);
        const epoch_num = try fields.int(u64);
        const epoch_hash = try fields.fixed(32);
        const timestamp = try fields.int(u64);
        var txs = try fields.list();
        try fields.finish();

        // First pass counts, second pass fills: bounded by the payload length.
        var count: usize = 0;
        var counter = txs;
        while (!counter.is_empty()) : (count += 1) _ = try counter.bytes();
        const transactions = try allocator.alloc([]const u8, count);
        errdefer allocator.free(transactions);
        for (transactions) |*tx| tx.* = try txs.bytes();
        assert(txs.is_empty());
        return .{
            .parent_hash = .init(parent_hash),
            .epoch_num = epoch_num,
            .epoch_hash = .init(epoch_hash),
            .timestamp = timestamp,
            .transactions = transactions,
        };
    }

    pub fn deinit(batch: *SingleBatch, allocator: Allocator) void {
        allocator.free(batch.transactions);
        batch.* = undefined;
    }

    /// Holocene-aware timestamp ordering check against the next safe block.
    pub fn check_timestamp(
        batch: *const SingleBatch,
        config: *const RollupConfig,
        safe_head: L2BlockInfo,
        inclusion_block: BlockInfo,
    ) Validity {
        const next_timestamp = config.l2_block_timestamp(safe_head.block_info.number +| 1);
        const inclusion_time = inclusion_block.timestamp;
        const holocene = config.is_feature_active(.strict_derivation_ordering, inclusion_time);
        if (batch.timestamp > next_timestamp) {
            return if (holocene) .{ .drop = .future_timestamp_holocene } else .future;
        }
        if (batch.timestamp < next_timestamp) {
            return if (holocene) .past else .{ .drop = .past_timestamp_pre_holocene };
        }
        return .accept;
    }

    /// Full validity check (base/base `SingleBatch::check_batch`). `l1_blocks[0]` is the
    /// current epoch; later entries are the following L1 blocks known so far.
    pub fn check(
        batch: *const SingleBatch,
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        safe_head: L2BlockInfo,
        inclusion_block: BlockInfo,
    ) Validity {
        if (l1_blocks.len == 0) return .undecided;
        const epoch_block = l1_blocks[0];
        const timestamp_check = batch.check_timestamp(config, safe_head, inclusion_block);
        if (!timestamp_check.is_accept()) return timestamp_check;
        if (!batch.parent_hash.eql(safe_head.block_info.hash)) {
            return .{ .drop = .parent_hash_mismatch };
        }
        const same_second = config.is_feature_active(.subsecond_blocks, batch.timestamp) and
            batch.timestamp == safe_head.block_info.timestamp;
        if (same_second and !batch.epoch().eql(safe_head.l1_origin)) {
            return .{ .drop = .same_second_origin_change };
        }
        if (batch.epoch_num +| config.seq_window_size < inclusion_block.number) {
            return .{ .drop = .included_too_late };
        }
        var batch_origin = epoch_block;
        if (batch.epoch_num < epoch_block.number) return .{ .drop = .epoch_too_old };
        if (batch.epoch_num == epoch_block.number +| 1) {
            if (l1_blocks.len < 2) return .undecided;
            batch_origin = l1_blocks[1];
        } else if (batch.epoch_num != epoch_block.number) {
            return .{ .drop = .epoch_too_far_in_future };
        }
        if (!batch.epoch_hash.eql(batch_origin.hash)) return .{ .drop = .epoch_hash_mismatch };
        if (batch.timestamp < batch_origin.timestamp) {
            return .{ .drop = .timestamp_before_l1_origin };
        }
        const drift_check = batch.check_drift(config, l1_blocks, batch_origin, same_second);
        if (!drift_check.is_accept()) return drift_check;
        if (config.is_feature_first_block(
            .jovian_upgrade_transactions,
            batch.timestamp,
            safe_head.block_info.timestamp,
        ) and batch.transactions.len > 0) {
            return .{ .drop = .non_empty_transition_block };
        }
        return check_transactions(config, batch.timestamp, batch.transactions);
    }

    fn check_drift(
        batch: *const SingleBatch,
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        batch_origin: BlockInfo,
        same_second: bool,
    ) Validity {
        const drift = config.max_sequencer_drift_at(batch_origin.timestamp);
        const max = std.math.add(u64, batch_origin.timestamp, drift) catch {
            return .{ .drop = .sequencer_drift_overflow };
        };
        if (batch.timestamp <= max) return .accept;
        if (batch.transactions.len > 0) return .{ .drop = .sequencer_drift_exceeded };
        // An empty batch may exceed the drift only while the next origin is not yet due.
        if (l1_blocks[0].number == batch_origin.number and !same_second) {
            if (l1_blocks.len < 2) return .undecided;
            if (batch.timestamp >= l1_blocks[1].timestamp) {
                return .{ .drop = .sequencer_drift_not_adopted_next_origin };
            }
        }
        return .accept;
    }
};

/// Per-transaction checks shared by singular and span batches.
pub fn check_transactions(
    config: *const RollupConfig,
    timestamp: u64,
    transactions: []const []const u8,
) Validity {
    const eip7702 = config.is_feature_active(.eip7702, timestamp);
    const eip8130 = config.is_feature_active(.eip8130, timestamp);
    for (transactions) |tx| {
        if (tx.len == 0) return .{ .drop = .empty_transaction };
        if (tx[0] == tx_type_deposit) return .{ .drop = .deposit_transaction };
        if (!eip7702 and tx[0] == tx_type_eip7702) return .{ .drop = .eip7702_pre_isthmus };
        if (!eip8130 and tx[0] == tx_type_eip8130) return .{ .drop = .eip8130_pre_everest };
    }
    return .accept;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn sample_batch(transactions: []const []const u8) SingleBatch {
    return .{
        .parent_hash = .init(@splat(0x11)),
        .epoch_num = 7,
        .epoch_hash = .init(@splat(0x22)),
        .timestamp = 1_000,
        .transactions = transactions,
    };
}

test "single batch: encode/decode roundtrip" {
    const txs = [_][]const u8{ &.{ 0x02, 0xaa, 0xbb }, &.{0x01}, "" };
    const batch = sample_batch(&txs);
    var buffer: [256]u8 = undefined;
    const encoded = batch.encode(&buffer);
    var decoded = try SingleBatch.decode(testing.allocator, encoded);
    defer decoded.deinit(testing.allocator);
    try testing.expect(decoded.parent_hash.eql(batch.parent_hash));
    try testing.expectEqual(batch.epoch_num, decoded.epoch_num);
    try testing.expectEqual(batch.timestamp, decoded.timestamp);
    try testing.expectEqual(@as(usize, 3), decoded.transactions.len);
    for (txs, decoded.transactions) |a, b| try testing.expectEqualSlices(u8, a, b);
    // Trailing fields inside the batch list are rejected.
    const truncated = SingleBatch.decode(testing.allocator, encoded[1..]);
    try testing.expectError(error.ExpectedList, truncated);
}

const Fixture = struct {
    config: RollupConfig,
    l1: [2]BlockInfo,
    safe_head: L2BlockInfo,

    fn init() Fixture {
        var fixture: Fixture = .{
            .config = .{ .block_time = 2, .seq_window_size = 100, .max_sequencer_drift = 600 },
            .l1 = .{
                .{ .number = 7, .hash = .init(@splat(0x22)), .timestamp = 990 },
                .{ .number = 8, .hash = .init(@splat(0x33)), .timestamp = 1_002 },
            },
            .safe_head = .{
                .block_info = .{ .number = 9, .hash = .init(@splat(0x11)), .timestamp = 998 },
                .l1_origin = .{ .number = 7, .hash = .init(@splat(0x22)) },
            },
        };
        fixture.config.genesis.l2_time = 980;
        return fixture;
    }

    fn check(fixture: *const Fixture, batch: SingleBatch, inclusion: BlockInfo) Validity {
        return batch.check(&fixture.config, &fixture.l1, fixture.safe_head, inclusion);
    }
};

fn expect_drop(
    fixture: *const Fixture,
    batch: SingleBatch,
    inclusion: BlockInfo,
    reason: DropReason,
) !void {
    const validity = fixture.check(batch, inclusion);
    try testing.expect(validity.eql(.{ .drop = reason }));
}

test "single batch: validity rules" {
    const fixture = Fixture.init();
    const inclusion: BlockInfo = .{ .number = 20, .timestamp = 1_100 };
    var batch = sample_batch(&.{&.{ 0x02, 0x01 }});
    try testing.expect(fixture.check(batch, inclusion).eql(.accept));
    const no_l1 = batch.check(&fixture.config, &.{}, fixture.safe_head, inclusion);
    try testing.expect(no_l1.eql(.undecided));

    batch.timestamp = 1_002;
    try testing.expect(fixture.check(batch, inclusion).eql(.future));
    batch.timestamp = 998;
    try expect_drop(&fixture, batch, inclusion, .past_timestamp_pre_holocene);
    batch.timestamp = 1_000;
    batch.parent_hash = .zero;
    try expect_drop(&fixture, batch, inclusion, .parent_hash_mismatch);
    batch.parent_hash = fixture.safe_head.block_info.hash;
    try expect_drop(&fixture, batch, .{ .number = 108 }, .included_too_late);
    batch.epoch_num = 6;
    try expect_drop(&fixture, batch, inclusion, .epoch_too_old);
    batch.epoch_num = 9;
    try expect_drop(&fixture, batch, inclusion, .epoch_too_far_in_future);
    batch.epoch_num = 8;
    try expect_drop(&fixture, batch, inclusion, .epoch_hash_mismatch);
    batch.epoch_hash = fixture.l1[1].hash;
    try expect_drop(&fixture, batch, inclusion, .timestamp_before_l1_origin);
    batch.epoch_num = 7;
    batch.epoch_hash = fixture.l1[0].hash;
    const deposit = [_][]const u8{&.{ 0x7e, 0x00 }};
    batch.transactions = &deposit;
    try expect_drop(&fixture, batch, inclusion, .deposit_transaction);
    const empty = [_][]const u8{""};
    batch.transactions = &empty;
    try expect_drop(&fixture, batch, inclusion, .empty_transaction);
    const set_code = [_][]const u8{&.{ 0x04, 0x00 }};
    batch.transactions = &set_code;
    try expect_drop(&fixture, batch, inclusion, .eip7702_pre_isthmus);
}

test "single batch: holocene ordering and drift" {
    var fixture = Fixture.init();
    fixture.config.upgrades.set(.holocene, 0);
    const inclusion: BlockInfo = .{ .number = 20, .timestamp = 1_100 };
    var batch = sample_batch(&.{});
    batch.timestamp = 1_002;
    try expect_drop(&fixture, batch, inclusion, .future_timestamp_holocene);
    batch.timestamp = 998;
    try testing.expect(fixture.check(batch, inclusion).eql(.past));

    // Holocene implies Fjord: drift is 1800, so origin 990 allows up to 2790.
    fixture.safe_head.block_info.timestamp = 2_798;
    fixture.safe_head.block_info.number = 909;
    batch.timestamp = 2_800;
    try expect_drop(&fixture, batch, inclusion, .sequencer_drift_not_adopted_next_origin);
    fixture.l1[1].timestamp = 2_900;
    try testing.expect(fixture.check(batch, inclusion).eql(.accept));
    const txs = [_][]const u8{&.{ 0x02, 0x00 }};
    batch.transactions = &txs;
    try expect_drop(&fixture, batch, inclusion, .sequencer_drift_exceeded);
}

fn check_decode(input: []const u8) !void {
    var batch = SingleBatch.decode(testing.allocator, input) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    defer batch.deinit(testing.allocator);
    var buffer: [4096]u8 = undefined;
    const encoded = batch.encode(&buffer);
    // Canonical decoding means re-encoding reproduces the consumed prefix.
    try testing.expectEqualSlices(u8, input[0..encoded.len], encoded);
}

test "single batch: seeded fuzz decode" {
    var prng = Prng.init(0x53494e47);
    var tx_storage: [8][64]u8 = undefined;
    var txs: [8][]const u8 = undefined;
    var buffer: [2048]u8 = undefined;
    for (0..3_000) |_| {
        const count = prng.below(txs.len + 1);
        for (0..count) |i| {
            const length = prng.below(64);
            prng.fill(tx_storage[i][0..length]);
            txs[i] = tx_storage[i][0..length];
        }
        var batch = sample_batch(txs[0..count]);
        batch.epoch_num = prng.int(u64);
        batch.timestamp = prng.int(u64);
        const encoded = batch.encode(&buffer);
        if (prng.chance(1, 2)) encoded[prng.below(encoded.len)] = prng.int(u8);
        try check_decode(encoded[0..prng.range(encoded.len / 2, encoded.len)]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "single batch: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

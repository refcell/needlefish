//! Span batches (batch type 1): many L2 blocks in one columnar, compressible batch.
//! This file holds the derived form (`SpanBatch` of per-block `Element`s), its
//! conversion to and from singular batches and the raw wire form, and the validity
//! rules `check_batch_prefix` / `check_batch`. Mirrors base/base
//! `crates/consensus/protocol/src/batch/{span,element}.rs` and the OP Stack span
//! batch spec.
//!
//! The wire codec lives in `span_batch_raw.zig` (prefix/payload), the transaction
//! columns in `span_batch_transactions.zig`, per-type tx data in
//! `span_batch_tx_data.zig`, and bitlists/varints in `span_batch_bits.zig`.
//!
//! Span batches are dropped once Denim (`singular_batches_only`) is active for the
//! next block, so element timestamps are whole seconds: `genesis_time +
//! rel_timestamp + block_time * i`, with no sub-second handling.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const batch_module = @import("batch.zig");
const block = @import("block.zig");
const RollupConfig = @import("rollup_config.zig").RollupConfig;
pub const bits = @import("span_batch_bits.zig");
pub const tx_data = @import("span_batch_tx_data.zig");
pub const transactions = @import("span_batch_transactions.zig");
pub const raw = @import("span_batch_raw.zig");

const B256 = primitives.B256;
const BlockInfo = block.BlockInfo;
const L2BlockInfo = block.L2BlockInfo;
const SingleBatch = batch_module.SingleBatch;
const Validity = batch_module.Validity;
pub const Error = bits.Error;
pub const Bits = bits.Bits;
pub const Prefix = raw.Prefix;
pub const Payload = raw.Payload;
pub const RawSpanBatch = raw.RawSpanBatch;
pub const Transactions = transactions.Transactions;
pub const TxData = tx_data.TxData;
pub const max_span_batch_elements = bits.max_span_batch_elements;

/// One L2 block of a span: a singular batch without parent and epoch hashes.
pub const Element = struct {
    epoch_num: u64 = 0,
    timestamp: u64 = 0,
    /// Full signed EIP-2718 transactions (borrowed).
    transactions: []const []const u8 = &.{},

    pub fn from_single_batch(single: *const SingleBatch) Element {
        return .{
            .epoch_num = single.epoch_num,
            .timestamp = single.timestamp,
            .transactions = single.transactions,
        };
    }
};

/// A safe L2 block as seen by the overlap check.
pub const SafeBlock = struct {
    /// EIP-2718 encoded transactions in block order, deposits first.
    transactions: []const []const u8,
    /// L1 origin number from the block's L1 info deposit, applying the genesis rule of
    /// base/base `L2BlockInfo::from_block_and_genesis`; null when extraction failed.
    l1_origin_number: ?u64,
};

/// Access to the local safe chain (base/base `BatchValidationProvider`). A null
/// result means the block could not be fetched now: the batch is undecided.
pub const SafeChain = struct {
    context: *anyopaque,
    l2_block_info_by_number: *const fn (context: *anyopaque, number: u64) ?L2BlockInfo,
    block_by_number: *const fn (context: *anyopaque, number: u64) ?SafeBlock,
};

pub const PrefixCheck = struct {
    validity: Validity,
    /// The span's parent block; set exactly when `validity` is accept.
    parent: ?L2BlockInfo = null,

    fn of(validity: Validity) PrefixCheck {
        assert(validity != .accept);
        return .{ .validity = validity };
    }
};

fn drop(reason: batch_module.DropReason) Validity {
    return .{ .drop = reason };
}

/// `b == a + 1` without overflow.
fn is_successor(a: u64, b: u64) bool {
    return a != std.math.maxInt(u64) and b == a + 1;
}

pub const SpanBatch = struct {
    /// First 20 bytes of the first block's parent hash.
    parent_check: [20]u8 = @splat(0),
    /// First 20 bytes of the last block's L1 origin hash.
    l1_origin_check: [20]u8 = @splat(0),
    genesis_timestamp: u64 = 0,
    chain_id: u64 = 0,
    batches: []const Element = &.{},
    /// Bit `i` set: block `i` advanced the L1 origin (bit 0: first block of an epoch).
    origin_bits: Bits = .empty,

    pub fn starting_timestamp(span: *const SpanBatch) u64 {
        assert(span.batches.len > 0);
        return span.batches[0].timestamp;
    }

    pub fn final_timestamp(span: *const SpanBatch) u64 {
        assert(span.batches.len > 0);
        return span.batches[span.batches.len - 1].timestamp;
    }

    pub fn starting_epoch_num(span: *const SpanBatch) u64 {
        assert(span.batches.len > 0);
        return span.batches[0].epoch_num;
    }

    pub fn check_origin_hash(span: *const SpanBatch, hash: B256) bool {
        return std.mem.eql(u8, &span.l1_origin_check, hash.bytes[0..20]);
    }

    pub fn check_parent_hash(span: *const SpanBatch, hash: B256) bool {
        return std.mem.eql(u8, &span.parent_check, hash.bytes[0..20]);
    }

    /// Builds a span from consecutive singular batches, as repeated base/base
    /// `append_singular_batch` calls do. `first_seq_num` is the sequence number of
    /// the first block within its epoch. Batches must be ordered by timestamp.
    pub fn from_singular_batches(
        arena: Allocator,
        singles: []const SingleBatch,
        first_seq_num: u64,
        genesis_timestamp: u64,
        chain_id: u64,
    ) Error!SpanBatch {
        if (singles.len == 0) return error.EmptySpanBatch;
        if (singles.len > max_span_batch_elements) return error.TooBigSpanBatchSize;
        const elements = try arena.alloc(Element, singles.len);
        const origin_bits = try arena.alloc(u8, bits.bits_buffer_length(singles.len));
        @memset(origin_bits, 0);
        for (singles, elements, 0..) |*single, *element, i| {
            element.* = .from_single_batch(single);
            const advanced = if (i == 0)
                first_seq_num == 0
            else
                singles[i - 1].epoch_num < single.epoch_num;
            if (i > 0) assert(singles[i - 1].timestamp <= single.timestamp);
            Bits.set_bit(origin_bits, i, advanced);
        }
        return .{
            .parent_check = singles[0].parent_hash.bytes[0..20].*,
            .l1_origin_check = singles[singles.len - 1].epoch_hash.bytes[0..20].*,
            .genesis_timestamp = genesis_timestamp,
            .chain_id = chain_id,
            .batches = elements,
            .origin_bits = .{ .bytes = origin_bits },
        };
    }

    /// Splits the transactions back into columns (the batcher's encode path).
    pub fn to_raw(span: *const SpanBatch, arena: Allocator) Error!RawSpanBatch {
        if (span.batches.len == 0) return error.EmptySpanBatch;
        if (span.batches.len > max_span_batch_elements) return error.TooBigSpanBatchSize;
        const counts = try arena.alloc(u64, span.batches.len);
        var total: usize = 0;
        for (span.batches, counts) |element, *count| {
            count.* = element.transactions.len;
            total += element.transactions.len;
        }
        const all = try arena.alloc([]const u8, total);
        var index: usize = 0;
        for (span.batches) |element| {
            @memcpy(all[index..][0..element.transactions.len], element.transactions);
            index += element.transactions.len;
        }
        assert(index == total);
        const first = span.batches[0];
        const rel_timestamp = std.math.sub(u64, first.timestamp, span.genesis_timestamp) catch
            return error.ArithmeticOverflow;
        return .{
            .prefix = .{
                .rel_timestamp = rel_timestamp,
                .l1_origin_num = span.batches[span.batches.len - 1].epoch_num,
                .parent_check = span.parent_check,
                .l1_origin_check = span.l1_origin_check,
            },
            .payload = .{
                .block_count = span.batches.len,
                .origin_bits = span.origin_bits,
                .block_tx_counts = counts,
                .txs = try Transactions.build(arena, all, span.chain_id),
            },
        };
    }

    /// The singular batches after the safe head (base/base `get_singular_batches`).
    /// Parent hashes are left zero, as in base/base.
    pub fn get_singular_batches(
        span: *const SpanBatch,
        arena: Allocator,
        l1_origins: []const BlockInfo,
        safe_head: L2BlockInfo,
    ) Error![]SingleBatch {
        const singles = try arena.alloc(SingleBatch, span.batches.len);
        var count: usize = 0;
        var origin_index: usize = 0;
        for (span.batches) |element| {
            if (element.timestamp <= safe_head.block_info.timestamp) continue;
            if (element.epoch_num < safe_head.l1_origin.number) {
                return error.L1OriginBeforeSafeHead;
            }
            const offset = find_origin(l1_origins[origin_index..], element.epoch_num) orelse
                return error.MissingL1Origin;
            origin_index += offset;
            singles[count] = .{
                .parent_hash = .zero,
                .epoch_num = element.epoch_num,
                .epoch_hash = l1_origins[origin_index].hash,
                .timestamp = element.timestamp,
                .transactions = element.transactions,
            };
            count += 1;
        }
        assert(count <= span.batches.len);
        return singles[0..count];
    }

    fn find_origin(l1_blocks: []const BlockInfo, number: u64) ?usize {
        for (l1_blocks, 0..) |l1_block, i| {
            if (l1_block.number == number) return i;
        }
        return null;
    }

    /// Prefix checks shared by the batch queue and the full check (base/base
    /// `check_batch_prefix`). On accept, returns the span's parent block.
    pub fn check_batch_prefix(
        span: *const SpanBatch,
        config: *const RollupConfig,
        l1_origins: []const BlockInfo,
        safe_head: L2BlockInfo,
        inclusion_block: BlockInfo,
        chain: SafeChain,
    ) PrefixCheck {
        assert(config.block_time > 0);
        if (l1_origins.len == 0) return .of(.undecided);
        if (span.batches.len == 0) return .of(.undecided);
        const next = safe_head.block_info.number +| 1;
        const next_timestamp = config.l2_block_timestamp(next);
        if (config.is_feature_active(.singular_batches_only, next_timestamp)) {
            return .of(drop(.span_batch_post_denim));
        }
        const starting_epoch = span.starting_epoch_num();
        var batch_origin = l1_origins[0];
        if (is_successor(batch_origin.number, starting_epoch)) {
            if (l1_origins.len < 2) return .of(.undecided);
            batch_origin = l1_origins[1];
        }
        if (!config.is_feature_active(.span_batches, batch_origin.timestamp)) {
            return .of(drop(.span_batch_pre_delta));
        }
        const holocene =
            config.is_feature_active(.strict_derivation_ordering, inclusion_block.timestamp);
        if (span.starting_timestamp() > next_timestamp) {
            return .of(if (holocene) drop(.future_timestamp_holocene) else .future);
        }
        if (span.final_timestamp() < next_timestamp) {
            return .of(if (holocene) .past else drop(.span_batch_no_new_blocks_pre_holocene));
        }
        const parent = switch (span.find_parent(config, safe_head, next_timestamp, chain)) {
            .parent => |parent| parent,
            .validity => |validity| return .of(validity),
        };
        const validity = span.check_parent_and_epochs(config, l1_origins, parent, inclusion_block);
        if (!validity.is_accept()) return .of(validity);
        return .{ .validity = .accept, .parent = parent };
    }

    const ParentLookup = union(enum) { parent: L2BlockInfo, validity: Validity };

    /// The safe head, or for an overlapping span the safe block before its start.
    fn find_parent(
        span: *const SpanBatch,
        config: *const RollupConfig,
        safe_head: L2BlockInfo,
        next_timestamp: u64,
        chain: SafeChain,
    ) ParentLookup {
        const start = span.starting_timestamp();
        if (start >= next_timestamp) return .{ .parent = safe_head };
        const safe_timestamp = safe_head.block_info.timestamp;
        if (start > safe_timestamp) return .{ .validity = drop(.span_batch_misaligned_timestamp) };
        const distance = safe_timestamp - start;
        if (distance % config.block_time != 0) {
            return .{ .validity = drop(.span_batch_not_overlapped_exactly) };
        }
        // base/base wraps on underflow and then fails the fetch: undecided.
        const blocks_back = distance / config.block_time + 1;
        const parent_number = std.math.sub(u64, safe_head.block_info.number, blocks_back) catch
            return .{ .validity = .undecided };
        const parent = chain.l2_block_info_by_number(chain.context, parent_number) orelse
            return .{ .validity = .undecided };
        return .{ .parent = parent };
    }

    fn check_parent_and_epochs(
        span: *const SpanBatch,
        config: *const RollupConfig,
        l1_origins: []const BlockInfo,
        parent: L2BlockInfo,
        inclusion_block: BlockInfo,
    ) Validity {
        assert(span.batches.len > 0);
        assert(l1_origins.len > 0);
        if (!span.check_parent_hash(parent.block_info.hash)) return drop(.parent_hash_mismatch);
        const starting_epoch = span.starting_epoch_num();
        if (starting_epoch +| config.seq_window_size < inclusion_block.number) {
            return drop(.included_too_late);
        }
        if (starting_epoch > parent.l1_origin.number +| 1) return drop(.epoch_too_far_in_future);
        const end_epoch = span.batches[span.batches.len - 1].epoch_num;
        // l1_origins is bounded by the sequencing window in the batch queue.
        const end_index = find_origin(l1_origins, end_epoch) orelse return .undecided;
        if (!span.check_origin_hash(l1_origins[end_index].hash)) {
            return drop(.epoch_hash_mismatch);
        }
        if (starting_epoch < parent.l1_origin.number) return drop(.epoch_too_old);
        return .accept;
    }

    /// Full validity check (base/base `SpanBatch::check_batch`).
    pub fn check_batch(
        span: *const SpanBatch,
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        safe_head: L2BlockInfo,
        inclusion_block: BlockInfo,
        chain: SafeChain,
    ) Validity {
        const prefix =
            span.check_batch_prefix(config, l1_blocks, safe_head, inclusion_block, chain);
        if (!prefix.validity.is_accept()) return prefix.validity;
        const parent = prefix.parent.?;
        const elements = span.check_elements(config, l1_blocks, safe_head, parent);
        if (!elements.is_accept()) return elements;
        return span.check_overlap(config, safe_head, parent, chain);
    }

    fn check_elements(
        span: *const SpanBatch,
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        safe_head: L2BlockInfo,
        parent: L2BlockInfo,
    ) Validity {
        assert(span.batches.len > 0);
        var origin_index: usize = 0;
        var origin_advanced = is_successor(parent.l1_origin.number, span.starting_epoch_num());
        for (span.batches, 0..) |element, i| {
            if (element.timestamp <= safe_head.block_info.timestamp) continue;
            if (element.epoch_num < safe_head.l1_origin.number) {
                return drop(.l1_origin_before_safe_head);
            }
            const offset = find_origin(l1_blocks[origin_index..], element.epoch_num) orelse
                return drop(.missing_l1_origin);
            origin_index += offset;
            const l1_origin = l1_blocks[origin_index];
            if (i > 0) origin_advanced = element.epoch_num > span.batches[i - 1].epoch_num;
            if (element.timestamp < l1_origin.timestamp) return drop(.timestamp_before_l1_origin);
            const drift = check_drift(config, l1_blocks, origin_index, element, origin_advanced);
            if (!drift.is_accept()) return drift;
            const txs = batch_module.check_transactions(
                config,
                element.timestamp,
                element.transactions,
            );
            if (!txs.is_accept()) return txs;
        }
        assert(origin_index < l1_blocks.len);
        return .accept;
    }

    fn check_drift(
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        origin_index: usize,
        element: Element,
        origin_advanced: bool,
    ) Validity {
        assert(origin_index < l1_blocks.len);
        const l1_origin = l1_blocks[origin_index];
        const max_drift = config.max_sequencer_drift_at(l1_origin.timestamp);
        if (element.timestamp <= l1_origin.timestamp +| max_drift) return .accept;
        if (element.transactions.len > 0) return drop(.sequencer_drift_exceeded);
        // An empty batch past the drift keeps L2 time >= L1 time; it is only invalid
        // when it stayed on its origin although the next one was already adoptable.
        if (origin_advanced) return .accept;
        if (origin_index + 1 >= l1_blocks.len) return .undecided;
        if (element.timestamp >= l1_blocks[origin_index + 1].timestamp) {
            return drop(.sequencer_drift_not_adopted_next_origin);
        }
        return .accept;
    }

    /// Blocks the span shares with the safe chain must match it exactly.
    fn check_overlap(
        span: *const SpanBatch,
        config: *const RollupConfig,
        safe_head: L2BlockInfo,
        parent: L2BlockInfo,
        chain: SafeChain,
    ) Validity {
        const next_timestamp = config.l2_block_timestamp(safe_head.block_info.number +| 1);
        if (span.starting_timestamp() >= next_timestamp) return .accept;
        const parent_number = parent.block_info.number;
        const overlap = safe_head.block_info.number -| parent_number;
        var i: u64 = 0;
        while (i < overlap) : (i += 1) {
            const safe_block = chain.block_by_number(chain.context, parent_number + i + 1) orelse
                return .undecided;
            // Unreachable for derived spans (timestamps are block-time aligned); base/base
            // would panic on the index.
            if (i >= span.batches.len) return drop(.span_batch_not_overlapped_exactly);
            const element = span.batches[@intCast(i)];
            const validity = check_overlapped_block(safe_block, element);
            if (!validity.is_accept()) return validity;
        }
        assert(i == overlap);
        return .accept;
    }

    fn check_overlapped_block(safe_block: SafeBlock, element: Element) Validity {
        var deposit_count: usize = 0;
        for (safe_block.transactions) |tx| {
            deposit_count += @intFromBool(tx.len > 0 and tx[0] == batch_module.tx_type_deposit);
        }
        assert(deposit_count <= safe_block.transactions.len);
        const batch_txs = element.transactions;
        if (safe_block.transactions.len - deposit_count != batch_txs.len) {
            return drop(.overlapped_tx_count_mismatch);
        }
        for (batch_txs, 0..) |tx, j| {
            const safe_tx = safe_block.transactions[j + deposit_count];
            if (!std.mem.eql(u8, safe_tx, tx)) return drop(.overlapped_tx_mismatch);
        }
        const l1_origin_number = safe_block.l1_origin_number orelse
            return drop(.l2_block_info_extraction_failed);
        if (l1_origin_number != element.epoch_num) return drop(.overlapped_l1_origin_mismatch);
        return .accept;
    }

    /// Encodes via the raw form (`to_raw` then `RawSpanBatch.encode_alloc`).
    pub fn encode_alloc(span: *const SpanBatch, arena: Allocator) Error![]u8 {
        const raw_batch = try span.to_raw(arena);
        const encoded = try raw_batch.encode_alloc(arena);
        assert(encoded.len >= 42);
        return encoded;
    }
};

test {
    _ = @import("span_batch_test.zig");
    std.testing.refAllDecls(@This());
}

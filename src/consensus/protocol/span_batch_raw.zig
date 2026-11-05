//! Raw span batch wire format: prefix (relative timestamp, L1 origin number, parent
//! check, L1 origin check) and payload (block count, origin bits, per-block tx counts,
//! transaction columns), plus `derive` into a `SpanBatch` of per-block elements.
//! Mirrors base/base `crates/consensus/protocol/src/batch/{raw,prefix,payload}.rs`.
//!
//! Memory: decoding and deriving allocate from a caller-supplied arena that is freed
//! as a whole; see `span_batch_transactions.zig` for the input-size bounds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const bits_module = @import("span_batch_bits.zig");
const transactions_module = @import("span_batch_transactions.zig");
const span_batch = @import("span_batch.zig");
const Bits = bits_module.Bits;
const Writer = bits_module.Writer;
const Error = bits_module.Error;
const Transactions = transactions_module.Transactions;
const max_span_batch_elements = bits_module.max_span_batch_elements;
const read_uvarint = bits_module.read_uvarint;

pub const Prefix = struct {
    /// Timestamp of the first block, relative to L2 genesis.
    rel_timestamp: u64 = 0,
    /// L1 origin number of the last block.
    l1_origin_num: u64 = 0,
    /// First 20 bytes of the first block's parent hash.
    parent_check: [20]u8 = @splat(0),
    /// First 20 bytes of the last block's L1 origin hash.
    l1_origin_check: [20]u8 = @splat(0),

    pub fn decode(r: *[]const u8) Error!Prefix {
        var prefix: Prefix = .{};
        prefix.rel_timestamp = read_uvarint(r) orelse return error.RelativeTimestamp;
        prefix.l1_origin_num = read_uvarint(r) orelse return error.L1OriginNumber;
        if (r.len < 20) return error.ParentCheck;
        prefix.parent_check = r.*[0..20].*;
        r.* = r.*[20..];
        if (r.len < 20) return error.L1OriginCheck;
        prefix.l1_origin_check = r.*[0..20].*;
        r.* = r.*[20..];
        return prefix;
    }

    pub fn encode(prefix: *const Prefix, writer: *Writer) void {
        const start = writer.position;
        writer.put_uvarint(prefix.rel_timestamp);
        writer.put_uvarint(prefix.l1_origin_num);
        writer.put(&prefix.parent_check);
        writer.put(&prefix.l1_origin_check);
        assert(writer.position - start >= 42);
    }
};

pub const Payload = struct {
    block_count: u64 = 0,
    /// Bit `i` set: block `i` advanced the L1 origin.
    origin_bits: Bits = .empty,
    block_tx_counts: []const u64 = &.{},
    txs: Transactions = .{},

    pub fn decode(arena: Allocator, r: *[]const u8) Error!Payload {
        var payload: Payload = .{};
        const block_count = read_uvarint(r) orelse return error.BlockCount;
        if (block_count > max_span_batch_elements) return error.TooBigSpanBatchSize;
        if (block_count == 0) return error.EmptySpanBatch;
        payload.block_count = block_count;
        payload.origin_bits = try Bits.decode(arena, r, block_count);
        payload.block_tx_counts = try decode_block_tx_counts(arena, r, block_count);
        const total = try total_tx_count(payload.block_tx_counts);
        payload.txs = try Transactions.decode(arena, r, total);
        assert(payload.block_tx_counts.len == block_count);
        return payload;
    }

    fn decode_block_tx_counts(arena: Allocator, r: *[]const u8, block_count: u64) Error![]u64 {
        // Each varint takes at least one byte, so a short input fails before the bound.
        const capacity: usize = @intCast(@min(block_count, r.len));
        const counts = try arena.alloc(u64, capacity);
        for (0..block_count) |i| {
            const count = read_uvarint(r) orelse return error.BlockTxCounts;
            if (count > max_span_batch_elements) return error.TooBigSpanBatchSize;
            assert(i < capacity);
            counts[i] = count;
        }
        assert(counts.len == block_count);
        return counts;
    }

    pub fn encode(payload: *const Payload, writer: *Writer) Error!void {
        assert(payload.block_tx_counts.len == payload.block_count);
        writer.put_uvarint(payload.block_count);
        try payload.origin_bits.encode(writer, payload.block_count);
        for (payload.block_tx_counts) |count| writer.put_uvarint(count);
        try payload.txs.encode(writer);
    }
};

/// Sum of per-block transaction counts, bounded by `max_span_batch_elements`.
pub fn total_tx_count(block_tx_counts: []const u64) Error!u64 {
    if (block_tx_counts.len == 0) return error.EmptySpanBatch;
    var total: u64 = 0;
    for (block_tx_counts) |count| {
        total = std.math.add(u64, total, count) catch return error.TooBigSpanBatchSize;
    }
    if (total > max_span_batch_elements) return error.TooBigSpanBatchSize;
    assert(total <= max_span_batch_elements);
    return total;
}

pub const RawSpanBatch = struct {
    prefix: Prefix,
    payload: Payload,

    /// Decodes a raw span batch (without the batch type byte) from the front of `r`.
    pub fn decode(arena: Allocator, r: *[]const u8) Error!RawSpanBatch {
        const prefix = try Prefix.decode(r);
        const payload = try Payload.decode(arena, r);
        assert(payload.block_count > 0);
        return .{ .prefix = prefix, .payload = payload };
    }

    pub fn encoded_length(raw: *const RawSpanBatch) Error!usize {
        var writer = Writer.counting();
        raw.prefix.encode(&writer);
        try raw.payload.encode(&writer);
        assert(writer.position > 0);
        return writer.position;
    }

    /// Encodes into `out`, which must hold `encoded_length()` bytes.
    pub fn encode(raw: *const RawSpanBatch, out: []u8) Error![]u8 {
        const length = try raw.encoded_length();
        assert(out.len >= length);
        var writer = Writer.init(out[0..length]);
        raw.prefix.encode(&writer);
        try raw.payload.encode(&writer);
        assert(writer.position == length);
        return writer.written();
    }

    pub fn encode_alloc(raw: *const RawSpanBatch, allocator: Allocator) Error![]u8 {
        const buffer = try allocator.alloc(u8, try raw.encoded_length());
        const encoded = try raw.encode(buffer);
        assert(encoded.len == buffer.len);
        return encoded;
    }

    /// Expands into per-block elements (base/base `RawSpanBatch::derive`). Transactions
    /// are rebuilt as full signed EIP-2718 bytes in `arena`.
    pub fn derive(
        raw: *const RawSpanBatch,
        arena: Allocator,
        block_time: u64,
        genesis_time: u64,
        chain_id: u64,
    ) Error!span_batch.SpanBatch {
        const block_count: usize = @intCast(raw.payload.block_count);
        if (block_count == 0) return error.EmptySpanBatch;
        assert(raw.payload.block_tx_counts.len == block_count);
        const origin_nums = try raw.block_origin_nums(arena);
        const txs = try raw.payload.txs.full_txs(arena, chain_id);
        const elements = try arena.alloc(span_batch.Element, block_count);
        const first_timestamp = std.math.add(u64, genesis_time, raw.prefix.rel_timestamp) catch
            return error.ArithmeticOverflow;
        var tx_index: usize = 0;
        for (elements, 0..) |*element, i| {
            const count: usize = @intCast(raw.payload.block_tx_counts[i]);
            const offset = std.math.mul(u64, block_time, i) catch return error.ArithmeticOverflow;
            element.* = .{
                .epoch_num = origin_nums[i],
                .timestamp = std.math.add(u64, first_timestamp, offset) catch
                    return error.ArithmeticOverflow,
                .transactions = txs[tx_index..][0..count],
            };
            tx_index += count;
        }
        assert(tx_index == txs.len);
        return .{
            .parent_check = raw.prefix.parent_check,
            .l1_origin_check = raw.prefix.l1_origin_check,
            .genesis_timestamp = genesis_time,
            .chain_id = chain_id,
            .batches = elements,
            .origin_bits = raw.payload.origin_bits,
        };
    }

    /// Epoch number per block, counting back from the last block's L1 origin.
    fn block_origin_nums(raw: *const RawSpanBatch, arena: Allocator) Error![]u64 {
        const block_count: usize = @intCast(raw.payload.block_count);
        const origin_nums = try arena.alloc(u64, block_count);
        var origin = raw.prefix.l1_origin_num;
        var index = block_count;
        while (index > 0) {
            index -= 1;
            origin_nums[index] = origin;
            const bit = raw.payload.origin_bits.get_bit(index) orelse return error.L1OriginCheck;
            if (bit == 1 and index > 0) {
                origin = std.math.sub(u64, origin, 1) catch return error.ArithmeticOverflow;
            }
        }
        assert(origin_nums[block_count - 1] == raw.prefix.l1_origin_num);
        return origin_nums;
    }
};

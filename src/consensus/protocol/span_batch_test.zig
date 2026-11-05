//! Span batch tests: ports of base/base span batch unit tests (codec, transactions,
//! derivation, validity scenarios), the public `raw_batch` vector, and seeded plus
//! coverage-guided fuzzing of decode/encode.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const batch_module = @import("batch.zig");
const block = @import("block.zig");
const RollupConfig = @import("rollup_config.zig").RollupConfig;
const span_batch = @import("span_batch.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const Signature = consensus.Signature;
const BlockInfo = block.BlockInfo;
const L2BlockInfo = block.L2BlockInfo;
const SingleBatch = batch_module.SingleBatch;
const Validity = batch_module.Validity;
const DropReason = batch_module.DropReason;
const SpanBatch = span_batch.SpanBatch;
const Element = span_batch.Element;
const RawSpanBatch = span_batch.RawSpanBatch;
const Transactions = span_batch.Transactions;
const Bits = span_batch.Bits;
const Writer = span_batch.bits.Writer;

const raw_batch_vector = @embedFile("testdata/raw_batch.bin");

/// alloy `Signature::test_signature()`.
const test_signature: Signature = .{
    .y_parity = false,
    .r = 0x840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565,
    .s = 0x25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1,
};

fn encode_envelope(arena: Allocator, envelope: Envelope) ![]const u8 {
    const buffer = try arena.alloc(u8, envelope.encoded_length());
    return envelope.encode_to(buffer);
}

fn encode_raw(arena: Allocator, raw: *const RawSpanBatch) ![]u8 {
    return raw.encode_alloc(arena);
}

test "span batch: raw_batch vector decode/encode roundtrip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var input: []const u8 = raw_batch_vector;
    const raw = try RawSpanBatch.decode(arena, &input);
    try testing.expectEqual(@as(usize, 0), input.len);
    const encoded = try encode_raw(arena, &raw);
    try testing.expectEqualSlices(u8, raw_batch_vector, encoded);
    // Deriving rebuilds every transaction as a decodable signed envelope.
    const span = try raw.derive(arena, 2, 1_000, 901);
    try testing.expectEqual(raw.payload.block_count, span.batches.len);
    for (span.batches, 0..) |element, i| {
        try testing.expectEqual(1_000 + raw.prefix.rel_timestamp + 2 * i, element.timestamp);
        for (element.transactions) |tx| _ = try Envelope.decode(tx);
    }
    try testing.expectEqual(raw.prefix.l1_origin_num, span.batches[span.batches.len - 1].epoch_num);
    // Re-splitting the derived transactions reproduces the vector byte for byte.
    const again = try span.to_raw(arena);
    try testing.expectEqualSlices(u8, raw_batch_vector, try encode_raw(arena, &again));
}

test "span batch: prefix truncated input and roundtrip" {
    var short: []const u8 = &(@as([2]u8, .{ 0, 0 }) ++ @as([19]u8, @splat(0)));
    try testing.expectError(error.ParentCheck, span_batch.Prefix.decode(&short));
    var short_origin: []const u8 = &(@as([22]u8, @splat(0)) ++ @as([19]u8, @splat(0)));
    try testing.expectError(error.L1OriginCheck, span_batch.Prefix.decode(&short_origin));
    var empty: []const u8 = &.{};
    try testing.expectError(error.RelativeTimestamp, span_batch.Prefix.decode(&empty));
    var no_origin: []const u8 = &.{0x01};
    try testing.expectError(error.L1OriginNumber, span_batch.Prefix.decode(&no_origin));
    const expected: span_batch.Prefix = .{
        .rel_timestamp = 0xff,
        .l1_origin_num = 0xee,
        .parent_check = (try Address.from_hex("beef00000000000000000000000000000000beef")).bytes,
        .l1_origin_check = (try Address.from_hex("babe00000000000000000000000000000000babe")).bytes,
    };
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    expected.encode(&writer);
    var input: []const u8 = writer.written();
    const decoded = try span_batch.Prefix.decode(&input);
    try testing.expectEqualDeep(expected, decoded);
}

fn varint(buffer: []u8, value: u64) []const u8 {
    var writer = Writer.init(buffer);
    writer.put_uvarint(value);
    return writer.written();
}

test "span batch: payload block count and tx counts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [16]u8 = undefined;
    var zero = varint(&buffer, 0);
    try testing.expectError(error.EmptySpanBatch, span_batch.Payload.decode(arena, &zero));
    var too_big = varint(&buffer, span_batch.max_span_batch_elements + 1);
    try testing.expectError(error.TooBigSpanBatchSize, span_batch.Payload.decode(arena, &too_big));
    var bad: []const u8 = &.{ 0x80, 0x00 };
    try testing.expectError(error.BlockCount, span_batch.Payload.decode(arena, &bad));
    // Two blocks: origin bits byte, then tx counts 2, 2 and then nothing.
    var counts: []const u8 = &.{ 0x02, 0x00, 0x02, 0x02 };
    const no_txs = span_batch.Payload.decode(arena, &counts);
    try testing.expectError(error.InvalidTransactionData, no_txs);
    var missing_count: []const u8 = &.{ 0x02, 0x00, 0x02 };
    const result = span_batch.Payload.decode(arena, &missing_count);
    try testing.expectError(error.BlockTxCounts, result);
    var huge_count = [_]u8{ 0x01, 0x00 } ++ [_]u8{ 0x81, 0xad, 0xe2, 0x04 };
    var huge: []const u8 = &huge_count;
    try testing.expectError(error.TooBigSpanBatchSize, span_batch.Payload.decode(arena, &huge));
    // Ten blocks need two origin-bit bytes; a high bit past bit 9 is too long.
    var long_bits: []const u8 = &.{ 0x0a, 0x04, 0x00 };
    try testing.expectError(error.BitfieldTooLong, span_batch.Payload.decode(arena, &long_bits));
}

test "span batch: transaction column truncation and auth proofs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // One tx: contract bits, y-parity bits, then only 32 of the 64 signature bytes.
    var truncated_sig: []const u8 = &(@as([2]u8, @splat(0)) ++ @as([32]u8, @splat(0)));
    const sig_result = Transactions.decode(arena, &truncated_sig, 1);
    try testing.expectError(error.InvalidTransactionData, sig_result);
    var truncated_to: []const u8 = &(@as([66]u8, @splat(0)) ++ @as([19]u8, @splat(0)));
    const to_result = Transactions.decode(arena, &truncated_to, 1);
    try testing.expectError(error.InvalidTransactionData, to_result);
    // A tx data RLP header claiming more payload than present.
    var short_data: []const u8 = &.{ 0xc3, 0x01, 0x02 };
    const read = span_batch.transactions.read_tx_data(&short_data);
    try testing.expectError(error.InvalidTransactionData, read);
    var blob_type: []const u8 = &.{ 0x03, 0xc0 };
    const blob = span_batch.transactions.read_tx_data(&blob_type);
    try testing.expectError(error.InvalidTransactionType, blob);
    var string_data: []const u8 = &.{ 0x02, 0x80 };
    const string = span_batch.transactions.read_tx_data(&string_data);
    try testing.expectError(error.InvalidTransactionData, string);
    // EIP-8130 auth column: a varint that never terminates, then an oversized length.
    var columns: [256]u8 = undefined;
    var writer = Writer.init(&columns);
    writer.put_zeros(2 + 64 + 20); // bits, signature, to.
    writer.put(&.{ 0x79, 0xc0 }); // tx data
    writer.put(&.{ 0x00, 0x00 }); // nonce, gas
    writer.put(&.{ 0xff, 0xff, 0xff });
    var unterminated: []const u8 = writer.written();
    const auth = Transactions.decode(arena, &unterminated, 1);
    try testing.expectError(error.InvalidAuthData, auth);
    writer.position -= 3;
    writer.put_uvarint(span_batch.bits.max_auth_proof_bytes + 1);
    var oversized: []const u8 = writer.written();
    try testing.expectError(error.TooBigSpanBatchSize, Transactions.decode(arena, &oversized, 1));
    writer.position -= span_batch.bits.uvarint_length(span_batch.bits.max_auth_proof_bytes + 1);
    writer.put(&.{ 0x01, 0xaa, 0x00 });
    var proofs: []const u8 = writer.written();
    const decoded = try Transactions.decode(arena, &proofs, 1);
    try testing.expectEqual(@as(usize, 1), decoded.eip8130_auth_data.len);
    try testing.expectEqualSlices(u8, &.{0xaa}, decoded.eip8130_auth_data[0].sender_proof);
    try testing.expectEqual(@as(usize, 0), decoded.legacy_tx_count);
    const encoded = try arena.alloc(u8, writer.position);
    var out = Writer.init(encoded);
    try decoded.encode(&out);
    try testing.expectEqualSlices(u8, writer.written(), out.written());
    // `0xc0` is not valid EIP-8130 span data (no fields).
    try testing.expectError(error.InvalidTransactionData, decoded.full_txs(arena, 1));
}

const call_target = Address{ .bytes = @splat(0x01) };

fn sample_envelopes(arena: Allocator, chain_id: u64) ![5][]const u8 {
    var auth_buffer: [128]u8 = undefined;
    const authorizations = consensus.AuthorizationList.build(&auth_buffer, &.{.{
        .chain_id = 1,
        .address = call_target,
        .nonce = 2,
        .y_parity = 1,
        .r = 5,
        .s = 6,
    }});
    const auth_copy = try arena.dupe(u8, authorizations.payload);
    const input: []const u8 = &.{ 0xde, 0xad };
    const envelopes = [5]Envelope{
        .{ .legacy = .{ .signature = test_signature, .tx = .{
            .chain_id = null,
            .nonce = 1,
            .gas_price = 7,
            .gas_limit = 21_000,
            .to = .create,
            .value = 3,
            .input = input,
        } } },
        .{ .legacy = .{ .signature = test_signature, .tx = .{
            .chain_id = chain_id,
            .nonce = 2,
            .gas_price = 7,
            .gas_limit = 21_000,
            .to = .{ .call = call_target },
            .value = 0,
            .input = &.{},
        } } },
        .{ .eip2930 = .{ .signature = test_signature, .tx = .{
            .chain_id = chain_id,
            .nonce = 3,
            .gas_price = 9,
            .gas_limit = 50_000,
            .to = .{ .call = call_target },
            .value = 1,
            .input = input,
            .access_list = .empty,
        } } },
        .{ .eip1559 = .{ .signature = .{ .y_parity = true, .r = 1, .s = 2 }, .tx = .{
            .chain_id = chain_id,
            .nonce = 4,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 2,
            .gas_limit = 2,
            .to = .create,
            .value = 3,
            .input = &.{},
            .access_list = .empty,
        } } },
        .{ .eip7702 = .{ .signature = test_signature, .tx = .{
            .chain_id = chain_id,
            .nonce = 5,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 2,
            .gas_limit = 60_000,
            .to = call_target,
            .value = 0,
            .input = input,
            .access_list = .empty,
            .authorization_list = .{ .payload = auth_copy, .count = 1 },
        } } },
    };
    var encoded: [5][]const u8 = undefined;
    for (envelopes, &encoded) |envelope, *out| out.* = try encode_envelope(arena, envelope);
    return encoded;
}

fn expect_transactions_roundtrip(arena: Allocator, raws: []const []const u8, chain_id: u64) !void {
    const txs = try Transactions.build(arena, raws, chain_id);
    var counter = Writer.counting();
    try txs.encode(&counter);
    const buffer = try arena.alloc(u8, counter.position);
    var writer = Writer.init(buffer);
    try txs.encode(&writer);
    var input: []const u8 = writer.written();
    const decoded = try Transactions.decode(arena, &input, raws.len);
    try testing.expectEqual(@as(usize, 0), input.len);
    const rebuilt = try decoded.full_txs(arena, chain_id);
    try testing.expectEqual(raws.len, rebuilt.len);
    for (raws, rebuilt) |expected, actual| try testing.expectEqualSlices(u8, expected, actual);
}

test "span batch: transactions build/encode/decode/full_txs roundtrip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const raws = try sample_envelopes(arena, 8453);
    try expect_transactions_roundtrip(arena, &raws, 8453);
    for (&raws) |*raw| try expect_transactions_roundtrip(arena, raw[0..1], 8453);
    const empty = try Transactions.build(arena, &.{}, 1);
    try testing.expectEqual(@as(u64, 0), empty.total_block_tx_count);
    // Typed and EIP-155 transactions must match the batch chain id.
    try testing.expectError(error.InvalidTransactionData, Transactions.build(arena, raws[1..2], 1));
    try testing.expectError(error.InvalidTransactionData, Transactions.build(arena, raws[2..3], 1));
    _ = try Transactions.build(arena, raws[0..1], 1);
    const deposit: []const u8 = &.{ 0x7e, 0xc0 };
    const deposit_result = Transactions.build(arena, &.{deposit}, 1);
    try testing.expectError(error.InvalidTransactionData, deposit_result);
    const valid_deposit = try encode_envelope(arena, .{ .deposit = .{
        .source_hash = .zero,
        .from = call_target,
        .to = .create,
        .mint = 0,
        .value = 0,
        .gas_limit = 1,
        .is_system_transaction = false,
        .input = &.{},
    } });
    const typed_deposit = Transactions.build(arena, &.{valid_deposit}, 1);
    try testing.expectError(error.InvalidTransactionType, typed_deposit);
    const empty_eip8130: []const u8 = &.{ 0x79, 0xc0 };
    const bad_eip8130 = Transactions.build(arena, &.{empty_eip8130}, 1);
    try testing.expectError(error.InvalidTransactionData, bad_eip8130);
}

test "span batch: legacy protected bit drives EIP-155 v" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const raws = try sample_envelopes(arena, 10);
    const txs = try Transactions.build(arena, raws[0..2], 10);
    try testing.expectEqual(@as(u64, 2), txs.legacy_tx_count);
    try testing.expectEqual(@as(?u1, 0), txs.protected_bits.get_bit(0));
    try testing.expectEqual(@as(?u1, 1), txs.protected_bits.get_bit(1));
    try testing.expectEqual(@as(?u1, 1), txs.contract_creation_bits.get_bit(0));
    const rebuilt = try txs.full_txs(arena, 10);
    const unprotected = try Envelope.decode(rebuilt[0]);
    const protected = try Envelope.decode(rebuilt[1]);
    try testing.expectEqual(@as(?u64, null), unprotected.chain_id());
    try testing.expectEqual(@as(?u64, 10), protected.chain_id());
}

fn hash_with_prefix(prefix_byte: u8, prefix_length: usize) B256 {
    var hash: B256 = .zero;
    @memset(hash.bytes[0..prefix_length], prefix_byte);
    return hash;
}

test "span batch: accessors and hash checks" {
    const elements = [_]Element{
        .{ .epoch_num = 10, .timestamp = 10 },
        .{ .epoch_num = 11, .timestamp = 20 },
    };
    const span: SpanBatch = .{
        .batches = &elements,
        .parent_check = @splat(0x11),
        .l1_origin_check = @splat(0x11),
    };
    try testing.expectEqual(@as(u64, 10), span.starting_timestamp());
    try testing.expectEqual(@as(u64, 20), span.final_timestamp());
    try testing.expectEqual(@as(u64, 10), span.starting_epoch_num());
    try testing.expect(span.check_origin_hash(hash_with_prefix(0x11, 20)));
    try testing.expect(!span.check_origin_hash(hash_with_prefix(0x11, 19)));
    try testing.expect(span.check_parent_hash(hash_with_prefix(0x11, 20)));
    try testing.expect(!span.check_parent_hash(hash_with_prefix(0x11, 19)));
}

test "span batch: singular batches outdated and missing origin" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const l1_blocks = [_]BlockInfo{.{ .number = 10, .timestamp = 20 }};
    const safe_head: L2BlockInfo = .{
        .block_info = .{ .timestamp = 10 },
        .l1_origin = .{ .number = 10 },
    };
    const outdated = [_]Element{
        .{ .epoch_num = 9, .timestamp = 20 },
        .{ .epoch_num = 10, .timestamp = 30 },
    };
    const span_outdated: SpanBatch = .{ .batches = &outdated };
    const result = span_outdated.get_singular_batches(arena, &l1_blocks, safe_head);
    try testing.expectError(error.L1OriginBeforeSafeHead, result);
    const missing = [_]Element{
        .{ .epoch_num = 10, .timestamp = 20 },
        .{ .epoch_num = 11, .timestamp = 30 },
    };
    const span_missing: SpanBatch = .{ .batches = &missing };
    const missing_result = span_missing.get_singular_batches(arena, &l1_blocks, safe_head);
    try testing.expectError(error.MissingL1Origin, missing_result);
    const present = [_]Element{
        .{ .epoch_num = 10, .timestamp = 10 },
        .{ .epoch_num = 10, .timestamp = 30 },
    };
    const span_present: SpanBatch = .{ .batches = &present };
    const singles = try span_present.get_singular_batches(arena, &l1_blocks, safe_head);
    try testing.expectEqual(@as(usize, 1), singles.len);
    try testing.expectEqual(@as(u64, 30), singles[0].timestamp);
}

test "span batch: from singular batches encodes like the raw form" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const legacy = try encode_envelope(arena, .{ .legacy = .{ .signature = test_signature, .tx = .{
        .chain_id = null,
        .nonce = 0,
        .gas_price = 0,
        .gas_limit = 0,
        .to = .create,
        .value = 0,
        .input = &.{},
    } } });
    const singles = [_]SingleBatch{
        .{
            .parent_hash = .init(@splat(0x11)),
            .epoch_num = 10,
            .epoch_hash = .init(@splat(0x22)),
            .timestamp = 110,
            .transactions = &.{legacy},
        },
        .{
            .parent_hash = .zero,
            .epoch_num = 11,
            .epoch_hash = .init(@splat(0x33)),
            .timestamp = 112,
            .transactions = &.{},
        },
    };
    const span = try SpanBatch.from_singular_batches(arena, &singles, 0, 100, 0);
    try testing.expectEqual(@as(?u1, 1), span.origin_bits.get_bit(0));
    try testing.expectEqual(@as(?u1, 1), span.origin_bits.get_bit(1));
    try testing.expectEqualSlices(u8, &@as([20]u8, @splat(0x33)), &span.l1_origin_check);
    const raw = try span.to_raw(arena);
    try testing.expectEqual(@as(u64, 10), raw.prefix.rel_timestamp);
    try testing.expectEqual(@as(u64, 11), raw.prefix.l1_origin_num);
    try testing.expectEqualSlices(u64, &.{ 1, 0 }, raw.payload.block_tx_counts);
    const encoded = try span.encode_alloc(arena);
    try testing.expectEqualSlices(u8, try encode_raw(arena, &raw), encoded);
    // Decode and derive back to the same elements.
    var input: []const u8 = encoded;
    const decoded = try RawSpanBatch.decode(arena, &input);
    const derived = try decoded.derive(arena, 2, 100, 0);
    try testing.expectEqual(@as(usize, 2), derived.batches.len);
    try testing.expectEqual(@as(u64, 10), derived.batches[0].epoch_num);
    try testing.expectEqual(@as(u64, 112), derived.batches[1].timestamp);
    try testing.expectEqualSlices(u8, legacy, derived.batches[0].transactions[0]);
    const empty: SpanBatch = .{};
    try testing.expectError(error.EmptySpanBatch, empty.encode_alloc(arena));
}

test "span batch: derive counts epochs back from the last origin" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var origin_bits = [_]u8{0b0000_1011};
    const counts = [_]u64{ 0, 0, 0, 0 };
    const raw: RawSpanBatch = .{
        .prefix = .{ .rel_timestamp = 4, .l1_origin_num = 7 },
        .payload = .{
            .block_count = 4,
            .origin_bits = .{ .bytes = &origin_bits },
            .block_tx_counts = &counts,
        },
    };
    const span = try raw.derive(arena, 2, 10, 1);
    const expected = [_]u64{ 5, 6, 6, 7 };
    for (span.batches, expected, 0..) |element, epoch, i| {
        try testing.expectEqual(epoch, element.epoch_num);
        try testing.expectEqual(14 + 2 * i, element.timestamp);
    }
    var underflow = raw;
    underflow.prefix.l1_origin_num = 1;
    try testing.expectError(error.ArithmeticOverflow, underflow.derive(arena, 2, 10, 1));
    var overflow = raw;
    overflow.prefix.rel_timestamp = std.math.maxInt(u64);
    try testing.expectError(error.ArithmeticOverflow, overflow.derive(arena, 2, 10, 1));
}

// ---- Validity scenarios (base/base span.rs `test_check_batch`) ----

const parent_hash = hash_with_prefix(0x11, 20);
const l1_hash = hash_with_prefix(0x33, 20);

const TestChain = struct {
    blocks: []const L2BlockInfo = &.{},
    short_circuit: bool = false,
    safe_blocks: []const NumberedBlock = &.{},

    const NumberedBlock = struct { number: u64, block: span_batch.SafeBlock };

    fn l2_block_info_by_number(context: *anyopaque, number: u64) ?L2BlockInfo {
        const chain: *TestChain = @ptrCast(@alignCast(context));
        if (chain.short_circuit) {
            return if (chain.blocks.len > 0) chain.blocks[0] else null;
        }
        for (chain.blocks) |info| if (info.block_info.number == number) return info;
        return null;
    }

    fn block_by_number(context: *anyopaque, number: u64) ?span_batch.SafeBlock {
        const chain: *TestChain = @ptrCast(@alignCast(context));
        for (chain.safe_blocks) |entry| if (entry.number == number) return entry.block;
        return null;
    }

    fn interface(chain: *TestChain) span_batch.SafeChain {
        return .{
            .context = chain,
            .l2_block_info_by_number = l2_block_info_by_number,
            .block_by_number = block_by_number,
        };
    }
};

fn test_config() RollupConfig {
    var config: RollupConfig = .{ .seq_window_size = 100, .block_time = 10 };
    config.upgrades.set(.delta, 0);
    config.genesis.l2.number = 41;
    config.genesis.l2_time = 10;
    return config;
}

fn l1_block(number: u64) BlockInfo {
    return .{ .number = number, .timestamp = 10, .hash = l1_hash };
}

fn gen_l1_blocks(
    out: []BlockInfo,
    start_number: u64,
    start_timestamp: u64,
    interval: u64,
) []const BlockInfo {
    for (out, 0..) |*info, i| {
        var hash: B256 = .zero;
        std.mem.writeInt(u64, hash.bytes[24..32], i, .big);
        info.* = .{
            .number = start_number + i,
            .timestamp = start_timestamp + i * interval,
            .hash = hash,
        };
    }
    return out;
}

fn l2_parent(l1_origin: u64) L2BlockInfo {
    return .{
        .block_info = .{ .number = 40, .timestamp = 10, .hash = parent_hash },
        .l1_origin = .{ .number = l1_origin },
    };
}

fn checked_span(elements: []const Element) SpanBatch {
    return .{
        .batches = elements,
        .parent_check = parent_hash.bytes[0..20].*,
        .l1_origin_check = l1_hash.bytes[0..20].*,
    };
}

const default_elements = [_]Element{
    .{ .epoch_num = 10, .timestamp = 10 },
    .{ .epoch_num = 11, .timestamp = 20 },
};
const default_blocks = [_]L2BlockInfo{l2_parent(9)};
const default_l1 = [_]BlockInfo{l1_block(11)};

const Scenario = struct {
    config: RollupConfig = test_config(),
    l1_blocks: []const BlockInfo = &default_l1,
    safe_head: L2BlockInfo = .{
        .block_info = .{ .number = 41, .timestamp = 10, .hash = parent_hash },
        .l1_origin = .{ .number = 9 },
    },
    inclusion_block: BlockInfo = .{ .number = 50 },
    chain: TestChain = .{ .blocks = &default_blocks },
    span: SpanBatch = checked_span(&default_elements),

    fn check(scenario: *Scenario) Validity {
        return scenario.span.check_batch(
            &scenario.config,
            scenario.l1_blocks,
            scenario.safe_head,
            scenario.inclusion_block,
            scenario.chain.interface(),
        );
    }

    fn expect(scenario: Scenario, expected: Validity) !void {
        var copy = scenario;
        const actual = copy.check();
        if (!actual.eql(expected)) {
            std.debug.print("expected {any}, got {any}\n", .{ expected, actual });
            return error.TestUnexpectedResult;
        }
    }

    fn expect_drop(scenario: Scenario, reason: DropReason) !void {
        return scenario.expect(.{ .drop = reason });
    }
};

test "span batch check: prefix scenarios" {
    try (Scenario{ .l1_blocks = &.{}, .span = .{} }).expect(.undecided);
    try (Scenario{ .span = .{} }).expect(.undecided);
    const eager = [_]Element{.{ .epoch_num = 10, .timestamp = 10 }};
    try (Scenario{ .l1_blocks = &.{l1_block(9)}, .span = checked_span(&eager) }).expect(.undecided);
    var pre_delta = Scenario{
        .l1_blocks = &.{.{ .number = 10, .timestamp = 9 }},
        .span = checked_span(&eager),
    };
    pre_delta.config.upgrades.set(.delta, 10);
    try pre_delta.expect_drop(.span_batch_pre_delta);
    const future = [_]Element{.{ .epoch_num = 10, .timestamp = 21 }};
    const l1_ten = [_]BlockInfo{l1_block(10)};
    try (Scenario{ .l1_blocks = &l1_ten, .span = checked_span(&future) }).expect(.future);
    try (Scenario{ .l1_blocks = &l1_ten, .span = checked_span(&eager) })
        .expect_drop(.span_batch_no_new_blocks_pre_holocene);
    var holocene = Scenario{ .l1_blocks = &l1_ten, .span = checked_span(&future) };
    holocene.config.upgrades.set(.holocene, 0);
    try holocene.expect_drop(.future_timestamp_holocene);
    holocene.span = checked_span(&eager);
    try holocene.expect(.past);
    const misaligned = [_]Element{
        .{ .epoch_num = 10, .timestamp = 11 },
        .{ .epoch_num = 11, .timestamp = 21 },
    };
    try (Scenario{ .l1_blocks = &l1_ten, .span = checked_span(&misaligned) })
        .expect_drop(.span_batch_misaligned_timestamp);
    const not_exact = [_]Element{
        .{ .epoch_num = 10, .timestamp = 8 },
        .{ .epoch_num = 11, .timestamp = 20 },
    };
    var not_overlapped = Scenario{
        .l1_blocks = &l1_ten,
        .safe_head = .{ .block_info = .{ .timestamp = 10 } },
        .span = checked_span(&not_exact),
    };
    not_overlapped.config.genesis = .{};
    try not_overlapped.expect_drop(.span_batch_not_overlapped_exactly);
    try (Scenario{ .l1_blocks = &l1_ten, .chain = .{} }).expect(.undecided);
}

test "span batch check: parent, window, and epoch scenarios" {
    const l1_ten = [_]BlockInfo{l1_block(10)};
    const wrong_parent = [_]L2BlockInfo{.{ .block_info = .{ .number = 41, .timestamp = 10 } }};
    try (Scenario{
        .l1_blocks = &l1_ten,
        .chain = .{ .blocks = &wrong_parent, .short_circuit = true },
    }).expect_drop(.parent_hash_mismatch);
    var window = Scenario{ .l1_blocks = &l1_ten };
    window.config.seq_window_size = 0;
    try window.expect_drop(.included_too_late);
    var far = Scenario{ .l1_blocks = &l1_ten, .chain = .{ .blocks = &.{l2_parent(8)} } };
    far.safe_head.l1_origin.number = 8;
    try far.expect_drop(.epoch_too_far_in_future);
    var wrong_l1 = Scenario{};
    wrong_l1.span.l1_origin_check = @splat(0);
    try wrong_l1.expect_drop(.epoch_hash_mismatch);
    try (Scenario{ .l1_blocks = &l1_ten }).expect(.undecided);
    var too_old = Scenario{ .chain = .{ .blocks = &.{l2_parent(14)} } };
    too_old.safe_head.l1_origin.number = 13;
    try too_old.expect_drop(.epoch_too_old);
}

test "span batch check: denim drops span batches from the first denim block" {
    var config: RollupConfig = .{ .block_time = 2 };
    config.genesis.l2.number = 40;
    config.genesis.l2_time = 100;
    config.upgrades.set(.denim, 104);
    const elements = [_]Element{.{ .timestamp = 1 }};
    const span: SpanBatch = .{ .batches = &elements };
    var chain: TestChain = .{};
    const l1_origins = [_]BlockInfo{.{}};
    const pre_denim: L2BlockInfo = .{ .block_info = .{ .number = 40, .timestamp = 100 } };
    const before = span.check_batch_prefix(&config, &l1_origins, pre_denim, .{}, chain.interface());
    try testing.expect(!before.validity.eql(.{ .drop = .span_batch_post_denim }));
    const denim: L2BlockInfo = .{ .block_info = .{ .number = 41, .timestamp = 102 } };
    const after = span.check_batch_prefix(&config, &l1_origins, denim, .{}, chain.interface());
    try testing.expect(after.validity.eql(.{ .drop = .span_batch_post_denim }));
}

fn drift_scenario(l1_blocks: []const BlockInfo, elements: []const Element) Scenario {
    var scenario = Scenario{ .l1_blocks = l1_blocks, .chain = .{}, .span = checked_span(elements) };
    scenario.config.max_sequencer_drift = 0;
    scenario.span.l1_origin_check = l1_blocks[1].hash.bytes[0..20].*;
    return scenario;
}

test "span batch check: element scenarios" {
    var l1_storage: [3]BlockInfo = undefined;
    const flat = gen_l1_blocks(&l1_storage, 9, 10, 0);
    const empty_elements = [_]Element{
        .{ .epoch_num = 10, .timestamp = 20 },
        .{ .epoch_num = 10, .timestamp = 30 },
        .{ .epoch_num = 11, .timestamp = 40 },
    };
    try drift_scenario(flat, &empty_elements).expect_drop(.sequencer_drift_not_adopted_next_origin);
    var late_storage: [2]BlockInfo = undefined;
    const late = gen_l1_blocks(&late_storage, 10, 10, 30);
    try drift_scenario(late, &empty_elements).expect(.accept);
    const empty_tx: []const u8 = &.{};
    const tx_elements = [_]Element{
        .{ .epoch_num = 10, .timestamp = 20, .transactions = &.{empty_tx} },
        .{ .epoch_num = 10, .timestamp = 20, .transactions = &.{empty_tx} },
        .{ .epoch_num = 11, .timestamp = 20, .transactions = &.{empty_tx} },
    };
    try drift_scenario(flat, &tx_elements).expect_drop(.sequencer_drift_exceeded);
    const before_origin = [_]Element{
        .{ .epoch_num = 10, .timestamp = 20 },
        .{ .epoch_num = 10, .timestamp = 19 },
        .{ .epoch_num = 10, .timestamp = 30 },
    };
    var timestamp = Scenario{
        .l1_blocks = &.{.{ .number = 10, .timestamp = 20 }},
        .safe_head = .{ .block_info = .{ .timestamp = 10 }, .l1_origin = .{ .number = 10 } },
        .span = .{ .batches = &before_origin },
    };
    timestamp.config.genesis = .{ .l2_time = 10 };
    try timestamp.expect_drop(.timestamp_before_l1_origin);
}

const TxStorage = struct {
    l1: [3]BlockInfo = undefined,
    txs: [3][1][]const u8 = undefined,
    elements: [3]Element = undefined,
};

fn tx_scenario(storage: *TxStorage, tx: []const u8) Scenario {
    const l1_blocks = gen_l1_blocks(&storage.l1, 9, 0, 10);
    const filler: []const u8 = &.{0x02};
    storage.txs = .{ .{filler}, .{tx}, .{filler} };
    for (&storage.elements, &storage.txs, 0..) |*element, *txs, i| {
        element.* = .{ .epoch_num = if (i == 2) 11 else 10, .timestamp = 20, .transactions = txs };
    }
    const elements = &storage.elements;
    var scenario = Scenario{ .l1_blocks = l1_blocks, .span = checked_span(elements) };
    scenario.config.max_sequencer_drift = 100;
    scenario.span.l1_origin_check = l1_blocks[0].hash.bytes[0..20].*;
    return scenario;
}

test "span batch check: transaction scenarios" {
    var storage: TxStorage = .{};
    try tx_scenario(&storage, &.{}).expect_drop(.empty_transaction);
    try tx_scenario(&storage, &.{0x7e}).expect_drop(.deposit_transaction);
    try tx_scenario(&storage, &.{0x04}).expect_drop(.eip7702_pre_isthmus);
    try tx_scenario(&storage, &.{0x79}).expect_drop(.eip8130_pre_everest);
    var everest = tx_scenario(&storage, &.{0x79});
    everest.config.upgrades.set(.denim, 0);
    everest.config.upgrades.set(.everest, 0);
    try everest.expect_drop(.span_batch_post_denim);
}

test "span batch check: overlap scenarios" {
    try (Scenario{}).expect(.undecided);
    const no_info = [_]TestChain.NumberedBlock{.{
        .number = 41,
        .block = .{ .transactions = &.{}, .l1_origin_number = null },
    }};
    try (Scenario{ .chain = .{ .blocks = &default_blocks, .safe_blocks = &no_info } })
        .expect_drop(.l2_block_info_extraction_failed);
    const genesis_origin = [_]TestChain.NumberedBlock{.{
        .number = 41,
        .block = .{ .transactions = &.{}, .l1_origin_number = 0 },
    }};
    try (Scenario{ .chain = .{ .blocks = &default_blocks, .safe_blocks = &genesis_origin } })
        .expect_drop(.overlapped_l1_origin_mismatch);
    const matching = [_]TestChain.NumberedBlock{.{
        .number = 41,
        .block = .{ .transactions = &.{}, .l1_origin_number = 10 },
    }};
    try (Scenario{ .chain = .{ .blocks = &default_blocks, .safe_blocks = &matching } })
        .expect(.accept);
}

test "span batch check: overlapped transactions and outdated origin" {
    var l1_storage: [3]BlockInfo = undefined;
    const l1_blocks = gen_l1_blocks(&l1_storage, 9, 0, 10);
    const blocks = [_]L2BlockInfo{
        .{ .block_info = .{ .number = 8, .timestamp = 0 }, .l1_origin = .{ .number = 9 } },
        .{ .block_info = .{ .number = 9, .timestamp = 10 }, .l1_origin = .{ .number = 10 } },
        .{ .block_info = .{ .number = 10, .timestamp = 20 }, .l1_origin = .{ .number = 11 } },
    };
    const batch_tx: []const u8 = &.{0x02};
    const elements = [_]Element{
        .{ .epoch_num = 10, .timestamp = 10, .transactions = &.{batch_tx} },
        .{ .epoch_num = 11, .timestamp = 60 },
    };
    const deposit: []const u8 = &.{ 0x7e, 0x01 };
    const other: []const u8 = &.{ 0x02, 0x01 };
    const empty_block = [_]TestChain.NumberedBlock{.{
        .number = 9,
        .block = .{ .transactions = &.{deposit}, .l1_origin_number = 10 },
    }};
    const mismatched_block = [_]TestChain.NumberedBlock{.{
        .number = 9,
        .block = .{ .transactions = &.{ deposit, other }, .l1_origin_number = 10 },
    }};
    var scenario = Scenario{
        .l1_blocks = l1_blocks,
        .safe_head = blocks[2],
        .chain = .{ .blocks = &blocks, .safe_blocks = &empty_block },
        .span = .{ .batches = &elements },
    };
    scenario.config.max_sequencer_drift = 1000;
    scenario.config.genesis = .{ .l2_time = 20 };
    scenario.config.genesis.l2.number = 10;
    try scenario.expect_drop(.overlapped_tx_count_mismatch);
    scenario.chain.safe_blocks = &mismatched_block;
    try scenario.expect_drop(.overlapped_tx_mismatch);

    const outdated_elements = [_]Element{
        .{ .epoch_num = 9, .timestamp = 10 },
        .{ .epoch_num = 9, .timestamp = 20 },
        .{ .epoch_num = 10, .timestamp = 30 },
    };
    var outdated = Scenario{
        .l1_blocks = &.{.{ .number = 10, .timestamp = 5, .hash = l1_hash }},
        .chain = .{ .blocks = &.{l2_parent(9)} },
        .span = checked_span(&outdated_elements),
    };
    outdated.config.genesis = .{};
    outdated.config.genesis.l2.number = 40;
    outdated.safe_head.l1_origin = .{ .number = 10, .hash = l1_hash };
    try outdated.expect_drop(.l1_origin_before_safe_head);
}

// ---- Fuzzing ----

fn random_envelope(prng: *Prng, arena: Allocator, chain_id: u64) ![]const u8 {
    const input = try arena.alloc(u8, prng.below(40));
    prng.fill(input);
    const signature: Signature = .{
        .y_parity = prng.chance(1, 2),
        .r = prng.int(u256),
        .s = prng.int(u256),
    };
    const to: consensus.TxKind = if (prng.chance(1, 4)) .create else .{
        .call = .{ .bytes = @splat(prng.int(u8)) },
    };
    const nonce = prng.int(u64);
    const gas = prng.int(u64) >> @intCast(prng.below(64));
    const value = prng.int(u256) >> @intCast(prng.below(256));
    const envelope: Envelope = switch (prng.below(4)) {
        0 => .{ .legacy = .{ .signature = signature, .tx = .{
            .chain_id = if (prng.chance(1, 2)) chain_id else null,
            .nonce = nonce,
            .gas_price = prng.int(u128),
            .gas_limit = gas,
            .to = to,
            .value = value,
            .input = input,
        } } },
        1 => .{ .eip2930 = .{ .signature = signature, .tx = .{
            .chain_id = chain_id,
            .nonce = nonce,
            .gas_price = prng.int(u64),
            .gas_limit = gas,
            .to = to,
            .value = value,
            .input = input,
            .access_list = .empty,
        } } },
        2 => .{ .eip1559 = .{ .signature = signature, .tx = .{
            .chain_id = chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = prng.int(u32),
            .max_fee_per_gas = prng.int(u128),
            .gas_limit = gas,
            .to = to,
            .value = value,
            .input = input,
            .access_list = .empty,
        } } },
        else => .{ .eip7702 = .{ .signature = signature, .tx = .{
            .chain_id = chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = prng.int(u32),
            .max_fee_per_gas = prng.int(u64),
            .gas_limit = gas,
            .to = .{ .bytes = @splat(prng.int(u8)) },
            .value = value,
            .input = input,
            .access_list = .empty,
            .authorization_list = .empty,
        } } },
    };
    return encode_envelope(arena, envelope);
}

fn random_span(prng: *Prng, arena: Allocator, chain_id: u64) !SpanBatch {
    const block_count = prng.range(1, 12);
    const elements = try arena.alloc(Element, block_count);
    const origin_bits = try arena.alloc(u8, span_batch.bits.bits_buffer_length(block_count));
    @memset(origin_bits, 0);
    var epoch = prng.int(u32);
    const start = prng.int(u32);
    for (elements, 0..) |*element, i| {
        const advanced = prng.chance(1, 3);
        if (advanced and i > 0) epoch += 1;
        Bits.set_bit(origin_bits, i, advanced);
        const txs = try arena.alloc([]const u8, prng.below(4));
        for (txs) |*tx| tx.* = try random_envelope(prng, arena, chain_id);
        element.* = .{ .epoch_num = epoch, .timestamp = start + 2 * i, .transactions = txs };
    }
    var span: SpanBatch = .{
        .genesis_timestamp = prng.below(start + 1),
        .chain_id = chain_id,
        .batches = elements,
        .origin_bits = .{ .bytes = origin_bits },
    };
    prng.fill(&span.parent_check);
    prng.fill(&span.l1_origin_check);
    return span;
}

fn expect_span_roundtrip(arena: Allocator, span: *const SpanBatch) ![]const u8 {
    const encoded = try span.encode_alloc(arena);
    var input: []const u8 = encoded;
    const raw = try RawSpanBatch.decode(arena, &input);
    try testing.expectEqual(@as(usize, 0), input.len);
    try testing.expectEqualSlices(u8, encoded, try encode_raw(arena, &raw));
    const derived = try raw.derive(arena, 2, span.genesis_timestamp, span.chain_id);
    try testing.expectEqual(span.batches.len, derived.batches.len);
    for (span.batches, derived.batches) |expected, actual| {
        try testing.expectEqual(expected.epoch_num, actual.epoch_num);
        try testing.expectEqual(expected.timestamp, actual.timestamp);
        try testing.expectEqual(expected.transactions.len, actual.transactions.len);
        for (expected.transactions, actual.transactions) |a, b| {
            try testing.expectEqualSlices(u8, a, b);
        }
    }
    return encoded;
}

/// Decodes arbitrary bytes; when decoding succeeds, re-encoding must be a fixed point
/// (decode quirks such as zero-padded short bitlists normalise on the first pass).
fn check_decode(input: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var reader = input;
    const raw = RawSpanBatch.decode(arena, &reader) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    const first = try encode_raw(arena, &raw);
    var again: []const u8 = first;
    const raw_again = try RawSpanBatch.decode(arena, &again);
    try testing.expectEqualSlices(u8, first, try encode_raw(arena, &raw_again));
    if (raw.derive(arena, 2, 0, 901)) |span| {
        try testing.expectEqual(raw.payload.block_count, span.batches.len);
    } else |err| if (err == error.OutOfMemory) return err;
}

test "span batch: seeded fuzz encode/decode/derive roundtrip and mutation" {
    var prng = Prng.init(0x5350414e);
    for (0..300) |_| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const chain_id = prng.range(1, 100_000);
        const span = try random_span(&prng, arena, chain_id);
        const encoded = try expect_span_roundtrip(arena, &span);
        const mutated = try arena.dupe(u8, encoded);
        const flips = prng.range(1, 4);
        for (0..flips) |_| mutated[prng.below(mutated.len)] = prng.int(u8);
        try check_decode(mutated[0..prng.range(mutated.len / 2, mutated.len)]);
    }
    for (0..200) |_| {
        var garbage: [96]u8 = undefined;
        const length = prng.below(garbage.len + 1);
        prng.fill(garbage[0..length]);
        try check_decode(garbage[0..length]);
    }
    try check_decode(raw_batch_vector);
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "span batch: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

const eip8130 = consensus.eip8130;

fn eip8130_raw(arena: Allocator, signed: eip8130.Signed) ![]const u8 {
    return encode_envelope(arena, .{ .eip8130 = signed });
}

fn eip8130_calls(buffers: *[2][256]u8) eip8130.Calls {
    const call: eip8130.Call = .{ .to = call_target, .value = 7, .data = &.{ 0xde, 0xad } };
    const phase = eip8130.Phase.build(&buffers[0], &.{ call, call });
    return eip8130.Calls.build(&buffers[1], &.{phase});
}

test "span batch: EIP-8130 transactions roundtrip through the auth column" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var call_buffers: [2][256]u8 = undefined;
    const calls = eip8130_calls(&call_buffers);
    const k1_signature: [65]u8 = @splat(0x1b);
    const authenticator = eip8130.k1_authenticator.bytes;
    const sender_auth = authenticator ++ @as([65]u8, @splat(0x1c));
    const payer: Address = .{ .bytes = @splat(0x42) };
    const base_tx: eip8130.TxEip8130 = .{
        .chain_id = 8453,
        .nonce_key = 9,
        .nonce_sequence = 3,
        .valid_before = 2_000,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 100,
        .gas_limit = 90_000,
        .calls = calls,
        .metadata = &.{0x01},
    };
    // EOA self-pay: the whole k1 signature is the proof.
    const eoa = try eip8130_raw(arena, .{ .tx = base_tx, .sender_auth = &k1_signature });
    // Account sender with a named payer: authenticators inline, proofs in the column.
    var account_tx = base_tx;
    account_tx.sender = .{ .bytes = @splat(0x55) };
    account_tx.payer = payer;
    const account = try eip8130_raw(arena, .{
        .tx = account_tx,
        .sender_auth = &sender_auth,
        .payer_auth = &authenticator, // Authenticator with an empty proof.
    });
    // Open payer: the payer proof is a raw k1 signature and no authenticator.
    var open_tx = base_tx;
    open_tx.payer = eip8130.open_payer;
    const open = try eip8130_raw(arena, .{
        .tx = open_tx,
        .sender_auth = &k1_signature,
        .payer_auth = &k1_signature,
    });
    const legacy = (try sample_envelopes(arena, 8453))[0];
    const raws = [_][]const u8{ eoa, legacy, account, open, legacy };
    try expect_transactions_roundtrip(arena, &raws, 8453);
    for (raws[0..4]) |raw| try expect_transactions_roundtrip(arena, &.{raw}, 8453);
    const txs = try Transactions.build(arena, &raws, 8453);
    try testing.expectEqual(@as(usize, 3), txs.eip8130_auth_data.len);
    // EIP-8130 transactions set the contract-creation bit and take no `to` slot.
    const legacy_creations = (try Transactions.build(arena, &.{legacy}, 8453))
        .contract_creation_count();
    try testing.expectEqual(3 + 2 * legacy_creations, txs.contract_creation_count());
    try testing.expectEqualSlices(u8, sender_auth[20..], txs.eip8130_auth_data[1].sender_proof);
    try testing.expectEqual(@as(usize, 0), txs.eip8130_auth_data[1].payer_proof.len);
    // Wrong chain id, and an account sender whose auth is shorter than an authenticator.
    try testing.expectError(error.InvalidTransactionData, Transactions.build(arena, &.{eoa}, 1));
    const short = try eip8130_raw(arena, .{ .tx = account_tx, .sender_auth = &.{0x01} });
    try testing.expectError(error.InvalidAuthData, Transactions.build(arena, &.{short}, 8453));
}

test "span batch: EIP-8130 span data rejects inconsistent authenticators" {
    const Eip8130 = span_batch.tx_data.Eip8130;
    var buffer: [256]u8 = undefined;
    const data: Eip8130 = .{ .sender = .{ .bytes = @splat(1) }, .sender_authenticator = &.{} };
    var encoder = @import("../../common/rlp/root.zig").Encoder.init(&buffer);
    data.encode(&encoder);
    try testing.expectError(error.InvalidTransactionData, Eip8130.decode(encoder.written()));
    const valid: Eip8130 = .{ .payer = eip8130.open_payer };
    encoder = .init(&buffer);
    valid.encode(&encoder);
    const decoded = try Eip8130.decode(encoder.written());
    try testing.expect(decoded.payer.?.eql(eip8130.open_payer));
    try testing.expect(!Eip8130.named_payer(decoded.payer));
}

test "span batch: seeded fuzz of EIP-8130 transaction columns" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = Prng.init(0x8130);
    var call_buffers: [2][256]u8 = undefined;
    const calls = eip8130_calls(&call_buffers);
    for (0..200) |_| {
        _ = arena_state.reset(.retain_capacity);
        var tx: eip8130.TxEip8130 = .{
            .chain_id = 10,
            .nonce_key = prng.int(u64),
            .nonce_sequence = prng.int(u64),
            .valid_after = prng.below(1_000),
            .max_fee_per_gas = prng.int(u64),
            .gas_limit = prng.int(u32),
            .calls = if (prng.chance(1, 2)) calls else .empty,
        };
        const proof_length = prng.below(100);
        const proof = try arena.alloc(u8, 20 + proof_length);
        prng.fill(proof);
        if (prng.chance(1, 2)) tx.sender = .{ .bytes = proof[0..20].* };
        tx.payer = switch (prng.below(3)) {
            0 => null,
            1 => eip8130.open_payer,
            else => .{ .bytes = @splat(0x77) },
        };
        const sender_auth = if (tx.sender != null) proof else proof[20..];
        const named = tx.payer != null and !tx.payer.?.eql(eip8130.open_payer);
        const payer_auth: []const u8 = if (tx.payer == null)
            &.{}
        else if (named) proof else proof[20..];
        const raw = try eip8130_raw(arena, .{
            .tx = tx,
            .sender_auth = sender_auth,
            .payer_auth = payer_auth,
        });
        try expect_transactions_roundtrip(arena, &.{raw}, 10);
    }
}

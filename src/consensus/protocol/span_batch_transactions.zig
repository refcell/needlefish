//! Span batch transaction columns: contract-creation bits, y-parity bits and
//! signatures, `to` addresses, tx data, nonces, gas limits, protected bits, and the
//! trailing EIP-8130 auth-proof column. Decoding, encoding, reconstruction of full
//! signed EIP-2718 transactions (`full_txs`), and the reverse split (`build`).
//! Mirrors base/base `crates/consensus/protocol/src/batch/transactions.rs` and
//! `utils.rs::read_tx_data`.
//!
//! Memory: every allocation comes from the caller's arena. Column buffers borrow the
//! decoded input where the wire layout allows it (signatures, `to` addresses, tx data,
//! auth proofs, and full-length bitlists). Allocation is bounded by the input size:
//! each decoded element consumes at least one input byte, so arrays are sized by
//! `min(count, remaining input)` before parsing.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const bits_module = @import("span_batch_bits.zig");
const tx_data_module = @import("span_batch_tx_data.zig");
const Address = primitives.Address;
const Envelope = consensus.Envelope;
const Signature = consensus.Signature;
const Bits = bits_module.Bits;
const Writer = bits_module.Writer;
const Error = bits_module.Error;
const TxData = tx_data_module.TxData;
const max_span_batch_elements = bits_module.max_span_batch_elements;
const read_uvarint = bits_module.read_uvarint;
const tx_type_of = tx_data_module.tx_type_of;

pub const signature_length = 64;
pub const address_length = 20;

/// The `(sender_proof, payer_proof)` pair of one EIP-8130 transaction.
pub const AuthProofs = tx_data_module.AuthProofs;

/// The `to` column entry: EIP-8130 transactions have none (their contract-creation bit
/// is set, as in base/base `add_txs`).
fn span_to(envelope: Envelope) ?Address {
    if (envelope == .eip8130) return null;
    return envelope.kind().to();
}

/// Reads one transaction's span tx data (`type || rlp_list` or `rlp_list`) and
/// returns it, borrowed from `r`.
pub fn read_tx_data(r: *[]const u8) Error![]const u8 {
    if (r.len == 0) return error.InvalidTransactionData;
    const input = r.*;
    const typed = input[0] <= 0x7f;
    const offset: usize = @intFromBool(typed);
    const header = rlp.decode_header(input[offset..]) catch return error.InvalidTransactionData;
    if (!header.list) return error.InvalidTransactionData;
    const total_length = header.total_length();
    if (total_length > max_span_batch_elements) return error.TooBigSpanBatchSize;
    assert(total_length <= input.len - offset);
    const tx_data = input[0 .. offset + total_length];
    r.* = input[tx_data.len..];
    const tx_type: u8 = if (typed) input[0] else tx_data_module.tx_type_legacy;
    if (!tx_data_module.is_known_tx_type(tx_type)) return error.InvalidTransactionType;
    return tx_data;
}

fn read_uvarints(arena: Allocator, r: *[]const u8, count: u64, err: Error) Error![]u64 {
    // Each varint takes at least one byte, so a short input fails before the bound.
    const capacity: usize = @intCast(@min(count, r.len));
    const values = try arena.alloc(u64, capacity);
    for (0..count) |i| {
        const value = read_uvarint(r) orelse return err;
        assert(i < capacity);
        values[i] = value;
    }
    return values;
}

fn read_auth_proof(r: *[]const u8) Error![]const u8 {
    const length = read_uvarint(r) orelse return error.InvalidAuthData;
    if (length > bits_module.max_auth_proof_bytes) return error.TooBigSpanBatchSize;
    if (r.len < length) return error.InvalidTransactionData;
    const proof = r.*[0..@intCast(length)];
    r.* = r.*[proof.len..];
    assert(proof.len == length);
    return proof;
}

fn count_type(datas: []const []const u8, tx_type: u8) u64 {
    var count: u64 = 0;
    for (datas) |data| count += @intFromBool(tx_type_of(data) == tx_type);
    assert(count <= datas.len);
    return count;
}

pub const Transactions = struct {
    total_block_tx_count: u64 = 0,
    contract_creation_bits: Bits = .empty,
    y_parity_bits: Bits = .empty,
    /// `r || s`, 32 bytes each big-endian, per transaction.
    tx_sigs: []const u8 = &.{},
    /// One 20-byte address per non-creation transaction.
    tx_tos: []const u8 = &.{},
    tx_datas: []const []const u8 = &.{},
    tx_nonces: []const u64 = &.{},
    tx_gases: []const u64 = &.{},
    protected_bits: Bits = .empty,
    legacy_tx_count: u64 = 0,
    eip8130_auth_data: []const AuthProofs = &.{},

    /// Decodes all columns for `total_block_tx_count` transactions from `r`.
    pub fn decode(
        arena: Allocator,
        r: *[]const u8,
        total_block_tx_count: u64,
    ) Error!Transactions {
        if (total_block_tx_count > max_span_batch_elements) return error.TooBigSpanBatchSize;
        const total = total_block_tx_count;
        var txs: Transactions = .{ .total_block_tx_count = total };
        txs.contract_creation_bits = try Bits.decode(arena, r, total);
        txs.y_parity_bits = try Bits.decode(arena, r, total);
        txs.tx_sigs = try take(r, total * signature_length);
        const to_count = total - txs.contract_creation_bits.count_ones();
        txs.tx_tos = try take(r, to_count * address_length);
        txs.tx_datas = try decode_tx_datas(arena, r, total);
        txs.legacy_tx_count = count_type(txs.tx_datas, tx_data_module.tx_type_legacy);
        txs.tx_nonces = try read_uvarints(arena, r, total, error.TxNonces);
        // base/base reports gas decoding failures as nonce failures too.
        txs.tx_gases = try read_uvarints(arena, r, total, error.TxNonces);
        if (txs.legacy_tx_count > max_span_batch_elements) return error.TooBigSpanBatchSize;
        txs.protected_bits = try Bits.decode(arena, r, txs.legacy_tx_count);
        txs.eip8130_auth_data = try decode_auth_data(arena, r, txs.tx_datas);
        assert(txs.tx_datas.len == total);
        return txs;
    }

    fn take(r: *[]const u8, length: u64) Error![]const u8 {
        if (r.len < length) return error.InvalidTransactionData;
        const taken = r.*[0..@intCast(length)];
        r.* = r.*[taken.len..];
        assert(taken.len == length);
        return taken;
    }

    fn decode_tx_datas(arena: Allocator, r: *[]const u8, total: u64) Error![]const []const u8 {
        // Each tx data takes at least one byte, so the capacity bounds every success.
        const capacity: usize = @intCast(@min(total, r.len));
        const datas = try arena.alloc([]const u8, capacity);
        for (0..total) |i| {
            const data = try read_tx_data(r);
            assert(i < capacity);
            datas[i] = data;
        }
        assert(capacity == total);
        return datas[0..@intCast(total)];
    }

    fn decode_auth_data(
        arena: Allocator,
        r: *[]const u8,
        datas: []const []const u8,
    ) Error![]const AuthProofs {
        const count: usize = @intCast(count_type(datas, tx_data_module.tx_type_eip8130));
        const proofs = try arena.alloc(AuthProofs, count);
        var index: usize = 0;
        for (datas) |data| {
            if (tx_type_of(data) != tx_data_module.tx_type_eip8130) continue;
            const sender_proof = try read_auth_proof(r);
            const payer_proof = try read_auth_proof(r);
            proofs[index] = .{ .sender_proof = sender_proof, .payer_proof = payer_proof };
            index += 1;
        }
        assert(index == count);
        return proofs;
    }

    pub fn encode(txs: *const Transactions, writer: *Writer) Error!void {
        const total = txs.total_block_tx_count;
        assert(txs.tx_sigs.len == total * signature_length);
        assert(txs.tx_tos.len % address_length == 0);
        try txs.contract_creation_bits.encode(writer, total);
        try txs.y_parity_bits.encode(writer, total);
        writer.put(txs.tx_sigs);
        writer.put(txs.tx_tos);
        for (txs.tx_datas) |data| writer.put(data);
        for (txs.tx_nonces) |nonce| writer.put_uvarint(nonce);
        for (txs.tx_gases) |gas| writer.put_uvarint(gas);
        try txs.protected_bits.encode(writer, txs.legacy_tx_count);
        for (txs.eip8130_auth_data) |proofs| {
            writer.put_uvarint(proofs.sender_proof.len);
            writer.put(proofs.sender_proof);
            writer.put_uvarint(proofs.payer_proof.len);
            writer.put(proofs.payer_proof);
        }
    }

    pub fn contract_creation_count(txs: *const Transactions) u64 {
        return txs.contract_creation_bits.count_ones();
    }

    fn signature_at(txs: *const Transactions, index: u64) Error!Signature {
        const offset = index * signature_length;
        if (offset + signature_length > txs.tx_sigs.len) return error.InvalidTransactionData;
        const sig = txs.tx_sigs[@intCast(offset)..][0..signature_length];
        const y_parity = txs.y_parity_bits.get_bit(index) orelse
            return error.InvalidTransactionData;
        return .{
            .y_parity = y_parity == 1,
            .r = primitives.u256_from_bytes(sig[0..32].*),
            .s = primitives.u256_from_bytes(sig[32..64].*),
        };
    }

    const Cursor = struct { to_index: usize = 0, protected_index: u64 = 0, auth_index: usize = 0 };

    /// Rebuilds every signed EIP-2718 transaction (base/base `full_txs`).
    pub fn full_txs(
        txs: *const Transactions,
        arena: Allocator,
        chain_id: u64,
    ) Error![]const []const u8 {
        const total: usize = @intCast(txs.total_block_tx_count);
        if (txs.tx_datas.len < total) return error.InvalidTransactionData;
        const out = try arena.alloc([]const u8, total);
        var cursor: Cursor = .{};
        for (out, 0..) |*tx, i| tx.* = try txs.full_tx(arena, chain_id, i, &cursor);
        assert(cursor.to_index * address_length <= txs.tx_tos.len);
        return out;
    }

    fn full_tx(
        txs: *const Transactions,
        arena: Allocator,
        chain_id: u64,
        index: usize,
        cursor: *Cursor,
    ) Error![]const u8 {
        const tx_data = try TxData.decode(txs.tx_datas[index]);
        if (index >= txs.tx_nonces.len) return error.InvalidTransactionData;
        if (index >= txs.tx_gases.len) return error.InvalidTransactionData;
        const bit = txs.contract_creation_bits.get_bit(index) orelse
            return error.InvalidTransactionData;
        var to: ?Address = null;
        if (bit == 0) {
            const offset = cursor.to_index * address_length;
            if (offset + address_length > txs.tx_tos.len) return error.InvalidTransactionData;
            to = Address.from_slice(txs.tx_tos[offset..][0..address_length]);
            cursor.to_index += 1;
        }
        const nonce = txs.tx_nonces[index];
        const gas = txs.tx_gases[index];
        if (tx_data == .eip8130) {
            // Reassembled from the remainder and the trailing auth column.
            if (cursor.auth_index >= txs.eip8130_auth_data.len) return error.InvalidTransactionData;
            const proofs = txs.eip8130_auth_data[cursor.auth_index];
            cursor.auth_index += 1;
            const data = &tx_data.eip8130;
            const signed = try data.to_signed(arena, chain_id, nonce, gas, proofs);
            return encode_envelope_alloc(arena, .{ .eip8130 = signed });
        }
        const signature = try txs.signature_at(index);
        var protected = true;
        if (tx_data == .legacy) {
            protected = (txs.protected_bits.get_bit(cursor.protected_index) orelse 0) == 1;
            cursor.protected_index += 1;
        }
        const envelope = try tx_data.to_envelope(nonce, gas, to, chain_id, signature, protected);
        return encode_envelope_alloc(arena, envelope);
    }

    fn encode_envelope_alloc(arena: Allocator, envelope: Envelope) Error![]const u8 {
        const buffer = try arena.alloc(u8, envelope.encoded_length());
        const encoded = envelope.encode_to(buffer);
        assert(encoded.len == buffer.len);
        return encoded;
    }

    /// Splits signed EIP-2718 transactions into columns (base/base `add_txs` over
    /// the concatenated transactions of every block in the span).
    pub fn build(
        arena: Allocator,
        raw_txs: []const []const u8,
        chain_id: u64,
    ) Error!Transactions {
        if (raw_txs.len > max_span_batch_elements) return error.TooBigSpanBatchSize;
        const envelopes = try arena.alloc(Envelope, raw_txs.len);
        var counts: Builder.Counts = .{};
        for (raw_txs, envelopes) |raw, *envelope| {
            envelope.* = try decode_envelope(raw, chain_id);
            counts.legacy += @intFromBool(envelope.* == .legacy);
            counts.to += @intFromBool(span_to(envelope.*) != null);
            counts.eip8130 += @intFromBool(envelope.* == .eip8130);
        }
        var builder = try Builder.init(arena, raw_txs.len, counts);
        for (envelopes, 0..) |envelope, i| try builder.add(arena, i, envelope);
        return builder.finish();
    }

    const Builder = struct {
        contract_bits: []u8,
        parity_bits: []u8,
        protected_bits: []u8,
        sigs: []u8,
        tos: []u8,
        datas: [][]const u8,
        nonces: []u64,
        gases: []u64,
        auth: []AuthProofs,
        legacy_count: u64,
        to_index: usize = 0,
        legacy_index: u64 = 0,
        auth_index: usize = 0,

        const Counts = struct { legacy: u64 = 0, to: usize = 0, eip8130: usize = 0 };

        fn init(arena: Allocator, total: usize, counts: Counts) Error!Builder {
            const legacy_count = counts.legacy;
            const to_count = counts.to;
            assert(legacy_count <= total);
            assert(to_count + counts.eip8130 <= total);
            return .{
                .contract_bits = try zeroed(arena, bits_module.bits_buffer_length(total)),
                .parity_bits = try zeroed(arena, bits_module.bits_buffer_length(total)),
                .protected_bits = try zeroed(arena, bits_module.bits_buffer_length(legacy_count)),
                .sigs = try arena.alloc(u8, total * signature_length),
                .tos = try arena.alloc(u8, to_count * address_length),
                .datas = try arena.alloc([]const u8, total),
                .nonces = try arena.alloc(u64, total),
                .gases = try arena.alloc(u64, total),
                .auth = try arena.alloc(AuthProofs, counts.eip8130),
                .legacy_count = legacy_count,
            };
        }

        fn add(builder: *Builder, arena: Allocator, index: usize, envelope: Envelope) Error!void {
            assert(index < builder.datas.len);
            // EIP-8130 carries a zero signature in the column (base/base `add_txs`).
            const zero: Signature = .{ .y_parity = false, .r = 0, .s = 0 };
            const signature = envelope.signature() orelse zero;
            assert(envelope.signature() != null or envelope == .eip8130);
            Bits.set_bit(builder.parity_bits, index, signature.y_parity);
            const sig = builder.sigs[index * signature_length ..][0..signature_length];
            sig[0..32].* = primitives.u256_to_bytes(signature.r);
            sig[32..64].* = primitives.u256_to_bytes(signature.s);
            if (envelope == .eip8130) {
                // Proof: decode_envelope already split this envelope successfully.
                const split = tx_data_module.Eip8130.from_signed(envelope.eip8130) catch
                    unreachable;
                builder.auth[builder.auth_index] = split.proofs;
                builder.auth_index += 1;
            }
            if (span_to(envelope)) |address| {
                const offset = builder.to_index * address_length;
                builder.tos[offset..][0..address_length].* = address.bytes;
                builder.to_index += 1;
            } else Bits.set_bit(builder.contract_bits, index, true);
            if (envelope == .legacy) {
                const protected = envelope.legacy.tx.chain_id != null;
                Bits.set_bit(builder.protected_bits, builder.legacy_index, protected);
                builder.legacy_index += 1;
            }
            // Proof: decode_envelope already ran from_envelope on this envelope.
            const tx_data = TxData.from_envelope(envelope) catch unreachable;
            const buffer = try arena.alloc(u8, tx_data.encoded_length());
            builder.datas[index] = tx_data.encode(buffer);
            builder.nonces[index] = envelope.nonce().?;
            builder.gases[index] = envelope.gas_limit();
        }

        fn finish(builder: *const Builder) Transactions {
            assert(builder.to_index * address_length == builder.tos.len);
            assert(builder.legacy_index == builder.legacy_count);
            assert(builder.auth_index == builder.auth.len);
            return .{
                .total_block_tx_count = builder.datas.len,
                .contract_creation_bits = .{ .bytes = builder.contract_bits },
                .y_parity_bits = .{ .bytes = builder.parity_bits },
                .tx_sigs = builder.sigs,
                .tx_tos = builder.tos,
                .tx_datas = builder.datas,
                .tx_nonces = builder.nonces,
                .tx_gases = builder.gases,
                .protected_bits = .{ .bytes = builder.protected_bits },
                .legacy_tx_count = builder.legacy_count,
                .eip8130_auth_data = builder.auth,
            };
        }
    };

    fn zeroed(arena: Allocator, length: usize) Error![]u8 {
        const buffer = try arena.alloc(u8, length);
        @memset(buffer, 0);
        assert(buffer.len == length);
        return buffer;
    }

    /// Decodes one signed transaction and checks it may be carried in a span batch.
    fn decode_envelope(raw: []const u8, chain_id: u64) Error!Envelope {
        const envelope = Envelope.decode(raw) catch return error.InvalidTransactionData;
        _ = try TxData.from_envelope(envelope);
        assert(envelope != .deposit and envelope != .eip4844);
        const tx_chain_id = envelope.chain_id();
        if (envelope == .legacy and tx_chain_id == null) return envelope;
        if (tx_chain_id != chain_id) return error.InvalidTransactionData;
        return envelope;
    }
};

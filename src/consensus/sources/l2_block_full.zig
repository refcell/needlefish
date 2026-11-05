//! Decodes a full L2 `eth_getBlockByNumber(n, true)` result into the consolidation view
//! (`attributes_match.L2Block`): the hash-verified header fields, the withdrawals, and
//! every transaction rebuilt as EIP-2718 bytes, including OP deposits (type 0x7e). Each
//! rebuilt transaction must hash to its reported `hash` and the rebuilt list must match the
//! header's transactions root, so the returned bytes are the bytes of that block.
//! The `L2BlockInfo` comes from the L1 info deposit (or the rollup genesis), as in
//! `l2_block.zig`. All memory comes from the caller's arena.
//! Mirrors base/base `L2BlockInfo::from_block_and_genesis` plus the full-block fetch that
//! `AttributesMatch` compares against.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const object = @import("json_object.zig");
const header_json = @import("header_json.zig");
const transaction_json = @import("transaction_json.zig");
const engine_json = @import("engine_json.zig");
const l2_block = @import("l2_block.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const ordered = @import("../../execution/trie/ordered.zig");
const protocol = @import("../protocol/root.zig");
const attributes_match = @import("../engine/attributes_match.zig");
const insert_task = @import("../engine/insert_task.zig");

const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const L2BlockInfo = protocol.block.L2BlockInfo;
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;

pub const L2Block = attributes_match.L2Block;
/// A block as an engine insert (`newPayload`) envelope, for follow mode.
pub const PayloadEnvelope = insert_task.Envelope;

pub const Error = l2_block.Error || transaction_json.Error;

pub const Limits = struct {
    transactions: transaction_json.Limits = .{},
    withdrawals_max: u32 = 16,
};

/// The block-level arrays, still raw.
const Body = struct {
    transactions: []const u8,
    withdrawals: ?[]const u8,
};

/// Decodes a full L2 block. Slices of the result live in `arena`.
pub fn decode(
    arena: Allocator,
    raw: []const u8,
    genesis: *const ChainGenesis,
    limits: Limits,
) Error!L2Block {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const header = &decoded.header;
    const body = try scan_body(raw);
    const transactions = try decode_transactions(
        arena,
        body.transactions,
        header.transactions_root,
        limits.transactions,
    );
    const info = try block_info(&decoded, transactions, genesis);
    const withdrawal_limits: engine_json.Limits = .{ .withdrawals_max = limits.withdrawals_max };
    const withdrawals = if (body.withdrawals) |list|
        try engine_json.decode_withdrawals(arena, list, withdrawal_limits)
    else
        null;
    const block: L2Block = .{
        .info = info,
        .prev_randao = header.mix_hash,
        .gas_limit = header.gas_limit,
        .fee_recipient = header.beneficiary,
        .extra_data = try arena.dupe(u8, header.extra_data),
        .withdrawals_root = header.withdrawals_root,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .withdrawals = withdrawals,
        .transactions = transactions,
    };
    assert(block.info.block_info.hash.eql(decoded.hash));
    assert(block.transactions.len == transactions.len);
    return block;
}

/// Decodes a full L2 block into the execution payload that produced it (base/base
/// `BaseExecutionPayloadEnvelope::from_block_unchecked`, used by follow mode). The header
/// hash and transactions root are verified like `decode`. Slices live in `arena`.
pub fn decode_envelope(arena: Allocator, raw: []const u8, limits: Limits) Error!PayloadEnvelope {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const header = &decoded.header;
    const base_fee = header.base_fee_per_gas orelse return error.MissingField;
    const body = try scan_body(raw);
    const transactions = try decode_transactions(
        arena,
        body.transactions,
        header.transactions_root,
        limits.transactions,
    );
    const withdrawal_limits: engine_json.Limits = .{ .withdrawals_max = limits.withdrawals_max };
    const withdrawals = if (body.withdrawals) |list|
        try engine_json.decode_withdrawals(arena, list, withdrawal_limits)
    else
        null;
    const envelope: PayloadEnvelope = .{
        .payload = .{
            .parent_hash = header.parent_hash,
            .fee_recipient = header.beneficiary,
            .state_root = header.state_root,
            .receipts_root = header.receipts_root,
            .logs_bloom = header.logs_bloom,
            .prev_randao = header.mix_hash,
            .block_number = header.number,
            .gas_limit = header.gas_limit,
            .gas_used = header.gas_used,
            .timestamp = header.timestamp,
            .extra_data = try arena.dupe(u8, header.extra_data),
            .base_fee_per_gas = base_fee,
            .block_hash = decoded.hash,
            .transactions = transactions,
            .withdrawals = withdrawals,
            .blob_gas_used = header.blob_gas_used,
            .excess_blob_gas = header.excess_blob_gas,
            .withdrawals_root = if (header.requests_hash != null) header.withdrawals_root else null,
        },
        .parent_beacon_block_root = header.parent_beacon_block_root,
    };
    assert(envelope.payload.block_hash.eql(decoded.hash));
    assert(envelope.payload.transactions.len == transactions.len);
    return envelope;
}

fn scan_body(raw: []const u8) Error!Body {
    var iterator = try object.ObjectIterator.init(raw);
    var transactions: ?[]const u8 = null;
    var withdrawals: ?[]const u8 = null;
    var fields: u32 = 0;
    while (try iterator.next()) |field| : (fields += 1) {
        assert(fields <= raw.len);
        const is_transactions = std.mem.eql(u8, field.key, "transactions");
        const is_withdrawals = std.mem.eql(u8, field.key, "withdrawals");
        if (!is_transactions and !is_withdrawals) continue;
        if (field.value.tag != .array_begin) return error.InvalidJson;
        const slot = if (is_transactions) &transactions else &withdrawals;
        if (slot.* != null) return error.InvalidJson; // Duplicate key.
        slot.* = field.raw;
    }
    const list = transactions orelse return error.MissingField;
    assert(list[0] == '[');
    return .{ .transactions = list, .withdrawals = withdrawals };
}

/// Rebuilds every transaction object as EIP-2718 bytes and checks the transactions root.
fn decode_transactions(
    arena: Allocator,
    raw: []const u8,
    transactions_root: B256,
    limits: transaction_json.Limits,
) Error![]const []const u8 {
    const count = try object.array_count(raw, limits.transactions_max);
    const items = try arena.alloc([]const u8, count);
    const options: transaction_json.Options = .{
        .limits = limits,
        .verify_root = false,
        .recover_senders = false,
    };
    var iterator = try object.ArrayIterator.init(raw);
    for (items) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        if (element.value.tag != .object_begin) return error.InvalidJson; // Hashes only.
        const decoded = try transaction_json.decode(arena, arena, element.raw, options);
        const envelope = decoded.envelope orelse return error.UnsupportedTransaction;
        const bytes = try arena.alloc(u8, envelope.encoded_length());
        item.* = envelope.encode_to(bytes);
        assert(item.len == bytes.len);
    }
    assert(try iterator.next() == null);
    const root: B256 = .{ .bytes = ordered.ordered_trie_root(items) };
    if (!root.eql(transactions_root)) return error.RootMismatch;
    return items;
}

/// The block's position: genesis anchors at the rollup genesis; every other block reads
/// its L1 origin and sequence number from the leading L1 info deposit.
fn block_info(
    decoded: *const header_json.Decoded,
    transactions: []const []const u8,
    genesis: *const ChainGenesis,
) Error!L2BlockInfo {
    const info = decoded.block_info();
    if (info.number == genesis.l2.number) {
        if (!info.hash.eql(genesis.l2.hash)) return error.GenesisMismatch;
        return .{ .block_info = info, .l1_origin = genesis.l1, .sequence_number = 0 };
    }
    if (transactions.len == 0) return error.MissingL1InfoDeposit;
    const first = transactions[0];
    assert(first.len > 0);
    if (first[0] != transaction_json.deposit_tx_type) return error.MissingL1InfoDeposit;
    // Proof: the bytes were just encoded from a decoded deposit envelope.
    const envelope = Envelope.decode(first) catch unreachable;
    const l1_info = L1BlockInfo.decode_calldata(envelope.deposit.input) catch
        return error.InvalidL1Info;
    return .{
        .block_info = info,
        .l1_origin = l1_info.id(),
        .sequence_number = l1_info.sequence_number,
    };
}

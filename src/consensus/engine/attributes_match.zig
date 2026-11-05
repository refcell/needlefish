//! Consolidation check: do derived payload attributes describe an L2 block the execution
//! engine already has? Compares parent hash, timestamp, prev randao, transactions (byte
//! equality, then canonical decoding to tell a malformed attribute apart from a different
//! one), gas limit, withdrawals (Bedrock/Canyon/Isthmus rules), parent beacon block root,
//! fee recipient, and the Holocene/Jovian EIP-1559 parameters in `extra_data`.
//! Mirrors base/base `crates/consensus/engine/src/attributes.rs` (`AttributesMatch`).

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const tx = @import("../../common/consensus/tx.zig");
const basefee = @import("../../execution/chainspec/basefee.zig");
const protocol = @import("../protocol/root.zig");
const derive_attributes = @import("../derive/attributes.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const Address = primitives.Address;
const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Withdrawal = derive_attributes.Withdrawal;

pub const deposit_tx_type: u8 = 0x7e;

/// The fields of an L2 block that consolidation compares against derived attributes.
/// `transactions` are EIP-2718 encoded. Slices borrow the engine client's memory.
pub const L2Block = struct {
    info: L2BlockInfo,
    prev_randao: B256 = .zero,
    gas_limit: u64 = 0,
    fee_recipient: Address = .zero,
    extra_data: []const u8 = &.{},
    withdrawals_root: ?B256 = null,
    parent_beacon_block_root: ?B256 = null,
    withdrawals: ?[]const Withdrawal = null,
    transactions: []const []const u8 = &.{},
};

/// EIP-1559 parameters as compared by consolidation (`BaseFeeParams`).
pub const FeeParams = struct {
    elasticity: u64,
    denominator: u64,

    pub fn eql(a: FeeParams, b: FeeParams) bool {
        return a.elasticity == b.elasticity and a.denominator == b.denominator;
    }
};

/// Post-Canyon EIP-1559 parameters of Base and OP mainnet (`post_canyon_params`), used when
/// Holocene attributes carry the all-zero `eip1559Params`.
pub const fee_params_canyon_default: FeeParams = .{ .elasticity = 6, .denominator = 250 };

/// Why attributes do not match a block (`AttributesMismatch`). base/base's
/// `MalformedBlockTransactions` (hash-only block bodies) and `MissingAttributesGasLimit`
/// cannot occur here: blocks always carry encoded transactions and the gas limit is
/// mandatory in derived attributes.
pub const Mismatch = union(enum) {
    parent_hash: [2]B256,
    timestamp: [2]u64,
    prev_randao: [2]B256,
    /// Index of an attribute transaction that is not canonically encoded.
    malformed_attributes_transaction: u32,
    transaction_len: [2]u64,
    transaction_content: struct { index: u32, attributes: B256, block: B256 },
    missing_attributes_eip1559,
    missing_block_eip1559,
    missing_attributes_min_base_fee,
    min_base_fee: [2]u64,
    invalid_extra_data_version,
    /// `UnknownExtraDataDecodingError(InvalidExtraDataLength)`.
    invalid_extra_data_length,
    invalid_eip1559_params_combination,
    eip1559_parameters: struct { attributes: FeeParams, block: FeeParams },
    gas_limit: [2]u64,
    fee_recipient: [2]Address,
    parent_beacon_block_root: [2]?B256,
    canyon_withdrawals_not_empty,
    canyon_not_empty_hash,
    bedrock_withdrawals,
    isthmus_missing_withdrawals_root,
};

/// Returns null when `attributes` match `block`, otherwise the first mismatch found, in
/// base/base's check order.
pub fn check(
    config: *const RollupConfig,
    fee_params_canyon: FeeParams,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) ?Mismatch {
    const payload = &attributes.attributes;
    const header = block.info.block_info;
    if (!attributes.parent.block_info.hash.eql(header.parent_hash)) {
        return .{ .parent_hash = .{ attributes.parent.block_info.hash, header.parent_hash } };
    }
    if (payload.timestamp != header.timestamp) {
        return .{ .timestamp = .{ payload.timestamp, header.timestamp } };
    }
    if (!payload.prev_randao.eql(block.prev_randao)) {
        return .{ .prev_randao = .{ payload.prev_randao, block.prev_randao } };
    }
    if (check_transactions(payload.transactions, block.transactions)) |m| return m;
    if (payload.gas_limit != block.gas_limit) {
        return .{ .gas_limit = .{ payload.gas_limit, block.gas_limit } };
    }
    if (check_withdrawals(config, payload.withdrawals, block)) |m| return m;
    if (!optional_hash_eql(payload.parent_beacon_block_root, block.parent_beacon_block_root)) {
        return .{ .parent_beacon_block_root = .{
            payload.parent_beacon_block_root,
            block.parent_beacon_block_root,
        } };
    }
    if (!payload.suggested_fee_recipient.eql(block.fee_recipient)) {
        return .{ .fee_recipient = .{ payload.suggested_fee_recipient, block.fee_recipient } };
    }
    const result = check_eip1559(config, fee_params_canyon, attributes, block);
    assert(result == null or result.? != .parent_hash);
    return result;
}

fn optional_hash_eql(a: ?B256, b: ?B256) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    assert(a != null and b != null);
    return a.?.eql(b.?);
}

/// Bedrock: no withdrawals in the attributes. Canyon: both lists present and empty, and
/// (before Isthmus) the empty withdrawals root. Isthmus: the withdrawals root is set.
fn check_withdrawals(
    config: *const RollupConfig,
    attributes_withdrawals: ?[]const Withdrawal,
    block: *const L2Block,
) ?Mismatch {
    const timestamp = block.info.block_info.timestamp;
    const isthmus = config.is_feature_active(.l2_to_l1_message_root, timestamp);
    if (config.is_feature_active(.withdrawals, timestamp)) {
        const attributes_empty = if (attributes_withdrawals) |w| w.len == 0 else false;
        if (!attributes_empty) return .canyon_withdrawals_not_empty;
        const block_empty = if (block.withdrawals) |w| w.len == 0 else false;
        if (!block_empty) return .canyon_withdrawals_not_empty;
        if (!isthmus) {
            const root = block.withdrawals_root orelse return .canyon_not_empty_hash;
            if (!root.eql(primitives.empty_root_hash)) return .canyon_not_empty_hash;
        }
    } else if (attributes_withdrawals != null) {
        return .bedrock_withdrawals;
    }
    if (isthmus and block.withdrawals_root == null) return .isthmus_missing_withdrawals_root;
    assert(!isthmus or config.is_feature_active(.withdrawals, timestamp));
    return null;
}

fn check_transactions(
    attributes_transactions: []const []const u8,
    block_transactions: []const []const u8,
) ?Mismatch {
    if (attributes_transactions.len != block_transactions.len) {
        return .{ .transaction_len = .{
            attributes_transactions.len,
            block_transactions.len,
        } };
    }
    for (attributes_transactions, block_transactions, 0..) |attribute_tx, block_tx, index| {
        if (std.mem.eql(u8, attribute_tx, block_tx)) continue;
        const index_u32: u32 = @intCast(index);
        if (!is_canonical(attribute_tx)) return .{ .malformed_attributes_transaction = index_u32 };
        return .{ .transaction_content = .{
            .index = index_u32,
            .attributes = primitives.keccak256(attribute_tx),
            .block = primitives.keccak256(block_tx),
        } };
    }
    assert(attributes_transactions.len == block_transactions.len);
    return null;
}

/// True when `encoded` decodes as one EIP-2718 transaction whose re-encoding is identical
/// (`decode_2718_canonical`): the hash of the re-encoding equals the hash of the input.
fn is_canonical(encoded: []const u8) bool {
    const envelope = tx.Envelope.decode(encoded) catch return false;
    if (envelope.encoded_length() != encoded.len) return false;
    assert(encoded.len > 0);
    return envelope.hash().eql(primitives.keccak256(encoded));
}

/// Holocene `eip1559Params`: denominator then elasticity, big endian.
pub fn decode_eip1559_params(params: [8]u8) FeeParams {
    const result: FeeParams = .{
        .denominator = std.mem.readInt(u32, params[0..4], .big),
        .elasticity = std.mem.readInt(u32, params[4..8], .big),
    };
    assert(result.denominator <= std.math.maxInt(u32));
    assert(result.elasticity <= std.math.maxInt(u32));
    return result;
}

fn check_eip1559(
    config: *const RollupConfig,
    fee_params_canyon: FeeParams,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) ?Mismatch {
    const timestamp = block.info.block_info.timestamp;
    const holocene = config.is_feature_active(.dynamic_base_fee_parameters, timestamp);
    const params = attributes.attributes.eip1559_params orelse {
        if (holocene) return .missing_attributes_eip1559;
        return null;
    };
    var expected = decode_eip1559_params(params);
    if (expected.elasticity == 0 and expected.denominator != 0) {
        return .invalid_eip1559_params_combination;
    }
    if (expected.elasticity == 0 and expected.denominator == 0) expected = fee_params_canyon;
    const jovian = config.is_feature_active(.min_base_fee, timestamp);
    if (!jovian and !holocene) return .missing_block_eip1559;
    const decoded = if (jovian)
        basefee.decode_jovian(block.extra_data)
    else
        basefee.decode_holocene(block.extra_data);
    const extra = decoded catch |err| return switch (err) {
        error.InvalidExtraDataVersion => .invalid_extra_data_version,
        error.InvalidExtraDataLength, error.InvalidEip1559Params => .invalid_extra_data_length,
    };
    const actual: FeeParams = .{ .elasticity = extra.elasticity, .denominator = extra.denominator };
    if (!expected.eql(actual)) {
        return .{ .eip1559_parameters = .{ .attributes = expected, .block = actual } };
    }
    if (!jovian) return null;
    const min_base_fee = attributes.attributes.min_base_fee orelse
        return .missing_attributes_min_base_fee;
    if (min_base_fee != extra.min_base_fee) {
        return .{ .min_base_fee = .{ min_base_fee, extra.min_base_fee } };
    }
    assert(jovian);
    return null;
}

/// True when every transaction is a deposit (`is_deposits_only`).
pub fn is_deposits_only(transactions: []const []const u8) bool {
    for (transactions) |transaction| {
        if (transaction.len == 0 or transaction[0] != deposit_tx_type) return false;
    }
    assert(deposits_prefix_len(transactions) == transactions.len);
    return true;
}

/// Number of leading deposit transactions. Derived and sequenced attributes place every
/// deposit before the batch transactions, so this prefix is the deposits-only payload.
pub fn deposits_prefix_len(transactions: []const []const u8) u32 {
    var count: u32 = 0;
    for (transactions) |transaction| {
        if (transaction.len == 0 or transaction[0] != deposit_tx_type) break;
        count += 1;
    }
    assert(count <= transactions.len);
    return count;
}

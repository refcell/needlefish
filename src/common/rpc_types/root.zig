//! Ethereum/Base JSON-RPC object forms: logs, transactions, receipts, headers, blocks.
//! Mirrors base/base `crates/common/rpc-types` (alloy serde field names, Base deposit
//! and L1-fee receipt extensions). Writers stream to a `std.Io.Writer`; callers supply
//! the block/position context that the consensus types do not carry.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const consensus = @import("../consensus/root.zig");
pub const json = @import("json.zig");
pub const eip8130 = @import("eip8130.zig");
pub const request = @import("request.zig");
pub const transaction = @import("transaction.zig");

const Writer = std.Io.Writer;
const Object = json.Object;
const Error = json.Error;
const Address = primitives.Address;
const B256 = primitives.B256;
const tx = consensus.tx;
const Envelope = tx.Envelope;
const Signature = consensus.signature.Signature;

/// Where a transaction, receipt or log sits. Null fields serialize as `null` (pending).
pub const Position = struct {
    block_hash: ?B256 = null,
    block_number: ?u64 = null,
    transaction_index: ?u64 = null,
    transaction_hash: ?B256 = null,
};

fn write_position(object: *Object, position: Position) Error!void {
    try object.fixed_or_null("blockHash", position.block_hash);
    try object.quantity_or_null("blockNumber", position.block_number);
    try object.quantity_or_null("transactionIndex", position.transaction_index);
}

pub fn write_log(
    w: *Writer,
    log: consensus.receipt.Log,
    position: Position,
    index: ?u64,
) Error!void {
    var object = try Object.begin(w);
    try object.address("address", log.address);
    try object.key("topics");
    try w.writeByte('[');
    for (0..log.topics.count()) |topic_index| {
        if (topic_index > 0) try w.writeByte(',');
        try json.write_data(w, &log.topics.get(topic_index).bytes);
    }
    try w.writeByte(']');
    try object.data("data", log.data);
    try write_position(&object, position);
    try object.fixed_or_null("transactionHash", position.transaction_hash);
    try object.quantity_or_null("logIndex", index);
    try object.boolean("removed", false);
    try object.end();
}

pub const TransactionContext = struct {
    hash: B256,
    /// Recovered sender (ignored for deposits, which carry `from`).
    from: Address,
    position: Position = .{},
    /// Mined dynamic-fee transactions report the effective price as `gasPrice`.
    effective_gas_price: ?u128 = null,
    block_timestamp: ?u64 = null,
    block_timestamp_ms: ?u64 = null,
    /// Deposits: the nonce and receipt version from the receipt.
    deposit_nonce: ?u64 = null,
    deposit_receipt_version: ?u64 = null,
};

pub fn write_transaction(w: *Writer, envelope: Envelope, context: TransactionContext) Error!void {
    var object = try Object.begin(w);
    try object.quantity("type", @backingInt(envelope.tx_type()));
    try object.fixed("hash", context.hash);
    const price = context.effective_gas_price;
    switch (envelope) {
        .legacy => |signed| try write_legacy(&object, signed),
        .eip2930 => |signed| try write_eip2930(&object, signed),
        .eip1559 => |signed| try write_eip1559(&object, signed, price),
        .eip4844 => |signed| try write_eip4844(&object, signed, price),
        .eip7702 => |signed| try write_eip7702(&object, signed, price),
        .eip8130 => |signed| try eip8130.write_fields(&object, signed, price),
        .deposit => |deposit| try write_deposit(&object, deposit, context),
    }
    if (envelope != .deposit) try object.address("from", context.from);
    try write_position(&object, context.position);
    try object.optional_quantity("blockTimestamp", context.block_timestamp);
    try object.optional_quantity("blockTimestampMs", context.block_timestamp_ms);
    try object.end();
}

fn write_to(object: *Object, to: tx.TxKind) Error!void {
    try object.address_or_null("to", switch (to) {
        .call => |address| address,
        .create => null,
    });
}

fn write_typed_signature(object: *Object, signature: Signature) Error!void {
    const parity: u8 = @intFromBool(signature.y_parity);
    try object.quantity("r", signature.r);
    try object.quantity("s", signature.s);
    try object.quantity("v", parity);
    try object.quantity("yParity", parity);
}

fn write_legacy(object: *Object, signed: tx.Signed(tx.Legacy)) Error!void {
    const t = signed.tx;
    try object.optional_quantity("chainId", t.chain_id);
    try object.quantity("nonce", t.nonce);
    try object.quantity("gasPrice", t.gas_price);
    try object.quantity("gas", t.gas_limit);
    try write_to(object, t.to);
    try object.quantity("value", t.value);
    try object.data("input", t.input);
    try object.quantity("r", signed.signature.r);
    try object.quantity("s", signed.signature.s);
    try object.quantity("v", signed.signature.legacy_v(t.chain_id));
}

fn write_eip2930(object: *Object, signed: tx.Signed(tx.Eip2930)) Error!void {
    const t = signed.tx;
    try object.quantity("chainId", t.chain_id);
    try object.quantity("nonce", t.nonce);
    try object.quantity("gasPrice", t.gas_price);
    try object.quantity("gas", t.gas_limit);
    try write_to(object, t.to);
    try object.quantity("value", t.value);
    try object.data("input", t.input);
    try write_access_list(object, t.access_list);
    try write_typed_signature(object, signed.signature);
}

/// Fields shared by every EIP-1559-priced transaction.
fn write_dynamic_fee(object: *Object, t: anytype, effective_gas_price: ?u128) Error!void {
    try object.quantity("chainId", t.chain_id);
    try object.quantity("nonce", t.nonce);
    try object.quantity("gas", t.gas_limit);
    try object.quantity("maxFeePerGas", t.max_fee_per_gas);
    try object.quantity("maxPriorityFeePerGas", t.max_priority_fee_per_gas);
    try object.quantity("gasPrice", effective_gas_price orelse t.max_fee_per_gas);
    try object.quantity("value", t.value);
    try object.data("input", t.input);
    try write_access_list(object, t.access_list);
}

fn write_eip1559(object: *Object, signed: tx.Signed(tx.Eip1559), price: ?u128) Error!void {
    try write_dynamic_fee(object, signed.tx, price);
    try write_to(object, signed.tx.to);
    try write_typed_signature(object, signed.signature);
}

fn write_eip4844(object: *Object, signed: tx.Signed(tx.Eip4844), price: ?u128) Error!void {
    const t = signed.tx;
    try write_dynamic_fee(object, t, price);
    try object.address("to", t.to);
    try object.quantity("maxFeePerBlobGas", t.max_fee_per_blob_gas);
    try object.key("blobVersionedHashes");
    try write_hash_list(object.w, t.blob_versioned_hashes);
    try write_typed_signature(object, signed.signature);
}

fn write_eip7702(object: *Object, signed: tx.Signed(tx.Eip7702), price: ?u128) Error!void {
    const t = signed.tx;
    try write_dynamic_fee(object, t, price);
    try object.address("to", t.to);
    try object.key("authorizationList");
    try object.w.writeByte('[');
    var iterator = t.authorization_list.iterator();
    var first = true;
    while (iterator.next()) |authorization| {
        if (!first) try object.w.writeByte(',');
        first = false;
        var item = try Object.begin(object.w);
        try item.quantity("chainId", authorization.chain_id);
        try item.address("address", authorization.address);
        try item.quantity("nonce", authorization.nonce);
        try item.quantity("yParity", authorization.y_parity);
        try item.quantity("r", authorization.r);
        try item.quantity("s", authorization.s);
        try item.end();
    }
    try object.w.writeByte(']');
    try write_typed_signature(object, signed.signature);
}

fn write_deposit(object: *Object, deposit: tx.Deposit, context: TransactionContext) Error!void {
    try object.fixed("sourceHash", deposit.source_hash);
    try object.address("from", deposit.from);
    try write_to(object, deposit.to);
    try object.quantity("mint", deposit.mint);
    try object.quantity("value", deposit.value);
    try object.quantity("gas", deposit.gas_limit);
    try object.boolean("isSystemTx", deposit.is_system_transaction);
    try object.data("input", deposit.input);
    try object.optional_quantity("nonce", context.deposit_nonce);
    try object.optional_quantity("depositReceiptVersion", context.deposit_receipt_version);
}

pub fn write_hash_list(w: *Writer, list: consensus.tx_fields.HashList) Error!void {
    try w.writeByte('[');
    for (0..list.count()) |index| {
        if (index > 0) try w.writeByte(',');
        try json.write_data(w, &list.get(index).bytes);
    }
    try w.writeByte(']');
}

fn write_access_list(object: *Object, list: tx.AccessList) Error!void {
    try object.key("accessList");
    try object.w.writeByte('[');
    var iterator = list.iterator();
    var first = true;
    while (iterator.next()) |item| {
        if (!first) try object.w.writeByte(',');
        first = false;
        var entry = try Object.begin(object.w);
        try entry.address("address", item.address);
        try entry.key("storageKeys");
        try write_hash_list(object.w, item.storage_keys);
        try entry.end();
    }
    try object.w.writeByte(']');
}

/// Base receipt L1-fee fields; each is omitted when null.
pub const L1BlockInfo = struct {
    l1_gas_price: ?u128 = null,
    l1_gas_used: ?u128 = null,
    l1_fee: ?u128 = null,
    /// Pre-Ecotone scalar, already decimal-scaled by the caller (e.g. "0.684").
    l1_fee_scalar: ?[]const u8 = null,
    l1_base_fee_scalar: ?u128 = null,
    l1_blob_base_fee: ?u128 = null,
    l1_blob_base_fee_scalar: ?u128 = null,
    operator_fee_scalar: ?u128 = null,
    operator_fee_constant: ?u128 = null,
    da_footprint_gas_scalar: ?u16 = null,
};

fn write_l1_block_info(object: *Object, info: L1BlockInfo) Error!void {
    try object.optional_quantity("l1GasPrice", info.l1_gas_price);
    try object.optional_quantity("l1GasUsed", info.l1_gas_used);
    try object.optional_quantity("l1Fee", info.l1_fee);
    if (info.l1_fee_scalar) |scalar| {
        try object.key("l1FeeScalar");
        try object.w.print("\"{s}\"", .{scalar});
    }
    try object.optional_quantity("l1BaseFeeScalar", info.l1_base_fee_scalar);
    try object.optional_quantity("l1BlobBaseFee", info.l1_blob_base_fee);
    try object.optional_quantity("l1BlobBaseFeeScalar", info.l1_blob_base_fee_scalar);
    try object.optional_quantity("operatorFeeScalar", info.operator_fee_scalar);
    try object.optional_quantity("operatorFeeConstant", info.operator_fee_constant);
    try object.optional_quantity("daFootprintGasScalar", info.da_footprint_gas_scalar);
}

pub const ReceiptContext = struct {
    position: Position,
    from: Address,
    to: ?Address,
    contract_address: ?Address = null,
    gas_used: u64,
    effective_gas_price: u128,
    blob_gas_used: ?u64 = null,
    blob_gas_price: ?u128 = null,
    /// Block-wide index of this receipt's first log.
    first_log_index: u64,
    l1_block_info: L1BlockInfo = .{},
    /// EIP-8130 extras: the payer, the transaction's phase count and metadata.
    payer: ?Address = null,
    phase_count: ?u64 = null,
    metadata: ?[]const u8 = null,
};

pub fn write_receipt(
    w: *Writer,
    receipt: consensus.receipt.Receipt,
    context: ReceiptContext,
) Error!void {
    assert(context.position.transaction_hash != null);
    var object = try Object.begin(w);
    try object.quantity("type", @backingInt(receipt.tx_type));
    try object.quantity("status", @intFromBool(receipt.status));
    try object.quantity("cumulativeGasUsed", receipt.cumulative_gas_used);
    try object.key("logs");
    try w.writeByte('[');
    var iterator = receipt.logs.iterator();
    var log_index = context.first_log_index;
    while (iterator.next()) |log| : (log_index += 1) {
        if (log_index > context.first_log_index) try w.writeByte(',');
        try write_log(w, log, context.position, log_index);
    }
    try w.writeByte(']');
    try object.fixed("logsBloom", receipt.logs_bloom);
    try object.fixed_or_null("transactionHash", context.position.transaction_hash);
    try write_position(&object, context.position);
    try object.quantity("gasUsed", context.gas_used);
    try object.quantity("effectiveGasPrice", context.effective_gas_price);
    try object.optional_quantity("blobGasUsed", context.blob_gas_used);
    try object.optional_quantity("blobGasPrice", context.blob_gas_price);
    try object.address("from", context.from);
    try object.address_or_null("to", context.to);
    try object.address_or_null("contractAddress", context.contract_address);
    try write_l1_block_info(&object, context.l1_block_info);
    try object.optional_quantity("depositNonce", receipt.deposit_nonce);
    try object.optional_quantity("depositReceiptVersion", receipt.deposit_receipt_version);
    if (context.payer) |payer| try object.address("payer", payer);
    try eip8130.write_phase_statuses(&object, receipt, context.phase_count);
    if (context.metadata) |metadata| try object.data("metadata", metadata);
    try object.end();
}

/// Header fields, without the closing brace (blocks append theirs).
fn write_header_fields(object: *Object, header: consensus.header.Header, hash: B256) Error!void {
    try object.fixed("hash", hash);
    try object.fixed("parentHash", header.parent_hash);
    try object.fixed("sha3Uncles", header.ommers_hash);
    try object.address("miner", header.beneficiary);
    try object.fixed("stateRoot", header.state_root);
    try object.fixed("transactionsRoot", header.transactions_root);
    try object.fixed("receiptsRoot", header.receipts_root);
    try object.fixed("logsBloom", header.logs_bloom);
    try object.quantity("difficulty", header.difficulty);
    try object.quantity("number", header.number);
    try object.quantity("gasLimit", header.gas_limit);
    try object.quantity("gasUsed", header.gas_used);
    try object.quantity("timestamp", header.timestamp);
    try object.data("extraData", header.extra_data);
    try object.fixed("mixHash", header.mix_hash);
    try object.fixed("nonce", header.nonce);
    try object.optional_quantity("baseFeePerGas", header.base_fee_per_gas);
    try object.optional_fixed("withdrawalsRoot", header.withdrawals_root);
    try object.optional_quantity("blobGasUsed", header.blob_gas_used);
    try object.optional_quantity("excessBlobGas", header.excess_blob_gas);
    try object.optional_fixed("parentBeaconBlockRoot", header.parent_beacon_block_root);
    try object.optional_fixed("requestsHash", header.requests_hash);
}

pub fn write_header(w: *Writer, header: consensus.header.Header, hash: B256) Error!void {
    var object = try Object.begin(w);
    try write_header_fields(&object, header, hash);
    try object.end();
}

/// The transactions of an `eth_getBlockBy*` response: hashes, or full objects.
pub const BlockTransactions = union(enum) {
    hashes: []const B256,
    full: struct { envelopes: []const Envelope, contexts: []const TransactionContext },
};

/// A block. `size` is the RLP length of the block; withdrawals are always empty on Base.
pub fn write_block(
    w: *Writer,
    header: consensus.header.Header,
    hash: B256,
    size: u64,
    transactions: BlockTransactions,
) Error!void {
    var object = try Object.begin(w);
    try write_header_fields(&object, header, hash);
    try object.quantity("size", size);
    try object.key("uncles");
    try w.writeAll("[]");
    try object.key("transactions");
    try w.writeByte('[');
    switch (transactions) {
        .hashes => |hashes| for (hashes, 0..) |transaction_hash, index| {
            if (index > 0) try w.writeByte(',');
            try json.write_data(w, &transaction_hash.bytes);
        },
        .full => |full| {
            assert(full.envelopes.len == full.contexts.len);
            for (full.envelopes, full.contexts, 0..) |envelope, context, index| {
                if (index > 0) try w.writeByte(',');
                try write_transaction(w, envelope, context);
            }
        },
    }
    try w.writeByte(']');
    if (header.withdrawals_root != null) {
        try object.key("withdrawals");
        try w.writeAll("[]");
    }
    try object.end();
}

test {
    _ = json;
    _ = eip8130;
    _ = request;
    _ = transaction;
    _ = @import("root_test.zig");
}

//! JSON shapes of the eth namespace: blocks, transactions, receipts and logs, written
//! from the chain's stored records. Field names and optionality follow the
//! execution-apis spec (and reth/geth output for fields the spec leaves open).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const node = @import("../node/root.zig");
const evm = @import("../evm/root.zig");

const Hash = [32]u8;
const Writer = json.Writer;
const WriteError = json.Writer.WriteError;
const Envelope = consensus.Envelope;
const Header = consensus.Header;

/// Where a transaction sits; null fields for pending transactions.
pub const Inclusion = struct {
    block_hash: Hash,
    block_number: u64,
    index: u32,
    base_fee: ?u64,
};

pub fn header_fields(w: *Writer, header: *const Header, hash: Hash, size: usize) WriteError!void {
    try field_data(w, "hash", &hash);
    try field_data(w, "parentHash", &header.parent_hash.bytes);
    try field_data(w, "sha3Uncles", &header.ommers_hash.bytes);
    try field_data(w, "miner", &header.beneficiary.bytes);
    try field_data(w, "stateRoot", &header.state_root.bytes);
    try field_data(w, "transactionsRoot", &header.transactions_root.bytes);
    try field_data(w, "receiptsRoot", &header.receipts_root.bytes);
    try field_data(w, "logsBloom", &header.logs_bloom.bytes);
    try field_quantity(w, "difficulty", header.difficulty);
    try field_quantity(w, "number", header.number);
    try field_quantity(w, "gasLimit", header.gas_limit);
    try field_quantity(w, "gasUsed", header.gas_used);
    try field_quantity(w, "timestamp", header.timestamp);
    try field_data(w, "extraData", header.extra_data);
    try field_data(w, "mixHash", &header.mix_hash.bytes);
    try field_data(w, "nonce", &header.nonce.bytes);
    try field_quantity(w, "size", size);
    if (header.base_fee_per_gas) |fee| try field_quantity(w, "baseFeePerGas", fee);
    if (header.withdrawals_root) |root| try field_data(w, "withdrawalsRoot", &root.bytes);
    if (header.blob_gas_used) |used| try field_quantity(w, "blobGasUsed", used);
    if (header.excess_blob_gas) |excess| try field_quantity(w, "excessBlobGas", excess);
    if (header.parent_beacon_block_root) |root| {
        try field_data(w, "parentBeaconBlockRoot", &root.bytes);
    }
    if (header.requests_hash) |hash_value| try field_data(w, "requestsHash", &hash_value.bytes);
}

/// A full block object. With `full`, transactions are objects; otherwise hashes.
pub fn block(
    w: *Writer,
    record: node.chain.Record,
    hash: Hash,
    size: usize,
    full: bool,
    recoverer: consensus.Recoverer,
) WriteError!void {
    try w.begin_object();
    try header_fields(w, &record.header, hash, size);
    try w.key("uncles");
    try w.begin_array();
    try w.end_array();
    try w.key("transactions");
    try w.begin_array();
    var transactions = record.transactions;
    var index: u32 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        if (!full) {
            try w.data(&primitives.keccak256(raw).bytes);
            continue;
        }
        const inclusion: Inclusion = .{
            .block_hash = hash,
            .block_number = record.header.number,
            .index = index,
            .base_fee = record.header.base_fee_per_gas,
        };
        try transaction(w, raw, inclusion, recoverer);
    }
    try w.end_array();
    if (record.withdrawals) |list| try withdrawals(w, list);
    try w.end_object();
}

fn withdrawals(w: *Writer, list: consensus.block.Withdrawals) WriteError!void {
    try w.key("withdrawals");
    try w.begin_array();
    var it = list.iterator();
    while (it.next()) |item| {
        try w.begin_object();
        try field_quantity(w, "index", item.index);
        try field_quantity(w, "validatorIndex", item.validator_index);
        try field_data(w, "address", &item.address.bytes);
        try field_quantity(w, "amount", item.amount);
        try w.end_object();
    }
    try w.end_array();
}

/// A transaction object from its EIP-2718 bytes. Invalid bytes (impossible for stored
/// blocks) are written as `null`.
pub fn transaction(
    w: *Writer,
    raw: []const u8,
    inclusion: ?Inclusion,
    recoverer: consensus.Recoverer,
) WriteError!void {
    const envelope = Envelope.decode(raw) catch return w.null_value();
    const sender = envelope.recover_sender(recoverer) orelse primitives.Address.zero;
    try w.begin_object();
    try field_data(w, "hash", &primitives.keccak256(raw).bytes);
    try field_quantity(w, "type", @as(u8, @backingInt(envelope.tx_type())));
    try field_data(w, "from", &sender.bytes);
    if (envelope.kind().to()) |to| try field_data(w, "to", &to.bytes) else {
        try w.key("to");
        try w.null_value();
    }
    try field_quantity(w, "nonce", envelope.nonce() orelse 0);
    try field_quantity(w, "gas", envelope.gas_limit());
    try field_quantity(w, "value", envelope.value());
    try field_data(w, "input", envelope.input());
    if (envelope.chain_id()) |id| try field_quantity(w, "chainId", id);
    try fee_fields(w, envelope, inclusion);
    try inclusion_fields(w, inclusion);
    try signature_fields(w, envelope);
    try w.end_object();
}

fn fee_fields(w: *Writer, envelope: Envelope, inclusion: ?Inclusion) WriteError!void {
    const base_fee = if (inclusion) |i| i.base_fee else null;
    switch (envelope) {
        .legacy, .eip2930 => try field_quantity(w, "gasPrice", envelope.max_fee_per_gas()),
        .deposit => try field_quantity(w, "gasPrice", @as(u8, 0)),
        else => {
            const price = if (base_fee) |fee|
                envelope.effective_gas_price(fee) orelse envelope.max_fee_per_gas()
            else
                envelope.max_fee_per_gas();
            try field_quantity(w, "gasPrice", price);
            try field_quantity(w, "maxFeePerGas", envelope.max_fee_per_gas());
            try field_quantity(w, "maxPriorityFeePerGas", envelope.max_priority_fee_per_gas());
        },
    }
    if (envelope != .legacy and envelope != .deposit) try access_list(w, envelope.access_list());
    if (envelope == .eip4844) {
        try field_quantity(w, "maxFeePerBlobGas", envelope.eip4844.tx.max_fee_per_blob_gas);
        try w.key("blobVersionedHashes");
        try w.begin_array();
        const hashes = envelope.blob_versioned_hashes();
        for (0..hashes.count()) |i| try w.data(&hashes.get(i).bytes);
        try w.end_array();
    }
}

fn access_list(w: *Writer, list: consensus.AccessList) WriteError!void {
    try w.key("accessList");
    try w.begin_array();
    var it = list.iterator();
    while (it.next()) |item| {
        try w.begin_object();
        try field_data(w, "address", &item.address.bytes);
        try w.key("storageKeys");
        try w.begin_array();
        for (0..item.storage_keys.count()) |i| try w.data(&item.storage_keys.get(i).bytes);
        try w.end_array();
        try w.end_object();
    }
    try w.end_array();
}

fn inclusion_fields(w: *Writer, inclusion: ?Inclusion) WriteError!void {
    const keys = [_][]const u8{ "blockHash", "blockNumber", "transactionIndex" };
    const at = inclusion orelse {
        for (keys) |k| {
            try w.key(k);
            try w.null_value();
        }
        return;
    };
    try field_data(w, keys[0], &at.block_hash);
    try field_quantity(w, keys[1], at.block_number);
    try field_quantity(w, keys[2], at.index);
}

fn signature_fields(w: *Writer, envelope: Envelope) WriteError!void {
    const sig = envelope.signature() orelse return;
    const parity: u64 = @intFromBool(sig.y_parity);
    if (envelope == .legacy) {
        const v = if (envelope.chain_id()) |id| 35 + 2 * id + parity else 27 + parity;
        try field_quantity(w, "v", v);
    } else {
        try field_quantity(w, "v", parity);
        try field_quantity(w, "yParity", parity);
    }
    try field_quantity(w, "r", sig.r);
    try field_quantity(w, "s", sig.s);
}

/// Receipt context computed by the caller from the block.
pub const ReceiptContext = struct {
    inclusion: Inclusion,
    tx_hash: Hash,
    from: primitives.Address,
    to: ?primitives.Address,
    contract_address: ?primitives.Address,
    gas_used: u64,
    effective_gas_price: u128,
    first_log_index: u64,
    blob_gas_used: u64,
    blob_gas_price: ?u128,
};

pub fn receipt(w: *Writer, value: consensus.Receipt, context: ReceiptContext) WriteError!void {
    const at = context.inclusion;
    try w.begin_object();
    try field_data(w, "transactionHash", &context.tx_hash);
    try inclusion_fields(w, at);
    try field_data(w, "from", &context.from.bytes);
    try w.key("to");
    if (context.to) |to| try w.data(&to.bytes) else try w.null_value();
    try w.key("contractAddress");
    if (context.contract_address) |a| try w.data(&a.bytes) else try w.null_value();
    try field_quantity(w, "cumulativeGasUsed", value.cumulative_gas_used);
    try field_quantity(w, "gasUsed", context.gas_used);
    try field_quantity(w, "effectiveGasPrice", context.effective_gas_price);
    try field_quantity(w, "type", @as(u8, @backingInt(value.tx_type)));
    try field_quantity(w, "status", @as(u8, @intFromBool(value.status)));
    try field_data(w, "logsBloom", &value.logs_bloom.bytes);
    if (context.blob_gas_price) |price| {
        try field_quantity(w, "blobGasUsed", context.blob_gas_used);
        try field_quantity(w, "blobGasPrice", price);
    }
    try w.key("logs");
    try w.begin_array();
    var it = value.logs.iterator();
    var log_index = context.first_log_index;
    while (it.next()) |item| : (log_index += 1) {
        try log(w, item, at, context.tx_hash, log_index);
    }
    try w.end_array();
    try w.end_object();
}

pub fn log(
    w: *Writer,
    item: consensus.Log,
    at: Inclusion,
    tx_hash: Hash,
    log_index: u64,
) WriteError!void {
    try w.begin_object();
    try field_data(w, "address", &item.address.bytes);
    try w.key("topics");
    try w.begin_array();
    for (0..item.topics.count()) |i| try w.data(&item.topics.get(i).bytes);
    try w.end_array();
    try field_data(w, "data", item.data);
    try field_quantity(w, "blockNumber", at.block_number);
    try field_data(w, "blockHash", &at.block_hash);
    try field_data(w, "transactionHash", &tx_hash);
    try field_quantity(w, "transactionIndex", at.index);
    try field_quantity(w, "logIndex", log_index);
    try w.key("removed");
    try w.boolean(false);
    try w.end_object();
}

pub fn field_data(w: *Writer, name: []const u8, bytes: []const u8) WriteError!void {
    try w.key(name);
    try w.data(bytes);
}

pub fn field_quantity(w: *Writer, name: []const u8, value: anytype) WriteError!void {
    try w.key(name);
    try w.quantity(value);
}

/// The address a creation by `sender` at `nonce` deploys to.
pub fn contract_address(sender: primitives.Address, nonce: u64) primitives.Address {
    return .{ .bytes = evm.evm.create_address(sender.bytes, nonce) };
}

const testing = std.testing;

test "format: header fields and transaction object" {
    var buffer: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var w: Writer = .init(&out);
    const header: Header = .{ .number = 5, .gas_limit = 30_000_000, .base_fee_per_gas = 7 };
    try w.begin_object();
    try header_fields(&w, &header, @splat(0xab), 600);
    try w.end_object();
    const text = out.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "\"number\":\"0x5\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"baseFeePerGas\":\"0x7\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"size\":\"0x258\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "withdrawalsRoot") == null);
    try json.validate(text);
}

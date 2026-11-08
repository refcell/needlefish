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
const op_receipt = @import("op_receipt.zig");
const chainspec = @import("../chainspec/root.zig");

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
    /// Denim: the block's millisecond timestamp (`blockTimestampMs`), when known.
    timestamp_ms: ?u64 = null,
    /// The block's timestamp (`blockTimestamp` of transactions and logs), when known.
    timestamp: ?u64 = null,
    /// A deposit's receipt fields its transaction object repeats (`nonce`,
    /// `depositReceiptVersion`), when known.
    deposit: ?DepositReceipt = null,
};

pub const DepositReceipt = struct { nonce: ?u64, version: ?u64 };

/// The deposit fields of the receipt at `index` of a stored block; null for other types.
pub fn deposit_receipt(record: node.chain.Record, index: u32) ?DepositReceipt {
    var receipts = record.receipts;
    var position: u32 = 0;
    while (!receipts.is_empty()) : (position += 1) {
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        if (position < index) continue;
        const value = consensus.Receipt.decode(encoded) catch unreachable;
        if (value.tx_type != .deposit) return null;
        return .{ .nonce = value.deposit_nonce, .version = value.deposit_receipt_version };
    }
    return null;
}

/// Denim: a block's timestamp in milliseconds from its BaseTime deposit (index 1), as
/// base/base's RPC reports it; null for pre-Denim blocks (no valid deposit there).
pub fn timestamp_ms(record: node.chain.Record) ?u64 {
    var transactions = record.transactions;
    if (transactions.is_empty()) return null;
    _ = transactions.bytes() catch return null;
    if (transactions.is_empty()) return null;
    const raw = transactions.bytes() catch return null;
    return timestamp_ms_of(raw, record.header.number, record.header.timestamp);
}

/// The millisecond timestamp when `second` (a block's transaction at index 1) is the
/// valid BaseTime deposit for block `number`.
pub fn timestamp_ms_of(second: []const u8, number: u64, timestamp: u64) ?u64 {
    const envelope = Envelope.decode(second) catch return null;
    const millis_part = consensus.base_time.extract(envelope, number) catch return null;
    assert(millis_part < 1_000);
    const result = consensus.base_time.timestamp_ms(timestamp, millis_part);
    assert(result >= timestamp *| 1_000);
    return result;
}

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
    const block_ms = timestamp_ms(record);
    try w.begin_object();
    try header_fields(w, &record.header, hash, size);
    if (block_ms) |ms| try field_quantity(w, "timestampMs", ms);
    try w.key("uncles");
    try w.begin_array();
    try w.end_array();
    try w.key("transactions");
    try w.begin_array();
    var transactions = record.transactions;
    var receipts = record.receipts;
    var index: u32 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        const encoded = if (receipts.is_empty()) null else receipts.bytes() catch unreachable;
        if (!full) {
            try w.data(&primitives.keccak256(raw).bytes);
            continue;
        }
        var inclusion: Inclusion = .{
            .block_hash = hash,
            .block_number = record.header.number,
            .index = index,
            .base_fee = record.header.base_fee_per_gas,
            .timestamp_ms = block_ms,
            .timestamp = record.header.timestamp,
        };
        if (encoded) |bytes| {
            const value = consensus.Receipt.decode(bytes) catch unreachable; // Stored.
            if (value.tx_type == .deposit) inclusion.deposit = .{
                .nonce = value.deposit_nonce,
                .version = value.deposit_receipt_version,
            };
        }
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
    // Deposits have no nonce field: like op-reth, the object shows their receipt's.
    const deposit_receipt_fields = if (inclusion) |at| at.deposit else null;
    if (envelope.nonce()) |nonce| {
        try field_quantity(w, "nonce", nonce);
    } else if (deposit_receipt_fields) |fields| if (fields.nonce) |nonce| {
        try field_quantity(w, "nonce", nonce);
    };
    try field_quantity(w, "gas", envelope.gas_limit());
    try field_quantity(w, "value", envelope.value());
    try field_data(w, "input", envelope.input());
    if (envelope.chain_id()) |id| try field_quantity(w, "chainId", id);
    try fee_fields(w, envelope, inclusion);
    try inclusion_fields(w, inclusion);
    if (inclusion) |at| if (at.timestamp) |time| try field_quantity(w, "blockTimestamp", time);
    if (inclusion) |at| if (at.timestamp_ms) |ms| try field_quantity(w, "blockTimestampMs", ms);
    try signature_fields(w, envelope);
    if (envelope == .deposit) {
        try deposit_fields(w, envelope.deposit);
        if (deposit_receipt_fields) |fields| if (fields.version) |version| {
            try field_quantity(w, "depositReceiptVersion", version);
        };
    }
    try w.end_object();
}

/// OP deposit fields as op-reth (base/base) writes them: source hash, mint, the system flag
/// only when set, and the zero signature values tooling expects on every transaction.
fn deposit_fields(w: *Writer, deposit: consensus.Deposit) WriteError!void {
    try field_data(w, "sourceHash", &deposit.source_hash.bytes);
    try field_quantity(w, "mint", deposit.mint);
    if (deposit.is_system_transaction) {
        try w.key("isSystemTx");
        try w.boolean(true);
    }
    inline for (.{ "v", "r", "s", "yParity" }) |name| try field_quantity(w, name, @as(u8, 0));
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
    if (envelope == .eip7702) try authorization_list(w, envelope.eip7702.tx.authorization_list);
    if (envelope == .eip4844) {
        try field_quantity(w, "maxFeePerBlobGas", envelope.eip4844.tx.max_fee_per_blob_gas);
        try w.key("blobVersionedHashes");
        try w.begin_array();
        const hashes = envelope.blob_versioned_hashes();
        for (0..hashes.count()) |i| try w.data(&hashes.get(i).bytes);
        try w.end_array();
    }
}

/// EIP-7702 authorizations, named as op-reth writes them. Without them a reader that rebuilds
/// the transaction (a consensus node checking the transactions root) gets different bytes.
fn authorization_list(w: *Writer, list: consensus.AuthorizationList) WriteError!void {
    try w.key("authorizationList");
    try w.begin_array();
    var it = list.iterator();
    var count: u32 = 0;
    while (it.next()) |item| : (count += 1) {
        try w.begin_object();
        try field_quantity(w, "chainId", item.chain_id);
        try field_data(w, "address", &item.address.bytes);
        try field_quantity(w, "nonce", item.nonce);
        try field_quantity(w, "yParity", item.y_parity);
        try field_quantity(w, "r", item.r);
        try field_quantity(w, "s", item.s);
        try w.end_object();
    }
    try w.end_array();
    assert(count == list.count);
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
    /// L2: the OP fee fields (`op_receipt`).
    op: ?op_receipt.Fields = null,
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
    // Jovian: `blobGasUsed` is the DA footprint, on every transaction.
    const da_footprint = if (context.op) |op| op.da_footprint else null;
    if (da_footprint) |footprint| {
        try field_quantity(w, "blobGasUsed", footprint);
    } else if (context.blob_gas_price != null) {
        try field_quantity(w, "blobGasUsed", context.blob_gas_used);
    }
    if (context.blob_gas_price) |price| try field_quantity(w, "blobGasPrice", price);
    if (context.op) |op| try op_receipt.write(w, op);
    if (value.deposit_nonce) |nonce| try field_quantity(w, "depositNonce", nonce);
    if (value.deposit_receipt_version) |version| {
        try field_quantity(w, "depositReceiptVersion", version);
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
    if (at.timestamp) |time| try field_quantity(w, "blockTimestamp", time);
    if (at.timestamp_ms) |ms| try field_quantity(w, "blockTimestampMs", ms);
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

/// Where a receipt sits in its block: the cumulative gas before it and its first log index.
pub const ReceiptPosition = struct { previous_gas: u64, log_index: u64 };

/// The context of receipt `value` of transaction `raw` at `index` of block `hash`.
pub fn receipt_context(
    spec: *const chainspec.ChainSpec,
    recoverer: consensus.Recoverer,
    header: *const Header,
    hash: Hash,
    raw: []const u8,
    index: u32,
    value: consensus.Receipt,
    position: ReceiptPosition,
) ReceiptContext {
    const envelope = Envelope.decode(raw) catch unreachable; // Stored by the chain.
    const sender = envelope.recover_sender(recoverer) orelse primitives.Address.zero;
    const to = envelope.kind().to();
    const base_fee = header.base_fee_per_gas orelse 0;
    const blob_count = envelope.blob_versioned_hashes().count();
    var blob_price: ?u128 = null;
    if (blob_count > 0) if (spec.blob_params_at(header.timestamp)) |params| {
        blob_price = params.base_fee(header.excess_blob_gas orelse 0);
    };
    assert(value.cumulative_gas_used >= position.previous_gas);
    return .{
        .inclusion = .{
            .block_hash = hash,
            .block_number = header.number,
            .index = index,
            .base_fee = base_fee,
            .timestamp = header.timestamp,
        },
        .tx_hash = primitives.keccak256(raw).bytes,
        .from = sender,
        .to = to,
        .contract_address = if (to == null) contract_address(sender, envelope.nonce().?) else null,
        .gas_used = value.cumulative_gas_used - position.previous_gas,
        .effective_gas_price = envelope.effective_gas_price(base_fee) orelse 0,
        .first_log_index = position.log_index,
        .blob_gas_used = @as(u64, blob_count) * (1 << 17),
        .blob_gas_price = blob_price,
    };
}

/// Writes the receipt at `only` (or every receipt, without the enclosing array) of the
/// stored block `record` whose hash is `hash`.
pub fn block_receipts(
    w: *Writer,
    spec: *const chainspec.ChainSpec,
    recoverer: consensus.Recoverer,
    record: node.chain.Record,
    hash: Hash,
    only: ?u32,
) WriteError!void {
    const block_ms = timestamp_ms(record);
    var transactions = record.transactions;
    var receipts = record.receipts;
    var index: u32 = 0;
    var previous_gas: u64 = 0;
    var log_index: u64 = 0;
    var first: []const u8 = &.{};
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        if (index == 0) first = raw;
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        const value = consensus.Receipt.decode(encoded) catch unreachable;
        defer previous_gas = value.cumulative_gas_used;
        defer log_index += value.logs.count;
        if (only) |wanted| if (wanted != index) continue;
        var context = receipt_context(spec, recoverer, &record.header, hash, raw, index, value, .{
            .previous_gas = previous_gas,
            .log_index = log_index,
        });
        context.inclusion.timestamp_ms = block_ms;
        context.op = op_receipt.fields(spec, record.header.timestamp, first, raw);
        try receipt(w, value, context);
    }
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

fn no_recovery(hash: primitives.B256, signature: consensus.Signature) ?primitives.Address {
    _ = hash;
    _ = signature;
    return null;
}

test "format: deposit transaction and receipt carry the OP fields" {
    const deposit: Envelope = .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(0x5c) },
        .from = .{ .bytes = @splat(0xde) },
        .to = .{ .call = .{ .bytes = @splat(0x15) } },
        .mint = 7,
        .value = 0,
        .gas_limit = 1_000_000,
        .is_system_transaction = false,
        .input = &.{ 1, 2 },
    } };
    var raw_buffer: [256]u8 = undefined;
    const raw = deposit.encode_to(&raw_buffer);
    var buffer: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var w: Writer = .init(&out);
    try transaction(&w, raw, null, no_recovery);
    const text = out.buffered();
    try json.validate(text);
    try testing.expect(std.mem.indexOf(u8, text, "\"type\":\"0x7e\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"mint\":\"0x7\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "isSystemTx") == null);
    try testing.expect(std.mem.indexOf(u8, text, "\"yParity\":\"0x0\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"from\":\"0xdede") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sourceHash") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"nonce\"") == null);

    out = .fixed(&buffer);
    w = .init(&out);
    const value: consensus.Receipt = .{
        .tx_type = .deposit,
        .status = true,
        .cumulative_gas_used = 50_000,
        .logs_bloom = .zero,
        .logs = .{ .payload = &.{}, .count = 0 },
        .deposit_nonce = 3,
        .deposit_receipt_version = 1,
    };
    try receipt(&w, value, .{
        .inclusion = .{ .block_hash = @splat(1), .block_number = 1, .index = 0, .base_fee = 1 },
        .tx_hash = @splat(2),
        .from = .{ .bytes = @splat(0xde) },
        .to = null,
        .contract_address = null,
        .gas_used = 50_000,
        .effective_gas_price = 0,
        .first_log_index = 0,
        .blob_gas_used = 0,
        .blob_gas_price = null,
    });
    const receipt_text = out.buffered();
    try json.validate(receipt_text);
    try testing.expect(std.mem.indexOf(u8, receipt_text, "\"depositNonce\":\"0x3\"") != null);
    const version = "\"depositReceiptVersion\":\"0x1\"";
    try testing.expect(std.mem.indexOf(u8, receipt_text, version) != null);
}

fn timestamp_scenario(seed: u64) !void {
    var prng = @import("../../testing/prng.zig").Prng.init(seed);
    const number = prng.below(1 << 40);
    const timestamp = prng.below(1 << 40);
    var buffer: [256]u8 = undefined;
    if (prng.chance(1, 2)) {
        const millis: u16 = @intCast(prng.below(5) * 200);
        const calldata = consensus.base_time.encode_calldata(millis);
        const envelope: Envelope = .{ .deposit = consensus.base_time.deposit(number, &calldata) };
        const raw = envelope.encode_to(&buffer);
        const expected = timestamp * 1_000 + millis;
        try std.testing.expectEqual(@as(?u64, expected), timestamp_ms_of(raw, number, timestamp));
        // The deposit of another block does not count.
        try std.testing.expectEqual(@as(?u64, null), timestamp_ms_of(raw, number + 1, timestamp));
        return;
    }
    const length = prng.below(buffer.len);
    prng.fill(buffer[0..length]);
    try std.testing.expectEqual(@as(?u64, null), timestamp_ms_of(buffer[0..length], number, 7));
}

test "format: seeded fuzz of BaseTime millisecond timestamps" {
    for (0..512) |seed| try timestamp_scenario(seed);
}

fn fuzz_timestamp(_: void, smith: *std.testing.Smith) anyerror!void {
    try timestamp_scenario(smith.value(u64));
}

test "format: fuzz BaseTime millisecond timestamps" {
    try std.testing.fuzz({}, fuzz_timestamp, .{});
}

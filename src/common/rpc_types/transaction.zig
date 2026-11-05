//! Parses an RPC transaction object (`eth_getTransactionByHash`, full blocks) back into a
//! signed EIP-2718 envelope: the inverse of `write_transaction`, for every Base type
//! (0-4, 0x79, deposits). The rebuilt envelope must hash to the reported `hash`, so a
//! node cannot hand back fields that disagree with the transaction it names.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const consensus = @import("../consensus/root.zig");
const request_module = @import("request.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Value = std.json.Value;
const Allocator = std.mem.Allocator;
const tx = consensus.tx;
const Signature = consensus.signature.Signature;
const Request = request_module.TransactionRequest;
const field = request_module.field;
const required = request_module.required;
const quantity = request_module.quantity;

pub const ParseError = request_module.ParseError || error{
    MissingField,
    UnknownType,
    /// Legacy `v` disagrees with `chainId`, or typed `v` with `yParity`.
    InvalidSignature,
    /// The rebuilt envelope does not hash to the reported `hash`.
    HashMismatch,
};

pub const Transaction = struct {
    envelope: tx.Envelope,
    hash: B256,
    /// Reported sender: not verified (deposits carry it in the envelope).
    from: ?Address,
    block_hash: ?B256 = null,
    block_number: ?u64 = null,
    transaction_index: ?u64 = null,
    deposit_nonce: ?u64 = null,
    deposit_receipt_version: ?u64 = null,
};

pub fn parse_transaction(arena: Allocator, value: Value) ParseError!Transaction {
    const request = try request_module.parse_transaction_request(arena, value);
    const object = value.object;
    const type_byte = request.tx_type orelse return error.MissingField;
    const tx_type = std.enums.fromInt(tx.TxType, type_byte) orelse return error.UnknownType;
    const envelope: tx.Envelope = switch (tx_type) {
        .legacy => .{ .legacy = try legacy(object, request) },
        .eip2930, .eip1559, .eip4844, .eip7702 => try signed_typed(tx_type, object, request),
        .eip8130 => .{ .eip8130 = try eip8130(request) },
        .deposit => .{ .deposit = try deposit(object, request) },
    };
    assert(envelope.tx_type() == tx_type);
    const hash = try request_module.hash_of(try required(object, "hash"));
    if (!envelope.hash().eql(hash)) return error.HashMismatch;
    return .{
        .envelope = envelope,
        .hash = hash,
        .from = request.from,
        .block_hash = try optional_hash(object, "blockHash"),
        .block_number = try optional(u64, object, "blockNumber"),
        .transaction_index = try optional(u64, object, "transactionIndex"),
        .deposit_nonce = if (tx_type == .deposit) request.nonce else null,
        .deposit_receipt_version = try optional(u64, object, "depositReceiptVersion"),
    };
}

fn optional(comptime T: type, object: std.json.ObjectMap, name: []const u8) ParseError!?T {
    const item = field(object, name) orelse return null;
    return try quantity(T, item);
}

/// Types 1-4: the type's fields plus `r`, `s`, `yParity`.
fn signed_typed(
    tx_type: tx.TxType,
    object: std.json.ObjectMap,
    request: Request,
) ParseError!tx.Envelope {
    const signature = try signature_of(object);
    return switch (tx_type) {
        .eip2930 => .{ .eip2930 = .{ .tx = try eip2930(request), .signature = signature } },
        .eip1559 => .{ .eip1559 = .{ .tx = try eip1559(request), .signature = signature } },
        .eip4844 => .{ .eip4844 = .{ .tx = try eip4844(request), .signature = signature } },
        .eip7702 => .{ .eip7702 = .{ .tx = try eip7702(request), .signature = signature } },
        .legacy, .eip8130, .deposit => unreachable, // Dispatched by parse_transaction.
    };
}

fn optional_hash(object: std.json.ObjectMap, name: []const u8) ParseError!?B256 {
    const item = field(object, name) orelse return null;
    return try request_module.hash_of(item);
}

fn need(comptime T: type, value: ?T) ParseError!T {
    return value orelse error.MissingField;
}

fn kind(to: ?Address) tx.TxKind {
    return if (to) |address| .{ .call = address } else .create;
}

fn signature_of(object: std.json.ObjectMap) ParseError!Signature {
    const r = try quantity(u256, try required(object, "r"));
    const s = try quantity(u256, try required(object, "s"));
    const parity = try optional(u256, object, "yParity");
    const v = try optional(u256, object, "v");
    const y = parity orelse v orelse return error.MissingField;
    if (y > 1) return error.InvalidSignature;
    if (parity != null and v != null and parity.? != v.?) return error.InvalidSignature;
    return .{ .y_parity = y == 1, .r = r, .s = s };
}

/// Legacy `v`: 27/28 before EIP-155, `chain_id * 2 + 35 + parity` after.
fn legacy(object: std.json.ObjectMap, request: Request) ParseError!tx.Signed(tx.Legacy) {
    const v = try quantity(u256, try required(object, "v"));
    var chain_id: ?u64 = null;
    var parity: bool = undefined;
    if (v == 27 or v == 28) {
        parity = v == 28;
    } else if (v >= 35) {
        const id = (v - 35) / 2;
        if (id > std.math.maxInt(u64)) return error.InvalidSignature;
        chain_id = @intCast(id);
        parity = (v - 35) % 2 == 1;
    } else return error.InvalidSignature;
    if (request.chain_id) |reported| {
        if (chain_id == null or chain_id.? != reported) return error.InvalidSignature;
    }
    const signature: Signature = .{
        .y_parity = parity,
        .r = try quantity(u256, try required(object, "r")),
        .s = try quantity(u256, try required(object, "s")),
    };
    assert(signature.legacy_v(chain_id) == v);
    return .{ .tx = .{
        .chain_id = chain_id,
        .nonce = try need(u64, request.nonce),
        .gas_price = try need(u128, request.gas_price),
        .gas_limit = try need(u64, request.gas),
        .to = kind(request.to),
        .value = try need(u256, request.value),
        .input = try need([]const u8, request.input),
    }, .signature = signature };
}

fn eip2930(request: Request) ParseError!tx.Eip2930 {
    return .{
        .chain_id = try need(u64, request.chain_id),
        .nonce = try need(u64, request.nonce),
        .gas_price = try need(u128, request.gas_price),
        .gas_limit = try need(u64, request.gas),
        .to = kind(request.to),
        .value = try need(u256, request.value),
        .input = try need([]const u8, request.input),
        .access_list = request.access_list orelse .empty,
    };
}

fn eip1559(request: Request) ParseError!tx.Eip1559 {
    return .{
        .chain_id = try need(u64, request.chain_id),
        .nonce = try need(u64, request.nonce),
        .max_priority_fee_per_gas = try need(u128, request.max_priority_fee_per_gas),
        .max_fee_per_gas = try need(u128, request.max_fee_per_gas),
        .gas_limit = try need(u64, request.gas),
        .to = kind(request.to),
        .value = try need(u256, request.value),
        .input = try need([]const u8, request.input),
        .access_list = request.access_list orelse .empty,
    };
}

fn eip4844(request: Request) ParseError!tx.Eip4844 {
    const base = try eip1559(request);
    return .{
        .chain_id = base.chain_id,
        .nonce = base.nonce,
        .max_priority_fee_per_gas = base.max_priority_fee_per_gas,
        .max_fee_per_gas = base.max_fee_per_gas,
        .gas_limit = base.gas_limit,
        .to = try need(Address, request.to),
        .value = base.value,
        .input = base.input,
        .access_list = base.access_list,
        .max_fee_per_blob_gas = try need(u128, request.max_fee_per_blob_gas),
        .blob_versioned_hashes = try need(tx.HashList, request.blob_versioned_hashes),
    };
}

fn eip7702(request: Request) ParseError!tx.Eip7702 {
    const base = try eip1559(request);
    return .{
        .chain_id = base.chain_id,
        .nonce = base.nonce,
        .max_priority_fee_per_gas = base.max_priority_fee_per_gas,
        .max_fee_per_gas = base.max_fee_per_gas,
        .gas_limit = base.gas_limit,
        .to = try need(Address, request.to),
        .value = base.value,
        .input = base.input,
        .access_list = base.access_list,
        .authorization_list = try need(tx.AuthorizationList, request.authorization_list),
    };
}

fn eip8130(request: Request) ParseError!consensus.eip8130.Signed {
    return .{
        .tx = .{
            .chain_id = try need(u64, request.chain_id),
            .sender = request.sender,
            .nonce_key = try need(u256, request.nonce_key),
            .nonce_sequence = try need(u64, request.nonce),
            .valid_after = request.valid_after orelse 0,
            .valid_before = request.valid_before orelse 0,
            .max_priority_fee_per_gas = try need(u128, request.max_priority_fee_per_gas),
            .max_fee_per_gas = try need(u128, request.max_fee_per_gas),
            .gas_limit = try need(u64, request.gas),
            .account_changes = request.account_changes orelse .empty,
            .calls = request.calls orelse .empty,
            .metadata = request.metadata orelse &.{},
            .payer = request.payer,
        },
        .sender_auth = try need([]const u8, request.sender_auth),
        .payer_auth = request.payer_auth orelse &.{},
    };
}

/// `mint` and `isSystemTx` default to zero/false like op-alloy.
fn deposit(object: std.json.ObjectMap, request: Request) ParseError!tx.Deposit {
    const system = field(object, "isSystemTx");
    if (system != null and system.? != .bool) return error.InvalidField;
    return .{
        .source_hash = try request_module.hash_of(try required(object, "sourceHash")),
        .from = try need(Address, request.from),
        .to = kind(request.to),
        .mint = try optional(u128, object, "mint") orelse 0,
        .value = try need(u256, request.value),
        .gas_limit = try need(u64, request.gas),
        .is_system_transaction = if (system) |flag| flag.bool else false,
        .input = try need([]const u8, request.input),
    };
}

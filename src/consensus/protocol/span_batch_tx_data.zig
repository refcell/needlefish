//! Span batch transaction data: the per-transaction fields that are not split into
//! shared columns (nonce, gas, `to`, and signature are columns), for legacy,
//! EIP-2930, EIP-1559 and EIP-7702 transactions, and their conversion to and from
//! signed EIP-2718 envelopes. Mirrors base/base
//! `crates/consensus/protocol/src/batch/tx_data/*`.
//!
//! EIP-8130 data (type 0x79, base/base `SpanBatchEip8130TransactionData`) keeps every
//! field except nonce and gas, with each authenticator's 20-byte prefix inline and the
//! proofs in the batch's trailing auth column. Decoding borrows the input.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const bits_module = @import("span_batch_bits.zig");
const Address = primitives.Address;
const AccessList = consensus.AccessList;
const AuthorizationList = consensus.AuthorizationList;
const Envelope = consensus.Envelope;
const Signature = consensus.Signature;
const Error = bits_module.Error;
const eip8130 = consensus.eip8130;

pub const tx_type_legacy: u8 = 0x00;
pub const tx_type_eip2930: u8 = 0x01;
pub const tx_type_eip1559: u8 = 0x02;
pub const tx_type_eip7702: u8 = 0x04;
pub const tx_type_eip8130: u8 = 0x79;
pub const tx_type_deposit: u8 = 0x7e;

/// base/base `OpTxType::try_from(u8)`: the type bytes a span batch may carry.
pub fn is_known_tx_type(tx_type: u8) bool {
    return switch (tx_type) {
        tx_type_legacy,
        tx_type_eip2930,
        tx_type_eip1559,
        tx_type_eip7702,
        tx_type_eip8130,
        tx_type_deposit,
        => true,
        else => false,
    };
}

/// Transaction type of encoded span tx data: the leading type byte, or legacy.
pub fn tx_type_of(data: []const u8) u8 {
    assert(data.len > 0);
    if (data[0] > 0x7f) return tx_type_legacy;
    assert(data[0] <= 0x7f);
    return data[0];
}

pub const Legacy = struct {
    value: u256,
    gas_price: u256,
    data: []const u8,
};

pub const Eip2930 = struct {
    value: u256,
    gas_price: u256,
    data: []const u8,
    access_list: AccessList,
};

pub const Eip1559 = struct {
    value: u256,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    data: []const u8,
    access_list: AccessList,
};

pub const Eip7702 = struct {
    value: u256,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    data: []const u8,
    access_list: AccessList,
    authorization_list: AuthorizationList,
};

/// The `(sender_proof, payer_proof)` pair of one EIP-8130 transaction.
pub const AuthProofs = struct {
    sender_proof: []const u8,
    payer_proof: []const u8,
};

/// Length of an authenticator address prefixed to its proof.
pub const authenticator_length = 20;

pub const Eip8130 = struct {
    sender: ?Address = null,
    nonce_key: u256 = 0,
    valid_after: u64 = 0,
    valid_before: u64 = 0,
    max_priority_fee_per_gas: u128 = 0,
    max_fee_per_gas: u128 = 0,
    /// The open payer is the zero address here (20 bytes), unlike the tx encoding.
    payer: ?Address = null,
    account_changes: eip8130.AccountChanges = .empty,
    calls: eip8130.Calls = .empty,
    metadata: []const u8 = &.{},
    /// 20 bytes when `sender` is set, else empty.
    sender_authenticator: []const u8 = &.{},
    /// 20 bytes for a named (non-open) payer, else empty.
    payer_authenticator: []const u8 = &.{},

    pub fn named_payer(payer: ?Address) bool {
        const address = payer orelse return false;
        return !address.eql(eip8130.open_payer);
    }

    fn optional_address_length(address: ?Address) usize {
        return if (address == null) 1 else 1 + authenticator_length;
    }

    fn encode_optional_address(encoder: *rlp.Encoder, address: ?Address) void {
        if (address) |value| encoder.bytes(&value.bytes) else encoder.bytes(&.{});
    }

    fn decode_optional_address(items: *rlp.Decoder) rlp.Error!?Address {
        const raw = try items.bytes();
        if (raw.len == 0) return null;
        if (raw.len != authenticator_length) return error.Overflow;
        return Address.from_slice(raw);
    }

    fn payload_length(data: *const Eip8130) usize {
        return optional_address_length(data.sender) + rlp.int_length(data.nonce_key) +
            rlp.int_length(data.valid_after) + rlp.int_length(data.valid_before) +
            rlp.int_length(data.max_priority_fee_per_gas) +
            rlp.int_length(data.max_fee_per_gas) + optional_address_length(data.payer) +
            data.account_changes.rlp_length() + data.calls.rlp_length() +
            rlp.bytes_length(data.metadata) + rlp.bytes_length(data.sender_authenticator) +
            rlp.bytes_length(data.payer_authenticator);
    }

    pub fn rlp_length(data: *const Eip8130) usize {
        return rlp.list_length(data.payload_length());
    }

    pub fn encode(data: *const Eip8130, encoder: *rlp.Encoder) void {
        const start = encoder.position;
        encoder.list_header(data.payload_length());
        encode_optional_address(encoder, data.sender);
        encoder.int(data.nonce_key);
        encoder.int(data.valid_after);
        encoder.int(data.valid_before);
        encoder.int(data.max_priority_fee_per_gas);
        encoder.int(data.max_fee_per_gas);
        encode_optional_address(encoder, data.payer);
        data.account_changes.rlp_encode(encoder);
        data.calls.rlp_encode(encoder);
        encoder.bytes(data.metadata);
        encoder.bytes(data.sender_authenticator);
        encoder.bytes(data.payer_authenticator);
        assert(encoder.position - start == data.rlp_length());
    }

    /// Decodes the list after the type byte; authenticator lengths must match the actors.
    pub fn decode(payload: []const u8) Error!Eip8130 {
        return decode_rlp(payload) catch return error.InvalidTransactionData;
    }

    fn decode_rlp(payload: []const u8) (rlp.Error || Error)!Eip8130 {
        var decoder = rlp.Decoder.init(payload);
        var items = try decoder.list();
        const data: Eip8130 = .{
            .sender = try decode_optional_address(&items),
            .nonce_key = try items.int(u256),
            .valid_after = try items.int(u64),
            .valid_before = try items.int(u64),
            .max_priority_fee_per_gas = try items.int(u128),
            .max_fee_per_gas = try items.int(u128),
            .payer = try decode_optional_address(&items),
            .account_changes = try eip8130.AccountChanges.decode_list(&items),
            .calls = try eip8130.Calls.decode_list(&items),
            .metadata = try items.bytes(),
            .sender_authenticator = try items.bytes(),
            .payer_authenticator = try items.bytes(),
        };
        try items.finish();
        if (data.calls.count > eip8130.max_call_phases_per_tx) return error.Overflow;
        try check_authenticator(data.sender_authenticator, data.sender != null);
        try check_authenticator(data.payer_authenticator, named_payer(data.payer));
        return data;
    }

    fn check_authenticator(authenticator: []const u8, configured: bool) Error!void {
        const length: usize = if (configured) authenticator_length else 0;
        if (authenticator.len != length) return error.InvalidTransactionData;
    }

    /// `authenticator || proof` for configured actors, else the proof alone.
    fn join(
        arena: std.mem.Allocator,
        authenticator: []const u8,
        proof: []const u8,
        configured: bool,
    ) Error![]const u8 {
        if (!configured) return proof;
        if (proof.len == 0) return authenticator;
        const joined = try arena.alloc(u8, authenticator.len + proof.len);
        @memcpy(joined[0..authenticator.len], authenticator);
        @memcpy(joined[authenticator.len..], proof);
        return joined;
    }

    /// Splits a signed auth field into its inline authenticator and the column proof.
    fn split(auth: []const u8, configured: bool) Error![2][]const u8 {
        if (!configured) return .{ &.{}, auth };
        if (auth.len < authenticator_length) return error.InvalidAuthData;
        return .{ auth[0..authenticator_length], auth[authenticator_length..] };
    }

    /// Rebuilds the signed transaction (base/base `to_tx`).
    pub fn to_signed(
        data: *const Eip8130,
        arena: std.mem.Allocator,
        chain_id: u64,
        nonce: u64,
        gas: u64,
        proofs: AuthProofs,
    ) Error!eip8130.Signed {
        const sender_auth = try join(
            arena,
            data.sender_authenticator,
            proofs.sender_proof,
            data.sender != null,
        );
        const payer_named = named_payer(data.payer);
        const payer_authenticator = data.payer_authenticator;
        const payer_auth = try join(arena, payer_authenticator, proofs.payer_proof, payer_named);
        const signed: eip8130.Signed = .{
            .sender_auth = sender_auth,
            .payer_auth = payer_auth,
            .tx = .{
                .chain_id = chain_id,
                .sender = data.sender,
                .nonce_key = data.nonce_key,
                .nonce_sequence = nonce,
                .valid_after = data.valid_after,
                .valid_before = data.valid_before,
                .max_priority_fee_per_gas = data.max_priority_fee_per_gas,
                .max_fee_per_gas = data.max_fee_per_gas,
                .gas_limit = gas,
                .account_changes = data.account_changes,
                .calls = data.calls,
                .metadata = data.metadata,
                .payer = data.payer,
            },
        };
        assert(signed.tx.gas_limit == gas);
        return signed;
    }

    pub const Split = struct { data: Eip8130, proofs: AuthProofs };

    /// Splits a signed transaction into span data and auth proofs (base/base `add_txs`).
    pub fn from_signed(signed: eip8130.Signed) Error!Split {
        const tx = signed.tx;
        const sender = try split(signed.sender_auth, tx.sender != null);
        const payer = try split(signed.payer_auth, named_payer(tx.payer));
        const result: Split = .{
            .data = .{
                .sender = tx.sender,
                .nonce_key = tx.nonce_key,
                .valid_after = tx.valid_after,
                .valid_before = tx.valid_before,
                .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
                .max_fee_per_gas = tx.max_fee_per_gas,
                .payer = tx.payer,
                .account_changes = tx.account_changes,
                .calls = tx.calls,
                .metadata = tx.metadata,
                .sender_authenticator = sender[0],
                .payer_authenticator = payer[0],
            },
            .proofs = .{ .sender_proof = sender[1], .payer_proof = payer[1] },
        };
        assert(result.data.sender_authenticator.len <= authenticator_length);
        return result;
    }
};

/// alloy truncates U256 fee fields to their low 128 bits when rebuilding a tx.
fn low_u128(value: u256) u128 {
    return @truncate(value);
}

pub const TxData = union(enum) {
    legacy: Legacy,
    eip2930: Eip2930,
    eip1559: Eip1559,
    eip7702: Eip7702,
    eip8130: Eip8130,

    pub fn tx_type(tx_data: TxData) u8 {
        return switch (tx_data) {
            .legacy => tx_type_legacy,
            .eip2930 => tx_type_eip2930,
            .eip1559 => tx_type_eip1559,
            .eip7702 => tx_type_eip7702,
            .eip8130 => tx_type_eip8130,
        };
    }

    /// Decodes span tx data (`rlp(fields)` or `type || rlp(fields)`).
    pub fn decode(data: []const u8) Error!TxData {
        if (data.len > 0 and data[0] > 0x7f) {
            return .{ .legacy = try decode_item(Legacy, data) };
        }
        if (data.len <= 1) return error.InvalidTransactionData;
        const payload = data[1..];
        return switch (data[0]) {
            tx_type_eip2930 => .{ .eip2930 = try decode_item(Eip2930, payload) },
            tx_type_eip1559 => .{ .eip1559 = try decode_item(Eip1559, payload) },
            tx_type_eip7702 => .{ .eip7702 = try decode_item(Eip7702, payload) },
            tx_type_eip8130 => .{ .eip8130 = try Eip8130.decode(payload) },
            else => error.InvalidTransactionData,
        };
    }

    fn decode_item(comptime T: type, payload: []const u8) Error!T {
        assert(payload.len > 0);
        var decoder = rlp.Decoder.init(payload);
        const value = rlp.decode(T, &decoder) catch return error.InvalidTransactionData;
        assert(decoder.position <= payload.len);
        return value;
    }

    pub fn encoded_length(tx_data: TxData) usize {
        const length = switch (tx_data) {
            .legacy => |fields| rlp.length(fields),
            .eip8130 => |fields| 1 + fields.rlp_length(),
            inline else => |fields| 1 + rlp.length(fields),
        };
        assert(length > 0);
        return length;
    }

    pub fn encode(tx_data: TxData, out: []u8) []u8 {
        const length = tx_data.encoded_length();
        assert(out.len >= length);
        var encoder = rlp.Encoder.init(out[0..length]);
        switch (tx_data) {
            .legacy => |fields| rlp.encode(&encoder, fields),
            .eip8130 => |fields| {
                encoder.raw(&.{tx_type_eip8130});
                fields.encode(&encoder);
            },
            inline else => |fields| {
                encoder.raw(&.{tx_data.tx_type()});
                rlp.encode(&encoder, fields);
            },
        }
        assert(encoder.written().len == length);
        return out[0..length];
    }

    /// Rebuilds the signed envelope (base/base `to_signed_tx`). `protected` selects
    /// EIP-155 replay protection for legacy transactions.
    pub fn to_envelope(
        tx_data: TxData,
        nonce: u64,
        gas: u64,
        to: ?Address,
        chain_id: u64,
        signature: Signature,
        protected: bool,
    ) Error!Envelope {
        const kind: consensus.TxKind = if (to) |address| .{ .call = address } else .create;
        const envelope: Envelope = switch (tx_data) {
            .legacy => |fields| .{ .legacy = .{ .signature = signature, .tx = .{
                .chain_id = if (protected) chain_id else null,
                .nonce = nonce,
                .gas_price = low_u128(fields.gas_price),
                .gas_limit = gas,
                .to = kind,
                .value = fields.value,
                .input = fields.data,
            } } },
            .eip2930 => |fields| .{ .eip2930 = .{ .signature = signature, .tx = .{
                .chain_id = chain_id,
                .nonce = nonce,
                .gas_price = low_u128(fields.gas_price),
                .gas_limit = gas,
                .to = kind,
                .value = fields.value,
                .input = fields.data,
                .access_list = fields.access_list,
            } } },
            .eip1559 => |fields| .{ .eip1559 = .{ .signature = signature, .tx = .{
                .chain_id = chain_id,
                .nonce = nonce,
                .max_priority_fee_per_gas = low_u128(fields.max_priority_fee_per_gas),
                .max_fee_per_gas = low_u128(fields.max_fee_per_gas),
                .gas_limit = gas,
                .to = kind,
                .value = fields.value,
                .input = fields.data,
                .access_list = fields.access_list,
            } } },
            .eip7702 => |fields| try eip7702_envelope(fields, nonce, gas, to, chain_id, signature),
            // Proof: callers rebuild EIP-8130 with `Eip8130.to_signed` (it needs auth proofs).
            .eip8130 => unreachable,
        };
        assert(envelope != .deposit);
        return envelope;
    }

    fn eip7702_envelope(
        fields: Eip7702,
        nonce: u64,
        gas: u64,
        to: ?Address,
        chain_id: u64,
        signature: Signature,
    ) Error!Envelope {
        const address = to orelse return error.InvalidTransactionData;
        return .{ .eip7702 = .{ .signature = signature, .tx = .{
            .chain_id = chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = low_u128(fields.max_priority_fee_per_gas),
            .max_fee_per_gas = low_u128(fields.max_fee_per_gas),
            .gas_limit = gas,
            .to = address,
            .value = fields.value,
            .input = fields.data,
            .access_list = fields.access_list,
            .authorization_list = fields.authorization_list,
        } } };
    }

    /// Splits the non-column fields out of a signed envelope (base/base `TryFrom`).
    pub fn from_envelope(envelope: Envelope) Error!TxData {
        const tx_data: TxData = switch (envelope) {
            .legacy => |signed| .{ .legacy = .{
                .value = signed.tx.value,
                .gas_price = signed.tx.gas_price,
                .data = signed.tx.input,
            } },
            .eip2930 => |signed| .{ .eip2930 = .{
                .value = signed.tx.value,
                .gas_price = signed.tx.gas_price,
                .data = signed.tx.input,
                .access_list = signed.tx.access_list,
            } },
            .eip1559 => |signed| .{ .eip1559 = .{
                .value = signed.tx.value,
                .max_priority_fee_per_gas = signed.tx.max_priority_fee_per_gas,
                .max_fee_per_gas = signed.tx.max_fee_per_gas,
                .data = signed.tx.input,
                .access_list = signed.tx.access_list,
            } },
            .eip7702 => |signed| .{ .eip7702 = .{
                .value = signed.tx.value,
                .max_priority_fee_per_gas = signed.tx.max_priority_fee_per_gas,
                .max_fee_per_gas = signed.tx.max_fee_per_gas,
                .data = signed.tx.input,
                .access_list = signed.tx.access_list,
                .authorization_list = signed.tx.authorization_list,
            } },
            // Base has no blob transactions: its envelope decoder rejects type 0x03.
            .eip4844 => return error.InvalidTransactionData,
            .eip8130 => |signed| .{ .eip8130 = (try Eip8130.from_signed(signed)).data },
            .deposit => return error.InvalidTransactionType,
        };
        assert(tx_data.tx_type() == @backingInt(envelope.tx_type()));
        return tx_data;
    }
};

const testing = std.testing;

fn expect_roundtrip(tx_data: TxData) !void {
    var buffer: [512]u8 = undefined;
    const encoded = tx_data.encode(&buffer);
    try testing.expectEqual(tx_data.tx_type(), tx_type_of(encoded));
    const decoded = try TxData.decode(encoded);
    var again: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, encoded, decoded.encode(&again));
}

test "span tx data: legacy, 2930, 1559 and 7702 roundtrip" {
    const data: []const u8 = &.{ 0x01, 0x02, 0x03 };
    try expect_roundtrip(.{ .legacy = .{ .value = 0xff, .gas_price = 0xee, .data = data } });
    try expect_roundtrip(.{ .eip2930 = .{
        .value = 0xff,
        .gas_price = 0xee,
        .data = data,
        .access_list = .empty,
    } });
    try expect_roundtrip(.{ .eip1559 = .{
        .value = 0xff,
        .max_priority_fee_per_gas = 0xdd,
        .max_fee_per_gas = 0xee,
        .data = data,
        .access_list = .empty,
    } });
    var auth_buffer: [128]u8 = undefined;
    const authorizations = AuthorizationList.build(&auth_buffer, &.{.{
        .chain_id = 1,
        .address = Address.from_slice(&(@as([17]u8, @splat(0)) ++ [_]u8{ 1, 2, 3 })),
        .nonce = 2,
        .y_parity = 1,
        .r = 5,
        .s = 6,
    }});
    try expect_roundtrip(.{ .eip7702 = .{
        .value = 0xff,
        .max_priority_fee_per_gas = 0xdd,
        .max_fee_per_gas = 0xee,
        .data = data,
        .access_list = .empty,
        .authorization_list = authorizations,
    } });
}

test "span tx data: invalid types and 7702 without to" {
    try testing.expectError(error.InvalidTransactionData, TxData.decode(&.{}));
    try testing.expectError(error.InvalidTransactionData, TxData.decode(&.{0x02}));
    try testing.expectError(error.InvalidTransactionData, TxData.decode(&.{ 0x00, 0xc0 }));
    try testing.expectError(error.InvalidTransactionData, TxData.decode(&.{ 0x7e, 0xc0 }));
    try testing.expectError(error.InvalidTransactionData, TxData.decode(&.{ 0x79, 0xc0 }));
    const tx_data: TxData = .{ .eip7702 = .{
        .value = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .data = &.{},
        .access_list = .empty,
        .authorization_list = .empty,
    } };
    const signature: Signature = .{ .y_parity = false, .r = 1, .s = 1 };
    const result = tx_data.to_envelope(0, 0, null, 1, signature, true);
    try testing.expectError(error.InvalidTransactionData, result);
}

//! Span batch transaction data: the per-transaction fields that are not split into
//! shared columns (nonce, gas, `to`, and signature are columns), for legacy,
//! EIP-2930, EIP-1559 and EIP-7702 transactions, and their conversion to and from
//! signed EIP-2718 envelopes. Mirrors base/base
//! `crates/consensus/protocol/src/batch/tx_data/*`.
//!
//! EIP-8130 data is recognised (type 0x79) but not decoded: see
//! `Error.Eip8130Unsupported`. Decoding borrows the input.

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

/// alloy truncates U256 fee fields to their low 128 bits when rebuilding a tx.
fn low_u128(value: u256) u128 {
    return @truncate(value);
}

pub const TxData = union(enum) {
    legacy: Legacy,
    eip2930: Eip2930,
    eip1559: Eip1559,
    eip7702: Eip7702,

    pub fn tx_type(tx_data: TxData) u8 {
        return switch (tx_data) {
            .legacy => tx_type_legacy,
            .eip2930 => tx_type_eip2930,
            .eip1559 => tx_type_eip1559,
            .eip7702 => tx_type_eip7702,
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
            tx_type_eip8130 => error.Eip8130Unsupported,
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
            // EIP-8130 span batch data (base/base `SpanBatchEip8130TransactionData`) is
            // not ported yet.
            .deposit, .eip8130 => return error.InvalidTransactionType,
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
    try testing.expectError(error.Eip8130Unsupported, TxData.decode(&.{ 0x79, 0xc0 }));
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

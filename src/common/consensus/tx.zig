//! Transaction types and the EIP-2718 envelope: legacy (EIP-155), EIP-2930, EIP-1559,
//! EIP-4844, EIP-7702 and the OP Stack deposit (0x7E).
//! Mirrors base/base `crates/common/consensus/src/transaction` and alloy-consensus.
//!
//! Decoding is zero copy: `input` and list fields borrow the encoded bytes, which must
//! outlive the decoded value. Hashing streams the encoding into keccak, so no buffer
//! sized for the transaction is needed.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const fields = @import("tx_fields.zig");
const signature_module = @import("signature.zig");
pub const eip8130 = @import("eip8130.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Encoder = rlp.Encoder;
const Decoder = rlp.Decoder;
const Signature = signature_module.Signature;
const Recoverer = signature_module.Recoverer;
pub const TxKind = fields.TxKind;
pub const AccessList = fields.AccessList;
pub const AuthorizationList = fields.AuthorizationList;
pub const HashList = fields.HashList;

pub const TxType = enum(u8) {
    legacy = 0x00,
    eip2930 = 0x01,
    eip1559 = 0x02,
    eip4844 = 0x03,
    eip7702 = 0x04,
    /// Base account abstraction (Everest).
    eip8130 = 0x79,
    deposit = 0x7e,
};

pub const Legacy = struct {
    /// EIP-155 replay protection; null for pre-EIP-155 transactions.
    chain_id: ?u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: TxKind,
    value: u256,
    input: []const u8,

    /// The six fields shared by the signed and signing encodings.
    fn core(tx: Legacy) LegacyCore {
        return .{
            .nonce = tx.nonce,
            .gas_price = tx.gas_price,
            .gas_limit = tx.gas_limit,
            .to = tx.to,
            .value = tx.value,
            .input = tx.input,
        };
    }
};

const LegacyCore = struct {
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: TxKind,
    value: u256,
    input: []const u8,
};

pub const Eip2930 = struct {
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: TxKind,
    value: u256,
    input: []const u8,
    access_list: AccessList,
};

pub const Eip1559 = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: TxKind,
    value: u256,
    input: []const u8,
    access_list: AccessList,
};

pub const Eip4844 = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    value: u256,
    input: []const u8,
    access_list: AccessList,
    max_fee_per_blob_gas: u128,
    blob_versioned_hashes: HashList,
};

pub const Eip7702 = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    value: u256,
    input: []const u8,
    access_list: AccessList,
    authorization_list: AuthorizationList,
};

/// OP Stack deposited transaction. Unsigned; `from` is set by L1 derivation.
pub const Deposit = struct {
    source_hash: B256,
    from: Address,
    to: TxKind,
    mint: u128,
    value: u256,
    gas_limit: u64,
    is_system_transaction: bool,
    input: []const u8,
};

pub fn Signed(comptime T: type) type {
    return struct { tx: T, signature: Signature };
}

fn signature_length(signature: Signature) usize {
    return 1 + rlp.int_length(signature.r) + rlp.int_length(signature.s);
}

fn encode_signature(encoder: *Encoder, signature: Signature) void {
    encoder.boolean(signature.y_parity);
    encoder.int(signature.r);
    encoder.int(signature.s);
}

fn legacy_payload_length(tx: Legacy, signature: ?Signature) usize {
    const core_length = rlp.codec.fields_length(tx.core());
    if (signature) |sig| {
        const v = sig.legacy_v(tx.chain_id);
        return core_length + rlp.int_length(v) + rlp.int_length(sig.r) + rlp.int_length(sig.s);
    }
    const chain_id = tx.chain_id orelse return core_length;
    return core_length + rlp.int_length(chain_id) + 2;
}

/// Legacy RLP list: signed `[..., v, r, s]` or EIP-155 signing `[..., chain_id, 0, 0]`.
fn encode_legacy(encoder: *Encoder, tx: Legacy, signature: ?Signature) void {
    encoder.list_header(legacy_payload_length(tx, signature));
    rlp.codec.encode_fields(encoder, tx.core());
    if (signature) |sig| {
        encoder.int(sig.legacy_v(tx.chain_id));
        encoder.int(sig.r);
        encoder.int(sig.s);
    } else if (tx.chain_id) |chain_id| {
        encoder.int(chain_id);
        encoder.int(@as(u8, 0));
        encoder.int(@as(u8, 0));
    }
}

fn typed_payload_length(tx: anytype, signature: ?Signature) usize {
    const sig_length = if (signature) |sig| signature_length(sig) else 0;
    return rlp.codec.fields_length(tx) + sig_length;
}

/// `type || rlp([fields..., (y_parity, r, s)])`.
fn encode_typed(encoder: *Encoder, tx_type: TxType, tx: anytype, signature: ?Signature) void {
    encoder.raw(&.{@backingInt(tx_type)});
    encoder.list_header(typed_payload_length(tx, signature));
    rlp.codec.encode_fields(encoder, tx);
    if (signature) |sig| encode_signature(encoder, sig);
}

/// Length of the payload of `rlp([fields..., y_parity, r, s])` for a signed typed tx.
pub fn signed_payload_length(comptime T: type, signed: Signed(T)) usize {
    return typed_payload_length(signed.tx, signed.signature);
}

/// Writes `rlp([fields..., y_parity, r, s])` without the EIP-2718 type byte.
pub fn encode_signed_list(comptime T: type, encoder: *Encoder, signed: Signed(T)) void {
    encoder.list_header(typed_payload_length(signed.tx, signed.signature));
    rlp.codec.encode_fields(encoder, signed.tx);
    encode_signature(encoder, signed.signature);
}

/// Decodes exactly one `rlp([fields..., y_parity, r, s])` list item.
pub fn decode_signed_list(comptime T: type, item: []const u8) DecodeError!Signed(T) {
    return decode_typed(T, item);
}

fn tx_type_of(comptime T: type) TxType {
    return switch (T) {
        Legacy => .legacy,
        Eip2930 => .eip2930,
        Eip1559 => .eip1559,
        Eip4844 => .eip4844,
        Eip7702 => .eip7702,
        Deposit => .deposit,
        else => @compileError("not a transaction type: " ++ @typeName(T)),
    };
}

pub const DecodeError = rlp.Error || error{
    UnknownTxType,
    /// Legacy `v` that is neither 27/28 nor a valid EIP-155 value.
    InvalidV,
    /// A typed transaction encoded as a list, or a legacy one wrapped in a string.
    InvalidEnvelope,
};

fn decode_typed(comptime T: type, payload: []const u8) DecodeError!Signed(T) {
    var decoder = Decoder.init(payload);
    var items = try decoder.list();
    try decoder.finish();
    const tx = try rlp.codec.decode_fields(T, &items);
    const signature: Signature = .{
        .y_parity = try items.boolean(),
        .r = try items.int(u256),
        .s = try items.int(u256),
    };
    try items.finish();
    return .{ .tx = tx, .signature = signature };
}

fn decode_legacy(input: []const u8) DecodeError!Signed(Legacy) {
    var decoder = Decoder.init(input);
    var items = try decoder.list();
    try decoder.finish();
    const core = try rlp.codec.decode_fields(LegacyCore, &items);
    const v = signature_module.decode_legacy_v(try items.int(u256)) orelse
        return error.InvalidV;
    const r = try items.int(u256);
    const s = try items.int(u256);
    try items.finish();
    return .{
        .tx = .{
            .chain_id = v.chain_id,
            .nonce = core.nonce,
            .gas_price = core.gas_price,
            .gas_limit = core.gas_limit,
            .to = core.to,
            .value = core.value,
            .input = core.input,
        },
        .signature = .{ .y_parity = v.y_parity, .r = r, .s = s },
    };
}

pub const KeccakSink = @import("hashing.zig").KeccakSink;

/// A signed transaction (or deposit) in any supported EIP-2718 type.
pub const Envelope = union(TxType) {
    legacy: Signed(Legacy),
    eip2930: Signed(Eip2930),
    eip1559: Signed(Eip1559),
    eip4844: Signed(Eip4844),
    eip7702: Signed(Eip7702),
    eip8130: eip8130.Signed,
    deposit: Deposit,

    pub fn tx_type(envelope: Envelope) TxType {
        return std.meta.activeTag(envelope);
    }

    /// Length of the EIP-2718 encoding (what is hashed and sent over RPC).
    pub fn encoded_length(envelope: Envelope) usize {
        return switch (envelope) {
            .legacy => |signed| rlp.list_length(legacy_payload_length(signed.tx, signed.signature)),
            .deposit => |tx| 1 + rlp.list_length(typed_payload_length(tx, null)),
            .eip8130 => |signed| signed.encoded_length(),
            inline else => |signed| 1 + rlp.list_length(
                typed_payload_length(signed.tx, signed.signature),
            ),
        };
    }

    /// Writes the EIP-2718 encoding.
    pub fn encode(envelope: Envelope, encoder: *Encoder) void {
        const start = encoder.position;
        switch (envelope) {
            .legacy => |signed| encode_legacy(encoder, signed.tx, signed.signature),
            .deposit => |tx| encode_typed(encoder, .deposit, tx, null),
            .eip8130 => |signed| signed.encode(encoder),
            inline else => |signed| encode_typed(
                encoder,
                tx_type_of(@TypeOf(signed.tx)),
                signed.tx,
                signed.signature,
            ),
        }
        assert(encoder.position - start == envelope.encoded_length());
    }

    pub fn encode_to(envelope: Envelope, buffer: []u8) []u8 {
        var encoder = Encoder.init(buffer);
        envelope.encode(&encoder);
        return encoder.written();
    }

    /// Length inside a block body / devp2p list: typed txs are wrapped in a string.
    pub fn network_length(envelope: Envelope) usize {
        const length = envelope.encoded_length();
        if (envelope == .legacy) return length;
        return rlp.header_length(length) + length;
    }

    pub fn encode_network(envelope: Envelope, encoder: *Encoder) void {
        if (envelope != .legacy) encoder.string_header(envelope.encoded_length());
        envelope.encode(encoder);
    }

    /// Decodes exactly one EIP-2718 encoded transaction.
    pub fn decode(encoded: []const u8) DecodeError!Envelope {
        if (encoded.len == 0) return error.UnexpectedEnd;
        if (encoded[0] >= 0xc0) return .{ .legacy = try decode_legacy(encoded) };
        const payload = encoded[1..];
        const type_byte = std.enums.fromInt(TxType, encoded[0]) orelse return error.UnknownTxType;
        return switch (type_byte) {
            .legacy => error.InvalidEnvelope,
            .eip2930 => .{ .eip2930 = try decode_typed(Eip2930, payload) },
            .eip1559 => .{ .eip1559 = try decode_typed(Eip1559, payload) },
            .eip4844 => .{ .eip4844 = try decode_typed(Eip4844, payload) },
            .eip7702 => .{ .eip7702 = try decode_typed(Eip7702, payload) },
            .eip8130 => .{ .eip8130 = try eip8130.Signed.decode_payload(payload) },
            .deposit => .{ .deposit = try rlp.decode_exact(Deposit, payload) },
        };
    }

    /// Decodes the next block-body item: a legacy list or a string holding EIP-2718.
    pub fn decode_network(decoder: *Decoder) DecodeError!Envelope {
        const header = try decoder.peek_header();
        if (header.list) return .{ .legacy = try decode_legacy(try decoder.raw()) };
        const inner = try decoder.bytes();
        if (inner.len == 0 or inner[0] >= 0x80) return error.InvalidEnvelope;
        return decode(inner);
    }

    /// keccak256 of the EIP-2718 encoding.
    pub fn hash(envelope: Envelope) B256 {
        var sink: KeccakSink = .{};
        var encoder = sink.encoder();
        envelope.encode(&encoder);
        return sink.final();
    }

    /// The hash the sender signed; null for deposits.
    pub fn signing_hash(envelope: Envelope) ?B256 {
        var sink: KeccakSink = .{};
        var encoder = sink.encoder();
        switch (envelope) {
            .legacy => |signed| encode_legacy(&encoder, signed.tx, null),
            .deposit => return null,
            .eip8130 => |signed| return signed.tx.sender_signature_hash(),
            inline else => |signed| {
                encode_typed(&encoder, tx_type_of(@TypeOf(signed.tx)), signed.tx, null);
            },
        }
        return sink.final();
    }

    /// The secp256k1 signature; null for deposits and EIP-8130 (auth blobs).
    pub fn signature(envelope: Envelope) ?Signature {
        return switch (envelope) {
            .deposit, .eip8130 => null,
            inline else => |signed| signed.signature,
        };
    }

    /// The sender. Rejects high-s signatures (EIP-2). Deposits report `from`.
    pub fn recover_sender(envelope: Envelope, recoverer: Recoverer) ?Address {
        switch (envelope) {
            .deposit => |tx| return tx.from,
            .eip8130 => |signed| return signed.recover_sender(recoverer),
            else => {},
        }
        const sig = envelope.signature().?;
        if (!sig.is_low_s()) return null;
        return recoverer(envelope.signing_hash().?, sig);
    }

    pub fn chain_id(envelope: Envelope) ?u64 {
        return switch (envelope) {
            .legacy => |signed| signed.tx.chain_id,
            .deposit => null,
            inline else => |signed| signed.tx.chain_id,
        };
    }

    pub fn nonce(envelope: Envelope) ?u64 {
        return switch (envelope) {
            .deposit => null,
            .eip8130 => |signed| signed.tx.nonce_sequence,
            inline else => |signed| signed.tx.nonce,
        };
    }

    pub fn gas_limit(envelope: Envelope) u64 {
        return switch (envelope) {
            .deposit => |tx| tx.gas_limit,
            inline else => |signed| signed.tx.gas_limit,
        };
    }

    pub fn value(envelope: Envelope) u256 {
        return switch (envelope) {
            .deposit => |tx| tx.value,
            .eip8130 => 0,
            inline else => |signed| signed.tx.value,
        };
    }

    pub fn input(envelope: Envelope) []const u8 {
        return switch (envelope) {
            .deposit => |tx| tx.input,
            .eip8130 => &.{},
            inline else => |signed| signed.tx.input,
        };
    }

    pub fn kind(envelope: Envelope) TxKind {
        return switch (envelope) {
            .deposit => |tx| tx.to,
            .eip4844 => |signed| .{ .call = signed.tx.to },
            .eip7702 => |signed| .{ .call = signed.tx.to },
            // As base/base: calls live in phases; the top-level kind is a call to zero.
            .eip8130 => .{ .call = Address.zero },
            inline else => |signed| signed.tx.to,
        };
    }

    pub fn access_list(envelope: Envelope) AccessList {
        return switch (envelope) {
            .legacy, .deposit, .eip8130 => AccessList.empty,
            inline else => |signed| signed.tx.access_list,
        };
    }

    /// Fee cap per gas (gas price for legacy/2930, 0 for deposits).
    pub fn max_fee_per_gas(envelope: Envelope) u128 {
        return switch (envelope) {
            .legacy => |signed| signed.tx.gas_price,
            .eip2930 => |signed| signed.tx.gas_price,
            .deposit => 0,
            inline else => |signed| signed.tx.max_fee_per_gas,
        };
    }

    /// Tip cap per gas (gas price for legacy/2930, 0 for deposits).
    pub fn max_priority_fee_per_gas(envelope: Envelope) u128 {
        return switch (envelope) {
            .legacy => |signed| signed.tx.gas_price,
            .eip2930 => |signed| signed.tx.gas_price,
            .deposit => 0,
            inline else => |signed| signed.tx.max_priority_fee_per_gas,
        };
    }

    /// Price paid per gas given the block base fee; null when the fee cap is below it.
    pub fn effective_gas_price(envelope: Envelope, base_fee: u64) ?u128 {
        if (envelope == .deposit) return 0;
        const fee_cap = envelope.max_fee_per_gas();
        if (fee_cap < base_fee) return null;
        const tip = @min(envelope.max_priority_fee_per_gas(), fee_cap - base_fee);
        return base_fee + tip;
    }

    pub fn blob_versioned_hashes(envelope: Envelope) HashList {
        return switch (envelope) {
            .eip4844 => |signed| signed.tx.blob_versioned_hashes,
            else => HashList.empty,
        };
    }

    pub fn is_deposit(envelope: Envelope) bool {
        return envelope == .deposit;
    }
};

/// Signs an unsigned transaction with a private key (tests and devnet accounts only).
pub fn sign(
    tx: anytype,
    private_key: [32]u8,
) signature_module.SignError!Envelope {
    const T = @TypeOf(tx);
    const zero: Signature = .{ .y_parity = false, .r = 0, .s = 0 };
    var envelope = @unionInit(Envelope, @tagName(tx_type_of(T)), .{ .tx = tx, .signature = zero });
    const sig = try signature_module.sign(private_key, envelope.signing_hash().?);
    switch (envelope) {
        .deposit, .eip8130 => unreachable, // tx_type_of rejects both at comptime.
        inline else => |*signed| signed.signature = sig,
    }
    return envelope;
}

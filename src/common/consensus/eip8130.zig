//! EIP-8130 (type 0x79): account abstraction by account configuration (Base, Everest).
//! Mirrors base/base `crates/common/consensus/src/transaction/eip8130`.
//!
//! Wire form: `0x79 || rlp([chain_id, sender, nonce_key, nonce_sequence, valid_after,
//! valid_before, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, account_changes,
//! calls, metadata, payer, sender_auth, payer_auth])`.
//!
//! `sender` is empty (EOA path: `sender_auth` is a raw 65-byte k1 signature) or a
//! 20-byte address (account path: `sender_auth` is `authenticator || data`). `payer` is
//! empty (self pay), `0x00` (open payer: `payer_auth` is a raw k1 signature), or a
//! non-zero 20-byte address. Nested lists stay zero copy (`ItemList`).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const signature_module = @import("signature.zig");
const item_list = @import("item_list.zig");
const hashing = @import("hashing.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Encoder = rlp.Encoder;
const Decoder = rlp.Decoder;
const Signature = signature_module.Signature;
const Recoverer = signature_module.Recoverer;
const ItemList = item_list.ItemList;

pub const tx_type: u8 = 0x79;
/// Domain byte of the payer signing hash.
pub const payer_type: u8 = 0x7a;
/// Domain prefix of the replay identifier.
pub const replay_id_type = [2]u8{ 0x79, 0x01 };
pub const base_cost: u64 = 15_000;
/// `nonce_key` value selecting the nonce-free (expiry-bounded) path.
pub const nonce_key_max: u256 = std.math.maxInt(u256);
pub const k1_authenticator = Address.comptime_hex("0000000000000000000000000000000000000001");
pub const open_payer: Address = .zero;
pub const policy_data_length = 52;
pub const max_config_changes_per_tx = 10;
pub const max_account_changes_per_tx = 3;
pub const nonce_free_max_expiry_window: u64 = 20_000;
/// Timestamps below this are seconds and are scaled to milliseconds.
pub const timestamp_ms_threshold: u64 = 100_000_000_000;
pub const max_actors_per_entry = 32;
pub const max_actor_changes_per_config = 5;
pub const max_call_phases_per_tx = 1_024;
pub const max_code_size = 24_576;

pub const scope_unrestricted: u16 = 0x0000;
pub const scope_operator: u16 = 0x0001;
pub const scope_self_payer: u16 = 0x0002;
pub const scope_sponsor_payer: u16 = 0x0004;
pub const scope_policy: u16 = 0x0008;
pub const scope_nonce: u16 = 0x0010;

/// Canonical CREATE2-deployed EIP-8130 contracts (identical on every Base chain).
pub const contracts = struct {
    pub const account_config = Address.comptime_hex("813012Bd8D971928475235BBac6F0488c4A100AC");
    pub const default_account = Address.comptime_hex("81309c54D6Bc190FbBc0FA9f296ea4C6A539ADEf");
    pub const p256_authenticator =
        Address.comptime_hex("8130C89F65750431b564A4730397552a11CeA256");
    pub const webauthn_authenticator =
        Address.comptime_hex("813007b6b1b48E75D91dEc5927ab515d12a0F1d0");
    pub const delegate_authenticator =
        Address.comptime_hex("81301AA52202f8C6b79Cde660440E3c6A7c5ade1");
    pub const canonical_authenticators = [_]Address{
        p256_authenticator,
        webauthn_authenticator,
        delegate_authenticator,
    };

    pub fn is_canonical_authenticator(authenticator: Address) bool {
        for (canonical_authenticators) |canonical| {
            if (canonical.eql(authenticator)) return true;
        }
        return false;
    }
};

pub fn sender_is_policy_gated(scope: u16) bool {
    return scope & scope_policy != 0 and scope & scope_operator == 0;
}

pub fn normalize_timestamp_ms(value: u64) u64 {
    return if (value != 0 and value < timestamp_ms_threshold) value *| 1000 else value;
}

/// One call of a phase: `[to, value, data]`.
pub const Call = struct {
    to: Address,
    value: u256,
    data: []const u8,
};

pub const Phase = ItemList(Call, item_list.codec_decoder(Call));
/// Call phases: `[[call, ...], ...]`.
pub const Calls = ItemList(Phase, Phase.decode_list);

/// `[actor_id, authenticator, scope, policy_data]`.
pub const InitialActor = struct {
    actor_id: B256,
    authenticator: Address,
    scope: u16,
    policy_data: []const u8,
};

pub const InitialActors = ItemList(InitialActor, item_list.codec_decoder(InitialActor));

pub const ChangeType = enum(u8) {
    authorize_actor = 0x00,
    revoke_actor = 0x01,
    increment_local_epoch = 0x02,
    lock = 0x03,
    unlock = 0x04,
};

pub const Channel = enum(u8) {
    local = 0x00,
    multichain = 0x01,

    pub fn rlp_length(channel: Channel) usize {
        return rlp.int_length(@backingInt(channel));
    }

    pub fn rlp_encode(channel: Channel, encoder: *Encoder) void {
        encoder.int(@backingInt(channel));
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!Channel {
        return decode_enum(Channel, decoder);
    }
};

fn decode_enum(comptime E: type, decoder: *Decoder) rlp.Error!E {
    return std.enums.fromInt(E, try decoder.int(u8)) orelse error.Overflow;
}

/// `[op, payload]`.
pub const SignedChange = struct {
    change_type: ChangeType,
    payload: []const u8,

    fn fields_length(change: SignedChange) usize {
        return rlp.int_length(@backingInt(change.change_type)) + rlp.bytes_length(change.payload);
    }

    pub fn rlp_length(change: SignedChange) usize {
        return rlp.list_length(change.fields_length());
    }

    pub fn rlp_encode(change: SignedChange, encoder: *Encoder) void {
        encoder.list_header(change.fields_length());
        encoder.int(@backingInt(change.change_type));
        encoder.bytes(change.payload);
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!SignedChange {
        var items = try decoder.list();
        const change: SignedChange = .{
            .change_type = try decode_enum(ChangeType, &items),
            .payload = try items.bytes(),
        };
        try items.finish();
        return change;
    }
};

pub const SignedChanges = ItemList(SignedChange, item_list.codec_decoder(SignedChange));

pub const CreateEntry = struct {
    user_salt: B256,
    code: []const u8,
    initial_actors: InitialActors,
};

pub const ConfigChange = struct {
    channel: Channel,
    sequence: u64,
    changes: SignedChanges,
    signature: []const u8,
};

/// `[type, ...fields]` with type 0x01 delegation, 0x02 create, 0x03 config change.
pub const AccountChange = union(enum(u8)) {
    delegation: Address = 0x01,
    create: CreateEntry = 0x02,
    config: ConfigChange = 0x03,

    fn fields_length(change: AccountChange) usize {
        const body = switch (change) {
            .delegation => 21,
            .create => |entry| rlp.codec.fields_length(entry),
            .config => |entry| rlp.codec.fields_length(entry),
        };
        return 1 + body;
    }

    pub fn rlp_length(change: AccountChange) usize {
        return rlp.list_length(change.fields_length());
    }

    pub fn rlp_encode(change: AccountChange, encoder: *Encoder) void {
        encoder.list_header(change.fields_length());
        encoder.int(@backingInt(change));
        switch (change) {
            .delegation => |target| encoder.bytes(&target.bytes),
            .create => |entry| rlp.codec.encode_fields(encoder, entry),
            .config => |entry| rlp.codec.encode_fields(encoder, entry),
        }
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!AccountChange {
        var items = try decoder.list();
        const tag = try decode_enum(std.meta.Tag(AccountChange), &items);
        const change: AccountChange = switch (tag) {
            .delegation => .{ .delegation = try rlp.decode(Address, &items) },
            .create => .{ .create = try rlp.codec.decode_fields(CreateEntry, &items) },
            .config => .{ .config = try rlp.codec.decode_fields(ConfigChange, &items) },
        };
        try items.finish();
        return change;
    }
};

pub const AccountChanges = ItemList(AccountChange, item_list.codec_decoder(AccountChange));

fn optional_address_length(address: ?Address) usize {
    return if (address == null) 1 else 21;
}

fn encode_optional_address(encoder: *Encoder, address: ?Address) void {
    if (address) |value| encoder.bytes(&value.bytes) else encoder.bytes(&.{});
}

fn decode_optional_address(decoder: *Decoder) rlp.Error!?Address {
    const raw = try decoder.bytes();
    if (raw.len == 0) return null;
    if (raw.len != 20) return error.Overflow;
    return Address.from_slice(raw);
}

fn payer_length(payer: ?Address) usize {
    const value = payer orelse return 1;
    return if (value.eql(open_payer)) 1 else 21;
}

fn encode_payer(encoder: *Encoder, payer: ?Address) void {
    const value = payer orelse return encoder.bytes(&.{});
    if (value.eql(open_payer)) return encoder.bytes(&.{0});
    encoder.bytes(&value.bytes);
}

fn decode_payer(decoder: *Decoder) rlp.Error!?Address {
    const raw = try decoder.bytes();
    if (raw.len == 0) return null;
    if (raw.len == 1 and raw[0] == 0) return open_payer;
    if (raw.len != 20) return error.Overflow;
    const address = Address.from_slice(raw);
    // The zero address must use the one-byte open-payer form.
    if (address.eql(open_payer)) return error.Overflow;
    return address;
}

/// The unsigned EIP-8130 transaction.
pub const TxEip8130 = struct {
    chain_id: u64,
    sender: ?Address = null,
    nonce_key: u256 = 0,
    nonce_sequence: u64 = 0,
    valid_after: u64 = 0,
    valid_before: u64 = 0,
    max_priority_fee_per_gas: u128 = 0,
    max_fee_per_gas: u128 = 0,
    gas_limit: u64 = 0,
    account_changes: AccountChanges = .empty,
    calls: Calls = .empty,
    metadata: []const u8 = &.{},
    payer: ?Address = null,

    pub fn is_open_payer(tx: TxEip8130) bool {
        return if (tx.payer) |payer| payer.eql(open_payer) else false;
    }

    pub fn valid_after_ms(tx: TxEip8130) u64 {
        return normalize_timestamp_ms(tx.valid_after);
    }

    pub fn valid_before_ms(tx: TxEip8130) u64 {
        return normalize_timestamp_ms(tx.valid_before);
    }

    fn tail_length(tx: TxEip8130) usize {
        return tx.account_changes.rlp_length() + tx.calls.rlp_length() +
            rlp.bytes_length(tx.metadata) + payer_length(tx.payer);
    }

    fn encode_tail(tx: TxEip8130, encoder: *Encoder) void {
        tx.account_changes.rlp_encode(encoder);
        tx.calls.rlp_encode(encoder);
        encoder.bytes(tx.metadata);
        encode_payer(encoder, tx.payer);
    }

    /// Payload length of the field list with `sender` in place of `tx.sender`.
    pub fn fields_length_with(tx: TxEip8130, sender: ?Address) usize {
        return rlp.int_length(tx.chain_id) + optional_address_length(sender) +
            rlp.int_length(tx.nonce_key) + rlp.int_length(tx.nonce_sequence) +
            rlp.int_length(tx.valid_after) + rlp.int_length(tx.valid_before) +
            rlp.int_length(tx.max_priority_fee_per_gas) + rlp.int_length(tx.max_fee_per_gas) +
            rlp.int_length(tx.gas_limit) + tx.tail_length();
    }

    pub fn encode_fields_with(tx: TxEip8130, encoder: *Encoder, sender: ?Address) void {
        const start = encoder.position;
        encoder.int(tx.chain_id);
        encode_optional_address(encoder, sender);
        encoder.int(tx.nonce_key);
        encoder.int(tx.nonce_sequence);
        encoder.int(tx.valid_after);
        encoder.int(tx.valid_before);
        encoder.int(tx.max_priority_fee_per_gas);
        encoder.int(tx.max_fee_per_gas);
        encoder.int(tx.gas_limit);
        tx.encode_tail(encoder);
        assert(encoder.position - start == tx.fields_length_with(sender));
    }

    pub fn decode_fields(items: *Decoder) rlp.Error!TxEip8130 {
        const tx: TxEip8130 = .{
            .chain_id = try items.int(u64),
            .sender = try decode_optional_address(items),
            .nonce_key = try items.int(u256),
            .nonce_sequence = try items.int(u64),
            .valid_after = try items.int(u64),
            .valid_before = try items.int(u64),
            .max_priority_fee_per_gas = try items.int(u128),
            .max_fee_per_gas = try items.int(u128),
            .gas_limit = try items.int(u64),
            .account_changes = try AccountChanges.decode_list(items),
            .calls = try Calls.decode_list(items),
            .metadata = try items.bytes(),
            .payer = try decode_payer(items),
        };
        if (tx.calls.count > max_call_phases_per_tx) return error.Overflow;
        return tx;
    }

    /// `keccak256(prefix || rlp([fields with sender]))`.
    fn domain_hash(tx: TxEip8130, prefix: u8, sender: ?Address) B256 {
        var sink: hashing.KeccakSink = .{};
        var encoder = sink.encoder();
        encoder.raw(&.{prefix});
        encoder.list_header(tx.fields_length_with(sender));
        tx.encode_fields_with(&encoder, sender);
        return sink.final();
    }

    /// What the sender signs: `keccak256(0x79 || rlp(unsigned tx))`.
    pub fn sender_signature_hash(tx: TxEip8130) B256 {
        return tx.domain_hash(tx_type, tx.sender);
    }

    /// What the payer signs: as the sender hash with the resolved sender, domain 0x7a.
    pub fn payer_signature_hash(tx: TxEip8130, resolved_sender: Address) B256 {
        return tx.domain_hash(payer_type, resolved_sender);
    }

    /// `keccak256(0x79 0x01 || rlp([chain_id, sender, valid_after, valid_before,
    /// account_changes, calls, metadata, payer]))`: identifies nonce-free replays.
    pub fn replay_id(tx: TxEip8130, resolved_sender: Address) B256 {
        const payload_length = rlp.int_length(tx.chain_id) + 21 +
            rlp.int_length(tx.valid_after) + rlp.int_length(tx.valid_before) + tx.tail_length();
        var sink: hashing.KeccakSink = .{};
        var encoder = sink.encoder();
        encoder.raw(&replay_id_type);
        encoder.list_header(payload_length);
        encoder.int(tx.chain_id);
        encoder.bytes(&resolved_sender.bytes);
        encoder.int(tx.valid_after);
        encoder.int(tx.valid_before);
        tx.encode_tail(&encoder);
        return sink.final();
    }
};

pub const StaticError = error{ ChainIdMismatch, TipAboveFeeCap, ZeroGasOrFee };

pub const TimestampError = error{
    NonceFreeMalformed,
    NotYetValid,
    NonceFreeExpired,
    NonceFreeExpiryTooFar,
    Expired,
};

pub const StructuralError = error{
    TooManyCallPhases,
    MalformedSenderAuth,
    MalformedPayerAuth,
    TooManyAccountChanges,
    MalformedAccountChange,
};

/// Parses a raw `r || s || v` k1 signature with v in {27, 28}.
pub fn parse_raw_k1(raw: []const u8) ?Signature {
    if (raw.len != 65 or (raw[64] != 27 and raw[64] != 28)) return null;
    return .{
        .y_parity = raw[64] == 28,
        .r = primitives.u256_from_bytes(raw[0..32].*),
        .s = primitives.u256_from_bytes(raw[32..64].*),
    };
}

/// Recovers a raw k1 signer, rejecting high s like transaction recovery does.
pub fn recover_raw_k1(hash: B256, raw: []const u8, recoverer: Recoverer) ?Address {
    const signature = parse_raw_k1(raw) orelse return null;
    if (!signature.is_low_s()) return null;
    return recoverer(hash, signature);
}

/// A signed EIP-8130 transaction.
pub const Signed = struct {
    tx: TxEip8130,
    sender_auth: []const u8,
    payer_auth: []const u8 = &.{},

    fn payload_length(signed: Signed, payer_auth: []const u8) usize {
        return signed.tx.fields_length_with(signed.tx.sender) +
            rlp.bytes_length(signed.sender_auth) + rlp.bytes_length(payer_auth);
    }

    fn encode_with(signed: Signed, encoder: *Encoder, payer_auth: []const u8) void {
        encoder.raw(&.{tx_type});
        encoder.list_header(signed.payload_length(payer_auth));
        signed.tx.encode_fields_with(encoder, signed.tx.sender);
        encoder.bytes(signed.sender_auth);
        encoder.bytes(payer_auth);
    }

    /// Length of the EIP-2718 encoding.
    pub fn encoded_length(signed: Signed) usize {
        return 1 + rlp.list_length(signed.payload_length(signed.payer_auth));
    }

    pub fn encode(signed: Signed, encoder: *Encoder) void {
        const start = encoder.position;
        signed.encode_with(encoder, signed.payer_auth);
        assert(encoder.position - start == signed.encoded_length());
    }

    pub fn encode_to(signed: Signed, buffer: []u8) []u8 {
        var encoder = Encoder.init(buffer);
        signed.encode(&encoder);
        return encoder.written();
    }

    /// The encoding with an empty `payer_auth`: the bytes billed to the sender for L1
    /// data when a payer sponsors the transaction.
    pub fn encoded_length_without_payer_auth(signed: Signed) usize {
        return 1 + rlp.list_length(signed.payload_length(&.{}));
    }

    pub fn encode_without_payer_auth(signed: Signed, encoder: *Encoder) void {
        signed.encode_with(encoder, &.{});
    }

    /// Decodes the payload after the 0x79 type byte (exactly one list).
    pub fn decode_payload(payload: []const u8) rlp.Error!Signed {
        var decoder = Decoder.init(payload);
        var items = try decoder.list();
        try decoder.finish();
        const signed: Signed = .{
            .tx = try TxEip8130.decode_fields(&items),
            .sender_auth = try items.bytes(),
            .payer_auth = try items.bytes(),
        };
        try items.finish();
        return signed;
    }

    pub fn decode(encoded: []const u8) rlp.Error!Signed {
        if (encoded.len == 0) return error.UnexpectedEnd;
        if (encoded[0] != tx_type) return error.Overflow;
        return decode_payload(encoded[1..]);
    }

    /// keccak256 of the EIP-2718 encoding (both auth fields included).
    pub fn hash(signed: Signed) B256 {
        var sink: hashing.KeccakSink = .{};
        var encoder = sink.encoder();
        signed.encode(&encoder);
        return sink.final();
    }

    /// The explicit sender, or the k1 signer of `sender_auth` on the EOA path.
    pub fn recover_sender(signed: Signed, recoverer: Recoverer) ?Address {
        if (signed.tx.sender) |sender| return sender;
        return recover_raw_k1(signed.tx.sender_signature_hash(), signed.sender_auth, recoverer);
    }

    /// Who pays: the sender, an explicit payer, or the k1 signer of `payer_auth`.
    pub fn resolved_payer(signed: Signed, sender: Address, recoverer: Recoverer) ?Address {
        const payer = signed.tx.payer orelse return sender;
        if (!payer.eql(open_payer)) return payer;
        return recover_raw_k1(signed.tx.payer_signature_hash(sender), signed.payer_auth, recoverer);
    }

    pub fn validate_static(signed: Signed, local_chain_id: u64) StaticError!void {
        const tx = signed.tx;
        if (tx.chain_id != local_chain_id) return error.ChainIdMismatch;
        if (tx.max_fee_per_gas < tx.max_priority_fee_per_gas) return error.TipAboveFeeCap;
        if (tx.gas_limit == 0 or tx.max_fee_per_gas == 0) return error.ZeroGasOrFee;
    }

    /// Validity window at `now_ms`; the nonce-free path also bounds the expiry.
    pub fn validate_timestamp(signed: Signed, now_ms: u64) TimestampError!void {
        const tx = signed.tx;
        const valid_after = tx.valid_after_ms();
        const valid_before = tx.valid_before_ms();
        if (tx.nonce_key == nonce_key_max) {
            if (tx.nonce_sequence != 0 or valid_before == 0) return error.NonceFreeMalformed;
            if (valid_after != 0 and now_ms < valid_after) return error.NotYetValid;
            if (valid_before <= now_ms) return error.NonceFreeExpired;
            if (valid_before > now_ms +| nonce_free_max_expiry_window) {
                return error.NonceFreeExpiryTooFar;
            }
            return;
        }
        if (valid_after != 0 and now_ms < valid_after) return error.NotYetValid;
        if (valid_before != 0 and now_ms > valid_before) return error.Expired;
    }

    pub const validate_structure = @import("eip8130_structure.zig").validate;
};

/// Signs the EOA path: `sender_auth = r || s || (27 + parity)` over the sender hash.
pub fn sign_sender(tx: TxEip8130, private_key: [32]u8) signature_module.SignError![65]u8 {
    assert(tx.sender == null);
    return raw_k1(try signature_module.sign(private_key, tx.sender_signature_hash()));
}

/// Signs as open payer for `resolved_sender`.
pub fn sign_payer(
    tx: TxEip8130,
    resolved_sender: Address,
    private_key: [32]u8,
) signature_module.SignError![65]u8 {
    assert(tx.is_open_payer());
    const hash = tx.payer_signature_hash(resolved_sender);
    return raw_k1(try signature_module.sign(private_key, hash));
}

fn raw_k1(signature: Signature) [65]u8 {
    var raw = signature.to_bytes();
    raw[64] += 27;
    return raw;
}

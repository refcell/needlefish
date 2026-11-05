//! EIP-8130 actor authentication and transaction-level authorization, mirroring base/base
//! `crates/execution/eip8130/src/{scope,resolved,recovered,dispatch,authorize,verify}.rs`.
//!
//! An auth blob is `authenticator(20) || data`. The k1 sentinel `address(1)` recovers a
//! secp256k1 signer; the canonical P-256, WebAuthn, and delegate authenticators are verified
//! natively. A delegate hands authentication to another account's actor, one hop deep, and
//! that nested actor must be an admin (scope 0). The resolved actor id must then be bound
//! to the same authenticator in the account's `AccountConfiguration` and be unexpired.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const config = @import("eip8130_config.zig");
const consensus = @import("../../common/consensus/root.zig");
const eip8130 = @import("../../common/consensus/eip8130.zig");
const crypto = @import("../../common/crypto/root.zig");
const common_primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Store = config.Store;
const AccountState = config.AccountState;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = config.Error || error{
    MalformedAuth,
    InvalidSignature,
    NotCanonical,
    NestedDelegate,
    AuthenticationFailed,
    AuthenticatorMismatch,
    ActorExpired,
    DefaultEoaRevoked,
    NestedSignatureScope,
    SenderRecovery,
    PayerRecovery,
    UnexpectedPayerAuth,
    ScopeDenied,
};

pub const p256_authenticator: Address = eip8130.contracts.p256_authenticator.bytes;
pub const webauthn_authenticator: Address = eip8130.contracts.webauthn_authenticator.bytes;
pub const delegate_authenticator: Address = eip8130.contracts.delegate_authenticator.bytes;
const k1_authenticator = config.k1_authenticator;

/// What an actor is being authorized to do.
pub const Operation = enum {
    sender,
    self_payer,
    sponsor_payer,
    config,

    pub fn is_granted_by(operation: Operation, scope: u16) bool {
        if (scope == eip8130.scope_unrestricted) return true;
        return switch (operation) {
            .config => false,
            .sender => scope & (eip8130.scope_operator | eip8130.scope_policy) != 0,
            .self_payer => scope & eip8130.scope_self_payer != 0,
            .sponsor_payer => scope & eip8130.scope_sponsor_payer != 0,
        };
    }
};

/// An authenticated actor: its id, scope, policy gate target, and expiry.
pub const ResolvedActor = struct {
    actor_id: B256,
    scope: u16,
    policy_target: Address,
    expiry: u64,

    pub fn unrestricted(actor_id: B256) ResolvedActor {
        return .{ .actor_id = actor_id, .scope = 0, .policy_target = @splat(0), .expiry = 0 };
    }

    pub fn is_admin(actor: ResolvedActor) bool {
        return actor.scope == 0;
    }

    pub fn is_policy_gated(actor: ResolvedActor) bool {
        return eip8130.sender_is_policy_gated(actor.scope);
    }

    pub fn can_use_nonce_key(actor: ResolvedActor, nonce_key: u256) bool {
        return actor.scope == eip8130.scope_unrestricted or nonce_key == eip8130.nonce_key_max or
            actor.scope & eip8130.scope_nonce != 0;
    }

    pub fn is_granted(actor: ResolvedActor, operation: Operation) bool {
        return operation.is_granted_by(actor.scope);
    }
};

pub fn address_actor_id(account: Address) B256 {
    return config.self_actor_id(account);
}

fn is_zero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

/// A raw 65-byte k1 signature (v = 27 or 28, low s) recovered to its signer.
pub fn recover_k1(hash: B256, signature: []const u8) Error!Address {
    if (signature.len != 65) return error.MalformedAuth;
    const hash_common = common_primitives.B256.init(hash);
    const signer = eip8130.recover_raw_k1(hash_common, signature, consensus.recover_address) orelse
        return error.InvalidSignature;
    return signer.bytes;
}

const Outcome = union(enum) {
    authenticated: B256,
    delegated: Address,
};

/// Stateless dispatch to the canonical authenticators.
fn dispatch(hash: B256, authenticator: Address, data: []const u8) Error!Outcome {
    if (std.mem.eql(u8, &authenticator, &k1_authenticator)) {
        return .{ .authenticated = address_actor_id(try recover_k1(hash, data)) };
    }
    if (std.mem.eql(u8, &authenticator, &p256_authenticator)) {
        return .{ .authenticated = try p256(hash, data) };
    }
    if (std.mem.eql(u8, &authenticator, &webauthn_authenticator)) {
        return .{ .authenticated = try webauthn(hash, data) };
    }
    if (std.mem.eql(u8, &authenticator, &delegate_authenticator)) {
        if (data.len < 40) return error.MalformedAuth;
        if (std.mem.eql(u8, data[20..40], &delegate_authenticator)) return error.NestedDelegate;
        return .{ .delegated = data[0..20].* };
    }
    return error.NotCanonical;
}

const p256_canonical_pre_hash: u8 = 0;
const p256_order: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

/// `r(32) || s(32) || x(32) || y(32) || 0x00`: actor id keccak256(x || y).
fn p256(hash: B256, data: []const u8) Error!B256 {
    if (data.len != 129 or data[128] != p256_canonical_pre_hash) return error.MalformedAuth;
    try p256_verify(hash, data[0..32].*, data[32..64].*, data[64..96].*, data[96..128].*);
    return crypto.keccak256(data[64..128]);
}

/// ECDSA P-256 over a prehash; high s is rejected (no malleable signatures).
fn p256_verify(prehash: B256, r: [32]u8, s: [32]u8, x: [32]u8, y: [32]u8) Error!void {
    if (std.mem.readInt(u256, &s, .big) > p256_order / 2) return error.InvalidSignature;
    if (!crypto.p256.verify(prehash, r, s, x, y)) return error.InvalidSignature;
}

const webauthn_type = "\"type\":\"webauthn.get\"";
const webauthn_challenge_prefix = "\"challenge\":\"";
const flag_user_present: u8 = 0x01;
const flag_backup_eligible: u8 = 0x08;
const flag_backup_state: u8 = 0x10;

const WebAuthn = struct {
    r: [32]u8,
    s: [32]u8,
    challenge_index: u256,
    type_index: u256,
    authenticator_data: []const u8,
    client_data_json: []const u8,
    x: [32]u8,
    y: [32]u8,
};

fn read_word(data: []const u8, offset: usize) u256 {
    return std.mem.readInt(u256, data[offset..][0..32], .big);
}

/// A length-prefixed tail at `offset`; null unless canonical (zero padding).
fn read_tail(data: []const u8, offset: usize) ?[]const u8 {
    if (data.len < offset + 32) return null;
    const length = read_word(data, offset);
    if (length > data.len) return null;
    const start = offset + 32;
    const padded = std.mem.alignForward(usize, @intCast(length), 32);
    if (data.len < start + padded) return null;
    if (!is_zero(data[start + @as(usize, @intCast(length)) .. start + padded])) return null;
    return data[start..][0..@intCast(length)];
}

/// abi.decode(data, (WebAuthnAuth, bytes32, bytes32)), accepting only the canonical
/// encoding (base re-encodes and compares, so the outer framing is not malleable).
fn decode_webauthn(data: []const u8) Error!WebAuthn {
    const tuple: usize = 3 * 32;
    if (data.len < tuple + 6 * 32) return error.MalformedAuth;
    if (read_word(data, 0) != tuple) return error.MalformedAuth;
    if (read_word(data, tuple + 128) != 6 * 32) return error.MalformedAuth;
    const authenticator_data = read_tail(data, tuple + 6 * 32) orelse return error.MalformedAuth;
    const json_offset = 7 * 32 + std.mem.alignForward(usize, authenticator_data.len, 32);
    if (read_word(data, tuple + 160) != json_offset) return error.MalformedAuth;
    const client_data_json = read_tail(data, tuple + json_offset) orelse
        return error.MalformedAuth;
    const end = tuple + json_offset + 32 + std.mem.alignForward(usize, client_data_json.len, 32);
    if (data.len != end) return error.MalformedAuth;
    if (!std.unicode.utf8ValidateSlice(client_data_json)) return error.MalformedAuth;
    return .{
        .r = data[tuple..][0..32].*,
        .s = data[tuple + 32 ..][0..32].*,
        .challenge_index = read_word(data, tuple + 64),
        .type_index = read_word(data, tuple + 96),
        .authenticator_data = authenticator_data,
        .client_data_json = client_data_json,
        .x = data[32..64].*,
        .y = data[64..96].*,
    };
}

/// `needle` must sit at `index` in `haystack`; an index past usize is malformed.
fn contains_at(haystack: []const u8, index: u256, needle: []const u8) Error!void {
    if (index > std.math.maxInt(u64) - needle.len) return error.MalformedAuth;
    const start: usize = @intCast(index);
    if (haystack.len < start + needle.len) return error.InvalidSignature;
    if (!std.mem.eql(u8, haystack[start..][0..needle.len], needle)) return error.InvalidSignature;
}

/// WebAuthn assertion over the signing hash as a base64url challenge.
fn webauthn(hash: B256, data: []const u8) Error!B256 {
    const auth = try decode_webauthn(data);
    if (auth.authenticator_data.len <= 36) return error.InvalidSignature;
    try contains_at(auth.client_data_json, auth.type_index, webauthn_type);
    const encoder = std.base64.url_safe_no_pad.Encoder;
    var expected: [webauthn_challenge_prefix.len + 44]u8 = undefined;
    expected[0..webauthn_challenge_prefix.len].* = webauthn_challenge_prefix.*;
    const encoded = encoder.encode(expected[webauthn_challenge_prefix.len..], &hash);
    assert(encoded.len == 43);
    expected[webauthn_challenge_prefix.len + encoded.len] = '"';
    const challenge = expected[0 .. webauthn_challenge_prefix.len + encoded.len + 1];
    try contains_at(auth.client_data_json, auth.challenge_index, challenge);
    const flags = auth.authenticator_data[32];
    if (flags & flag_user_present == 0) return error.InvalidSignature;
    if (flags & flag_backup_eligible == 0 and flags & flag_backup_state != 0) {
        return error.InvalidSignature;
    }
    var client_hash: [32]u8 = undefined;
    Sha256.hash(auth.client_data_json, &client_hash, .{});
    var hasher = Sha256.init(.{});
    hasher.update(auth.authenticator_data);
    hasher.update(&client_hash);
    const signed = hasher.finalResult();
    try p256_verify(signed, auth.r, auth.s, auth.x, auth.y);
    var key: [64]u8 = undefined;
    key[0..32].* = auth.x;
    key[32..64].* = auth.y;
    return crypto.keccak256(&key);
}

/// Inputs shared by the actor resolution paths.
pub const Lookup = struct {
    store: Store,
    account: Address,
    now: u64,
    /// The in-memory batch state for the inline self (else read from storage).
    account_state: ?AccountState = null,
    /// Payers skip the policy-manager read.
    resolve_policy: bool = true,
};

/// Authenticate `auth` over `hash` for `lookup.account` and resolve the bound actor.
pub fn authenticate(lookup: Lookup, hash: B256, auth: []const u8) Error!ResolvedActor {
    if (auth.len < 20) return error.MalformedAuth;
    const authenticator: Address = auth[0..20].*;
    const data = auth[20..];
    if (std.mem.eql(u8, &authenticator, &k1_authenticator)) {
        return resolve_k1(lookup, try recover_k1(hash, data));
    }
    switch (try dispatch(hash, authenticator, data)) {
        .authenticated => |actor_id| return resolve_bound(lookup, actor_id, authenticator),
        .delegated => |delegate_account| {
            // One hop: the nested auth cannot itself delegate (dispatch rejected it).
            const nested_lookup = Lookup{
                .store = lookup.store,
                .account = delegate_account,
                .now = lookup.now,
            };
            const nested = try authenticate_direct(nested_lookup, hash, data[20..]);
            if (nested.scope != 0) return error.NestedSignatureScope;
            const actor_id = address_actor_id(delegate_account);
            return resolve_bound(lookup, actor_id, delegate_authenticator);
        },
    }
}

/// `authenticate` without the delegate hop (the nested half of a delegation).
fn authenticate_direct(lookup: Lookup, hash: B256, auth: []const u8) Error!ResolvedActor {
    if (auth.len < 20) return error.MalformedAuth;
    const authenticator: Address = auth[0..20].*;
    const data = auth[20..];
    if (std.mem.eql(u8, &authenticator, &k1_authenticator)) {
        return resolve_k1(lookup, try recover_k1(hash, data));
    }
    if (std.mem.eql(u8, &authenticator, &delegate_authenticator)) return error.NestedDelegate;
    const outcome = try dispatch(hash, authenticator, data);
    assert(outcome == .authenticated);
    return resolve_bound(lookup, outcome.authenticated, authenticator);
}

/// A recovered k1 signer: the account's own key resolves the inline self config.
pub fn resolve_k1(lookup: Lookup, signer: Address) Error!ResolvedActor {
    const actor_id = address_actor_id(signer);
    if (!std.mem.eql(u8, &signer, &lookup.account)) {
        return resolve_bound(lookup, actor_id, k1_authenticator);
    }
    const current = lookup.account_state orelse try lookup.store.account_state(lookup.account);
    if (current.default_eoa_revoked()) return error.DefaultEoaRevoked;
    const expiry = current.default_eoa_expiry;
    if (expiry != 0 and lookup.now > expiry) return error.ActorExpired;
    const scope = current.default_eoa_scope;
    var target: Address = @splat(0);
    if (lookup.resolve_policy and eip8130.sender_is_policy_gated(scope)) {
        target = try lookup.store.policy_manager(lookup.account, actor_id);
    }
    return .{ .actor_id = actor_id, .scope = scope, .policy_target = target, .expiry = expiry };
}

/// An actor id must be configured with exactly this authenticator and be unexpired.
fn resolve_bound(lookup: Lookup, actor_id: B256, authenticator: Address) Error!ResolvedActor {
    if (is_zero(&actor_id)) return error.AuthenticationFailed;
    const stored = try lookup.store.actor_config_slot(lookup.account, actor_id);
    if (!std.mem.eql(u8, &stored.authenticator, &authenticator)) {
        return error.AuthenticatorMismatch;
    }
    if (stored.is_expired(lookup.now)) return error.ActorExpired;
    var target: Address = @splat(0);
    if (lookup.resolve_policy and eip8130.sender_is_policy_gated(stored.scope)) {
        target = try lookup.store.policy_manager(lookup.account, actor_id);
    }
    return .{
        .actor_id = actor_id,
        .scope = stored.scope,
        .policy_target = target,
        .expiry = stored.expiry,
    };
}

pub const AuthorizedActor = struct { account: Address, resolved: ResolvedActor };
pub const TxActors = struct { sender: AuthorizedActor, payer: ?AuthorizedActor };

/// Resolve and scope-gate the sender and payer of a signed 8130 transaction.
/// `recovered_sender` skips the EOA-path recovery when the caller already did it.
pub fn verify(
    signed: eip8130.Signed,
    store: Store,
    now: u64,
    recovered_sender: ?Address,
) Error!TxActors {
    const sender = try verify_sender(signed, store, now, recovered_sender);
    const payer_field = signed.tx.payer orelse {
        if (signed.payer_auth.len != 0) return error.UnexpectedPayerAuth;
        if (!sender.resolved.is_granted(.self_payer)) return error.ScopeDenied;
        return .{ .sender = sender, .payer = null };
    };
    const hash = signed.tx.payer_signature_hash(.init(sender.account)).bytes;
    var account: Address = payer_field.bytes;
    var resolved: ResolvedActor = undefined;
    const lookup_payer = Lookup{
        .store = store,
        .account = account,
        .now = now,
        .resolve_policy = false,
    };
    if (signed.tx.is_open_payer()) {
        account = recover_k1(hash, signed.payer_auth) catch return error.PayerRecovery;
        var lookup = lookup_payer;
        lookup.account = account;
        resolved = try resolve_k1(lookup, account);
    } else {
        resolved = try authenticate(lookup_payer, hash, signed.payer_auth);
    }
    const self_pay = std.mem.eql(u8, &account, &sender.account);
    const operation: Operation = if (self_pay) .self_payer else .sponsor_payer;
    if (!resolved.is_granted(operation)) return error.ScopeDenied;
    return .{ .sender = sender, .payer = .{ .account = account, .resolved = resolved } };
}

fn verify_sender(
    signed: eip8130.Signed,
    store: Store,
    now: u64,
    recovered_sender: ?Address,
) Error!AuthorizedActor {
    const hash = signed.tx.sender_signature_hash().bytes;
    var account: Address = undefined;
    var resolved: ResolvedActor = undefined;
    if (signed.tx.sender) |explicit| {
        account = explicit.bytes;
        const lookup = Lookup{ .store = store, .account = account, .now = now };
        resolved = try authenticate(lookup, hash, signed.sender_auth);
    } else {
        account = recovered_sender orelse
            (recover_k1(hash, signed.sender_auth) catch return error.SenderRecovery);
        const lookup = Lookup{ .store = store, .account = account, .now = now };
        resolved = try resolve_k1(lookup, account);
    }
    if (!resolved.is_granted(.sender)) return error.ScopeDenied;
    if (!resolved.can_use_nonce_key(signed.tx.nonce_key)) return error.ScopeDenied;
    return .{ .account = account, .resolved = resolved };
}

const testing = std.testing;
const memory_db = @import("memory_db.zig");
const state_module = @import("state.zig");
const signature_module = @import("../../common/consensus/signature.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Hardhat/anvil dev accounts 0 and 1 (publicly known keys).
const dev_key_0 = hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const dev_key_1 = hex32("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

fn hex32(comptime text: []const u8) [32]u8 {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    return bytes;
}

fn k1_address(private_key: [32]u8) !Address {
    const raw = try sign_k1(private_key, @splat(1));
    return recover_k1(@splat(1), &raw);
}

fn sign_k1(private_key: [32]u8, hash: B256) ![65]u8 {
    const signature = try signature_module.sign(private_key, .init(hash));
    var raw = signature.to_bytes();
    raw[64] += 27;
    return raw;
}

const Fixture = struct {
    database: memory_db.MemoryDatabase,
    state: state_module.State,

    fn init(fixture: *Fixture) !void {
        fixture.database = memory_db.MemoryDatabase.init(testing.allocator);
        const limits = @import("evm_test.zig").test_limits;
        fixture.state = try .init(testing.allocator, fixture.database.interface(), limits);
        fixture.state.begin_transaction();
    }

    fn deinit(fixture: *Fixture) void {
        fixture.state.deinit(testing.allocator);
        fixture.database.deinit();
    }

    fn store(fixture: *Fixture) Store {
        return .{ .state = &fixture.state };
    }
};

fn p256_sign(seed_byte: u8, hash: B256) !struct { r: [32]u8, s: [32]u8, x: [32]u8, y: [32]u8 } {
    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(seed_byte);
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
    const signature = try key_pair.signPrehashed(hash, null);
    var s = std.mem.readInt(u256, &signature.s, .big);
    if (s > p256_order / 2) s = p256_order - s;
    var s_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &s_bytes, s, .big);
    const sec1 = key_pair.public_key.toUncompressedSec1();
    return .{ .r = signature.r, .s = s_bytes, .x = sec1[1..33].*, .y = sec1[33..65].* };
}

test "eip8130 auth: operations follow the scope bits" {
    try testing.expect(Operation.config.is_granted_by(0));
    try testing.expect(!Operation.config.is_granted_by(eip8130.scope_operator));
    try testing.expect(Operation.sender.is_granted_by(eip8130.scope_policy));
    try testing.expect(!Operation.sender.is_granted_by(eip8130.scope_self_payer));
    try testing.expect(Operation.self_payer.is_granted_by(eip8130.scope_self_payer));
    try testing.expect(!Operation.sponsor_payer.is_granted_by(eip8130.scope_self_payer));
    const actor = ResolvedActor{
        .actor_id = @splat(1),
        .scope = eip8130.scope_operator,
        .policy_target = @splat(0),
        .expiry = 0,
    };
    try testing.expect(!actor.can_use_nonce_key(5));
    try testing.expect(actor.can_use_nonce_key(eip8130.nonce_key_max));
}

test "eip8130 auth: EOA senders self-pay through the inline k1 self" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const tx = eip8130.TxEip8130{ .chain_id = 8453, .gas_limit = 100_000 };
    const sender_auth = try eip8130.sign_sender(tx, dev_key_0);
    const signed = eip8130.Signed{ .tx = tx, .sender_auth = &sender_auth };
    const actors = try verify(signed, fixture.store(), 1, null);
    try testing.expectEqualSlices(u8, &(try k1_address(dev_key_0)), &actors.sender.account);
    try testing.expect(actors.payer == null);
    try testing.expect(actors.sender.resolved.is_admin());

    const stray = eip8130.Signed{ .tx = tx, .sender_auth = &sender_auth, .payer_auth = "x" };
    try testing.expectError(error.UnexpectedPayerAuth, verify(stray, fixture.store(), 1, null));
    var current = try fixture.store().account_state(actors.sender.account);
    current.flags = eip8130.flag_default_eoa_revoked;
    try fixture.store().set_account_state(actors.sender.account, current);
    try testing.expectError(error.DefaultEoaRevoked, verify(signed, fixture.store(), 1, null));
}

test "eip8130 auth: configured k1 and p256 actors bind to their authenticator" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const account: Address = @splat(0xaa);
    const hash: B256 = @splat(0x33);
    const signer = try k1_address(dev_key_1);
    const lookup = Lookup{ .store = fixture.store(), .account = account, .now = 10 };
    var auth: [20 + 129]u8 = undefined;
    auth[0..20].* = k1_authenticator;
    auth[20..85].* = try sign_k1(dev_key_1, hash);
    try testing.expectError(error.AuthenticatorMismatch, authenticate(lookup, hash, auth[0..85]));
    const scoped = config.ActorConfig{
        .authenticator = k1_authenticator,
        .expiry = 0,
        .scope = eip8130.scope_operator,
    };
    try fixture.store().set_actor_config(account, address_actor_id(signer), scoped);
    const resolved = try authenticate(lookup, hash, auth[0..85]);
    try testing.expectEqual(eip8130.scope_operator, resolved.scope);

    const signature = try p256_sign(7, hash);
    auth[0..20].* = p256_authenticator;
    auth[20..52].* = signature.r;
    auth[52..84].* = signature.s;
    auth[84..116].* = signature.x;
    auth[116..148].* = signature.y;
    auth[148] = 0;
    const p256_id = crypto.keccak256(auth[84..148]);
    try testing.expectError(error.AuthenticatorMismatch, authenticate(lookup, hash, &auth));
    const p256_config = config.ActorConfig{
        .authenticator = p256_authenticator,
        .expiry = 9,
        .scope = 0,
    };
    try fixture.store().set_actor_config(account, p256_id, p256_config);
    try testing.expectError(error.ActorExpired, authenticate(lookup, hash, &auth));
    var live = lookup;
    live.now = 9;
    _ = try authenticate(live, hash, &auth);
    auth[148] = 1;
    try testing.expectError(error.MalformedAuth, authenticate(live, hash, &auth));
    auth[148] = 0;
    auth[30] ^= 1;
    try testing.expectError(error.InvalidSignature, authenticate(live, hash, &auth));
}

test "eip8130 auth: a delegate hands authentication to an admin actor one hop deep" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const account: Address = @splat(0xbb);
    const delegate = try k1_address(dev_key_1);
    const hash: B256 = @splat(0x44);
    var auth: [20 + 20 + 20 + 65]u8 = undefined;
    auth[0..20].* = delegate_authenticator;
    auth[20..40].* = delegate;
    auth[40..60].* = k1_authenticator;
    auth[60..125].* = try sign_k1(dev_key_1, hash);
    const delegated = config.ActorConfig{
        .authenticator = delegate_authenticator,
        .expiry = 0,
        .scope = eip8130.scope_sponsor_payer,
    };
    try fixture.store().set_actor_config(account, address_actor_id(delegate), delegated);
    const lookup = Lookup{ .store = fixture.store(), .account = account, .now = 1 };
    const resolved = try authenticate(lookup, hash, &auth);
    try testing.expectEqual(eip8130.scope_sponsor_payer, resolved.scope);
    auth[40..60].* = delegate_authenticator;
    try testing.expectError(error.NestedDelegate, authenticate(lookup, hash, &auth));
    const unknown: [20]u8 = @splat(9);
    try testing.expectError(error.NotCanonical, authenticate(lookup, hash, &unknown));
}

/// Canonical abi.encode((r, s, challengeIndex, typeIndex, authenticatorData, json), x, y).
fn encode_webauthn(
    buffer: []u8,
    signature: anytype,
    authenticator_data: []const u8,
    json: []const u8,
    challenge_index: u256,
    type_index: u256,
) []const u8 {
    const padded_data = std.mem.alignForward(usize, authenticator_data.len, 32);
    const padded_json = std.mem.alignForward(usize, json.len, 32);
    const total = 3 * 32 + 6 * 32 + 32 + padded_data + 32 + padded_json;
    @memset(buffer[0..total], 0);
    std.mem.writeInt(u256, buffer[0..32], 96, .big);
    buffer[32..64].* = signature.x;
    buffer[64..96].* = signature.y;
    buffer[96..128].* = signature.r;
    buffer[128..160].* = signature.s;
    std.mem.writeInt(u256, buffer[160..192], challenge_index, .big);
    std.mem.writeInt(u256, buffer[192..224], type_index, .big);
    std.mem.writeInt(u256, buffer[224..256], 192, .big);
    std.mem.writeInt(u256, buffer[256..288], 224 + padded_data, .big);
    std.mem.writeInt(u256, buffer[288..320], authenticator_data.len, .big);
    @memcpy(buffer[320..][0..authenticator_data.len], authenticator_data);
    const json_at = 320 + padded_data;
    std.mem.writeInt(u256, buffer[json_at..][0..32], json.len, .big);
    @memcpy(buffer[json_at + 32 ..][0..json.len], json);
    return buffer[0..total];
}

test "eip8130 auth: webauthn assertions verify over the base64url challenge" {
    const hash: B256 = @splat(0x55);
    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &hash);
    var json_buffer: [128]u8 = undefined;
    const json = try std.fmt.bufPrint(
        &json_buffer,
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{s}\",\"origin\":\"o\"}}",
        .{challenge},
    );
    var authenticator_data: [37]u8 = @splat(0);
    authenticator_data[32] = flag_user_present;
    var client_hash: [32]u8 = undefined;
    Sha256.hash(json, &client_hash, .{});
    var hasher = Sha256.init(.{});
    hasher.update(&authenticator_data);
    hasher.update(&client_hash);
    const signature = try p256_sign(3, hasher.finalResult());
    var buffer: [512]u8 = undefined;
    const data = encode_webauthn(&buffer, signature, &authenticator_data, json, 23, 1);
    var key: [64]u8 = undefined;
    key[0..32].* = signature.x;
    key[32..64].* = signature.y;
    try testing.expectEqualSlices(u8, &crypto.keccak256(&key), &(try webauthn(hash, data)));
    const wrong_index = encode_webauthn(&buffer, signature, &authenticator_data, json, 22, 1);
    try testing.expectError(error.InvalidSignature, webauthn(hash, wrong_index));
    var padded: [513]u8 = undefined;
    const good = encode_webauthn(&buffer, signature, &authenticator_data, json, 23, 1);
    @memcpy(padded[0..good.len], good);
    padded[good.len] = 0;
    try testing.expectError(error.MalformedAuth, webauthn(hash, padded[0 .. good.len + 1]));
    const far = encode_webauthn(&buffer, signature, &authenticator_data, json, 1 << 70, 1);
    try testing.expectError(error.MalformedAuth, webauthn(hash, far));
}

test "eip8130 auth: seeded fuzz never accepts corrupted auth blobs" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var prng = std.Random.DefaultPrng.init(0x8130a);
    const random = prng.random();
    const lookup = Lookup{ .store = fixture.store(), .account = @splat(0xcc), .now = 1 };
    var auth: [256]u8 = undefined;
    for (0..512) |round| {
        const length = random.uintLessThan(usize, auth.len);
        random.bytes(auth[0..length]);
        if (length >= 20) {
            const authenticators = [4]Address{
                k1_authenticator,       p256_authenticator,
                webauthn_authenticator, delegate_authenticator,
            };
            auth[0..20].* = authenticators[round % 4];
        }
        const hash: B256 = @splat(@truncate(round));
        if (authenticate(lookup, hash, auth[0..length])) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

//! Tests for EIP-8130 encoding, hashing, signing and validation.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../primitives/root.zig");
const signature = @import("signature.zig");
const eip8130 = @import("eip8130.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Address = primitives.Address;
const B256 = primitives.B256;
const TxEip8130 = eip8130.TxEip8130;
const Signed = eip8130.Signed;

// Public `test test ... junk` devnet accounts #0 and #1.
const key_0 = [32]u8{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};
const key_1 = [32]u8{
    0x59, 0xc6, 0x99, 0x5e, 0x99, 0x8f, 0x97, 0xa5, 0xa0, 0x04, 0x49, 0x66, 0xf0, 0x94, 0x53, 0x89,
    0xdc, 0x9e, 0x86, 0xda, 0xe8, 0x8c, 0x7a, 0x84, 0x12, 0xf4, 0x60, 0x3b, 0x6b, 0x78, 0x69, 0x0d,
};
const address_0 = Address.comptime_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const address_1 = Address.comptime_hex("70997970C51812dc3A010C7d01b50e0d17dc79C8");

fn round_trip(signed: Signed) !void {
    var buffer: [4096]u8 = undefined;
    const encoded = signed.encode_to(&buffer);
    try testing.expectEqual(signed.encoded_length(), encoded.len);
    const decoded = try Signed.decode(encoded);
    var again: [4096]u8 = undefined;
    try testing.expectEqualSlices(u8, encoded, decoded.encode_to(&again));
    try testing.expect(decoded.hash().eql(primitives.keccak256(encoded)));
}

test "eip8130: minimal encoding layout" {
    const auth: [65]u8 = @splat(0x11);
    const signed: Signed = .{ .tx = .{ .chain_id = 1 }, .sender_auth = &auth };
    var buffer: [128]u8 = undefined;
    const encoded = signed.encode_to(&buffer);
    // 13 one-byte fields (two empty lists), b8 41 || auth, empty payer_auth: 81 bytes.
    const prefix = [_]u8{
        0x79, 0xf8, 0x51, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0xc0, 0xc0, 0x80, 0x80, 0xb8, 0x41,
    };
    try testing.expectEqual(@as(usize, 84), encoded.len);
    try testing.expectEqualSlices(u8, &prefix, encoded[0..prefix.len]);
    try testing.expectEqual(@as(u8, 0x80), encoded[83]);
    try round_trip(signed);
}

test "eip8130: EOA sender signs and recovers" {
    var phase_buffer: [256]u8 = undefined;
    var calls_buffer: [256]u8 = undefined;
    const call: eip8130.Call = .{ .to = address_1, .value = 5, .data = &.{ 0xde, 0xad } };
    const phase = eip8130.Phase.build(&phase_buffer, &.{call});
    var tx: TxEip8130 = .{
        .chain_id = 8453,
        .nonce_sequence = 7,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 2,
        .gas_limit = 100_000,
        .calls = eip8130.Calls.build(&calls_buffer, &.{ phase, phase }),
        .metadata = "memo",
    };
    const auth = try eip8130.sign_sender(tx, key_0);
    const signed: Signed = .{ .tx = tx, .sender_auth = &auth };
    try testing.expect(signed.recover_sender(signature.recover_address).?.eql(address_0));
    const payer = signed.resolved_payer(address_0, signature.recover_address).?;
    try testing.expect(payer.eql(address_0));
    try signed.validate_static(8453);
    try signed.validate_structure();
    try round_trip(signed);
    var phases = signed.tx.calls.iterator();
    var phase_count: u32 = 0;
    while (phases.next()) |item| : (phase_count += 1) {
        var calls = item.iterator();
        try testing.expect(calls.next().?.to.eql(address_1));
        try testing.expect(calls.next() == null);
    }
    try testing.expectEqual(@as(u32, 2), phase_count);
    // Any change to signed fields breaks recovery.
    tx.nonce_sequence = 8;
    const tampered: Signed = .{ .tx = tx, .sender_auth = &auth };
    const wrong = tampered.recover_sender(signature.recover_address);
    try testing.expect(wrong == null or !wrong.?.eql(address_0));
    try testing.expectError(error.ChainIdMismatch, signed.validate_static(1));
}

test "eip8130: open payer" {
    const tx: TxEip8130 = .{
        .chain_id = 8453,
        .max_fee_per_gas = 1,
        .gas_limit = 1,
        .payer = eip8130.open_payer,
    };
    try testing.expect(tx.is_open_payer());
    const sender_auth = try eip8130.sign_sender(tx, key_0);
    const payer_auth = try eip8130.sign_payer(tx, address_0, key_1);
    const signed: Signed = .{ .tx = tx, .sender_auth = &sender_auth, .payer_auth = &payer_auth };
    const sender = signed.recover_sender(signature.recover_address).?;
    try testing.expect(sender.eql(address_0));
    try testing.expect(signed.resolved_payer(sender, signature.recover_address).?.eql(address_1));
    try testing.expect(!tx.payer_signature_hash(sender).eql(tx.sender_signature_hash()));
    try testing.expectEqual(
        signed.encoded_length() - 65 - 1,
        signed.encoded_length_without_payer_auth(),
    );
    try signed.validate_structure();
    try round_trip(signed);
    // Payer auth is required exactly when a payer is set.
    const missing: Signed = .{ .tx = tx, .sender_auth = &sender_auth };
    try testing.expectError(error.MalformedPayerAuth, missing.validate_structure());
}

test "eip8130: payer and sender field encodings" {
    var buffer: [256]u8 = undefined;
    const auth: [65]u8 = @splat(1);
    var signed: Signed = .{ .tx = .{ .chain_id = 1, .payer = address_1 }, .sender_auth = &auth };
    try round_trip(signed);
    signed.tx.payer = eip8130.open_payer;
    const encoded = signed.encode_to(&buffer);
    // The payer field is the single byte 0x00, right after metadata (0x80).
    try testing.expectEqualSlices(u8, &.{ 0xc0, 0xc0, 0x80, 0x00, 0xb8 }, encoded[12..17]);
    // A 20-byte zero payer is non-canonical.
    var long: [256]u8 = undefined;
    var encoder = @import("../rlp/root.zig").Encoder.init(&long);
    encoder.raw(&.{eip8130.tx_type});
    const fields = [_]u8{ 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0, 0xc0, 0x80 };
    encoder.list_header(fields.len + 21 + 1 + 1);
    encoder.raw(&fields);
    encoder.bytes(&Address.zero.bytes);
    encoder.bytes(&.{});
    encoder.bytes(&.{});
    try testing.expectError(error.Overflow, Signed.decode(encoder.written()));
}

const ChangeFixture = struct {
    actors_buffer: [512]u8 = undefined,
    changes_buffer: [512]u8 = undefined,
    list_buffer: [2048]u8 = undefined,

    fn build(fixture: *ChangeFixture, items: []const eip8130.AccountChange) eip8130.AccountChanges {
        return eip8130.AccountChanges.build(&fixture.list_buffer, items);
    }

    fn create(fixture: *ChangeFixture) eip8130.AccountChange {
        var id: B256 = .zero;
        id.bytes[31] = 1;
        const actor: eip8130.InitialActor = .{
            .actor_id = id,
            .authenticator = eip8130.k1_authenticator,
            .scope = eip8130.scope_operator,
            .policy_data = &.{},
        };
        return .{ .create = .{
            .user_salt = .zero,
            .code = &.{ 0x60, 0x00 },
            .initial_actors = eip8130.InitialActors.build(&fixture.actors_buffer, &.{actor}),
        } };
    }

    fn config(fixture: *ChangeFixture, change_type: eip8130.ChangeType) eip8130.AccountChange {
        const payload: [32]u8 = @splat(1);
        const change: eip8130.SignedChange = .{ .change_type = change_type, .payload = &payload };
        const signature_blob = eip8130.k1_authenticator.bytes ++ @as([65]u8, @splat(2));
        return .{ .config = .{
            .channel = .multichain,
            .sequence = 3,
            .changes = eip8130.SignedChanges.build(&fixture.changes_buffer, &.{change}),
            .signature = &signature_blob,
        } };
    }
};

test "eip8130: account changes and structure" {
    const auth: [65]u8 = @splat(1);
    var fixture: ChangeFixture = .{};
    const delegation: eip8130.AccountChange = .{ .delegation = address_1 };
    var signed: Signed = .{ .tx = .{ .chain_id = 1 }, .sender_auth = &auth };
    const create = fixture.create();
    const revoke = fixture.config(.revoke_actor);
    signed.tx.account_changes = fixture.build(&.{ create, revoke });
    try signed.validate_structure();
    try round_trip(signed);
    var iterator = signed.tx.account_changes.iterator();
    try testing.expect(iterator.next().? == .create);
    const config = iterator.next().?.config;
    try testing.expectEqual(eip8130.Channel.multichain, config.channel);
    try testing.expectEqual(@as(u64, 3), config.sequence);
    signed.tx.account_changes = fixture.build(&.{ revoke, create });
    try testing.expectError(error.MalformedAccountChange, signed.validate_structure());
    signed.tx.account_changes = fixture.build(&.{ fixture.create(), delegation });
    try testing.expectError(error.MalformedAccountChange, signed.validate_structure());
    signed.tx.account_changes = fixture.build(&.{fixture.config(.lock)});
    try testing.expectError(error.MalformedAccountChange, signed.validate_structure());
    signed.tx.account_changes = fixture.build(&.{ delegation, delegation });
    try testing.expectError(error.MalformedAccountChange, signed.validate_structure());
    const four: [4]eip8130.AccountChange = @splat(delegation);
    signed.tx.account_changes = fixture.build(&four);
    try testing.expectError(error.TooManyAccountChanges, signed.validate_structure());
    signed.tx.account_changes = fixture.build(&.{delegation});
    try signed.validate_structure();
    try round_trip(signed);
}

test "eip8130: validity window" {
    try testing.expectEqual(@as(u64, 0), eip8130.normalize_timestamp_ms(0));
    const ms: u64 = 1_700_000_000_000;
    try testing.expectEqual(ms, eip8130.normalize_timestamp_ms(1_700_000_000));
    try testing.expectEqual(ms, eip8130.normalize_timestamp_ms(ms));
    const now: u64 = 1_700_000_000_000;
    var signed: Signed = .{
        .tx = .{ .chain_id = 1, .valid_after = 1_700_000_001 },
        .sender_auth = &.{},
    };
    try testing.expectError(error.NotYetValid, signed.validate_timestamp(now));
    signed.tx = .{ .chain_id = 1, .valid_before = 1_699_999_999 };
    try testing.expectError(error.Expired, signed.validate_timestamp(now));
    signed.tx = .{ .chain_id = 1, .nonce_key = eip8130.nonce_key_max };
    try testing.expectError(error.NonceFreeMalformed, signed.validate_timestamp(now));
    signed.tx.valid_before = now + 10_000;
    try signed.validate_timestamp(now);
    signed.tx.valid_before = now + 30_000;
    try testing.expectError(error.NonceFreeExpiryTooFar, signed.validate_timestamp(now));
    signed.tx.valid_before = now;
    try testing.expectError(error.NonceFreeExpired, signed.validate_timestamp(now));
}

test "eip8130: replay id binds sender, not nonce or fees" {
    var tx: TxEip8130 = .{
        .chain_id = 8453,
        .nonce_key = eip8130.nonce_key_max,
        .valid_before = 9,
    };
    const base = tx.replay_id(address_0);
    try testing.expect(!base.eql(tx.replay_id(address_1)));
    tx.max_fee_per_gas = 100;
    tx.gas_limit = 5;
    try testing.expect(base.eql(tx.replay_id(address_0)));
    tx.metadata = "x";
    try testing.expect(!base.eql(tx.replay_id(address_0)));
}

fn decode_any(input: []const u8) !void {
    const signed = Signed.decode(input) catch return;
    signed.validate_structure() catch {};
    signed.validate_timestamp(1_700_000_000_000) catch {};
    var buffer: [4096]u8 = undefined;
    if (signed.encoded_length() > buffer.len) return;
    try testing.expectEqualSlices(u8, input, signed.encode_to(&buffer));
}

test "eip8130: seeded fuzz mutations" {
    var fixture: ChangeFixture = .{};
    const auth: [65]u8 = @splat(1);
    var signed: Signed = .{ .tx = .{ .chain_id = 1, .payer = address_1 }, .sender_auth = &auth };
    signed.payer_auth = &auth;
    const changes = [_]eip8130.AccountChange{ fixture.create(), fixture.config(.revoke_actor) };
    signed.tx.account_changes = fixture.build(&changes);
    var buffer: [4096]u8 = undefined;
    const encoded = signed.encode_to(&buffer);
    var mutated: [4096]u8 = undefined;
    var prng = Prng.init(0x8130);
    for (0..512) |_| {
        @memcpy(mutated[0..encoded.len], encoded);
        for (0..prng.range(1, 4)) |_| mutated[prng.below(encoded.len)] = prng.int(u8);
        try decode_any(mutated[0..prng.range(1, encoded.len)]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    try decode_any(input[0..smith.slice(&input)]);
}

test "eip8130: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

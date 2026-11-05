//! Tests for EIP-8130 intrinsic gas, ported from base/base `intrinsic.rs`.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const eip8130 = @import("eip8130.zig");
const gas_module = @import("eip8130_gas.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Address = primitives.Address;
const B256 = primitives.B256;
const schedule = gas_module.schedule;
const TxEip8130 = eip8130.TxEip8130;
const Signed = eip8130.Signed;

const account = Address.comptime_hex("1111111111111111111111111111111111111111");
const existing_key: gas_module.Input = .{ .sender = account, .nonce_key_first_use = false };
const k1_auth = schedule.auth_exec_k1 + schedule.cold_sload;
const bare_signature = @as([65]u8, @splat(0xcd));

fn base_tx() TxEip8130 {
    return .{ .chain_id = 8453 };
}

/// `authenticator(20) || 0xab * 65`.
fn configured_auth(authenticator: Address) [85]u8 {
    return authenticator.bytes ++ @as([65]u8, @splat(0xab));
}

fn intrinsic(signed: Signed, input: gas_module.Input) !gas_module.IntrinsicGas {
    var buffer: [32 * 1024]u8 = undefined;
    return gas_module.compute(signed, signed.encode_to(&buffer), input);
}

fn with_changes(buffer: []u8, changes: []const eip8130.AccountChange) TxEip8130 {
    var tx = base_tx();
    tx.sender = account;
    tx.account_changes = eip8130.AccountChanges.build(buffer, changes);
    return tx;
}

fn config_change(
    buffer: []u8,
    ops: []const eip8130.SignedChange,
    signature: []const u8,
) eip8130.AccountChange {
    return .{ .config = .{
        .channel = .multichain,
        .sequence = 0,
        .changes = eip8130.SignedChanges.build(buffer, ops),
        .signature = signature,
    } };
}

/// abi.encode(actorId, (authenticator, expiry, scope), policyData) params.
fn authorize_payload(buffer: []u8, policy_length: usize) []const u8 {
    const length = 6 * 32 + std.mem.alignForward(usize, policy_length, 32);
    @memset(buffer[0..length], 0);
    buffer[159] = 0xa0; // policyData offset (word 4).
    std.mem.writeInt(u256, buffer[160..192], policy_length, .big);
    return buffer[0..length];
}

test "eip8130 gas: authorize_attaches_policy reads the policy length" {
    var buffer: [512]u8 = undefined;
    try testing.expect(gas_module.authorize_attaches_policy(authorize_payload(&buffer, 52)));
    try testing.expect(!gas_module.authorize_attaches_policy(authorize_payload(&buffer, 0)));
    try testing.expect(!gas_module.authorize_attaches_policy(authorize_payload(&buffer, 51)));
    try testing.expect(!gas_module.authorize_attaches_policy(&(@as([128]u8, @splat(0)))));
    // An out-of-range offset is metered as no policy.
    const payload = authorize_payload(&buffer, 52);
    buffer[159] = 0xff;
    try testing.expect(!gas_module.authorize_attaches_policy(payload));
    @memset(buffer[128..160], 0xff);
    try testing.expect(!gas_module.authorize_attaches_policy(payload));
}

test "eip8130 gas: EOA self-pay minimal and EIP-7623 floor" {
    const gas = try intrinsic(.{ .tx = base_tx(), .sender_auth = &bare_signature }, existing_key);
    try testing.expectEqual(schedule.aa_base_cost, gas.base);
    try testing.expectEqual(@as(u64, 0), gas.nonce_key + gas.bytecode + gas.account_changes);
    try testing.expectEqual(k1_auth, gas.sender_auth);
    try testing.expectEqual(@as(u64, 0), gas.payer_floor + gas.payer_auth_cost);
    // The type byte is non-zero, so the payload has 4-token bytes: the floor premium is
    // exactly (10 - 4) per token.
    const tokens = gas.payload / schedule.tx_data_zero_byte;
    try testing.expectEqual(@as(u64, 0), gas.payload % schedule.tx_data_zero_byte);
    try testing.expectEqual(schedule.tx_total_cost_floor_per_token * tokens, gas.payload_floor);
    try testing.expectEqual((10 - 4) * tokens, gas.sender_floor() - gas.sender_intrinsic());
    const intrinsic_gas = gas.sender_intrinsic();
    try testing.expectEqual(@as(?u64, null), gas.execution_gas_available(intrinsic_gas - 1));
    try testing.expectEqual(@as(?u64, 5), gas.execution_gas_available(gas.sender_intrinsic() + 5));
}

test "eip8130 gas: nonce key costs" {
    var tx = base_tx();
    for ([_]bool{ true, false }) |first_use| {
        const input: gas_module.Input = .{ .sender = account, .nonce_key_first_use = first_use };
        const gas = try intrinsic(.{ .tx = tx, .sender_auth = &bare_signature }, input);
        try testing.expectEqual(@as(u64, 0), gas.nonce_key);
    }
    tx.nonce_key = eip8130.nonce_key_max;
    const free = try intrinsic(.{ .tx = tx, .sender_auth = &bare_signature }, existing_key);
    try testing.expectEqual(schedule.nonce_free_cost, free.nonce_key);
    tx.nonce_key = 7;
    const first = try intrinsic(
        .{ .tx = tx, .sender_auth = &bare_signature },
        .{ .sender = account, .nonce_key_first_use = true },
    );
    try testing.expectEqual(schedule.nonce_key_first_use_cost, first.nonce_key);
    const existing = try intrinsic(.{ .tx = tx, .sender_auth = &bare_signature }, existing_key);
    try testing.expectEqual(schedule.nonce_key_existing_cost, existing.nonce_key);
}

test "eip8130 gas: payer auth floor and standard rates" {
    var tx = base_tx();
    tx.payer = Address{ .bytes = @splat(0x22) };
    const payer_auth = configured_auth(eip8130.k1_authenticator);
    var zeros: u64 = 0;
    for (payer_auth) |byte| zeros += @intFromBool(byte == 0);
    const non_zeros = payer_auth.len - zeros;
    const signed: Signed = .{ .tx = tx, .sender_auth = &bare_signature, .payer_auth = &payer_auth };
    const gas = try intrinsic(signed, existing_key);
    try testing.expectEqual(k1_auth + 10 * (zeros + 4 * non_zeros), gas.payer_floor);
    try testing.expectEqual(k1_auth + 4 * zeros + 16 * non_zeros, gas.payer_auth_cost);
    try testing.expectEqual(gas.payer_floor, try gas_module.max_payer_auth_cost(signed));
    const self_pay: Signed = .{ .tx = base_tx(), .sender_auth = &bare_signature };
    try testing.expectEqual(@as(u64, 0), try gas_module.max_payer_auth_cost(self_pay));
    // The sender is billed as if payer_auth were empty.
    const unsponsored: Signed = .{ .tx = tx, .sender_auth = &bare_signature };
    try testing.expectEqual((try intrinsic(unsponsored, existing_key)).payload, gas.payload);
    // Payer auth gas above MAX_AUTHENTICATION_GAS is rejected.
    var large: [4096]u8 = @splat(0xab);
    large[0..20].* = eip8130.k1_authenticator.bytes;
    const too_large: Signed = .{ .tx = tx, .sender_auth = &bare_signature, .payer_auth = &large };
    try testing.expectError(error.PayerAuthGasExceeded, intrinsic(too_large, existing_key));
}

test "eip8130 gas: worst case pins the policy gate only with the keystore" {
    try testing.expect(!gas_module.Input.worst_case(account, false, false).sender_policy_gated);
    try testing.expect(gas_module.Input.worst_case(account, false, true).sender_policy_gated);
    const gated = try intrinsic(
        .{ .tx = base_tx(), .sender_auth = &bare_signature },
        gas_module.Input.worst_case(account, false, true),
    );
    try testing.expectEqual(k1_auth + schedule.cold_sload, gated.sender_auth);
}

test "eip8130 gas: create entries charge bytecode and actor slots" {
    var actors_buffer: [512]u8 = undefined;
    const owner = eip8130.InitialActor{
        .actor_id = B256{ .bytes = @splat(1) },
        .authenticator = eip8130.k1_authenticator,
        .scope = 0,
        .policy_data = &.{},
    };
    var policy = owner;
    policy.policy_data = &(@as([52]u8, @splat(0x44)));
    const actors = eip8130.InitialActors.build(&actors_buffer, &.{ owner, policy });
    const create: eip8130.AccountChange = .{ .create = .{
        .user_salt = .zero,
        .code = &(@as([4]u8, @splat(0x60))),
        .initial_actors = actors,
    } };
    var buffer: [1024]u8 = undefined;
    const tx = with_changes(&buffer, &.{create});
    const auth = configured_auth(eip8130.k1_authenticator);
    const gas = try intrinsic(.{ .tx = tx, .sender_auth = &auth }, existing_key);
    try testing.expectEqual(schedule.create_base_cost + 200 * 4, gas.bytecode);
    try testing.expectEqual(
        schedule.account_state_set_cost + schedule.actor_slot_set_cost * 4 +
            schedule.policy_slots_noop_cost,
        gas.account_changes,
    );
    try testing.expectEqual(k1_auth, gas.sender_auth);
}

test "eip8130 gas: delegation and config changes" {
    var buffer: [2048]u8 = undefined;
    var ops_buffer: [1024]u8 = undefined;
    var payload_buffer: [512]u8 = undefined;
    const auth = configured_auth(eip8130.k1_authenticator);
    const delegation = with_changes(&buffer, &.{.{ .delegation = account }});
    const delegated = try intrinsic(.{ .tx = delegation, .sender_auth = &auth }, existing_key);
    try testing.expectEqual(schedule.delegation_deposit_cost, delegated.account_changes);

    const ops = [_]eip8130.SignedChange{
        .{ .change_type = .authorize_actor, .payload = &(@as([128]u8, @splat(0))) },
        .{ .change_type = .revoke_actor, .payload = &.{} },
        .{ .change_type = .increment_local_epoch, .payload = &.{} },
        .{ .change_type = .authorize_actor, .payload = authorize_payload(&payload_buffer, 52) },
    };
    const change = config_change(&ops_buffer, &ops, &auth);
    const one = with_changes(&buffer, &.{change});
    const one_gas = try intrinsic(.{ .tx = one, .sender_auth = &auth }, existing_key);
    const per_change = k1_auth + schedule.actor_slot_set_cost + schedule.policy_slots_noop_cost +
        schedule.actor_revoke_cost + schedule.increment_local_epoch_cost +
        schedule.actor_slot_set_cost * 3;
    const one_expected = schedule.config_change_state_cost + per_change;
    try testing.expectEqual(one_expected, one_gas.account_changes);

    const two = with_changes(&buffer, &.{ change, change });
    const two_gas = try intrinsic(.{ .tx = two, .sender_auth = &auth }, existing_key);
    try testing.expectEqual(
        per_change + schedule.config_change_state_cost_subsequent,
        two_gas.account_changes - one_gas.account_changes,
    );
    // Revoke discount: bounded by three slots per charged revoke.
    var discounted_input = existing_key;
    discounted_input.revoke_discount_slots = 3;
    const discounted = try intrinsic(.{ .tx = one, .sender_auth = &auth }, discounted_input);
    try testing.expectEqual(
        one_gas.account_changes - 3 * schedule.cold_slot_reset_discount,
        discounted.account_changes,
    );
    discounted_input.revoke_discount_slots = 100;
    const capped = try intrinsic(.{ .tx = one, .sender_auth = &auth }, discounted_input);
    try testing.expectEqual(discounted.account_changes, capped.account_changes);
}

test "eip8130 gas: authenticator resolution" {
    var tx = base_tx();
    tx.sender = account;
    const contracts = eip8130.contracts;
    const p256 = configured_auth(contracts.p256_authenticator);
    const p256_gas = try intrinsic(.{ .tx = tx, .sender_auth = &p256 }, existing_key);
    try testing.expectEqual(schedule.auth_exec_p256 + schedule.cold_sload, p256_gas.sender_auth);
    // Delegate: overhead + nested leaf + one outer SLOAD.
    const delegate = contracts.delegate_authenticator.bytes ++ account.bytes ++
        contracts.webauthn_authenticator.bytes ++ @as([8]u8, @splat(0xab));
    const delegate_gas = try intrinsic(.{ .tx = tx, .sender_auth = &delegate }, existing_key);
    try testing.expectEqual(
        schedule.auth_exec_delegate_overhead + schedule.auth_exec_webauthn + schedule.cold_sload,
        delegate_gas.sender_auth,
    );
    // A nested delegate is not a priced leaf; nor is address(0) or an unknown contract.
    const nested = contracts.delegate_authenticator.bytes ++ account.bytes ++
        contracts.delegate_authenticator.bytes;
    try testing.expectError(
        error.UnscheduledAuthenticator,
        intrinsic(.{ .tx = tx, .sender_auth = &nested }, existing_key),
    );
    const zero = configured_auth(.zero);
    try testing.expectError(
        error.UnscheduledAuthenticator,
        intrinsic(.{ .tx = tx, .sender_auth = &zero }, existing_key),
    );
    // A degenerate sub-20-byte prefixed blob costs nothing.
    const short_gas = try intrinsic(.{ .tx = tx, .sender_auth = &.{ 1, 2, 3 } }, existing_key);
    try testing.expectEqual(@as(u64, 0), short_gas.sender_auth);
}

test "eip8130 gas: value transfers skip zero value and self calls" {
    var phase_buffer: [256]u8 = undefined;
    var calls_buffer: [512]u8 = undefined;
    const other = Address{ .bytes = @splat(0x22) };
    const phase = eip8130.Phase.build(&phase_buffer, &.{
        .{ .to = other, .value = 1, .data = &.{} },
        .{ .to = account, .value = 1, .data = &.{} },
        .{ .to = other, .value = 0, .data = &.{} },
    });
    var tx = base_tx();
    tx.calls = eip8130.Calls.build(&calls_buffer, &.{ phase, phase });
    const gas = try intrinsic(.{ .tx = tx, .sender_auth = &bare_signature }, existing_key);
    try testing.expectEqual(2 * schedule.tx_value_cost, gas.value_transfer);
}

/// Reference: price the re-encoded sender-billed bytes directly.
fn reference_payload(signed: Signed) [2]u64 {
    var buffer: [32 * 1024]u8 = undefined;
    var encoder = rlp.Encoder.init(&buffer);
    signed.encode_without_payer_auth(&encoder);
    var costs = [2]u64{ 0, 0 };
    for (encoder.written()) |byte| {
        costs[0] += if (byte == 0) 4 else 16;
        costs[1] += if (byte == 0) 10 else 40;
    }
    return costs;
}

test "eip8130 gas: seeded fuzz sender-billed payload matches re-encoding" {
    var prng = Prng.init(0x8130_6a5);
    var metadata: [20_000]u8 = undefined;
    var payer_auth: [600]u8 = undefined;
    for (0..256) |_| {
        // Sizes straddle the 55-byte and 256-byte RLP header boundaries.
        const metadata_length = prng.below(metadata.len);
        const payer_length = prng.below(payer_auth.len);
        prng.fill(metadata[0..metadata_length]);
        prng.fill(payer_auth[0..payer_length]);
        if (prng.chance(1, 2)) @memset(metadata[0..metadata_length], 0);
        var tx = base_tx();
        tx.metadata = metadata[0..metadata_length];
        tx.payer = Address{ .bytes = @splat(0x22) };
        const prefix_length = @min(20, payer_length);
        @memcpy(payer_auth[0..prefix_length], eip8130.k1_authenticator.bytes[0..prefix_length]);
        const signed: Signed = .{
            .tx = tx,
            .sender_auth = &bare_signature,
            .payer_auth = payer_auth[0..payer_length],
        };
        const gas = intrinsic(signed, existing_key) catch |err| {
            try testing.expect(err == error.PayerAuthGasExceeded or payer_length < 20);
            continue;
        };
        const reference = reference_payload(signed);
        try testing.expectEqual(reference[0], gas.payload);
        try testing.expectEqual(reference[1], gas.payload_floor);
    }
}

fn fuzz_compute(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [4096]u8 = undefined;
    buffer[0] = eip8130.tx_type;
    const length = 1 + smith.slice(buffer[1..]);
    const signed = Signed.decode(buffer[0..length]) catch return;
    const input: gas_module.Input = .{
        .sender = account,
        .nonce_key_first_use = smith.value(bool),
        .sender_policy_gated = smith.value(bool),
        .revoke_discount_slots = smith.value(u32),
    };
    const gas = gas_module.compute(signed, buffer[0..length], input) catch return;
    try testing.expect(gas.sender_floor() >= gas.sender_intrinsic());
    try testing.expect(gas.payer_floor >= gas.payer_auth_cost or gas.payer_floor == 0);
    const reference = reference_payload(signed);
    try testing.expectEqual(reference[0], gas.payload);
    _ = gas_module.authorize_attaches_policy(buffer[0..length]);
}

test "eip8130 gas: fuzz compute" {
    try testing.fuzz({}, fuzz_compute, .{});
}

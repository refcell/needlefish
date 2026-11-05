//! EIP-8130 intrinsic gas (base/base `base-common-eip8130`): the gas schedule and the
//! per-component cost of including a 0x79 transaction. Pure function of the signed
//! transaction, its EIP-2718 encoding, and state hints supplied by the caller.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const eip8130 = @import("eip8130.zig");
const Address = primitives.Address;

/// Base's gas schedule (EIP-2929 storage, EIP-2028 data, EIP-7623 floor, EIP-8130 table).
pub const schedule = struct {
    pub const cold_sload: u64 = 2_100;
    pub const warm_sload: u64 = 100;
    pub const sstore_set: u64 = 20_000;
    pub const sstore_reset: u64 = 2_900;
    /// SSTORE to a slot already modified in this transaction (EIP-2200 dirty).
    pub const sstore_dirty: u64 = warm_sload;
    pub const tx_data_zero_byte: u64 = 4;
    pub const tx_data_nonzero_byte: u64 = 16;
    pub const tx_total_cost_floor_per_token: u64 = 10;
    pub const aa_base_cost: u64 = eip8130.base_cost;
    pub const nonce_free_cost: u64 = 2 * cold_sload + warm_sload + 3 * sstore_reset;
    pub const protocol_nonce_cost: u64 = 0;
    pub const nonce_key_first_use_cost: u64 = cold_sload + sstore_set;
    pub const nonce_key_existing_cost: u64 = cold_sload + sstore_reset;
    pub const create_base_cost: u64 = 32_000;
    pub const code_deposit_per_byte: u64 = 200;
    pub const delegation_deposit_cost: u64 =
        code_deposit_per_byte * eip8130.delegation_indicator_size;
    pub const tx_value_cost: u64 = 6_000;
    pub const new_account_cost: u64 = 25_000;
    pub const max_authentication_gas: u64 = 100_000;
    pub const actor_slot_set_cost: u64 = cold_sload + sstore_set;
    pub const actor_slot_reset_cost: u64 = cold_sload + sstore_reset;
    pub const cold_slot_noop_cost: u64 = cold_sload + warm_sload;
    pub const policy_slots_noop_cost: u64 = cold_slot_noop_cost * 2;
    pub const account_state_set_cost: u64 = cold_sload + sstore_set;
    pub const config_change_state_cost: u64 = account_state_set_cost;
    pub const config_change_state_cost_subsequent: u64 = warm_sload + sstore_dirty;
    pub const increment_local_epoch_cost: u64 = sstore_dirty;
    pub const actor_revoke_cost: u64 = actor_slot_reset_cost * 3;
    pub const cold_slot_reset_discount: u64 = actor_slot_reset_cost - cold_slot_noop_cost;
    pub const auth_exec_k1: u64 = 3_000;
    pub const auth_exec_p256: u64 = 6_900;
    pub const auth_exec_webauthn: u64 = 6_900;
    pub const auth_exec_delegate_overhead: u64 = cold_sload;

    comptime {
        assert(nonce_free_cost == 13_000);
        assert(nonce_key_first_use_cost == 22_100);
        assert(nonce_key_existing_cost == 5_000);
        assert(delegation_deposit_cost == 4_600);
    }

    /// Execution gas of a leaf (non-delegate) enshrined authenticator.
    pub fn leaf_auth_exec_gas(authenticator: Address) ?u64 {
        const contracts = eip8130.contracts;
        if (authenticator.eql(eip8130.k1_authenticator)) return auth_exec_k1;
        if (authenticator.eql(contracts.p256_authenticator)) return auth_exec_p256;
        if (authenticator.eql(contracts.webauthn_authenticator)) return auth_exec_webauthn;
        return null;
    }
};

pub const Error = error{ UnscheduledAuthenticator, PayerAuthGasExceeded };

/// How an auth blob is parsed: a bare 65-byte k1 signature (empty `sender`, open payer)
/// or `authenticator(20) || data`.
pub const AuthWireForm = enum { bare_signature, prefixed };

/// State-derived hints the body cannot determine.
pub const Input = struct {
    sender: Address,
    nonce_key_first_use: bool,
    sender_policy_gated: bool = false,
    /// Revoke slots execution resolved as empty zero-to-zero touches.
    revoke_discount_slots: u32 = 0,

    /// The ceiling shared by estimation and mempool admission: policy gate charged
    /// while the keystore is active, no revoke discount.
    pub fn worst_case(sender: Address, nonce_key_first_use: bool, keystore: bool) Input {
        return .{
            .sender = sender,
            .nonce_key_first_use = nonce_key_first_use,
            .sender_policy_gated = keystore,
        };
    }
};

pub const IntrinsicGas = struct {
    base: u64 = 0,
    payload: u64 = 0,
    payload_floor: u64 = 0,
    nonce_key: u64 = 0,
    value_transfer: u64 = 0,
    bytecode: u64 = 0,
    account_changes: u64 = 0,
    sender_auth: u64 = 0,
    payer_floor: u64 = 0,
    payer_auth_cost: u64 = 0,

    /// Every component except payer authentication (metered outside `gas_limit`).
    pub fn sender_intrinsic(gas: IntrinsicGas) u64 {
        var total = gas.base;
        for ([_]u64{
            gas.payload,  gas.nonce_key,       gas.value_transfer,
            gas.bytecode, gas.account_changes, gas.sender_auth,
        }) |part| total +|= part;
        return total;
    }

    pub fn execution_gas_available(gas: IntrinsicGas, gas_limit: u64) ?u64 {
        return std.math.sub(u64, gas_limit, gas.sender_intrinsic()) catch null;
    }

    /// EIP-7623 sender floor: the payload swapped for its floor price.
    pub fn sender_floor(gas: IntrinsicGas) u64 {
        assert(gas.payload_floor >= gas.payload);
        return (gas.sender_intrinsic() -| gas.payload) +| gas.payload_floor;
    }
};

/// Intrinsic gas of `signed`, whose EIP-2718 encoding is `encoded`.
pub fn compute(signed: eip8130.Signed, encoded: []const u8, input: Input) Error!IntrinsicGas {
    assert(encoded.len == signed.encoded_length());
    assert(encoded[0] == eip8130.tx_type);
    const tx = signed.tx;
    var gas: IntrinsicGas = .{ .base = schedule.aa_base_cost };
    gas.nonce_key = if (tx.nonce_key == 0)
        schedule.protocol_nonce_cost
    else if (tx.nonce_key == eip8130.nonce_key_max)
        schedule.nonce_free_cost
    else if (input.nonce_key_first_use)
        schedule.nonce_key_first_use_cost
    else
        schedule.nonce_key_existing_cost;
    try account_changes_cost(tx, input.revoke_discount_slots, &gas);
    const sender_form: AuthWireForm = if (tx.sender == null) .bare_signature else .prefixed;
    gas.sender_auth = try auth_cost(signed.sender_auth, sender_form, input.sender_policy_gated);
    const payer = try payer_auth_costs(signed);
    gas.payer_auth_cost = payer.standard;
    gas.payer_floor = payer.floor;
    gas.value_transfer = schedule.tx_value_cost *| value_calls(tx, input.sender);
    const payload = sender_billed_costs(signed, encoded);
    gas.payload = payload.standard;
    gas.payload_floor = payload.floor;
    assert(gas.payload_floor >= gas.payload);
    return gas;
}

/// Ceiling on payer authentication billed on top of `gas_limit` (0 for self-pay).
pub fn max_payer_auth_cost(signed: eip8130.Signed) Error!u64 {
    return (try payer_auth_costs(signed)).floor;
}

fn value_calls(tx: eip8130.TxEip8130, sender: Address) u64 {
    var count: u64 = 0;
    var phases = tx.calls.iterator();
    while (phases.next()) |phase| {
        var calls = phase.iterator();
        while (calls.next()) |call| {
            count += @intFromBool(call.value != 0 and !call.to.eql(sender));
        }
    }
    assert(count <= tx.calls.payload.len);
    return count;
}

fn account_changes_cost(tx: eip8130.TxEip8130, discount_slots: u32, gas: *IntrinsicGas) Error!void {
    var revokes: u32 = 0;
    var state_touched = false;
    var changes = tx.account_changes.iterator();
    while (changes.next()) |change| switch (change) {
        .create => |entry| {
            gas.bytecode +|= schedule.create_base_cost +|
                schedule.code_deposit_per_byte *| @as(u64, entry.code.len);
            gas.account_changes +|= schedule.account_state_set_cost;
            state_touched = true;
            var actors = entry.initial_actors.iterator();
            while (actors.next()) |actor| {
                gas.account_changes +|= actor_slots_cost(actor.policy_data.len != 0);
            }
        },
        .config => |config| {
            gas.account_changes +|= if (state_touched)
                schedule.config_change_state_cost_subsequent
            else
                schedule.config_change_state_cost;
            state_touched = true;
            gas.account_changes +|= try auth_cost(config.signature, .prefixed, false);
            var ops = config.changes.iterator();
            while (ops.next()) |op| {
                revokes +|= @intFromBool(op.change_type == .revoke_actor);
                gas.account_changes +|= actor_change_write_cost(op);
            }
        },
        .delegation => gas.account_changes +|= schedule.delegation_deposit_cost,
    };
    // Execution may only discount slots the body was charged resets for.
    const discounted = @min(discount_slots, revokes *| 3);
    gas.account_changes -|= schedule.cold_slot_reset_discount * @as(u64, discounted);
}

/// An actor's config slot plus its two policy slots (set, or zero-to-zero touches).
fn actor_slots_cost(attaches_policy: bool) u64 {
    const policy_slots = if (attaches_policy)
        schedule.actor_slot_set_cost * 2
    else
        schedule.policy_slots_noop_cost;
    return schedule.actor_slot_set_cost + policy_slots;
}

fn actor_change_write_cost(op: eip8130.SignedChange) u64 {
    return switch (op.change_type) {
        .revoke_actor => schedule.actor_revoke_cost,
        .authorize_actor => actor_slots_cost(authorize_attaches_policy(op.payload)),
        .increment_local_epoch => schedule.increment_local_epoch_cost,
        // Not yet enshrined in base/base; priced when wired in.
        .lock, .unlock => 0,
    };
}

const Costs = struct { standard: u64, floor: u64 };

fn byte_costs(byte: u8) Costs {
    if (byte == 0) return .{
        .standard = schedule.tx_data_zero_byte,
        .floor = schedule.tx_total_cost_floor_per_token,
    };
    return .{
        .standard = schedule.tx_data_nonzero_byte,
        .floor = schedule.tx_total_cost_floor_per_token * 4,
    };
}

fn data_costs(costs: *Costs, data: []const u8) void {
    for (data) |byte| {
        const one = byte_costs(byte);
        costs.standard +|= one.standard;
        costs.floor +|= one.floor;
    }
}

/// Data costs of the encoding with an empty `payer_auth`, computed in place:
/// type byte, the re-sized list header, the body up to `payer_auth`, then `0x80`.
fn sender_billed_costs(signed: eip8130.Signed, encoded: []const u8) Costs {
    const old_payload = signed.payload_length(signed.payer_auth);
    const body_start = 1 + rlp.header_length(old_payload);
    const body_end = encoded.len - rlp.bytes_length(signed.payer_auth);
    assert(body_start <= body_end);
    var header_buffer: [9]u8 = undefined;
    var header = rlp.Encoder.init(&header_buffer);
    header.list_header(signed.payload_length(&.{}));
    var costs: Costs = .{ .standard = 0, .floor = 0 };
    data_costs(&costs, encoded[0..1]);
    data_costs(&costs, header.written());
    data_costs(&costs, encoded[body_start..body_end]);
    data_costs(&costs, &.{0x80});
    return costs;
}

fn payer_auth_costs(signed: eip8130.Signed) Error!Costs {
    if (signed.tx.payer == null) return .{ .standard = 0, .floor = 0 };
    const form: AuthWireForm = if (signed.tx.is_open_payer()) .bare_signature else .prefixed;
    const auth = try auth_cost(signed.payer_auth, form, false);
    var data: Costs = .{ .standard = 0, .floor = 0 };
    data_costs(&data, signed.payer_auth);
    const floor = auth +| data.floor;
    if (floor > schedule.max_authentication_gas) return error.PayerAuthGasExceeded;
    return .{ .standard = auth +| data.standard, .floor = floor };
}

/// Authenticator execution gas plus the cold SLOADs `authorize` reads (one per
/// resolved authenticator, one more for a policy-gated actor).
fn auth_cost(auth: []const u8, form: AuthWireForm, policy_gated: bool) Error!u64 {
    const exec = try auth_exec_cost(auth, form);
    var sloads: u64 = switch (form) {
        .bare_signature => 1,
        .prefixed => @intFromBool(auth.len >= 20 and exec > 0),
    };
    sloads += @intFromBool(policy_gated and exec > 0);
    assert(sloads <= 2);
    return exec +| schedule.cold_sload * sloads;
}

fn auth_exec_cost(auth: []const u8, form: AuthWireForm) Error!u64 {
    if (form == .bare_signature) return schedule.auth_exec_k1;
    if (auth.len < 20) return 0;
    const authenticator: Address = .{ .bytes = auth[0..20].* };
    if (!authenticator.eql(eip8130.contracts.delegate_authenticator)) {
        return schedule.leaf_auth_exec_gas(authenticator) orelse error.UnscheduledAuthenticator;
    }
    // delegate(20) || account(20) || nested authenticator(20) || data; depth 1 only.
    const nested_exec: u64 = if (auth.len >= 60)
        schedule.leaf_auth_exec_gas(.{ .bytes = auth[40..60].* }) orelse
            return error.UnscheduledAuthenticator
    else
        0;
    return schedule.auth_exec_delegate_overhead + nested_exec;
}

/// Whether an authorize payload `abi.encode(actorId, ActorConfig, policyData)` carries a
/// 52-byte `policyData`, following the offset word like the apply-path decoder.
pub fn authorize_attaches_policy(payload: []const u8) bool {
    const offset_word = 4 * 32;
    if (payload.len < offset_word + 32) return false;
    const offset = std.mem.readInt(u256, payload[offset_word..][0..32], .big);
    if (offset > payload.len or payload.len - offset < 32) return false;
    const start: usize = @intCast(offset);
    const length = std.mem.readInt(u256, payload[start..][0..32], .big);
    return length == eip8130.policy_data_length;
}

test {
    _ = @import("eip8130_gas_test.zig");
}

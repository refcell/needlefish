//! Stateless structural checks for EIP-8130 transactions (base/base `structure.rs`):
//! auth field shapes, account-change ordering and limits, actor lists.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const eip8130 = @import("eip8130.zig");
const Address = primitives.Address;
const Signed = eip8130.Signed;
const Error = eip8130.StructuralError;

pub fn validate(signed: Signed) Error!void {
    if (signed.tx.calls.count > eip8130.max_call_phases_per_tx) return error.TooManyCallPhases;
    if (!sender_auth_valid(signed)) return error.MalformedSenderAuth;
    if (!payer_auth_valid(signed)) return error.MalformedPayerAuth;
    if (signed.tx.account_changes.count > eip8130.max_account_changes_per_tx) {
        return error.TooManyAccountChanges;
    }
    try validate_account_changes(signed);
}

/// Authenticators are addresses at or above the k1 authenticator (0x..01).
pub fn authenticator_out_of_range(authenticator: Address) bool {
    return std.mem.order(u8, &authenticator.bytes, &eip8130.k1_authenticator.bytes) == .lt;
}

pub fn authenticator_allowed_for_tx_path(authenticator: Address) bool {
    return authenticator.eql(eip8130.k1_authenticator) or
        eip8130.contracts.is_canonical_authenticator(authenticator);
}

pub fn authenticator_payload_well_formed(authenticator: Address, data: []const u8) bool {
    if (authenticator.eql(eip8130.k1_authenticator)) return data.len == 65;
    if (authenticator.eql(eip8130.contracts.delegate_authenticator)) {
        if (data.len < 40) return false;
        const nested = Address.from_slice(data[20..40]);
        return !nested.eql(eip8130.contracts.delegate_authenticator) and
            authenticator_allowed_for_tx_path(nested);
    }
    return true;
}

/// `authenticator || data` with an allowed authenticator and well-formed data.
fn authenticated_blob_valid(auth: []const u8) bool {
    if (auth.len < 20) return false;
    const authenticator = Address.from_slice(auth[0..20]);
    return authenticator_allowed_for_tx_path(authenticator) and
        authenticator_payload_well_formed(authenticator, auth[20..]);
}

fn sender_auth_valid(signed: Signed) bool {
    const auth = signed.sender_auth;
    if (auth.len == 0) return false;
    if (signed.tx.sender == null) return auth.len == 65;
    return authenticated_blob_valid(auth);
}

fn payer_auth_valid(signed: Signed) bool {
    const payer_present = signed.tx.payer != null;
    const auth = signed.payer_auth;
    if (payer_present == (auth.len == 0)) return false;
    if (signed.tx.is_open_payer()) return auth.len == 65;
    if (payer_present) return authenticated_blob_valid(auth);
    return true;
}

fn validate_account_changes(signed: Signed) Error!void {
    var create_count: u32 = 0;
    var delegation_count: u32 = 0;
    var config_count: u32 = 0;
    var iterator = signed.tx.account_changes.iterator();
    var index: u32 = 0;
    while (iterator.next()) |change| : (index += 1) {
        switch (change) {
            .create => |create| {
                create_count += 1;
                if (create_count > 1 or index != 0) return error.MalformedAccountChange;
                const code = create.code;
                if (code.len == 0 or code.len > eip8130.max_code_size or code[0] == 0xef) {
                    return error.MalformedAccountChange;
                }
                if (create.initial_actors.count == 0) return error.MalformedAccountChange;
                try validate_initial_actors(create.initial_actors);
            },
            .config => |config| {
                config_count += 1;
                if (config_count > eip8130.max_config_changes_per_tx) {
                    return error.MalformedAccountChange;
                }
                if (config.changes.count == 0) return error.MalformedAccountChange;
                if (!authenticated_blob_valid(config.signature)) {
                    return error.MalformedAccountChange;
                }
                try validate_actor_changes(config.changes);
            },
            .delegation => {
                delegation_count += 1;
                if (delegation_count > 1 or create_count > 0) {
                    return error.MalformedAccountChange;
                }
            },
        }
    }
    assert(index == signed.tx.account_changes.count);
}

/// At most 32 actors, strictly increasing ids, valid authenticators, policy data
/// empty or exactly 52 bytes.
pub fn validate_initial_actors(actors: eip8130.InitialActors) Error!void {
    if (actors.count > eip8130.max_actors_per_entry) return error.MalformedAccountChange;
    var previous: ?primitives.B256 = null;
    var iterator = actors.iterator();
    while (iterator.next()) |actor| {
        if (authenticator_out_of_range(actor.authenticator)) return error.MalformedAccountChange;
        if (previous) |id| {
            if (std.mem.order(u8, &actor.actor_id.bytes, &id.bytes) != .gt) {
                return error.MalformedAccountChange;
            }
        }
        const length = actor.policy_data.len;
        if (length != 0 and length != eip8130.policy_data_length) {
            return error.MalformedAccountChange;
        }
        previous = actor.actor_id;
    }
}

/// At most 5 changes; lock/unlock are not allowed in transactions.
pub fn validate_actor_changes(changes: eip8130.SignedChanges) Error!void {
    if (changes.count > eip8130.max_actor_changes_per_config) return error.MalformedAccountChange;
    var iterator = changes.iterator();
    while (iterator.next()) |change| {
        const payload = change.payload;
        switch (change.change_type) {
            .authorize_actor => {
                if (payload.len < 64) return error.MalformedAccountChange;
                if (std.mem.allEqual(u8, payload[0..32], 0)) return error.MalformedAccountChange;
                if (!std.mem.allEqual(u8, payload[32..44], 0)) return error.MalformedAccountChange;
                const authenticator = Address.from_slice(payload[44..64]);
                if (authenticator_out_of_range(authenticator)) return error.MalformedAccountChange;
            },
            .revoke_actor => if (payload.len != 32) return error.MalformedAccountChange,
            .increment_local_epoch => if (payload.len != 0) return error.MalformedAccountChange,
            .lock, .unlock => return error.MalformedAccountChange,
        }
    }
}

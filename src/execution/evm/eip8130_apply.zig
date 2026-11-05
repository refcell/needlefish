//! EIP-8130 account-changes apply step, mirroring base/base
//! `crates/execution/eip8130/src/{apply,events}.rs`.
//!
//! `eip8130_auth.authorize_changes` authenticates a signed batch; this module performs the
//! `AccountConfiguration` storage transitions (authorize, revoke, increment epoch), account
//! creation at the deterministic CREATE2 address, and EIP-7702-style delegation, and emits
//! the `IAccountConfiguration` logs (the enshrined path has no LOG opcodes of its own).
//! Config changes thread an in-memory `AccountState` that the caller persists at the end
//! of the batch, like `Keystore._applySignedAccountChanges`.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const config = @import("eip8130_config.zig");
const abi = @import("native_abi.zig");
const native = @import("native.zig");
const state_module = @import("state.zig");
const eip8130 = @import("../../common/consensus/eip8130.zig");
const keccak256 = @import("../../common/crypto/root.zig").keccak256;

const Address = primitives.Address;
const B256 = primitives.B256;
const Store = config.Store;
const AccountState = config.AccountState;
const ActorConfig = config.ActorConfig;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const Error = config.Error || error{
    MalformedAuthorizeData,
    MalformedRevokeData,
    InvalidChangePayload,
    EpochSaturated,
    UnknownChangeType,
    AccountIsLocked,
    ExpiryDoesNotOutliveUnlock,
    EmptyChangeSet,
    InvalidActorId,
    InvalidAuthenticator,
    InvalidPolicyData,
    NoInitialActors,
    ActorsNotSortedOrDuplicate,
    EmptyBytecode,
    BytecodeTooLarge,
    CreateCodeExceedsMaxSize,
    CreateCodeStartsWithEf,
    AlreadyInitialized,
    NonDelegatableCode,
    SequenceSaturated,
    BadSequence,
    StaleEpoch,
};

const event_actor_authorized = hex32(
    "7427678b205ea26cd22254b5ebdc924c4bf6f9bb78e436872e49599e97963559",
);
const event_actor_revoked = hex32(
    "eb5bd9b1e97c446e28bffcb6963893ca5ad94dc662962fd732ffc03ca279b3e5",
);
const event_account_created = hex32(
    "934abbffb6906db60a85b076f1e41da9667dfa53c7724f4fe2333298d7b1db8c",
);

fn hex32(comptime text: []const u8) [32]u8 {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    return bytes;
}

fn is_zero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

fn address_word(account: Address) B256 {
    return config.self_actor_id(account);
}

fn is_self(account: Address, actor_id: B256) bool {
    return std.mem.eql(u8, &actor_id, &config.self_actor_id(account));
}

const Policy = struct { manager: Address, commitment: B256 };

/// Empty policy data clears the gate; otherwise exactly `manager(20) || commitment(32)`.
pub fn slice_policy(policy_data: []const u8) Error!Policy {
    if (policy_data.len == 0) return .{ .manager = @splat(0), .commitment = @splat(0) };
    if (policy_data.len != eip8130.policy_data_length) return error.InvalidPolicyData;
    return .{ .manager = policy_data[0..20].*, .commitment = policy_data[20..52].* };
}

const Authorize = struct { actor_id: B256, config: ActorConfig, policy_data: []const u8 };

/// abi.decode(payload, (bytes32, (address, uint48, uint16), bytes)) in validate mode.
pub fn decode_authorize(payload: []const u8) Error!Authorize {
    const kinds = [_]abi.Kind{ .bytes32, .address, .uint48, .uint16, .bytes };
    var failure: native.DecodeFailure = .overrun;
    const arguments = abi.decode_arguments(payload, &kinds, 0, &failure) orelse
        return error.MalformedAuthorizeData;
    return .{
        .actor_id = arguments.words[0].*,
        .config = .{
            .authenticator = arguments.address(1),
            .expiry = @truncate(arguments.uint256(2)),
            .scope = @truncate(arguments.uint256(3)),
        },
        .policy_data = arguments.bytes(4),
    };
}

fn decode_revoke(payload: []const u8) Error!B256 {
    const kinds = [_]abi.Kind{.bytes32};
    var failure: native.DecodeFailure = .overrun;
    const arguments = abi.decode_arguments(payload, &kinds, 0, &failure) orelse
        return error.MalformedRevokeData;
    return arguments.words[0].*;
}

/// Apply a pre-authorized config-change batch against the in-memory batch `current`
/// state; the caller persists `current` afterwards. Returns the revoke discount (empty
/// slots a revoke found already clear).
pub fn apply_config_change(
    store: Store,
    account: Address,
    change: eip8130.ConfigChange,
    current: *AccountState,
    now: u64,
) Error!u32 {
    if (change.changes.payload.len == 0) return error.EmptyChangeSet;
    try advance_channel_sequence(change.channel, change.sequence, current);
    const sequence_low: u32 = @truncate(change.sequence);
    const unsequenced = change.channel == .local and sequence_low == eip8130.unsequenced;
    const locked = current.is_locked(now);
    var discount: u32 = 0;
    var items = change.changes.iterator();
    var count: u32 = 0;
    while (items.next()) |item| : (count += 1) {
        assert(count < eip8130.max_config_changes_per_tx * eip8130.max_actor_changes_per_config);
        switch (item.change_type) {
            .authorize_actor => {
                const decoded = try decode_authorize(item.payload);
                if (unsequenced and decoded.config.is_expired(now)) continue;
                if (locked) try enforce_locked_rules(store, account, decoded, current.*, now);
                try authorize_with_state(store, account, decoded, current);
            },
            .revoke_actor => {
                if (locked) return error.AccountIsLocked;
                const actor_id = try decode_revoke(item.payload);
                discount +|= try revoke_with_state(store, account, actor_id, current);
            },
            .increment_local_epoch => {
                if (item.payload.len != 0) return error.InvalidChangePayload;
                if (current.local_epoch == std.math.maxInt(u32)) return error.EpochSaturated;
                current.local_epoch += 1;
                current.local_sequence = 0;
            },
            .lock, .unlock => return error.UnknownChangeType,
        }
    }
    return discount;
}

fn advance_channel_sequence(
    channel: eip8130.Channel,
    sequence: u64,
    current: *AccountState,
) Error!void {
    switch (channel) {
        .local => {
            const epoch: u32 = @truncate(sequence >> 32);
            if (epoch != current.local_epoch) return error.StaleEpoch;
            const low: u32 = @truncate(sequence);
            if (low != eip8130.unsequenced) {
                if (low != current.local_sequence) return error.BadSequence;
                // The authorizer rejected low >= unsequenced - 1, so this cannot wrap.
                assert(low < std.math.maxInt(u32));
                current.local_sequence = low + 1;
            } else if (!current.is_initialized()) {
                current.local_sequence = 1;
            }
        },
        .multichain => {
            if (sequence != current.multichain_sequence) return error.BadSequence;
            const next = std.math.add(u64, current.multichain_sequence, 1) catch
                return error.SequenceSaturated;
            current.multichain_sequence = next;
        },
    }
}

/// While locked, an authorize may only re-add an identical live actor (or a new one)
/// whose expiry outlives the unlock floor.
fn enforce_locked_rules(
    store: Store,
    account: Address,
    decoded: Authorize,
    current: AccountState,
    now: u64,
) Error!void {
    const floor = current.unlock_floor(now);
    if (decoded.config.expiry != 0 and decoded.config.expiry <= floor) {
        return error.ExpiryDoesNotOutliveUnlock;
    }
    const live = try store.resolve_live_actor_config(account, decoded.actor_id, current, now);
    if (live.is_empty()) return;
    const policy = try slice_policy(decoded.policy_data);
    const same_identity =
        std.mem.eql(u8, &decoded.config.authenticator, &live.authenticator) and
        decoded.config.scope == live.scope;
    const manager = try store.policy_manager(account, decoded.actor_id);
    const commitment = try store.policy_commitment(account, decoded.actor_id);
    const same_policy = std.mem.eql(u8, &policy.manager, &manager) and
        std.mem.eql(u8, &policy.commitment, &commitment);
    if (!same_identity or !same_policy) return error.AccountIsLocked;
}

/// The self actor with the k1 authenticator re-enables the inline self; any other
/// authenticator on the self id disables it in favor of the explicit entry.
fn authorize_with_state(
    store: Store,
    account: Address,
    decoded: Authorize,
    current: *AccountState,
) Error!void {
    if (is_zero(&decoded.config.authenticator)) return error.InvalidAuthenticator;
    if (!is_self(account, decoded.actor_id)) return authorize_non_self(store, account, decoded);
    const policy = try slice_policy(decoded.policy_data);
    if (std.mem.eql(u8, &decoded.config.authenticator, &config.k1_authenticator)) {
        try store.clear_actor_config(account, decoded.actor_id);
        current.default_eoa_scope = decoded.config.scope;
        current.default_eoa_expiry = decoded.config.expiry;
        current.flags &= ~eip8130.flag_default_eoa_revoked;
    } else {
        try store.set_actor_config(account, decoded.actor_id, decoded.config);
        disable_inline_self(current);
    }
    try store.set_policy(account, decoded.actor_id, policy.manager, policy.commitment);
    try emit_authorized(store, account, decoded, policy);
}

fn authorize_non_self(store: Store, account: Address, decoded: Authorize) Error!void {
    if (is_zero(&decoded.actor_id)) return error.InvalidActorId;
    if (is_zero(&decoded.config.authenticator)) return error.InvalidAuthenticator;
    const policy = try slice_policy(decoded.policy_data);
    try store.set_actor_config(account, decoded.actor_id, decoded.config);
    try store.set_policy(account, decoded.actor_id, policy.manager, policy.commitment);
    try emit_authorized(store, account, decoded, policy);
}

/// Standalone authorize (account creation): the self id goes through the stored state.
fn authorize_actor(store: Store, account: Address, decoded: Authorize) Error!void {
    if (!is_self(account, decoded.actor_id)) return authorize_non_self(store, account, decoded);
    var current = try store.account_state(account);
    try authorize_with_state(store, account, decoded, &current);
    try store.set_account_state(account, current);
}

fn disable_inline_self(current: *AccountState) void {
    current.flags |= eip8130.flag_default_eoa_revoked;
    current.default_eoa_scope = 0;
    current.default_eoa_expiry = 0;
}

/// Revoke an actor. Returns how many of its three record slots were already empty
/// (revoking an absent actor discounts all three).
fn revoke_with_state(
    store: Store,
    account: Address,
    actor_id: B256,
    current: *AccountState,
) Error!u32 {
    const stored = try store.actor_config_slot(account, actor_id);
    const self_actor = is_self(account, actor_id);
    if (!stored.is_empty()) {
        try revoke_explicit(store, account, actor_id);
        if (self_actor) disable_inline_self(current);
        return 0;
    }
    if (!self_actor or current.default_eoa_revoked()) return 3;
    var empty_slots: u32 = 1;
    if (is_zero(&try store.policy_manager(account, actor_id))) empty_slots += 1;
    if (is_zero(&try store.policy_commitment(account, actor_id))) empty_slots += 1;
    try store.clear_actor_config(account, actor_id);
    try store.clear_policy(account, actor_id);
    disable_inline_self(current);
    try emit_revoked(store, account, actor_id);
    assert(empty_slots <= 3);
    return empty_slots;
}

fn revoke_explicit(store: Store, account: Address, actor_id: B256) Error!void {
    try store.clear_actor_config(account, actor_id);
    try store.clear_policy(account, actor_id);
    try emit_revoked(store, account, actor_id);
}

/// `authenticator(20) || uint48 expiry || uint16 scope || 0(4)`, plus
/// `manager || commitment` when a policy was attached.
fn emit_authorized(store: Store, account: Address, decoded: Authorize, policy: Policy) Error!void {
    var data: [3 * 32 + 96]u8 = @splat(0);
    const actor_data_length: usize = if (decoded.policy_data.len == 0) 32 else 84;
    std.mem.writeInt(u256, data[0..32], 32, .big);
    std.mem.writeInt(u256, data[32..64], actor_data_length, .big);
    const actor_data = data[64..];
    actor_data[0..20].* = decoded.config.authenticator;
    std.mem.writeInt(u48, actor_data[20..26], @intCast(decoded.config.expiry), .big);
    std.mem.writeInt(u16, actor_data[26..28], decoded.config.scope, .big);
    if (actor_data_length == 84) {
        actor_data[32..52].* = policy.manager;
        actor_data[52..84].* = policy.commitment;
    }
    const length = 64 + std.mem.alignForward(usize, actor_data_length, 32);
    const topics = [3]B256{ event_actor_authorized, address_word(account), decoded.actor_id };
    try store.state.log(config.address, &topics, data[0..length]);
}

fn emit_revoked(store: Store, account: Address, actor_id: B256) Error!void {
    const topics = [3]B256{ event_actor_revoked, address_word(account), actor_id };
    try store.state.log(config.address, &topics, &.{});
}

pub const Created = struct { address: Address, code: []const u8 };

/// Create a counterfactual account: validate the runtime, derive its CREATE2 address,
/// mark it initialized with the inline self revoked, and authorize the initial actors.
/// The caller deploys `code` at `address`.
pub fn apply_create(store: Store, entry: eip8130.CreateEntry) Error!Created {
    try validate_create_runtime(entry.code);
    const address = try compute_address(entry.user_salt.bytes, entry.code, entry.initial_actors);
    var current = try store.account_state(address);
    if (current.is_initialized()) return error.AlreadyInitialized;
    current.local_sequence = 1;
    current.flags = eip8130.flag_default_eoa_revoked;
    try store.set_account_state(address, current);
    try initialize_actors(store, address, entry.initial_actors);
    var data: [64]u8 = undefined;
    data[0..32].* = entry.user_salt.bytes;
    data[32..64].* = keccak256(entry.code);
    const topics = [2]B256{ event_account_created, address_word(address) };
    try store.state.log(config.address, &topics, &data);
    return .{ .address = address, .code = entry.code };
}

fn initialize_actors(store: Store, account: Address, actors: eip8130.InitialActors) Error!void {
    var items = actors.iterator();
    var previous: B256 = @splat(0);
    var count: u32 = 0;
    while (items.next()) |actor| : (count += 1) {
        assert(count < eip8130.max_actors_per_entry);
        const actor_id = actor.actor_id.bytes;
        if (std.mem.order(u8, &actor_id, &previous) != .gt) {
            return error.ActorsNotSortedOrDuplicate;
        }
        previous = actor_id;
        const decoded = Authorize{
            .actor_id = actor_id,
            .config = .{
                .authenticator = actor.authenticator.bytes,
                .scope = actor.scope,
                .expiry = 0,
            },
            .policy_data = actor.policy_data,
        };
        try authorize_actor(store, account, decoded);
    }
    if (count == 0) return error.NoInitialActors;
}

pub fn validate_create_runtime(code: []const u8) Error!void {
    if (code.len == 0) return error.EmptyBytecode;
    if (code.len > eip8130.max_code_size) return error.CreateCodeExceedsMaxSize;
    if (code[0] == 0xef) return error.CreateCodeStartsWithEf;
}

/// PUSH2 n PUSH1 14 PUSH1 0 CODECOPY PUSH2 n PUSH1 0 RETURN, followed by the runtime.
pub fn deployment_prefix(code_length: usize) Error![14]u8 {
    if (code_length == 0) return error.EmptyBytecode;
    if (code_length > 0xffff) return error.BytecodeTooLarge;
    const high: u8 = @truncate(code_length >> 8);
    const low: u8 = @truncate(code_length);
    return .{ 0x61, high, low, 0x60, 0x0e, 0x60, 0x00, 0x39, 0x61, high, low, 0x60, 0x00, 0xf3 };
}

/// CREATE2 from the AccountConfiguration contract with salt
/// keccak256(userSalt || actorsCommitment) over the deployment code.
pub fn compute_address(
    user_salt: B256,
    code: []const u8,
    actors: eip8130.InitialActors,
) Error!Address {
    var salt_preimage: [64]u8 = undefined;
    salt_preimage[0..32].* = user_salt;
    salt_preimage[32..64].* = actors_commitment(actors);
    const salt = keccak256(&salt_preimage);
    var hasher = Keccak256.init(.{});
    hasher.update(&try deployment_prefix(code.len));
    hasher.update(code);
    var code_hash: [32]u8 = undefined;
    hasher.final(&code_hash);
    var preimage: [85]u8 = undefined;
    preimage[0] = 0xff;
    preimage[1..21].* = config.address;
    preimage[21..53].* = salt;
    preimage[53..85].* = code_hash;
    return keccak256(&preimage)[12..32].*;
}

/// keccak256(concat(keccak256(actorId || authenticator || uint16 scope || policyData))).
fn actors_commitment(actors: eip8130.InitialActors) B256 {
    var packed_hasher = Keccak256.init(.{});
    var items = actors.iterator();
    var count: u32 = 0;
    while (items.next()) |actor| : (count += 1) {
        assert(count <= eip8130.max_actors_per_entry);
        var leaf_hasher = Keccak256.init(.{});
        leaf_hasher.update(&actor.actor_id.bytes);
        leaf_hasher.update(&actor.authenticator.bytes);
        var scope: [2]u8 = undefined;
        std.mem.writeInt(u16, &scope, actor.scope, .big);
        leaf_hasher.update(&scope);
        leaf_hasher.update(actor.policy_data);
        var leaf: [32]u8 = undefined;
        leaf_hasher.final(&leaf);
        packed_hasher.update(&leaf);
    }
    var commitment: [32]u8 = undefined;
    packed_hasher.final(&commitment);
    return commitment;
}

/// Deploy a created account's runtime (account changes apply at transaction start,
/// outside the execution journal, like EIP-7702 authorizations).
pub fn deploy_created(state: *state_module.State, created: Created) Error!void {
    const account = try state.load(created.address);
    assert(created.code.len > 0);
    try state.set_code_unjournaled(account, created.code);
    try state.touch(account);
}

/// Point `account` at `target` with a delegation indicator (zero target clears the code).
/// Only empty code or an existing indicator may be replaced.
pub fn install_delegation(
    state: *state_module.State,
    account_address: Address,
    target: Address,
) Error!void {
    const account = try state.load(account_address);
    const code = try state.code(account);
    const prefix = eip8130.delegation_indicator_prefix;
    const replaceable = code.len == 0 or std.mem.startsWith(u8, code, &prefix);
    if (!replaceable) return error.NonDelegatableCode;
    if (is_zero(&target)) {
        try state.set_code_unjournaled(account, &.{});
    } else {
        const indicator = eip8130.delegation_indicator(.init(target));
        try state.set_code_unjournaled(account, &indicator);
    }
    try state.touch(account);
}

const testing = std.testing;
const memory_db = @import("memory_db.zig");

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

/// abi.encode(actorId, (authenticator, expiry, scope), policyData).
fn authorize_payload(buffer: []u8, actor_id: B256, actor: ActorConfig, policy: []const u8) []u8 {
    @memset(buffer, 0);
    buffer[0..32].* = actor_id;
    buffer[44..64].* = actor.authenticator;
    std.mem.writeInt(u256, buffer[64..96], actor.expiry, .big);
    std.mem.writeInt(u256, buffer[96..128], actor.scope, .big);
    std.mem.writeInt(u256, buffer[128..160], 160, .big);
    std.mem.writeInt(u256, buffer[160..192], policy.len, .big);
    @memcpy(buffer[192..][0..policy.len], policy);
    return buffer[0 .. 192 + std.mem.alignForward(usize, policy.len, 32)];
}

test "eip8130 apply: authorize, revoke, and epoch changes thread the batch state" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    const account: Address = @splat(0x11);
    const actor_id: B256 = @splat(0x22);
    const actor = ActorConfig{ .authenticator = @splat(0x33), .expiry = 0, .scope = 4 };
    var policy: [52]u8 = @splat(0x44);
    var payload_buffer: [256]u8 = undefined;
    const payload = authorize_payload(&payload_buffer, actor_id, actor, &policy);
    var revoke_payload: [32]u8 = config.self_actor_id(account);
    const items = [3]eip8130.SignedChange{
        .{ .change_type = .authorize_actor, .payload = payload },
        .{ .change_type = .revoke_actor, .payload = &revoke_payload },
        .{ .change_type = .increment_local_epoch, .payload = &.{} },
    };
    var list_buffer: [512]u8 = undefined;
    const change = eip8130.ConfigChange{
        .channel = .local,
        .sequence = 0,
        .changes = eip8130.SignedChanges.build(&list_buffer, &items),
        .signature = &.{},
    };
    var current = try store.account_state(account);
    const discount = try apply_config_change(store, account, change, &current, 1);
    try testing.expectEqual(@as(u32, 3), discount);
    try testing.expect(current.default_eoa_revoked());
    try testing.expectEqual(@as(u32, 1), current.local_epoch);
    try testing.expectEqual(@as(u32, 0), current.local_sequence);
    const stored = try store.actor_config_slot(account, actor_id);
    try testing.expectEqualDeep(actor, stored);
    try testing.expectEqualSlices(u8, policy[0..20], &try store.policy_manager(account, actor_id));
    try testing.expectEqual(@as(usize, 2), fixture.state.transaction_logs().len);
    try testing.expectError(
        error.StaleEpoch,
        apply_config_change(store, account, change, &current, 1),
    );

    policy[0] = 0;
    const short = authorize_payload(&payload_buffer, actor_id, actor, policy[0..51]);
    const bad = [1]eip8130.SignedChange{.{ .change_type = .authorize_actor, .payload = short }};
    var retry = change;
    retry.sequence = 1 << 32;
    retry.changes = eip8130.SignedChanges.build(&list_buffer, &bad);
    try testing.expectError(
        error.InvalidPolicyData,
        apply_config_change(store, account, retry, &current, 1),
    );
    const locked_items = [1]eip8130.SignedChange{.{ .change_type = .lock, .payload = &.{} }};
    retry.changes = eip8130.SignedChanges.build(&list_buffer, &locked_items);
    current.local_sequence = 0;
    try testing.expectError(
        error.UnknownChangeType,
        apply_config_change(store, account, retry, &current, 1),
    );
}

test "eip8130 apply: locked accounts only re-add identical actors past the unlock floor" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    const account: Address = @splat(0x12);
    const actor_id: B256 = @splat(0x23);
    const actor = ActorConfig{ .authenticator = @splat(0x34), .expiry = 0, .scope = 4 };
    var current = try store.account_state(account);
    current.flags = eip8130.flag_locked;
    current.lock_union = 100;
    var payload_buffer: [256]u8 = undefined;
    const fresh = Authorize{ .actor_id = actor_id, .config = actor, .policy_data = &.{} };
    try enforce_locked_rules(store, account, fresh, current, 5);
    try authorize_with_state(store, account, fresh, &current);
    try enforce_locked_rules(store, account, fresh, current, 5);
    var changed = fresh;
    changed.config.scope = 2;
    try testing.expectError(
        error.AccountIsLocked,
        enforce_locked_rules(store, account, changed, current, 5),
    );
    var short_lived = fresh;
    short_lived.config.expiry = 105;
    try testing.expectError(
        error.ExpiryDoesNotOutliveUnlock,
        enforce_locked_rules(store, account, short_lived, current, 5),
    );
    const decoded = try decode_authorize(authorize_payload(&payload_buffer, actor_id, actor, &.{}));
    try testing.expectEqualDeep(actor, decoded.config);
    payload_buffer[64] = 1;
    try testing.expectError(error.MalformedAuthorizeData, decode_authorize(payload_buffer[0..192]));
}

test "eip8130 apply: create derives the CREATE2 address and authorizes sorted actors" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    const common = @import("../../common/primitives/root.zig");
    const actors = [2]eip8130.InitialActor{
        .{
            .actor_id = .init(@splat(1)),
            .authenticator = .init(@splat(5)),
            .scope = 0,
            .policy_data = &.{},
        },
        .{
            .actor_id = .init(@splat(2)),
            .authenticator = .init(@splat(6)),
            .scope = 8,
            .policy_data = &.{},
        },
    };
    var actors_buffer: [256]u8 = undefined;
    const entry = eip8130.CreateEntry{
        .user_salt = common.B256.init(@splat(9)),
        .code = &.{ 0x60, 0x00 },
        .initial_actors = eip8130.InitialActors.build(&actors_buffer, &actors),
    };
    const created = try apply_create(store, entry);
    const expected = try compute_address(@splat(9), entry.code, entry.initial_actors);
    try testing.expectEqualSlices(u8, &expected, &created.address);
    const current = try store.account_state(created.address);
    try testing.expect(current.is_initialized());
    try testing.expect(current.default_eoa_revoked());
    try testing.expect(try store.is_actor(created.address, @splat(2)));
    try testing.expectError(error.AlreadyInitialized, apply_create(store, entry));
    try deploy_created(&fixture.state, created);

    const reversed = [2]eip8130.InitialActor{ actors[1], actors[0] };
    var unsorted = entry;
    unsorted.initial_actors = eip8130.InitialActors.build(&actors_buffer, &reversed);
    try testing.expectError(error.ActorsNotSortedOrDuplicate, apply_create(store, unsorted));
    var bad_code = entry;
    bad_code.code = &.{0xef};
    try testing.expectError(error.CreateCodeStartsWithEf, apply_create(store, bad_code));
    const prefix = try deployment_prefix(0x1234);
    try testing.expectEqual(@as(u8, 0x12), prefix[1]);
    try testing.expectError(error.BytecodeTooLarge, deployment_prefix(0x10000));
}

test "eip8130 apply: delegation replaces only empty code or an indicator" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const account: Address = @splat(0x13);
    try install_delegation(&fixture.state, account, @splat(0x77));
    const loaded = try fixture.state.load(account);
    const code = try fixture.state.code(loaded);
    try testing.expectEqualSlices(u8, &eip8130.delegation_indicator_prefix, code[0..3]);
    try install_delegation(&fixture.state, account, @splat(0));
    try testing.expectEqual(@as(usize, 0), (try fixture.state.code(loaded)).len);
    try fixture.state.set_code_unjournaled(loaded, &.{0x00});
    try testing.expectError(
        error.NonDelegatableCode,
        install_delegation(&fixture.state, account, @splat(1)),
    );
}

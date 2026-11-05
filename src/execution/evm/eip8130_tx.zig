//! EIP-8130 transaction authorization orchestrator, nonce-sequence and fee checks,
//! mirroring base/base `crates/execution/eip8130/src/{transaction,validate,fee}.rs`.
//!
//! `authorize_and_apply` walks the ordered account changes against the evolving state
//! (one create, only at index 0 and deriving to the sender; config batches authorized as
//! they are reached; at most one delegation, never with a create), then authenticates the
//! sender and payer against the post-apply state.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const config = @import("eip8130_config.zig");
const auth = @import("eip8130_auth.zig");
const apply = @import("eip8130_apply.zig");
const eip8130 = @import("../../common/consensus/eip8130.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Store = config.Store;

pub const Error = auth.Error || apply.Error || error{
    CreateAndDelegation,
    InvalidCreatePosition,
    CreateAddressMismatch,
    MultipleDelegations,
    AccountIsLocked,
    DelegationUnauthorized,
    UnsupportedAccountChange,
    UnsupportedAuthenticator,
    SignerMismatch,
};

pub const Delegation = struct { account: Address, target: Address };

pub const AppliedTransaction = struct {
    actors: auth.TxActors,
    created: ?apply.Created = null,
    delegation: ?Delegation = null,
    config_change_count: u32 = 0,
    revoke_discount_slots: u32 = 0,
};

/// The sender before authentication: the explicit wire sender or the EOA k1 signer.
fn sender_account(signed: eip8130.Signed) Error!struct { account: Address, recovered: bool } {
    if (signed.tx.sender) |explicit| return .{ .account = explicit.bytes, .recovered = false };
    const hash = signed.tx.sender_signature_hash().bytes;
    const signer = auth.recover_k1(hash, signed.sender_auth) catch return error.SenderRecovery;
    return .{ .account = signer, .recovered = true };
}

/// Apply the account changes in order, then verify sender and payer post-apply.
pub fn authorize_and_apply(
    signed: eip8130.Signed,
    store: Store,
    local_chain_id: u64,
    now: u64,
) Error!AppliedTransaction {
    const sender = try sender_account(signed);
    var applied = AppliedTransaction{ .actors = undefined };
    var changes = signed.tx.account_changes.iterator();
    var index: u32 = 0;
    while (changes.next()) |change| : (index += 1) {
        assert(index < eip8130.max_account_changes_per_tx + eip8130.max_config_changes_per_tx);
        switch (change) {
            .create => |entry| {
                if (applied.delegation != null) return error.CreateAndDelegation;
                if (index != 0 or applied.created != null) return error.InvalidCreatePosition;
                const created = try apply.apply_create(store, entry);
                if (!std.mem.eql(u8, &created.address, &sender.account)) {
                    return error.CreateAddressMismatch;
                }
                applied.created = created;
            },
            .config => |batch| {
                var current = try store.account_state(sender.account);
                _ = try auth.authorize_changes(
                    store,
                    sender.account,
                    local_chain_id,
                    batch,
                    now,
                    current,
                );
                applied.config_change_count += 1;
                const discount = try apply.apply_config_change(
                    store,
                    sender.account,
                    batch,
                    &current,
                    now,
                );
                applied.revoke_discount_slots +|= discount;
                try store.set_account_state(sender.account, current);
            },
            .delegation => |target| {
                if (applied.delegation != null) return error.MultipleDelegations;
                if (applied.created != null) return error.CreateAndDelegation;
                applied.delegation = .{ .account = sender.account, .target = target.bytes };
            },
        }
    }
    const recovered: ?Address = if (sender.recovered) sender.account else null;
    applied.actors = try auth.verify(signed, store, now, recovered);
    if (applied.delegation != null) {
        if (try store.is_locked(applied.actors.sender.account, now)) return error.AccountIsLocked;
        if (!applied.actors.sender.resolved.is_admin()) return error.DelegationUnauthorized;
    }
    return applied;
}

fn named_k1(auth_blob: []const u8) bool {
    return std.mem.startsWith(u8, auth_blob, &config.k1_authenticator);
}

/// Without a deployed keystore only delegations and k1 authentication are supported.
pub fn check_without_keystore(signed: eip8130.Signed) Error!void {
    var changes = signed.tx.account_changes.iterator();
    while (changes.next()) |change| {
        if (change != .delegation) return error.UnsupportedAccountChange;
    }
    if (signed.tx.payer == null and signed.payer_auth.len != 0) return error.UnexpectedPayerAuth;
    const named_sender_bad = signed.tx.sender != null and !named_k1(signed.sender_auth);
    const named_payer = signed.tx.payer != null and !signed.tx.is_open_payer();
    if (named_sender_bad or (named_payer and !named_k1(signed.payer_auth))) {
        return error.UnsupportedAuthenticator;
    }
}

fn recover_named_k1(account: Address, hash: B256, auth_blob: []const u8) Error!Address {
    if (!named_k1(auth_blob)) return error.UnsupportedAuthenticator;
    const signer = try auth.recover_k1(hash, auth_blob[20..]);
    if (!std.mem.eql(u8, &signer, &account)) return error.SignerMismatch;
    return account;
}

/// Every actor is the unrestricted owner; only delegations apply.
pub fn authorize_without_keystore(signed: eip8130.Signed) Error!AppliedTransaction {
    try check_without_keystore(signed);
    const tx = signed.tx;
    const sender_hash = tx.sender_signature_hash().bytes;
    const sender: Address = if (tx.sender) |explicit|
        try recover_named_k1(explicit.bytes, sender_hash, signed.sender_auth)
    else
        auth.recover_k1(sender_hash, signed.sender_auth) catch return error.SenderRecovery;
    var payer: ?Address = null;
    if (tx.payer) |payer_field| {
        const payer_hash = tx.payer_signature_hash(.init(sender)).bytes;
        payer = if (tx.is_open_payer())
            auth.recover_k1(payer_hash, signed.payer_auth) catch return error.PayerRecovery
        else
            try recover_named_k1(payer_field.bytes, payer_hash, signed.payer_auth);
    }
    var applied = AppliedTransaction{ .actors = .{
        .sender = owner(sender),
        .payer = if (payer) |account| owner(account) else null,
    } };
    var changes = tx.account_changes.iterator();
    while (changes.next()) |change| {
        assert(change == .delegation);
        if (applied.delegation != null) return error.MultipleDelegations;
        applied.delegation = .{ .account = sender, .target = change.delegation.bytes };
    }
    return applied;
}

fn owner(account: Address) auth.AuthorizedActor {
    const actor_id = config.self_actor_id(account);
    return .{ .account = account, .resolved = auth.ResolvedActor.unrestricted(actor_id) };
}

pub const NonceMode = enum { pool, inclusion };
pub const NonceStatus = union(enum) { ready, buffered: u64 };
pub const NonceError = error{ NonceFreeSequence, Replay, SequenceSaturated, TooLow, TooHigh };

/// A sequenced nonce against its channel value: equal is ready; ahead buffers in the
/// pool and is invalid at inclusion.
pub fn validate_sequence(
    nonce_sequence: u64,
    channel: u64,
    mode: NonceMode,
) NonceError!NonceStatus {
    if (nonce_sequence == std.math.maxInt(u64)) return error.SequenceSaturated;
    if (nonce_sequence < channel) return error.TooLow;
    if (nonce_sequence == channel) return .ready;
    if (mode == .inclusion) return error.TooHigh;
    return .{ .buffered = nonce_sequence - channel };
}

pub const FeeError = error{ TipAboveFeeCap, FeeCapBelowBaseFee, InsufficientBalance };

pub fn effective_gas_price(max_fee: u128, max_priority_fee: u128, base_fee: u128) u128 {
    return @min(max_fee, base_fee +| max_priority_fee);
}

/// (gas_limit + payer auth cost) * max_fee, saturating.
pub fn max_fee_charge(gas_limit: u64, payer_auth_cost: u64, max_fee: u128) u256 {
    const gas = gas_limit +| payer_auth_cost;
    return std.math.mul(u256, gas, max_fee) catch unreachable; // u64 * u128 fits in u256.
}

pub fn validate_fees(max_fee: u128, max_priority_fee: u128, base_fee: u128) FeeError!void {
    if (max_priority_fee > max_fee) return error.TipAboveFeeCap;
    if (max_fee < base_fee) return error.FeeCapBelowBaseFee;
}

pub fn validate_balance(
    balance: u256,
    gas_limit: u64,
    payer_auth_cost: u64,
    max_fee: u128,
) FeeError!void {
    if (balance < max_fee_charge(gas_limit, payer_auth_cost, max_fee)) {
        return error.InsufficientBalance;
    }
}

/// A self-paying sender covers prepay plus tip; a sponsored one covers only the tip.
pub fn validate_gas_and_tip(
    payer_balance: u256,
    sender_balance: u256,
    payer_is_sender: bool,
    prepay: u256,
    tip: u256,
) FeeError!void {
    if (payer_is_sender) {
        if (payer_balance < prepay +| tip) return error.InsufficientBalance;
        return;
    }
    if (payer_balance < prepay) return error.InsufficientBalance;
    if (sender_balance < tip) return error.InsufficientBalance;
}

const testing = std.testing;
const memory_db = @import("memory_db.zig");
const state_module = @import("state.zig");

const dev_key_0 = blk: {
    var bytes: [32]u8 = undefined;
    const text = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    break :blk bytes;
};

test "eip8130 tx: nonce sequences and fee checks" {
    try testing.expectEqual(NonceStatus.ready, try validate_sequence(4, 4, .inclusion));
    try testing.expectEqual(NonceStatus{ .buffered = 2 }, try validate_sequence(6, 4, .pool));
    try testing.expectError(error.TooHigh, validate_sequence(6, 4, .inclusion));
    try testing.expectError(error.TooLow, validate_sequence(3, 4, .pool));
    try testing.expectError(
        error.SequenceSaturated,
        validate_sequence(std.math.maxInt(u64), 0, .pool),
    );
    try testing.expectEqual(@as(u128, 15), effective_gas_price(20, 5, 10));
    try testing.expectEqual(@as(u128, 12), effective_gas_price(12, 5, 10));
    try testing.expectError(error.TipAboveFeeCap, validate_fees(5, 6, 1));
    try testing.expectError(error.FeeCapBelowBaseFee, validate_fees(5, 1, 6));
    try validate_balance(300, 10, 20, 10);
    try testing.expectError(error.InsufficientBalance, validate_balance(299, 10, 20, 10));
    try validate_gas_and_tip(10, 0, true, 7, 3);
    try testing.expectError(error.InsufficientBalance, validate_gas_and_tip(9, 0, true, 7, 3));
    try testing.expectError(error.InsufficientBalance, validate_gas_and_tip(9, 2, false, 7, 3));
}

test "eip8130 tx: an EOA delegation applies after post-apply verification" {
    var database = memory_db.MemoryDatabase.init(testing.allocator);
    defer database.deinit();
    const limits = @import("evm_test.zig").test_limits;
    var state = try state_module.State.init(testing.allocator, database.interface(), limits);
    defer state.deinit(testing.allocator);
    state.begin_transaction();
    const store = Store{ .state = &state };
    const common = @import("../../common/primitives/root.zig");
    const target = common.Address.init(@splat(0x55));
    const changes = [1]eip8130.AccountChange{.{ .delegation = target }};
    var buffer: [128]u8 = undefined;
    const tx = eip8130.TxEip8130{
        .chain_id = 8453,
        .gas_limit = 100_000,
        .account_changes = eip8130.AccountChanges.build(&buffer, &changes),
    };
    const sender_auth = try eip8130.sign_sender(tx, dev_key_0);
    const signed = eip8130.Signed{ .tx = tx, .sender_auth = &sender_auth };
    const applied = try authorize_and_apply(signed, store, 8453, 1);
    try testing.expectEqualSlices(u8, &target.bytes, &applied.delegation.?.target);
    try testing.expectEqualSlices(
        u8,
        &applied.actors.sender.account,
        &applied.delegation.?.account,
    );
    const keystoreless = try authorize_without_keystore(signed);
    try testing.expectEqualSlices(
        u8,
        &applied.actors.sender.account,
        &keystoreless.actors.sender.account,
    );

    const twice = [2]eip8130.AccountChange{ .{ .delegation = target }, .{ .delegation = target } };
    var doubled = tx;
    doubled.account_changes = eip8130.AccountChanges.build(&buffer, &twice);
    const doubled_auth = try eip8130.sign_sender(doubled, dev_key_0);
    const doubled_signed = eip8130.Signed{ .tx = doubled, .sender_auth = &doubled_auth };
    try testing.expectError(
        error.MultipleDelegations,
        authorize_and_apply(doubled_signed, store, 8453, 1),
    );

    var account_state = try store.account_state(applied.actors.sender.account);
    account_state.flags = eip8130.flag_locked;
    try store.set_account_state(applied.actors.sender.account, account_state);
    try testing.expectError(error.AccountIsLocked, authorize_and_apply(signed, store, 8453, 1));
}

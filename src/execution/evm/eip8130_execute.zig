//! Enshrined EIP-8130 (account-abstraction) transaction execution, mirroring base/base
//! `crates/common/evm/src/eip8130.rs` (`Eip8130Executor::execute`).
//!
//! The pre-call pipeline runs outside any call frame, against the journal and without
//! gas metering (the EIP-8130 intrinsic schedule is the only charge for it):
//!   1. authorize the sender and payer and apply the account changes (config batches,
//!      account creation, delegation), installing the deferred code effects;
//!   2. validate and consume the nonce (protocol, 2D channel, or nonce-free replay id);
//!   3. price the intrinsic gas, then check the EIP-7825 cap, fee caps, and payer balance;
//!   4. publish the transaction context (sender, payer, actor id) in transient storage.
//! The payer is then charged the worst case up front, and the `calls` phases run as real
//! frames from one gas pool. A phase commits atomically; the first reverting phase is
//! rolled back and ends execution, but the transaction is still included. Settlement
//! refunds the unused pre-charge and pays the base fee, priority fee, L1 fee, and
//! operator fee vaults.
//!
//! Any pre-call failure rejects the transaction: every state change is discarded.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const op = @import("op.zig");
const gas = @import("gas.zig");
const native = @import("native.zig");
const bytecode = @import("bytecode.zig");
const config = @import("eip8130_config.zig");
const apply = @import("eip8130_apply.zig");
const tx_module = @import("eip8130_tx.zig");
const nonce = @import("eip8130_nonce.zig");
const Fork = @import("fork.zig").Fork;
const eip8130 = @import("../../common/consensus/eip8130.zig");
const eip8130_gas = @import("../../common/consensus/eip8130_gas.zig");
const common_primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Evm = evm_module.Evm;
const State = state_module.State;
const TxEnv = transaction.TxEnv;

/// `BaseTime` predeploy; storage slot 0 packs the block's millisecond part at bytes 30-31.
pub const base_time_address: Address = blk: {
    var address: Address = @splat(0);
    address[0] = 0x42;
    address[19] = 0x30;
    break :blk address;
};
/// EIP-7825 per-transaction gas cap, applied to `gas_limit + payer_floor`.
pub const tx_gas_limit_cap = transaction.tx_gas_limit_cap;
/// `ActorPolicyViolation(bytes32 actorId, address target)`.
pub const selector_actor_policy_violation = [4]u8{ 0x1f, 0x1c, 0x0d, 0x27 };
const refund_quotient_max: u64 = 5;

pub const Rejection = error{
    NotActive,
    ChainIdMismatch,
    NotYetValid,
    Expired,
    NonceKeyOutOfScope,
    GasLimitBelowFloor,
    GasLimitBelowIntrinsic,
    GasCapExceeded,
    InvalidContextIdentity,
    SettlementExceedsPrecharge,
};

pub const Error = Rejection || tx_module.Error || tx_module.FeeError || nonce.Error ||
    eip8130_gas.Error || evm_module.Error;

/// The pre-call pipeline's result: who pays, the intrinsic gas split, and the price.
pub const Outcome = struct {
    sender: Address,
    payer: Address,
    sender_actor_id: B256,
    policy_gated: bool,
    policy_target: Address,
    gas_limit: u64,
    sender_intrinsic: u64,
    sender_floor: u64,
    payer_floor: u64,
    payer_auth_cost: u64,
    execution_gas_available: u64,
    effective_gas_price: u128,
    base_fee: u128,
    bump_protocol_nonce: bool,

    /// Gas billed for `sender_gas` of sender-side work: the standard charge (plus payer
    /// authentication), floored by the EIP-7623 sender and payer floors.
    pub fn metered_gas(outcome: *const Outcome, sender_gas: u64) u64 {
        const standard = sender_gas +| outcome.payer_auth_cost;
        const floor = outcome.sender_floor +| outcome.payer_floor;
        return @max(standard, floor);
    }

    /// Worst-case chargeable gas, the basis of the pre-charge and the EIP-7825 cap.
    pub fn max_chargeable_gas(outcome: *const Outcome) u64 {
        return outcome.gas_limit +| outcome.payer_floor;
    }
};

pub const CallsResult = struct {
    call_gas_spent: u64 = 0,
    refund: i64 = 0,
    reverted: bool = false,
    output: []const u8 = &.{},
    committed_phases: u64 = 0,
};

/// Fatal failures propagate; every other failure rejects the transaction.
fn fatal(err: Error) ?evm_module.Error {
    return switch (err) {
        error.DatabaseFailure => error.DatabaseFailure,
        error.StateFull => error.StateFull,
        error.CodeArenaFull => error.CodeArenaFull,
        else => null,
    };
}

const checkpoint_zero = state_module.Checkpoint{
    .journal_len = 0,
    .logs_len = 0,
    .log_data_len = 0,
};

pub fn transact(
    comptime fork: Fork,
    evm: *Evm,
    tx: *const TxEnv,
) evm_module.Error!transaction.Result {
    const executed = execute(fork, evm, tx) catch |err| {
        if (fatal(err)) |failure| return failure;
        return .{ .invalid = .eip8130_rejected };
    };
    return .{ .executed = executed };
}

/// Run one EIP-8130 transaction. On error the transaction's state changes are discarded.
pub fn execute(comptime fork: Fork, evm: *Evm, tx: *const TxEnv) Error!transaction.Executed {
    assert(tx.tx_type == .eip8130);
    const signed = tx.eip8130 orelse return error.NotActive;
    const context = evm.block.op orelse return error.NotActive;
    if (!context.upgrade.at_least(.everest)) return error.NotActive;
    if (signed.tx.chain_id != evm.config.chain_id) return error.ChainIdMismatch;
    evm.state.begin_transaction();
    errdefer evm.state.revert(checkpoint_zero);
    const now_ms = try timestamp_ms(evm.state, evm.block.timestamp);
    const outcome = try pre_call(evm, signed, tx.envelope, now_ms, context.upgrade);
    const params = try op.load_params(evm.state, context.rules());
    const max_gas = outcome.max_chargeable_gas();
    const fees = op.Fees.compute(params, context.rules(), tx.envelope, max_gas);
    const prepaid = try prepay(evm, &outcome, &fees);
    try warm_pre_call_accounts(fork, evm, &outcome);
    const pool = outcome.execution_gas_available;
    const calls = try execute_calls(fork, evm, signed, &outcome, pool);
    const gas_used = try settle(evm, &outcome, &calls, prepaid, &fees, tx.envelope);
    const logs = evm.state.transaction_logs();
    evm.state.finalize_transaction(fork);
    return .{
        .status = if (calls.reverted) .revert else .success,
        .exit = if (calls.reverted) .revert else .return_,
        .gas_used = gas_used,
        .gas_refunded = 0,
        .output = calls.output,
        .created = null,
        .logs = logs,
        .committed_phases = calls.committed_phases,
    };
}

/// Block time in milliseconds: seconds plus `BaseTime`'s millisecond part, read without
/// warming the slot (Everest implies Denim, so the block's system call already ran).
pub fn timestamp_ms(state: *State, timestamp: u64) state_module.Error!u64 {
    const word = try state.storage_value(base_time_address, 0);
    const millis_part: u16 = @truncate(word);
    return timestamp *% 1000 +% millis_part;
}

fn pre_call(
    evm: *Evm,
    signed: *const eip8130.Signed,
    encoded: []const u8,
    now_ms: u64,
    upgrade: op.Upgrade,
) Error!Outcome {
    const tx = &signed.tx;
    const valid_after = tx.valid_after_ms();
    const valid_before = tx.valid_before_ms();
    if (valid_after != 0 and now_ms < valid_after) return error.NotYetValid;
    if (valid_before != 0 and now_ms > valid_before) return error.Expired;
    const store = config.Store{ .state = evm.state };
    const applied = if (upgrade.at_least(.zenith))
        try tx_module.authorize_and_apply(signed.*, store, evm.config.chain_id, evm.block.timestamp)
    else
        try tx_module.authorize_without_keystore(signed.*);
    const actor = applied.actors.sender.resolved;
    const sender = applied.actors.sender.account;
    const payer = if (applied.actors.payer) |authorized| authorized.account else sender;
    if (!actor.can_use_nonce_key(tx.nonce_key)) return error.NonceKeyOutOfScope;
    if (applied.created) |created| try apply.deploy_created(evm.state, created);
    if (applied.delegation) |delegation| {
        try apply.install_delegation(evm.state, delegation.account, delegation.target);
    }
    const nonce_use = try consume_nonce(evm.state, tx, sender, now_ms);
    const intrinsic = try intrinsic_gas(signed, encoded, .{
        .sender = .init(sender),
        .nonce_key_first_use = nonce_use.first_use,
        .sender_policy_gated = actor.is_policy_gated(),
        .revoke_discount_slots = applied.revoke_discount_slots,
    });
    var outcome = Outcome{
        .sender = sender,
        .payer = payer,
        .sender_actor_id = actor.actor_id,
        .policy_gated = actor.is_policy_gated(),
        .policy_target = actor.policy_target,
        .gas_limit = tx.gas_limit,
        .sender_intrinsic = intrinsic.sender_intrinsic(),
        .sender_floor = intrinsic.sender_floor(),
        .payer_floor = intrinsic.payer_floor,
        .payer_auth_cost = intrinsic.payer_auth_cost,
        .execution_gas_available = 0,
        .effective_gas_price = 0,
        .base_fee = @intCast(evm.block.base_fee),
        .bump_protocol_nonce = nonce_use.bump_protocol,
    };
    if (tx.gas_limit < outcome.sender_floor) return error.GasLimitBelowFloor;
    outcome.execution_gas_available = intrinsic.execution_gas_available(tx.gas_limit) orelse
        return error.GasLimitBelowIntrinsic;
    try check_fees(evm.state, tx, &outcome);
    try set_context(evm.state, sender, payer, actor.actor_id);
    return outcome;
}

fn intrinsic_gas(
    signed: *const eip8130.Signed,
    encoded: []const u8,
    input: eip8130_gas.Input,
) Error!eip8130_gas.IntrinsicGas {
    const intrinsic = try eip8130_gas.compute(signed.*, encoded, input);
    assert(intrinsic.payload_floor >= intrinsic.payload);
    return intrinsic;
}

/// EIP-7825 cap, fee caps against the base fee, then the payer's worst-case balance.
fn check_fees(state: *State, tx: *const eip8130.TxEip8130, outcome: *Outcome) Error!void {
    if (outcome.max_chargeable_gas() > tx_gas_limit_cap) return error.GasCapExceeded;
    const max_fee = tx.max_fee_per_gas;
    const max_priority = tx.max_priority_fee_per_gas;
    try tx_module.validate_fees(max_fee, max_priority, outcome.base_fee);
    const payer = (try state.access(outcome.payer)).account;
    try tx_module.validate_balance(payer.info.balance, tx.gas_limit, outcome.payer_floor, max_fee);
    outcome.effective_gas_price =
        tx_module.effective_gas_price(max_fee, max_priority, outcome.base_fee);
    assert(outcome.effective_gas_price >= outcome.base_fee);
}

const NonceUse = struct { first_use: bool, bump_protocol: bool };

/// Nonce-free transactions mark their replay id; protocol-key transactions bump the
/// account nonce at prepay; 2D keys advance their channel.
fn consume_nonce(
    state: *State,
    tx: *const eip8130.TxEip8130,
    sender: Address,
    now_ms: u64,
) Error!NonceUse {
    const store = nonce.Store{ .state = state };
    const protocol_nonce = (try state.access(sender)).account.info.nonce;
    if (tx.nonce_key == eip8130.nonce_key_max) {
        _ = try nonce.validate(store, tx, sender, protocol_nonce, .inclusion, now_ms);
        const replay = tx.replay_id(common_primitives.Address.init(sender)).bytes;
        try store.check_and_mark_expiring_nonce(replay, tx.valid_before_ms(), now_ms);
        return .{ .first_use = false, .bump_protocol = false };
    }
    if (tx.nonce_key == 0) {
        _ = try nonce.validate(store, tx, sender, protocol_nonce, .inclusion, now_ms);
        return .{ .first_use = protocol_nonce == 0, .bump_protocol = true };
    }
    const current = try store.get_nonce(sender, tx.nonce_key);
    _ = try tx_module.validate_sequence(tx.nonce_sequence, current, .inclusion);
    const next = try store.increment_nonce(sender, tx.nonce_key);
    assert(next == current + 1);
    return .{ .first_use = current == 0, .bump_protocol = false };
}

/// TxContext transient slots 0-2. A zero field would read back as "unset" and fall back
/// to tx.origin, so it is rejected.
pub fn set_context(state: *State, sender: Address, payer: Address, actor_id: B256) Error!void {
    const zero_address = primitives.address_zero;
    if (std.mem.eql(u8, &sender, &zero_address)) return error.InvalidContextIdentity;
    if (std.mem.eql(u8, &payer, &zero_address)) return error.InvalidContextIdentity;
    const actor_word = primitives.b256_to_u256(actor_id);
    if (actor_word == 0) return error.InvalidContextIdentity;
    const context = native.tx_context_address;
    try state.transient_store(context, 0, primitives.address_to_u256(sender));
    try state.transient_store(context, 1, primitives.address_to_u256(payer));
    try state.transient_store(context, 2, actor_word);
}

/// Bump the protocol nonce if due and debit the payer the worst-case fee, so `calls`
/// cannot spend the reservation.
fn prepay(evm: *Evm, outcome: *const Outcome, fees: *const op.Fees) Error!u256 {
    if (outcome.bump_protocol_nonce) {
        const sender = try evm.state.load(outcome.sender);
        assert(sender.info.nonce < std.math.maxInt(u64));
        try evm.state.set_nonce(sender, sender.info.nonce + 1);
        try evm.state.touch(sender);
    }
    const gas_charge = @as(u256, outcome.max_chargeable_gas()) * outcome.effective_gas_price;
    const total = @as(u512, gas_charge) + fees.l1 + fees.operator_charge;
    const payer = try evm.state.load(outcome.payer);
    if (total > payer.info.balance) return error.InsufficientBalance;
    const prepaid: u256 = @intCast(total);
    try evm.state.set_balance(payer, payer.info.balance - prepaid);
    try evm.state.touch(payer);
    evm.tx = .{ .origin = outcome.sender, .gas_price = outcome.effective_gas_price };
    return prepaid;
}

fn warm_pre_call_accounts(comptime fork: Fork, evm: *Evm, outcome: *const Outcome) Error!void {
    try transaction.warm_system_addresses(fork, evm);
    _ = try evm.state.access(outcome.sender);
    _ = try evm.state.access(outcome.payer);
    assert(evm.state.is_warm(outcome.sender));
}

/// Run the phases from one pool of `pool` gas (at most the execution gas available).
pub fn execute_calls(
    comptime fork: Fork,
    evm: *Evm,
    signed: *const eip8130.Signed,
    outcome: *const Outcome,
    pool: u64,
) Error!CallsResult {
    assert(pool <= outcome.execution_gas_available);
    var remaining = pool;
    var result = CallsResult{};
    var phases = signed.tx.calls.iterator();
    var phase_index: u32 = 0;
    while (phases.next()) |phase| : (phase_index += 1) {
        assert(phase_index < signed.tx.calls.count);
        const checkpoint = evm.state.checkpoint();
        const phase_result = try run_phase(fork, evm, phase, outcome, &remaining);
        if (phase_result.reverted) {
            evm.state.revert(checkpoint);
            result.reverted = true;
            result.output = phase_result.output orelse &.{};
            break;
        }
        result.committed_phases += 1;
        result.refund +|= phase_result.refund;
        if (phase_result.output) |output| result.output = output;
    }
    assert(remaining <= pool);
    result.call_gas_spent = pool - remaining;
    return result;
}

const PhaseResult = struct { reverted: bool, refund: i64, output: ?[]const u8 };

fn run_phase(
    comptime fork: Fork,
    evm: *Evm,
    phase: eip8130.Phase,
    outcome: *const Outcome,
    remaining: *u64,
) Error!PhaseResult {
    var result = PhaseResult{ .reverted = false, .refund = 0, .output = null };
    var calls = phase.iterator();
    while (calls.next()) |call| {
        const to = call.to.bytes;
        if (outcome.policy_gated and !std.mem.eql(u8, &to, &outcome.policy_target)) {
            return .{ .reverted = true, .refund = 0, .output = policy_violation(evm, outcome, to) };
        }
        var charge = try root_call_access_gas(evm, to);
        if (try creates_account(evm, outcome.sender, to, call.value)) charge += gas.new_account;
        if (charge > remaining.*) return .{ .reverted = true, .refund = 0, .output = &.{} };
        remaining.* -= charge;
        const frame = try evm.execute_fork(fork, .{
            .kind = .call,
            .caller = outcome.sender,
            .target = to,
            .value = call.value,
            .input = call.data,
            .gas_limit = remaining.*,
        });
        assert(frame.gas_remaining <= remaining.*);
        // An exceptional halt consumes the whole pool, as for any frame.
        remaining.* = if (frame.status == .halt) 0 else frame.gas_remaining;
        if (frame.status != .success) {
            return .{ .reverted = true, .refund = 0, .output = frame.output };
        }
        result.refund +|= frame.gas_refund;
        result.output = frame.output;
    }
    return result;
}

/// EIP-2929 access for a root call, as a CALL would pay: the target, plus the target of
/// an EIP-7702 or EIP-8130 delegation indicator at it.
fn root_call_access_gas(evm: *Evm, to: Address) Error!u64 {
    const target = try evm.state.access(to);
    var charge: u64 = if (target.is_cold) gas.cold_account_access else gas.warm_storage_read;
    const code = try evm.state.code(target.account);
    if (bytecode.delegation_target(code)) |delegate| {
        const delegated = try evm.state.access(delegate);
        charge += if (delegated.is_cold) gas.cold_account_access else gas.warm_storage_read;
    }
    return charge;
}

/// A value transfer from `sender` that would bring an empty account into existence.
fn creates_account(evm: *Evm, sender: Address, to: Address, value: u256) Error!bool {
    if (value == 0 or std.mem.eql(u8, &to, &sender)) return false;
    const target = try evm.state.load(to);
    if (!target.info.is_empty()) return false;
    const source = try evm.state.load(sender);
    return source.info.balance >= value;
}

/// `ActorPolicyViolation(actorId, target)` revert data, written to the return buffer
/// (no frame runs after it).
fn policy_violation(evm: *Evm, outcome: *const Outcome, target: Address) []const u8 {
    const out = evm.return_buffer[0 .. 4 + 32 + 32];
    out[0..4].* = selector_actor_policy_violation;
    out[4..36].* = outcome.sender_actor_id;
    out[36..68].* = native.address_word(target);
    return out;
}

/// Billable gas: sender intrinsic plus call gas, less the refund capped at a fifth,
/// then floored and charged for payer authentication.
pub fn billable_gas(outcome: *const Outcome, calls: *const CallsResult) u64 {
    const gross = outcome.sender_intrinsic +| calls.call_gas_spent;
    const requested: u64 = if (calls.refund > 0) @intCast(calls.refund) else 0;
    const refund = @min(requested, gross / refund_quotient_max);
    assert(refund <= gross);
    return outcome.metered_gas(gross - refund);
}

/// Refund the unused pre-charge to the payer and pay the four recipients.
fn settle(
    evm: *Evm,
    outcome: *const Outcome,
    calls: *const CallsResult,
    prepaid: u256,
    fees: *const op.Fees,
    envelope: []const u8,
) Error!u64 {
    const billable = billable_gas(outcome, calls);
    const fee = @as(u256, billable) * outcome.effective_gas_price;
    const base_fee_amount = @as(u256, billable) * outcome.base_fee;
    assert(fee >= base_fee_amount);
    const rules = evm.block.op.?.rules();
    const operator = fees.operator_used(rules, envelope, billable);
    const total = @as(u512, fee) + fees.l1 + operator;
    if (total > prepaid) return error.SettlementExceedsPrecharge;
    try credit(evm, outcome.payer, prepaid - @as(u256, @intCast(total)));
    try credit(evm, op.base_fee_vault, base_fee_amount);
    try credit(evm, evm.block.coinbase, fee - base_fee_amount);
    try credit(evm, op.l1_fee_vault, fees.l1);
    try credit(evm, op.operator_fee_vault, operator);
    return billable;
}

fn credit(evm: *Evm, address: Address, amount: u256) Error!void {
    const account = try evm.state.load(address);
    try evm.state.set_balance(account, account.info.balance + amount);
    try evm.state.touch(account);
}

test {
    _ = @import("eip8130_execute_test.zig");
}

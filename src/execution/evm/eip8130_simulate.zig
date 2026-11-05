//! Read-only EIP-8130 simulation for `eth_call` / `eth_estimateGas`, mirroring base/base
//! `Eip8130Executor::simulate` (`crates/common/evm/src/eip8130.rs`).
//!
//! Like any call simulation it runs from the request's `from` without verifying a
//! signature: the sender actor is its self actor (or, with the keystore, the caller's
//! actor hint), and authentication is priced from the declared auth blob shapes. The
//! account changes still apply exactly as at inclusion, so the calls see the same state.
//! Nothing is charged and every state change is discarded.
//!
//! `call` runs the phases once at the transaction's gas limit. `estimate` returns the
//! smallest gas limit at which the calls succeed: refunds never rejoin the call pool and
//! EIP-150 forwards only 63/64 at each call, so the gross spend of one run at a large pool
//! can be too little. A bounded binary search over the call pool finds the limit.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const config = @import("eip8130_config.zig");
const apply = @import("eip8130_apply.zig");
const tx_module = @import("eip8130_tx.zig");
const nonce = @import("eip8130_nonce.zig");
const execute = @import("eip8130_execute.zig");
const Fork = @import("fork.zig").Fork;
const eip8130 = @import("../../common/consensus/eip8130.zig");
const eip8130_gas = @import("../../common/consensus/eip8130_gas.zig");
const consensus = @import("../../common/consensus/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Evm = evm_module.Evm;
const State = state_module.State;
const Outcome = execute.Outcome;
const CallsResult = execute.CallsResult;
const Error = execute.Error;

/// Payer published for an open-payer transaction whose payer signature does not recover.
pub const unsigned_open_payer: Address = blk: {
    var address: Address = @splat(0);
    address[18] = 0x81;
    address[19] = 0x30;
    break :blk address;
};
pub const pool_search_iterations_max: u32 = 16;
/// The search stops once the bracket is within 1.5% of its upper bound.
pub const pool_search_tolerance_per_mille: u64 = 15;

pub const Mode = enum { call, estimate };

pub const Request = struct {
    from: Address,
    mode: Mode,
    /// Keystore only: the actor the caller acts as (defaults to the self actor).
    actor_hint: ?B256 = null,
};

/// Valid until the state or EVM next runs: `output` and `logs` point into their buffers.
pub const Simulated = struct {
    reverted: bool,
    gas: u64,
    output: []const u8,
    logs: []const state_module.Log,
    committed_phases: u64,
};

const checkpoint_zero = state_module.Checkpoint{
    .journal_len = 0,
    .logs_len = 0,
    .log_data_len = 0,
};

pub fn simulate(
    comptime fork: Fork,
    evm: *Evm,
    tx: *const transaction.TxEnv,
    request: Request,
) Error!Simulated {
    assert(tx.tx_type == .eip8130);
    const signed = tx.eip8130 orelse return error.NotActive;
    const context = evm.block.op orelse return error.NotActive;
    if (!context.upgrade.at_least(.everest)) return error.NotActive;
    evm.state.begin_transaction();
    defer evm.state.revert(checkpoint_zero);
    const keystore = context.upgrade.at_least(.zenith);
    const outcome = try resolve(evm, signed, tx.envelope, request, keystore);
    evm.tx = .{ .origin = outcome.sender, .gas_price = outcome.effective_gas_price };
    try transaction.warm_system_addresses(fork, evm);
    _ = try evm.state.access(outcome.sender);
    _ = try evm.state.access(outcome.payer);
    const ceiling_pool = outcome.execution_gas_available;
    if (request.mode == .call) {
        const calls = try execute.execute_calls(fork, evm, signed, &outcome, ceiling_pool);
        const gross = outcome.metered_gas(outcome.sender_intrinsic +| calls.call_gas_spent);
        return finish(evm, &calls, gross);
    }
    const ceiling = try probe(fork, evm, signed, &outcome, ceiling_pool);
    if (ceiling.reverted) {
        // A failure even at the full pool is not a gas shortfall: report that run.
        const calls = try execute.execute_calls(fork, evm, signed, &outcome, ceiling_pool);
        const gross = outcome.metered_gas(outcome.sender_intrinsic +| calls.call_gas_spent);
        return finish(evm, &calls, gross);
    }
    const pool = try search_pool(fork, evm, signed, &outcome, ceiling.call_gas_spent);
    const calls = try execute.execute_calls(fork, evm, signed, &outcome, pool);
    const sender_gas = @max(outcome.sender_intrinsic +| pool, outcome.sender_floor);
    return finish(evm, &calls, sender_gas +| outcome.payer_floor);
}

fn finish(evm: *Evm, calls: *const CallsResult, gas: u64) Simulated {
    return .{
        .reverted = calls.reverted,
        .gas = gas,
        .output = calls.output,
        .logs = evm.state.transaction_logs(),
        .committed_phases = calls.committed_phases,
    };
}

/// One run of the phases at `pool`, rolled back.
fn probe(
    comptime fork: Fork,
    evm: *Evm,
    signed: *const eip8130.Signed,
    outcome: *const Outcome,
    pool: u64,
) Error!CallsResult {
    const checkpoint = evm.state.checkpoint();
    defer evm.state.revert(checkpoint);
    return execute.execute_calls(fork, evm, signed, outcome, pool);
}

/// The smallest call pool (within the tolerance) at which the calls succeed, seeded with
/// the gross spend and its 64/63 EIP-150 headroom.
fn search_pool(
    comptime fork: Fork,
    evm: *Evm,
    signed: *const eip8130.Signed,
    outcome: *const Outcome,
    ceiling_spent: u64,
) Error!u64 {
    const ceiling_pool = outcome.execution_gas_available;
    const spent = @min(ceiling_spent, ceiling_pool);
    if (spent >= ceiling_pool) return spent;
    if (!(try probe(fork, evm, signed, outcome, spent)).reverted) return spent;
    var lowest = spent;
    var highest = ceiling_pool;
    const seed = (spent *| 64) / 63;
    if (seed > lowest and seed < highest) {
        const reverted = (try probe(fork, evm, signed, outcome, seed)).reverted;
        if (reverted) lowest = seed else highest = seed;
    }
    var iterations: u32 = 0;
    while (lowest + 1 < highest and iterations < pool_search_iterations_max) : (iterations += 1) {
        const width = highest - lowest;
        if (width *| 1000 <= highest *| pool_search_tolerance_per_mille) break;
        const middle = lowest + width / 2;
        if ((try probe(fork, evm, signed, outcome, middle)).reverted) {
            lowest = middle;
        } else {
            highest = middle;
        }
    }
    assert(highest > lowest or highest == ceiling_pool);
    return highest;
}

/// Sender/payer resolution without signatures, worst-case intrinsic gas, the account
/// changes, and the transaction context.
fn resolve(
    evm: *Evm,
    signed: *const eip8130.Signed,
    encoded: []const u8,
    request: Request,
    keystore: bool,
) Error!Outcome {
    const tx = &signed.tx;
    const sender = request.from;
    const payer_auth_ceiling = try eip8130_gas.max_payer_auth_cost(signed.*);
    const gas_limit = @min(tx.gas_limit, execute.tx_gas_limit_cap -| payer_auth_ceiling);
    const resolved = signed.resolved_payer(.init(sender), consensus.recover_address);
    const payer = if (resolved) |account| account.bytes else unsigned_open_payer;
    if (!keystore) try tx_module.check_without_keystore(signed.*);
    const first_use = try nonce_key_first_use(evm.state, tx, sender);
    const input = eip8130_gas.Input.worst_case(.init(sender), first_use, keystore);
    const intrinsic = try eip8130_gas.compute(signed.*, encoded, input);
    if (gas_limit < intrinsic.sender_floor()) return error.GasLimitBelowFloor;
    const available = intrinsic.execution_gas_available(gas_limit) orelse
        return error.GasLimitBelowIntrinsic;
    const store = config.Store{ .state = evm.state };
    try apply_changes(evm.state, signed, sender, evm.block.timestamp);
    const actor_id = if (keystore)
        request.actor_hint orelse config.self_actor_id(sender)
    else
        config.self_actor_id(sender);
    var outcome = Outcome{
        .sender = sender,
        .payer = payer,
        .sender_actor_id = actor_id,
        .policy_gated = false,
        .policy_target = primitives.address_zero,
        .gas_limit = gas_limit,
        .sender_intrinsic = intrinsic.sender_intrinsic(),
        .sender_floor = intrinsic.sender_floor(),
        .payer_floor = intrinsic.payer_floor,
        .payer_auth_cost = intrinsic.payer_auth_cost,
        .execution_gas_available = available,
        .base_fee = @intCast(evm.block.base_fee),
        .effective_gas_price = 0,
        .bump_protocol_nonce = false,
    };
    outcome.effective_gas_price = tx_module.effective_gas_price(
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        outcome.base_fee,
    );
    if (keystore) {
        const scope = (try store.resolve_actor_config(sender, actor_id)).scope;
        outcome.policy_gated = eip8130.sender_is_policy_gated(scope);
        if (outcome.policy_gated) {
            outcome.policy_target = try store.policy_manager(sender, actor_id);
        }
    }
    try execute.set_context(evm.state, sender, payer, actor_id);
    return outcome;
}

fn nonce_key_first_use(state: *State, tx: *const eip8130.TxEip8130, sender: Address) Error!bool {
    if (tx.nonce_key == eip8130.nonce_key_max) return false;
    if (tx.nonce_key == 0) return (try state.access(sender)).account.info.nonce == 0;
    const store = nonce.Store{ .state = state };
    return try store.get_nonce(sender, tx.nonce_key) == 0;
}

/// The account changes in order, unauthorized, then their code effects.
fn apply_changes(
    state: *State,
    signed: *const eip8130.Signed,
    sender: Address,
    now: u64,
) Error!void {
    const store = config.Store{ .state = state };
    var created: ?apply.Created = null;
    var delegation: ?Address = null;
    var changes = signed.tx.account_changes.iterator();
    var index: u32 = 0;
    while (changes.next()) |change| : (index += 1) {
        assert(index < eip8130.max_account_changes_per_tx + eip8130.max_config_changes_per_tx);
        switch (change) {
            .create => |entry| {
                if (delegation != null) return error.CreateAndDelegation;
                if (index != 0 or created != null) return error.InvalidCreatePosition;
                created = try apply.apply_create(store, entry);
            },
            .config => |batch| {
                var current = try store.account_state(sender);
                _ = try apply.apply_config_change(store, sender, batch, &current, now);
                try store.set_account_state(sender, current);
            },
            .delegation => |target| {
                if (delegation != null) return error.MultipleDelegations;
                if (created != null) return error.CreateAndDelegation;
                delegation = target.bytes;
            },
        }
    }
    if (created) |effect| try apply.deploy_created(state, effect);
    if (delegation) |target| try apply.install_delegation(state, sender, target);
}

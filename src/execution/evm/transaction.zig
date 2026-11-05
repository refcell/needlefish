//! Transaction-level execution: validation, intrinsic gas, fee purchase and refund,
//! access-list warming, EIP-7702 authorizations, beneficiary payment, finalization.
//!
//! `TxEnv` is the EVM's own flat view of a transaction (like revm's `TxEnv`); the node
//! converts consensus envelopes into it after recovering signers.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const gas = @import("gas.zig");
const env = @import("env.zig");
const bytecode = @import("bytecode.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const precompiles = @import("precompiles.zig");
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;
const B256 = primitives.B256;
const Evm = evm_module.Evm;

pub const TxType = enum(u8) {
    legacy = 0,
    eip2930 = 1,
    eip1559 = 2,
    eip4844 = 3,
    eip7702 = 4,
    deposit = 0x7e,
};

pub const AccessListItem = struct {
    address: Address,
    storage_keys: []const B256 = &.{},
};

pub const Authorization = struct {
    chain_id: u256,
    address: Address,
    nonce: u64,
    /// Recovered signer, or null when the signature is invalid.
    authority: ?Address,
};

pub const TxEnv = struct {
    tx_type: TxType = .legacy,
    caller: Address,
    gas_limit: u64,
    /// Legacy/EIP-2930 gas price, or EIP-1559 max fee per gas.
    gas_price: u256 = 0,
    /// EIP-1559 max priority fee per gas; null for legacy pricing.
    gas_priority_fee: ?u256 = null,
    /// Callee; null creates a contract.
    to: ?Address = null,
    value: u256 = 0,
    data: []const u8 = &.{},
    nonce: u64 = 0,
    chain_id: ?u64 = null,
    access_list: []const AccessListItem = &.{},
    blob_hashes: []const B256 = &.{},
    max_fee_per_blob_gas: u256 = 0,
    authorization_list: []const Authorization = &.{},
};

pub const Invalid = enum {
    type_not_supported,
    gas_limit_too_high,
    gas_cap_exceeded,
    chain_id_mismatch,
    fee_below_base_fee,
    priority_fee_above_max_fee,
    initcode_too_large,
    intrinsic_gas_too_low,
    floor_gas_too_low,
    sender_has_code,
    nonce_too_low,
    nonce_too_high,
    nonce_overflow,
    insufficient_funds,
    blob_create,
    blob_empty,
    blob_too_many,
    blob_version,
    blob_fee_too_low,
    authorization_empty,
    authorization_create,
};

pub const Executed = struct {
    status: evm_module.Status,
    exit: evm_module.Exit,
    gas_used: u64,
    /// Refund applied (after the cap).
    gas_refunded: u64,
    output: []const u8,
    created: ?Address,
    logs: []const state_module.Log,
};

pub const Result = union(enum) {
    invalid: Invalid,
    executed: Executed,
};

pub const blob_version_kzg: u8 = 0x01;
/// EIP-7825 (Osaka): per-transaction gas limit cap.
pub const tx_gas_limit_cap: u64 = 1 << 24;

pub fn blobs_per_tx_max(comptime fork: Fork) u64 {
    if (fork.at_least(.osaka)) return 6;
    if (fork.at_least(.prague)) return 9;
    return 6;
}

pub const Intrinsic = struct { gas: u64, floor: u64 };

pub fn intrinsic_gas(comptime fork: Fork, tx: *const TxEnv) Intrinsic {
    var zero_bytes: u64 = 0;
    for (tx.data) |b| zero_bytes += @intFromBool(b == 0);
    const nonzero_bytes: u64 = tx.data.len - zero_bytes;
    var total: u64 = gas.tx_base;
    total += zero_bytes * gas.tx_data_zero + nonzero_bytes * gas.tx_data_nonzero(fork);
    if (tx.to == null) {
        if (fork.at_least(.homestead)) total += gas.tx_create;
        if (fork.at_least(.shanghai)) total += gas.initcode_cost(tx.data.len);
    }
    for (tx.access_list) |item| {
        total += gas.access_list_address;
        total += gas.access_list_storage_key * @as(u64, item.storage_keys.len);
    }
    total += gas.per_empty_account * @as(u64, tx.authorization_list.len);
    var floor: u64 = 0;
    if (fork.at_least(.prague)) {
        const tokens = zero_bytes + nonzero_bytes * gas.floor_tokens_per_nonzero_byte;
        floor = gas.tx_base + gas.total_cost_floor_per_token * tokens;
    }
    return .{ .gas = total, .floor = floor };
}

pub fn effective_gas_price(tx: *const TxEnv, base_fee: u256) u256 {
    const priority = tx.gas_priority_fee orelse return tx.gas_price;
    return @min(tx.gas_price, base_fee + priority);
}

fn type_supported(comptime fork: Fork, tx_type: TxType) bool {
    return switch (tx_type) {
        .legacy => true,
        .eip2930 => fork.at_least(.berlin),
        .eip1559 => fork.at_least(.london),
        .eip4844 => fork.at_least(.cancun),
        .eip7702 => fork.at_least(.prague),
        .deposit => false,
    };
}

/// Checks that need no state.
fn validate_env(comptime fork: Fork, evm: *const Evm, tx: *const TxEnv) ?Invalid {
    if (!type_supported(fork, tx.tx_type)) return .type_not_supported;
    if (fork.at_least(.osaka) and tx.gas_limit > tx_gas_limit_cap) return .gas_cap_exceeded;
    if (tx.chain_id) |chain_id| {
        if (chain_id != evm.config.chain_id) return .chain_id_mismatch;
    }
    if (tx.gas_limit > evm.block.gas_limit) return .gas_limit_too_high;
    if (tx.gas_priority_fee) |priority| {
        if (priority > tx.gas_price) return .priority_fee_above_max_fee;
    }
    if (fork.at_least(.london) and tx.gas_price < evm.block.base_fee) return .fee_below_base_fee;
    if (fork.at_least(.shanghai) and tx.to == null) {
        if (tx.data.len > evm.config.initcode_size_max) return .initcode_too_large;
    }
    if (tx.tx_type == .eip4844) {
        if (validate_blobs(fork, evm, tx)) |invalid| return invalid;
    }
    if (tx.tx_type == .eip7702) {
        if (tx.to == null) return .authorization_create;
        if (tx.authorization_list.len == 0) return .authorization_empty;
    }
    const intrinsic = intrinsic_gas(fork, tx);
    if (intrinsic.gas > tx.gas_limit) return .intrinsic_gas_too_low;
    if (intrinsic.floor > tx.gas_limit) return .floor_gas_too_low;
    return null;
}

fn validate_blobs(comptime fork: Fork, evm: *const Evm, tx: *const TxEnv) ?Invalid {
    if (tx.to == null) return .blob_create;
    if (tx.blob_hashes.len == 0) return .blob_empty;
    if (tx.blob_hashes.len > blobs_per_tx_max(fork)) return .blob_too_many;
    for (tx.blob_hashes) |hash| {
        if (hash[0] != blob_version_kzg) return .blob_version;
    }
    if (tx.max_fee_per_blob_gas < evm.block.blob_base_fee) return .blob_fee_too_low;
    return null;
}

fn blob_gas(tx: *const TxEnv) u64 {
    return gas.blob_gas_per_blob * @as(u64, tx.blob_hashes.len);
}

/// Checks against the sender account, then buys gas and bumps the nonce.
fn validate_and_buy_gas(
    comptime fork: Fork,
    evm: *Evm,
    tx: *const TxEnv,
) state_module.Error!?Invalid {
    const sender = try evm.state.load(tx.caller);
    if (sender.info.has_code()) {
        const code = try evm.state.code(sender);
        const delegated = fork.at_least(.prague) and bytecode.delegation_target(code) != null;
        if (!delegated) return .sender_has_code;
    }
    if (sender.info.nonce == std.math.maxInt(u64)) return .nonce_overflow;
    if (tx.nonce < sender.info.nonce) return .nonce_too_low;
    if (tx.nonce > sender.info.nonce) return .nonce_too_high;
    const max_cost = @as(u512, tx.gas_limit) * tx.gas_price + tx.value +
        @as(u512, blob_gas(tx)) * tx.max_fee_per_blob_gas;
    if (max_cost > sender.info.balance) return .insufficient_funds;
    const price = effective_gas_price(tx, evm.block.base_fee);
    const upfront = @as(u256, tx.gas_limit) * price + blob_gas(tx) * evm.block.blob_base_fee;
    try evm.state.set_balance(sender, sender.info.balance - upfront);
    if (tx.to != null) try evm.state.set_nonce(sender, sender.info.nonce + 1);
    try evm.state.touch(sender);
    return null;
}

fn warm_addresses(comptime fork: Fork, evm: *Evm, tx: *const TxEnv) state_module.Error!void {
    if (!fork.at_least(.berlin)) return;
    _ = try evm.state.access(tx.caller);
    if (tx.to) |to| _ = try evm.state.access(to);
    if (fork.at_least(.shanghai)) _ = try evm.state.access(evm.block.coinbase);
    var number: u64 = 1;
    while (number <= 0x11) : (number += 1) {
        const address = primitives.address_from_int(number);
        if (precompiles.is_precompile(fork, address)) _ = try evm.state.access(address);
    }
    const p256 = primitives.address_from_int(0x100);
    if (precompiles.is_precompile(fork, p256)) _ = try evm.state.access(p256);
    for (tx.access_list) |item| {
        const access = try evm.state.access(item.address);
        for (item.storage_keys) |key| {
            _ = try evm.state.storage_access(access.account, primitives.b256_to_u256(key));
        }
    }
}

/// EIP-7702: apply valid authorizations. Returns the refund for existing authorities.
fn apply_authorizations(evm: *Evm, tx: *const TxEnv) state_module.Error!u64 {
    var refund: u64 = 0;
    for (tx.authorization_list) |auth| {
        if (auth.chain_id != 0 and auth.chain_id != evm.config.chain_id) continue;
        if (auth.nonce == std.math.maxInt(u64)) continue;
        const authority_address = auth.authority orelse continue;
        const access = try evm.state.access(authority_address);
        const authority = access.account;
        const code = try evm.state.code(authority);
        if (code.len != 0 and bytecode.delegation_target(code) == null) continue;
        if (authority.info.nonce != auth.nonce) continue;
        if (!authority.info.is_empty() or authority.in_database) {
            refund += gas.per_empty_account - gas.per_auth_base;
        }
        if (std.mem.eql(u8, &auth.address, &primitives.address_zero)) {
            try evm.state.set_code_unjournaled(authority, &.{});
        } else {
            var designator: [bytecode.delegation_len]u8 = undefined;
            designator[0..3].* = bytecode.delegation_prefix;
            designator[3..23].* = auth.address;
            try evm.state.set_code_unjournaled(authority, &designator);
        }
        try evm.state.set_nonce(authority, authority.info.nonce + 1);
        try evm.state.touch(authority);
    }
    return refund;
}

/// Validate and execute one transaction against the current block state.
pub fn transact(evm: *Evm, fork: Fork, tx: *const TxEnv) evm_module.Error!Result {
    return switch (fork) {
        inline else => |comptime_fork| transact_fork(comptime_fork, evm, tx),
    };
}

pub fn transact_fork(comptime fork: Fork, evm: *Evm, tx: *const TxEnv) evm_module.Error!Result {
    if (validate_env(fork, evm, tx)) |invalid| return .{ .invalid = invalid };
    evm.state.begin_transaction();
    if (try validate_and_buy_gas(fork, evm, tx)) |invalid| {
        evm.state.revert(.{ .journal_len = 0, .logs_len = 0, .log_data_len = 0 });
        return .{ .invalid = invalid };
    }
    evm.tx = .{
        .origin = tx.caller,
        .gas_price = effective_gas_price(tx, evm.block.base_fee),
        .blob_hashes = tx.blob_hashes,
    };
    try warm_addresses(fork, evm, tx);
    var authorization_refund: u64 = 0;
    if (fork.at_least(.prague)) authorization_refund = try apply_authorizations(evm, tx);
    const intrinsic = intrinsic_gas(fork, tx);
    const outcome = try evm.execute_fork(fork, .{
        .kind = if (tx.to == null) .create else .call,
        .caller = tx.caller,
        .target = tx.to orelse primitives.address_zero,
        .value = tx.value,
        .input = tx.data,
        .gas_limit = tx.gas_limit - intrinsic.gas,
    });
    return .{ .executed = try settle(fork, evm, tx, outcome, intrinsic, authorization_refund) };
}

/// Apply refunds, the calldata floor, the sender reimbursement, and the tip.
fn settle(
    comptime fork: Fork,
    evm: *Evm,
    tx: *const TxEnv,
    outcome: evm_module.Outcome,
    intrinsic: Intrinsic,
    authorization_refund: u64,
) evm_module.Error!Executed {
    assert(outcome.gas_remaining <= tx.gas_limit - intrinsic.gas);
    const gas_spent = tx.gas_limit - outcome.gas_remaining;
    const refund_counter: i64 = outcome.gas_refund + @as(i64, @intCast(authorization_refund));
    const refund_requested: u64 = if (refund_counter > 0) @intCast(refund_counter) else 0;
    const refund = @min(refund_requested, gas_spent / gas.max_refund_quotient(fork));
    var gas_used = gas_spent - refund;
    if (fork.at_least(.prague)) gas_used = @max(gas_used, intrinsic.floor);
    assert(gas_used <= tx.gas_limit);
    const price = effective_gas_price(tx, evm.block.base_fee);
    const sender = try evm.state.load(tx.caller);
    const reimbursement = @as(u256, tx.gas_limit - gas_used) * price;
    try evm.state.set_balance(sender, sender.info.balance + reimbursement);
    const tip_per_gas = if (fork.at_least(.london)) price - evm.block.base_fee else price;
    const coinbase = try evm.state.load(evm.block.coinbase);
    try evm.state.set_balance(coinbase, coinbase.info.balance + @as(u256, gas_used) * tip_per_gas);
    try evm.state.touch(coinbase);
    const logs = evm.state.transaction_logs();
    evm.state.finalize_transaction(fork);
    return .{
        .status = outcome.status,
        .exit = outcome.exit,
        .gas_used = gas_used,
        .gas_refunded = refund,
        .output = outcome.output,
        .created = outcome.created,
        .logs = logs,
    };
}

test "transaction: intrinsic gas" {
    const tx = TxEnv{
        .caller = primitives.address_zero,
        .gas_limit = 100_000,
        .to = primitives.address_from_int(1),
        .data = &.{ 0, 1, 0, 2 },
    };
    try std.testing.expectEqual(@as(u64, 21000 + 8 + 32), intrinsic_gas(.cancun, &tx).gas);
    try std.testing.expectEqual(@as(u64, 21000 + 8 + 136), intrinsic_gas(.byzantium, &tx).gas);
    try std.testing.expectEqual(@as(u64, 21000 + 10 * (2 + 8)), intrinsic_gas(.prague, &tx).floor);
    var create = tx;
    create.to = null;
    const shanghai = intrinsic_gas(.shanghai, &create).gas;
    try std.testing.expectEqual(@as(u64, 21000 + 40 + 32000 + 2), shanghai);
    try std.testing.expectEqual(@as(u64, 21000 + 8 + 136), intrinsic_gas(.frontier, &create).gas);
}

//! Gas schedule. Every function takes `comptime fork` so costs fold to constants.
//!
//! Convention for EIP-2929 (Berlin+): the static cost of BALANCE, EXT*, SLOAD, and the
//! CALL family is the *warm* cost; a cold access adds `cold_*_extra`. Every
//! out-of-gas halt consumes all frame gas, so charging order never changes results.

const std = @import("std");
const assert = std.debug.assert;
const Fork = @import("fork.zig").Fork;
const op = @import("opcode.zig");

pub const zero = 0;
pub const base = 2;
pub const very_low = 3;
pub const low = 5;
pub const mid = 8;
pub const high = 10;
pub const jumpdest = 1;
pub const keccak256_word = 6;
pub const copy_word = 3;
pub const log = 375;
pub const log_topic = 375;
pub const log_data_byte = 8;
pub const create = 32000;
pub const call_value = 9000;
pub const call_stipend = 2300;
pub const new_account = 25000;
pub const memory_word = 3;
pub const memory_quadratic_divisor = 512;
pub const warm_storage_read = 100;
pub const cold_sload = 2100;
pub const cold_account_access = 2600;
pub const cold_sload_extra = cold_sload - warm_storage_read;
pub const cold_account_access_extra = cold_account_access - warm_storage_read;
pub const sstore_set = 20000;
pub const sstore_reset_legacy = 5000;
pub const selfdestruct_refund_legacy = 24000;
pub const code_deposit_byte = 200;
pub const initcode_word = 2;
pub const transient = warm_storage_read;
pub const tx_base = 21000;
pub const tx_create = 32000;
pub const tx_data_zero = 4;
pub const access_list_address = 2400;
pub const access_list_storage_key = 1900;
/// EIP-7702: cost per authorization tuple and refund when the authority already exists.
pub const per_empty_account = 25000;
pub const per_auth_base = 12500;
/// EIP-7623 calldata floor: tokens per non-zero byte, floor cost per token.
pub const floor_tokens_per_nonzero_byte = 4;
pub const total_cost_floor_per_token = 10;
/// EIP-4844: gas per blob.
pub const blob_gas_per_blob = 1 << 17;

comptime {
    assert(cold_sload_extra == 2000);
    assert(cold_account_access_extra == 2500);
}

pub fn tx_data_nonzero(comptime fork: Fork) u64 {
    return if (fork.at_least(.istanbul)) 16 else 68;
}

/// Static gas charged before an opcode executes.
pub fn static_cost(comptime fork: Fork, comptime opcode: u8) u64 {
    return switch (opcode) {
        op.STOP, op.RETURN, op.REVERT, op.INVALID, op.SSTORE => zero,
        op.ADD, op.SUB, op.LT, op.GT, op.SLT, op.SGT, op.EQ, op.ISZERO => very_low,
        op.AND, op.OR, op.XOR, op.NOT, op.BYTE, op.SHL, op.SHR, op.SAR => very_low,
        op.CALLDATALOAD, op.MLOAD, op.MSTORE, op.MSTORE8, op.CALLDATACOPY => very_low,
        op.CODECOPY, op.RETURNDATACOPY, op.MCOPY, op.BLOBHASH => very_low,
        op.PUSH1...op.PUSH32, op.DUP1...op.DUP16, op.SWAP1...op.SWAP16 => very_low,
        op.MUL, op.DIV, op.SDIV, op.MOD, op.SMOD, op.SIGNEXTEND, op.SELFBALANCE => low,
        op.CLZ => low,
        op.ADDMOD, op.MULMOD, op.JUMP => mid,
        op.EXP, op.JUMPI => high,
        op.JUMPDEST => jumpdest,
        op.KECCAK256 => 30,
        op.ADDRESS, op.ORIGIN, op.CALLER, op.CALLVALUE, op.CALLDATASIZE => base,
        op.CODESIZE, op.GASPRICE, op.RETURNDATASIZE, op.COINBASE, op.TIMESTAMP => base,
        op.NUMBER, op.PREVRANDAO, op.GASLIMIT, op.CHAINID, op.BASEFEE => base,
        op.BLOBBASEFEE, op.POP, op.PC, op.MSIZE, op.GAS, op.PUSH0 => base,
        op.BLOCKHASH => 20,
        op.BALANCE => account_read(fork, 20, 400, 700),
        op.EXTCODESIZE, op.EXTCODECOPY => account_read(fork, 20, 700, 700),
        op.EXTCODEHASH => account_read(fork, 400, 400, 700),
        op.SLOAD => account_read(fork, 50, 200, 800),
        op.TLOAD, op.TSTORE => transient,
        op.LOG0...op.LOG4 => log + log_topic * @as(u64, opcode - op.LOG0),
        op.CREATE, op.CREATE2 => create,
        op.CALL, op.CALLCODE, op.DELEGATECALL, op.STATICCALL => account_read(fork, 40, 700, 700),
        op.SELFDESTRUCT => if (fork.at_least(.tangerine)) 5000 else 0,
        else => zero,
    };
}

/// Frontier / Tangerine / Istanbul cost, or the warm cost from Berlin on.
fn account_read(comptime fork: Fork, frontier: u64, tangerine: u64, istanbul: u64) u64 {
    if (fork.at_least(.berlin)) return warm_storage_read;
    if (fork.at_least(.istanbul)) return istanbul;
    if (fork.at_least(.tangerine)) return tangerine;
    return frontier;
}

/// Total memory cost for `words` 32-byte words: 3w + w²/512.
pub fn memory_cost(words: u64) u64 {
    assert(words <= max_memory_words);
    return memory_word * words + (words * words) / memory_quadratic_divisor;
}

/// Larger than any reachable memory: its cost exceeds 2^45 gas.
pub const max_memory_words: u64 = 1 << 32;

pub fn words_for(size_bytes: u64) u64 {
    assert(size_bytes <= std.math.maxInt(u64) - 31);
    return (size_bytes + 31) / 32;
}

/// Per-word cost for copy-style operations.
pub fn copy_cost(size_bytes: u64) u64 {
    return copy_word * words_for(size_bytes);
}

pub fn exp_byte(comptime fork: Fork) u64 {
    return if (fork.at_least(.spurious_dragon)) 50 else 10;
}

pub fn exp_cost(comptime fork: Fork, exponent: u256) u64 {
    const bits: u64 = 256 - @as(u64, @clz(exponent));
    return high + exp_byte(fork) * ((bits + 7) / 8);
}

/// EIP-3860 (Shanghai): cost per word of init code.
pub fn initcode_cost(size_bytes: u64) u64 {
    return initcode_word * words_for(size_bytes);
}

/// EIP-150: all but one 64th of the remaining gas.
pub fn all_but_one_64th(gas: u64) u64 {
    return gas - gas / 64;
}

/// EIP-3529 (London) lowered the refund cap from 1/2 to 1/5 of gas used.
pub fn max_refund_quotient(comptime fork: Fork) u64 {
    return if (fork.at_least(.london)) 5 else 2;
}

pub fn selfdestruct_refund(comptime fork: Fork) i64 {
    return if (fork.at_least(.london)) 0 else selfdestruct_refund_legacy;
}

/// Cost and refund delta of SSTORE, given original (tx start), current, and new values.
pub const SstoreCost = struct { cost: u64, refund: i64 };

pub fn sstore(
    comptime fork: Fork,
    original: u256,
    current: u256,
    new: u256,
    is_cold: bool,
) SstoreCost {
    if (fork.at_least(.istanbul) or fork == .constantinople) {
        var result = sstore_net_metered(fork, original, current, new);
        if (fork.at_least(.berlin) and is_cold) result.cost += cold_sload;
        return result;
    }
    // Frontier through Byzantium and Petersburg: set 20000, otherwise 5000.
    const refund: i64 = if (current != 0 and new == 0) 15000 else 0;
    const cost: u64 = if (current == 0 and new != 0) sstore_set else sstore_reset_legacy;
    return .{ .cost = cost, .refund = refund };
}

/// EIP-1283 (Constantinople), EIP-2200 (Istanbul), EIP-2929 and EIP-3529 variants.
fn sstore_net_metered(comptime fork: Fork, original: u256, current: u256, new: u256) SstoreCost {
    const sload_cost: u64 = if (fork.at_least(.berlin))
        warm_storage_read
    else if (fork.at_least(.istanbul)) 800 else 200;
    const reset_cost: u64 = if (fork.at_least(.berlin)) 5000 - cold_sload else 5000;
    const clear_refund: i64 = if (fork.at_least(.london)) 4800 else 15000;
    if (current == new) return .{ .cost = sload_cost, .refund = 0 };
    if (original == current) {
        if (original == 0) return .{ .cost = sstore_set, .refund = 0 };
        const refund: i64 = if (new == 0) clear_refund else 0;
        return .{ .cost = reset_cost, .refund = refund };
    }
    var refund: i64 = 0;
    if (original != 0) {
        if (current == 0) refund -= clear_refund;
        if (new == 0) refund += clear_refund;
    }
    if (original == new) {
        const restore: i64 = if (original == 0) sstore_set else @intCast(reset_cost);
        refund += restore - @as(i64, @intCast(sload_cost));
    }
    return .{ .cost = sload_cost, .refund = refund };
}

/// EIP-2200: SSTORE fails if gas left is at or below the call stipend.
pub fn sstore_requires_stipend(comptime fork: Fork) bool {
    return fork.at_least(.istanbul);
}

test "gas: static costs by fork" {
    try std.testing.expectEqual(@as(u64, 3), static_cost(.osaka, op.ADD));
    try std.testing.expectEqual(@as(u64, 50), static_cost(.frontier, op.SLOAD));
    try std.testing.expectEqual(@as(u64, 800), static_cost(.istanbul, op.SLOAD));
    try std.testing.expectEqual(@as(u64, 100), static_cost(.berlin, op.SLOAD));
    try std.testing.expectEqual(@as(u64, 700), static_cost(.tangerine, op.CALL));
    try std.testing.expectEqual(@as(u64, 375 + 4 * 375), static_cost(.osaka, op.LOG4));
}

test "gas: memory and exp" {
    try std.testing.expectEqual(@as(u64, 0), memory_cost(0));
    try std.testing.expectEqual(@as(u64, 3), memory_cost(1));
    try std.testing.expectEqual(@as(u64, 3 * 1024 + 2048), memory_cost(1024));
    try std.testing.expectEqual(@as(u64, 10), exp_cost(.osaka, 0));
    try std.testing.expectEqual(@as(u64, 60), exp_cost(.osaka, 0xff));
    try std.testing.expectEqual(@as(u64, 10 + 50 * 32), exp_cost(.osaka, std.math.maxInt(u256)));
    try std.testing.expectEqual(@as(u64, 30), exp_cost(.frontier, 0x100));
}

test "gas: sstore EIP-2200 and EIP-3529 table" {
    // (original, current, new) -> cost, refund for London, from the EIP-3529 test table.
    const cases = [_]struct { u256, u256, u256, u64, i64 }{
        .{ 0, 0, 0, 100, 0 },     .{ 0, 0, 1, 20000, 0 },  .{ 0, 1, 0, 100, 19900 },
        .{ 0, 1, 2, 100, 0 },     .{ 0, 1, 1, 100, 0 },    .{ 1, 1, 0, 2900, 4800 },
        .{ 1, 1, 2, 2900, 0 },    .{ 1, 0, 0, 100, 0 },    .{ 1, 0, 1, 100, -4800 + 2800 },
        .{ 1, 0, 2, 100, -4800 }, .{ 1, 2, 0, 100, 4800 }, .{ 1, 2, 1, 100, 2800 },
    };
    for (cases) |c| {
        const result = sstore(.london, c[0], c[1], c[2], false);
        try std.testing.expectEqual(c[3], result.cost);
        try std.testing.expectEqual(c[4], result.refund);
    }
    const cold = sstore(.london, 0, 0, 1, true);
    try std.testing.expectEqual(@as(u64, 22100), cold.cost);
    const legacy = sstore(.byzantium, 1, 1, 0, false);
    try std.testing.expectEqual(@as(u64, 5000), legacy.cost);
    try std.testing.expectEqual(@as(i64, 15000), legacy.refund);
}

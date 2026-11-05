//! OP Stack / Base transaction semantics on top of the Ethereum handler: L1 data fee and
//! operator fee inputs read from the L1Block predeploy, and fee vault addresses.
//!
//! Mirrors base/base `crates/common/evm/src/l1block.rs` and `handler.rs`. The fee math
//! itself lives in `common.l1_fees`; this file only reads its inputs from state.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const l1_fees = @import("../../common/l1_fees/root.zig");
const Address = primitives.Address;
const State = state_module.State;

pub const Rules = l1_fees.Rules;
pub const L1FeeParams = l1_fees.L1FeeParams;

const hex = primitives.hex_to_address;
pub const l1_block_address = hex("4200000000000000000000000000000000000015");
pub const sequencer_fee_vault = hex("4200000000000000000000000000000000000011");
pub const base_fee_vault = hex("4200000000000000000000000000000000000019");
pub const l1_fee_vault = hex("420000000000000000000000000000000000001a");
pub const operator_fee_vault = hex("420000000000000000000000000000000000001b");

/// L1Block storage layout.
pub const slot_l1_base_fee: u256 = 1;
pub const slot_ecotone_scalars: u256 = 3;
pub const slot_overhead: u256 = 5;
pub const slot_scalar: u256 = 6;
pub const slot_blob_base_fee: u256 = 7;
pub const slot_operator_fee: u256 = 8;

/// Byte offsets inside the packed 32-byte big-endian storage words.
const base_fee_scalar_offset = 16;
const blob_base_fee_scalar_offset = 20;
const da_footprint_scalar_offset = 18;
const operator_fee_scalar_offset = 20;
const operator_fee_constant_offset = 24;

/// Per-block OP context; null on `BlockEnv.op` means plain Ethereum semantics.
pub const Context = struct {
    rules: Rules,
};

fn word_field(word: u256, comptime offset: usize, comptime T: type) T {
    const size = @sizeOf(T);
    comptime assert(offset + size <= 32);
    const shift = (32 - offset - size) * 8;
    return @truncate(word >> shift);
}

/// Read the L1 fee parameters from L1Block storage as of the current state.
pub fn load_params(state: *State, rules: Rules) state_module.Error!L1FeeParams {
    var params = L1FeeParams{
        .l1_base_fee = try state.storage_value(l1_block_address, slot_l1_base_fee),
    };
    if (!rules.at_least(.ecotone)) {
        params.l1_base_fee_scalar = try state.storage_value(l1_block_address, slot_scalar);
        params.l1_fee_overhead = try state.storage_value(l1_block_address, slot_overhead);
        return params;
    }
    params.l1_blob_base_fee = try state.storage_value(l1_block_address, slot_blob_base_fee);
    const scalars = try state.storage_value(l1_block_address, slot_ecotone_scalars);
    const base_scalar = word_field(scalars, base_fee_scalar_offset, u32);
    const blob_scalar = word_field(scalars, blob_base_fee_scalar_offset, u32);
    params.l1_base_fee_scalar = base_scalar;
    params.l1_blob_base_fee_scalar = blob_scalar;
    params.empty_ecotone_scalars = params.l1_blob_base_fee.? == 0 and
        base_scalar == 0 and blob_scalar == 0;
    if (params.empty_ecotone_scalars) {
        params.l1_fee_overhead = try state.storage_value(l1_block_address, slot_overhead);
    }
    if (rules.at_least(.isthmus)) {
        const operator = try state.storage_value(l1_block_address, slot_operator_fee);
        params.operator_fee_scalar = word_field(operator, operator_fee_scalar_offset, u32);
        params.operator_fee_constant = word_field(operator, operator_fee_constant_offset, u64);
        if (rules.at_least(.jovian)) {
            params.da_footprint_gas_scalar = word_field(operator, da_footprint_scalar_offset, u16);
        }
    }
    assert(rules.at_least(.isthmus) == (params.operator_fee_scalar != null));
    return params;
}

/// Fees a non-deposit transaction owes on top of execution gas.
pub const Fees = struct {
    params: L1FeeParams,
    l1: u256,
    /// Operator fee on the full gas limit, charged upfront.
    operator_charge: u256,

    pub fn compute(
        params: L1FeeParams,
        rules: Rules,
        envelope: []const u8,
        gas_limit: u64,
    ) Fees {
        const operator = if (rules.at_least(.isthmus))
            params.operator_fee_charge(envelope, gas_limit, rules)
        else
            0;
        return .{
            .params = params,
            .l1 = params.tx_l1_cost(envelope, rules),
            .operator_charge = operator,
        };
    }

    /// Operator fee for the gas actually used (credited to the operator vault).
    pub fn operator_used(fees: *const Fees, rules: Rules, envelope: []const u8, used: u64) u256 {
        if (!rules.at_least(.isthmus)) return 0;
        const fee = fees.params.operator_fee_charge(envelope, used, rules);
        assert(fee <= fees.operator_charge);
        return fee;
    }
};

const testing = std.testing;

test "op: word fields" {
    const word: u256 = (@as(u256, 0xaabbccdd) << (8 * 12)) | (@as(u256, 0x11223344) << (8 * 8));
    try testing.expectEqual(@as(u32, 0xaabbccdd), word_field(word, 16, u32));
    try testing.expectEqual(@as(u32, 0x11223344), word_field(word, 20, u32));
    try testing.expectEqual(@as(u16, 0), word_field(word, 30, u16));
}

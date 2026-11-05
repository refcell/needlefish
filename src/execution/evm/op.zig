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

/// Base / OP Stack upgrades that change execution, in activation order (base/base
/// `BaseUpgrade`). Azul and later run on the Osaka execution fork.
pub const Upgrade = enum(u8) {
    bedrock,
    regolith,
    canyon,
    ecotone,
    fjord,
    granite,
    holocene,
    isthmus,
    jovian,
    azul,
    beryl,
    cobalt,
    denim,
    everest,

    pub fn at_least(upgrade: Upgrade, other: Upgrade) bool {
        return @backingInt(upgrade) >= @backingInt(other);
    }

    /// The L1 fee rule set in force.
    pub fn rules(upgrade: Upgrade) Rules {
        if (upgrade.at_least(.jovian)) return .jovian;
        if (upgrade.at_least(.isthmus)) return .isthmus;
        if (upgrade.at_least(.fjord)) return .fjord;
        if (upgrade.at_least(.ecotone)) return .ecotone;
        if (upgrade.at_least(.regolith)) return .regolith;
        return .bedrock;
    }
};

/// Per-block OP context; null on `BlockEnv.op` means plain Ethereum semantics.
pub const Context = struct {
    upgrade: Upgrade,

    pub fn rules(context: Context) Rules {
        return context.upgrade.rules();
    }
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

/// Canyon: CREATE2 deployer force-deployed on the activation block (base/base `canyon.rs`).
pub const create2_deployer = hex("13b0d85ccb8bf860b6b79af3029fca081ae9bef2");
pub const create2_deployer_code: [1584]u8 = decode_hex(&create2_deployer_hex);
const create2_deployer_hex = [_][]const u8{
    "6080604052600436106100435760003560e01c8063076c37b21461004f578063481286e61461007157806356",
    "299481146100ba57806366cfa057146100da57600080fd5b3661004a57005b600080fd5b34801561005b5760",
    "0080fd5b5061006f61006a366004610327565b6100fa565b005b34801561007d57600080fd5b506100916100",
    "8c366004610327565b61014a565b60405173ffffffffffffffffffffffffffffffffffffffff909116815260",
    "200160405180910390f35b3480156100c657600080fd5b506100916100d5366004610349565b61015d565b34",
    "80156100e657600080fd5b5061006f6100f53660046103ca565b610172565b61014582826040518060200161",
    "010f9061031a565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0828203",
    "81018352601f90910116604052610183565b505050565b600061015683836102e7565b9392505050565b6000",
    "61016a8484846102f0565b949350505050565b61017d838383610183565b50505050565b6000834710156101",
    "f4576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004",
    "820152601d60248201527f437265617465323a20696e73756666696369656e742062616c616e636500000060",
    "448201526064015b60405180910390fd5b815160000361025f576040517f08c379a000000000000000000000",
    "000000000000000000000000000000000000815260206004820181905260248201527f437265617465323a20",
    "62797465636f6465206c656e677468206973207a65726f60448201526064016101eb565b8282516020840186",
    "f5905073ffffffffffffffffffffffffffffffffffffffff8116610156576040517f08c379a0000000000000",
    "00000000000000000000000000000000000000000000815260206004820152601960248201527f4372656174",
    "65323a204661696c6564206f6e206465706c6f790000000000000060448201526064016101eb565b60006101",
    "568383305b6000604051836040820152846020820152828152600b8101905060ff8153605590209493505050",
    "50565b61014e806104ad83390190565b6000806040838503121561033a57600080fd5b505080359260209091",
    "01359150565b60008060006060848603121561035e57600080fd5b8335925060208401359150604084013573",
    "ffffffffffffffffffffffffffffffffffffffff8116811461039057600080fd5b809150509250925092565b",
    "7f4e487b71000000000000000000000000000000000000000000000000000000006000526041600452602460",
    "00fd5b6000806000606084860312156103df57600080fd5b8335925060208401359150604084013567ffffff",
    "ffffffffff8082111561040557600080fd5b818601915086601f83011261041957600080fd5b813581811115",
    "61042b5761042b61039b565b604051601f82017fffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffe0908116603f011681019083821181831017156104715761047161039b565b816040528281",
    "5289602084870101111561048a57600080fd5b82602086016020830137600060208483010152809550505050",
    "5050925092509256fe608060405234801561001057600080fd5b5061012e806100206000396000f3fe608060",
    "4052348015600f57600080fd5b506004361060285760003560e01c8063249cb3fa14602d575b600080fd5b60",
    "3c603836600460b1565b604e565b60405190815260200160405180910390f35b600082815260208181526040",
    "80832073ffffffffffffffffffffffffffffffffffffffff8516845290915281205460ff16608857600060aa",
    "565b7fa2ef4600d742022d532d4747cb3547474667d6f13804902513b2ec01c848f4b45b9392505050565b60",
    "00806040838503121560c357600080fd5b82359150602083013573ffffffffffffffffffffffffffffffffff",
    "ffffff8116811460ed57600080fd5b80915050925092905056fea26469706673582212205ffd4e6cede7d06a",
    "5daf93d48d0541fc68189eeb16608c1999a82063b666eb1164736f6c63430008130033a26469706673582212",
    "20fdc4a0fe96e3b21c108ca155438d37c9143fb01278a3c1d274948bad89c564ba64736f6c63430008130033",
};

/// Cobalt 2D nonce manager; Everest plants a one-byte stub so EIP-161 never deletes it.
pub const nonce_manager = hex("813000000000000000000000000000000000aa01");
const system_account_stub = [_]u8{0xef};

fn decode_hex(comptime chunks: []const []const u8) [hex_length(chunks) / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [hex_length(chunks) / 2]u8 = undefined;
    var offset: usize = 0;
    for (chunks) |chunk| {
        // Proof: comptime literals of even length and valid hex digits.
        _ = std.fmt.hexToBytes(out[offset..][0 .. chunk.len / 2], chunk) catch unreachable;
        offset += chunk.len / 2;
    }
    return out;
}

fn hex_length(comptime chunks: []const []const u8) usize {
    var total: usize = 0;
    for (chunks) |chunk| total += chunk.len;
    return total;
}

/// Irregular state transition run before the first transaction of a block. The caller
/// decides activation (the block executor owns the fork schedule).
pub const Transition = enum { canyon_create2_deployer, everest_nonce_manager };

pub fn apply_transition(state: *State, transition: Transition) state_module.Error!void {
    state.begin_transaction();
    switch (transition) {
        .canyon_create2_deployer => {
            const account = try state.load(create2_deployer);
            try state.set_code(account, &create2_deployer_code);
            try state.touch(account);
        },
        .everest_nonce_manager => {
            const account = try state.load(nonce_manager);
            // Existing code is never overwritten.
            if (!account.info.has_code()) {
                try state.set_code(account, &system_account_stub);
                try state.touch(account);
            }
        },
    }
    assert(state.transaction_logs().len == 0);
    state.finalize_transaction(.cancun);
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

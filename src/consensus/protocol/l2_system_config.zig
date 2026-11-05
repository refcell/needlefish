//! The system config in effect for an L2 block, recovered from the block itself (base/base
//! `crates/consensus/protocol/src/utils.rs` `to_system_config`): batcher, overhead and
//! scalar from the L1 info deposit, gas limit from the header, EIP-1559 parameters from
//! `extraData` (Holocene: version 0, 9 bytes; Jovian: version 1, 17 bytes with the minimum
//! base fee), operator fee from the deposit (Isthmus), and the DA footprint gas scalar
//! (Jovian deposit format). The genesis block takes the rollup genesis system config.

const std = @import("std");
const assert = std.debug.assert;

const basefee = @import("../../execution/chainspec/basefee.zig");
const l1_info = @import("l1_info.zig");
const rollup_config = @import("rollup_config.zig");
const SystemConfig = @import("system_config.zig").SystemConfig;
const B256 = @import("../../common/primitives/root.zig").B256;

const L1BlockInfo = l1_info.L1BlockInfo;
const RollupConfig = rollup_config.RollupConfig;

pub const Error = error{
    InvalidGenesisHash,
    MissingSystemConfigGenesis,
    InvalidExtraData,
};

/// The block fields `to_system_config` reads.
pub const BlockFields = struct {
    number: u64,
    hash: B256,
    timestamp: u64,
    gas_limit: u64,
    extra_data: []const u8,
};

/// Genesis system config when `block` is the L2 genesis block, else null.
pub fn genesis_system_config(rollup: *const RollupConfig, block: BlockFields) Error!?SystemConfig {
    if (block.number != rollup.genesis.l2.number) return null;
    if (!block.hash.eql(rollup.genesis.l2.hash)) return error.InvalidGenesisHash;
    const config = rollup.genesis.system_config orelse return error.MissingSystemConfigGenesis;
    assert(block.number == rollup.genesis.l2.number);
    return config;
}

/// Ecotone-style scalar word: version 1, blob base fee scalar, base fee scalar.
pub fn encode_scalar(blob_base_fee_scalar: u32, base_fee_scalar: u32) u256 {
    var word: [32]u8 = @splat(0);
    word[0] = 0x01;
    std.mem.writeInt(u32, word[24..28], blob_base_fee_scalar, .big);
    std.mem.writeInt(u32, word[28..32], base_fee_scalar, .big);
    const scalar = std.mem.readInt(u256, &word, .big);
    assert(scalar >> 248 == 1);
    return scalar;
}

/// The system config for a non-genesis block whose first transaction carries `info`.
pub fn from_l1_info(
    rollup: *const RollupConfig,
    info: *const L1BlockInfo,
    block: BlockFields,
) Error!SystemConfig {
    assert(block.number != rollup.genesis.l2.number or !block.hash.eql(rollup.genesis.l2.hash));
    const bedrock = info.format == .bedrock;
    var config: SystemConfig = .{
        .batcher_address = info.batcher_address,
        .overhead = if (bedrock) info.l1_fee_overhead else 0,
        .scalar = if (bedrock)
            info.l1_fee_scalar
        else
            encode_scalar(info.blob_base_fee_scalar, info.base_fee_scalar),
        .gas_limit = block.gas_limit,
    };
    if (rollup.is_feature_active(.min_base_fee, block.timestamp)) {
        const params = basefee.decode_jovian(block.extra_data) catch
            return error.InvalidExtraData;
        config.eip1559_denominator = params.denominator;
        config.eip1559_elasticity = params.elasticity;
        config.min_base_fee = params.min_base_fee;
    } else if (rollup.is_feature_active(.dynamic_base_fee_parameters, block.timestamp)) {
        const params = basefee.decode_holocene(block.extra_data) catch
            return error.InvalidExtraData;
        config.eip1559_denominator = params.denominator;
        config.eip1559_elasticity = params.elasticity;
    }
    if (rollup.is_feature_active(.operator_fee, block.timestamp)) {
        config.operator_fee_scalar = info.operator_fee_scalar;
        config.operator_fee_constant = info.operator_fee_constant;
    }
    if (info.format == .jovian) config.da_footprint_gas_scalar = info.da_footprint_gas_scalar;
    assert(config.gas_limit == block.gas_limit);
    return config;
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "l2 system config: genesis and per-fork fields" {
    var rollup: RollupConfig = .{ .block_time = 2 };
    rollup.genesis.l2 = .{ .number = 0, .hash = .init(@splat(1)) };
    const genesis_block: BlockFields = .{
        .number = 0,
        .hash = .init(@splat(1)),
        .timestamp = 0,
        .gas_limit = 1,
        .extra_data = "",
    };
    try testing.expectError(error.MissingSystemConfigGenesis, genesis_system_config(
        &rollup,
        genesis_block,
    ));
    rollup.genesis.system_config = .{ .gas_limit = 77 };
    const genesis_config = (try genesis_system_config(&rollup, genesis_block)).?;
    try testing.expectEqual(@as(u64, 77), genesis_config.gas_limit);
    var other = genesis_block;
    other.hash = .init(@splat(2));
    try testing.expectError(error.InvalidGenesisHash, genesis_system_config(&rollup, other));
    other.number = 5;
    try testing.expectEqual(@as(?SystemConfig, null), try genesis_system_config(&rollup, other));

    const info: L1BlockInfo = .{
        .format = .jovian,
        .batcher_address = .init(@splat(0xba)),
        .blob_base_fee_scalar = 7,
        .base_fee_scalar = 9,
        .operator_fee_scalar = 3,
        .operator_fee_constant = 4,
        .da_footprint_gas_scalar = 400,
    };
    const jovian_extra = [_]u8{ 1, 0, 0, 0, 250, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 100 };
    other.extra_data = &jovian_extra;
    other.gas_limit = 30_000_000;
    rollup.upgrades.set(.jovian, 0);
    const config = try from_l1_info(&rollup, &info, other);
    try testing.expectEqual(encode_scalar(7, 9), config.scalar);
    try testing.expectEqual(@as(?u32, 250), config.eip1559_denominator);
    try testing.expectEqual(@as(?u32, 6), config.eip1559_elasticity);
    try testing.expectEqual(@as(?u64, 100), config.min_base_fee);
    try testing.expectEqual(@as(?u32, 3), config.operator_fee_scalar);
    try testing.expectEqual(@as(?u16, 400), config.da_footprint_gas_scalar);
    try testing.expect(config.batcher_address.eql(info.batcher_address));
    // Holocene extra data under Jovian is rejected.
    other.extra_data = jovian_extra[0..9];
    try testing.expectError(error.InvalidExtraData, from_l1_info(&rollup, &info, other));
    // Pre-Holocene: extra data ignored, no EIP-1559 or operator fields.
    rollup.upgrades = .{};
    const bedrock_info: L1BlockInfo = .{
        .format = .bedrock,
        .l1_fee_overhead = 5,
        .l1_fee_scalar = 6,
    };
    const bedrock = try from_l1_info(&rollup, &bedrock_info, other);
    try testing.expectEqual(@as(u256, 5), bedrock.overhead);
    try testing.expectEqual(@as(u256, 6), bedrock.scalar);
    try testing.expectEqual(@as(?u32, null), bedrock.eip1559_denominator);
    try testing.expectEqual(@as(?u32, null), bedrock.operator_fee_scalar);
}

test "l2 system config: seeded fuzz, scalar round trip and no crashes" {
    var prng = Prng.init(0x4c325343);
    var extra: [32]u8 = undefined;
    for (0..2000) |_| {
        const blob_scalar = prng.int(u32);
        const base_scalar = prng.int(u32);
        const scalar = encode_scalar(blob_scalar, base_scalar);
        try testing.expectEqual(@as(u32, @truncate(scalar)), base_scalar);
        try testing.expectEqual(@as(u32, @truncate(scalar >> 32)), blob_scalar);
        var rollup: RollupConfig = .{ .block_time = 2 };
        if (prng.chance(1, 2)) rollup.upgrades.set(.holocene, prng.below(10));
        if (prng.chance(1, 3)) rollup.upgrades.set(.jovian, prng.below(10));
        prng.fill(&extra);
        const length = prng.below(extra.len + 1);
        if (length > 0 and prng.chance(1, 2)) extra[0] = @intCast(prng.below(2));
        const info: L1BlockInfo = .{ .format = .ecotone };
        const block: BlockFields = .{
            .number = 1 + prng.below(100),
            .hash = .init(@splat(9)),
            .timestamp = prng.below(20),
            .gas_limit = prng.int(u64),
            .extra_data = extra[0..length],
        };
        const config = from_l1_info(&rollup, &info, block) catch |err| {
            try testing.expectEqual(error.InvalidExtraData, err);
            continue;
        };
        try testing.expectEqual(block.gas_limit, config.gas_limit);
    }
}

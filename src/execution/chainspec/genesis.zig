//! ChainSpec from a geth-style genesis `config` object (the `--chain` file). OP chains
//! (Bedrock/Regolith keys present) run in L2 mode with their upgrade schedule; others
//! run as post-merge Ethereum (L1 mode). Blob schedules use the standard Cancun/Prague
//! parameters (the genesis parser does not read `blobSchedule` yet).

const std = @import("std");
const assert = std.debug.assert;
const genesis = @import("../../common/genesis/root.zig");
const root = @import("root.zig");

const ChainSpec = root.ChainSpec;
const BaseFeeParams = root.BaseFeeParams;

pub const Error = error{ PreMergeGenesis, InvalidForkOrder, InvalidBaseFeeParams };

pub fn from_genesis(parsed: *const genesis.Genesis) Error!ChainSpec {
    const config = parsed.config;
    if (config.london_block != 0) return error.PreMergeGenesis;
    var spec: ChainSpec = .{
        .chain_id = config.chain_id,
        .mode = if (config.is_optimism()) .l2 else .l1,
        .base_fee_params = BaseFeeParams.ethereum,
        .base_fee_params_canyon = BaseFeeParams.ethereum,
        .gas_limit = if (parsed.gas_limit > 0) parsed.gas_limit else 30_000_000,
        .genesis_base_fee = parsed.base_fee_per_gas orelse genesis.initial_base_fee,
    };
    switch (spec.mode) {
        .l1 => {
            const forks = &spec.ethereum_forks;
            forks[@backingInt(root.EthereumFork.shanghai)] = config.shanghai_time;
            forks[@backingInt(root.EthereumFork.cancun)] = config.cancun_time;
            forks[@backingInt(root.EthereumFork.prague)] = config.prague_time;
            forks[@backingInt(root.EthereumFork.osaka)] = config.osaka_time;
        },
        .l2 => try set_upgrades(&spec, config),
    }
    try spec.validate();
    assert(spec.chain_id == config.chain_id);
    assert(spec.gas_limit > 0);
    return spec;
}

fn set_upgrades(spec: *ChainSpec, config: genesis.Config) Error!void {
    const upgrades = &spec.upgrades;
    const pairs = .{
        .{ root.Upgrade.regolith, config.regolith_time },
        .{ root.Upgrade.canyon, config.canyon_time },
        .{ root.Upgrade.delta, config.delta_time },
        .{ root.Upgrade.ecotone, config.ecotone_time },
        .{ root.Upgrade.fjord, config.fjord_time },
        .{ root.Upgrade.granite, config.granite_time },
        .{ root.Upgrade.holocene, config.holocene_time },
        .{ root.Upgrade.isthmus, config.isthmus_time },
        .{ root.Upgrade.jovian, config.jovian_time },
    };
    inline for (pairs) |pair| upgrades[@backingInt(pair[0])] = pair[1];
    const elasticity = config.eip1559_elasticity orelse 6;
    const denominator = config.eip1559_denominator orelse 50;
    const denominator_canyon = config.eip1559_denominator_canyon orelse denominator;
    if (elasticity == 0 or denominator == 0 or denominator_canyon == 0) {
        return error.InvalidBaseFeeParams;
    }
    spec.base_fee_params = BaseFeeParams.init(denominator, elasticity);
    spec.base_fee_params_canyon = BaseFeeParams.init(denominator_canyon, elasticity);
}

const testing = std.testing;

test "chainspec: from L1 and L2 genesis configs" {
    var l1: genesis.Genesis = .{
        .config = .{
            .chain_id = 900,
            .london_block = 0,
            .shanghai_time = 0,
            .cancun_time = 0,
            .prague_time = 0,
        },
        .gas_limit = 60_000_000,
    };
    const l1_spec = try from_genesis(&l1);
    try testing.expectEqual(root.Mode.l1, l1_spec.mode);
    try testing.expectEqual(root.Spec.prague, l1_spec.spec_at(0));
    try testing.expect(l1_spec.blob_params_at(0) != null);
    try testing.expectEqual(@as(u64, 60_000_000), l1_spec.gas_limit);
    const l2: genesis.Genesis = .{ .config = .{
        .chain_id = 901,
        .london_block = 0,
        .bedrock_block = 0,
        .regolith_time = 0,
        .canyon_time = 0,
        .delta_time = 0,
        .ecotone_time = 0,
        .fjord_time = 0,
        .granite_time = 0,
        .holocene_time = 0,
        .isthmus_time = 0,
        .eip1559_elasticity = 6,
        .eip1559_denominator = 50,
        .eip1559_denominator_canyon = 250,
    } };
    const l2_spec = try from_genesis(&l2);
    try testing.expectEqual(root.Mode.l2, l2_spec.mode);
    try testing.expectEqual(root.Spec.prague, l2_spec.spec_at(0));
    try testing.expect(l2_spec.blob_params_at(0) == null);
    try testing.expectEqual(@as(u64, 250), l2_spec.base_fee_params_at(0).max_change_denominator);
    l1.config.london_block = null;
    try testing.expectError(error.PreMergeGenesis, from_genesis(&l1));
}

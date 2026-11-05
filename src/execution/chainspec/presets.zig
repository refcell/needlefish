//! Built-in chain specs. Timestamps and parameters come from the public base/base
//! `crates/common/chains/src/config.rs`.

const root = @import("root.zig");
const ChainSpec = root.ChainSpec;
const BaseFeeParams = root.BaseFeeParams;

/// Base upgrades in `root.Upgrade` order.
fn upgrades(values: [15]?u64) root.UpgradeSchedule {
    return values;
}

pub const base_mainnet: ChainSpec = .{
    .chain_id = 8453,
    .mode = .l2,
    .upgrades = upgrades(.{
        1_686_789_347, // regolith
        1_704_992_401, // canyon
        1_708_560_000, // delta
        1_710_374_401, // ecotone
        1_720_627_201, // fjord
        1_726_070_401, // granite
        1_736_445_601, // holocene
        null, // pectra blob schedule (not scheduled on mainnet)
        1_746_806_401, // isthmus
        1_764_691_201, // jovian
        1_779_991_200, // azul
        1_782_410_400, // beryl
        1_790_791_200, // cobalt
        1_793_901_600, // denim
        null, // everest
    }),
    .base_fee_params = .{ .max_change_denominator = 50, .elasticity_multiplier = 6 },
    .base_fee_params_canyon = .{ .max_change_denominator = 250, .elasticity_multiplier = 6 },
    .gas_limit = 30_000_000,
};

pub const base_sepolia: ChainSpec = .{
    .chain_id = 84532,
    .mode = .l2,
    .upgrades = upgrades(.{
        1_695_768_288, // regolith
        1_699_981_200, // canyon
        1_703_203_200, // delta
        1_708_534_800, // ecotone
        1_716_998_400, // fjord
        1_723_478_400, // granite
        1_732_633_200, // holocene
        1_742_486_400, // pectra blob schedule
        1_744_905_600, // isthmus
        1_763_568_001, // jovian
        1_776_708_000, // azul
        1_781_805_600, // beryl
        1_790_186_400, // cobalt
        1_792_605_600, // denim
        null, // everest
    }),
    .base_fee_params = .{ .max_change_denominator = 50, .elasticity_multiplier = 10 },
    .base_fee_params_canyon = .{ .max_change_denominator = 250, .elasticity_multiplier = 10 },
    .gas_limit = 25_000_000,
};

/// Local devnet L2: every upgrade through Azul active at genesis.
pub const base_devnet: ChainSpec = .{
    .chain_id = 84538453,
    .mode = .l2,
    .upgrades = upgrades(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, null }),
    .base_fee_params = .{ .max_change_denominator = 50, .elasticity_multiplier = 6 },
    .base_fee_params_canyon = .{ .max_change_denominator = 250, .elasticity_multiplier = 6 },
    .gas_limit = 30_000_000,
};

/// `--dev-l1` chain: Shanghai, Cancun and Prague at genesis. Osaka stays off by default
/// because it requires EIP-7594 cell-proof blob sidecars from the batcher.
pub const l1_dev: ChainSpec = .{
    .chain_id = 1337,
    .mode = .l1,
    .ethereum_forks = .{ 0, 0, 0, null, null, null },
    .base_fee_params = BaseFeeParams.ethereum,
    .base_fee_params_canyon = BaseFeeParams.ethereum,
    .gas_limit = 30_000_000,
};

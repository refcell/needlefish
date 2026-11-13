//! Rollup configuration and network upgrade (hardfork) activation.
//!
//! OP Stack upgrades cascade: an active later upgrade implies every earlier one from
//! Regolith through Jovian. Base-specific upgrades (Azul onward) and the Pectra blob
//! schedule activate independently. Mirrors base/base `crates/common/genesis/src/rollup.rs`,
//! `chain/upgrade.rs`, `feature.rs` and `schedule.rs`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const BlockId = @import("block.zig").BlockId;
const SystemConfig = @import("system_config.zig").SystemConfig;
const genesis_feature = @import("../../common/genesis/feature.zig");

/// Network upgrades in activation order; OP Stack upgrades cascade through `implied_by`.
pub const Upgrade = genesis_feature.Upgrade;
/// Protocol features and the upgrade that activates each (`BaseFeature`).
pub const Feature = genesis_feature.BaseFeature;

/// Activation timestamps per upgrade; null means never. Bedrock is block-activated.
pub const UpgradeConfig = struct {
    timestamps: [Upgrade.count]?u64 = @splat(null),

    pub fn get(config: *const UpgradeConfig, upgrade: Upgrade) ?u64 {
        if (upgrade == .bedrock) return null;
        return config.timestamps[@backingInt(upgrade)];
    }

    pub fn set(config: *UpgradeConfig, upgrade: Upgrade, timestamp: ?u64) void {
        assert(upgrade != .bedrock);
        config.timestamps[@backingInt(upgrade)] = timestamp;
    }

    fn from(pairs: []const struct { Upgrade, u64 }) UpgradeConfig {
        var config: UpgradeConfig = .{};
        for (pairs) |pair| config.set(pair[0], pair[1]);
        return config;
    }

    pub const base_mainnet: UpgradeConfig = .from(&.{
        .{ .regolith, 1_686_789_347 }, .{ .canyon, 1_704_992_401 },
        .{ .delta, 1_708_560_000 },    .{ .ecotone, 1_710_374_401 },
        .{ .fjord, 1_720_627_201 },    .{ .granite, 1_726_070_401 },
        .{ .holocene, 1_736_445_601 }, .{ .isthmus, 1_746_806_401 },
        .{ .jovian, 1_764_691_201 },   .{ .azul, 1_779_991_200 },
        .{ .beryl, 1_782_410_400 },    .{ .cobalt, 1_790_791_200 },
        .{ .denim, 1_793_901_600 },
    });

    pub const base_sepolia: UpgradeConfig = .from(&.{
        .{ .regolith, 1_695_768_288 }, .{ .canyon, 1_699_981_200 },
        .{ .delta, 1_703_203_200 },    .{ .ecotone, 1_708_534_800 },
        .{ .fjord, 1_716_998_400 },    .{ .granite, 1_723_478_400 },
        .{ .holocene, 1_732_633_200 }, .{ .pectra_blob_schedule, 1_742_486_400 },
        .{ .isthmus, 1_744_905_600 },  .{ .jovian, 1_763_568_001 },
        .{ .azul, 1_776_708_000 },     .{ .beryl, 1_781_805_600 },
        .{ .cobalt, 1_790_186_400 },   .{ .denim, 1_792_605_600 },
    });

    pub fn for_chain_id(chain_id: u64) ?UpgradeConfig {
        return switch (chain_id) {
            8453 => base_mainnet,
            84532 => base_sepolia,
            else => null,
        };
    }
};

/// Genesis anchor of the rollup (`ChainGenesis`).
pub const ChainGenesis = struct {
    l1: BlockId = .{},
    l2: BlockId = .{},
    l2_time: u64 = 0,
    system_config: ?SystemConfig = null,
};

/// Timestamps for chains that switch to 200 ms blocks at Denim.
pub const DenimTimestampSchedule = struct {
    genesis_block_number: u64,
    genesis_timestamp: u64,
    legacy_block_interval: u64,
    denim_activation_timestamp: u64,

    pub const denim_block_interval_ms: u64 = 200;

    pub fn denim_activation_block_number(schedule: DenimTimestampSchedule) u64 {
        assert(schedule.legacy_block_interval > 0);
        const elapsed = schedule.denim_activation_timestamp -| schedule.genesis_timestamp;
        return std.math.divCeil(u64, elapsed, schedule.legacy_block_interval) catch unreachable;
    }

    pub fn block_timestamp_ms(schedule: DenimTimestampSchedule, block_number: u64) u64 {
        const blocks = block_number -| schedule.genesis_block_number;
        const activation_block = schedule.denim_activation_block_number();
        if (blocks < activation_block) {
            const elapsed = blocks *| schedule.legacy_block_interval;
            const seconds = schedule.genesis_timestamp +| elapsed;
            return seconds *| 1_000;
        }
        const activation_seconds = schedule.genesis_timestamp +|
            (activation_block *| schedule.legacy_block_interval);
        const result = (activation_seconds *| 1_000) +|
            ((blocks - activation_block) *| denim_block_interval_ms);
        assert(result >= schedule.genesis_timestamp *| 1_000);
        return result;
    }
};

pub const RollupConfig = struct {
    genesis: ChainGenesis = .{},
    block_time: u64 = 0,
    max_sequencer_drift: u64 = 0,
    seq_window_size: u64 = 0,
    channel_timeout: u64 = 0,
    granite_channel_timeout: u64 = granite_channel_timeout_default,
    l1_chain_id: u64 = 0,
    l2_chain_id: u64 = 0,
    upgrades: UpgradeConfig = .{},
    batch_inbox_address: Address = .zero,
    deposit_contract_address: Address = .zero,
    l1_system_config_address: Address = .zero,
    protocol_versions_address: Address = .zero,
    blobs_enabled_l1_timestamp: ?u64 = null,

    pub const max_rlp_bytes_per_channel_bedrock: u64 = 10_000_000;
    pub const max_rlp_bytes_per_channel_fjord: u64 = 100_000_000;
    pub const fjord_max_sequencer_drift: u64 = 1800;
    pub const denim_max_sequencer_drift: u64 = 6 * 60 * 60;
    pub const granite_channel_timeout_default: u64 = 50;

    /// True when `upgrade` is active at `timestamp`, following the OP cascade.
    pub fn is_active(config: *const RollupConfig, upgrade: Upgrade, timestamp: u64) bool {
        if (upgrade == .bedrock) return true;
        var current: ?Upgrade = upgrade;
        // The cascade chain is at most `Upgrade.count` long.
        for (0..Upgrade.count) |_| {
            const step = current orelse return false;
            if (config.upgrades.get(step)) |activation| {
                if (timestamp >= activation) return true;
            }
            current = step.implied_by();
        } else unreachable; // Proof: implied_by strictly increases the enum value.
    }

    /// True when `timestamp` is the first block of `upgrade` relative to its parent.
    pub fn is_first_block(
        config: *const RollupConfig,
        upgrade: Upgrade,
        timestamp: u64,
        parent_timestamp: u64,
    ) bool {
        return config.is_active(upgrade, timestamp) and
            !config.is_active(upgrade, parent_timestamp);
    }

    pub fn is_feature_active(config: *const RollupConfig, feature: Feature, timestamp: u64) bool {
        return config.is_active(feature.activation_upgrade(), timestamp);
    }

    pub fn is_feature_first_block(
        config: *const RollupConfig,
        feature: Feature,
        timestamp: u64,
        parent_timestamp: u64,
    ) bool {
        return config.is_first_block(feature.activation_upgrade(), timestamp, parent_timestamp);
    }

    pub fn max_sequencer_drift_at(config: *const RollupConfig, timestamp: u64) u64 {
        if (config.is_feature_active(.extended_sequencer_drift, timestamp)) {
            return denim_max_sequencer_drift;
        }
        if (config.is_feature_active(.fixed_sequencer_drift, timestamp)) {
            return fjord_max_sequencer_drift;
        }
        return config.max_sequencer_drift;
    }

    pub fn max_rlp_bytes_per_channel(config: *const RollupConfig, timestamp: u64) u64 {
        if (config.is_feature_active(.large_channels, timestamp)) {
            return max_rlp_bytes_per_channel_fjord;
        }
        return max_rlp_bytes_per_channel_bedrock;
    }

    pub fn channel_timeout_at(config: *const RollupConfig, timestamp: u64) u64 {
        if (config.is_feature_active(.short_channel_timeout, timestamp)) {
            return config.granite_channel_timeout;
        }
        return config.channel_timeout;
    }

    pub fn denim_timestamp_schedule(config: *const RollupConfig) ?DenimTimestampSchedule {
        if (config.block_time == 0) return null;
        const activation = config.upgrades.get(.denim) orelse return null;
        return .{
            .genesis_block_number = config.genesis.l2.number,
            .genesis_timestamp = config.genesis.l2_time,
            .legacy_block_interval = config.block_time,
            .denim_activation_timestamp = activation,
        };
    }

    pub fn l2_block_timestamp_ms(config: *const RollupConfig, block_number: u64) u64 {
        if (config.denim_timestamp_schedule()) |schedule| {
            return schedule.block_timestamp_ms(block_number);
        }
        const blocks = block_number -| config.genesis.l2.number;
        return (config.genesis.l2_time +| (blocks *| config.block_time)) *| 1_000;
    }

    pub fn l2_block_timestamp(config: *const RollupConfig, block_number: u64) u64 {
        return config.l2_block_timestamp_ms(block_number) / 1_000;
    }
};

/// Validates an Ecotone-format L1 fee scalar from the system config.
pub fn check_ecotone_l1_system_config_scalar(scalar: [32]u8) error{InvalidScalar}!void {
    const zeros: [27]u8 = @splat(0);
    switch (scalar[0]) {
        0 => if (!std.mem.eql(u8, scalar[1..28], &zeros)) return error.InvalidScalar,
        1 => if (!std.mem.eql(u8, scalar[1..24], zeros[0..23])) return error.InvalidScalar,
        else => return error.InvalidScalar,
    }
}

const testing = std.testing;

test "rollup config: cascading activation" {
    var config: RollupConfig = .{};
    try testing.expect(config.is_active(.bedrock, 0));
    try testing.expect(!config.is_active(.regolith, 100));
    config.upgrades.set(.holocene, 50);
    try testing.expect(config.is_active(.regolith, 50));
    try testing.expect(config.is_active(.granite, 60));
    try testing.expect(!config.is_active(.granite, 49));
    try testing.expect(!config.is_active(.isthmus, 60));
    try testing.expect(!config.is_active(.pectra_blob_schedule, 60));
    try testing.expect(config.is_first_block(.ecotone, 50, 48));
    try testing.expect(!config.is_first_block(.ecotone, 52, 50));
    // Base upgrades do not cascade into Jovian or back.
    config.upgrades.set(.azul, 10);
    try testing.expect(config.is_active(.azul, 10));
    try testing.expect(!config.is_active(.jovian, 10));
    config.upgrades.set(.jovian, 70);
    try testing.expect(config.is_active(.isthmus, 70));
    try testing.expect(!config.is_active(.azul, 9));
}

test "rollup config: feature mapping" {
    const monotonic = Feature.monotonic_block_timestamps;
    try testing.expectEqual(Upgrade.bedrock, monotonic.activation_upgrade());
    try testing.expectEqual(Upgrade.delta, Feature.span_batches.activation_upgrade());
    try testing.expectEqual(Upgrade.fjord, Feature.brotli_compression.activation_upgrade());
    const strict = Feature.strict_derivation_ordering;
    try testing.expectEqual(Upgrade.holocene, strict.activation_upgrade());
    try testing.expectEqual(Upgrade.isthmus, Feature.operator_fee.activation_upgrade());
    try testing.expectEqual(Upgrade.jovian, Feature.min_base_fee.activation_upgrade());
    try testing.expectEqual(Upgrade.azul, Feature.engine_api_v5.activation_upgrade());
    try testing.expectEqual(Upgrade.denim, Feature.singular_batches_only.activation_upgrade());
    try testing.expectEqual(Upgrade.everest, Feature.eip8130.activation_upgrade());
}

test "rollup config: drift, channel limits, timeouts" {
    var config: RollupConfig = .{ .max_sequencer_drift = 600, .channel_timeout = 300 };
    config.upgrades = .base_mainnet;
    try testing.expectEqual(@as(u64, 600), config.max_sequencer_drift_at(1_720_627_200));
    try testing.expectEqual(@as(u64, 1800), config.max_sequencer_drift_at(1_720_627_201));
    try testing.expectEqual(@as(u64, 21600), config.max_sequencer_drift_at(1_793_901_600));
    try testing.expectEqual(@as(u64, 10_000_000), config.max_rlp_bytes_per_channel(0));
    try testing.expectEqual(@as(u64, 100_000_000), config.max_rlp_bytes_per_channel(1_720_627_201));
    try testing.expectEqual(@as(u64, 300), config.channel_timeout_at(1_726_070_400));
    try testing.expectEqual(@as(u64, 50), config.channel_timeout_at(1_726_070_401));
    try testing.expect(UpgradeConfig.for_chain_id(8453) != null);
    try testing.expect(UpgradeConfig.for_chain_id(1) == null);
    const pectra = UpgradeConfig.base_sepolia.get(.pectra_blob_schedule);
    try testing.expectEqual(@as(?u64, 1_742_486_400), pectra);
}

test "rollup config: denim subsecond timestamps" {
    var config: RollupConfig = .{ .block_time = 2 };
    config.genesis = .{ .l2 = .{ .number = 10 }, .l2_time = 1000 };
    try testing.expectEqual(@as(u64, 1004), config.l2_block_timestamp(12));
    config.upgrades.set(.denim, 1009); // Activation block rounds up: ceil(9 / 2) = 5.
    const schedule = config.denim_timestamp_schedule().?;
    try testing.expectEqual(@as(u64, 5), schedule.denim_activation_block_number());
    try testing.expectEqual(@as(u64, 1_008_000), config.l2_block_timestamp_ms(14));
    try testing.expectEqual(@as(u64, 1_010_000), config.l2_block_timestamp_ms(15));
    try testing.expectEqual(@as(u64, 1_010_200), config.l2_block_timestamp_ms(16));
    try testing.expectEqual(@as(u64, 1_011_000), config.l2_block_timestamp_ms(20));
}

test "rollup config: ecotone scalar check" {
    var scalar: [32]u8 = @splat(0);
    try check_ecotone_l1_system_config_scalar(scalar);
    scalar[5] = 1;
    try testing.expectError(error.InvalidScalar, check_ecotone_l1_system_config_scalar(scalar));
    scalar[0] = 1;
    try testing.expectError(error.InvalidScalar, check_ecotone_l1_system_config_scalar(scalar));
    scalar[5] = 0;
    scalar[30] = 9;
    try check_ecotone_l1_system_config_scalar(scalar);
    scalar[0] = 2;
    try testing.expectError(error.InvalidScalar, check_ecotone_l1_system_config_scalar(scalar));
}

//! Chain specification: fork schedule, EIP-1559 parameters, blob parameters and gas
//! limits for both node modes. L1 mode is plain post-merge Ethereum (the `--dev-l1`
//! chain); L2 mode is Base / OP Stack, whose Ethereum forks are implied by Base
//! upgrades (Shanghai=Canyon, Cancun=Ecotone, Prague=Isthmus, Osaka=Azul).
//!
//! Mirrors base/base `crates/execution/chainspec` and `crates/common/chains`.

const std = @import("std");
const assert = std.debug.assert;

pub const basefee = @import("basefee.zig");
pub const blob = @import("blob.zig");
pub const BaseFeeParams = basefee.BaseFeeParams;
pub const BlobParams = blob.BlobParams;

pub const Mode = enum { l1, l2 };

/// EVM rule set. Every chain this node runs starts at the merge (Paris).
pub const Spec = enum(u8) { paris, shanghai, cancun, prague, osaka };

/// Ethereum forks after the merge, plus the blob-parameter-only forks.
pub const EthereumFork = enum(u8) { shanghai, cancun, prague, osaka, bpo1, bpo2 };

/// Base upgrades in activation order. Bedrock is genesis for every chain we run.
pub const Upgrade = enum(u8) {
    regolith,
    canyon,
    delta,
    ecotone,
    fjord,
    granite,
    holocene,
    pectra_blob_schedule,
    isthmus,
    jovian,
    azul,
    beryl,
    cobalt,
    denim,
    everest,
};

const ethereum_fork_count = @typeInfo(EthereumFork).@"enum".field_names.len;
const upgrade_count = @typeInfo(Upgrade).@"enum".field_names.len;

/// Activation timestamps; `null` means never.
pub const EthereumSchedule = [ethereum_fork_count]?u64;
pub const UpgradeSchedule = [upgrade_count]?u64;

pub const ChainSpec = struct {
    chain_id: u64,
    mode: Mode,
    /// L1 mode only.
    ethereum_forks: EthereumSchedule = @splat(null),
    /// L2 mode only.
    upgrades: UpgradeSchedule = @splat(null),
    /// L1 params, and L2 params before Canyon.
    base_fee_params: BaseFeeParams,
    /// L2 params from Canyon on (ignored in L1 mode).
    base_fee_params_canyon: BaseFeeParams,
    /// Default block gas limit for locally built blocks.
    gas_limit: u64,
    /// Base fee of the genesis block (London active at genesis).
    genesis_base_fee: u64 = 1_000_000_000,

    pub const presets = @import("presets.zig");

    /// Schedules must activate in order; a later fork never precedes an earlier one.
    pub fn validate(spec: *const ChainSpec) error{InvalidForkOrder}!void {
        assert(spec.gas_limit > 0);
        try check_order(&spec.ethereum_forks);
        try check_order(&spec.upgrades);
        if (spec.mode == .l1) assert(std.mem.allEqual(?u64, &spec.upgrades, null));
        if (spec.mode == .l2) assert(std.mem.allEqual(?u64, &spec.ethereum_forks, null));
    }

    pub fn is_upgrade_active(spec: *const ChainSpec, upgrade: Upgrade, timestamp: u64) bool {
        if (spec.mode != .l2) return false;
        const at = spec.upgrades[@backingInt(upgrade)] orelse return false;
        return timestamp >= at;
    }

    pub fn is_ethereum_fork_active(
        spec: *const ChainSpec,
        fork: EthereumFork,
        timestamp: u64,
    ) bool {
        return switch (spec.mode) {
            .l1 => if (spec.ethereum_forks[@backingInt(fork)]) |at| timestamp >= at else false,
            .l2 => switch (fork) {
                .shanghai => spec.is_upgrade_active(.canyon, timestamp),
                .cancun => spec.is_upgrade_active(.ecotone, timestamp),
                .prague => spec.is_upgrade_active(.isthmus, timestamp),
                .osaka => spec.is_upgrade_active(.azul, timestamp),
                // BPO forks only change blob params; L2 has no blob transactions.
                .bpo1, .bpo2 => false,
            },
        };
    }

    pub fn spec_at(spec: *const ChainSpec, timestamp: u64) Spec {
        if (spec.is_ethereum_fork_active(.osaka, timestamp)) return .osaka;
        if (spec.is_ethereum_fork_active(.prague, timestamp)) return .prague;
        if (spec.is_ethereum_fork_active(.cancun, timestamp)) return .cancun;
        if (spec.is_ethereum_fork_active(.shanghai, timestamp)) return .shanghai;
        return .paris;
    }

    pub fn base_fee_params_at(spec: *const ChainSpec, timestamp: u64) BaseFeeParams {
        if (spec.is_upgrade_active(.canyon, timestamp)) return spec.base_fee_params_canyon;
        return spec.base_fee_params;
    }

    /// Blob parameters at `timestamp`; null before Cancun and always null on L2 (OP
    /// chains reject blob transactions and keep the blob header fields at zero).
    pub fn blob_params_at(spec: *const ChainSpec, timestamp: u64) ?BlobParams {
        if (spec.mode == .l2) return null;
        if (spec.is_ethereum_fork_active(.bpo2, timestamp)) return BlobParams.bpo2;
        if (spec.is_ethereum_fork_active(.bpo1, timestamp)) return BlobParams.bpo1;
        if (spec.is_ethereum_fork_active(.osaka, timestamp)) return BlobParams.osaka;
        if (spec.is_ethereum_fork_active(.prague, timestamp)) return BlobParams.prague;
        if (spec.is_ethereum_fork_active(.cancun, timestamp)) return BlobParams.cancun;
        return null;
    }

    /// Base fee of a block at `timestamp` built on `parent`. On L2 the parent's
    /// extra data carries Holocene/Jovian EIP-1559 overrides once active at the parent.
    pub fn next_base_fee(
        spec: *const ChainSpec,
        parent: ParentFees,
        timestamp: u64,
    ) basefee.ExtraDataError!u64 {
        assert(timestamp >= parent.timestamp);
        const defaults = spec.base_fee_params_at(timestamp);
        if (spec.is_upgrade_active(.jovian, parent.timestamp)) {
            const extra = try basefee.decode_jovian(parent.extra_data);
            const params = try extra.resolve(defaults);
            // Jovian prices the DA footprint stored in blob_gas_used as block gas.
            const used = @max(parent.gas_used, parent.blob_gas_used);
            const next = basefee.next_base_fee(used, parent.gas_limit, parent.base_fee, params);
            return @max(next, extra.min_base_fee);
        }
        if (spec.is_upgrade_active(.holocene, parent.timestamp)) {
            const extra = try basefee.decode_holocene(parent.extra_data);
            const params = try extra.resolve(defaults);
            const fee = parent.base_fee;
            return basefee.next_base_fee(parent.gas_used, parent.gas_limit, fee, params);
        }
        return basefee.next_base_fee(parent.gas_used, parent.gas_limit, parent.base_fee, defaults);
    }
};

/// The parent header fields that determine the next block's fees.
pub const ParentFees = struct {
    timestamp: u64,
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,
    blob_gas_used: u64 = 0,
    excess_blob_gas: u64 = 0,
    extra_data: []const u8 = &.{},
};

fn check_order(schedule: []const ?u64) error{InvalidForkOrder}!void {
    // Unscheduled forks are skipped: base/base leaves contract-only upgrades such as
    // the Pectra blob schedule unset on some chains while later forks are scheduled.
    var previous: u64 = 0;
    for (schedule) |entry| {
        const at = entry orelse continue;
        if (at < previous) return error.InvalidForkOrder;
        previous = at;
    }
}

test {
    std.testing.refAllDecls(@This());
}

const testing = std.testing;

test "chainspec: base mainnet fork schedule" {
    const spec = ChainSpec.presets.base_mainnet;
    try spec.validate();
    try testing.expectEqual(Spec.paris, spec.spec_at(1_686_789_347));
    try testing.expectEqual(Spec.shanghai, spec.spec_at(1_704_992_401));
    try testing.expectEqual(Spec.cancun, spec.spec_at(1_710_374_401));
    try testing.expectEqual(Spec.prague, spec.spec_at(1_746_806_401));
    try testing.expect(!spec.is_upgrade_active(.azul, 1_779_991_199));
    try testing.expectEqual(Spec.osaka, spec.spec_at(1_779_991_200));
    try testing.expect(spec.is_upgrade_active(.jovian, 1_764_691_201));
    try testing.expect(!spec.is_upgrade_active(.jovian, 1_764_691_200));
    try testing.expect(!spec.is_upgrade_active(.everest, std.math.maxInt(u64)));
    try testing.expectEqual(@as(?BlobParams, null), spec.blob_params_at(std.math.maxInt(u64)));
}

test "chainspec: canyon switches base fee denominator" {
    const spec = ChainSpec.presets.base_sepolia;
    try spec.validate();
    try testing.expectEqual(@as(u64, 50), spec.base_fee_params_at(0).max_change_denominator);
    const canyon = spec.upgrades[@backingInt(Upgrade.canyon)].?;
    try testing.expectEqual(@as(u64, 250), spec.base_fee_params_at(canyon).max_change_denominator);
    try testing.expectEqual(@as(u64, 10), spec.base_fee_params_at(canyon).elasticity_multiplier);
}

test "chainspec: jovian base fee uses blob gas and min base fee" {
    const spec = ChainSpec.presets.base_devnet;
    try spec.validate();
    const defaults = spec.base_fee_params_at(1);
    const zero = @as([8]u8, @splat(0));
    var extra = basefee.encode_jovian(zero, defaults, 100_000_000);
    var parent: ParentFees = .{
        .timestamp = 0,
        .gas_used = 1_000_000_000,
        .gas_limit = 10_000_000_000,
        .base_fee = 1_000_000_000,
        .blob_gas_used = 5_000_000_000,
        .extra_data = &extra,
    };
    const expected = basefee.next_base_fee(5_000_000_000, 10_000_000_000, 1e9, defaults);
    try testing.expectEqual(expected, try spec.next_base_fee(parent, 2));
    extra = basefee.encode_jovian(zero, defaults, 5_000_000_000);
    parent.blob_gas_used = 100_000_000;
    try testing.expectEqual(@as(u64, 5_000_000_000), try spec.next_base_fee(parent, 2));
    parent.extra_data = &.{};
    try testing.expectError(error.InvalidExtraDataLength, spec.next_base_fee(parent, 2));
}

test "chainspec: l1 dev schedule" {
    const spec = ChainSpec.presets.l1_dev;
    try spec.validate();
    try testing.expectEqual(Spec.prague, spec.spec_at(0));
    try testing.expectEqual(BlobParams.prague, spec.blob_params_at(0).?);
    try testing.expect(!spec.is_upgrade_active(.canyon, 0));
    const parent: ParentFees = .{ .timestamp = 0, .gas_used = 0, .gas_limit = 30e6, .base_fee = 8 };
    try testing.expectEqual(@as(u64, 7), try spec.next_base_fee(parent, 12));
}

test "chainspec: fork order validation" {
    var spec = ChainSpec.presets.base_devnet;
    spec.upgrades[@backingInt(Upgrade.canyon)] = 10;
    try testing.expectError(error.InvalidForkOrder, spec.validate());
    spec = ChainSpec.presets.base_devnet;
    spec.upgrades[@backingInt(Upgrade.delta)] = null;
    try spec.validate();
}

test "chainspec: seeded fuzz spec_at is monotone" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xc4a1);
    const specs = [_]ChainSpec{
        ChainSpec.presets.base_mainnet,
        ChainSpec.presets.base_sepolia,
        ChainSpec.presets.l1_dev,
    };
    for (0..10_000) |_| {
        const spec = specs[prng.below(specs.len)];
        const a = prng.below(2_000_000_000);
        const b = a + prng.below(100_000_000);
        try testing.expect(@backingInt(spec.spec_at(a)) <= @backingInt(spec.spec_at(b)));
    }
}

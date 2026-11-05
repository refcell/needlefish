//! Genesis: geth-style genesis JSON, allocation, state root and the genesis header.
//! Mirrors base/base `crates/common/genesis` and the genesis handling of
//! `crates/execution/chainspec` (`make_genesis_header` with the Isthmus rule).
//!
//! Parsing happens once at startup: `parse` returns a `Parsed` that owns an arena with
//! every decoded account, code blob and storage slot.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const Header = @import("../consensus/header.zig").Header;
const block = @import("../consensus/block.zig");
pub const state = @import("state.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const B64 = primitives.B64;
pub const Account = state.Account;
pub const StorageSlot = state.StorageSlot;

/// EIP-1559 initial base fee, used when London is active at genesis without a value.
pub const initial_base_fee: u64 = 1_000_000_000;

/// OP Stack `L2ToL1MessagePasser` predeploy; its storage root is the Isthmus
/// withdrawals root.
pub const l2_to_l1_message_passer = Address.comptime_hex(
    "4200000000000000000000000000000000000016",
);

/// Base-specific upgrades after Jovian, in activation order (base/base `UpgradeInfo`).
pub const BaseUpgrade = enum(u8) {
    azul,
    beryl,
    cobalt,
    denim,
    everest,
    zenith,

    /// The legacy JSON alias base/base still accepts (`v1`, `v2`, `v3`, `future`).
    pub fn alias(upgrade: BaseUpgrade) ?[]const u8 {
        return switch (upgrade) {
            .azul => "v1",
            .beryl => "v2",
            .cobalt => "v3",
            .zenith => "future",
            .denim, .everest => null,
        };
    }
};

pub const base_upgrade_count = @typeInfo(BaseUpgrade).@"enum".field_names.len;

/// The subset of the genesis `config` object that affects genesis and fork rules.
pub const Config = struct {
    chain_id: u64 = 0,
    london_block: ?u64 = null,
    shanghai_time: ?u64 = null,
    cancun_time: ?u64 = null,
    prague_time: ?u64 = null,
    osaka_time: ?u64 = null,
    bedrock_block: ?u64 = null,
    regolith_time: ?u64 = null,
    canyon_time: ?u64 = null,
    delta_time: ?u64 = null,
    ecotone_time: ?u64 = null,
    fjord_time: ?u64 = null,
    granite_time: ?u64 = null,
    holocene_time: ?u64 = null,
    isthmus_time: ?u64 = null,
    jovian_time: ?u64 = null,
    eip1559_elasticity: ?u64 = null,
    eip1559_denominator: ?u64 = null,
    eip1559_denominator_canyon: ?u64 = null,
    /// Base upgrades (`config.base`), indexed by `BaseUpgrade`.
    base_upgrade_times: [base_upgrade_count]?u64 = @splat(null),
    activation_admin_address: ?Address = null,

    pub fn base_upgrade_time(config: Config, upgrade: BaseUpgrade) ?u64 {
        return config.base_upgrade_times[@backingInt(upgrade)];
    }

    pub fn is_base_upgrade_active(config: Config, upgrade: BaseUpgrade, timestamp: u64) bool {
        return active(config.base_upgrade_time(upgrade), timestamp);
    }

    pub fn is_optimism(config: Config) bool {
        return config.bedrock_block != null or config.regolith_time != null;
    }

    fn active(time: ?u64, timestamp: u64) bool {
        return if (time) |activation| timestamp >= activation else false;
    }

    /// OP chains imply Shanghai at Canyon, Cancun at Ecotone, Prague at Isthmus.
    pub fn is_shanghai(config: Config, timestamp: u64) bool {
        return active(config.shanghai_time, timestamp) or active(config.canyon_time, timestamp);
    }

    pub fn is_cancun(config: Config, timestamp: u64) bool {
        return active(config.cancun_time, timestamp) or active(config.ecotone_time, timestamp);
    }

    pub fn is_prague(config: Config, timestamp: u64) bool {
        return active(config.prague_time, timestamp) or active(config.isthmus_time, timestamp);
    }

    pub fn is_isthmus(config: Config, timestamp: u64) bool {
        return active(config.isthmus_time, timestamp);
    }
};

pub const Genesis = struct {
    config: Config = .{},
    nonce: u64 = 0,
    timestamp: u64 = 0,
    extra_data: []const u8 = &.{},
    gas_limit: u64 = 0,
    difficulty: u256 = 0,
    mix_hash: B256 = .zero,
    coinbase: Address = .zero,
    number: u64 = 0,
    gas_used: u64 = 0,
    parent_hash: B256 = .zero,
    base_fee_per_gas: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    blob_gas_used: ?u64 = null,
    /// A `stateRoot` given in the JSON (not part of geth's schema; base/base dev files
    /// carry it). Used only for cross-checking.
    state_root: ?B256 = null,
    accounts: []const Account = &.{},

    pub fn find_account(genesis: *const Genesis, address: Address) ?*const Account {
        for (genesis.accounts) |*account| {
            if (account.address.eql(address)) return account;
        }
        return null;
    }

    /// The genesis header for `state_root`, with fork-dependent optional fields.
    pub fn header(
        genesis: *const Genesis,
        allocator: std.mem.Allocator,
        state_root: B256,
    ) state.Error!Header {
        const config = genesis.config;
        const timestamp = genesis.timestamp;
        var result: Header = .{
            .parent_hash = genesis.parent_hash,
            .beneficiary = genesis.coinbase,
            .state_root = state_root,
            .difficulty = genesis.difficulty,
            .number = genesis.number,
            .gas_limit = genesis.gas_limit,
            .gas_used = genesis.gas_used,
            .timestamp = timestamp,
            .extra_data = genesis.extra_data,
            .mix_hash = genesis.mix_hash,
            .nonce = .{ .bytes = std.mem.toBytes(std.mem.nativeToBig(u64, genesis.nonce)) },
        };
        if (config.london_block == 0) {
            result.base_fee_per_gas = genesis.base_fee_per_gas orelse initial_base_fee;
        }
        if (config.is_shanghai(timestamp)) result.withdrawals_root = primitives.empty_root_hash;
        if (config.is_cancun(timestamp)) {
            result.blob_gas_used = genesis.blob_gas_used orelse 0;
            result.excess_blob_gas = genesis.excess_blob_gas orelse 0;
            result.parent_beacon_block_root = .zero;
        }
        if (config.is_prague(timestamp)) result.requests_hash = block.empty_requests_hash;
        if (config.is_isthmus(timestamp)) {
            if (genesis.find_account(l2_to_l1_message_passer)) |passer| {
                result.withdrawals_root = try state.storage_root(allocator, passer.storage);
            }
        }
        assert(result.optionals_contiguous());
        return result;
    }

    pub fn compute_state_root(
        genesis: *const Genesis,
        allocator: std.mem.Allocator,
    ) state.Error!B256 {
        return state.state_root(allocator, genesis.accounts);
    }
};

pub const json = @import("json.zig");
pub const parse = json.parse;
pub const Parsed = json.Parsed;

test {
    std.testing.refAllDecls(@This());
}

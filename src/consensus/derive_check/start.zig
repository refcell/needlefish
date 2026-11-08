//! Derivation check, start half: the rollup config of a built-in chain (base/base
//! `ChainConfig::rollup_config`), and the choice of the L2 range to derive.
//!
//! The check starts like a verifier whose engine reports `start` as its safe head: the
//! block's L1 origin and system config come from its L1 info deposit, and the pipeline is
//! reset with that safe head (`Pipeline.signal(.reset)`), which walks back one channel
//! timeout of L1 origins before reading L1 (base/base `initial_reset`). Every block after
//! `start` up to `last` must already be safe on the reference node, so its batch is on L1.

const std = @import("std");
const assert = std.debug.assert;

const chains = @import("../../common/chains/root.zig");
const protocol = @import("../protocol/root.zig");
const attributes_match = @import("../engine/attributes_match.zig");

const RollupConfig = protocol.rollup_config.RollupConfig;
const UpgradeConfig = protocol.rollup_config.UpgradeConfig;
const ChainConfig = chains.ChainConfig;

/// Beacon nodes keep blobs for `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` (4096) epochs of 32
/// slots of 12 seconds.
pub const blob_retention_s: u64 = 4096 * 32 * 12;
/// Margin kept from the edge of the blob window: the reset walks back one channel timeout of
/// L1 blocks before the start's origin, and the run takes time.
pub const blob_retention_margin_s: u64 = 24 * 60 * 60;
/// Upper bound on the blocks one check derives.
pub const blocks_max: u64 = 1_000_000;

/// The full rollup config of a built-in chain (base/base `ChainConfig::rollup_config`).
pub fn rollup_config_for(chain: *const ChainConfig) RollupConfig {
    chain.validate();
    var config: RollupConfig = .{
        .block_time = chain.block_time,
        .max_sequencer_drift = chain.max_sequencer_drift,
        .seq_window_size = chain.seq_window_size,
        .channel_timeout = chain.channel_timeout,
        .granite_channel_timeout = RollupConfig.granite_channel_timeout_default,
        .l1_chain_id = chain.l1_chain_id,
        .l2_chain_id = chain.chain_id,
        .upgrades = UpgradeConfig.for_chain_id(chain.chain_id) orelse .{},
        .batch_inbox_address = chain.batch_inbox_address,
        .deposit_contract_address = chain.deposit_contract_address,
        .l1_system_config_address = chain.system_config_address,
        .protocol_versions_address = chain.protocol_versions_address,
        .blobs_enabled_l1_timestamp = null,
    };
    config.genesis = .{
        .l1 = .{ .number = chain.genesis_l1_number, .hash = chain.genesis_l1_hash },
        .l2 = .{ .number = chain.genesis_l2_number, .hash = chain.genesis_l2_hash },
        .l2_time = chain.genesis_l2_time,
        .system_config = .{
            .batcher_address = chain.genesis_batcher_address,
            .overhead = chain.genesis_overhead,
            .scalar = chain.genesis_scalar,
            .gas_limit = chain.genesis_gas_limit,
        },
    };
    assert(config.l2_chain_id == chain.chain_id);
    assert(config.block_time > 0);
    return config;
}

/// Post-Canyon EIP-1559 parameters (`BaseFeeParams` of the chain's fee config), used by
/// consolidation for all-zero Holocene `eip1559Params`.
pub fn fee_params_canyon(chain: *const ChainConfig) attributes_match.FeeParams {
    assert(chain.eip1559_elasticity > 0);
    assert(chain.eip1559_denominator_canyon > 0);
    return .{
        .elasticity = chain.eip1559_elasticity,
        .denominator = chain.eip1559_denominator_canyon,
    };
}

/// The derived range: `start` is the safe head the pipeline resets to, blocks
/// `start + 1 ..= last` are derived and compared.
pub const Range = struct {
    start: u64,
    last: u64,

    pub fn count(range: Range) u64 {
        assert(range.start < range.last);
        return range.last - range.start;
    }
};

pub const RangeError = error{ EmptyRange, TooManyBlocks, BeforeGenesis, NotYetSafe };

/// `blocks` blocks after `from`, or, without `from`, the `blocks` blocks ending at the
/// reference's safe head. Every derived block must be safe on the reference.
pub fn choose_range(
    reference_safe: u64,
    genesis_number: u64,
    from: ?u64,
    blocks: u64,
) RangeError!Range {
    if (blocks == 0) return error.EmptyRange;
    if (blocks > blocks_max) return error.TooManyBlocks;
    const start = from orelse (std.math.sub(u64, reference_safe, blocks) catch
        return error.BeforeGenesis);
    if (start < genesis_number) return error.BeforeGenesis;
    const last = start + blocks;
    if (last > reference_safe) return error.NotYetSafe;
    const range: Range = .{ .start = start, .last = last };
    assert(range.count() == blocks);
    assert(range.last <= reference_safe);
    return range;
}

/// True when blobs of an L1 block at `l1_time_s` are still served at `now_s`, with margin.
pub fn blobs_retained(l1_time_s: u64, now_s: u64) bool {
    if (l1_time_s >= now_s) return true;
    const age_s = now_s - l1_time_s;
    assert(age_s > 0);
    return age_s + blob_retention_margin_s <= blob_retention_s;
}

const testing = std.testing;

test "derive check start: base sepolia rollup config" {
    const chain = &chains.sepolia;
    const config = rollup_config_for(chain);
    try testing.expectEqual(@as(u64, 84532), config.l2_chain_id);
    try testing.expectEqual(@as(u64, 11_155_111), config.l1_chain_id);
    try testing.expect(config.batch_inbox_address.eql(chain.batch_inbox_address));
    try testing.expect(config.l1_system_config_address.eql(chain.system_config_address));
    try testing.expect(config.genesis.l2.hash.eql(chain.genesis_l2_hash));
    try testing.expectEqual(@as(u64, 25_000_000), config.genesis.system_config.?.gas_limit);
    // Block 56060011 (recorded fixture): 200 ms blocks, `timestampMs` 0x1a1bab64998.
    try testing.expectEqual(@as(u64, 1_794_133_871), config.l2_block_timestamp(56_060_011));
    try testing.expectEqual(@as(u64, 0x1a1bab64998), config.l2_block_timestamp_ms(56_060_011));
    const time = config.l2_block_timestamp(56_060_011);
    try testing.expect(config.is_feature_active(.subsecond_blocks, time));
    try testing.expect(config.is_feature_active(.min_base_fee, time));
    try testing.expect(config.is_feature_active(.blob_data_source, time));
    // Granite's channel timeout (base/base `GRANITE_CHANNEL_TIMEOUT`).
    try testing.expectEqual(@as(u64, 50), config.channel_timeout_at(time));
    const params = fee_params_canyon(chain);
    try testing.expectEqual(@as(u64, 10), params.elasticity);
    try testing.expectEqual(@as(u64, 250), params.denominator);
}

test "derive check start: range choice" {
    const range = try choose_range(1000, 0, null, 100);
    try testing.expectEqual(@as(u64, 900), range.start);
    try testing.expectEqual(@as(u64, 1000), range.last);
    try testing.expectEqual(@as(u64, 100), range.count());
    const from = try choose_range(1000, 0, 10, 5);
    try testing.expectEqual(@as(u64, 15), from.last);
    try testing.expectError(error.NotYetSafe, choose_range(1000, 0, 996, 5));
    try testing.expectError(error.EmptyRange, choose_range(1000, 0, null, 0));
    try testing.expectError(error.BeforeGenesis, choose_range(1000, 0, null, 1001));
    try testing.expectError(error.BeforeGenesis, choose_range(1000, 50, 10, 5));
    try testing.expectError(error.TooManyBlocks, choose_range(1000, 0, 0, blocks_max + 1));
}

test "derive check start: blob window" {
    const now: u64 = 1_800_000_000;
    try testing.expect(blobs_retained(now - 3600, now));
    try testing.expect(blobs_retained(now + 5, now));
    try testing.expect(!blobs_retained(now - blob_retention_s, now));
    try testing.expect(!blobs_retained(now - blob_retention_s + blob_retention_margin_s - 1, now));
    try testing.expect(blobs_retained(now - blob_retention_s + blob_retention_margin_s, now));
}

test "derive check start: seeded fuzz of the range rules" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x5354_4152);
    for (0..2000) |_| {
        const safe = prng.below(10_000);
        const genesis = prng.below(100);
        const from: ?u64 = if (prng.chance(1, 2)) prng.below(10_000) else null;
        const blocks = prng.below(2_000);
        const range = choose_range(safe, genesis, from, blocks) catch continue;
        try testing.expect(range.start >= genesis);
        try testing.expect(range.last <= safe);
        try testing.expectEqual(blocks, range.count());
    }
}

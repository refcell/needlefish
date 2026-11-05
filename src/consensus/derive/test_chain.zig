//! In-memory chain and blob provider for derivation tests. Blocks are indexed by number;
//! receipts, transactions, and blobs are indexed by block position. Setting
//! `unavailable_from` makes every query at or above that block number return
//! `error.NotAvailable`, emulating an in-flight fetch. L1 headers are derived from the
//! block infos; L2 system configs are registered per L2 block hash.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const providers = @import("providers.zig");
const blob = @import("blob.zig");

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const SafeBlock = protocol.span_batch.SafeBlock;
const Hash = protocol.block.Hash;
const Receipt = protocol.log.Receipt;
const L1Header = protocol.l1_info.L1Header;
const SystemConfig = protocol.SystemConfig;
const ProviderError = errors.ProviderError;

pub const blocks_max = 64;
pub const system_configs_max = 16;
pub const l2_blocks_max = 64;

pub const SystemConfigEntry = struct { l2_hash: Hash, config: SystemConfig };
pub const SafeBlockEntry = struct { number: u64, block: SafeBlock };

pub const TestChain = struct {
    blocks: [blocks_max]BlockInfo = undefined,
    receipts: [blocks_max][]const Receipt = @splat(&.{}),
    transactions: [blocks_max][]const providers.L1Transaction = @splat(&.{}),
    blob_list: [blocks_max][]const *const blob.Blob = @splat(&.{}),
    count: u32 = 0,
    unavailable_from: u64 = std.math.maxInt(u64),
    blobs_missing: bool = false,
    /// Per-block `mix_hash` (prevrandao) reported by `l1_header_by_hash`.
    mix_hashes: [blocks_max]Hash = @splat(.zero),
    base_fees: [blocks_max]?u64 = @splat(null),
    system_configs: [system_configs_max]SystemConfigEntry = undefined,
    system_config_count: u32 = 0,
    /// L2 safe chain: block infos searched in insertion order (duplicates allowed, the
    /// first match wins), full blocks keyed by number.
    l2_blocks: [l2_blocks_max]L2BlockInfo = undefined,
    l2_block_count: u32 = 0,
    l2_safe_blocks: [l2_blocks_max]SafeBlockEntry = undefined,
    l2_safe_block_count: u32 = 0,
    /// Every L2 query returns `error.NotAvailable` while set.
    l2_unavailable: bool = false,

    /// Builds `count` linked blocks starting at `first_number` with `block_time` spacing.
    pub fn init(count: u32, first_number: u64, block_time: u64) TestChain {
        assert(count <= blocks_max);
        var chain: TestChain = .{ .count = count };
        var parent: Hash = .zero;
        for (0..count) |index| {
            const number = first_number + index;
            var hash_input: [8]u8 = undefined;
            std.mem.writeInt(u64, &hash_input, number, .big);
            const hash = @import("../../common/primitives/root.zig").keccak256(&hash_input);
            chain.blocks[index] = .{
                .hash = hash,
                .number = number,
                .parent_hash = parent,
                .timestamp = 1000 + index * block_time,
            };
            parent = hash;
        }
        return chain;
    }

    fn index_of_number(chain: *const TestChain, number: u64) ProviderError!u32 {
        if (number >= chain.unavailable_from) return error.NotAvailable;
        if (chain.count == 0 or number < chain.blocks[0].number) return error.NotFound;
        const offset = number - chain.blocks[0].number;
        if (offset >= chain.count) return error.NotFound;
        return @intCast(offset);
    }

    fn index_of_hash(chain: *const TestChain, hash: Hash) ProviderError!u32 {
        for (chain.blocks[0..chain.count], 0..) |block, index| {
            if (!block.hash.eql(hash)) continue;
            if (block.number >= chain.unavailable_from) return error.NotAvailable;
            return @intCast(index);
        }
        return error.NotFound;
    }

    pub fn l1_block_info_by_number(chain: *TestChain, number: u64) ProviderError!BlockInfo {
        return chain.blocks[try chain.index_of_number(number)];
    }

    pub fn l1_receipts_by_hash(chain: *TestChain, hash: Hash) ProviderError![]const Receipt {
        return chain.receipts[try chain.index_of_hash(hash)];
    }

    pub fn l1_transactions_by_hash(
        chain: *TestChain,
        hash: Hash,
    ) ProviderError![]const providers.L1Transaction {
        return chain.transactions[try chain.index_of_hash(hash)];
    }

    pub fn l1_header_by_hash(chain: *TestChain, hash: Hash) ProviderError!L1Header {
        const index = try chain.index_of_hash(hash);
        const block = chain.blocks[index];
        assert(block.hash.eql(hash));
        return .{
            .number = block.number,
            .timestamp = block.timestamp,
            .hash = block.hash,
            .parent_hash = block.parent_hash,
            .base_fee = chain.base_fees[index],
            .excess_blob_gas = null,
            .mix_hash = chain.mix_hashes[index],
        };
    }

    /// Registers (or replaces) the system config of an L2 block.
    pub fn add_system_config(chain: *TestChain, l2_hash: Hash, config: SystemConfig) void {
        for (chain.system_configs[0..chain.system_config_count]) |*entry| {
            if (!entry.l2_hash.eql(l2_hash)) continue;
            entry.config = config;
            return;
        }
        assert(chain.system_config_count < system_configs_max);
        chain.system_configs[chain.system_config_count] = .{ .l2_hash = l2_hash, .config = config };
        chain.system_config_count += 1;
    }

    pub fn system_config_by_l2_hash(chain: *TestChain, l2_hash: Hash) ProviderError!SystemConfig {
        assert(chain.system_config_count <= system_configs_max);
        for (chain.system_configs[0..chain.system_config_count]) |entry| {
            if (entry.l2_hash.eql(l2_hash)) return entry.config;
        }
        return error.NotFound;
    }

    pub fn add_l2_block(chain: *TestChain, info: L2BlockInfo) void {
        assert(chain.l2_block_count < l2_blocks_max);
        chain.l2_blocks[chain.l2_block_count] = info;
        chain.l2_block_count += 1;
    }

    pub fn add_l2_safe_block(chain: *TestChain, number: u64, block: SafeBlock) void {
        assert(chain.l2_safe_block_count < l2_blocks_max);
        chain.l2_safe_blocks[chain.l2_safe_block_count] = .{ .number = number, .block = block };
        chain.l2_safe_block_count += 1;
    }

    pub fn l2_block_info_by_number(chain: *TestChain, number: u64) ProviderError!L2BlockInfo {
        assert(chain.l2_block_count <= l2_blocks_max);
        if (chain.l2_unavailable) return error.NotAvailable;
        for (chain.l2_blocks[0..chain.l2_block_count]) |info| {
            if (info.block_info.number == number) return info;
        }
        return error.NotFound;
    }

    pub fn l2_block_info_by_hash(chain: *TestChain, hash: Hash) ProviderError!L2BlockInfo {
        assert(chain.l2_block_count <= l2_blocks_max);
        if (chain.l2_unavailable) return error.NotAvailable;
        for (chain.l2_blocks[0..chain.l2_block_count]) |info| {
            if (info.block_info.hash.eql(hash)) return info;
        }
        return error.NotFound;
    }

    pub fn l2_block_by_number(chain: *TestChain, number: u64) ProviderError!SafeBlock {
        assert(chain.l2_safe_block_count <= l2_blocks_max);
        if (chain.l2_unavailable) return error.NotAvailable;
        for (chain.l2_safe_blocks[0..chain.l2_safe_block_count]) |entry| {
            if (entry.number == number) return entry.block;
        }
        return error.NotFound;
    }

    pub fn blobs(
        chain: *TestChain,
        block: BlockInfo,
        hashes: []const Hash,
    ) ProviderError![]const *const blob.Blob {
        if (chain.blobs_missing) return error.BlobsUnavailable;
        const list = chain.blob_list[try chain.index_of_hash(block.hash)];
        assert(hashes.len > 0);
        return list;
    }
};

test "test chain: lookups" {
    var chain = TestChain.init(4, 10, 12);
    try std.testing.expect(chain.blocks[0].is_parent_of(chain.blocks[1]));
    const block = try chain.l1_block_info_by_number(12);
    try std.testing.expectEqual(@as(u64, 1024), block.timestamp);
    try std.testing.expectError(error.NotFound, chain.l1_block_info_by_number(14));
    chain.unavailable_from = 11;
    try std.testing.expectError(error.NotAvailable, chain.l1_receipts_by_hash(block.hash));
}

test "test chain: headers and system configs" {
    var chain = TestChain.init(3, 5, 12);
    const header = try chain.l1_header_by_hash(chain.blocks[1].hash);
    try std.testing.expect(header.parent_hash.eql(chain.blocks[0].hash));
    try std.testing.expectEqual(@as(u64, 6), header.number);
    try std.testing.expectError(error.NotFound, chain.system_config_by_l2_hash(.zero));
    chain.add_system_config(.zero, .{ .gas_limit = 7 });
    chain.add_system_config(.zero, .{ .gas_limit = 8 });
    try std.testing.expectEqual(@as(u64, 8), (try chain.system_config_by_l2_hash(.zero)).gas_limit);
    try std.testing.expectEqual(@as(u32, 1), chain.system_config_count);
}

test "test chain: l2 safe chain" {
    var chain = TestChain.init(0, 0, 12);
    chain.add_l2_block(.{ .block_info = .{ .number = 4, .hash = .init(@splat(4)) } });
    chain.add_l2_safe_block(4, .{ .transactions = &.{}, .l1_origin_number = 2 });
    const info = try chain.l2_block_info_by_number(4);
    try std.testing.expect(info.block_info.hash.eql(.init(@splat(4))));
    const by_hash = try chain.l2_block_info_by_hash(.init(@splat(4)));
    try std.testing.expectEqual(@as(u64, 4), by_hash.block_info.number);
    try std.testing.expectEqual(@as(?u64, 2), (try chain.l2_block_by_number(4)).l1_origin_number);
    try std.testing.expectError(error.NotFound, chain.l2_block_info_by_number(5));
    chain.l2_unavailable = true;
    try std.testing.expectError(error.NotAvailable, chain.l2_block_by_number(4));
}

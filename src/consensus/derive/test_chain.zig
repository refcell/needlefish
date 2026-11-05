//! In-memory chain and blob provider for derivation tests. Blocks are indexed by number;
//! receipts, transactions, and blobs are indexed by block position. Setting
//! `unavailable_from` makes every query at or above that block number return
//! `error.NotAvailable`, emulating an in-flight fetch.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const providers = @import("providers.zig");
const blob = @import("blob.zig");

const BlockInfo = protocol.block.BlockInfo;
const Hash = protocol.block.Hash;
const Receipt = protocol.log.Receipt;
const ProviderError = errors.ProviderError;

pub const blocks_max = 64;

pub const TestChain = struct {
    blocks: [blocks_max]BlockInfo = undefined,
    receipts: [blocks_max][]const Receipt = @splat(&.{}),
    transactions: [blocks_max][]const providers.L1Transaction = @splat(&.{}),
    blob_list: [blocks_max][]const *const blob.Blob = @splat(&.{}),
    count: u32 = 0,
    unavailable_from: u64 = std.math.maxInt(u64),
    blobs_missing: bool = false,

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

//! Batcher data from one L1 block: calldata of batcher transactions before Ecotone, blobs
//! (and calldata of non-blob batcher transactions) after.
//! Mirrors base/base `crates/consensus/derive/src/sources/{ethereum,calldata,blobs}.rs`.
//!
//! On first use for a block the source loads every item it will yield and copies it into
//! owned memory, so provider buffers may be reused. Blob payloads are decoded eagerly; a
//! blob that fails to decode is skipped, matching base/base.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const errors = @import("errors.zig");
const providers = @import("providers.zig");
const blob = @import("blob.zig");

const BlockInfo = protocol.block.BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Address = primitives.Address;
const B256 = primitives.B256;
const L1Transaction = providers.L1Transaction;
const Error = errors.Error;

/// Upper bound on items (batcher transactions or blobs) per L1 block. An L1 block holds at
/// most ~1500 minimal transactions at 45M gas, and far fewer blobs.
pub const items_per_block_max = 4096;

const Item = union(enum) {
    data: []u8,
    /// A blob whose payload failed to decode; skipped when reached.
    invalid,
};

pub const DataSource = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    items: std.ArrayList(Item) = .empty,
    cursor: u32 = 0,
    open: bool = false,
    /// The item handed out by the last `next`, freed on the following call.
    current: ?[]u8 = null,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) DataSource {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(source: *DataSource) void {
        source.clear();
        source.items.deinit(source.allocator);
        source.* = undefined;
    }

    pub fn clear(source: *DataSource) void {
        for (source.items.items[source.cursor..]) |item| switch (item) {
            .data => |data| source.allocator.free(data),
            .invalid => {},
        };
        source.items.clearRetainingCapacity();
        source.free_current();
        source.cursor = 0;
        source.open = false;
    }

    fn free_current(source: *DataSource) void {
        if (source.current) |data| source.allocator.free(data);
        source.current = null;
    }

    /// Returns the next batcher payload of `block`, or `error.Eof` when exhausted. The
    /// slice stays valid until the next call to `next` or `clear`.
    pub fn next(
        source: *DataSource,
        chain: anytype,
        blob_provider: anytype,
        block: BlockInfo,
        batcher_address: Address,
    ) Error![]const u8 {
        source.free_current();
        if (!source.open) {
            const blobs_enabled = source.rollup.is_feature_active(
                .blob_data_source,
                block.timestamp,
            );
            if (blobs_enabled) {
                try source.load_blobs(chain, blob_provider, block, batcher_address);
            } else {
                try source.load_calldata(chain, block, batcher_address);
            }
            source.open = true;
        }
        assert(source.cursor <= source.items.items.len);
        while (source.cursor < source.items.items.len) {
            const item = source.items.items[source.cursor];
            source.cursor += 1;
            switch (item) {
                .data => |data| {
                    source.current = data;
                    return data;
                },
                .invalid => {},
            }
        }
        return error.Eof;
    }

    fn accepts(source: *const DataSource, tx: L1Transaction, batcher_address: Address) bool {
        const known_type = tx.tx_type <= L1Transaction.type_eip4844;
        if (!known_type) return false;
        const to = tx.to orelse return false;
        if (!to.eql(source.rollup.batch_inbox_address)) return false;
        return tx.from.eql(batcher_address);
    }

    fn push_copy(source: *DataSource, data: []const u8) Error!void {
        if (source.items.items.len >= items_per_block_max) return;
        const copy = try source.allocator.dupe(u8, data);
        errdefer source.allocator.free(copy);
        try source.items.append(source.allocator, .{ .data = copy });
    }

    fn load_calldata(
        source: *DataSource,
        chain: anytype,
        block: BlockInfo,
        batcher_address: Address,
    ) Error!void {
        assert(source.items.items.len == 0);
        const transactions = try chain.l1_transactions_by_hash(block.hash);
        errdefer source.clear();
        for (transactions) |tx| {
            if (!source.accepts(tx, batcher_address)) continue;
            try source.push_copy(tx.input);
        }
        assert(source.items.items.len <= items_per_block_max);
    }

    fn load_blobs(
        source: *DataSource,
        chain: anytype,
        blob_provider: anytype,
        block: BlockInfo,
        batcher_address: Address,
    ) Error!void {
        assert(source.items.items.len == 0);
        const transactions = try chain.l1_transactions_by_hash(block.hash);
        var hashes: std.ArrayList(B256) = .empty;
        defer hashes.deinit(source.allocator);
        // Collect the blob hashes first: the blob fetch may fail temporarily, and nothing is
        // copied until it succeeds.
        for (transactions) |tx| {
            if (!source.accepts(tx, batcher_address)) continue;
            if (tx.tx_type != L1Transaction.type_eip4844) continue;
            try hashes.appendSlice(source.allocator, tx.blob_hashes);
        }
        if (hashes.items.len > items_per_block_max) return error.BlobsOverFill;
        var blobs: []const *const blob.Blob = &.{};
        if (hashes.items.len > 0) blobs = try blob_provider.blobs(block, hashes.items);
        if (blobs.len < hashes.items.len) return error.BlobsUnderFill;
        if (blobs.len > hashes.items.len) return error.BlobsOverFill;

        errdefer source.clear();
        var blob_index: u32 = 0;
        for (transactions) |tx| {
            if (!source.accepts(tx, batcher_address)) continue;
            if (tx.tx_type != L1Transaction.type_eip4844) {
                try source.push_copy(tx.input);
                continue;
            }
            for (tx.blob_hashes) |_| {
                try source.push_blob(blobs[blob_index]);
                blob_index += 1;
            }
        }
        assert(blob_index == blobs.len);
    }

    fn push_blob(source: *DataSource, encoded: *const blob.Blob) Error!void {
        const scratch = try source.allocator.create([blob.max_data_size]u8);
        defer source.allocator.destroy(scratch);
        const payload = blob.decode(encoded, scratch) catch {
            try source.items.append(source.allocator, .invalid);
            return;
        };
        try source.push_copy(payload);
    }
};

const testing = std.testing;
const TestChain = @import("test_chain.zig").TestChain;

const inbox = Address.init(@splat(0x11));
const batcher = Address.init(@splat(0x22));
const stranger = Address.init(@splat(0x33));

fn next_of(source: *DataSource, chain: *TestChain) Error![]const u8 {
    return source.next(chain, chain, chain.blocks[1], batcher);
}

fn expect_next(source: *DataSource, chain: *TestChain, block: BlockInfo, want: []const u8) !void {
    const data = try source.next(chain, chain, block, batcher);
    try testing.expectEqualSlices(u8, want, data);
}

test "sources: calldata filters by inbox, sender, and type" {
    var chain = TestChain.init(2, 0, 12);
    const rollup: RollupConfig = .{ .batch_inbox_address = inbox };
    const transactions = [_]L1Transaction{
        .{ .tx_type = 2, .to = inbox, .from = batcher, .input = "one" },
        .{ .tx_type = 2, .to = inbox, .from = stranger, .input = "bad sender" },
        .{ .tx_type = 0, .to = stranger, .from = batcher, .input = "bad to" },
        .{ .tx_type = 2, .to = null, .from = batcher, .input = "create" },
        .{ .tx_type = 0x7e, .to = inbox, .from = batcher, .input = "deposit type" },
        .{ .tx_type = 0, .to = inbox, .from = batcher, .input = "two" },
    };
    chain.transactions[1] = &transactions;
    var source = DataSource.init(testing.allocator, &rollup);
    defer source.deinit();

    chain.unavailable_from = 1;
    try testing.expectError(error.NotAvailable, next_of(&source, &chain));
    chain.unavailable_from = std.math.maxInt(u64);
    try expect_next(&source, &chain, chain.blocks[1], "one");
    try expect_next(&source, &chain, chain.blocks[1], "two");
    try testing.expectError(error.Eof, next_of(&source, &chain));
    source.clear();
    try expect_next(&source, &chain, chain.blocks[1], "one");
}

var test_blobs: [3]blob.Blob = undefined;

test "sources: blobs with mixed calldata, invalid blobs, and fill errors" {
    var chain = TestChain.init(2, 0, 12);
    var rollup: RollupConfig = .{ .batch_inbox_address = inbox };
    rollup.upgrades.set(.ecotone, 0);
    try blob.encode("first blob", &test_blobs[0]);
    @memset(&test_blobs[1], 0xff); // Fails to decode and is skipped.
    try blob.encode("third blob", &test_blobs[2]);
    const pointers = [_]*const blob.Blob{ &test_blobs[0], &test_blobs[1], &test_blobs[2] };
    const hashes = [_]B256{ .zero, .zero, .zero };
    const transactions = [_]L1Transaction{
        .{ .tx_type = 3, .to = inbox, .from = batcher, .input = "", .blob_hashes = hashes[0..2] },
        .{ .tx_type = 2, .to = inbox, .from = batcher, .input = "calldata" },
        .{ .tx_type = 3, .to = inbox, .from = stranger, .input = "", .blob_hashes = hashes[0..1] },
        .{ .tx_type = 3, .to = inbox, .from = batcher, .input = "", .blob_hashes = hashes[2..3] },
    };
    chain.transactions[1] = &transactions;
    chain.blob_list[1] = &pointers;
    var source = DataSource.init(testing.allocator, &rollup);
    defer source.deinit();
    try expect_next(&source, &chain, chain.blocks[1], "first blob");
    try expect_next(&source, &chain, chain.blocks[1], "calldata");
    try expect_next(&source, &chain, chain.blocks[1], "third blob");
    try testing.expectError(error.Eof, next_of(&source, &chain));

    source.clear();
    chain.blob_list[1] = pointers[0..2];
    try testing.expectError(error.BlobsUnderFill, next_of(&source, &chain));
    source.clear();
    chain.blobs_missing = true;
    try testing.expectError(error.BlobsUnavailable, next_of(&source, &chain));
}

test "sources: seeded fuzz over random transaction lists" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x534f5552);
    var chain = TestChain.init(2, 0, 12);
    const rollup: RollupConfig = .{ .batch_inbox_address = inbox };
    var transactions: [16]L1Transaction = undefined;
    var inputs: [16][4]u8 = undefined;
    for (0..200) |_| {
        const count = prng.below(transactions.len + 1);
        var expected: u32 = 0;
        for (transactions[0..count], 0..) |*tx, index| {
            prng.fill(&inputs[index]);
            const good = prng.chance(1, 2);
            tx.* = .{
                .tx_type = if (good) 2 else prng.int(u8),
                .to = if (good or prng.chance(1, 2)) inbox else stranger,
                .from = if (good or prng.chance(1, 2)) batcher else stranger,
                .input = &inputs[index],
            };
            if (tx.tx_type <= 3 and tx.to.?.eql(inbox) and tx.from.eql(batcher)) expected += 1;
        }
        chain.transactions[1] = transactions[0..count];
        var source = DataSource.init(testing.allocator, &rollup);
        defer source.deinit();
        var seen: u32 = 0;
        while (next_of(&source, &chain)) |_| seen += 1 else |err| {
            try testing.expectEqual(error.Eof, err);
        }
        try testing.expectEqual(expected, seen);
    }
}

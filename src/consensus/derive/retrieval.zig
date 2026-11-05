//! L1 retrieval: pulls batcher payloads for the current L1 block from the data source.
//! Mirrors base/base `crates/consensus/derive/src/stages/l1_retrieval.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const sources = @import("sources.zig");
const Traversal = @import("traversal.zig").Traversal;

const BlockInfo = protocol.block.BlockInfo;
const BlockId = protocol.block.BlockId;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.system_config.SystemConfig;
const Address = @import("../../common/primitives/root.zig").Address;
const Error = errors.Error;

pub const Retrieval = struct {
    traversal: Traversal,
    source: sources.DataSource,
    /// Overrides the system config batcher address (base/base `da_batcher_sender_override`).
    batcher_override: ?Address = null,
    next_block: ?BlockInfo = null,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) Retrieval {
        return .{
            .traversal = Traversal.init(rollup),
            .source = sources.DataSource.init(allocator, rollup),
        };
    }

    pub fn deinit(retrieval: *Retrieval) void {
        retrieval.source.deinit();
        retrieval.* = undefined;
    }

    pub fn origin(retrieval: *const Retrieval) ?BlockInfo {
        return retrieval.traversal.origin();
    }

    pub fn advance_origin(retrieval: *Retrieval, chain: anytype) Error!void {
        return retrieval.traversal.advance_origin(chain);
    }

    /// Returns the next batcher payload, valid until the next call. `error.Eof` means the
    /// current L1 block is exhausted and the origin must advance.
    pub fn next_data(
        retrieval: *Retrieval,
        chain: anytype,
        blob_provider: anytype,
    ) Error![]const u8 {
        if (retrieval.next_block == null) {
            const block = try retrieval.traversal.next_l1_block();
            retrieval.next_block = block orelse return error.MissingL1Data;
        }
        const block = retrieval.next_block.?;
        const batcher = retrieval.batcher_override orelse retrieval.traversal.batcher_address();
        return retrieval.source.next(chain, blob_provider, block, batcher) catch |err| {
            if (err == error.Eof) {
                retrieval.next_block = null;
                retrieval.source.clear();
            }
            return err;
        };
    }

    pub fn reset(
        retrieval: *Retrieval,
        chain: anytype,
        l1_origin: BlockId,
        system_config: SystemConfig,
    ) Error!void {
        try retrieval.traversal.reset(chain, l1_origin, system_config);
        retrieval.activate();
        assert(retrieval.next_block.?.number == l1_origin.number);
    }

    /// Restarts reading the current origin (Holocene activation).
    pub fn activate(retrieval: *Retrieval) void {
        retrieval.source.clear();
        retrieval.next_block = retrieval.traversal.origin();
    }
};

const testing = std.testing;
const TestChain = @import("test_chain.zig").TestChain;
const L1Transaction = @import("providers.zig").L1Transaction;

test "retrieval: walks payloads, eof advances, reset re-reads origin" {
    var chain = TestChain.init(3, 0, 12);
    const inbox = Address.init(@splat(0x11));
    const batcher = Address.init(@splat(0x22));
    const rollup: RollupConfig = .{ .batch_inbox_address = inbox };
    const block1 = [_]L1Transaction{.{ .tx_type = 2, .to = inbox, .from = batcher, .input = "a" }};
    chain.transactions[1] = &block1;

    var retrieval = Retrieval.init(testing.allocator, &rollup);
    defer retrieval.deinit();
    try retrieval.reset(&chain, chain.blocks[0].id(), .{ .batcher_address = batcher });
    try testing.expectError(error.Eof, retrieval.next_data(&chain, &chain));
    try testing.expectError(error.Eof, retrieval.next_data(&chain, &chain));
    try retrieval.advance_origin(&chain);
    try testing.expectEqualStrings("a", try retrieval.next_data(&chain, &chain));
    try testing.expectError(error.Eof, retrieval.next_data(&chain, &chain));

    retrieval.batcher_override = Address.init(@splat(0x99));
    try retrieval.reset(&chain, chain.blocks[1].id(), .{ .batcher_address = batcher });
    try testing.expectError(error.Eof, retrieval.next_data(&chain, &chain));
    retrieval.batcher_override = null;
    retrieval.activate();
    try testing.expectEqualStrings("a", try retrieval.next_data(&chain, &chain));
}

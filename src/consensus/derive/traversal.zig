//! L1 traversal: walks L1 one block at a time, checks the parent-hash link, and applies
//! system config updates from each block's receipts.
//! Mirrors base/base `crates/consensus/derive/src/stages/traversal/polling.rs`.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");

const BlockInfo = protocol.block.BlockInfo;
const BlockId = protocol.block.BlockId;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.system_config.SystemConfig;
const Address = @import("../../common/primitives/root.zig").Address;
const Error = errors.Error;

pub const Traversal = struct {
    rollup: *const RollupConfig,
    block: ?BlockInfo = BlockInfo{},
    /// Whether the current block was handed to the next stage.
    done: bool = false,
    system_config: SystemConfig = .{},

    pub fn init(rollup: *const RollupConfig) Traversal {
        return .{ .rollup = rollup };
    }

    pub fn origin(traversal: *const Traversal) ?BlockInfo {
        return traversal.block;
    }

    pub fn batcher_address(traversal: *const Traversal) Address {
        return traversal.system_config.batcher_address;
    }

    /// Returns the current block once, then `error.Eof` until the origin advances.
    pub fn next_l1_block(traversal: *Traversal) Error!?BlockInfo {
        if (traversal.done) return error.Eof;
        traversal.done = true;
        return traversal.block;
    }

    /// Moves to the next L1 block. The system config is updated only after every fetch
    /// succeeded, so a temporary failure can be retried without double-applying logs.
    pub fn advance_origin(traversal: *Traversal, chain: anytype) Error!void {
        const block = traversal.block orelse return error.Eof;
        assert(block.number < std.math.maxInt(u64));
        const next = try chain.l1_block_info_by_number(block.number + 1);
        if (!block.hash.eql(next.parent_hash)) return error.ReorgDetected;
        const receipts = try chain.l1_receipts_by_hash(next.hash);
        const ecotone_active = traversal.rollup.is_feature_active(
            .blob_aware_l1_fees,
            next.timestamp,
        );
        _ = traversal.system_config.update_with_receipts(
            receipts,
            traversal.rollup.l1_system_config_address,
            ecotone_active,
        );
        const parent_holocene = traversal.rollup.is_feature_active(
            .strict_derivation_ordering,
            block.timestamp,
        );
        const next_holocene = traversal.rollup.is_feature_active(
            .strict_derivation_ordering,
            next.timestamp,
        );
        traversal.block = next;
        traversal.done = false;
        if (!parent_holocene and next_holocene) return error.HoloceneActivation;
    }

    pub fn reset(
        traversal: *Traversal,
        chain: anytype,
        l1_origin: BlockId,
        system_config: SystemConfig,
    ) Error!void {
        const block = try chain.l1_block_info_by_number(l1_origin.number);
        traversal.block = block;
        traversal.done = false;
        traversal.system_config = system_config;
        assert(traversal.block.?.number == l1_origin.number);
    }
};

const testing = std.testing;
const TestChain = @import("test_chain.zig").TestChain;
const primitives = @import("../../common/primitives/root.zig");
const Log = protocol.log.Log;
const Receipt = protocol.log.Receipt;

test "traversal: advance, eof, reorg, and reset" {
    var chain = TestChain.init(4, 0, 12);
    const rollup: RollupConfig = .{};
    var traversal = Traversal.init(&rollup);
    try traversal.reset(&chain, chain.blocks[0].id(), .{});
    try testing.expectEqual(@as(u64, 0), (try traversal.next_l1_block()).?.number);
    try testing.expectError(error.Eof, traversal.next_l1_block());
    try traversal.advance_origin(&chain);
    try testing.expectEqual(@as(u64, 1), (try traversal.next_l1_block()).?.number);

    chain.unavailable_from = 2;
    try testing.expectError(error.NotAvailable, traversal.advance_origin(&chain));
    try testing.expectEqual(@as(u64, 1), traversal.origin().?.number);
    chain.unavailable_from = std.math.maxInt(u64);

    chain.blocks[2].parent_hash = .zero;
    try testing.expectError(error.ReorgDetected, traversal.advance_origin(&chain));
    try testing.expectEqual(@as(u64, 1), traversal.origin().?.number);
}

test "traversal: system config update and holocene activation" {
    var chain = TestChain.init(3, 0, 12);
    var rollup: RollupConfig = .{};
    rollup.l1_system_config_address = primitives.Address.init(@splat(0x55));
    rollup.upgrades.set(.holocene, chain.blocks[1].timestamp);

    var topics = [_]primitives.B256{
        protocol.system_config.config_update_topic,
        .zero,
        .zero, // Update kind 0: batcher address.
    };
    var data: [96]u8 = @splat(0);
    data[31] = 32;
    data[63] = 32;
    @memset(data[76..96], 0xbb);
    const address = rollup.l1_system_config_address;
    const logs = [_]Log{.{ .address = address, .topics = &topics, .data = &data }};
    const receipts = [_]Receipt{.{ .success = true, .logs = &logs }};
    chain.receipts[1] = &receipts;

    var traversal = Traversal.init(&rollup);
    try traversal.reset(&chain, chain.blocks[0].id(), .{});
    try testing.expectError(error.HoloceneActivation, traversal.advance_origin(&chain));
    try testing.expectEqual(@as(u64, 1), traversal.origin().?.number);
    try testing.expect(traversal.batcher_address().eql(primitives.Address.init(@splat(0xbb))));
    try traversal.advance_origin(&chain);
}

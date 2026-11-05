//! Batch stages: decoded batches → validated singular batches for the attributes stage.
//!
//! - `BatchStream` (Holocene) expands span batches into singular batches.
//! - `BatchQueue` (pre-Holocene) buffers batches, orders them, and forces empty batches
//!   when the sequencing window expires.
//! - `BatchValidator` (Holocene) validates batches strictly in order.
//! - `BatchProvider` switches between the queue and the validator at Holocene.
//! Mirrors base/base `crates/consensus/derive/src/stages/batch/` and
//! `crates/consensus/protocol/src/batch/inclusion.rs`.
//!
//! Upstream stages are passed as `anytype`:
//! - the batch stream reads from a stage with `next_batch() Error!OwnedBatch`, `flush()`,
//!   and `origin() ?BlockInfo` (see `channel_reader.Upstream`);
//! - the queue and validator read from a stage with
//!   `next_batch(parent: L2BlockInfo, l1_origins: []const BlockInfo) Error!OwnedBatch`,
//!   `flush()`, `span_buffer_size() usize`, and `origin() ?BlockInfo`
//!   (see `BatchStream.upstream`).
//!
//! The L2 safe chain (`l2`) is a pointer to a provider with:
//!   fn l2_block_info_by_number(self, number: u64) ProviderError!L2BlockInfo
//!   fn l2_block_info_by_hash(self, hash: Hash) ProviderError!L2BlockInfo
//!   fn l2_block_by_number(self, number: u64) ProviderError!SafeBlock
//! A fetch failure during span validation leaves the batch undecided (base/base does
//! the same for every fetch error).
//!
//! Ownership: every `OwnedBatch` handed between stages belongs to the receiver. A
//! `SingleBatch` returned by the queue, validator, or provider borrows memory owned by
//! that stage and stays valid until the next call into the same stage (`next_batch`,
//! `reset`, `activate`, `flush_channel`, or `deinit`).

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const channel_reader = @import("channel_reader.zig");

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Validity = protocol.batch.Validity;
const SafeChain = protocol.span_batch.SafeChain;
const SafeBlock = protocol.span_batch.SafeBlock;
const Batch = channel_reader.Batch;
const OwnedBatch = channel_reader.OwnedBatch;

pub const BatchStream = @import("batch_stream.zig").BatchStream;
pub const BatchQueue = @import("batch_queue.zig").BatchQueue;
pub const BatchValidator = @import("batch_validator.zig").BatchValidator;
pub const BatchProvider = @import("batch_provider.zig").BatchProvider;

/// A batch and the L1 block it was included in (base/base `BatchWithInclusionBlock`).
pub const PendingBatch = struct {
    owned: OwnedBatch,
    inclusion_block: BlockInfo,
    /// Scratch flag for the batch queue's retention pass.
    keep: bool = true,

    pub fn deinit(pending: *PendingBatch) void {
        pending.owned.deinit();
        pending.* = undefined;
    }

    pub fn check(
        pending: *const PendingBatch,
        config: *const RollupConfig,
        l1_blocks: []const BlockInfo,
        safe_head: L2BlockInfo,
        chain: SafeChain,
    ) Validity {
        return check_batch(
            config,
            l1_blocks,
            safe_head,
            pending.inclusion_block,
            &pending.owned.batch,
            chain,
        );
    }
};

/// Validity of a singular or span batch (base/base `BatchWithInclusionBlock::check_batch`).
pub fn check_batch(
    config: *const RollupConfig,
    l1_blocks: []const BlockInfo,
    safe_head: L2BlockInfo,
    inclusion_block: BlockInfo,
    batch: *const Batch,
    chain: SafeChain,
) Validity {
    return switch (batch.*) {
        .single => |*single| single.check(config, l1_blocks, safe_head, inclusion_block),
        .span => |*span| span.check_batch(config, l1_blocks, safe_head, inclusion_block, chain),
    };
}

/// Adapts an `l2` provider pointer to the span batch `SafeChain` interface. Any fetch
/// error maps to null (undecided).
pub fn safe_chain(l2: anytype) SafeChain {
    const Pointer = @TypeOf(l2);
    comptime assert(@typeInfo(Pointer) == .pointer);
    const Adapter = struct {
        fn block_info(context: *anyopaque, number: u64) ?L2BlockInfo {
            const provider: Pointer = @ptrCast(@alignCast(context));
            return provider.l2_block_info_by_number(number) catch null;
        }

        fn block(context: *anyopaque, number: u64) ?SafeBlock {
            const provider: Pointer = @ptrCast(@alignCast(context));
            return provider.l2_block_by_number(number) catch null;
        }
    };
    return .{
        .context = @ptrCast(l2),
        .l2_block_info_by_number = Adapter.block_info,
        .block_by_number = Adapter.block,
    };
}

pub fn same_origin(a: ?BlockInfo, b: ?BlockInfo) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}

/// True when the upstream origin is behind the parent's L1 origin (or unknown).
pub fn origin_behind(prev_origin: ?BlockInfo, parent: L2BlockInfo) bool {
    const origin = prev_origin orelse return true;
    return origin.number < parent.l1_origin.number;
}

/// Drops L1 blocks before the parent's L1 origin when the parent moved to a later epoch.
pub fn advance_epoch(l1_blocks: *std.ArrayList(BlockInfo), parent: L2BlockInfo) void {
    const items = l1_blocks.items;
    if (items.len == 0 or parent.l1_origin.number <= items[0].number) return;
    for (items, 0..) |block, index| {
        if (block.number != parent.l1_origin.number) continue;
        std.mem.copyForwards(BlockInfo, items[0 .. items.len - index], items[index..]);
        l1_blocks.shrinkRetainingCapacity(items.len - index);
        break;
    }
    assert(l1_blocks.items.len <= items.len);
}

/// Moves `source` into `target`, leaving `source` empty (used when the provider switches
/// stages). Both lists keep using the same allocator.
pub fn move_l1_blocks(target: *std.ArrayList(BlockInfo), source: *std.ArrayList(BlockInfo)) void {
    const count = source.items.len;
    std.mem.swap(std.ArrayList(BlockInfo), target, source);
    source.clearRetainingCapacity();
    assert(source.items.len == 0);
    assert(target.items.len == count);
}

const testing = std.testing;

test "batch stage: advance epoch and origin helpers" {
    var blocks: std.ArrayList(BlockInfo) = .empty;
    defer blocks.deinit(testing.allocator);
    for (3..7) |number| try blocks.append(testing.allocator, .{ .number = number });
    advance_epoch(&blocks, .{ .l1_origin = .{ .number = 2 } });
    try testing.expectEqual(@as(usize, 4), blocks.items.len);
    advance_epoch(&blocks, .{ .l1_origin = .{ .number = 5 } });
    try testing.expectEqual(@as(usize, 2), blocks.items.len);
    try testing.expectEqual(@as(u64, 5), blocks.items[0].number);
    advance_epoch(&blocks, .{ .l1_origin = .{ .number = 9 } });
    try testing.expectEqual(@as(usize, 2), blocks.items.len);
    try testing.expect(origin_behind(null, .{}));
    try testing.expect(origin_behind(.{ .number = 1 }, .{ .l1_origin = .{ .number = 2 } }));
    try testing.expect(!origin_behind(.{ .number = 2 }, .{ .l1_origin = .{ .number = 2 } }));
    try testing.expect(same_origin(null, null));
    try testing.expect(!same_origin(.{}, null));
    try testing.expect(same_origin(.{ .number = 1 }, .{ .number = 1 }));
}

test {
    _ = @import("batch_stage_test.zig");
}

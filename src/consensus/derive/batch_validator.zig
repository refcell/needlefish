//! Batch validator (Holocene): validates singular batches strictly in order, without
//! buffering future batches, and forces empty batches once the sequencing window of the
//! current epoch expires. Mirrors base/base
//! `crates/consensus/derive/src/stages/batch/batch_validator.rs`.
//!
//! See `batch_stage.zig` for the upstream, `l2`, and ownership contracts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const channel_reader = @import("channel_reader.zig");
const batch_stage = @import("batch_stage.zig");

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const DenimTimestampSchedule = protocol.rollup_config.DenimTimestampSchedule;
const SingleBatch = protocol.batch.SingleBatch;
const OwnedBatch = channel_reader.OwnedBatch;
const PendingBatch = batch_stage.PendingBatch;
const Error = errors.Error;

/// Blocks per second once subsecond blocks are active (base/base
/// `1_000 / NATIVE_SUBSECOND_BLOCK_INTERVAL_MILLIS`).
pub const same_second_blocks: u64 = 1_000 / DenimTimestampSchedule.denim_block_interval_ms;

pub const BatchValidator = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    /// The L1 origin of the stage, last seen from upstream.
    origin: ?BlockInfo = null,
    /// The current epoch's L1 block followed by the L1 blocks seen since.
    l1_blocks: std.ArrayList(BlockInfo) = .empty,
    /// A batch kept across a temporary failure of the ancestry check.
    pending_batch: ?PendingBatch = null,
    /// Owns the last returned batch until the next call.
    returned: ?OwnedBatch = null,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) BatchValidator {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(validator: *BatchValidator) void {
        validator.clear_pending();
        validator.release_returned();
        validator.l1_blocks.deinit(validator.allocator);
        validator.* = undefined;
    }

    fn release_returned(validator: *BatchValidator) void {
        if (validator.returned) |*owned| owned.deinit();
        validator.returned = null;
        assert(validator.returned == null);
    }

    pub fn clear_pending(validator: *BatchValidator) void {
        if (validator.pending_batch) |*pending| pending.deinit();
        validator.pending_batch = null;
        assert(validator.pending_batch == null);
    }

    /// Resets to `origin` (the upstream origin after its own reset).
    pub fn reset(validator: *BatchValidator, origin: ?BlockInfo) Error!void {
        validator.release_returned();
        validator.clear_pending();
        validator.origin = origin;
        validator.l1_blocks.clearRetainingCapacity();
        if (origin) |block| try validator.l1_blocks.append(validator.allocator, block);
        assert(validator.l1_blocks.items.len <= 1);
    }

    pub fn activate(validator: *BatchValidator) void {
        validator.release_returned();
    }

    pub fn flush_channel(validator: *BatchValidator) void {
        validator.release_returned();
        validator.clear_pending();
    }

    pub fn is_last_in_span(validator: *const BatchValidator, prev: anytype) bool {
        _ = validator;
        return prev.span_buffer_size() == 0;
    }

    /// Follows the upstream origin and drops L1 blocks before the parent's epoch.
    pub fn update_origins(
        validator: *BatchValidator,
        prev: anytype,
        parent: L2BlockInfo,
    ) Error!void {
        const prev_origin = prev.origin();
        const behind = batch_stage.origin_behind(prev_origin, parent);
        if (!batch_stage.same_origin(validator.origin, prev_origin)) {
            validator.origin = prev_origin;
            if (behind) {
                validator.l1_blocks.clearRetainingCapacity();
            } else {
                const origin = prev_origin orelse return error.MissingOrigin;
                try validator.l1_blocks.append(validator.allocator, origin);
            }
        }
        batch_stage.advance_epoch(&validator.l1_blocks, parent);
        assert(validator.origin != null or behind);
    }

    /// Returns the next singular batch for `parent` (base/base
    /// `AttributesProvider::next_batch`).
    pub fn next_batch(
        validator: *BatchValidator,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
    ) Error!SingleBatch {
        validator.release_returned();
        try validator.update_origins(prev, parent);
        const stage_origin = validator.origin orelse return error.MissingOrigin;
        const behind = batch_stage.origin_behind(prev.origin(), parent);
        if (behind or parent.l1_origin.number == stage_origin.number) {
            // Drain upstream until the origin catches up.
            var drained = try prev.next_batch(parent, validator.l1_blocks.items);
            drained.deinit();
            return error.NotEnoughData;
        }
        if (validator.l1_blocks.items.len < 2) return error.MissingOrigin;
        const epoch = validator.l1_blocks.items[0];
        if (!parent.l1_origin.eql(epoch.id()) and parent.l1_origin.number +| 1 != epoch.number) {
            return error.L1OriginMismatch;
        }
        var pending = validator.take_pending(prev, parent, stage_origin) catch |err| {
            if (err != error.Eof) return err;
            return validator.try_derive_empty_batch(parent);
        };
        if (try validator.stale_same_second(l2, &pending, parent)) {
            pending.deinit();
            return error.NotEnoughData;
        }
        return validator.validate(prev, pending, parent);
    }

    /// The batch kept from a previous call, or the next upstream batch.
    fn take_pending(
        validator: *BatchValidator,
        prev: anytype,
        parent: L2BlockInfo,
        stage_origin: BlockInfo,
    ) Error!PendingBatch {
        if (validator.pending_batch) |pending| {
            validator.pending_batch = null;
            return pending;
        }
        var owned = try prev.next_batch(parent, validator.l1_blocks.items);
        if (owned.batch != .single) {
            owned.deinit();
            return error.InvalidBatchType;
        }
        assert(validator.pending_batch == null);
        return .{ .owned = owned, .inclusion_block = stage_origin };
    }

    fn validate(
        validator: *BatchValidator,
        prev: anytype,
        pending: PendingBatch,
        parent: L2BlockInfo,
    ) Error!SingleBatch {
        var batch = pending;
        const single = &batch.owned.batch.single;
        const validity = single.check(
            validator.rollup,
            validator.l1_blocks.items,
            parent,
            batch.inclusion_block,
        );
        switch (validity) {
            .accept => {
                assert(validator.returned == null);
                validator.returned = batch.owned;
                return validator.returned.?.batch.single;
            },
            .past, .undecided => {
                batch.deinit();
                return error.NotEnoughData;
            },
            .drop => {
                batch.deinit();
                prev.flush();
                return error.NotEnoughData;
            },
            .future => {
                batch.deinit();
                return error.InvalidBatchValidity;
            },
        }
    }

    /// Subsecond blocks: true when the batch builds on a canonical ancestor within the
    /// same second as the next block (a stale batch to skip without flushing). A
    /// temporary provider failure keeps the batch for the next call.
    fn stale_same_second(
        validator: *BatchValidator,
        l2: anytype,
        pending: *PendingBatch,
        parent: L2BlockInfo,
    ) Error!bool {
        const rollup = validator.rollup;
        const batch = &pending.owned.batch.single;
        const next_timestamp = rollup.l2_block_timestamp(parent.block_info.number +| 1);
        if (!rollup.is_feature_active(.subsecond_blocks, next_timestamp)) return false;
        if (batch.timestamp != next_timestamp) return false;
        if (batch.parent_hash.eql(parent.block_info.hash)) return false;
        const first = @max(
            parent.block_info.number -| same_second_blocks,
            rollup.genesis.l2.number,
        );
        var ancestor_hash = parent.block_info.parent_hash;
        var number = parent.block_info.number;
        // At most `same_second_blocks` iterations.
        while (number > first) {
            number -= 1;
            if (rollup.l2_block_timestamp(number +| 1) != batch.timestamp) break;
            if (ancestor_hash.eql(batch.parent_hash)) return true;
            if (number == first or rollup.l2_block_timestamp(number) != batch.timestamp) break;
            const ancestor = l2.l2_block_info_by_hash(ancestor_hash) catch |err| {
                if (errors.kind(err) == .temporary) {
                    validator.pending_batch = pending.*;
                } else {
                    pending.deinit();
                }
                return err;
            };
            ancestor_hash = ancestor.block_info.parent_hash;
        }
        assert(number >= first);
        return false;
    }

    /// Forces an empty batch at sequencing window expiry, or advances the epoch.
    pub fn try_derive_empty_batch(
        validator: *BatchValidator,
        parent: L2BlockInfo,
    ) Error!SingleBatch {
        assert(validator.l1_blocks.items.len >= 2);
        const rollup = validator.rollup;
        const epoch = validator.l1_blocks.items[0];
        const stage_origin = validator.origin orelse return error.MissingOrigin;
        const expiry_epoch = epoch.number +| rollup.seq_window_size;
        if (expiry_epoch > stage_origin.number) return error.Eof;
        const next_timestamp = rollup.l2_block_timestamp(parent.block_info.number +| 1);
        const first_of_epoch = epoch.number == parent.l1_origin.number +| 1;
        const same_second = rollup.is_feature_active(.subsecond_blocks, next_timestamp) and
            next_timestamp == parent.block_info.timestamp;
        const next_epoch = validator.l1_blocks.items[1];
        if (next_timestamp < next_epoch.timestamp or first_of_epoch or same_second) {
            return .{
                .parent_hash = parent.block_info.hash,
                .epoch_num = epoch.number,
                .epoch_hash = epoch.hash,
                .timestamp = next_timestamp,
                .transactions = &.{},
            };
        }
        _ = validator.l1_blocks.orderedRemove(0);
        assert(validator.l1_blocks.items.len > 0);
        return error.Eof;
    }
};

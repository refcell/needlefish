//! Batch provider: runs the batch queue before Holocene and the batch validator after,
//! switching on the upstream origin. Switching carries the L1 block window (and, into
//! the validator, the origin) exactly as base/base does; the old stage's buffered
//! batches are dropped. Mirrors base/base
//! `crates/consensus/derive/src/stages/batch/batch_provider.rs`.
//!
//! See `batch_stage.zig` for the upstream, `l2`, and ownership contracts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const batch_stage = @import("batch_stage.zig");
const BatchQueue = @import("batch_queue.zig").BatchQueue;
const BatchValidator = @import("batch_validator.zig").BatchValidator;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SingleBatch = protocol.batch.SingleBatch;
const Error = errors.Error;

pub const Mode = enum { unset, queue, validator };

pub const BatchProvider = struct {
    rollup: *const RollupConfig,
    mode: Mode = .unset,
    queue: BatchQueue,
    validator: BatchValidator,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) BatchProvider {
        return .{
            .rollup = rollup,
            .queue = BatchQueue.init(allocator, rollup),
            .validator = BatchValidator.init(allocator, rollup),
        };
    }

    pub fn deinit(provider: *BatchProvider) void {
        provider.queue.deinit();
        provider.validator.deinit();
        provider.* = undefined;
    }

    /// Selects the stage for the upstream origin, carrying state across the switch.
    pub fn attempt_update(provider: *BatchProvider, prev: anytype) Error!void {
        const origin = prev.origin() orelse return error.MissingOrigin;
        const holocene = provider.rollup.is_feature_active(
            .strict_derivation_ordering,
            origin.timestamp,
        );
        switch (provider.mode) {
            .unset => provider.mode = if (holocene) .validator else .queue,
            .queue => if (holocene) {
                const queue = &provider.queue;
                const validator = &provider.validator;
                try validator.reset(null);
                batch_stage.move_l1_blocks(&validator.l1_blocks, &queue.l1_blocks);
                validator.origin = queue.origin;
                try queue.reset(null);
                provider.mode = .validator;
            },
            .validator => if (!holocene) {
                const queue = &provider.queue;
                const validator = &provider.validator;
                try queue.reset(null);
                batch_stage.move_l1_blocks(&queue.l1_blocks, &validator.l1_blocks);
                try validator.reset(null);
                provider.mode = .queue;
            },
        }
        assert(provider.mode != .unset);
    }

    pub fn next_batch(
        provider: *BatchProvider,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
    ) Error!SingleBatch {
        try provider.attempt_update(prev);
        return switch (provider.mode) {
            .queue => provider.queue.next_batch(prev, l2, parent),
            .validator => provider.validator.next_batch(prev, l2, parent),
            .unset => unreachable, // Proof: attempt_update always sets a mode.
        };
    }

    /// Resets the active stage; `prev` must already be reset.
    pub fn reset(provider: *BatchProvider, prev: anytype) Error!void {
        try provider.attempt_update(prev);
        const origin = prev.origin();
        assert(origin != null);
        switch (provider.mode) {
            .queue => try provider.queue.reset(origin),
            .validator => try provider.validator.reset(origin),
            .unset => unreachable, // Proof: attempt_update always sets a mode.
        }
    }

    pub fn activate(provider: *BatchProvider, prev: anytype) Error!void {
        try provider.attempt_update(prev);
        switch (provider.mode) {
            .queue => provider.queue.activate(),
            .validator => provider.validator.activate(),
            .unset => unreachable, // Proof: attempt_update always sets a mode.
        }
        assert(provider.mode != .unset);
    }

    pub fn flush_channel(provider: *BatchProvider, prev: anytype) Error!void {
        try provider.attempt_update(prev);
        switch (provider.mode) {
            .queue => provider.queue.flush_channel(),
            .validator => provider.validator.flush_channel(),
            .unset => unreachable, // Proof: attempt_update always sets a mode.
        }
        assert(provider.mode != .unset);
    }

    pub fn is_last_in_span(provider: *const BatchProvider, prev: anytype) bool {
        return switch (provider.mode) {
            .queue => provider.queue.is_last_in_span(),
            .validator => provider.validator.is_last_in_span(prev),
            .unset => false,
        };
    }

    /// Binds the provider to its upstream and `l2` provider so the attributes queue can
    /// read singular batches from it.
    pub fn upstream(
        provider: *BatchProvider,
        prev: anytype,
        l2: anytype,
    ) Upstream(@TypeOf(prev), @TypeOf(l2)) {
        return .{ .provider = provider, .prev = prev, .l2 = l2 };
    }
};

/// The batch provider seen as a stage by the attributes queue.
pub fn Upstream(comptime Prev: type, comptime L2: type) type {
    return struct {
        provider: *BatchProvider,
        prev: Prev,
        l2: L2,

        const Self = @This();

        pub fn next_batch(self: Self, parent: L2BlockInfo) Error!SingleBatch {
            return self.provider.next_batch(self.prev, self.l2, parent);
        }

        pub fn is_last_in_span(self: Self) bool {
            return self.provider.is_last_in_span(self.prev);
        }

        pub fn origin(self: Self) ?BlockInfo {
            return self.prev.origin();
        }
    };
}

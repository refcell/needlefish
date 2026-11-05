//! Batch stream (Holocene): buffers one span batch at a time and hands out its singular
//! batches in order; singular batches pass straight through. Before Holocene the stage
//! is a pass-through. Mirrors base/base
//! `crates/consensus/derive/src/stages/batch/batch_stream.rs`.
//!
//! See `batch_stage.zig` for the upstream and `l2` provider contracts. Every returned
//! `OwnedBatch` belongs to the caller; span-derived singular batches are deep copies.

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
const SingleBatch = protocol.batch.SingleBatch;
const OwnedBatch = channel_reader.OwnedBatch;
const Error = errors.Error;

pub const BatchStream = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    /// The staged span batch, accepted by the prefix check but not yet expanded.
    span: ?OwnedBatch = null,
    /// Owns the memory behind `buffer` (the expanded span batch).
    buffer_owner: ?OwnedBatch = null,
    /// Singular batches derived from the span; `buffer[cursor..]` are still pending.
    buffer: []SingleBatch = &.{},
    cursor: usize = 0,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) BatchStream {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(stream: *BatchStream) void {
        stream.clear();
        stream.* = undefined;
    }

    /// Drops the staged span and the buffer (reset, activation, channel flush).
    pub fn clear(stream: *BatchStream) void {
        if (stream.span) |*span| span.deinit();
        if (stream.buffer_owner) |*owner| owner.deinit();
        stream.span = null;
        stream.buffer_owner = null;
        stream.buffer = &.{};
        stream.cursor = 0;
        assert(stream.span_buffer_size() == 0);
    }

    pub fn span_buffer_size(stream: *const BatchStream) usize {
        assert(stream.cursor <= stream.buffer.len);
        return stream.buffer.len - stream.cursor;
    }

    pub fn is_active(stream: *const BatchStream, prev: anytype) Error!bool {
        const origin = prev.origin() orelse return error.MissingOrigin;
        return stream.rollup.is_feature_active(.strict_derivation_ordering, origin.timestamp);
    }

    /// Flushes the stage and the upstream channel, post-Holocene only.
    pub fn flush(stream: *BatchStream, prev: anytype) void {
        const active = stream.is_active(prev) catch false;
        if (!active) return;
        prev.flush();
        stream.clear();
    }

    pub fn next_batch(
        stream: *BatchStream,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
        l1_origins: []const BlockInfo,
    ) Error!OwnedBatch {
        // A non-empty buffer is always backed by its owner.
        assert(stream.span_buffer_size() == 0 or stream.buffer_owner != null);
        assert(stream.span == null or stream.span.?.batch == .span);
        if (!try stream.is_active(prev)) return prev.next_batch();
        const next_number = parent.block_info.number +| 1;
        const next_timestamp = stream.rollup.l2_block_timestamp(next_number);
        const denim = stream.rollup.is_feature_active(.singular_batches_only, next_timestamp);
        if (denim and (stream.span != null or stream.span_buffer_size() > 0)) {
            stream.flush(prev);
            return error.NotEnoughData;
        }
        if (stream.span_buffer_size() == 0) {
            if (try stream.pull(prev, l2, parent, l1_origins)) |single| return single;
        }
        return stream.pop_single(prev, parent, l1_origins);
    }

    /// Pulls the next upstream batch. Singular batches are returned; an accepted span
    /// batch is staged and null is returned.
    fn pull(
        stream: *BatchStream,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
        l1_origins: []const BlockInfo,
    ) Error!?OwnedBatch {
        assert(stream.span == null);
        const inclusion_block = prev.origin() orelse return error.MissingOrigin;
        var owned = try prev.next_batch();
        if (owned.batch == .single) return owned;
        const prefix = owned.batch.span.check_batch_prefix(
            stream.rollup,
            l1_origins,
            parent,
            inclusion_block,
            batch_stage.safe_chain(l2),
        );
        if (prefix.validity == .accept) {
            stream.span = owned;
            return null;
        }
        owned.deinit();
        switch (prefix.validity) {
            .accept => unreachable, // Proof: handled above.
            .drop => {
                stream.flush(prev);
                return error.NotEnoughData;
            },
            .past => {
                if (!try stream.is_active(prev)) return error.InvalidBatchValidity;
                return error.NotEnoughData;
            },
            .undecided, .future => return error.NotEnoughData,
        }
    }

    /// Expands the staged span if any, then copies out the next buffered singular batch
    /// with its parent hash set.
    fn pop_single(
        stream: *BatchStream,
        prev: anytype,
        parent: L2BlockInfo,
        l1_origins: []const BlockInfo,
    ) Error!OwnedBatch {
        if (stream.span) |span| {
            assert(stream.span_buffer_size() == 0);
            stream.span = null;
            if (stream.buffer_owner) |*owner| owner.deinit();
            stream.buffer_owner = span;
            stream.buffer = &.{};
            stream.cursor = 0;
            const owner = &stream.buffer_owner.?;
            stream.buffer = owner.batch.span.get_singular_batches(
                owner.arena.allocator(),
                l1_origins,
                parent,
            ) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                // Extraction failure is handled like a dropped batch.
                stream.flush(prev);
                return error.NotEnoughData;
            };
        }
        if (stream.span_buffer_size() == 0) return error.NotEnoughData;
        assert(stream.buffer_owner != null);
        var single = stream.buffer[stream.cursor];
        stream.cursor += 1;
        single.parent_hash = parent.block_info.hash;
        const owned = try OwnedBatch.from_single(stream.allocator, &single);
        if (stream.span_buffer_size() == 0) {
            stream.buffer_owner.?.deinit();
            stream.buffer_owner = null;
            stream.buffer = &.{};
            stream.cursor = 0;
        }
        return owned;
    }

    /// Binds the stream to its upstream and `l2` provider so the queue and validator can
    /// read from it.
    pub fn upstream(
        stream: *BatchStream,
        prev: anytype,
        l2: anytype,
    ) Upstream(@TypeOf(prev), @TypeOf(l2)) {
        return .{ .stream = stream, .prev = prev, .l2 = l2 };
    }
};

/// The batch stream seen as a stage by the batch queue and validator.
pub fn Upstream(comptime Prev: type, comptime L2: type) type {
    return struct {
        stream: *BatchStream,
        prev: Prev,
        l2: L2,

        const Self = @This();

        pub fn next_batch(
            self: Self,
            parent: L2BlockInfo,
            l1_origins: []const BlockInfo,
        ) Error!OwnedBatch {
            return self.stream.next_batch(self.prev, self.l2, parent, l1_origins);
        }

        pub fn flush(self: Self) void {
            self.stream.flush(self.prev);
        }

        pub fn span_buffer_size(self: Self) usize {
            return self.stream.span_buffer_size();
        }

        pub fn origin(self: Self) ?BlockInfo {
            return self.prev.origin();
        }
    };
}

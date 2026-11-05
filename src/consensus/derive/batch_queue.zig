//! Batch queue (pre-Holocene): buffers batches with their inclusion block, picks the
//! next valid batch for the safe head, and forces empty batches once the sequencing
//! window of the current epoch expires. Accepted span batches are expanded and their
//! singular batches handed out one per call. Mirrors base/base
//! `crates/consensus/derive/src/stages/batch/batch_queue.rs`.
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
const SingleBatch = protocol.batch.SingleBatch;
const OwnedBatch = channel_reader.OwnedBatch;
const PendingBatch = batch_stage.PendingBatch;
const Error = errors.Error;

/// The result of `derive_next_batch`: a buffered batch (now owned by the caller) or a
/// forced empty batch.
pub const Derived = union(enum) {
    owned: OwnedBatch,
    empty: SingleBatch,
};

pub const BatchQueue = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    /// The L1 origin of the stage, last seen from upstream.
    origin: ?BlockInfo = null,
    /// The current epoch's L1 block followed by the L1 blocks seen since.
    l1_blocks: std.ArrayList(BlockInfo) = .empty,
    /// Buffered batches, in arrival order.
    batches: std.ArrayList(PendingBatch) = .empty,
    /// Owns the span batch behind `next_spans`.
    span_owner: ?OwnedBatch = null,
    /// Singular batches of the accepted span; `next_spans[spans_cursor..]` are pending.
    next_spans: []SingleBatch = &.{},
    spans_cursor: usize = 0,
    /// Owns the last returned batch until the next call.
    returned: ?OwnedBatch = null,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) BatchQueue {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(queue: *BatchQueue) void {
        queue.clear_batches();
        queue.release_returned();
        queue.l1_blocks.deinit(queue.allocator);
        queue.batches.deinit(queue.allocator);
        queue.* = undefined;
    }

    fn release_returned(queue: *BatchQueue) void {
        if (queue.returned) |*owned| owned.deinit();
        queue.returned = null;
        assert(queue.returned == null);
    }

    pub fn clear_next_spans(queue: *BatchQueue) void {
        if (queue.span_owner) |*owner| owner.deinit();
        queue.span_owner = null;
        queue.next_spans = &.{};
        queue.spans_cursor = 0;
        assert(queue.is_last_in_span());
    }

    fn clear_batches(queue: *BatchQueue) void {
        for (queue.batches.items) |*pending| pending.deinit();
        queue.batches.clearRetainingCapacity();
        queue.clear_next_spans();
        assert(queue.batches.items.len == 0);
    }

    pub fn is_last_in_span(queue: *const BatchQueue) bool {
        assert(queue.spans_cursor <= queue.next_spans.len);
        return queue.spans_cursor == queue.next_spans.len;
    }

    /// Resets to `origin` (the upstream origin after its own reset).
    pub fn reset(queue: *BatchQueue, origin: ?BlockInfo) Error!void {
        queue.release_returned();
        queue.clear_batches();
        queue.origin = origin;
        queue.l1_blocks.clearRetainingCapacity();
        if (origin) |block| try queue.l1_blocks.append(queue.allocator, block);
        assert(queue.l1_blocks.items.len <= 1);
    }

    pub fn activate(queue: *BatchQueue) void {
        queue.release_returned();
        queue.clear_batches();
    }

    pub fn flush_channel(queue: *BatchQueue) void {
        queue.release_returned();
        queue.clear_batches();
    }

    /// Pops the next span-derived singular batch with its parent hash set. Borrows
    /// `span_owner`.
    pub fn pop_next_batch(queue: *BatchQueue, parent: L2BlockInfo) ?SingleBatch {
        if (queue.is_last_in_span()) return null;
        var next = queue.next_spans[queue.spans_cursor];
        queue.spans_cursor += 1;
        next.parent_hash = parent.block_info.hash;
        assert(queue.spans_cursor <= queue.next_spans.len);
        return next;
    }

    /// Returns the next singular batch for `parent` (base/base
    /// `AttributesProvider::next_batch`).
    pub fn next_batch(
        queue: *BatchQueue,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
    ) Error!SingleBatch {
        queue.release_returned();
        if (queue.is_last_in_span()) queue.clear_next_spans();
        if (queue.cached_span_batch(parent)) |single| return single;
        batch_stage.advance_epoch(&queue.l1_blocks, parent);
        const behind = batch_stage.origin_behind(prev.origin(), parent);
        try queue.update_origin(prev, behind);
        // Deviation from base/base: advance again after the new origin is appended, as the
        // Holocene batch validator does. A reset point one L1 block behind the parent's origin
        // (always the case near genesis) otherwise leaves [reset origin, parent origin] here,
        // and every step fails L1OriginMismatch, resets, and rebuilds the same state.
        batch_stage.advance_epoch(&queue.l1_blocks, parent);

        var out_of_data = false;
        if (prev.next_batch(parent, queue.l1_blocks.items)) |owned| {
            var batch = owned;
            if (behind) {
                batch.deinit();
            } else {
                queue.add_batch(prev, l2, batch, parent) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                };
            }
        } else |err| {
            if (err != error.Eof) return err;
            out_of_data = true;
        }
        if (behind) return if (out_of_data) error.Eof else error.NotEnoughData;

        const derived = queue.derive_next_batch(prev, l2, out_of_data, parent) catch |err| {
            if (err != error.Eof) return err;
            return if (out_of_data) error.Eof else error.NotEnoughData;
        };
        return queue.emit(derived, parent);
    }

    /// Serves a cached span-derived batch when it matches the next block; otherwise
    /// drops the cache. Denim drops it unconditionally.
    fn cached_span_batch(queue: *BatchQueue, parent: L2BlockInfo) ?SingleBatch {
        const next_timestamp = queue.rollup.l2_block_timestamp(parent.block_info.number +| 1);
        const denim = queue.rollup.is_feature_active(.singular_batches_only, next_timestamp);
        if (denim and !queue.is_last_in_span()) queue.clear_next_spans();
        if (queue.is_last_in_span()) return null;
        if (queue.next_spans[queue.spans_cursor].timestamp == next_timestamp) {
            return queue.pop_next_batch(parent);
        }
        queue.clear_next_spans();
        assert(queue.is_last_in_span());
        return null;
    }

    fn update_origin(queue: *BatchQueue, prev: anytype, behind: bool) Error!void {
        const prev_origin = prev.origin();
        if (batch_stage.same_origin(queue.origin, prev_origin)) return;
        queue.origin = prev_origin;
        if (behind) {
            queue.l1_blocks.clearRetainingCapacity();
        } else {
            try queue.l1_blocks.append(queue.allocator, prev_origin orelse
                return error.MissingOrigin);
        }
        assert(queue.origin != null or behind);
    }

    fn emit(queue: *BatchQueue, derived: Derived, parent: L2BlockInfo) Error!SingleBatch {
        assert(queue.returned == null);
        switch (derived) {
            .empty => |single| return single,
            .owned => |owned| switch (owned.batch) {
                .single => |single| {
                    queue.returned = owned;
                    return single;
                },
                .span => return queue.expand_span(owned, parent),
            },
        }
    }

    fn expand_span(queue: *BatchQueue, owned: OwnedBatch, parent: L2BlockInfo) Error!SingleBatch {
        assert(owned.batch == .span);
        assert(queue.span_owner == null);
        queue.span_owner = owned;
        const owner = &queue.span_owner.?;
        const singles = owner.batch.span.get_singular_batches(
            owner.arena.allocator(),
            queue.l1_blocks.items,
            parent,
        ) catch |err| {
            queue.clear_next_spans();
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return error.BadEncoding;
        };
        queue.next_spans = singles;
        queue.spans_cursor = 0;
        return queue.pop_next_batch(parent) orelse error.BatchQueueEmpty;
    }

    /// Buffers `owned` unless it is invalid now (base/base `add_batch`). Takes ownership.
    pub fn add_batch(
        queue: *BatchQueue,
        prev: anytype,
        l2: anytype,
        owned: OwnedBatch,
        parent: L2BlockInfo,
    ) Error!void {
        var batch = owned;
        if (queue.l1_blocks.items.len == 0) {
            // base/base panics here; the batch is dropped instead.
            batch.deinit();
            return error.MissingOrigin;
        }
        const origin = queue.origin orelse {
            batch.deinit();
            return error.MissingOrigin;
        };
        const pending: PendingBatch = .{ .owned = batch, .inclusion_block = origin };
        const chain = batch_stage.safe_chain(l2);
        const validity = pending.check(queue.rollup, queue.l1_blocks.items, parent, chain);
        const holocene = queue.rollup.is_feature_active(
            .strict_derivation_ordering,
            origin.timestamp,
        );
        if (validity == .drop or (holocene and validity == .future)) {
            prev.flush();
            batch.deinit();
            return;
        }
        if (validity == .past) {
            batch.deinit();
            return;
        }
        queue.batches.append(queue.allocator, pending) catch |err| {
            batch.deinit();
            return err;
        };
        assert(queue.batches.items.len > 0);
    }

    /// Picks the next batch for `parent`, or a forced empty batch at sequencing window
    /// expiry. `error.Eof` means no batch is ready.
    pub fn derive_next_batch(
        queue: *BatchQueue,
        prev: anytype,
        l2: anytype,
        empty: bool,
        parent: L2BlockInfo,
    ) Error!Derived {
        if (queue.l1_blocks.items.len == 0) return error.MissingOrigin;
        const epoch = queue.l1_blocks.items[0];
        const parent_on_epoch = parent.l1_origin.eql(epoch.id());
        const parent_on_previous = epoch.number > 0 and
            parent.l1_origin.number == epoch.number - 1;
        if (!parent_on_epoch and !parent_on_previous) return error.L1OriginMismatch;
        const origin = queue.origin orelse return error.MissingOrigin;
        if (try queue.select_batch(prev, l2, parent, origin)) |owned| return .{ .owned = owned };
        return .{ .empty = try queue.force_empty_batch(empty, parent, origin) };
    }

    /// Checks buffered batches in order: returns the first accepted one, drops invalid
    /// ones, and keeps future ones. The retention decisions only apply when the pass
    /// completes, accepts, or is undecided, as in base/base.
    fn select_batch(
        queue: *BatchQueue,
        prev: anytype,
        l2: anytype,
        parent: L2BlockInfo,
        origin: BlockInfo,
    ) Error!?OwnedBatch {
        const holocene = queue.rollup.is_feature_active(
            .strict_derivation_ordering,
            origin.timestamp,
        );
        const chain = batch_stage.safe_chain(l2);
        const items = queue.batches.items;
        for (items, 0..) |*pending, index| {
            switch (pending.check(queue.rollup, queue.l1_blocks.items, parent, chain)) {
                .future => {
                    pending.keep = !holocene;
                    if (holocene) prev.flush();
                },
                .drop => {
                    pending.keep = false;
                    prev.flush();
                },
                .accept => {
                    const accepted = pending.owned;
                    pending.keep = false;
                    queue.apply_retention(index, accepted);
                    return accepted;
                },
                .undecided => {
                    queue.apply_retention(index, null);
                    return error.Eof;
                },
                .past => {
                    if (!holocene) {
                        for (items[0..index]) |*decided| decided.keep = true;
                        return error.InvalidBatchValidity;
                    }
                    pending.keep = false;
                },
            }
        }
        queue.apply_retention(items.len, null);
        return null;
    }

    /// Frees the batches before `decided_end` marked as not kept (except `accepted`,
    /// whose ownership moves to the caller) and compacts the list. Batches at and after
    /// `decided_end` are kept, except an accepted one.
    fn apply_retention(queue: *BatchQueue, decided_end: usize, accepted: ?OwnedBatch) void {
        const items = queue.batches.items;
        assert(decided_end <= items.len);
        var write: usize = 0;
        for (items, 0..) |*pending, index| {
            const decided = index < decided_end or (accepted != null and index == decided_end);
            if (decided and !pending.keep) {
                if (!(accepted != null and index == decided_end)) pending.deinit();
                continue;
            }
            pending.keep = true;
            items[write] = pending.*;
            write += 1;
        }
        queue.batches.shrinkRetainingCapacity(write);
        assert(queue.batches.items.len <= items.len);
    }

    fn force_empty_batch(
        queue: *BatchQueue,
        empty: bool,
        parent: L2BlockInfo,
        origin: BlockInfo,
    ) Error!SingleBatch {
        const epoch = queue.l1_blocks.items[0];
        const expiry_epoch = epoch.number +| queue.rollup.seq_window_size;
        const force_empty_batches = (expiry_epoch == origin.number and empty) or
            expiry_epoch < origin.number;
        if (!force_empty_batches) return error.Eof;
        if (queue.l1_blocks.items.len < 2) return error.Eof;
        const next_timestamp = queue.rollup.l2_block_timestamp(parent.block_info.number +| 1);
        const first_of_epoch = epoch.number == parent.l1_origin.number +| 1;
        const same_second = queue.rollup.is_feature_active(.subsecond_blocks, next_timestamp) and
            next_timestamp == parent.block_info.timestamp;
        const next_epoch = queue.l1_blocks.items[1];
        if (next_timestamp < next_epoch.timestamp or first_of_epoch or same_second) {
            return .{
                .parent_hash = parent.block_info.hash,
                .epoch_num = epoch.number,
                .epoch_hash = epoch.hash,
                .timestamp = next_timestamp,
                .transactions = &.{},
            };
        }
        _ = queue.l1_blocks.orderedRemove(0);
        assert(queue.l1_blocks.items.len > 0);
        return error.Eof;
    }
};

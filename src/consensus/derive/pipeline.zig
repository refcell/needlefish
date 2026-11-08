//! The derivation pipeline: owns every stage, steps them to prepare payload attributes,
//! and dispatches signals (reset, activation, channel flush) to each stage upstream-first.
//! Mirrors base/base `crates/consensus/derive/src/pipeline/{core,builder}.rs` and
//! `types/{signals,results}.rs`.
//!
//! Providers are passed per call (`anytype`, see `providers.zig`, `batch_stage.zig`):
//! - `chain`: L1 blocks, receipts, transactions, and headers;
//! - `blobs`: blob provider;
//! - `l2`: the L2 safe chain plus `system_config_by_l2_hash(hash)`.
//! Stages do not own their upstream: each call binds them into a stack.
//!
//! Prepared attributes are buffered in a bounded queue (base/base: unbounded). When it is
//! full, `step` fails with the temporary `error.PreparedAttributesFull` until drained.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const Retrieval = @import("retrieval.zig").Retrieval;
const FrameQueue = @import("frame_queue.zig").FrameQueue;
const ChannelProvider = @import("channel_stage.zig").ChannelProvider;
const channel_reader = @import("channel_reader.zig");
const batch_stream = @import("batch_stream.zig");
const batch_provider = @import("batch_provider.zig");
const attributes_queue = @import("attributes_queue.zig");

const BlockInfo = protocol.block.BlockInfo;
const BlockId = protocol.block.BlockId;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const Frame = protocol.frame.Frame;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.SystemConfig;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;
const ChannelReader = channel_reader.ChannelReader;
const BatchStream = batch_stream.BatchStream;
const BatchProvider = batch_provider.BatchProvider;
const AttributesQueue = attributes_queue.AttributesQueue;
const BuilderChain = attributes_queue.BuilderChain;
pub const AttributesWithParent = attributes_queue.AttributesWithParent;
const Error = errors.Error;

/// Upper bound on prepared attributes awaiting the driver.
pub const prepared_max = 16;

pub const ResetSignal = struct { l2_safe_head: L2BlockInfo = .{} };
pub const ActivationSignal = struct { l2_safe_head: L2BlockInfo = .{} };

/// A signal sent down the pipeline by the driver.
pub const Signal = union(enum) {
    /// Rewind to an L1 origin safe for `l2_safe_head` and clear every stage.
    reset: ResetSignal,
    /// Upgrade activation (Holocene): clear buffers, keep origin and system config.
    activation: ActivationSignal,
    /// Drop the active channel.
    flush_channel,
};

pub const StepResult = union(enum) {
    prepared_attributes,
    advanced_origin,
    origin_advance_err: Error,
    step_failed: Error,
};

/// The L1 origin and system config a reset rewinds to.
pub const ResetPoint = struct { l1_origin: BlockId, system_config: SystemConfig };

/// The frame queue bound to retrieval and the L1 providers, as seen by the channel stage.
fn FrameSource(comptime Chain: type, comptime Blobs: type) type {
    return struct {
        queue: *FrameQueue,
        retrieval: *Retrieval,
        chain: Chain,
        blobs: Blobs,

        const Self = @This();

        pub fn next_frame(self: Self) Error!Frame {
            return self.queue.next_frame(self.retrieval, self.chain, self.blobs);
        }

        pub fn origin(self: Self) ?BlockInfo {
            return self.retrieval.origin();
        }
    };
}

fn ReaderUpstream(comptime Chain: type, comptime Blobs: type) type {
    return channel_reader.Upstream(*ChannelProvider, FrameSource(Chain, Blobs));
}

fn StreamUpstream(comptime Chain: type, comptime Blobs: type, comptime L2: type) type {
    return batch_stream.Upstream(ReaderUpstream(Chain, Blobs), L2);
}

fn BatchesUpstream(comptime Chain: type, comptime Blobs: type, comptime L2: type) type {
    return batch_provider.Upstream(StreamUpstream(Chain, Blobs, L2), L2);
}

/// The upstream of the batch provider for signals, which only read the origin.
const OriginSource = struct {
    retrieval: *const Retrieval,

    pub fn origin(self: OriginSource) ?BlockInfo {
        return self.retrieval.origin();
    }
};

pub const Pipeline = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    retrieval: Retrieval,
    frame_queue: FrameQueue,
    channel_provider: ChannelProvider,
    channel_reader: ChannelReader,
    batch_stream: BatchStream,
    batch_provider: BatchProvider,
    attributes_queue: AttributesQueue,
    /// Ring buffer of prepared attributes: `prepared[head..][0..count]` (wrapping).
    prepared: [prepared_max]AttributesWithParent = undefined,
    prepared_head: u32 = 0,
    prepared_count: u32 = 0,
    /// The reset walk-back in progress (`initial_reset`), kept when an L2 block is not yet
    /// available and resumed by the next retry for the same safe head. On 200 ms blocks a
    /// channel timeout spans thousands of L2 blocks, more than an L2 provider caches, so a
    /// walk restarted from the safe head on every retry would never finish.
    reset_walk: ?ResetWalk = null,
    /// A finished walk-back's point, kept while the reset's L1 half is not yet available.
    reset_point: ?KeptResetPoint = null,

    const ResetWalk = struct { safe_hash: Hash, current: L2BlockInfo };
    const KeptResetPoint = struct { safe_hash: Hash, point: ResetPoint };

    /// Builds the stage stack starting at L1 `origin` with the genesis system config
    /// (base/base `PipelineBuilder`). Drivers usually send a reset before stepping.
    pub fn init(
        allocator: Allocator,
        rollup: *const RollupConfig,
        blob_schedule: *const L1BlobSchedule,
        start_origin: BlockInfo,
    ) Pipeline {
        var pipeline: Pipeline = .{
            .allocator = allocator,
            .rollup = rollup,
            .retrieval = Retrieval.init(allocator, rollup),
            .frame_queue = FrameQueue.init(allocator, rollup),
            .channel_provider = ChannelProvider.init(allocator, rollup),
            .channel_reader = ChannelReader.init(allocator, rollup),
            .batch_stream = BatchStream.init(allocator, rollup),
            .batch_provider = BatchProvider.init(allocator, rollup),
            .attributes_queue = AttributesQueue.init(allocator, rollup, blob_schedule),
        };
        pipeline.retrieval.traversal.block = start_origin;
        if (rollup.genesis.system_config) |config| {
            pipeline.retrieval.traversal.system_config = config;
        }
        assert(pipeline.origin().?.eql(start_origin));
        assert(pipeline.prepared_count == 0);
        return pipeline;
    }

    pub fn deinit(pipeline: *Pipeline) void {
        while (pipeline.next()) |prepared| {
            var owned = prepared;
            owned.deinit(pipeline.allocator);
        }
        assert(pipeline.prepared_count == 0);
        pipeline.batch_provider.deinit();
        pipeline.batch_stream.deinit();
        pipeline.channel_reader.deinit();
        pipeline.channel_provider.deinit();
        pipeline.frame_queue.deinit();
        pipeline.retrieval.deinit();
        pipeline.* = undefined;
    }

    pub fn rollup_config(pipeline: *const Pipeline) *const RollupConfig {
        return pipeline.rollup;
    }

    /// The current L1 origin of the pipeline.
    pub fn origin(pipeline: *const Pipeline) ?BlockInfo {
        return pipeline.retrieval.origin();
    }

    pub fn prepared_len(pipeline: *const Pipeline) u32 {
        assert(pipeline.prepared_count <= prepared_max);
        assert(pipeline.prepared_head < prepared_max);
        return pipeline.prepared_count;
    }

    /// The oldest prepared attributes, still owned by the pipeline.
    pub fn peek(pipeline: *const Pipeline) ?*const AttributesWithParent {
        if (pipeline.prepared_len() == 0) return null;
        return &pipeline.prepared[pipeline.prepared_head];
    }

    /// Pops the oldest prepared attributes; the caller takes ownership and releases them
    /// with `deinit(pipeline.allocator)`.
    pub fn next(pipeline: *Pipeline) ?AttributesWithParent {
        if (pipeline.prepared_len() == 0) return null;
        const result = pipeline.prepared[pipeline.prepared_head];
        pipeline.prepared_head = (pipeline.prepared_head + 1) % prepared_max;
        pipeline.prepared_count -= 1;
        assert(pipeline.prepared_count < prepared_max);
        return result;
    }

    fn push_prepared(pipeline: *Pipeline, prepared: AttributesWithParent) void {
        assert(pipeline.prepared_len() < prepared_max);
        const index = (pipeline.prepared_head + pipeline.prepared_count) % prepared_max;
        pipeline.prepared[index] = prepared;
        pipeline.prepared_count += 1;
        assert(pipeline.prepared_count <= prepared_max);
    }

    /// The system config of an L2 block, from the `l2` provider.
    pub fn system_config_by_l2_hash(l2: anytype, hash: Hash) Error!SystemConfig {
        return l2.system_config_by_l2_hash(hash);
    }

    fn batches_upstream(
        pipeline: *Pipeline,
        chain: anytype,
        blobs: anytype,
        l2: anytype,
    ) BatchesUpstream(@TypeOf(chain), @TypeOf(blobs), @TypeOf(l2)) {
        const frames: FrameSource(@TypeOf(chain), @TypeOf(blobs)) = .{
            .queue = &pipeline.frame_queue,
            .retrieval = &pipeline.retrieval,
            .chain = chain,
            .blobs = blobs,
        };
        const reader = pipeline.channel_reader.upstream(&pipeline.channel_provider, frames);
        const stream = pipeline.batch_stream.upstream(reader, l2);
        return pipeline.batch_provider.upstream(stream, l2);
    }

    /// Attempts to prepare the attributes of the child of `cursor`. `error.Eof` from the
    /// stages (no more data at this origin) advances the L1 origin instead. Any result
    /// other than a failure means the driver should step again.
    pub fn step(
        pipeline: *Pipeline,
        chain: anytype,
        blobs: anytype,
        l2: anytype,
        cursor: L2BlockInfo,
    ) StepResult {
        if (pipeline.prepared_len() == prepared_max) {
            return .{ .step_failed = error.PreparedAttributesFull };
        }
        const upstream = pipeline.batches_upstream(chain, blobs, l2);
        const builder_chain: BuilderChain(@TypeOf(chain), @TypeOf(l2)) = .{
            .l1 = chain,
            .l2 = l2,
        };
        const prepared = pipeline.attributes_queue.next_attributes(
            upstream,
            builder_chain,
            cursor,
        ) catch |err| {
            if (err != error.Eof) return .{ .step_failed = err };
            pipeline.retrieval.advance_origin(chain) catch |advance_err| {
                return .{ .origin_advance_err = advance_err };
            };
            return .advanced_origin;
        };
        assert(prepared.parent.eql(cursor));
        pipeline.push_prepared(prepared);
        return .prepared_attributes;
    }

    /// Applies `signal` to every stage, upstream-first. A failed reset leaves the stages
    /// untouched when the failure happens before the L1 origin is fetched.
    pub fn signal(pipeline: *Pipeline, chain: anytype, l2: anytype, sig: Signal) Error!void {
        switch (sig) {
            .reset => |reset_signal| try pipeline.signal_reset(chain, l2, reset_signal),
            .activation => try pipeline.activate(),
            .flush_channel => try pipeline.flush_channel(),
        }
        assert(pipeline.origin() != null);
        assert(pipeline.attributes_queue.batch == null);
    }

    /// The reset: the walk-back's point, then the stages from its L1 origin. A walked point
    /// is kept while the L1 half is not yet available, so a retry for the same safe head
    /// does not walk again (an L2 provider's cache cannot hold a whole walk).
    fn signal_reset(
        pipeline: *Pipeline,
        chain: anytype,
        l2: anytype,
        reset_signal: ResetSignal,
    ) Error!void {
        const safe_head = reset_signal.l2_safe_head;
        const point = if (pipeline.reset_point_for(safe_head.block_info.hash)) |kept|
            kept
        else
            try pipeline.initial_reset(l2, safe_head);
        pipeline.reset_point = null;
        pipeline.reset(chain, point) catch |err| {
            if (err == error.NotAvailable) {
                pipeline.reset_point = .{ .safe_hash = safe_head.block_info.hash, .point = point };
            }
            return err;
        };
        assert(pipeline.reset_point == null);
        assert(pipeline.reset_walk == null);
    }

    fn reset_point_for(pipeline: *const Pipeline, safe_hash: Hash) ?ResetPoint {
        const kept = pipeline.reset_point orelse return null;
        if (!kept.safe_hash.eql(safe_hash)) return null;
        return kept.point;
    }

    /// Walks back from `l2_safe_head` until the walked-back block's L1 origin is at least
    /// one channel timeout behind the safe head's L1 origin (or genesis), and returns that
    /// block's L1 origin and system config, so batcher changes affecting channels still
    /// open in the window are seen (base/base `initial_reset`). The Granite timeout switch
    /// uses the safe lower bound `l2 time - max sequencer drift` for the L1 origin time.
    pub fn initial_reset(
        pipeline: *Pipeline,
        l2: anytype,
        l2_safe_head: L2BlockInfo,
    ) Error!ResetPoint {
        const rollup = pipeline.rollup;
        const safe_time = l2_safe_head.block_info.timestamp;
        const origin_time_lower_bound = safe_time -| rollup.max_sequencer_drift_at(safe_time);
        const channel_timeout = rollup.channel_timeout_at(origin_time_lower_bound);
        const origin_number = l2_safe_head.l1_origin.number;
        const genesis_number = rollup.genesis.l2.number;
        // Each step moves to the parent block, so the walk ends at genesis at the latest.
        const steps_max = (l2_safe_head.block_info.number -| genesis_number) + 1;
        var current = l2_safe_head;
        if (pipeline.reset_walk) |walk| {
            if (walk.safe_hash.eql(l2_safe_head.block_info.hash)) current = walk.current;
        }
        pipeline.reset_walk = null;
        assert(current.block_info.number <= l2_safe_head.block_info.number);
        for (0..steps_max) |_| {
            if (current.block_info.number <= genesis_number) break;
            if (current.l1_origin.number +| channel_timeout <= origin_number) break;
            const parent_hash = current.block_info.parent_hash;
            const parent = l2.l2_block_info_by_hash(parent_hash) catch |err| {
                pipeline.reset_walk_keep(err, l2_safe_head, current);
                return err;
            };
            // An inconsistent L2 provider (not a parent) is treated as a reorg.
            if (parent.block_info.number +| 1 != current.block_info.number) {
                return error.ReorgDetected;
            }
            current = parent;
        } else unreachable; // Proof: the block number decreases by one per step.
        assert(current.block_info.number <= l2_safe_head.block_info.number);
        const config = l2.system_config_by_l2_hash(current.block_info.hash) catch |err| {
            pipeline.reset_walk_keep(err, l2_safe_head, current);
            return err;
        };
        assert(pipeline.reset_walk == null);
        return .{ .l1_origin = current.l1_origin, .system_config = config };
    }

    /// Keeps the walk at `current` for the next retry when `err` only means "not yet".
    fn reset_walk_keep(
        pipeline: *Pipeline,
        err: Error,
        l2_safe_head: L2BlockInfo,
        current: L2BlockInfo,
    ) void {
        assert(pipeline.reset_walk == null);
        assert(current.block_info.number <= l2_safe_head.block_info.number);
        if (err != error.NotAvailable) return;
        pipeline.reset_walk = .{ .safe_hash = l2_safe_head.block_info.hash, .current = current };
    }

    fn reset(pipeline: *Pipeline, chain: anytype, point: ResetPoint) Error!void {
        try pipeline.retrieval.reset(chain, point.l1_origin, point.system_config);
        const origin_block = pipeline.origin() orelse return error.MissingOrigin;
        pipeline.frame_queue.clear();
        pipeline.channel_provider.clear(origin_block);
        pipeline.channel_reader.next_channel();
        pipeline.batch_stream.clear();
        try pipeline.batch_provider.reset(OriginSource{ .retrieval = &pipeline.retrieval });
        pipeline.attributes_queue.reset();
        assert(origin_block.number == point.l1_origin.number);
    }

    fn activate(pipeline: *Pipeline) Error!void {
        pipeline.retrieval.activate();
        const origin_block = pipeline.origin() orelse return error.MissingOrigin;
        pipeline.frame_queue.clear();
        pipeline.channel_provider.clear(origin_block);
        pipeline.channel_reader.next_channel();
        pipeline.batch_stream.clear();
        try pipeline.batch_provider.activate(OriginSource{ .retrieval = &pipeline.retrieval });
        pipeline.attributes_queue.activate();
        assert(pipeline.frame_queue.len() == 0);
    }

    /// Drops the active channel: the attributes queue's batch, the batch stages' buffers,
    /// the batch stream, and the channel reader's channel. Does not reach the channel stage
    /// (base/base `ChannelReader::flush_channel` stops propagation).
    fn flush_channel(pipeline: *Pipeline) Error!void {
        pipeline.attributes_queue.flush_channel();
        const source: OriginSource = .{ .retrieval = &pipeline.retrieval };
        try pipeline.batch_provider.flush_channel(source);
        pipeline.batch_stream.clear();
        pipeline.channel_reader.next_channel();
        assert(pipeline.batch_stream.span_buffer_size() == 0);
    }
};

test {
    _ = @import("pipeline_test.zig");
}

//! Consolidate task: promotes derived attributes to the safe head. While the safe head is
//! behind the unsafe head, the engine's block at the attributes' number is compared with
//! the attributes; a match advances the safe heads (with a forkchoice update only for the
//! last block of a span batch), a mismatch builds and seals the derived block as safe
//! (a reorg of the unsafe chain). When the safe head has caught up with the unsafe head,
//! a block the engine already has (backfilled after a SYNCING forkchoice update) is
//! adopted before falling back to build and seal.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/consolidate/task.rs`.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const attributes_match = @import("attributes_match.zig");
const SynchronizeTask = @import("synchronize_task.zig").SynchronizeTask;
const BuildTask = @import("build_task.zig").BuildTask;
const SealTask = @import("seal_task.zig").SealTask;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const L2BlockInfo = protocol.block.L2BlockInfo;
const EngineState = task.EngineState;
const Error = task.Error;

pub const ConsolidateTask = struct {
    /// Borrowed from the queue slot that owns the task.
    attributes: *const AttributesWithParent,
    phase: enum { start, synchronize, build, seal } = .start,
    synchronize: SynchronizeTask = undefined,
    /// The synchronize step adopts an existing block and must advance every head to it.
    reconcile: bool = false,
    block: L2BlockInfo = .{},
    seal: SealTask = undefined,

    pub fn restart(consolidate: *ConsolidateTask) void {
        const attributes = consolidate.attributes;
        consolidate.* = .{ .attributes = attributes };
        assert(consolidate.phase == .start);
        assert(!consolidate.reconcile);
    }

    pub fn step(
        consolidate: *ConsolidateTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!void {
        for (0..4) |_| {
            switch (consolidate.phase) {
                .start => {
                    const done = try consolidate.check_block(context, engine_state, client);
                    if (done) return;
                    assert(consolidate.phase != .start);
                },
                .synchronize => return consolidate.step_synchronize(context, engine_state, client),
                .build => {
                    const build = BuildTask.init(consolidate.attributes);
                    const payload_id = try build.step(context, engine_state, client);
                    consolidate.seal = SealTask.init(
                        payload_id,
                        consolidate.attributes,
                        .safe_payload,
                    );
                    consolidate.phase = .seal;
                },
                .seal => {
                    _ = try consolidate.seal.step(context, engine_state, client);
                    return;
                },
            }
        }
        unreachable; // Proof: start -> build -> seal returns; synchronize returns.
    }

    /// Fetches and compares the engine's block. Returns true when consolidation finished
    /// without a forkchoice update; otherwise selects the next phase.
    fn check_block(
        consolidate: *ConsolidateTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!bool {
        assert(consolidate.phase == .start);
        const sync_state = engine_state.sync_state;
        const behind = sync_state.safe_head.block_info.number <
            sync_state.unsafe_head.block_info.number;
        const number = consolidate.attributes.parent.block_info.number +| 1;
        const fetched = client.l2_block_by_number(number) catch |err| return switch (err) {
            error.NotAvailable => error.NotAvailable,
            error.InvalidForkchoiceState, error.RpcFailed, error.InvalidBlock => {
                if (behind) return error.FailedToFetchUnsafeL2Block;
                return error.FailedToFetchDerivedL2Block;
            },
        };
        const block = fetched orelse {
            if (behind) return error.MissingUnsafeL2Block;
            consolidate.phase = .build;
            return false;
        };
        const mismatch = attributes_match.check(
            context.rollup,
            context.fee_params_canyon,
            consolidate.attributes,
            &block,
        );
        if (mismatch != null) {
            engine_state.mismatches += 1;
            engine_state.mismatch_last = mismatch;
            engine_state.mismatch_last_number = number;
            consolidate.phase = .build;
            return false;
        }
        consolidate.block = block.info;
        if (behind and !consolidate.attributes.is_last_in_span) {
            // Transient safe head update without a forkchoice update (span batch interior).
            try task.apply_update(engine_state, .{
                .local_safe_head = block.info,
                .safe_head = block.info,
            });
            return true;
        }
        consolidate.reconcile = !behind;
        consolidate.synchronize = .{ .update = .{
            .unsafe_head = if (behind) null else block.info,
            .local_safe_head = block.info,
            .safe_head = block.info,
        } };
        consolidate.phase = .synchronize;
        return false;
    }

    fn step_synchronize(
        consolidate: *ConsolidateTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!void {
        assert(consolidate.phase == .synchronize);
        try consolidate.synchronize.step(context, engine_state, client);
        if (!consolidate.reconcile) return;
        const sync_state = engine_state.sync_state;
        if (!sync_state.unsafe_head.eql(consolidate.block) or
            !sync_state.local_safe_head.eql(consolidate.block) or
            !sync_state.safe_head.eql(consolidate.block))
        {
            return error.ConsolidateDidNotApply;
        }
        assert(engine_state.sync_state.safe_head.eql(consolidate.block));
    }
};

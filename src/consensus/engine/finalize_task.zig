//! Finalize task: fetches the L2 block at `block_number` and moves the finalized head to it
//! with a forkchoice update. A stale task below the current finalized head is skipped so
//! the finalized head never regresses; a block that is not yet safe is critical.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/finalize/task.rs`.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const SynchronizeTask = @import("synchronize_task.zig").SynchronizeTask;

const EngineState = task.EngineState;
const Error = task.Error;

pub const FinalizeTask = struct {
    block_number: u64,
    phase: enum { fetch, synchronize } = .fetch,
    synchronize: SynchronizeTask = undefined,

    pub fn restart(finalize: *FinalizeTask) void {
        finalize.phase = .fetch;
        finalize.synchronize = undefined;
        assert(finalize.phase == .fetch);
    }

    pub fn step(
        finalize: *FinalizeTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!void {
        if (finalize.phase == .fetch) {
            const sync_state = engine_state.sync_state;
            if (finalize.block_number < sync_state.finalized_head.block_info.number) return;
            if (sync_state.safe_head.block_info.number < finalize.block_number) {
                return error.BlockNotSafe;
            }
            const fetched = client.l2_block_info_by_number(finalize.block_number) catch |err|
                return switch (err) {
                    error.NotAvailable => error.NotAvailable,
                    error.InvalidBlock => error.L2BlockInfoConstruction,
                    error.InvalidForkchoiceState, error.RpcFailed => error.FinalizeFetchFailed,
                };
            const block = fetched orelse return error.BlockNotFound;
            if (block.block_info.number != finalize.block_number) return error.BlockNotFound;
            finalize.synchronize = .{ .update = .{ .finalized_head = block } };
            finalize.phase = .synchronize;
        }
        assert(finalize.phase == .synchronize);
        try finalize.synchronize.step(context, engine_state, client);
    }
};

//! Synchronize task: an `engine_forkchoiceUpdated` without attributes that commits a sync
//! state update once the execution engine confirms it. VALID applies the whole update and
//! marks EL sync finished; SYNCING keeps the unsafe head and, once EL sync has finished,
//! applies only the safe-side heads that are not ahead of the unsafe head; any other status
//! asks for a reset.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/synchronize/task.rs`.
//!
//! Deviation: applying an update that would break the head ordering invariant fails with
//! `UnorderedHeads` (critical) instead of corrupting the state (the engine should already
//! reject such a forkchoice state), and a SYNCING-filtered update that would break it is
//! dropped.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");

const L2BlockInfo = protocol.block.L2BlockInfo;
const EngineState = task.EngineState;
const SyncState = task.SyncState;
const SyncStateUpdate = task.SyncStateUpdate;
const Error = task.Error;

pub const SynchronizeTask = struct {
    update: SyncStateUpdate,
    /// Send the forkchoice update even when the update changes nothing.
    force: bool = false,

    /// Stateless between calls: every retry recomputes the same forkchoice state, so a
    /// pending client request is matched by its arguments.
    pub fn step(
        synchronize: *const SynchronizeTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!void {
        _ = context;
        const current = engine_state.sync_state;
        const next = current.updated(synchronize.update);
        const default_state: SyncState = .{};
        if (!synchronize.force and !task.sync_state_eql(current, default_state) and
            task.sync_state_eql(current, next))
        {
            return;
        }
        const unsafe_number = next.unsafe_head.block_info.number;
        if (unsafe_number < next.finalized_head.block_info.number) {
            return error.FinalizedAheadOfUnsafe;
        }
        const forkchoice = task.engine_forkchoice(next);
        // Without attributes the forkchoice update is version agnostic (base/base uses V3).
        const response = client.forkchoice_updated(.v3, &forkchoice, null) catch |err|
            return switch (err) {
                error.NotAvailable => error.NotAvailable,
                error.InvalidForkchoiceState => error.InvalidForkchoiceState,
                error.RpcFailed, error.InvalidBlock => error.ForkchoiceUpdateFailed,
            };
        switch (response.payload_status.status) {
            .valid => {
                engine_state.el_sync_finished = true;
                try task.apply_update(engine_state, synchronize.update);
            },
            .syncing => {
                const filtered = synchronize.safe_only_update(engine_state);
                // A partial update that would unorder the heads is dropped entirely.
                task.apply_update(engine_state, filtered) catch {};
            },
            .invalid, .accepted => return error.ForkchoiceInvalidStatus,
        }
        assert(engine_state.sync_state.is_ordered());
    }

    /// The update to apply on SYNCING: nothing before EL sync finished; afterwards only
    /// safe-side heads at or behind the current unsafe head, never the unsafe head itself.
    pub fn safe_only_update(
        synchronize: *const SynchronizeTask,
        engine_state: *const EngineState,
    ) SyncStateUpdate {
        if (!engine_state.el_sync_finished) return .{};
        const unsafe_head = engine_state.sync_state.unsafe_head;
        const update = synchronize.update;
        const result: SyncStateUpdate = .{
            .unsafe_head = null,
            .local_safe_head = not_ahead(update.local_safe_head, unsafe_head),
            .safe_head = not_ahead(update.safe_head, unsafe_head),
            .finalized_head = not_ahead(update.finalized_head, unsafe_head),
        };
        assert(result.unsafe_head == null);
        return result;
    }
};

fn not_ahead(head: ?L2BlockInfo, unsafe_head: L2BlockInfo) ?L2BlockInfo {
    const candidate = head orelse return null;
    const number = candidate.block_info.number;
    const unsafe_number = unsafe_head.block_info.number;
    const same = number == unsafe_number and
        candidate.block_info.hash.eql(unsafe_head.block_info.hash);
    const keep = number < unsafe_number or same;
    assert(!keep or number <= unsafe_number);
    assert(keep or number >= unsafe_number);
    return if (keep) candidate else null;
}

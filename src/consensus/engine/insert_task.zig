//! Insert task: imports an execution payload with `engine_newPayload` and canonicalizes it
//! with a forkchoice update. Unsafe payloads that are already known, older than the unsafe
//! head, or do not build on it are skipped before import (`ExtendingOnly`); authoritative
//! payloads replace the unsafe chain and reset the local safe head to the safe head.
//! Externally received payloads that the engine rejects as INVALID are dropped.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/insert/task.rs`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const SynchronizeTask = @import("synchronize_task.zig").SynchronizeTask;

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const EngineState = task.EngineState;
const ExecutionPayload = task.ExecutionPayload;
const Error = task.Error;

pub const Safety = enum { unsafe_payload, safe_payload };
pub const Policy = enum { extending_only, authoritative };

/// An execution payload with the parent beacon block root sent alongside it (V3+).
pub const Envelope = struct {
    payload: ExecutionPayload,
    parent_beacon_block_root: ?B256 = null,
};

pub const InsertTask = struct {
    /// Borrowed from the owner (queue slot or seal task).
    envelope: *const Envelope,
    safety: Safety,
    policy: Policy = .extending_only,
    /// Consume an EL-invalid payload instead of retrying it (gossiped unsafe payloads).
    drop_invalid: bool = false,
    phase: enum { start, new_payload, synchronize } = .start,
    block: L2BlockInfo = .{},

    pub fn restart(insert: *InsertTask) void {
        insert.phase = .start;
        insert.block = .{};
        assert(insert.phase == .start);
    }

    /// Returns the engine-acknowledged unsafe head (the current one when skipped).
    pub fn step(
        insert: *InsertTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!L2BlockInfo {
        for (0..3) |_| {
            switch (insert.phase) {
                .start => {
                    const payload = &insert.envelope.payload;
                    insert.block = try task.block_info_from_payload(
                        payload,
                        &context.rollup.genesis,
                    );
                    if (!insert.applicable(engine_state)) {
                        return engine_state.sync_state.unsafe_head;
                    }
                    insert.phase = .new_payload;
                },
                .new_payload => {
                    try insert.new_payload(client);
                    insert.phase = .synchronize;
                },
                .synchronize => return insert.synchronize(context, engine_state, client),
            }
        }
        unreachable; // Proof: each phase either returns or advances to a later phase.
    }

    fn new_payload(insert: *InsertTask, client: anytype) Error!void {
        assert(insert.phase == .new_payload);
        const payload = &insert.envelope.payload;
        const params: task.NewPayloadParams = .{
            .versioned_hashes = &.{},
            .parent_beacon_block_root = insert.envelope.parent_beacon_block_root orelse .zero,
            .execution_requests = &.{},
        };
        const version = task.new_payload_version(payload);
        const status = client.new_payload(version, payload, &params) catch |err|
            return switch (err) {
                error.NotAvailable => error.NotAvailable,
                error.InvalidForkchoiceState, error.RpcFailed, error.InvalidBlock => {
                    return error.InsertFailed;
                },
            };
        switch (status.status) {
            .valid, .syncing => {},
            .invalid => return error.NewPayloadInvalid,
            .accepted => return error.NewPayloadUnexpectedStatus,
        }
        assert(status.status == .valid or status.status == .syncing);
    }

    fn synchronize(
        insert: *InsertTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!L2BlockInfo {
        assert(insert.phase == .synchronize);
        const safe = insert.safety == .safe_payload;
        const authoritative = insert.policy == .authoritative;
        const synchronize_task: SynchronizeTask = .{
            .update = .{
                .unsafe_head = insert.block,
                .local_safe_head = if (safe) insert.block else null,
                .safe_head = if (safe) insert.block else null,
            },
            .force = authoritative,
        };
        try synchronize_task.step(context, engine_state, client);
        if (!authoritative) return insert.block;
        if (!engine_state.sync_state.unsafe_head.eql(insert.block)) {
            return error.ForkchoiceUpdateDidNotApply;
        }
        try task.apply_update(engine_state, .{
            .local_safe_head = engine_state.sync_state.safe_head,
        });
        assert(engine_state.sync_state.unsafe_head.eql(insert.block));
        return insert.block;
    }

    fn applicable(insert: *const InsertTask, engine_state: *const EngineState) bool {
        if (insert.safety == .safe_payload or insert.policy == .authoritative) return true;
        const unsafe_head = engine_state.sync_state.unsafe_head.block_info;
        const block = insert.block.block_info;
        if (block.hash.eql(unsafe_head.hash)) return false; // Already processed.
        if (block.number <= unsafe_head.number) return false; // Older than the unsafe head.
        if (block.number == unsafe_head.number +| 1 and !block.parent_hash.eql(unsafe_head.hash)) {
            return false; // Does not build onto the unsafe head.
        }
        assert(block.number > unsafe_head.number);
        return true;
    }
};

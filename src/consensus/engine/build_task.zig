//! Build task: `engine_forkchoiceUpdated` with payload attributes on top of the attributes'
//! parent, returning the payload id of the execution engine's build job. The engine
//! state is not changed: the parent becomes the unsafe head only once the payload is sealed.
//! Mirrors base/base `Engine::start_build` (`crates/consensus/engine/src/task_queue/core.rs`)
//! and `BuildTaskError` severities.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const EngineState = task.EngineState;
const PayloadId = task.PayloadId;
const Error = task.Error;

pub const BuildTask = struct {
    /// Borrowed from the queue slot that owns the task.
    attributes: *const AttributesWithParent,
    /// Number of transactions to build with: all, or the deposits-only prefix.
    transactions_count: u32,

    pub fn init(attributes: *const AttributesWithParent) BuildTask {
        const count: u32 = @intCast(attributes.attributes.transactions.len);
        return .{ .attributes = attributes, .transactions_count = count };
    }

    /// Stateless between calls (one request, matched by its arguments).
    pub fn step(
        build: *const BuildTask,
        context: *const task.Context,
        engine_state: *const EngineState,
        client: anytype,
    ) Error!PayloadId {
        const sync_state = engine_state.sync_state;
        const unsafe_number = sync_state.unsafe_head.block_info.number;
        if (unsafe_number < sync_state.finalized_head.block_info.number) {
            return error.FinalizedAheadOfUnsafe;
        }
        const forkchoice = task.engine_forkchoice(sync_state.updated(.{
            .unsafe_head = build.attributes.parent,
        }));
        const timestamp = build.attributes.attributes.timestamp;
        const version = task.forkchoice_version(context.rollup, timestamp);
        const attributes = task.engine_attributes(build.attributes, build.transactions_count);
        const response = client.forkchoice_updated(version, &forkchoice, &attributes) catch |err|
            return switch (err) {
                error.NotAvailable => error.NotAvailable,
                error.InvalidForkchoiceState => error.InvalidForkchoiceState,
                error.RpcFailed, error.InvalidBlock => error.AttributesInsertionFailed,
            };
        switch (response.payload_status.status) {
            .valid => {},
            .invalid => return error.BuildInvalidPayload,
            .syncing => return error.EngineSyncing,
            .accepted => return error.BuildUnexpectedStatus,
        }
        const payload_id = response.payload_id orelse return error.MissingPayloadId;
        assert(response.payload_status.status == .valid);
        return payload_id;
    }
};

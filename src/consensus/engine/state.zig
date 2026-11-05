//! Engine sync state: the unsafe, local-safe, safe, and finalized L2 heads tracked by the
//! consensus node, and the forkchoice state sent to the execution engine.
//! Mirrors base/base `crates/consensus/engine/src/state/core.rs`.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");

const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;

/// `engine_forkchoiceUpdated` head hashes.
pub const ForkchoiceState = struct {
    head_block_hash: Hash,
    safe_block_hash: Hash,
    finalized_block_hash: Hash,
};

pub const SyncStateUpdate = struct {
    unsafe_head: ?L2BlockInfo = null,
    local_safe_head: ?L2BlockInfo = null,
    safe_head: ?L2BlockInfo = null,
    finalized_head: ?L2BlockInfo = null,
};

pub const SyncState = struct {
    unsafe_head: L2BlockInfo = .{},
    local_safe_head: L2BlockInfo = .{},
    safe_head: L2BlockInfo = .{},
    finalized_head: L2BlockInfo = .{},

    pub fn forkchoice_state(state: SyncState) ForkchoiceState {
        return .{
            .head_block_hash = state.unsafe_head.block_info.hash,
            .safe_block_hash = state.safe_head.block_info.hash,
            .finalized_block_hash = state.finalized_head.block_info.hash,
        };
    }

    /// Returns the state with every set field of `update` applied.
    pub fn updated(state: SyncState, update: SyncStateUpdate) SyncState {
        const result: SyncState = .{
            .unsafe_head = update.unsafe_head orelse state.unsafe_head,
            .local_safe_head = update.local_safe_head orelse state.local_safe_head,
            .safe_head = update.safe_head orelse state.safe_head,
            .finalized_head = update.finalized_head orelse state.finalized_head,
        };
        assert(update.unsafe_head != null or
            result.unsafe_head.block_info.eql(state.unsafe_head.block_info));
        return result;
    }

    /// The ordering invariant the engine maintains between heads:
    /// finalized <= safe <= local safe <= unsafe (by block number).
    pub fn is_ordered(state: SyncState) bool {
        const finalized = state.finalized_head.block_info.number;
        const safe = state.safe_head.block_info.number;
        const local_safe = state.local_safe_head.block_info.number;
        const unsafe_number = state.unsafe_head.block_info.number;
        return finalized <= safe and safe <= local_safe and local_safe <= unsafe_number;
    }
};

pub const EngineState = struct {
    sync_state: SyncState = .{},
    /// Whether execution-layer sync has finished (the engine accepted a valid head).
    el_sync_finished: bool = false,
};

const testing = std.testing;

test "engine state: updates and forkchoice state" {
    var state: SyncState = .{};
    try testing.expect(state.is_ordered());
    const head: L2BlockInfo = .{ .block_info = .{ .number = 5, .hash = .{ .bytes = @splat(5) } } };
    const safe: L2BlockInfo = .{ .block_info = .{ .number = 3, .hash = .{ .bytes = @splat(3) } } };
    state = state.updated(.{ .unsafe_head = head });
    try testing.expect(state.forkchoice_state().head_block_hash.eql(head.block_info.hash));
    try testing.expect(state.forkchoice_state().safe_block_hash.is_zero());
    state = state.updated(.{ .safe_head = safe, .local_safe_head = safe });
    try testing.expect(state.is_ordered());
    try testing.expect(state.forkchoice_state().safe_block_hash.eql(safe.block_info.hash));
    try testing.expect(!state.updated(.{ .safe_head = head, .unsafe_head = safe }).is_ordered());
}

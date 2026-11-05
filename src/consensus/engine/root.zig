//! Engine controller: L2 head tracking, forkchoice, and finalization.
//! Mirrors base/base `crates/consensus/engine`.

const std = @import("std");

pub const state = @import("state.zig");
pub const finalizer = @import("finalizer.zig");
pub const sync_start = @import("sync_start.zig");
pub const attributes_match = @import("attributes_match.zig");
pub const task = @import("task.zig");
pub const synchronize_task = @import("synchronize_task.zig");
pub const build_task = @import("build_task.zig");
pub const insert_task = @import("insert_task.zig");
pub const seal_task = @import("seal_task.zig");
pub const consolidate_task = @import("consolidate_task.zig");
pub const finalize_task = @import("finalize_task.zig");
pub const task_queue = @import("task_queue.zig");
pub const EngineTaskQueue = task_queue.EngineTaskQueue;
pub const mock_engine = @import("mock_engine.zig");
pub const polling_client = @import("polling_client.zig");
pub const PollingClient = polling_client.PollingClient;

test {
    std.testing.refAllDecls(@This());
    _ = @import("attributes_match_test.zig");
    _ = @import("task_queue_test.zig");
    _ = @import("polling_client_test.zig");
}

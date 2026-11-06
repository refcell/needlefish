//! State bootstrap from a snapshot (docs/SYNC_PLAN.md M3).
//!
//! - `state_root`: streaming state root over a whole state in hashed-key order, the check
//!   every imported snapshot must pass against its header.

const std = @import("std");

pub const state_root = @import("state_root.zig");
pub const StateRootBuilder = state_root.StateRootBuilder;

test {
    std.testing.refAllDecls(@This());
}

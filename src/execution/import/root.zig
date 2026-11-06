//! State bootstrap from a snapshot (docs/SYNC_PLAN.md M3).
//!
//! - `state_root`: streaming state root over a whole state in hashed-key order, the check
//!   every imported snapshot must pass against its header.
//! - `mdbx`: read-only reader for MDBX files (reth's state database).

const std = @import("std");

pub const state_root = @import("state_root.zig");
pub const StateRootBuilder = state_root.StateRootBuilder;
pub const mdbx = @import("mdbx.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("mdbx_test.zig");
}

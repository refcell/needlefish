//! The execution node: world state, block execution and the chain backend that the
//! Engine API and JSON-RPC drive. Mirrors base/base `crates/execution/node`.

const std = @import("std");

pub const state_db = @import("state_db.zig");
pub const StateDb = state_db.StateDb;

test {
    std.testing.refAllDecls(@This());
}

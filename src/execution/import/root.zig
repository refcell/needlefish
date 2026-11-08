//! State bootstrap from a snapshot (docs/SYNC_PLAN.md M3).
//!
//! - `state_root`: streaming state root over a whole state in hashed-key order, the check
//!   every imported snapshot must pass against its header.
//! - `mdbx`: read-only reader for MDBX files (reth's state database).
//! - `reth`: decoders for the reth table values the import reads.
//! - `hashed_state`: the state root of reth's `HashedAccounts` + `HashedStorages` tables.
//! - `to_disk`: one pass of that state into a needlefish disk-mode database (bulk loaders).
//! - `run`: executes blocks N+1.. on that database, checking every header field.
//! - `room`: waits for journal and admission room before each such block.

const std = @import("std");

pub const state_root = @import("state_root.zig");
pub const StateRootBuilder = state_root.StateRootBuilder;
pub const mdbx = @import("mdbx.zig");
pub const reth = @import("reth.zig");
pub const hashed_state = @import("hashed_state.zig");
pub const to_disk = @import("to_disk.zig");
pub const run = @import("run.zig");
pub const room = @import("room.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("mdbx_test.zig");
    _ = @import("to_disk_test.zig");
    _ = @import("run_test.zig");
}

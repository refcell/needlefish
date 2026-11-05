//! Execution database. Mirrors base/base `crates/execution` storage (reth db/provider).
//!
//! Sub-modules are re-exported here as they land:
//! - `storage`: crash-safe storage engine (superblock, journal, checkpoints) over an injected
//!   sector storage, with a deterministic fault-injecting simulator.
//! - `state`: state provider (accounts, storage, code, block hashes) with a block overlay.

const std = @import("std");

pub const changeset = @import("changeset.zig");
pub const state = @import("state.zig");
pub const overlay = @import("overlay.zig");

pub const Changeset = changeset.Changeset;
pub const AccountInfo = changeset.AccountInfo;
pub const State = state.State;
pub const Overlay = overlay.Overlay;

test {
    std.testing.refAllDecls(@This());
    _ = @import("state_test.zig");
}

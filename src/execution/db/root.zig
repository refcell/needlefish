//! Execution database. Mirrors base/base `crates/execution` storage (reth db/provider).
//!
//! Sub-modules are re-exported here as they land:
//! - `storage`: crash-safe storage engine (superblock, journal, checkpoints) over an injected
//!   sector storage, with a deterministic fault-injecting simulator.
//! - `state`: state provider (accounts, storage, code, block hashes) with a block overlay.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

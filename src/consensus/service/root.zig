//! The consensus node service: L1 watching, startup, derivation and engine driving, RPC.
//! Mirrors base/base `crates/consensus/service`.

pub const l1_watcher = @import("l1_watcher.zig");

test {
    _ = l1_watcher;
}

//! The consensus node service: L1 watching, startup, derivation and engine driving, RPC.
//! Mirrors base/base `crates/consensus/service`.

pub const l1_watcher = @import("l1_watcher.zig");
pub const node = @import("node.zig");
pub const Node = node.Node;

test {
    _ = l1_watcher;
    _ = node;
}

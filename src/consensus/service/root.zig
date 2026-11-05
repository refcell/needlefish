//! The consensus node service: L1 watching, startup, derivation and engine driving, RPC.
//! Mirrors base/base `crates/consensus/service`.

pub const l1_watcher = @import("l1_watcher.zig");
pub const node = @import("node.zig");
pub const driver = @import("driver.zig");
pub const gossip_bridge = @import("gossip_bridge.zig");
pub const unsafe_buffer = @import("unsafe_buffer.zig");
pub const signer_watcher = @import("signer_watcher.zig");
pub const Node = node.Node;

test {
    _ = l1_watcher;
    _ = node;
    _ = driver;
    _ = gossip_bridge;
    _ = unsafe_buffer;
    _ = signer_watcher;
}

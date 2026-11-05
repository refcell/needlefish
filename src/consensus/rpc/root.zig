//! Consensus node JSON-RPC namespaces.

pub const rollup = @import("rollup.zig");
pub const admin = @import("admin.zig");

test {
    _ = rollup;
    _ = admin;
}

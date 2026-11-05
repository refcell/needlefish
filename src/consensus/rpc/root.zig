//! Consensus node JSON-RPC namespaces.

pub const rollup = @import("rollup.zig");
pub const admin = @import("admin.zig");
pub const base = @import("base.zig");

test {
    _ = rollup;
    _ = admin;
    _ = base;
}

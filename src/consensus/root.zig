//! `consensus` group. Mirrors base/base `crates/consensus`. Sub-modules are re-exported
//! here as they land, e.g. `pub const rlp = @import("rlp/root.zig");`.

const std = @import("std");

pub const protocol = @import("protocol/root.zig");
pub const p2p = @import("p2p/root.zig");
pub const derive = @import("derive/root.zig");
pub const safedb = @import("safedb/root.zig");

test {
    std.testing.refAllDecls(@This());
}

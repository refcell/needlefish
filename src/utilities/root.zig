//! `utilities` group. Mirrors base/base `crates/utilities`. Sub-modules are re-exported
//! here as they land, e.g. `pub const rlp = @import("rlp/root.zig");`.

const std = @import("std");

pub const io = @import("io/root.zig");
pub const time = @import("time/root.zig");
pub const json = @import("json/root.zig");
pub const http = @import("http/root.zig");
pub const rpc = @import("rpc/root.zig");

test {
    std.testing.refAllDecls(@This());
}

//! `common` group. Mirrors base/base `crates/common`. Sub-modules are re-exported
//! here as they land.

const std = @import("std");

pub const primitives = @import("primitives/root.zig");
pub const crypto = @import("crypto/root.zig");
pub const rlp = @import("rlp/root.zig");
pub const consensus = @import("consensus/root.zig");

test {
    std.testing.refAllDecls(@This());
}

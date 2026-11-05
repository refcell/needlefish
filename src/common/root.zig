//! `common` group. Mirrors base/base `crates/common`. Sub-modules are re-exported
//! here as they land, e.g. `pub const rlp = @import("rlp/root.zig");`.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

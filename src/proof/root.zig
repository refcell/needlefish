//! `proof` group. Mirrors base/base `crates/proof`. Sub-modules are re-exported
//! here as they land, e.g. `pub const rlp = @import("rlp/root.zig");`.

const std = @import("std");

pub const preimage = @import("preimage/root.zig");
pub const mpt = @import("mpt/root.zig");
pub const executor = @import("executor/root.zig");

test {
    std.testing.refAllDecls(@This());
}

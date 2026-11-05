//! `proof` group. Mirrors base/base `crates/proof`. Sub-modules are re-exported
//! here as they land, e.g. `pub const rlp = @import("rlp/root.zig");`.

const std = @import("std");

pub const preimage = @import("preimage/root.zig");
pub const mpt = @import("mpt/root.zig");
pub const executor = @import("executor/root.zig");
pub const program = @import("program/root.zig");
pub const driver = @import("driver/root.zig");
pub const client = @import("client/root.zig");
pub const host = @import("host/root.zig");
pub const contracts = @import("contracts/root.zig");

test {
    std.testing.refAllDecls(@This());
}

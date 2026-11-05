//! Devnet tooling: dev accounts, genesis and rollup config generation for
//! `base devnet init` (docs/DEVNET.md).

const std = @import("std");

pub const accounts = @import("accounts.zig");
pub const portal = @import("portal.zig");
pub const genesis = @import("genesis.zig");
pub const init = @import("init.zig");
pub const transfer = @import("transfer.zig");
pub const inspect = @import("inspect.zig");

test {
    std.testing.refAllDecls(@This());
}

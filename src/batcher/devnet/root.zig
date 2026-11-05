//! Devnet tooling: dev accounts, genesis and rollup config generation for
//! `base devnet init` (docs/DEVNET.md).

const std = @import("std");

pub const accounts = @import("accounts.zig");

test {
    std.testing.refAllDecls(@This());
}

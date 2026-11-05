//! `proof/program`: the fault-proof program's boot inputs and the oracle-backed chain
//! providers it feeds into derivation. Port of base/base `crates/proof/proof`.

const std = @import("std");

pub const boot = @import("boot.zig");

pub const BootInfo = boot.BootInfo;

test {
    std.testing.refAllDecls(@This());
}

//! Trusted execution environment proofs (base/base `crates/proof/tee`).

const std = @import("std");

pub const nitro = @import("nitro/root.zig");

test {
    std.testing.refAllDecls(@This());
}

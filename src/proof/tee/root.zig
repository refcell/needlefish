//! Trusted execution environment proofs (base/base `crates/proof/tee`).

const std = @import("std");

pub const nitro = @import("nitro/root.zig");
pub const enclave = @import("enclave/root.zig");
pub const registrar = @import("registrar/root.zig");
pub const host = @import("host/root.zig");
pub const verify = @import("verify.zig");

test {
    std.testing.refAllDecls(@This());
}

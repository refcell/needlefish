//! `proof/client`: prologue, driver and epilogue of the fault-proof program. Port of
//! base/base `crates/proof/client`.

const std = @import("std");

pub const client = @import("client.zig");

pub const Client = client.Client;
pub const Outcome = client.Outcome;
pub const run = client.run;
pub const claim_holds = client.claim_holds;

test {
    std.testing.refAllDecls(@This());
    _ = @import("client_test.zig");
}

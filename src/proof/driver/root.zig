//! `proof/driver`: the fault-proof program's derive-and-execute loop. Port of base/base
//! `crates/proof/driver`.

const std = @import("std");

pub const driver = @import("driver.zig");

pub const Driver = driver.Driver;
pub const Tip = driver.Tip;

test {
    std.testing.refAllDecls(@This());
}

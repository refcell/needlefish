//! `builder` group: the Base block builder (full blocks at the native 200 ms cadence, no
//! flashblocks). Mirrors base/base `crates/builder/{core,metering}`. Sub-modules are
//! re-exported here.

const std = @import("std");

pub const core = @import("core/root.zig");
pub const metering = @import("metering/root.zig");

test {
    std.testing.refAllDecls(@This());
}

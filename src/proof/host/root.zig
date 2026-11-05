//! `proof/host`: serves the fault-proof program's preimages. Port of base/base
//! `crates/proof/host`.

const std = @import("std");

pub const store = @import("store.zig");

pub const Store = store.Store;
pub const BootValues = store.BootValues;

test {
    std.testing.refAllDecls(@This());
}

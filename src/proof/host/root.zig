//! `proof/host`: serves the fault-proof program's preimages. Port of base/base
//! `crates/proof/host`.

const std = @import("std");

pub const store = @import("store.zig");
pub const handler = @import("handler.zig");

pub const Store = store.Store;
pub const BootValues = store.BootValues;
pub const Handler = handler.Handler;
pub const Source = handler.Source;

test {
    std.testing.refAllDecls(@This());
    _ = @import("host_test.zig");
}

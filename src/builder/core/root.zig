//! Flashblocks builder core: timing, best-transactions view, generator, and the Engine API
//! service. Mirrors base/base `crates/builder/core`.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

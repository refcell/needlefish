//! Flashblocks builder core: timing, best-transactions view, generator, and the Engine API
//! service. Mirrors base/base `crates/builder/core`.

const std = @import("std");

pub const timing = @import("timing.zig");
pub const best_txs = @import("best_txs.zig");
pub const generator = @import("generator.zig");

test {
    std.testing.refAllDecls(@This());
}

//! needlefish: Base, the Ethereum L2, rewritten in Zig.
//!
//! This is the root of the single `base` module. Groups mirror base/base's
//! `crates/` directory. Each group root re-exports its sub-modules. Every
//! declaration reachable from here is compiled and tested by `zig build test`.

const std = @import("std");

pub const common = @import("common/root.zig");
pub const utilities = @import("utilities/root.zig");
pub const execution = @import("execution/root.zig");
pub const consensus = @import("consensus/root.zig");
pub const batcher = @import("batcher/root.zig");
pub const proof = @import("proof/root.zig");
pub const builder = @import("builder/root.zig");
pub const testing = @import("testing/root.zig");

pub const build_options = @import("build_options");

test {
    std.testing.refAllDecls(@This());
}

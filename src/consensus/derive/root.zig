//! Derivation pipeline: L1 data → frames → channels → batches → payload attributes.
//! Mirrors base/base `crates/consensus/derive`.

const std = @import("std");

pub const blob = @import("blob.zig");

test {
    std.testing.refAllDecls(@This());
}

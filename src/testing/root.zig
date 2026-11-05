//! Testing infrastructure: deterministic PRNG, simulator harness, fuzz helpers.

const std = @import("std");

pub const prng = @import("prng.zig");
pub const Prng = prng.Prng;

test {
    std.testing.refAllDecls(@This());
}

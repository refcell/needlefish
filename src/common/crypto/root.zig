//! Cryptographic primitives for Base: hashes, curves, and EVM precompile math.
//! Mirrors the crypto pieces of base/base `crates/common/precompiles` and alloy/revm
//! dependencies, implemented from scratch on the Zig standard library only.

const std = @import("std");

pub const keccak = @import("keccak.zig");
pub const keccak256 = keccak.keccak256;
pub const bench = @import("bench.zig");

test {
    std.testing.refAllDecls(@This());
}

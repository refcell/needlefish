//! Cryptographic primitives for Base: hashes, curves, and EVM precompile math.
//! Mirrors the crypto pieces of base/base `crates/common/precompiles` and alloy/revm
//! dependencies, implemented from scratch on the Zig standard library only.

const std = @import("std");

pub const keccak = @import("keccak.zig");
pub const keccak256 = keccak.keccak256;
pub const sha256 = @import("sha256.zig");
pub const ripemd160 = @import("ripemd160.zig");
pub const bench = @import("bench.zig");
pub const montgomery = @import("montgomery.zig");
pub const kzg = @import("kzg/root.zig");
pub const bls12_381 = @import("bls12_381/root.zig");
pub const bigint = @import("bigint.zig");
pub const modexp = @import("modexp.zig");

test {
    std.testing.refAllDecls(@This());
}

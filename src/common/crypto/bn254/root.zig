//! bn254 (alt_bn128): field tower, G1/G2 groups, optimal ate pairing, and the
//! EIP-196/197 precompiles (0x06 add, 0x07 mul, 0x08 pairing check).

const std = @import("std");

pub const fp = @import("fp.zig");
pub const Fp = fp.Fp;
pub const Fr = fp.Fr;
pub const Fp2 = @import("fp2.zig").Fp2;
pub const Fp6 = @import("fp6.zig").Fp6;
pub const Fp12 = @import("fp12.zig").Fp12;
pub const curve = @import("curve.zig");
pub const g1 = @import("g1.zig");
pub const g2 = @import("g2.zig");
pub const pairing = @import("pairing.zig");
pub const precompile = @import("precompile.zig");
pub const vectors = @import("vectors.zig");

pub const Error = precompile.Error;
pub const precompile_bn254_add = precompile.precompile_bn254_add;
pub const precompile_bn254_mul = precompile.precompile_bn254_mul;
pub const precompile_bn254_pairing = precompile.precompile_bn254_pairing;

test {
    std.testing.refAllDecls(@This());
}

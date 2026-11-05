//! BLS12-381: fields, G1/G2 groups, optimal ate pairing, RFC 9380 hash-to-curve,
//! and the EIP-2537 precompiles. Backs KZG (EIP-4844) through the same G1/G2/Fr APIs.

const std = @import("std");

pub const fields = @import("fields.zig");
pub const Fp = fields.Fp;
pub const Fr = fields.Fr;
pub const Fp2 = fields.Fp2;
pub const Fp6 = fields.Fp6;
pub const Fp12 = fields.Fp12;

test {
    std.testing.refAllDecls(@This());
}

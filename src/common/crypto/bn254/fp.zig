//! bn254 (alt_bn128) prime fields: the base field Fp and the scalar field Fr.
//!
//! Both are 254-bit moduli over four 64-bit limbs and reuse the shared
//! `montgomery.Field`. The curve parameter x (the "BN parameter") generates both:
//! p = 36x^4 + 36x^3 + 24x^2 + 6x + 1 and r = 36x^4 + 36x^3 + 18x^2 + 6x + 1.

const std = @import("std");
const assert = std.debug.assert;
const montgomery = @import("../montgomery.zig");

/// BN parameter x (positive for bn254).
pub const curve_x: u64 = 4965661367192848881;

pub const p: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
pub const r: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

pub const Fp = montgomery.Field(4, p);
pub const Fr = montgomery.Field(4, r);

comptime {
    const x: u512 = curve_x;
    assert(p == 36 * x * x * x * x + 36 * x * x * x + 24 * x * x + 6 * x + 1);
    assert(r == 36 * x * x * x * x + 36 * x * x * x + 18 * x * x + 6 * x + 1);
    assert(p % 4 == 3);
    assert(p > r);
}

test "fp: field constants" {
    try std.testing.expect(Fp.from_int(p - 1).add(Fp.one).is_zero());
    try std.testing.expect(Fr.from_int(r - 1).add(Fr.one).is_zero());
}

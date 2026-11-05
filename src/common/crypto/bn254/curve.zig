//! Short Weierstrass curves y^2 = x^3 + b (a = 0) in Jacobian coordinates.
//!
//! Generic over the coordinate field so G1 (over Fp) and the G2 twist (over Fp2)
//! share one implementation. (X, Y, Z) represents the affine (X / Z^2, Y / Z^3);
//! Z = 0 is the point at infinity. Scalar multiplication uses width-5 wNAF.
//! Inputs to the EVM precompiles are public, so variable time is acceptable here.

const std = @import("std");
const assert = std.debug.assert;

/// Maximum number of signed digits in the wNAF of a 256-bit scalar.
pub const wnaf_digits_max = 257;
pub const wnaf_width = 5;
/// Odd multiples P, 3P, ..., 15P precomputed for width-5 wNAF.
pub const wnaf_table_size = 1 << (wnaf_width - 2);

/// Writes the width-`wnaf_width` NAF of `scalar` (least significant digit first)
/// and returns the number of digits. Every non-zero digit is odd and |digit| < 16.
pub fn wnaf_digits(scalar: u256, out: *[wnaf_digits_max]i8) u32 {
    const window: u32 = 1 << wnaf_width;
    var value: u264 = scalar;
    var length: u32 = 0;
    while (value != 0) : (length += 1) {
        assert(length < wnaf_digits_max);
        var digit: i32 = 0;
        if (value & 1 == 1) {
            digit = @intCast(value & (window - 1));
            if (digit >= window / 2) digit -= @as(i32, window);
            if (digit > 0) value -= @intCast(digit) else value += @intCast(-digit);
        }
        out[length] = @intCast(digit);
        value >>= 1;
    }
    assert(length <= 257);
    return length;
}

pub fn Curve(comptime F: type, comptime b: F) type {
    return struct {
        const Point = @This();
        pub const Field = F;
        pub const coefficient_b = b;

        x: F,
        y: F,
        z: F,

        pub const infinity: Point = .{ .x = F.one, .y = F.one, .z = F.zero };

        pub const Affine = struct {
            x: F,
            y: F,
            /// Encoded as all-zero coordinates in the precompiles.
            is_infinity: bool,

            pub const infinity_affine: Affine = .{ .x = F.zero, .y = F.zero, .is_infinity = true };

            pub fn is_on_curve(point: Affine) bool {
                if (point.is_infinity) return true;
                const right = point.x.square().mul(point.x).add(b);
                return point.y.square().eql(right);
            }

            pub fn neg(point: Affine) Affine {
                return .{ .x = point.x, .y = point.y.neg(), .is_infinity = point.is_infinity };
            }
        };

        pub fn from_affine(point: Affine) Point {
            if (point.is_infinity) return infinity;
            return .{ .x = point.x, .y = point.y, .z = F.one };
        }

        pub fn to_affine(point: Point) Affine {
            if (point.is_infinity()) return Affine.infinity_affine;
            const z_inverse = point.z.inverse();
            const z_inverse_squared = z_inverse.square();
            const result: Affine = .{
                .x = point.x.mul(z_inverse_squared),
                .y = point.y.mul(z_inverse_squared).mul(z_inverse),
                .is_infinity = false,
            };
            assert(!result.is_infinity);
            return result;
        }

        pub fn is_infinity(point: Point) bool {
            return point.z.is_zero();
        }

        pub fn is_on_curve(point: Point) bool {
            if (point.is_infinity()) return true;
            const z_squared = point.z.square();
            const z_sixth = z_squared.square().mul(z_squared);
            const right = point.x.square().mul(point.x).add(z_sixth.mul(b));
            return point.y.square().eql(right);
        }

        pub fn eql(a: Point, other: Point) bool {
            if (a.is_infinity() or other.is_infinity()) {
                return a.is_infinity() and other.is_infinity();
            }
            const a_z_squared = a.z.square();
            const other_z_squared = other.z.square();
            if (!a.x.mul(other_z_squared).eql(other.x.mul(a_z_squared))) return false;
            const a_y_scaled = a.y.mul(other_z_squared).mul(other.z);
            return a_y_scaled.eql(other.y.mul(a_z_squared).mul(a.z));
        }

        pub fn neg(point: Point) Point {
            return .{ .x = point.x, .y = point.y.neg(), .z = point.z };
        }

        /// dbl-2009-l (a = 0): 2M + 5S. Doubling infinity yields infinity (Z3 = 0).
        pub fn double(point: Point) Point {
            const xx = point.x.square();
            const yy = point.y.square();
            const yyyy = yy.square();
            const d = point.x.add(yy).square().sub(xx).sub(yyyy).double();
            const e = xx.double().add(xx);
            const x3 = e.square().sub(d.double());
            const eight_yyyy = yyyy.double().double().double();
            const result: Point = .{
                .x = x3,
                .y = e.mul(d.sub(x3)).sub(eight_yyyy),
                .z = point.y.mul(point.z).double(),
            };
            assert(point.is_infinity() == result.is_infinity() or point.y.is_zero());
            return result;
        }

        /// add-2007-bl with explicit handling of infinity and equal inputs.
        pub fn add(a: Point, other: Point) Point {
            if (a.is_infinity()) return other;
            if (other.is_infinity()) return a;
            const z1z1 = a.z.square();
            const z2z2 = other.z.square();
            const x1_scaled = a.x.mul(z2z2);
            const x2_scaled = other.x.mul(z1z1);
            const s1 = a.y.mul(other.z).mul(z2z2);
            const s2 = other.y.mul(a.z).mul(z1z1);
            const h = x2_scaled.sub(x1_scaled);
            const r = s2.sub(s1).double();
            if (h.is_zero()) {
                if (r.is_zero()) return a.double();
                return infinity;
            }
            const i = h.double().square();
            const j = h.mul(i);
            const v = x1_scaled.mul(i);
            const x3 = r.square().sub(j).sub(v.double());
            const result: Point = .{
                .x = x3,
                .y = r.mul(v.sub(x3)).sub(s1.mul(j).double()),
                .z = a.z.add(other.z).square().sub(z1z1).sub(z2z2).mul(h),
            };
            assert(!result.is_infinity());
            return result;
        }

        /// madd-2007-bl: `other` is affine (Z = 1).
        pub fn add_affine(a: Point, other: Affine) Point {
            if (other.is_infinity) return a;
            if (a.is_infinity()) return from_affine(other);
            const z1z1 = a.z.square();
            const x2_scaled = other.x.mul(z1z1);
            const s2 = other.y.mul(a.z).mul(z1z1);
            const h = x2_scaled.sub(a.x);
            const r = s2.sub(a.y).double();
            if (h.is_zero()) {
                if (r.is_zero()) return a.double();
                return infinity;
            }
            const hh = h.square();
            const i = hh.double().double();
            const j = h.mul(i);
            const v = a.x.mul(i);
            const x3 = r.square().sub(j).sub(v.double());
            const result: Point = .{
                .x = x3,
                .y = r.mul(v.sub(x3)).sub(a.y.mul(j).double()),
                .z = a.z.add(h).square().sub(z1z1).sub(hh),
            };
            assert(!result.is_infinity());
            return result;
        }

        pub const Table = [wnaf_table_size]Point;

        /// Odd multiples P, 3P, 5P, ..., 15P.
        pub fn odd_multiples(point: Point) Table {
            var table: Table = undefined;
            table[0] = point;
            const twice = point.double();
            for (1..wnaf_table_size) |index| table[index] = table[index - 1].add(twice);
            assert(table.len == 8);
            return table;
        }

        /// Adds digit * P using the odd-multiple table of P.
        pub fn add_digit(accumulator: Point, table: *const Table, digit: i8) Point {
            assert(digit == 0 or @rem(digit, 2) != 0);
            if (digit > 0) return accumulator.add(table[@intCast(@divTrunc(digit - 1, 2))]);
            if (digit < 0) return accumulator.add(table[@intCast(@divTrunc(-digit - 1, 2))].neg());
            return accumulator;
        }

        /// scalar * point (scalar used as a plain integer, not reduced).
        pub fn mul(point: Point, scalar: u256) Point {
            var digits: [wnaf_digits_max]i8 = undefined;
            const length = wnaf_digits(scalar, &digits);
            const table = odd_multiples(point);
            var result = infinity;
            var index = length;
            while (index > 0) {
                index -= 1;
                result = result.double();
                result = add_digit(result, &table, digits[index]);
            }
            assert(scalar != 0 or result.is_infinity());
            return result;
        }

        /// Reference double-and-add for tests (no tables, no NAF).
        pub fn mul_reference(point: Point, scalar: u256) Point {
            var result = infinity;
            var index: u32 = 256;
            while (index > 0) {
                index -= 1;
                result = result.double();
                if ((scalar >> @intCast(index)) & 1 == 1) result = result.add(point);
            }
            return result;
        }
    };
}

test "curve: wnaf digits reconstruct the scalar" {
    const Prng = @import("../../../testing/prng.zig").Prng;
    var prng = Prng.init(0x7a4f);
    var digits: [wnaf_digits_max]i8 = undefined;
    const edge = [_]u256{ 0, 1, 15, 16, 31, std.math.maxInt(u256), 1 << 255 };
    for (0..300) |round| {
        const scalar: u256 = if (round < edge.len) edge[round] else prng.int(u256);
        const length = wnaf_digits(scalar, &digits);
        var value: i512 = 0;
        var index = length;
        while (index > 0) {
            index -= 1;
            value = value * 2 + digits[index];
            try std.testing.expect(digits[index] == 0 or @rem(digits[index], 2) != 0);
        }
        try std.testing.expectEqual(@as(i512, scalar), value);
    }
}

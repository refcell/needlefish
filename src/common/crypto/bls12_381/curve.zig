//! Short Weierstrass curves y^2 = x^3 + b (a = 0) in Jacobian coordinates,
//! generic over the coordinate field so G1 (over Fp) and G2 (over Fp2) share one
//! implementation. A Jacobian point (X, Y, Z) is the affine point (X/Z^2, Y/Z^3);
//! Z = 0 is the point at infinity.
//!
//! These routines branch on point values and scalar bits: they are variable time
//! and intended for public data (precompiles, KZG verification), not secret keys.

const std = @import("std");
const assert = std.debug.assert;

pub fn Curve(comptime F: type, comptime b: F) type {
    return struct {
        const Self = @This();
        pub const Field = F;
        pub const coefficient_b = b;

        pub const Affine = struct {
            x: F,
            y: F,
            infinity: bool,

            pub const identity: Affine = .{ .x = F.zero, .y = F.zero, .infinity = true };

            pub fn is_on_curve(point: Affine) bool {
                if (point.infinity) return true;
                const rhs = point.x.square().mul(point.x).add(b);
                return point.y.square().eql(rhs);
            }

            pub fn neg(point: Affine) Affine {
                return .{ .x = point.x, .y = point.y.neg(), .infinity = point.infinity };
            }

            pub fn eql(a: Affine, other: Affine) bool {
                if (a.infinity or other.infinity) return a.infinity == other.infinity;
                return a.x.eql(other.x) and a.y.eql(other.y);
            }

            pub fn to_jacobian(point: Affine) Self {
                if (point.infinity) return Self.identity;
                return .{ .x = point.x, .y = point.y, .z = F.one };
            }
        };

        x: F,
        y: F,
        z: F,

        pub const identity: Self = .{ .x = F.one, .y = F.one, .z = F.zero };

        pub fn is_identity(point: Self) bool {
            return point.z.is_zero();
        }

        pub fn is_on_curve(point: Self) bool {
            if (point.is_identity()) return true;
            // Y^2 = X^3 + b Z^6.
            const z2 = point.z.square();
            const z6 = z2.square().mul(z2);
            const rhs = point.x.square().mul(point.x).add(z6.mul(b));
            return point.y.square().eql(rhs);
        }

        pub fn to_affine(point: Self) Affine {
            if (point.is_identity()) return Affine.identity;
            const z_inverse = point.z.inverse();
            const z_inverse2 = z_inverse.square();
            const result: Affine = .{
                .x = point.x.mul(z_inverse2),
                .y = point.y.mul(z_inverse2.mul(z_inverse)),
                .infinity = false,
            };
            assert(!result.infinity);
            return result;
        }

        /// Converts many points with one inversion (Montgomery's trick).
        /// `scratch` must hold at least `points.len` field elements.
        pub fn batch_to_affine(points: []const Self, out: []Affine, scratch: []F) void {
            assert(out.len == points.len);
            assert(scratch.len >= points.len);
            var accumulator = F.one;
            for (points, 0..) |point, index| {
                scratch[index] = accumulator;
                if (!point.is_identity()) accumulator = accumulator.mul(point.z);
            }
            var inverse = accumulator.inverse();
            var index = points.len;
            while (index > 0) {
                index -= 1;
                const point = points[index];
                if (point.is_identity()) {
                    out[index] = Affine.identity;
                    continue;
                }
                const z_inverse = inverse.mul(scratch[index]);
                inverse = inverse.mul(point.z);
                const z_inverse2 = z_inverse.square();
                out[index] = .{
                    .x = point.x.mul(z_inverse2),
                    .y = point.y.mul(z_inverse2.mul(z_inverse)),
                    .infinity = false,
                };
            }
        }

        /// Projective equality: X1 Z2^2 = X2 Z1^2 and Y1 Z2^3 = Y2 Z1^3.
        pub fn eql(a: Self, other: Self) bool {
            if (a.is_identity() or other.is_identity()) {
                return a.is_identity() == other.is_identity();
            }
            const z1z1 = a.z.square();
            const z2z2 = other.z.square();
            if (!a.x.mul(z2z2).eql(other.x.mul(z1z1))) return false;
            return a.y.mul(z2z2.mul(other.z)).eql(other.y.mul(z1z1.mul(a.z)));
        }

        pub fn neg(point: Self) Self {
            return .{ .x = point.x, .y = point.y.neg(), .z = point.z };
        }

        /// dbl-2009-l.
        pub fn double(point: Self) Self {
            if (point.is_identity()) return point;
            const a = point.x.square();
            const b2 = point.y.square();
            const c = b2.square();
            const d = point.x.add(b2).square().sub(a).sub(c).double();
            const e = a.double().add(a);
            const f = e.square();
            const x3 = f.sub(d.double());
            const c8 = c.double().double().double();
            const result: Self = .{
                .x = x3,
                .y = e.mul(d.sub(x3)).sub(c8),
                .z = point.y.mul(point.z).double(),
            };
            assert(result.is_identity() == point.y.is_zero());
            return result;
        }

        /// add-2007-bl, with the exceptional cases handled explicitly.
        pub fn add(p1: Self, p2: Self) Self {
            if (p1.is_identity()) return p2;
            if (p2.is_identity()) return p1;
            const z1z1 = p1.z.square();
            const z2z2 = p2.z.square();
            const scaled_x1 = p1.x.mul(z2z2);
            const scaled_x2 = p2.x.mul(z1z1);
            const s1 = p1.y.mul(p2.z).mul(z2z2);
            const s2 = p2.y.mul(p1.z).mul(z1z1);
            const h = scaled_x2.sub(scaled_x1);
            const r = s2.sub(s1).double();
            if (h.is_zero()) {
                if (r.is_zero()) return p1.double();
                return identity;
            }
            const i = h.double().square();
            const j = h.mul(i);
            const v = scaled_x1.mul(i);
            const x3 = r.square().sub(j).sub(v.double());
            const result: Self = .{
                .x = x3,
                .y = r.mul(v.sub(x3)).sub(s1.mul(j).double()),
                .z = p1.z.add(p2.z).square().sub(z1z1).sub(z2z2).mul(h),
            };
            assert(!result.is_identity());
            return result;
        }

        /// madd-2007-bl: Jacobian plus affine.
        pub fn add_affine(p1: Self, p2: Affine) Self {
            if (p2.infinity) return p1;
            if (p1.is_identity()) return p2.to_jacobian();
            const z1z1 = p1.z.square();
            const scaled_x2 = p2.x.mul(z1z1);
            const s2 = p2.y.mul(p1.z).mul(z1z1);
            const h = scaled_x2.sub(p1.x);
            const r = s2.sub(p1.y).double();
            if (h.is_zero()) {
                if (r.is_zero()) return p1.double();
                return identity;
            }
            const hh = h.square();
            const i = hh.double().double();
            const j = h.mul(i);
            const v = p1.x.mul(i);
            const x3 = r.square().sub(j).sub(v.double());
            const result: Self = .{
                .x = x3,
                .y = r.mul(v.sub(x3)).sub(p1.y.mul(j).double()),
                .z = p1.z.add(h).square().sub(z1z1).sub(hh),
            };
            assert(!result.is_identity());
            return result;
        }

        pub fn sub(p1: Self, p2: Self) Self {
            return p1.add(p2.neg());
        }

        /// Scalar multiplication with a fixed 4-bit window (public scalar).
        pub fn mul(point: Self, scalar: u256) Self {
            var table: [16]Self = undefined;
            table[0] = identity;
            table[1] = point;
            for (2..16) |index| table[index] = table[index - 1].add(point);
            var result = identity;
            var window: u32 = 64;
            while (window > 0) {
                window -= 1;
                if (!result.is_identity()) {
                    inline for (0..4) |_| result = result.double();
                }
                const digit: u4 = @truncate(scalar >> @intCast(window * 4));
                if (digit != 0) result = result.add(table[digit]);
            }
            assert(scalar != 0 or result.is_identity());
            return result;
        }

        /// Multiplication by a 64-bit public scalar (double-and-add, MSB first).
        pub fn mul_u64(point: Self, scalar: u64) Self {
            var result = identity;
            var bit: u32 = 64;
            while (bit > 0) {
                bit -= 1;
                result = result.double();
                if ((scalar >> @intCast(bit)) & 1 == 1) result = result.add(point);
            }
            assert(scalar != 0 or result.is_identity());
            return result;
        }
    };
}

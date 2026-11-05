//! secp256k1 group operations (y^2 = x^3 + 7).
//!
//! Two independent paths:
//! - Variable time, for public data (ecrecover): Jacobian coordinates with an
//!   explicit infinity flag and every exceptional case handled, plus a GLV + wNAF
//!   Strauss-Shamir double-scalar multiplication g_factor G + r_factor R.
//! - Constant time, for secrets (signing, public keys): homogeneous projective
//!   coordinates with complete addition formulas (Renes-Costello-Batina 2015,
//!   algorithm 8) over a signed 4-bit window table, with masked table scans.

const std = @import("std");
const assert = std.debug.assert;
const field = @import("field.zig");
const scalar_module = @import("scalar.zig");
const table = @import("table.zig");
const Fe = field.Fe;
const Scalar = scalar_module.Scalar;
const FieldInverse = @import("modinv.zig").Modulus(field.p_int);

pub const Affine = table.Affine;

const curve_b = Fe.from_int(7);
const beta = Fe.from_int(table.beta_int);
pub const generator: Affine = .{ .x = Fe.from_int(table.g_x_int), .y = Fe.from_int(table.g_y_int) };

pub fn on_curve(point: Affine) bool {
    const right = point.x.sqr().mul(point.x).add(curve_b);
    return point.y.sqr().equal(right);
}

/// The curve point with abscissa `x` and the requested y parity, if any.
pub fn decompress(x: Fe, y_odd: bool) ?Affine {
    const right = x.sqr().mul(x).add(curve_b);
    var y = right.sqrt() orelse return null;
    if (y.is_odd() != y_odd) y = y.neg();
    const point: Affine = .{ .x = x, .y = y.normalize() };
    assert(on_curve(point));
    assert(point.y.is_odd() == y_odd);
    return point;
}

pub const Jacobian = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    infinity: bool,

    pub const identity: Jacobian = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero, .infinity = true };

    pub fn from_affine(point: Affine) Jacobian {
        assert(!point.x.is_zero() or !point.y.is_zero());
        return .{ .x = point.x, .y = point.y, .z = Fe.one, .infinity = false };
    }

    /// Affine form in variable time (for public points).
    pub fn to_affine(point: Jacobian) ?Affine {
        if (point.infinity) return null;
        assert(!point.z.is_zero());
        const z_inverse = Fe.from_int(FieldInverse.invert(point.z.to_int()));
        const z_inverse_squared = z_inverse.sqr();
        return .{
            .x = point.x.mul(z_inverse_squared).normalize(),
            .y = point.y.mul(z_inverse_squared.mul(z_inverse)).normalize(),
        };
    }

    pub fn negate(point: Jacobian) Jacobian {
        return .{ .x = point.x, .y = point.y.neg(), .z = point.z, .infinity = point.infinity };
    }

    /// dbl-2009-l (a = 0). The curve has prime order, so no finite point doubles
    /// to infinity.
    pub fn dbl(point: Jacobian) Jacobian {
        if (point.infinity) return point;
        const a = point.x.sqr();
        const b = point.y.sqr();
        const c = b.sqr();
        const d = point.x.add(b).sqr().sub(a).sub(c).dbl();
        const e = a.mul_small(3);
        const x3 = e.sqr().sub(d.dbl());
        const y3 = e.mul(d.sub(x3)).sub(c.mul_small(8));
        const z3 = point.y.mul(point.z).dbl();
        assert(!z3.is_zero());
        return .{ .x = x3, .y = y3, .z = z3, .infinity = false };
    }

    /// Variable-time mixed addition (madd-2004-hmv) with all special cases.
    pub fn add_affine(a: Jacobian, b: Affine) Jacobian {
        if (a.infinity) return from_affine(b);
        const z1z1 = a.z.sqr();
        const x2_scaled = b.x.mul(z1z1);
        const s2 = b.y.mul(a.z).mul(z1z1);
        const h = x2_scaled.sub(a.x);
        const r = s2.sub(a.y);
        if (h.is_zero()) {
            if (r.is_zero()) return a.dbl();
            return identity;
        }
        const hh = h.sqr();
        const hhh = h.mul(hh);
        const v = a.x.mul(hh);
        const x3 = r.sqr().sub(hhh).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(a.y.mul(hhh));
        const z3 = a.z.mul(h);
        assert(!z3.is_zero());
        return .{ .x = x3, .y = y3, .z = z3, .infinity = false };
    }

    /// Variable-time general addition (add-1998-cmo-2) with all special cases.
    pub fn add(a: Jacobian, b: Jacobian) Jacobian {
        if (a.infinity) return b;
        if (b.infinity) return a;
        const z1z1 = a.z.sqr();
        const z2z2 = b.z.sqr();
        const x1_scaled = a.x.mul(z2z2);
        const x2_scaled = b.x.mul(z1z1);
        const s1 = a.y.mul(b.z).mul(z2z2);
        const s2 = b.y.mul(a.z).mul(z1z1);
        const h = x2_scaled.sub(x1_scaled);
        const r = s2.sub(s1);
        if (h.is_zero()) {
            if (r.is_zero()) return a.dbl();
            return identity;
        }
        const hh = h.sqr();
        const hhh = h.mul(hh);
        const v = x1_scaled.mul(hh);
        const x3 = r.sqr().sub(hhh).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(hhh));
        const z3 = a.z.mul(b.z).mul(h);
        assert(!z3.is_zero());
        return .{ .x = x3, .y = y3, .z = z3, .infinity = false };
    }
};

/// wNAF window for the arbitrary point R (2^(window-2) odd multiples).
const r_window = 5;
const r_table_size = 1 << (r_window - 2);

const Recoded = struct {
    digits: [scalar_module.wnaf_length_max]i8,
    length: u32,
};

fn recode(half: scalar_module.SignedHalf, comptime window: u4) Recoded {
    var recoded: Recoded = undefined;
    recoded.length = scalar_module.wnaf(half.magnitude, window, &recoded.digits);
    if (half.negative) {
        for (recoded.digits[0..recoded.length]) |*digit| digit.* = -digit.*;
    }
    assert(recoded.length <= scalar_module.wnaf_length_max);
    return recoded;
}

fn odd_multiples(point: Affine) [r_table_size]Jacobian {
    var multiples: [r_table_size]Jacobian = undefined;
    multiples[0] = Jacobian.from_affine(point);
    const twice = multiples[0].dbl();
    for (1..r_table_size) |index| multiples[index] = multiples[index - 1].add(twice);
    assert(!multiples[0].infinity);
    return multiples;
}

inline fn add_jacobian_digit(
    acc: Jacobian,
    multiples: *const [r_table_size]Jacobian,
    digit: i8,
) Jacobian {
    if (digit > 0) return acc.add(multiples[@intCast((digit - 1) >> 1)]);
    if (digit < 0) return acc.add(multiples[@intCast((-digit - 1) >> 1)].negate());
    return acc;
}

inline fn add_affine_digit(
    acc: Jacobian,
    multiples: *const [table.g_table_size]Affine,
    digit: i8,
) Jacobian {
    if (digit > 0) return acc.add_affine(multiples[@intCast((digit - 1) >> 1)]);
    if (digit < 0) {
        const entry = multiples[@intCast((-digit - 1) >> 1)];
        return acc.add_affine(.{ .x = entry.x, .y = entry.y.neg() });
    }
    return acc;
}

/// g_factor G + r_factor R in variable time (Strauss-Shamir with GLV on both scalars).
pub fn mul_double_var(g_factor: Scalar, r_factor: Scalar, r_point: Affine) Jacobian {
    assert(on_curve(r_point));
    const g_halves = scalar_module.split_lambda(g_factor);
    const r_halves = scalar_module.split_lambda(r_factor);
    const g1 = recode(g_halves[0], table.g_window);
    const g2 = recode(g_halves[1], table.g_window);
    const r1 = recode(r_halves[0], r_window);
    const r2 = recode(r_halves[1], r_window);

    const r_multiples = odd_multiples(r_point);
    var r_lambda_multiples: [r_table_size]Jacobian = r_multiples;
    for (&r_lambda_multiples) |*entry| entry.x = entry.x.mul(beta);

    const length = @max(@max(g1.length, g2.length), @max(r1.length, r2.length));
    var acc = Jacobian.identity;
    var index = length;
    while (index > 0) {
        index -= 1;
        acc = acc.dbl();
        acc = add_jacobian_digit(acc, &r_multiples, r1.digits[index]);
        acc = add_jacobian_digit(acc, &r_lambda_multiples, r2.digits[index]);
        acc = add_affine_digit(acc, &table.g_odd, g1.digits[index]);
        acc = add_affine_digit(acc, &table.g_lambda_odd, g2.digits[index]);
    }
    assert(index == 0);
    return acc;
}

/// Homogeneous projective point (X : Y : Z) for the constant-time path.
const Projective = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Complete mixed addition, RCB15 algorithm 8 (a = 0, b3 = 21). Correct for
    /// every `a` (including identity and a == b) as long as `b` is a curve point.
    fn add_affine(a: Projective, b: Affine) Projective {
        var t0 = a.x.mul(b.x);
        var t1 = a.y.mul(b.y);
        var t3 = b.x.add(b.y);
        var t4 = a.x.add(a.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = b.y.mul(a.z).add(a.y);
        var y3 = b.x.mul(a.z).add(a.x);
        var x3 = t0.dbl();
        t0 = x3.add(t0);
        var t2 = a.z.mul_small(21);
        var z3 = t1.add(t2);
        t1 = t1.sub(t2);
        y3 = y3.mul_small(21);
        x3 = t4.mul(y3);
        t2 = t3.mul(t1);
        x3 = t2.sub(x3);
        y3 = y3.mul(t0);
        t1 = t1.mul(z3);
        y3 = t1.add(y3);
        t0 = t0.mul(t3);
        z3 = z3.mul(t4).add(t0);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn select(a: Projective, b: Projective, flag: u1) Projective {
        return .{
            .x = a.x.select(b.x, flag),
            .y = a.y.select(b.y, flag),
            .z = a.z.select(b.z, flag),
        };
    }
};

/// Scans a whole row and returns entry |digit| - 1, negated when digit < 0 (zero
/// when digit is 0). Memory access and branches do not depend on the digit.
fn lookup(row: *const [table.gen_row_size]Affine, digit: i8) Affine {
    const sign: u8 = @bitCast(digit >> 7);
    const magnitude: u8 = (@as(u8, @bitCast(digit)) ^ sign) -% sign;
    assert(magnitude <= table.gen_row_size);
    var result: Affine = .{ .x = Fe.zero, .y = Fe.zero };
    for (row, 1..) |entry, position| {
        const flag: u1 = @intFromBool(magnitude == position);
        result.x = result.x.select(entry.x, flag);
        result.y = result.y.select(entry.y, flag);
    }
    result.y = result.y.select(result.y.neg(), @truncate(sign));
    return result;
}

/// k G in constant time. Returns null only for k = 0.
pub fn mul_generator_ct(k: Scalar) ?Affine {
    // Signed nibbles in [-8, 7] plus a final carry digit, so k = sum d_i 16^i.
    var digits: [table.gen_row_count]i8 = undefined;
    var carry: u8 = 0;
    for (0..64) |index| {
        const limb = k.limbs[index / 16];
        const nibble: u8 = @as(u8, @truncate(limb >> @intCast(4 * (index % 16)))) & 0x0f;
        const value = nibble + carry;
        carry = (value + 8) >> 4;
        digits[index] = @intCast(@as(i16, value) - 16 * @as(i16, carry));
    }
    digits[64] = @intCast(carry);
    assert(carry <= 1);

    var acc = Projective.identity;
    for (&table.gen_rows, digits) |*row, digit| {
        const sum = acc.add_affine(lookup(row, digit));
        acc = acc.select(sum, @intFromBool(digit != 0));
    }
    if (k.is_zero()) return null;
    const z_inverse = acc.z.invert();
    const point: Affine = .{
        .x = acc.x.mul(z_inverse).normalize(),
        .y = acc.y.mul(z_inverse).normalize(),
    };
    assert(on_curve(point));
    return point;
}

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
const ct = @import("../ct.zig");
const field = @import("field.zig");
const scalar_module = @import("scalar.zig");
const table = @import("table.zig");
const Fe = field.Fe;
const Scalar = scalar_module.Scalar;
const FieldInverse = @import("../safegcd.zig").Modulus(u256, field.p_int);

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

    /// Doubling with the libsecp256k1 formula (3M + 4S): L = 3/2 X^2, S = Y^2,
    /// X3 = L^2 - 2 X S, Y3 = L (X S - X3) - S^2, Z3 = Y Z. The curve has prime
    /// order, so no finite point doubles to infinity.
    pub fn dbl(point: Jacobian) Jacobian {
        if (point.infinity) return point;
        const z3 = point.y.mul(point.z);
        const s = point.y.sqr();
        const l = point.x.sqr().mul_small(3).half();
        const xs = point.x.mul(s);
        const x3 = l.sqr().sub(xs).sub(xs);
        const y3 = l.mul(xs.sub(x3)).sub(s.sqr());
        assert(!z3.is_zero());
        return .{ .x = x3, .y = y3, .z = z3, .infinity = false };
    }

    /// Variable-time mixed addition (madd-2004-hmv) with all special cases.
    pub fn add_affine(a: Jacobian, b: Affine) Jacobian {
        return a.add_affine_scaled(b, null, null);
    }

    /// Mixed addition of `b` taken with Jacobian z = 1 / `b_z_inverse` (null means 1),
    /// so a point affine in one frame adds into an accumulator kept in a frame whose
    /// coordinates are scaled by `b_z_inverse`. `ratio`, when given, receives z3 / a.z
    /// (only for operands that hit no special case).
    fn add_affine_scaled(a: Jacobian, b: Affine, b_z_inverse: ?Fe, ratio: ?*Fe) Jacobian {
        if (a.infinity) {
            assert(ratio == null);
            const scale = b_z_inverse orelse return from_affine(b);
            const scale_squared = scale.sqr();
            return from_affine(.{
                .x = b.x.mul(scale_squared),
                .y = b.y.mul(scale_squared.mul(scale)),
            });
        }
        const az = if (b_z_inverse) |scale| a.z.mul(scale) else a.z;
        const z1z1 = az.sqr();
        const x2_scaled = b.x.mul(z1z1);
        const s2 = b.y.mul(az).mul(z1z1);
        const h = x2_scaled.sub(a.x);
        const r = s2.sub(a.y);
        if (h.is_zero()) {
            assert(ratio == null);
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
        if (ratio) |out| out.* = h;
        return .{ .x = x3, .y = y3, .z = z3, .infinity = false };
    }
};

/// wNAF window for the arbitrary point R (2^(window-2) odd multiples).
const r_window = 5;
const r_table_size = 1 << (r_window - 2);

const Recoded = struct {
    digits: [scalar_module.wnaf_length_max]i16,
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

/// Odd multiples R, 3R, ..., 15R as affine points of an isomorphic frame in which a
/// Jacobian (X, Y, Z) stands for the real point (X, Y, Z * global_z). Every R digit
/// then costs a mixed addition instead of a general one (libsecp256k1's global-z
/// table). The a = 0 formulas do not involve b, so they hold in the frame unchanged.
const RTable = struct {
    entries: [r_table_size]Affine,
    global_z: Fe,
};

fn odd_multiples(point: Affine) RTable {
    // Frame scaled by twice.z, where 2R is affine and R is (x z^2, y z^3).
    const twice = Jacobian.from_affine(point).dbl();
    const twice_frame: Affine = .{ .x = twice.x, .y = twice.y };
    const z_squared = twice.z.sqr();
    var jacobian: [r_table_size]Jacobian = undefined;
    var ratios: [r_table_size]Fe = undefined;
    jacobian[0] = Jacobian.from_affine(.{
        .x = point.x.mul(z_squared),
        .y = point.y.mul(z_squared.mul(twice.z)),
    });
    // (2i + 1)R + 2R hits no special case: the order is prime and above 2i + 3.
    for (1..r_table_size) |index| {
        jacobian[index] = jacobian[index - 1].add_affine_scaled(twice_frame, null, &ratios[index]);
    }
    // Rescale entry i by z_last / z_i, the product of the later ratios.
    const last = r_table_size - 1;
    var table_out: RTable = undefined;
    table_out.entries[last] = .{ .x = jacobian[last].x, .y = jacobian[last].y };
    var scale = ratios[last];
    var index: usize = last;
    while (index > 0) {
        index -= 1;
        const scale_squared = scale.sqr();
        table_out.entries[index] = .{
            .x = jacobian[index].x.mul(scale_squared),
            .y = jacobian[index].y.mul(scale_squared.mul(scale)),
        };
        if (index > 0) scale = scale.mul(ratios[index]);
    }
    table_out.global_z = jacobian[last].z.mul(twice.z);
    assert(!table_out.global_z.is_zero());
    assert(!jacobian[last].infinity);
    return table_out;
}

inline fn add_r_digit(
    acc: Jacobian,
    multiples: *const [r_table_size]Affine,
    digit: i16,
) Jacobian {
    if (digit > 0) return acc.add_affine(multiples[@intCast((digit - 1) >> 1)]);
    if (digit < 0) {
        const entry = multiples[@intCast((-digit - 1) >> 1)];
        return acc.add_affine(.{ .x = entry.x, .y = entry.y.neg() });
    }
    return acc;
}

/// Adds a real affine G multiple into an accumulator kept in the R table's frame.
inline fn add_g_digit(
    acc: Jacobian,
    multiples: *const [table.g_table_size]Affine,
    digit: i16,
    global_z: Fe,
) Jacobian {
    if (digit > 0) {
        return acc.add_affine_scaled(multiples[@intCast((digit - 1) >> 1)], global_z, null);
    }
    if (digit < 0) {
        const entry = multiples[@intCast((-digit - 1) >> 1)];
        return acc.add_affine_scaled(.{ .x = entry.x, .y = entry.y.neg() }, global_z, null);
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

    const r_table = odd_multiples(r_point);
    var r_lambda_multiples: [r_table_size]Affine = r_table.entries;
    for (&r_lambda_multiples) |*entry| entry.x = entry.x.mul(beta);

    const length = @max(@max(g1.length, g2.length), @max(r1.length, r2.length));
    var acc = Jacobian.identity;
    var index = length;
    while (index > 0) {
        index -= 1;
        acc = acc.dbl();
        acc = add_r_digit(acc, &r_table.entries, r1.digits[index]);
        acc = add_r_digit(acc, &r_lambda_multiples, r2.digits[index]);
        acc = add_g_digit(acc, &table.g_odd, g1.digits[index], r_table.global_z);
        acc = add_g_digit(acc, &table.g_lambda_odd, g2.digits[index], r_table.global_z);
    }
    assert(index == 0);
    // Back from the frame to real Jacobian coordinates.
    if (!acc.infinity) acc.z = acc.z.mul(r_table.global_z);
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

    /// Complete doubling, RCB15 algorithm 9 (a = 0, b3 = 21). Correct for every
    /// point including the identity.
    fn dbl(a: Projective) Projective {
        const t0 = a.y.sqr();
        var z3 = t0.mul_small(8);
        var t1 = a.y.mul(a.z);
        var t2 = a.z.sqr().mul_small(21);
        var x3 = t2.mul(z3);
        var y3 = t0.add(t2);
        z3 = t1.mul(z3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        const t0_reduced = t0.sub(t2);
        y3 = t0_reduced.mul(y3).add(x3);
        t1 = a.x.mul(a.y);
        x3 = t0_reduced.mul(t1).dbl();
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
pub fn lookup(row: *const [table.gen_row_size]Affine, digit: i8) Affine {
    const sign: u8 = @bitCast(digit >> 7);
    const magnitude: u8 = (@as(u8, @bitCast(digit)) ^ sign) -% sign;
    assert(magnitude <= table.gen_row_size);
    var result: Affine = .{ .x = Fe.zero, .y = Fe.zero };
    for (row, 1..) |entry, position| {
        const flag = ct.equal(magnitude, position);
        result.x = result.x.select(entry.x, flag);
        result.y = result.y.select(entry.y, flag);
    }
    result.y = result.y.select(result.y.neg(), @truncate(sign));
    return result;
}

/// Signed nibbles in [-8, 7] plus a final carry digit, so k = sum d_i 16^i.
/// Branch-free in k.
fn signed_nibbles(k: Scalar) [table.gen_row_count]i8 {
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
    assert(digits.len == 65);
    return digits;
}

/// Affine form of a constant-time projective result. The variable-time inversion
/// runs on Z * blind, which is independent of the secret for a secret uniform blind.
fn to_affine_blinded(acc: Projective, blind: Fe) Affine {
    assert(!acc.z.is_zero());
    const z_inverse = if (blind.is_zero())
        acc.z.invert()
    else
        Fe.from_int(FieldInverse.invert(acc.z.mul(blind).to_int())).mul(blind);
    const point: Affine = .{
        .x = acc.x.mul(z_inverse).normalize(),
        .y = acc.y.mul(z_inverse).normalize(),
    };
    assert(on_curve(point));
    return point;
}

/// k G in constant time. Returns null only for k = 0. `blind` is a secret, uniformly
/// random field element: the final inversion runs in variable time on Z * blind,
/// which is independent of k, so its timing reveals nothing about k.
pub fn mul_generator_ct(k: Scalar, blind: Fe) ?Affine {
    const digits = signed_nibbles(k);
    var acc = Projective.identity;
    for (&table.gen_rows, digits) |*row, digit| {
        const sum = acc.add_affine(lookup(row, digit));
        acc = acc.select(sum, ct.nonzero(@as(u8, @bitCast(digit))));
    }
    if (k.is_zero()) return null;
    return to_affine_blinded(acc, blind);
}

/// [P, 2P, ..., 8P] in affine form with one shared inversion. P is public.
fn small_multiples_affine(base: Affine) [table.gen_row_size]Affine {
    var jacobian: [table.gen_row_size]Jacobian = undefined;
    jacobian[0] = Jacobian.from_affine(base);
    for (1..jacobian.len) |index| jacobian[index] = jacobian[index - 1].add_affine(base);
    // Prime order: iP for i <= 8 is never the identity.
    var prefix: [table.gen_row_size]Fe = undefined;
    var product = Fe.one;
    for (jacobian, &prefix) |entry, *slot| {
        assert(!entry.infinity);
        slot.* = product;
        product = product.mul(entry.z);
    }
    var inverse = Fe.from_int(FieldInverse.invert(product.to_int()));
    var multiples: [table.gen_row_size]Affine = undefined;
    var index: usize = jacobian.len;
    while (index > 0) {
        index -= 1;
        const z_inverse = inverse.mul(prefix[index]);
        inverse = inverse.mul(jacobian[index].z);
        const z_inverse_squared = z_inverse.sqr();
        multiples[index] = .{
            .x = jacobian[index].x.mul(z_inverse_squared).normalize(),
            .y = jacobian[index].y.mul(z_inverse_squared.mul(z_inverse)).normalize(),
        };
    }
    assert(multiples[0].x.equal(base.x));
    return multiples;
}

/// k P in constant time in k for a public curve point P (ECDH). Returns null only
/// for k = 0. The table of P multiples is built in variable time (P is public); the
/// digit loop uses complete formulas, full-row lookups, and no secret branches.
/// `blind` has the same role as in `mul_generator_ct`.
pub fn mul_ct(base: Affine, k: Scalar, blind: Fe) ?Affine {
    assert(on_curve(base));
    const multiples = small_multiples_affine(base);
    const digits = signed_nibbles(k);
    var acc = Projective.identity;
    var index: usize = digits.len;
    while (index > 0) {
        index -= 1;
        for (0..4) |_| acc = acc.dbl();
        const sum = acc.add_affine(lookup(&multiples, digits[index]));
        acc = acc.select(sum, ct.nonzero(@as(u8, @bitCast(digits[index]))));
    }
    if (k.is_zero()) return null;
    return to_affine_blinded(acc, blind);
}

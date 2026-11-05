//! Optimal ate pairing on bn254.
//!
//! Miller loop over the NAF of 6x + 2 with the G2 accumulator in homogeneous
//! projective coordinates, so line functions need no inversions (Costello,
//! Lange, Naehrig, "Faster pairing computations on curves with high-degree
//! twists"). The twist is D-type, so each line is sparse in Fp12 at positions
//! (0, 3, 4). Pairs are processed in lockstep chunks so one Fp12 squaring per
//! loop step serves every pair, and all chunks share a single final
//! exponentiation (easy part, then the Fuentes-Castaneda et al. hard part).

const std = @import("std");
const assert = std.debug.assert;
const fp = @import("fp.zig");
const Fp = fp.Fp;
const Fp2 = @import("fp2.zig").Fp2;
const Fp12 = @import("fp12.zig").Fp12;
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const G1Affine = g1.G1Affine;
const G2Affine = g2.G2Affine;

/// Signed binary digits of 6x + 2, least significant first.
const ate_loop_naf = [65]i2{
    0,  0, 0, 1,  0, 1, 0, -1, 0,  0, -1, 0,  0, 0,  1, 0, 0, -1, 0, -1, 0, 0,
    0,  1, 0, -1, 0, 0, 0, 0,  -1, 0, 0,  1,  0, -1, 0, 0, 1, 0,  0, 0,  0, 0,
    -1, 0, 0, -1, 0, 1, 0, -1, 0,  0, 0,  -1, 0, -1, 0, 0, 0, 1,  0, 1,  1,
};

/// Signed binary digits of x, least significant first (24 non-zero of 63).
const x_naf = [63]i2{
    1, 0, 0, 0,  -1, 0, 0, 0, 0, 1,  0, 1, 0, 0, 0,  0, 1,  0, 0,  1, 0, -1,
    0, 1, 0, 1,  0,  1, 0, 0, 1, 0,  0, 0, 1, 0, -1, 0, -1, 0, -1, 0, 1, 0,
    1, 0, 0, -1, 0,  1, 0, 1, 0, -1, 0, 0, 1, 0, 1,  0, 0,  0, 1,
};

comptime {
    @setEvalBranchQuota(10_000);
    var ate: i128 = 0;
    for (0..ate_loop_naf.len) |index| {
        ate += @as(i128, ate_loop_naf[index]) << @intCast(index);
    }
    assert(ate == 6 * @as(i128, fp.curve_x) + 2);
    var x: i128 = 0;
    for (0..x_naf.len) |index| x += @as(i128, x_naf[index]) << @intCast(index);
    assert(x == fp.curve_x);
}

/// Pairs processed in lockstep per Miller loop; bounds the stack state.
pub const chunk_pairs_max = 8;

const two_inverse = Fp.from_int_comptime((fp.p + 1) / 2);

/// G2 accumulator in homogeneous projective coordinates (x / z, y / z).
const Accumulator = struct { x: Fp2, y: Fp2, z: Fp2 };

/// Line coefficients before scaling by the G1 point: l = c0 yP + c1 xP w + c2 v w.
const Line = struct { c0: Fp2, c1: Fp2, c2: Fp2 };

fn double_step(state: *Accumulator) Line {
    const a = state.x.mul(state.y).mul_by_fp(two_inverse);
    const b = state.y.square();
    const c = state.z.square();
    const e = g2.twist_b.mul(c.double().add(c));
    const f = e.double().add(e);
    const g = b.add(f).mul_by_fp(two_inverse);
    const h = state.y.add(state.z).square().sub(b.add(c));
    const i = e.sub(b);
    const j = state.x.square();
    const e_squared = e.square();
    state.x = a.mul(b.sub(f));
    state.y = g.square().sub(e_squared.double().add(e_squared));
    state.z = b.mul(h);
    assert(!state.z.is_zero());
    return .{ .c0 = h.neg(), .c1 = j.double().add(j), .c2 = i };
}

fn add_step(state: *Accumulator, q: G2Affine) Line {
    assert(!q.is_infinity);
    const theta = state.y.sub(q.y.mul(state.z));
    const lambda = state.x.sub(q.x.mul(state.z));
    const c = theta.square();
    const d = lambda.square();
    const e = lambda.mul(d);
    const f = state.z.mul(c);
    const g = state.x.mul(d);
    const h = e.add(f).sub(g.double());
    state.x = lambda.mul(h);
    state.y = theta.mul(g.sub(h)).sub(e.mul(state.y));
    state.z = state.z.mul(e);
    const j = theta.mul(q.x).sub(lambda.mul(q.y));
    return .{ .c0 = lambda, .c1 = theta.neg(), .c2 = j };
}

fn evaluate(f: Fp12, line: Line, p: G1Affine) Fp12 {
    return f.mul_by_034(line.c0.mul_by_fp(p.y), line.c1.mul_by_fp(p.x), line.c2);
}

/// Miller loop product over up to `chunk_pairs_max` pairs, none at infinity.
pub fn miller_loop(g1_points: []const G1Affine, g2_points: []const G2Affine) Fp12 {
    assert(g1_points.len == g2_points.len);
    assert(g1_points.len <= chunk_pairs_max);
    var states: [chunk_pairs_max]Accumulator = undefined;
    var negated: [chunk_pairs_max]G2Affine = undefined;
    for (g1_points, g2_points, 0..) |p, q, index| {
        assert(!p.is_infinity and !q.is_infinity);
        states[index] = .{ .x = q.x, .y = q.y, .z = Fp2.one };
        negated[index] = q.neg();
    }
    var f = Fp12.one;
    var bit_index: u32 = ate_loop_naf.len - 1;
    while (bit_index > 0) {
        bit_index -= 1;
        if (bit_index != ate_loop_naf.len - 2) f = f.square();
        for (g1_points, 0..) |p, index| f = evaluate(f, double_step(&states[index]), p);
        const digit = ate_loop_naf[bit_index];
        if (digit == 0) continue;
        for (g1_points, g2_points, 0..) |p, q, index| {
            const addend = if (digit == 1) q else negated[index];
            f = evaluate(f, add_step(&states[index], addend), p);
        }
    }
    // Final additions with psi(Q) and -psi^2(Q).
    for (g1_points, g2_points, 0..) |p, q, index| {
        const q1 = g2.psi_affine(q);
        const q2 = g2.psi_affine(q1).neg();
        f = evaluate(f, add_step(&states[index], q1), p);
        f = evaluate(f, add_step(&states[index], q2), p);
    }
    return f;
}

/// f^x for f in the cyclotomic subgroup.
fn cyclotomic_pow_x(f: Fp12) Fp12 {
    const f_inverse = f.conjugate();
    var result = f;
    var index: u32 = x_naf.len - 1;
    assert(x_naf[index] == 1);
    while (index > 0) {
        index -= 1;
        result = result.cyclotomic_square();
        switch (x_naf[index]) {
            1 => result = result.mul(f),
            -1 => result = result.mul(f_inverse),
            else => {},
        }
    }
    return result;
}

fn cyclotomic_pow_negative_x(f: Fp12) Fp12 {
    return cyclotomic_pow_x(f).conjugate();
}

/// f^((p^12 - 1) / r): easy part f^((p^6 - 1)(p^2 + 1)), then the hard part
/// f^(2x (6x^2 + 3x + 1) (p^4 - p^2 + 1) / r) (Fuentes-Castaneda et al.), a
/// fixed power coprime to r, so the result is 1 exactly when the pairing is.
pub fn final_exponentiation(f: Fp12) Fp12 {
    const f_inverse = f.inverse();
    assert(!f_inverse.c0.is_zero() or !f_inverse.c1.is_zero());
    const t = f.conjugate().mul(f_inverse);
    var r = t.frobenius(2).mul(t);
    const y0 = cyclotomic_pow_negative_x(r);
    const y1 = y0.cyclotomic_square();
    const y2 = y1.cyclotomic_square();
    const y3 = y2.mul(y1);
    const y4 = cyclotomic_pow_negative_x(y3);
    const y5 = y4.cyclotomic_square();
    const y6 = cyclotomic_pow_negative_x(y5).conjugate();
    const y7 = y6.mul(y4);
    const y8 = y7.mul(y3.conjugate());
    const y9 = y8.mul(y1);
    const y10 = y8.mul(y4);
    const y11 = y10.mul(r);
    const y13 = y9.frobenius(1).mul(y11);
    const y14 = y8.frobenius(2).mul(y13);
    r = r.conjugate();
    const y16 = r.mul(y9).frobenius(3).mul(y14);
    return y16;
}

/// Full reduced pairing e(P, Q); identity when either input is at infinity.
pub fn pairing(p: G1Affine, q: G2Affine) Fp12 {
    if (p.is_infinity or q.is_infinity) return Fp12.one;
    const g1_points = [1]G1Affine{p};
    const g2_points = [1]G2Affine{q};
    const result = final_exponentiation(miller_loop(&g1_points, &g2_points));
    assert(!result.c0.is_zero() or !result.c1.is_zero());
    return result;
}

/// Accumulates Miller loops over many pairs in chunks, then exponentiates once.
pub const Checker = struct {
    product: Fp12 = Fp12.one,
    g1_points: [chunk_pairs_max]G1Affine = undefined,
    g2_points: [chunk_pairs_max]G2Affine = undefined,
    pending: u32 = 0,

    /// Adds a validated pair (on curve, G2 in subgroup); pairs with infinity skip.
    pub fn push(checker: *Checker, p: G1Affine, q: G2Affine) void {
        assert(p.is_on_curve() and q.is_on_curve());
        if (p.is_infinity or q.is_infinity) return;
        assert(checker.pending < chunk_pairs_max);
        checker.g1_points[checker.pending] = p;
        checker.g2_points[checker.pending] = q;
        checker.pending += 1;
        if (checker.pending == chunk_pairs_max) checker.flush();
    }

    fn flush(checker: *Checker) void {
        assert(checker.pending <= chunk_pairs_max);
        if (checker.pending == 0) return;
        const count = checker.pending;
        const loop = miller_loop(checker.g1_points[0..count], checker.g2_points[0..count]);
        checker.product = checker.product.mul(loop);
        checker.pending = 0;
    }

    /// True when the product of all pushed pairings is 1.
    pub fn finish(checker: *Checker) bool {
        checker.flush();
        assert(checker.pending == 0);
        if (checker.product.is_one()) return true;
        return final_exponentiation(checker.product).is_one();
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const G1 = g1.G1;
const G2 = g2.G2;

test "pairing: bilinearity e(aP, bQ) = e(P, Q)^(ab)" {
    var prng = Prng.init(0xb111);
    const base = pairing(g1.generator, g2.generator);
    try testing.expect(!base.is_one());
    // Order r: e(P, Q)^r = 1.
    try testing.expect(base.pow(fp.r).is_one());
    for (0..2) |_| {
        const a = prng.int(u256) % fp.r;
        const b = prng.int(u256) % fp.r;
        const pa = g1.mul(G1.from_affine(g1.generator), a).to_affine();
        const qb = G2.from_affine(g2.generator).mul(b).to_affine();
        const ab: u256 = @intCast((@as(u512, a) * b) % fp.r);
        try testing.expect(pairing(pa, qb).eql(base.pow(ab)));
        const pab = g1.mul(G1.from_affine(g1.generator), ab).to_affine();
        try testing.expect(pairing(pab, g2.generator).eql(pairing(pa, qb)));
    }
}

test "pairing: multi-pairing check over chunks" {
    var prng = Prng.init(0xc4ec);
    var checker: Checker = .{};
    // sum of a_i b_i = 0 across 11 pairs (more than one chunk).
    var total: u512 = 0;
    for (0..10) |_| {
        const a = prng.int(u256) % fp.r;
        const b = prng.int(u256) % fp.r;
        total = (total + @as(u512, a) * b) % fp.r;
        const pa = g1.mul(G1.from_affine(g1.generator), a).to_affine();
        checker.push(pa, G2.from_affine(g2.generator).mul(b).to_affine());
    }
    var failing = checker;
    const minus: u256 = @intCast((fp.r - total) % fp.r);
    const closing = g1.mul(G1.from_affine(g1.generator), minus).to_affine();
    checker.push(closing, g2.generator);
    try testing.expect(checker.finish());
    failing.push(closing.neg(), g2.generator);
    try testing.expect(!failing.finish());
}

//! Variable-time modular inversion by the Bernstein-Yang "safegcd" divstep method,
//! generic over the modulus width (used by secp256k1 and `montgomery.Field.inverse`).
//!
//! Only for public inputs: the number of outer iterations depends on the value.
//! Batches of 62 divsteps run on the low 64 bits of (f, g) (`divsteps_var`, after
//! libsecp256k1's modinv64_divsteps_62_var: zero runs skipped with ctz, several low bits
//! of g cleared per multiply); the resulting 2x2 transition matrix is then applied to the
//! full values in signed 62-bit limbs. With f0 = m and g0 = x, the invariants f = d x, g = e x
//! (mod m) hold throughout, and the loop ends at g = 0, f = +-1, so x^-1 = +-d.

const std = @import("std");
const assert = std.debug.assert;

const limb_bits = 62;
const limb_mask: u64 = (1 << limb_bits) - 1;

const Matrix = struct { u: i64, v: i64, q: i64, r: i64 };

pub fn Modulus(comptime Int: type, comptime modulus: Int) type {
    comptime assert(modulus & 1 == 1);
    comptime assert(@typeInfo(Int).int.signedness == .unsigned);
    const bits = @typeInfo(Int).int.bits;
    return struct {
        /// 62-bit limbs with headroom for the sign and |d|, |e| < 2m.
        const limb_count = (bits + 3 + limb_bits - 1) / limb_bits;
        /// Divsteps are bounded by (49 bits + 57) / 17 (Bernstein-Yang theorem 11.2).
        const batch_count_max = ((49 * bits + 57) / 17 + limb_bits - 1) / limb_bits + 1;
        const Signed62 = [limb_count]i64;
        // Rounded up to whole words: odd widths (i318) generate much slower code.
        const Wide = @Int(.signed, (limb_bits * limb_count + 8 + 63) / 64 * 64);
        const m_limbs = to_signed62(modulus);
        /// m^-1 mod 2^62 by Newton iteration.
        const m_inverse_62: u64 = blk: {
            var inverse: u64 = 1;
            for (0..6) |_| inverse *%= 2 -% @as(u64, @truncate(modulus)) *% inverse;
            assert(inverse *% @as(u64, @truncate(modulus)) == 1);
            break :blk inverse & limb_mask;
        };

        /// x^-1 mod m for x in [1, m), in variable time; zero maps to zero.
        pub fn invert(x: Int) Int {
            assert(x < modulus);
            if (x == 0) return 0;
            var f: Signed62 = m_limbs;
            var g: Signed62 = to_signed62(x);
            var d: Signed62 = @splat(0);
            var e: Signed62 = to_signed62(1);
            var delta: i64 = 1;
            var batches: u32 = 0;
            while (!is_zero(&g)) : (batches += 1) {
                assert(batches < batch_count_max);
                const low_f = low_bits(&f);
                const low_g = low_bits(&g);
                const matrix = divsteps_var(&delta, low_f, low_g);
                update_fg(&f, &g, matrix);
                update_de(&d, &e, matrix);
            }
            // f = +-1 because gcd(x, m) = 1.
            const sign_negative = f[limb_count - 1] < 0;
            assert(f[0] == 1 or f[0] == limb_mask);
            const inverse = reduce(&d, sign_negative);
            assert(mul_mod(inverse, x) == 1);
            return inverse;
        }

        /// Bit length k of the modulus and Barrett's mu = floor(2^2k / m).
        const modulus_bits = bits - @clz(modulus);
        const Barrett = @Int(.unsigned, (2 * modulus_bits + 2 + 63) / 64 * 64);
        const barrett_mu: Barrett = (@as(Barrett, 1) << (2 * modulus_bits)) / modulus;

        /// a * b mod m for a, b < m by Barrett reduction (HAC 14.42, base 2) with mu fixed at
        /// comptime: `invert`'s safe-build self-check. LLVM lowers a wide `%` to a bit-serial
        /// loop of about 70k instructions at 256 bits, on every inversion of an ecrecover.
        fn mul_mod(a: Int, b: Int) Int {
            assert(a < modulus and b < modulus);
            // Wrapping operations cannot wrap: x < 2^2k, q1 * mu < 2^(2k + 2) fits `Barrett`,
            // and q3 <= floor(x / m), so x - q3 m is in [0, 3m) (HAC 14.42).
            const x: Barrett = @as(Barrett, a) *% b;
            const q1 = x >> (modulus_bits - 1);
            const q3 = (q1 *% barrett_mu) >> (modulus_bits + 1);
            var remainder = x -% q3 *% modulus;
            var rounds: u32 = 0;
            while (remainder >= modulus) : (rounds += 1) {
                assert(rounds < 2);
                remainder -= modulus;
            }
            return @intCast(remainder);
        }

        fn update_de(d: *Signed62, e: *Signed62, t: Matrix) void {
            var cd: i128 = @as(i128, t.u) * d[0] + @as(i128, t.v) * e[0];
            var ce: i128 = @as(i128, t.q) * d[0] + @as(i128, t.r) * e[0];
            // Add md * m, me * m so the low 62 bits vanish (exact division by 2^62).
            const md = cancel_factor(cd);
            const me = cancel_factor(ce);
            cd += @as(i128, md) * m_limbs[0];
            ce += @as(i128, me) * m_limbs[0];
            assert(cd & limb_mask == 0 and ce & limb_mask == 0);
            cd >>= limb_bits;
            ce >>= limb_bits;
            inline for (1..limb_count) |i| {
                cd += @as(i128, t.u) * d[i] + @as(i128, t.v) * e[i] + @as(i128, md) * m_limbs[i];
                ce += @as(i128, t.q) * d[i] + @as(i128, t.r) * e[i] + @as(i128, me) * m_limbs[i];
                d[i - 1] = @intCast(cd & limb_mask);
                e[i - 1] = @intCast(ce & limb_mask);
                cd >>= limb_bits;
                ce >>= limb_bits;
            }
            d[limb_count - 1] = @intCast(cd);
            e[limb_count - 1] = @intCast(ce);
        }

        /// The multiple of m in [0, 2^62) that makes `value + factor * m` divisible by 2^62.
        fn cancel_factor(value: i128) i64 {
            const low: u64 = @truncate(@as(u128, @bitCast(value)));
            const factor = ((0 -% low) *% m_inverse_62) & limb_mask;
            assert((low +% factor *% @as(u64, @truncate(modulus))) & limb_mask == 0);
            return @intCast(factor);
        }

        /// Converts +-d (|d| < 16 m) to the canonical residue in [0, m).
        fn reduce(d: *const Signed62, negate: bool) Int {
            var value: Wide = 0;
            inline for (0..limb_count) |step| {
                const index = limb_count - 1 - step;
                value = (value << limb_bits) + d[index];
            }
            if (negate) value = -value;
            const m: Wide = modulus;
            var rounds: u32 = 0;
            while (value < 0) : (rounds += 1) {
                assert(rounds < 32);
                value += m;
            }
            while (value >= m) : (rounds += 1) {
                assert(rounds < 32);
                value -= m;
            }
            return @intCast(value);
        }

        fn to_signed62(value: Int) Signed62 {
            var limbs: Signed62 = undefined;
            inline for (0..limb_count) |index| {
                limbs[index] = @intCast((value >> (limb_bits * index)) & limb_mask);
            }
            assert(limbs[limb_count - 1] >= 0);
            return limbs;
        }

        /// The low 64 bits of the two's complement value.
        fn low_bits(limbs: *const Signed62) u64 {
            const low: u64 = @bitCast(limbs[0]);
            const next: u64 = @bitCast(limbs[1]);
            return low | (next << limb_bits);
        }

        fn is_zero(limbs: *const Signed62) bool {
            var accumulated: i64 = 0;
            for (limbs) |limb| accumulated |= limb;
            return accumulated == 0;
        }

        /// 62 branch-free divsteps on the low bits of (f, g). Returns the matrix with
        /// 2^62 (f', g') = (u f + v g, q f + r g).
        fn divsteps(delta: *i64, f_low: u64, g_low: u64) Matrix {
            assert(f_low & 1 == 1);
            var f = f_low;
            var g = g_low;
            var u: u64 = 1;
            var v: u64 = 0;
            var q: u64 = 0;
            var r: u64 = 1;
            var d = delta.*;
            for (0..limb_bits) |_| {
                // Swap when delta > 0 and g is odd: (delta, f, g) <- (-delta, g, -f).
                const g_odd: u64 = 0 -% (g & 1);
                const swap: u64 = g_odd & @as(u64, @bitCast((-d) >> 63));
                const d_bits: u64 = @bitCast(d);
                d = @bitCast((d_bits ^ swap) -% swap);
                const f_new = (f & ~swap) | (g & swap);
                const g_new = (g & ~swap) | ((0 -% f) & swap);
                const u_new = (u & ~swap) | (q & swap);
                const v_new = (v & ~swap) | (r & swap);
                const q_new = (q & ~swap) | ((0 -% u) & swap);
                const r_new = (r & ~swap) | ((0 -% v) & swap);
                f = f_new;
                // g odd: add f (after a swap, g = -f_old is always odd).
                g = g_new +% (f & g_odd);
                q = q_new +% (u_new & g_odd);
                r = r_new +% (v_new & g_odd);
                g >>= 1;
                u = u_new << 1;
                v = v_new << 1;
                d +%= 1;
            }
            delta.* = d;
            assert(f & 1 == 1);
            return .{ .u = @bitCast(u), .v = @bitCast(v), .q = @bitCast(q), .r = @bitCast(r) };
        }

        fn update_fg(f: *Signed62, g: *Signed62, t: Matrix) void {
            var cf: i128 = @as(i128, t.u) * f[0] + @as(i128, t.v) * g[0];
            var cg: i128 = @as(i128, t.q) * f[0] + @as(i128, t.r) * g[0];
            assert(cf & limb_mask == 0 and cg & limb_mask == 0);
            cf >>= limb_bits;
            cg >>= limb_bits;
            inline for (1..limb_count) |i| {
                cf += @as(i128, t.u) * f[i] + @as(i128, t.v) * g[i];
                cg += @as(i128, t.q) * f[i] + @as(i128, t.r) * g[i];
                f[i - 1] = @intCast(cf & limb_mask);
                g[i - 1] = @intCast(cg & limb_mask);
                cf >>= limb_bits;
                cg >>= limb_bits;
            }
            f[limb_count - 1] = @intCast(cf);
            g[limb_count - 1] = @intCast(cg);
        }
    };
}

/// The same 62 divsteps and matrix as `Modulus(..).divsteps`, in variable time: runs of
/// zero bits of g are skipped with ctz, and while f stays put one multiply clears up to
/// 4 (no swap) or 6 (after a swap) low bits of g, using w = -g / f mod 2^limit.
fn divsteps_var(delta: *i64, f_low: u64, g_low: u64) Matrix {
    assert(f_low & 1 == 1);
    var f = f_low;
    var g = g_low;
    var u: u64 = 1;
    var v: u64 = 0;
    var q: u64 = 0;
    var r: u64 = 1;
    var eta: i64 = -delta.*;
    var remaining: u32 = limb_bits;
    var rounds: u32 = 0;
    while (true) : (rounds += 1) {
        assert(rounds <= limb_bits);
        const zeros: u32 = @ctz(g | (~@as(u64, 0) << @intCast(remaining)));
        assert(zeros <= remaining);
        g >>= @intCast(zeros);
        u <<= @intCast(zeros);
        v <<= @intCast(zeros);
        eta -= zeros;
        remaining -= zeros;
        if (remaining == 0) break;
        var w: u64 = undefined;
        var mask: u64 = undefined;
        if (eta < 0) {
            eta = -eta;
            const old_f = f;
            f = g;
            g = 0 -% old_f;
            const old_u = u;
            u = q;
            q = 0 -% old_u;
            const old_v = v;
            v = r;
            r = 0 -% old_v;
            const limit: u32 = @intCast(@min(eta + 1, remaining));
            mask = (~@as(u64, 0) >> @intCast(64 - limit)) & 63;
            w = (f *% g *% (f *% f -% 2)) & mask;
        } else {
            const limit: u32 = @intCast(@min(eta + 1, remaining));
            mask = (~@as(u64, 0) >> @intCast(64 - limit)) & 15;
            w = f +% (((f +% 1) & 4) << 1);
            w = (0 -% w) *% g & mask;
        }
        g +%= f *% w;
        q +%= u *% w;
        r +%= v *% w;
        assert(g & mask == 0);
    }
    delta.* = -eta;
    assert(f & 1 == 1);
    return .{ .u = @bitCast(u), .v = @bitCast(v), .q = @bitCast(q), .r = @bitCast(r) };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn check_modulus(comptime Int: type, comptime modulus: Int, seed: u64) !void {
    const Inverse = Modulus(Int, modulus);
    const Wide = @Int(.unsigned, 2 * @typeInfo(Int).int.bits);
    var prng = Prng.init(seed);
    try testing.expectEqual(@as(Int, 0), Inverse.invert(0));
    try testing.expectEqual(@as(Int, 1), Inverse.invert(1));
    try testing.expectEqual(modulus - 1, Inverse.invert(modulus - 1));
    for (0..300) |_| {
        var x: Int = 0;
        for (0..@sizeOf(Int) / 8) |_| x = (x << 32 << 32) | prng.int(u64);
        if (prng.chance(1, 8)) x >>= @intCast(prng.below(@typeInfo(Int).int.bits));
        x %= modulus;
        if (x == 0) continue;
        const inverse = Inverse.invert(x);
        try testing.expectEqual(@as(Wide, 1), @as(Wide, inverse) * x % modulus);
        // The Barrett product behind `invert`'s self-check, against the wide `%`.
        const y = (inverse ^ @as(Int, @truncate(prng.int(u64)))) % modulus;
        const expected: Int = @intCast(@as(Wide, x) * y % modulus);
        try testing.expectEqual(expected, Inverse.mul_mod(x, y));
    }
    const top = modulus - 1;
    const expected_top: Int = @intCast(@as(Wide, top) * top % modulus);
    try testing.expectEqual(expected_top, Inverse.mul_mod(top, top));
}

test "safegcd: bn254, p256, bls12-381 and secp256k1 moduli" {
    try check_modulus(u256, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47, 1);
    try check_modulus(u256, 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, 2);
    try check_modulus(u256, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, 3);
    try check_modulus(
        u384,
        (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192) |
            0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab,
        4,
    );
}

const bls_modulus: u384 = (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192) |
    0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
const secp256k1_modulus: u256 =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    const x = smith.value(u384) % bls_modulus;
    const inverse = Modulus(u384, bls_modulus).invert(x);
    const expected: u768 = if (x == 0) 0 else 1;
    try testing.expectEqual(expected, @as(u768, inverse) * x % bls_modulus);
    const y = smith.value(u256) % secp256k1_modulus;
    const inverse_y = Modulus(u256, secp256k1_modulus).invert(y);
    const expected_y: u512 = if (y == 0) 0 else 1;
    try testing.expectEqual(expected_y, @as(u512, inverse_y) * y % secp256k1_modulus);
}

test "safegcd: coverage-guided fuzz" {
    try testing.fuzz({}, fuzz_one, .{});
}

/// Compares `divsteps_var` with the branch-free reference for one (delta, f, g).
fn expect_divsteps_match(delta: i64, f_low: u64, g_low: u64) !void {
    const Reference = Modulus(u256, secp256k1_modulus);
    var delta_reference = delta;
    var delta_var = delta;
    const expected = Reference.divsteps(&delta_reference, f_low | 1, g_low);
    const actual = divsteps_var(&delta_var, f_low | 1, g_low);
    try testing.expectEqual(expected, actual);
    try testing.expectEqual(delta_reference, delta_var);
}

test "safegcd: divsteps_var matches the branch-free divsteps (seeded)" {
    var prng = Prng.init(0x64697673);
    try expect_divsteps_match(1, 1, 0);
    try expect_divsteps_match(1, std.math.maxInt(u64), std.math.maxInt(u64));
    for (0..20_000) |round| {
        const delta: i64 = switch (round % 4) {
            0 => 1,
            1 => @as(i64, @intCast(prng.below(1200))) - 600,
            else => @as(i64, @intCast(prng.below(40))) - 20,
        };
        var g = prng.int(u64);
        if (prng.chance(1, 4)) g <<= @intCast(prng.below(64));
        try expect_divsteps_match(delta, prng.int(u64), g);
    }
}

fn fuzz_divsteps(_: void, smith: *testing.Smith) anyerror!void {
    const delta: i64 = @as(i64, smith.value(i16));
    try expect_divsteps_match(delta, smith.value(u64), smith.value(u64));
}

test "safegcd: coverage-guided fuzz of divsteps_var vs branch-free divsteps" {
    try testing.fuzz({}, fuzz_divsteps, .{});
}

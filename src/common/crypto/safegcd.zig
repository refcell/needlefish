//! Variable-time modular inversion by the Bernstein-Yang "safegcd" divstep method,
//! generic over the modulus width (generalized from `secp256k1/modinv.zig`).
//!
//! Only for public inputs: the number of outer iterations depends on the value.
//! Batches of 62 divsteps run on the low 64 bits of (f, g) with a branch-free
//! inner loop; the resulting 2x2 transition matrix is then applied to the full values
//! in signed 62-bit limbs. With f0 = m and g0 = x, the invariants f = d x, g = e x
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
        const Wide = @Int(.signed, limb_bits * limb_count + 8);
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
                const matrix = divsteps(&delta, low_f, low_g);
                update_fg(&f, &g, matrix);
                update_de(&d, &e, matrix);
            }
            // f = +-1 because gcd(x, m) = 1.
            const sign_negative = f[limb_count - 1] < 0;
            assert(f[0] == 1 or f[0] == limb_mask);
            const inverse = reduce(&d, sign_negative);
            assert(@as(@Int(.unsigned, 2 * bits), inverse) * x % modulus == 1);
            return inverse;
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
    }
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

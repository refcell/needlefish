//! Arithmetic in the secp256k1 base field, modulo p = 2^256 - 2^32 - 977.
//!
//! Elements are four little-endian 64-bit limbs holding any value below 2^256 that is
//! congruent to the element (weakly reduced: a value may equal x or x + p). Because
//! 2^256 = 0x1000003D1 (mod p), every overflow past 2^256 folds back with one small
//! multiply. Only `normalize` (and what calls it) produces the canonical value < p.
//! All operations are branch-free so they also serve the constant-time signing path.

const std = @import("std");
const assert = std.debug.assert;

/// The field prime p.
pub const p_int: u256 = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F;

/// 2^256 mod p: folding constant for overflow past 256 bits.
const fold: u64 = 0x1000003D1;

comptime {
    assert(@as(u257, p_int) + fold == @as(u257, 1) << 256);
    assert(p_int % 4 == 3); // sqrt is a single exponentiation.
}

pub const Fe = struct {
    limbs: [4]u64,

    pub const zero: Fe = .{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one: Fe = .{ .limbs = .{ 1, 0, 0, 0 } };

    pub fn from_int(value: u256) Fe {
        assert(value < p_int);
        var fe: Fe = undefined;
        inline for (0..4) |index| fe.limbs[index] = @truncate(value >> (64 * index));
        return fe;
    }

    /// Converts to the canonical integer below p.
    pub fn to_int(fe: Fe) u256 {
        const n = fe.normalize();
        var value: u256 = 0;
        inline for (0..4) |index| value |= @as(u256, n.limbs[index]) << (64 * index);
        assert(value < p_int);
        return value;
    }

    /// Parses 32 big-endian bytes; null unless the value is canonical (< p).
    pub fn from_bytes(bytes: *const [32]u8) ?Fe {
        const fe = from_bytes_unchecked(bytes);
        const canonical = fe.normalize();
        if (!std.mem.eql(u64, &fe.limbs, &canonical.limbs)) return null;
        assert(fe.limbs[3] <= std.math.maxInt(u64));
        return fe;
    }

    /// Parses 32 big-endian bytes as any value below 2^256 (implicitly reduced mod p).
    pub fn from_bytes_unchecked(bytes: *const [32]u8) Fe {
        var fe: Fe = undefined;
        inline for (0..4) |index| {
            fe.limbs[index] = std.mem.readInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], .big);
        }
        return fe;
    }

    /// Serializes the canonical value as 32 big-endian bytes.
    pub fn to_bytes(fe: Fe) [32]u8 {
        const n = fe.normalize();
        var bytes: [32]u8 = undefined;
        inline for (0..4) |index| {
            std.mem.writeInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], n.limbs[index], .big);
        }
        return bytes;
    }

    /// Returns the canonical representative (< p). Branch-free.
    pub fn normalize(fe: Fe) Fe {
        // fe >= p exactly when fe + fold overflows 2^256; then fe - p = fe + fold - 2^256.
        var shifted: [4]u64 = undefined;
        var accumulator: u128 = @as(u128, fe.limbs[0]) + fold;
        shifted[0] = @truncate(accumulator);
        inline for (1..4) |index| {
            accumulator = (accumulator >> 64) + fe.limbs[index];
            shifted[index] = @truncate(accumulator);
        }
        const overflow: u64 = @truncate(accumulator >> 64);
        assert(overflow <= 1);
        const mask = 0 -% overflow;
        var result: Fe = undefined;
        inline for (0..4) |index| {
            result.limbs[index] = (shifted[index] & mask) | (fe.limbs[index] & ~mask);
        }
        return result;
    }

    pub fn is_zero(fe: Fe) bool {
        const n = fe.normalize();
        return (n.limbs[0] | n.limbs[1] | n.limbs[2] | n.limbs[3]) == 0;
    }

    pub fn equal(a: Fe, b: Fe) bool {
        return a.sub(b).is_zero();
    }

    pub fn is_odd(fe: Fe) bool {
        return fe.normalize().limbs[0] & 1 == 1;
    }

    /// Adds `top * 2^256` (top < 2^35) into a 256-bit value via 2^256 = fold (mod p).
    inline fn fold_top(limbs: [4]u64, top: u64) Fe {
        assert(top < (1 << 35));
        var result: Fe = undefined;
        var accumulator: u128 = @as(u128, limbs[0]) + @as(u128, top) * fold;
        result.limbs[0] = @truncate(accumulator);
        inline for (1..4) |index| {
            accumulator = (accumulator >> 64) + limbs[index];
            result.limbs[index] = @truncate(accumulator);
        }
        // On a second overflow the wrapped value is below 2^70, so the extra fold
        // reaches at most limb 1 and cannot carry further.
        const overflow: u64 = @truncate(accumulator >> 64);
        accumulator = @as(u128, result.limbs[0]) + overflow * fold;
        result.limbs[0] = @truncate(accumulator);
        result.limbs[1] +%= @truncate(accumulator >> 64);
        return result;
    }

    pub fn add(a: Fe, b: Fe) Fe {
        var limbs: [4]u64 = undefined;
        var accumulator: u128 = 0;
        inline for (0..4) |index| {
            accumulator = (accumulator >> 64) + a.limbs[index] + b.limbs[index];
            limbs[index] = @truncate(accumulator);
        }
        return fold_top(limbs, @truncate(accumulator >> 64));
    }

    pub fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    pub fn sub(a: Fe, b: Fe) Fe {
        var limbs: [4]u64 = undefined;
        var borrow: u1 = 0;
        inline for (0..4) |index| {
            const step = @subWithOverflow(a.limbs[index], b.limbs[index]);
            const step_borrow = @subWithOverflow(step[0], borrow);
            limbs[index] = step_borrow[0];
            borrow = step[1] | step_borrow[1];
        }
        // A borrow wrapped by +2^256; adding p instead means subtracting fold.
        var second: u1 = 0;
        const correction = fold & (0 -% @as(u64, borrow));
        inline for (0..4) |index| {
            const subtrahend = if (index == 0) correction else 0;
            const step = @subWithOverflow(limbs[index], subtrahend);
            const step_borrow = @subWithOverflow(step[0], second);
            limbs[index] = step_borrow[0];
            second = step[1] | step_borrow[1];
        }
        // A second borrow leaves limb 0 near 2^64, so this subtraction cannot borrow.
        limbs[0] -%= fold & (0 -% @as(u64, second));
        assert(second == 0 or borrow == 1);
        return .{ .limbs = limbs };
    }

    pub fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    pub fn mul_small(a: Fe, comptime factor: u32) Fe {
        comptime assert(factor > 0);
        var limbs: [4]u64 = undefined;
        var accumulator: u128 = 0;
        inline for (0..4) |index| {
            accumulator = (accumulator >> 64) + @as(u128, a.limbs[index]) * factor;
            limbs[index] = @truncate(accumulator);
        }
        return fold_top(limbs, @truncate(accumulator >> 64));
    }

    /// Reduces a 512-bit product: low + high * fold, then folds the small top.
    inline fn reduce_wide(wide: [8]u64) Fe {
        var limbs: [4]u64 = undefined;
        var accumulator: u128 = 0;
        inline for (0..4) |index| {
            accumulator = (accumulator >> 64) + wide[index] +
                @as(u128, wide[index + 4]) * fold;
            limbs[index] = @truncate(accumulator);
        }
        const top: u64 = @truncate(accumulator >> 64);
        assert(top <= fold);
        return fold_top(limbs, top);
    }

    pub fn mul(a: Fe, b: Fe) Fe {
        var wide: [8]u64 = @splat(0);
        inline for (0..4) |i| {
            var carry: u64 = 0;
            inline for (0..4) |j| {
                const product = @as(u128, a.limbs[i]) * b.limbs[j] + wide[i + j] + carry;
                wide[i + j] = @truncate(product);
                carry = @truncate(product >> 64);
            }
            wide[i + 4] = carry;
        }
        return reduce_wide(wide);
    }

    pub fn sqr(a: Fe) Fe {
        const x = a.limbs;
        var wide: [8]u64 = @splat(0);
        // Off-diagonal products a_i * a_j (i < j), accumulated once.
        inline for (0..3) |i| {
            var carry: u64 = 0;
            inline for (i + 1..4) |j| {
                const product = @as(u128, x[i]) * x[j] + wide[i + j] + carry;
                wide[i + j] = @truncate(product);
                carry = @truncate(product >> 64);
            }
            wide[i + 4] = carry;
        }
        // Double them, then add the diagonal squares.
        wide[7] = wide[6] >> 63;
        inline for (0..6) |step| {
            const index = 6 - step;
            wide[index] = (wide[index] << 1) | (wide[index - 1] >> 63);
        }
        var carry: u128 = 0;
        inline for (0..4) |i| {
            const square = @as(u128, x[i]) * x[i];
            carry = (carry >> 64) + wide[2 * i] + @as(u64, @truncate(square));
            wide[2 * i] = @truncate(carry);
            carry = (carry >> 64) + wide[2 * i + 1] + @as(u64, @truncate(square >> 64));
            wide[2 * i + 1] = @truncate(carry);
        }
        assert(carry >> 64 == 0);
        return reduce_wide(wide);
    }

    fn sqr_n(a: Fe, comptime count: u32) Fe {
        comptime assert(count > 0);
        var result = a;
        for (0..count) |_| result = result.sqr();
        return result;
    }

    /// Powers a^(2^k - 1) shared by inversion and square root (libsecp256k1's chain).
    const Chain = struct { x2: Fe, x22: Fe, x223: Fe };

    fn chain(a: Fe) Chain {
        const x2 = a.sqr().mul(a);
        const x3 = x2.sqr().mul(a);
        const x6 = x3.sqr_n(3).mul(x3);
        const x9 = x6.sqr_n(3).mul(x3);
        const x11 = x9.sqr_n(2).mul(x2);
        const x22 = x11.sqr_n(11).mul(x11);
        const x44 = x22.sqr_n(22).mul(x22);
        const x88 = x44.sqr_n(44).mul(x44);
        const x176 = x88.sqr_n(88).mul(x88);
        const x220 = x176.sqr_n(44).mul(x44);
        const x223 = x220.sqr_n(3).mul(x3);
        return .{ .x2 = x2, .x22 = x22, .x223 = x223 };
    }

    /// a^(p-2), the inverse (zero maps to zero). Constant time.
    pub fn invert(a: Fe) Fe {
        const powers = chain(a);
        var t = powers.x223.sqr_n(23).mul(powers.x22);
        t = t.sqr_n(5).mul(a);
        t = t.sqr_n(3).mul(powers.x2);
        t = t.sqr_n(2).mul(a);
        assert(a.is_zero() or t.mul(a).equal(one));
        return t;
    }

    /// Square root a^((p+1)/4); null when `a` is not a quadratic residue.
    pub fn sqrt(a: Fe) ?Fe {
        const powers = chain(a);
        var t = powers.x223.sqr_n(23).mul(powers.x22);
        t = t.sqr_n(6).mul(powers.x2);
        t = t.sqr_n(2);
        if (!t.sqr().equal(a)) return null;
        assert(t.sqr().equal(a));
        return t;
    }

    /// Constant-time select: `b` when `flag` is 1, else `a`.
    pub fn select(a: Fe, b: Fe, flag: u1) Fe {
        const mask = 0 -% @as(u64, flag);
        var result: Fe = undefined;
        inline for (0..4) |index| {
            result.limbs[index] = (a.limbs[index] & ~mask) | (b.limbs[index] & mask);
        }
        return result;
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

fn random_fe(prng: *Prng) Fe {
    // Mix in edge values near 0, p and 2^256 to exercise the weak representation.
    const max = ~@as(u64, 0);
    var fe: Fe = .{ .limbs = .{ prng.int(u64), prng.int(u64), prng.int(u64), prng.int(u64) } };
    switch (prng.below(8)) {
        0 => fe.limbs = .{ prng.below(4), 0, 0, 0 },
        1 => fe.limbs = .{ 0xFFFFFFFEFFFFFC2F -% prng.below(4), max, max, max },
        2 => fe.limbs = .{ max - prng.below(fold + 4), max, max, max },
        else => {},
    }
    return fe;
}

fn raw_int(fe: Fe) u512 {
    var value: u512 = 0;
    inline for (0..4) |index| value |= @as(u512, fe.limbs[index]) << (64 * index);
    return value;
}

test "field: arithmetic matches u512 reference" {
    var prng = Prng.init(0x6669656c64);
    for (0..3000) |_| {
        const a = random_fe(&prng);
        const b = random_fe(&prng);
        const x = raw_int(a);
        const y = raw_int(b);
        const p: u512 = p_int;
        try testing.expectEqual(@as(u256, @intCast((x + y) % p)), a.add(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((x + p * 2 - y) % p)), a.sub(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((x * y) % p)), a.mul(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((x * x) % p)), a.sqr().to_int());
        try testing.expectEqual(@as(u256, @intCast((x * 21) % p)), a.mul_small(21).to_int());
        try testing.expectEqual(@as(u256, @intCast((p * 2 - x) % p)), a.neg().to_int());
        try testing.expectEqual(x % p == 0, a.is_zero());
    }
}

test "field: invert and sqrt" {
    var prng = Prng.init(0x696e76);
    try testing.expect(Fe.zero.invert().is_zero());
    try testing.expect(Fe.from_int(7).sqrt() == null); // b = 7 is a non-residue.
    for (0..200) |_| {
        const a = random_fe(&prng);
        if (a.is_zero()) continue;
        try testing.expect(a.mul(a.invert()).equal(Fe.one));
        const square = a.sqr();
        const root = square.sqrt().?;
        try testing.expect(root.equal(a) or root.equal(a.neg()));
    }
}

test "field: bytes round trip and canonical check" {
    const p_bytes: [32]u8 = @bitCast(@byteSwap(p_int));
    try testing.expect(Fe.from_bytes(&p_bytes) == null);
    var below = p_bytes;
    below[31] -= 1;
    const fe = Fe.from_bytes(&below).?;
    try testing.expectEqual(below, fe.to_bytes());
    try testing.expect(Fe.from_bytes_unchecked(&p_bytes).is_zero());
}

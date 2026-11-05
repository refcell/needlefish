//! Arithmetic modulo the secp256k1 group order n, the GLV scalar split, and wNAF
//! recoding.
//!
//! Scalars are always fully reduced (< n) in four little-endian 64-bit limbs.
//! Reduction of a 512-bit product uses 2^256 = n_c (mod n), with n_c a 129-bit
//! constant, folding 512 -> 385 -> 258 -> 256 bits (the libsecp256k1 approach).
//! Arithmetic is branch-free; `invert` uses a fixed public exponent, so it is
//! constant time with respect to the scalar.

const std = @import("std");
const assert = std.debug.assert;

/// The group order n.
pub const n_int: u256 = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141;
/// 2^256 - n.
const n_c_int: u256 = (1 << 256) - @as(u257, n_int);
const n_c: [3]u64 = .{ @truncate(n_c_int), @truncate(n_c_int >> 64), @truncate(n_c_int >> 128) };

/// GLV endomorphism constants (lambda^3 = 1 mod n) and the rounding multipliers
/// g1, g2 and lattice vectors used to split k = r1 + r2 * lambda with |r1|, |r2| < 2^128.
pub const lambda_int: u256 =
    0x5363AD4CC05C30E0_A5261C028812645A_122E22EA20816678_DF02967C1B23BD72;
const g1_int: u256 = 0x3086D221A7D46BCD_E86C90E49284EB15_3DAA8A1471E8CA7F_E893209A45DBB031;
const g2_int: u256 = 0xE4437ED6010E8828_6F547FA90ABFE4C4_221208AC9DF506C6_1571B4AE8AC47F71;
const b1_negated_int: u256 = 0xE4437ED6010E8828_6F547FA90ABFE4C3;
const b2_negated_int: u256 = n_int - 0x3086D221A7D46BCD_E86C90E49284EB15;

comptime {
    assert(n_c[2] == 1);
    @setEvalBranchQuota(10_000);
    const n: comptime_int = n_int;
    const lambda: comptime_int = lambda_int;
    assert((lambda * lambda * lambda) % n == 1);
    assert(lambda != 1);
}

pub const Scalar = struct {
    limbs: [4]u64,

    pub const zero: Scalar = .{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one: Scalar = .{ .limbs = .{ 1, 0, 0, 0 } };

    pub fn from_int(value: u256) Scalar {
        assert(value < n_int);
        var scalar: Scalar = undefined;
        inline for (0..4) |index| scalar.limbs[index] = @truncate(value >> (64 * index));
        return scalar;
    }

    pub fn to_int(scalar: Scalar) u256 {
        var value: u256 = 0;
        inline for (0..4) |index| value |= @as(u256, scalar.limbs[index]) << (64 * index);
        assert(value < n_int);
        return value;
    }

    fn read_limbs(bytes: *const [32]u8) [4]u64 {
        var limbs: [4]u64 = undefined;
        inline for (0..4) |index| {
            limbs[index] = std.mem.readInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], .big);
        }
        return limbs;
    }

    /// Parses 32 big-endian bytes; null unless the value is below n.
    pub fn from_bytes(bytes: *const [32]u8) ?Scalar {
        const limbs = read_limbs(bytes);
        const reduced = reduce_once(limbs, 0);
        if (!std.mem.eql(u64, &limbs, &reduced.limbs)) return null;
        assert(reduced.limbs[3] == limbs[3]);
        return reduced;
    }

    /// Parses 32 big-endian bytes reduced mod n (any 256-bit value).
    pub fn from_bytes_reduce(bytes: *const [32]u8) Scalar {
        const scalar = reduce_once(read_limbs(bytes), 0);
        assert(scalar.limbs[3] <= n_int >> 192);
        return scalar;
    }

    pub fn to_bytes(scalar: Scalar) [32]u8 {
        assert(scalar.limbs[3] <= n_int >> 192);
        var bytes: [32]u8 = undefined;
        inline for (0..4) |index| {
            std.mem.writeInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], scalar.limbs[index], .big);
        }
        return bytes;
    }

    pub fn is_zero(scalar: Scalar) bool {
        return (scalar.limbs[0] | scalar.limbs[1] | scalar.limbs[2] | scalar.limbs[3]) == 0;
    }

    pub fn equal(a: Scalar, b: Scalar) bool {
        return std.mem.eql(u64, &a.limbs, &b.limbs);
    }

    /// True when the scalar exceeds n / 2 (a "high-s" signature value).
    pub fn is_high(scalar: Scalar) bool {
        return scalar.to_int() > n_int / 2;
    }

    /// Reduces `value = top * 2^256 + limbs` (value < 2n) to below n. Branch-free.
    fn reduce_once(limbs: [4]u64, top: u64) Scalar {
        assert(top <= 1);
        // value >= n exactly when top is set or limbs + n_c overflows; then
        // value - n = limbs + n_c (mod 2^256).
        var shifted: [4]u64 = undefined;
        var accumulator: u128 = 0;
        inline for (0..4) |index| {
            const addend: u64 = if (index < 3) n_c[index] else 0;
            accumulator = (accumulator >> 64) + limbs[index] + addend;
            shifted[index] = @truncate(accumulator);
        }
        const overflow: u64 = @as(u64, @truncate(accumulator >> 64)) | top;
        const mask = 0 -% overflow;
        var result: Scalar = undefined;
        inline for (0..4) |index| {
            result.limbs[index] = (shifted[index] & mask) | (limbs[index] & ~mask);
        }
        assert(result.limbs[3] <= n_int >> 192);
        return result;
    }

    pub fn add(a: Scalar, b: Scalar) Scalar {
        var limbs: [4]u64 = undefined;
        var accumulator: u128 = 0;
        inline for (0..4) |index| {
            accumulator = (accumulator >> 64) + a.limbs[index] + b.limbs[index];
            limbs[index] = @truncate(accumulator);
        }
        return reduce_once(limbs, @truncate(accumulator >> 64));
    }

    pub fn neg(a: Scalar) Scalar {
        // n - a, mapped to zero when a is zero.
        const n = from_int_unchecked(n_int);
        var limbs: [4]u64 = undefined;
        var borrow: u1 = 0;
        inline for (0..4) |index| {
            const step = @subWithOverflow(n.limbs[index], a.limbs[index]);
            const step_borrow = @subWithOverflow(step[0], borrow);
            limbs[index] = step_borrow[0];
            borrow = step[1] | step_borrow[1];
        }
        assert(borrow == 0);
        const mask = 0 -% @as(u64, @intFromBool(!a.is_zero()));
        inline for (0..4) |index| limbs[index] &= mask;
        return .{ .limbs = limbs };
    }

    pub fn sub(a: Scalar, b: Scalar) Scalar {
        return a.add(b.neg());
    }

    fn from_int_unchecked(value: u256) Scalar {
        var scalar: Scalar = undefined;
        inline for (0..4) |index| scalar.limbs[index] = @truncate(value >> (64 * index));
        return scalar;
    }

    /// low + high * n_c for a `high_len`-limb `high`, as `high_len + 4` limbs.
    inline fn fold_step(
        comptime high_len: u32,
        low: [4]u64,
        high: [high_len]u64,
    ) [high_len + 4]u64 {
        var out: [high_len + 4]u64 = @splat(0);
        inline for (0..high_len) |i| {
            var carry: u64 = 0;
            inline for (0..3) |j| {
                const product = @as(u128, high[i]) * n_c[j] + out[i + j] + carry;
                out[i + j] = @truncate(product);
                carry = @truncate(product >> 64);
            }
            out[i + 3] = carry;
        }
        var accumulator: u128 = 0;
        inline for (0..high_len + 4) |index| {
            const addend: u64 = if (index < 4) low[index] else 0;
            accumulator = (accumulator >> 64) + out[index] + addend;
            out[index] = @truncate(accumulator);
        }
        assert(accumulator >> 64 == 0);
        return out;
    }

    pub fn mul(a: Scalar, b: Scalar) Scalar {
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

    /// Reduces a 512-bit value modulo n.
    fn reduce_wide(wide: [8]u64) Scalar {
        // 512 -> 385 bits.
        const m = fold_step(4, wide[0..4].*, wide[4..8].*);
        assert(m[7] == 0);
        // 385 -> 258 bits.
        const p = fold_step(3, m[0..4].*, m[4..7].*);
        assert(p[5] == 0 and p[6] == 0 and p[4] < 8);
        // 258 -> 256 bits plus a carry bit; the value is then below 2n.
        const r = fold_step(1, p[0..4].*, p[4..5].*);
        assert(r[4] <= 1);
        return reduce_once(r[0..4].*, r[4]);
    }

    pub fn sqr(a: Scalar) Scalar {
        return a.mul(a);
    }

    /// a^(n-2) by a fixed 4-bit window over the public exponent. Constant time.
    pub fn invert(a: Scalar) Scalar {
        var powers: [16]Scalar = undefined;
        powers[0] = one;
        powers[1] = a;
        for (2..16) |index| powers[index] = powers[index - 1].mul(a);
        const exponent = n_int - 2;
        var result = one;
        for (0..64) |step| {
            const shift: u8 = @intCast(252 - 4 * step);
            const nibble: u4 = @truncate(exponent >> shift);
            if (step != 0) {
                for (0..4) |_| result = result.sqr();
            }
            // The exponent is public, so skipping zero nibbles leaks nothing.
            if (nibble != 0) result = result.mul(powers[nibble]);
        }
        assert(a.is_zero() or result.mul(a).equal(one));
        return result;
    }
};

/// A scalar half of magnitude below 2^129 with its sign.
pub const SignedHalf = struct {
    magnitude: [4]u64,
    negative: bool,
};

fn signed_half(scalar: Scalar) SignedHalf {
    const negative = scalar.is_high();
    const magnitude = if (negative) scalar.neg() else scalar;
    assert(magnitude.limbs[2] <= 1 and magnitude.limbs[3] == 0);
    return .{ .magnitude = magnitude.limbs, .negative = negative };
}

/// round(k * g / 2^384), the GLV rounding step.
fn mul_shift_384(k: u256, g: u256) Scalar {
    const product = std.math.mulWide(u256, k, g);
    const rounded = (product >> 384) + ((product >> 383) & 1);
    assert(rounded < (1 << 129));
    return Scalar.from_int(@intCast(rounded));
}

/// Splits k into (r1, r2) with k = r1 + r2 * lambda (mod n), both of small magnitude.
pub fn split_lambda(k: Scalar) [2]SignedHalf {
    const k_int = k.to_int();
    const c1 = mul_shift_384(k_int, g1_int);
    const c2 = mul_shift_384(k_int, g2_int);
    const r2 = c1.mul(Scalar.from_int(b1_negated_int)).add(c2.mul(Scalar.from_int(b2_negated_int)));
    const r1 = k.sub(r2.mul(Scalar.from_int(lambda_int)));
    assert(r1.add(r2.mul(Scalar.from_int(lambda_int))).equal(k));
    return .{ signed_half(r1), signed_half(r2) };
}

/// Maximum wNAF length for a magnitude below 2^129 (one extra digit for the carry).
pub const wnaf_length_max = 131;

/// Width-`window` non-adjacent form of a magnitude below 2^129: odd digits in
/// (-2^(window-1), 2^(window-1)), at least `window - 1` zeros between non-zero
/// digits. Returns the digit count (index of the highest non-zero digit + 1).
pub fn wnaf(magnitude: [4]u64, comptime window: u4, digits: *[wnaf_length_max]i16) u32 {
    comptime assert(window >= 2 and window <= 15);
    assert(magnitude[3] == 0 and magnitude[2] <= 1);
    const padded: [5]u64 = .{ magnitude[0], magnitude[1], magnitude[2], 0, 0 };
    @memset(digits, 0);
    var bit: u32 = 0;
    var carry: u32 = 0;
    var length: u32 = 0;
    while (bit < wnaf_length_max) {
        const word_bit: u32 = @intCast((padded[bit / 64] >> @intCast(bit % 64)) & 1);
        if (word_bit == carry) {
            bit += 1;
            continue;
        }
        const word = bits_at(&padded, bit, window) + carry;
        carry = (word >> (window - 1)) & 1;
        const digit: i32 = @as(i32, @intCast(word)) - @as(i32, @intCast(carry << window));
        assert(digit & 1 == 1);
        digits[bit] = @intCast(digit);
        length = bit + 1;
        bit += window;
    }
    assert(carry == 0);
    return length;
}

fn bits_at(padded: *const [5]u64, bit: u32, comptime count: u4) u32 {
    assert(bit < wnaf_length_max);
    const limb = bit / 64;
    const offset: u6 = @intCast(bit % 64);
    var value = padded[limb] >> offset;
    if (offset != 0) value |= padded[limb + 1] << @intCast(@as(u7, 64) - offset);
    return @intCast(value & ((@as(u64, 1) << count) - 1));
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

fn random_scalar(prng: *Prng) Scalar {
    const value: u256 = switch (prng.below(6)) {
        0 => prng.below(3),
        1 => n_int - 1 - prng.below(3),
        2 => n_int / 2 + prng.below(3) - 1,
        else => @as(u256, prng.int(u128)) << 128 | prng.int(u128),
    };
    return Scalar.from_int(value % n_int);
}

test "scalar: arithmetic matches u512 reference" {
    var prng = Prng.init(0x7363616c6172);
    const n: u512 = n_int;
    for (0..3000) |_| {
        const a = random_scalar(&prng);
        const b = random_scalar(&prng);
        const x: u512 = a.to_int();
        const y: u512 = b.to_int();
        try testing.expectEqual(@as(u256, @intCast((x + y) % n)), a.add(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((x + n - y) % n)), a.sub(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((x * y) % n)), a.mul(b).to_int());
        try testing.expectEqual(@as(u256, @intCast((n - x) % n)), a.neg().to_int());
        try testing.expectEqual(x > n / 2, a.is_high());
    }
    for (0..50) |_| {
        const a = random_scalar(&prng);
        if (a.is_zero()) continue;
        try testing.expect(a.mul(a.invert()).equal(Scalar.one));
    }
}

test "scalar: byte parsing" {
    const n_bytes: [32]u8 = @bitCast(@byteSwap(n_int));
    try testing.expect(Scalar.from_bytes(&n_bytes) == null);
    try testing.expect(Scalar.from_bytes_reduce(&n_bytes).is_zero());
    var below = n_bytes;
    below[31] -= 1;
    try testing.expectEqual(below, Scalar.from_bytes(&below).?.to_bytes());
    const all_ones: [32]u8 = @splat(0xff);
    try testing.expectEqual(@as(u256, n_c_int - 1), Scalar.from_bytes_reduce(&all_ones).to_int());
}

fn wnaf_value(digits: *const [wnaf_length_max]i16, length: u32) i512 {
    var value: i512 = 0;
    var index = length;
    while (index > 0) {
        index -= 1;
        value = value * 2 + digits[index];
    }
    return value;
}

test "scalar: GLV split and wNAF recode" {
    var prng = Prng.init(0x676c76);
    const lambda = Scalar.from_int(lambda_int);
    var digits: [wnaf_length_max]i16 = undefined;
    for (0..2000) |_| {
        const k = random_scalar(&prng);
        const halves = split_lambda(k);
        var parts: [2]Scalar = undefined;
        for (halves, &parts) |half, *part| {
            const magnitude: u256 = @as(u256, half.magnitude[2]) << 128 |
                @as(u256, half.magnitude[1]) << 64 | half.magnitude[0];
            try testing.expect(magnitude < (1 << 128));
            part.* = Scalar.from_int(magnitude);
            if (half.negative) part.* = part.neg();
            const window: u4 = @intCast(2 + prng.below(14));
            const length = switch (window) {
                inline 2...15 => |w| wnaf(half.magnitude, w, &digits),
                else => unreachable,
            };
            try testing.expectEqual(@as(i512, magnitude), wnaf_value(&digits, length));
        }
        try testing.expect(parts[0].add(parts[1].mul(lambda)).equal(k));
    }
}

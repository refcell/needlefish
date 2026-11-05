//! Generic prime fields in Montgomery form over little-endian 64-bit limbs.
//!
//! `Field(limb_count, modulus)` returns a type whose elements are `[limb_count]u64`
//! holding `a * R mod p` with `R = 2^(64 * limb_count)`. All constants (the
//! Montgomery inverse, R^2, exponents) are derived at compile time from the
//! modulus, so bn254 (4 limbs), BLS12-381 (6 limbs) and P-256 (4 limbs) share one
//! audited implementation. Arithmetic is branch-free on secret data except the
//! final conditional subtraction, which is done with a mask.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub fn Field(comptime limb_count: comptime_int, comptime modulus_int: anytype) type {
    comptime assert(limb_count >= 1 and limb_count <= 8);
    return struct {
        const Self = @This();
        pub const limbs = limb_count;
        pub const bits = 64 * limb_count;
        pub const Int = @Int(.unsigned, bits);
        const Wide = @Int(.unsigned, 2 * bits);
        pub const bytes_length = bits / 8;
        pub const modulus: Int = modulus_int;
        pub const modulus_limbs: [limbs]u64 = int_to_limbs(modulus);
        /// -p^-1 mod 2^64.
        const inverse_word: u64 = compute_inverse_word(modulus_limbs[0]);
        const r_mod: Wide = (@as(Wide, 1) << bits) % modulus;
        const r_squared: Int = @intCast((r_mod * r_mod) % modulus);

        comptime {
            assert(modulus % 2 == 1);
            assert(modulus > 3);
            assert(modulus_limbs[0] *% inverse_word == std.math.maxInt(u64));
        }

        limbs_value: [limbs]u64,

        pub const zero: Self = .{ .limbs_value = @splat(0) };
        pub const one: Self = from_int_comptime(1);

        fn int_to_limbs(value: Int) [limbs]u64 {
            var out: [limbs]u64 = undefined;
            inline for (0..limbs) |index| out[index] = @truncate(value >> (64 * index));
            return out;
        }

        fn limbs_to_int(value: [limbs]u64) Int {
            var out: Int = 0;
            inline for (0..limbs) |index| out |= @as(Int, value[index]) << (64 * index);
            return out;
        }

        fn compute_inverse_word(word: u64) u64 {
            // Newton iteration for word^-1 mod 2^64; each step doubles correct bits.
            var word_inverse: u64 = 1;
            for (0..6) |_| word_inverse *%= 2 -% word *% word_inverse;
            assert(word *% word_inverse == 1);
            return 0 -% word_inverse;
        }

        /// Element for a compile-time known integer (reduced modulo p).
        pub fn from_int_comptime(comptime value: comptime_int) Self {
            const reduced: Int = @intCast(@mod(value, @as(comptime_int, modulus)));
            const mont: Int = @intCast((@as(Wide, reduced) << bits) % modulus);
            return .{ .limbs_value = comptime int_to_limbs(mont) };
        }

        /// Element for a runtime integer; reduces modulo p first.
        pub fn from_int(value: Int) Self {
            const reduced = value % modulus;
            const plain: Self = .{ .limbs_value = int_to_limbs(reduced) };
            const result = plain.mul(.{ .limbs_value = comptime int_to_limbs(r_squared) });
            assert(result.is_canonical());
            return result;
        }

        /// Canonical integer value in [0, p).
        pub fn to_int(element: Self) Int {
            assert(element.is_canonical());
            var one_plain: [limbs]u64 = @splat(0);
            one_plain[0] = 1;
            const plain = element.mul(.{ .limbs_value = one_plain });
            const value = limbs_to_int(plain.limbs_value);
            assert(value < modulus);
            return value;
        }

        /// Parses a big-endian encoding; rejects values >= p (EVM precompile rule).
        pub fn from_bytes_be(bytes: *const [bytes_length]u8) ?Self {
            const value = std.mem.readInt(Int, bytes, .big);
            if (value >= modulus) return null;
            return from_int(value);
        }

        pub fn to_bytes_be(element: Self) [bytes_length]u8 {
            var out: [bytes_length]u8 = undefined;
            std.mem.writeInt(Int, &out, element.to_int(), .big);
            return out;
        }

        fn is_canonical(element: Self) bool {
            return limbs_to_int(element.limbs_value) < modulus;
        }

        pub fn is_zero(element: Self) bool {
            var accumulator: u64 = 0;
            for (element.limbs_value) |limb| accumulator |= limb;
            return accumulator == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            var accumulator: u64 = 0;
            for (a.limbs_value, b.limbs_value) |x, y| accumulator |= x ^ y;
            return accumulator == 0;
        }

        /// Subtracts p from `value` (with an extra top word) when value >= p.
        inline fn reduce_once(value: [limbs]u64, top: u64) Self {
            var difference: [limbs]u64 = undefined;
            var borrow: u1 = 0;
            inline for (0..limbs) |index| {
                const step1 = @subWithOverflow(value[index], modulus_limbs[index]);
                const step2 = @subWithOverflow(step1[0], borrow);
                difference[index] = step2[0];
                borrow = step1[1] | step2[1];
            }
            // Keep `value` when the subtraction borrowed past the top word.
            const keep_original = @as(u64, borrow) & ~top & 1;
            const mask = 0 -% keep_original;
            var out: [limbs]u64 = undefined;
            inline for (0..limbs) |index| {
                out[index] = (value[index] & mask) | (difference[index] & ~mask);
            }
            return .{ .limbs_value = out };
        }

        pub fn add(a: Self, b: Self) Self {
            var sum: [limbs]u64 = undefined;
            var carry: u1 = 0;
            inline for (0..limbs) |index| {
                const step1 = @addWithOverflow(a.limbs_value[index], b.limbs_value[index]);
                const step2 = @addWithOverflow(step1[0], carry);
                sum[index] = step2[0];
                carry = step1[1] | step2[1];
            }
            const result = reduce_once(sum, carry);
            assert(result.is_canonical());
            return result;
        }

        pub fn sub(a: Self, b: Self) Self {
            var difference: [limbs]u64 = undefined;
            var borrow: u1 = 0;
            inline for (0..limbs) |index| {
                const step1 = @subWithOverflow(a.limbs_value[index], b.limbs_value[index]);
                const step2 = @subWithOverflow(step1[0], borrow);
                difference[index] = step2[0];
                borrow = step1[1] | step2[1];
            }
            // Add p back when the subtraction went negative.
            const mask = 0 -% @as(u64, borrow);
            var carry: u1 = 0;
            inline for (0..limbs) |index| {
                const step1 = @addWithOverflow(difference[index], modulus_limbs[index] & mask);
                const step2 = @addWithOverflow(step1[0], carry);
                difference[index] = step2[0];
                carry = step1[1] | step2[1];
            }
            const result: Self = .{ .limbs_value = difference };
            assert(result.is_canonical());
            return result;
        }

        pub fn neg(a: Self) Self {
            return zero.sub(a);
        }

        pub fn double(a: Self) Self {
            return a.add(a);
        }

        inline fn multiply_add(a: u64, b: u64, c: u64, carry: u64) struct { u64, u64 } {
            const wide = @as(u128, a) * b + c + carry;
            return .{ @truncate(wide), @truncate(wide >> 64) };
        }

        /// Adds `addend` into `accumulator[offset..offset + limbs]` with one carry chain and
        /// ripples the carry into the following words of the window.
        inline fn accumulate(
            accumulator: *[limbs + 2]u64,
            comptime offset: usize,
            addend: *const [limbs]u64,
        ) void {
            comptime assert(offset <= 1);
            var carry: u1 = 0;
            inline for (0..limbs) |j| {
                const step1 = @addWithOverflow(accumulator[offset + j], addend[j]);
                const step2 = @addWithOverflow(step1[0], carry);
                accumulator[offset + j] = step2[0];
                carry = step1[1] | step2[1];
            }
            inline for (offset + limbs..limbs + 2) |k| {
                const step = @addWithOverflow(accumulator[k], carry);
                accumulator[k] = step[0];
                carry = step[1];
            }
            assert(carry == 0);
        }

        /// Adds the row x * y[0..limbs] into the window: low halves at offset 0, high
        /// halves at offset 1, as two straight carry chains (adds/adcs on AArch64).
        inline fn accumulate_row(accumulator: *[limbs + 2]u64, x: u64, y: *const [limbs]u64) void {
            var low: [limbs]u64 = undefined;
            var high: [limbs]u64 = undefined;
            inline for (0..limbs) |j| {
                const product = @as(u128, x) * y[j];
                low[j] = @truncate(product);
                high[j] = @truncate(product >> 64);
            }
            accumulate(accumulator, 0, &low);
            accumulate(accumulator, 1, &high);
        }

        /// Montgomery product a * b * R^-1 mod p (CIOS, row-wise carry chains).
        pub fn mul(a: Self, b: Self) Self {
            var t: [limbs + 2]u64 = @splat(0);
            inline for (0..limbs) |i| {
                accumulate_row(&t, b.limbs_value[i], &a.limbs_value);
                const m = t[0] *% inverse_word;
                accumulate_row(&t, m, &modulus_limbs);
                assert(t[0] == 0);
                inline for (0..limbs + 1) |k| t[k] = t[k + 1];
                t[limbs + 1] = 0;
            }
            assert(t[limbs] <= 1);
            const result = reduce_once(t[0..limbs].*, t[limbs]);
            assert(result.is_canonical());
            return result;
        }

        pub fn square(a: Self) Self {
            return a.mul(a);
        }

        /// a^exponent for a public exponent (square-and-multiply, MSB first).
        pub fn pow(a: Self, exponent: Int) Self {
            var result = one;
            var index: u32 = bits;
            while (index > 0) {
                index -= 1;
                result = result.square();
                if ((exponent >> @intCast(index)) & 1 == 1) result = result.mul(a);
            }
            return result;
        }

        /// Multiplicative inverse via Fermat; inverse(0) = 0.
        pub fn inverse(a: Self) Self {
            const result = a.pow(modulus - 2);
            assert(a.is_zero() or result.mul(a).eql(one));
            return result;
        }

        /// Square root when p = 3 mod 4; null when `a` is not a square.
        pub fn sqrt(a: Self) ?Self {
            comptime assert(modulus % 4 == 3);
            const candidate = a.pow((modulus + 1) / 4);
            if (!candidate.square().eql(a)) return null;
            return candidate;
        }

        /// Legendre-style check: true for zero and quadratic residues.
        pub fn is_square(a: Self) bool {
            const symbol = a.pow((modulus - 1) / 2);
            return symbol.is_zero() or symbol.eql(one);
        }

        /// Sign of the canonical value, as used by hash-to-curve: value mod 2.
        pub fn is_odd(a: Self) bool {
            return a.to_int() & 1 == 1;
        }
    };
}

// Tests use the bn254 base field (4 limbs, 254 bits), the P-256 field (4 limbs,
// full 256 bits, exercising the carry word), and the BLS12-381 field (6 limbs).
const bn254_p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
const p256_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const bls_p = (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf << 192) |
    0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

const testing = std.testing;

fn check_field_against_big_ints(comptime F: type, seed: u64) !void {
    const Wide = @Int(.unsigned, 2 * F.bits);
    var prng = Prng.init(seed);
    for (0..400) |round| {
        var a_int: F.Int = 0;
        var b_int: F.Int = 0;
        for (0..F.limbs) |index| {
            a_int |= @as(F.Int, prng.int(u64)) << @intCast(64 * index);
            b_int |= @as(F.Int, prng.int(u64)) << @intCast(64 * index);
        }
        // Mix in edge values near 0 and p.
        if (round % 7 == 0) a_int = F.modulus - 1 - (round % 3);
        if (round % 11 == 0) b_int = round % 2;
        a_int %= F.modulus;
        b_int %= F.modulus;
        const a = F.from_int(a_int);
        const b = F.from_int(b_int);
        try testing.expectEqual(a_int, a.to_int());
        try testing.expectEqual((@as(Wide, a_int) + b_int) % F.modulus, a.add(b).to_int());
        try testing.expectEqual(
            (@as(Wide, a_int) + F.modulus - b_int) % F.modulus,
            a.sub(b).to_int(),
        );
        try testing.expectEqual((@as(Wide, a_int) * b_int) % F.modulus, a.mul(b).to_int());
        if (round % 50 == 0 and !a.is_zero()) {
            try testing.expect(a.inverse().mul(a).eql(F.one));
            const s = a.square();
            const root = s.sqrt().?;
            try testing.expect(root.eql(a) or root.eql(a.neg()));
            try testing.expect(s.is_square());
        }
    }
}

test "montgomery: bn254 base field matches big-int arithmetic" {
    try check_field_against_big_ints(Field(4, bn254_p), 1);
}

test "montgomery: p256 field (full-width modulus) matches big-int arithmetic" {
    try check_field_against_big_ints(Field(4, p256_p), 2);
}

test "montgomery: bls12-381 base field matches big-int arithmetic" {
    try check_field_against_big_ints(Field(6, bls_p), 3);
}

test "montgomery: byte encoding rejects non-canonical values" {
    const F = Field(4, bn254_p);
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, bn254_p, .big);
    try testing.expect(F.from_bytes_be(&bytes) == null);
    std.mem.writeInt(u256, &bytes, bn254_p - 1, .big);
    const element = F.from_bytes_be(&bytes).?;
    try testing.expectEqualSlices(u8, &bytes, &element.to_bytes_be());
    try testing.expect(element.add(F.one).is_zero());
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    const F = Field(4, p256_p);
    const a_int = smith.value(u256) % F.modulus;
    const b_int = smith.value(u256) % F.modulus;
    const a = F.from_int(a_int);
    const b = F.from_int(b_int);
    try testing.expectEqual((@as(u512, a_int) * b_int) % F.modulus, a.mul(b).to_int());
    try testing.expect(a.sub(b).add(b).eql(a));
}

test "montgomery: coverage-guided fuzz" {
    try testing.fuzz({}, fuzz_one, .{});
}

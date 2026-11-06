//! Fast unsigned division and remainder for EVM words.
//!
//! LLVM lowers `u256 / u256` (and `%`, and the u512 MULMOD reduction) to a generic
//! bit-serial expansion that costs ~500 ns per operation on aarch64, which made DIV/MOD
//! the hottest path in arithmetic-heavy contracts. This is Knuth's algorithm D
//! (TAOCP 4.3.1) over 64-bit limbs; each quotient digit comes from a Möller-Granlund
//! 2-by-1 step with a precomputed reciprocal, so the inner loops are only 64x64->128
//! multiplies. Differentially fuzzed against the builtin
//! operators below.

const std = @import("std");
const assert = std.debug.assert;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const limb_bits = 64;
const divisor_limbs_max = 256 / limb_bits;

pub fn DivRem(comptime T: type) type {
    return struct { quotient: T, remainder: u256 };
}

/// `a / b` and `a % b` for `b != 0`. `T` is `u256` or a wider dividend (u320 for
/// ADDMOD, u512 for MULMOD); the divisor is always a word.
pub fn div_rem(comptime T: type, a: T, b: u256) DivRem(T) {
    comptime assert(@bitSizeOf(T) % limb_bits == 0);
    comptime assert(@bitSizeOf(T) >= 256);
    assert(b != 0);
    if (a < b) return .{ .quotient = 0, .remainder = @intCast(a) };
    if (a <= std.math.maxInt(u64)) {
        // b <= a, so both fit in a machine word.
        const x: u64 = @intCast(a);
        const y: u64 = @intCast(b);
        return .{ .quotient = x / y, .remainder = x % y };
    }
    const dividend_limbs = limbs_of(T, a);
    const divisor_limbs = limbs_of(u256, b);
    assert(dividend_limbs >= divisor_limbs);
    if (divisor_limbs == 1) return div_rem_single(T, a, dividend_limbs, @intCast(b));
    return div_rem_knuth(T, a, dividend_limbs, b, divisor_limbs);
}

pub fn div(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return div_rem(u256, a, b).quotient;
}

pub fn rem(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return div_rem(u256, a, b).remainder;
}

/// Number of significant 64-bit limbs in `x` (at least one).
fn limbs_of(comptime T: type, x: T) u32 {
    const bits: u32 = @bitSizeOf(T) - @clz(x);
    return @max(1, (bits + limb_bits - 1) / limb_bits);
}

inline fn limb(x: anytype, index: u32) u64 {
    const T = @TypeOf(x);
    assert(index < @bitSizeOf(T) / limb_bits);
    return @truncate(x >> @intCast(index * limb_bits));
}

/// Möller-Granlund reciprocal of a normalized divisor: floor((2^128 - 1) / d) - 2^64.
fn reciprocal(d: u64) u64 {
    assert(d >> 63 == 1);
    return @truncate(~@as(u128, 0) / d);
}

const QuotientRemainder = struct { quotient: u64, remainder: u64 };

/// Divide `high:low` by the normalized `d` (high < d) with two multiplications
/// ("Improved division by invariant integers", Möller and Granlund, algorithm 4).
inline fn div_2by1(high: u64, low: u64, d: u64, v: u64) QuotientRemainder {
    assert(high < d);
    const product = @as(u128, v) * high +% ((@as(u128, high) << 64) | low);
    var quotient: u64 = @as(u64, @truncate(product >> 64)) +% 1;
    var remainder: u64 = low -% quotient *% d;
    if (remainder > @as(u64, @truncate(product))) {
        quotient -%= 1;
        remainder +%= d;
    }
    if (remainder >= d) {
        quotient += 1;
        remainder -= d;
    }
    return .{ .quotient = quotient, .remainder = remainder };
}

/// Short division by a single-limb divisor: one reciprocal step per dividend limb.
fn div_rem_single(comptime T: type, a: T, dividend_limbs: u32, divisor: u64) DivRem(T) {
    assert(divisor != 0);
    assert(dividend_limbs <= @bitSizeOf(T) / limb_bits);
    const shift: u6 = @intCast(@clz(divisor));
    const d = divisor << shift;
    const v = reciprocal(d);
    const Wide = @Int(.unsigned, @bitSizeOf(T) + limb_bits);
    const a_shifted = @as(Wide, a) << shift;
    var quotient: T = 0;
    var carry: u64 = limb(a_shifted, dividend_limbs);
    var index = dividend_limbs;
    while (index > 0) {
        index -= 1;
        const step = div_2by1(carry, limb(a_shifted, index), d, v);
        carry = step.remainder;
        quotient |= @as(T, step.quotient) << @intCast(index * limb_bits);
    }
    assert(carry >> shift < divisor);
    return .{ .quotient = quotient, .remainder = carry >> shift };
}

fn div_rem_knuth(
    comptime T: type,
    a: T,
    dividend_limbs: u32,
    b: u256,
    divisor_limbs: u32,
) DivRem(T) {
    const n = divisor_limbs;
    const m = dividend_limbs;
    assert(n >= 2 and n <= divisor_limbs_max);
    assert(m >= n);
    // Normalize so the divisor's top limb has its high bit set (D1).
    const shift: u6 = @intCast(@clz(limb(b, n - 1)));
    const Wide = @Int(.unsigned, @bitSizeOf(T) + limb_bits);
    var v: [divisor_limbs_max]u64 = undefined;
    const b_shifted = b << shift;
    for (0..n) |i| v[i] = limb(b_shifted, @intCast(i));
    assert(v[n - 1] >> 63 == 1);
    var u: [@bitSizeOf(T) / limb_bits + 1]u64 = undefined;
    const a_shifted = @as(Wide, a) << shift;
    for (0..m + 1) |i| u[i] = limb(a_shifted, @intCast(i));
    const top_reciprocal = reciprocal(v[n - 1]);

    var quotient: T = 0;
    var j: u32 = m - n + 1;
    while (j > 0) {
        j -= 1;
        const digit = knuth_step(u[j .. j + n + 1], v[0..n], top_reciprocal);
        quotient |= @as(T, digit) << @intCast(j * limb_bits);
    }
    var remainder: u256 = 0;
    for (0..n) |i| remainder |= @as(u256, u[i]) << @intCast(i * limb_bits);
    remainder >>= shift;
    assert(remainder < b);
    return .{ .quotient = quotient, .remainder = remainder };
}

/// One quotient digit (D3-D6): `window` is u[j..j+n], updated in place to the remainder.
fn knuth_step(window: []u64, v: []const u64, top_reciprocal: u64) u64 {
    const n = v.len;
    assert(window.len == n + 1);
    assert(n >= 2);
    assert(window[n] <= v[n - 1]);
    var estimate: u64 = std.math.maxInt(u64);
    var estimate_rem: u64 = undefined;
    var rem_overflow = false;
    if (window[n] == v[n - 1]) {
        const sum = @addWithOverflow(window[n - 1], v[n - 1]);
        estimate_rem = sum[0];
        rem_overflow = sum[1] == 1;
    } else {
        const step = div_2by1(window[n], window[n - 1], v[n - 1], top_reciprocal);
        estimate = step.quotient;
        estimate_rem = step.remainder;
    }
    // Knuth: at most two corrections bring the estimate within one of the true digit.
    var correction: u32 = 0;
    while (correction < 2 and !rem_overflow) : (correction += 1) {
        const lhs = @as(u128, estimate) * v[n - 2];
        if (lhs <= ((@as(u128, estimate_rem) << 64) | window[n - 2])) break;
        estimate -= 1;
        const sum = @addWithOverflow(estimate_rem, v[n - 1]);
        estimate_rem = sum[0];
        rem_overflow = sum[1] == 1;
    }
    // Multiply and subtract (D4).
    var carry: u64 = 0;
    var borrow: u1 = 0;
    for (0..n) |i| {
        const product = @as(u128, estimate) * v[i] + carry;
        carry = @truncate(product >> 64);
        const first = @subWithOverflow(window[i], @as(u64, @truncate(product)));
        const second = @subWithOverflow(first[0], borrow);
        window[i] = second[0];
        borrow = first[1] | second[1];
    }
    const first = @subWithOverflow(window[n], carry);
    const second = @subWithOverflow(first[0], borrow);
    window[n] = second[0];
    if (first[1] | second[1] == 0) return estimate;
    // Add back (D6): the estimate was one too large.
    var add_carry: u1 = 0;
    for (0..n) |i| {
        const sum = @addWithOverflow(window[i], v[i]);
        const sum_carry = @addWithOverflow(sum[0], add_carry);
        window[i] = sum_carry[0];
        add_carry = sum[1] | sum_carry[1];
    }
    window[n] +%= add_carry;
    return estimate - 1;
}

// ------------------------------------------------------------------------- tests

const testing = std.testing;

fn expect_matches(comptime T: type, a: T, b: u256) !void {
    if (b == 0) return;
    const result = div_rem(T, a, b);
    try testing.expectEqual(a / b, result.quotient);
    try testing.expectEqual(@as(u256, @intCast(a % b)), result.remainder);
}

test "uint: edge cases match the builtin operators" {
    const max = std.math.maxInt(u256);
    const cases = [_][2]u256{
        .{ 0, 1 },                         .{ 1, 1 },
        .{ max, 1 },                       .{ max, max },
        .{ max, 2 },                       .{ max - 1, max },
        .{ 1 << 255, 3 },                  .{ max, 0xffff_ffff },
        .{ max, 0x1_0000_0000 },           .{ max, (1 << 64) - 1 },
        .{ max, 1 << 128 },                .{ (1 << 192) + 5, (1 << 96) + 1 },
        .{ max, (1 << 255) + 1 },          .{ 0x8000_0000_0000_0000_0000_0001, 0x8000_0001 },
        .{ (1 << 96) - 1, (1 << 64) + 1 },
    };
    for (cases) |case| try expect_matches(u256, case[0], case[1]);
    try testing.expectEqual(@as(u256, 0), div(5, 0));
    try testing.expectEqual(@as(u256, 0), rem(5, 0));
}

test "uint: wide dividends for ADDMOD and MULMOD" {
    const max = std.math.maxInt(u256);
    try expect_matches(u320, @as(u320, max) + max, max - 2);
    try expect_matches(u512, @as(u512, max) * max, max);
    try expect_matches(u512, @as(u512, max) * max, 7);
    try expect_matches(u512, @as(u512, max) * max, (1 << 200) + 3);
}

/// Random value with a random number of significant bits and sparse runs of ones and
/// zeros, which exercise the Knuth correction and add-back paths far more often than
/// uniform values.
fn shaped(comptime T: type, prng: *Prng) T {
    var value: T = 0;
    var index: u32 = 0;
    while (index < @bitSizeOf(T) / 64) : (index += 1) {
        const word: u64 = switch (prng.below(4)) {
            0 => 0,
            1 => std.math.maxInt(u64),
            else => prng.int(u64),
        };
        value |= @as(T, word) << @intCast(index * 64);
    }
    const bits: u32 = @intCast(prng.below(@bitSizeOf(T) + 1));
    if (bits == @bitSizeOf(T)) return value;
    return value & ((@as(T, 1) << @intCast(bits)) - 1);
}

test "uint: seeded differential against the builtin operators" {
    var prng = Prng.init(0x0d17_0001);
    var iteration: u32 = 0;
    while (iteration < 20_000) : (iteration += 1) {
        try expect_matches(u256, shaped(u256, &prng), shaped(u256, &prng));
    }
    iteration = 0;
    while (iteration < 2_000) : (iteration += 1) {
        try expect_matches(u512, shaped(u512, &prng), shaped(u256, &prng));
    }
}

fn fuzz_div_rem(_: void, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    const take = @min(bytes.len, 8);
    @memcpy(seed[0..take], bytes[0..take]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try expect_matches(u256, shaped(u256, &prng), shaped(u256, &prng));
    try expect_matches(u512, shaped(u512, &prng), shaped(u256, &prng));
}

test "uint: fuzz div_rem" {
    try fuzz.run_bytes({}, fuzz_div_rem, .{ .seed = 0x0d17_0002, .iterations = 512 });
}

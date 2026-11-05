//! Fast unsigned division and remainder for EVM words.
//!
//! LLVM lowers `u256 / u256` (and `%`, and the u512 MULMOD reduction) to a generic
//! bit-serial expansion that costs ~500 ns per operation on aarch64, which made DIV/MOD
//! the hottest path in arithmetic-heavy contracts. This is Knuth's algorithm D
//! (TAOCP 4.3.1, as in Hacker's Delight `divmnu`) over 32-bit limbs, so every step is a
//! native 64-bit hardware divide or multiply. Differentially fuzzed against the builtin
//! operators below.

const std = @import("std");
const assert = std.debug.assert;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const limb_bits = 32;
const limb_base: u64 = 1 << limb_bits;
const divisor_limbs_max = 256 / limb_bits;

pub fn DivRem(comptime T: type) type {
    return struct { quotient: T, remainder: u256 };
}

/// `a / b` and `a % b` for `b != 0`. `T` is `u256` or a wider dividend (u288 for
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

/// Number of significant 32-bit limbs in `x` (at least one).
fn limbs_of(comptime T: type, x: T) u32 {
    const bits: u32 = @bitSizeOf(T) - @clz(x);
    return @max(1, (bits + limb_bits - 1) / limb_bits);
}

inline fn limb(x: anytype, index: u32) u32 {
    const T = @TypeOf(x);
    assert(index < @bitSizeOf(T) / limb_bits);
    return @truncate(x >> @intCast(index * limb_bits));
}

/// Short division by a single-limb divisor: one hardware divide per dividend limb.
fn div_rem_single(comptime T: type, a: T, dividend_limbs: u32, divisor: u32) DivRem(T) {
    assert(divisor != 0);
    assert(dividend_limbs <= @bitSizeOf(T) / limb_bits);
    var quotient: T = 0;
    var carry: u64 = 0;
    var index = dividend_limbs;
    while (index > 0) {
        index -= 1;
        const numerator = (carry << limb_bits) | limb(a, index);
        const digit = numerator / divisor;
        assert(digit < limb_base);
        carry = numerator - digit * divisor;
        quotient |= @as(T, @intCast(digit)) << @intCast(index * limb_bits);
    }
    assert(carry < divisor);
    return .{ .quotient = quotient, .remainder = carry };
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
    const shift: u5 = @intCast(@clz(limb(b, n - 1)));
    const Wide = @Int(.unsigned, @bitSizeOf(T) + limb_bits);
    var v: [divisor_limbs_max]u32 = undefined;
    const b_shifted = b << shift;
    for (0..n) |i| v[i] = limb(b_shifted, @intCast(i));
    assert(v[n - 1] >= limb_base / 2);
    var u: [@bitSizeOf(T) / limb_bits + 1]u32 = undefined;
    const a_shifted = @as(Wide, a) << shift;
    for (0..m + 1) |i| u[i] = limb(a_shifted, @intCast(i));

    var quotient: T = 0;
    var j: u32 = m - n + 1;
    while (j > 0) {
        j -= 1;
        const digit = knuth_step(u[j .. j + n + 1], v[0..n]);
        quotient |= @as(T, digit) << @intCast(j * limb_bits);
    }
    var remainder: u256 = 0;
    for (0..n) |i| remainder |= @as(u256, u[i]) << @intCast(i * limb_bits);
    remainder >>= shift;
    assert(remainder < b);
    return .{ .quotient = quotient, .remainder = remainder };
}

/// One quotient digit (D3-D6): `window` is u[j..j+n], updated in place to the remainder.
fn knuth_step(window: []u32, v: []const u32) u32 {
    const n = v.len;
    assert(window.len == n + 1);
    assert(n >= 2);
    const top = (@as(u64, window[n]) << limb_bits) | window[n - 1];
    var estimate = top / v[n - 1];
    var estimate_rem = top - estimate * v[n - 1];
    // Knuth: at most two corrections bring the estimate within one of the true digit.
    var correction: u32 = 0;
    while (correction < 2) : (correction += 1) {
        const too_big = estimate >= limb_base or
            estimate * v[n - 2] > ((estimate_rem << limb_bits) | window[n - 2]);
        if (!too_big) break;
        estimate -= 1;
        estimate_rem += v[n - 1];
        if (estimate_rem >= limb_base) break;
    }
    assert(estimate < limb_base);
    // Multiply and subtract (D4).
    var borrow: i64 = 0;
    for (0..n) |i| {
        const product: u64 = estimate * v[i];
        const t: i64 = @as(i64, window[i]) - borrow - @as(i64, @intCast(product & 0xffff_ffff));
        window[i] = @truncate(@as(u64, @bitCast(t)));
        borrow = @as(i64, @intCast(product >> limb_bits)) - (t >> limb_bits);
    }
    const t: i64 = @as(i64, window[n]) - borrow;
    window[n] = @truncate(@as(u64, @bitCast(t)));
    var digit: u32 = @intCast(estimate);
    if (t < 0) {
        // Add back (D6): the estimate was one too large.
        digit -= 1;
        var carry: u64 = 0;
        for (0..n) |i| {
            const sum: u64 = @as(u64, window[i]) + v[i] + carry;
            window[i] = @truncate(sum);
            carry = sum >> limb_bits;
        }
        window[n] +%= @truncate(carry);
    }
    return digit;
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
    try expect_matches(u288, @as(u288, max) + max, max - 2);
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

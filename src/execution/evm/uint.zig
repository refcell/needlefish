//! Fast unsigned division and remainder for EVM words.
//!
//! LLVM lowers `u256 / u256` (and `%`, and the u512 MULMOD reduction) to a generic
//! bit-serial expansion that costs ~500 ns per operation on aarch64, which made DIV/MOD
//! the hottest path in arithmetic-heavy contracts. This is Knuth's algorithm D
//! (TAOCP 4.3.1) over 64-bit limbs, unrolled per divisor length. Each quotient digit
//! comes from x86-64's `divq`, or elsewhere from a Möller-Granlund 2-by-1 step with a
//! precomputed reciprocal. Both paths are differentially fuzzed against the builtin
//! operators below.

const std = @import("std");
const builtin = @import("builtin");
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
    return div_rem_with(hardware_divide, T, a, b);
}

/// x86-64 divides 128 by 64 bits in one instruction, which on current cores (Ice Lake and
/// later, Zen 3 and later) costs less than computing a reciprocal for the few digits an
/// EVM word has. Elsewhere each digit is a Möller-Granlund 2-by-1 step.
const hardware_divide = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm;

fn div_rem_with(comptime hardware: bool, comptime T: type, a: T, b: u256) DivRem(T) {
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
    if (T != u256 and a <= std.math.maxInt(u256)) {
        // Most ADDMOD and MULMOD dividends fit a word: skip the wide limb loops.
        const narrow = div_rem_with(hardware, u256, @intCast(a), b);
        return .{ .quotient = narrow.quotient, .remainder = narrow.remainder };
    }
    const dividend_limbs = limbs_of(T, a);
    const divisor_limbs = limbs_of(u256, b);
    assert(dividend_limbs >= divisor_limbs);
    return switch (divisor_limbs) {
        1 => div_rem_single(hardware, T, a, dividend_limbs, @intCast(b)),
        inline 2, 3, 4 => |n| div_rem_knuth(hardware, T, n, a, dividend_limbs, b),
        else => unreachable,
    };
}

pub fn div(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return div_rem(u256, a, b).quotient;
}

pub fn rem(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return div_rem(u256, a, b).remainder;
}

/// The full 512-bit product as a 4x4-limb schoolbook multiply (16 64x64->128 products;
/// the generic `u512 * u512` lowering multiplies wider than needed).
pub fn wide_mul(a: u256, b: u256) u512 {
    const a_limbs = to_limbs(u256, a);
    const b_limbs = to_limbs(u256, b);
    var result: [8]u64 = @splat(0);
    for (0..4) |i| {
        var carry: u64 = 0;
        for (0..4) |j| {
            const t = @as(u128, a_limbs[i]) * b_limbs[j] + result[i + j] + carry;
            result[i + j] = @truncate(t);
            carry = @truncate(t >> 64);
        }
        result[i + 4] = carry;
    }
    return @bitCast(result);
}

/// `x mod (2^256 - 1)`: 2^256 is congruent to 1, so fold the high word onto the low one.
pub fn reduce_all_ones(x: u512) u256 {
    const all_ones: u256 = std.math.maxInt(u256);
    const sum = @addWithOverflow(@as(u256, @truncate(x)), @as(u256, @truncate(x >> 256)));
    // hi + lo <= 2^257 - 2, so with a carry the low word is at most 2^256 - 2.
    const folded = sum[0] + sum[1];
    return if (folded == all_ones) 0 else folded;
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

/// 11-bit seeds for the reciprocal: 0x7fd00 / (256 + i), indexed by the divisor's top 9 bits.
const reciprocal_table: [256]u16 = table: {
    var table: [256]u16 = undefined;
    for (&table, 0..) |*item, index| item.* = @intCast(0x7fd00 / (256 + index));
    break :table table;
};

inline fn high_product(a: u64, b: u64) u64 {
    return @truncate((@as(u128, a) * b) >> 64);
}

/// Möller-Granlund reciprocal of a normalized divisor: floor((2^128 - 1) / d) - 2^64.
/// Table seed plus Newton steps (algorithm 2 of the paper, as in intx) instead of a
/// software 128-bit division.
fn reciprocal(d: u64) u64 {
    assert(d >> 63 == 1);
    const d9 = d >> 55;
    const v0: u64 = reciprocal_table[d9 - 256];
    assert(v0 >= 1024 and v0 <= 2045);
    const d40 = (d >> 24) + 1;
    const v1 = (v0 << 11) -% @as(u64, @as(u32, @truncate((v0 *% v0 *% d40) >> 40))) -% 1;
    const v2 = (v1 << 13) +% ((v1 *% ((1 << 60) -% v1 *% d40)) >> 47);
    const d0 = d & 1;
    const d63 = (d >> 1) + d0;
    const e = ((v2 >> 1) & (0 -% d0)) -% v2 *% d63;
    const v3 = (high_product(v2, e) >> 1) +% (v2 << 31);
    const product = @as(u128, v3) * d +% d;
    const v4 = v3 -% @as(u64, @truncate(product >> 64)) -% d;
    return v4;
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

fn Limbs(comptime T: type) type {
    return [@bitSizeOf(T) / limb_bits]u64;
}

/// Limbs of `x`, least significant first (the target is little-endian).
inline fn to_limbs(comptime T: type, x: T) Limbs(T) {
    comptime assert(builtin.cpu.arch.endian() == .little);
    return @bitCast(x);
}

/// The low `count` limbs of `a` shifted left by `shift`, in `count + 1` limbs so the
/// shifted-out bits are kept; the limbs above are undefined.
fn normalized(comptime T: type, a: T, count: u32, shift: u6) Limbs(Wide(T)) {
    assert(count >= 1 and count <= @bitSizeOf(T) / limb_bits);
    const limbs = to_limbs(T, a);
    var out: Limbs(Wide(T)) = undefined;
    out[count] = @truncate((@as(u128, limbs[count - 1]) << shift) >> limb_bits);
    var index = count - 1;
    while (index > 0) : (index -= 1) {
        const pair = (@as(u128, limbs[index]) << limb_bits) | limbs[index - 1];
        out[index] = @truncate((pair << shift) >> limb_bits);
    }
    out[0] = limbs[0] << shift;
    return out;
}

fn Wide(comptime T: type) type {
    return @Int(.unsigned, @bitSizeOf(T) + limb_bits);
}

/// Divide `high:low` by `d` (high < d): the `divq` instruction, or a Möller-Granlund step
/// with the reciprocal `v` of the normalized `d`.
inline fn divide_2by1(
    comptime hardware: bool,
    high: u64,
    low: u64,
    d: u64,
    v: u64,
) QuotientRemainder {
    assert(high < d);
    if (!hardware) return div_2by1(high, low, d, v);
    var remainder: u64 = undefined;
    const quotient = asm (
        \\divq %[d]
        : [_] "={rax}" (-> u64),
          [_] "={rdx}" (remainder),
        : [d] "r" (d),
          [_] "{rax}" (low),
          [_] "{rdx}" (high),
    );
    return .{ .quotient = quotient, .remainder = remainder };
}

/// Short division by a single-limb divisor, one digit per dividend limb. `divq` needs no
/// normalization; the reciprocal step does.
fn div_rem_single(
    comptime hardware: bool,
    comptime T: type,
    a: T,
    dividend_limbs: u32,
    divisor: u64,
) DivRem(T) {
    assert(divisor != 0);
    assert(dividend_limbs >= 1 and dividend_limbs <= @bitSizeOf(T) / limb_bits);
    // Unrolled per dividend length so the digits stay in registers: a loop indexing a
    // stack array stored the quotient one limb at a time and read it back as wider vectors,
    // which cannot be forwarded from the narrower stores and stalled every division.
    return switch (dividend_limbs) {
        inline 1...@bitSizeOf(T) / limb_bits => |count| div_rem_single_unrolled(
            hardware,
            T,
            count,
            a,
            divisor,
        ),
        else => unreachable,
    };
}

inline fn div_rem_single_unrolled(
    comptime hardware: bool,
    comptime T: type,
    comptime count: u32,
    a: T,
    divisor: u64,
) DivRem(T) {
    comptime assert(count >= 1 and count <= @bitSizeOf(T) / limb_bits);
    assert(divisor != 0);
    const shift: u6 = if (hardware) 0 else @intCast(@clz(divisor));
    const d = divisor << shift;
    const v = if (hardware) 0 else reciprocal(d);
    // `a` has `count` significant limbs, so limb `count` of the shifted dividend holds the
    // bits shifted out of the top one.
    const u = to_limbs(Wide(T), @as(Wide(T), a) << shift);
    var quotient: Limbs(T) = @splat(0);
    var carry: u64 = u[count];
    inline for (0..count) |step_index| {
        const index = count - 1 - step_index;
        const step = divide_2by1(hardware, carry, u[index], d, v);
        carry = step.remainder;
        quotient[index] = step.quotient;
    }
    assert(carry >> shift < divisor);
    return .{ .quotient = @bitCast(quotient), .remainder = carry >> shift };
}

/// Knuth's algorithm D for an `n`-limb divisor (n >= 2), unrolled per `n`.
fn div_rem_knuth(
    comptime hardware: bool,
    comptime T: type,
    comptime n: u32,
    a: T,
    dividend_limbs: u32,
    b: u256,
) DivRem(T) {
    comptime assert(n >= 2 and n <= divisor_limbs_max);
    assert(dividend_limbs >= n and dividend_limbs <= @bitSizeOf(T) / limb_bits);
    // Normalize so the divisor's top limb has its high bit set (D1).
    const shift: u6 = @intCast(@clz(b) - (divisor_limbs_max - n) * limb_bits);
    const v: [n]u64 = to_limbs(u256, b << shift)[0..n].*;
    assert(v[n - 1] >> 63 == 1);
    const top_reciprocal = if (hardware) 0 else reciprocal(v[n - 1]);
    var u = normalized(T, a, dividend_limbs, shift);
    var quotient: Limbs(T) = @splat(0);
    var j: u32 = dividend_limbs + 1 - n;
    while (j > 0) {
        j -= 1;
        quotient[j] = knuth_step(hardware, n, u[j..][0 .. n + 1], &v, top_reciprocal);
    }
    // Denormalize the remainder u[0..n] (D8).
    var remainder: [divisor_limbs_max]u64 = @splat(0);
    remainder[0..n].* = u[0..n].*;
    const result = @as(u256, @bitCast(remainder)) >> shift;
    assert(result < b);
    return .{ .quotient = @bitCast(quotient), .remainder = result };
}

/// One quotient digit (D3-D6): `window` is u[j..j+n], updated in place to the remainder.
inline fn knuth_step(
    comptime hardware: bool,
    comptime n: u32,
    window: *[n + 1]u64,
    v: *const [n]u64,
    top_reciprocal: u64,
) u64 {
    assert(window[n] <= v[n - 1]);
    var estimate: u64 = std.math.maxInt(u64);
    var estimate_rem: u64 = undefined;
    var rem_overflow = false;
    if (window[n] == v[n - 1]) {
        const sum = @addWithOverflow(window[n - 1], v[n - 1]);
        estimate_rem = sum[0];
        rem_overflow = sum[1] == 1;
    } else {
        const step = divide_2by1(hardware, window[n], window[n - 1], v[n - 1], top_reciprocal);
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
    inline for (0..n) |i| {
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
    inline for (0..n) |i| {
        const sum = @addWithOverflow(window[i], v[i]);
        const sum_carry = @addWithOverflow(sum[0], add_carry);
        window[i] = sum_carry[0];
        add_carry = sum[1] | sum_carry[1];
    }
    window[n] +%= add_carry;
    return estimate - 1;
}

// ------------------------------------------------------------------------- tests

test "uint: schoolbook product and the all-ones reduction match the builtins" {
    var prng = Prng.init(0x3c3c_0001);
    const max: u256 = std.math.maxInt(u256);
    const edges = [_]u256{ 0, 1, 2, max, max - 1, 1 << 255, (1 << 128) - 1 };
    for (edges) |a| for (edges) |b| try expect_product(a, b);
    var round: u32 = 0;
    while (round < 20_000) : (round += 1) {
        try expect_product(shaped(u256, &prng), shaped(u256, &prng));
    }
}

fn expect_product(a: u256, b: u256) !void {
    const product = @as(u512, a) * b;
    try testing.expectEqual(product, wide_mul(a, b));
    const modulus: u512 = std.math.maxInt(u256);
    try testing.expectEqual(@as(u256, @intCast(product % modulus)), reduce_all_ones(product));
}

test "uint: table-and-Newton reciprocal equals the 128-bit division" {
    var prng = Prng.init(0x2ec1_0001);
    const edges = [_]u64{ 1 << 63, (1 << 63) + 1, std.math.maxInt(u64), std.math.maxInt(u64) - 1 };
    for (edges) |d| try testing.expectEqual(@as(u64, @truncate(~@as(u128, 0) / d)), reciprocal(d));
    var round: u32 = 0;
    while (round < 100_000) : (round += 1) {
        const d = prng.int(u64) | (1 << 63);
        try testing.expectEqual(@as(u64, @truncate(~@as(u128, 0) / d)), reciprocal(d));
    }
}

const testing = std.testing;

fn expect_matches(comptime T: type, a: T, b: u256) !void {
    if (b == 0) return;
    inline for (.{ false, hardware_divide }) |hardware| {
        const result = div_rem_with(hardware, T, a, b);
        try testing.expectEqual(a / b, result.quotient);
        try testing.expectEqual(@as(u256, @intCast(a % b)), result.remainder);
    }
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
        try expect_matches(u320, shaped(u320, &prng), shaped(u256, &prng));
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

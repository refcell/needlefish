//! Fixed-capacity big-integer helpers for the MODEXP precompile.
//!
//! Numbers are little-endian slices of 64-bit limbs owned by the caller, so nothing here
//! allocates. `Padded` views a big-endian byte string that is logically right-padded with
//! zeros (the EVM precompile input rule) without materializing the padding.
//! `std.math.big` is used only as a test oracle.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const Limb = u64;
pub const limb_bits = 64;
pub const limb_bytes = 8;

comptime {
    assert(@bitSizeOf(Limb) == limb_bits);
    assert(limb_bytes * 8 == limb_bits);
}

/// A big-endian integer of `len` bytes whose last `len - data.len` bytes are zero.
pub const Padded = struct {
    data: []const u8,
    len: u64,

    pub fn from_slice(bytes: []const u8) Padded {
        return .{ .data = bytes, .len = bytes.len };
    }

    /// Byte at distance `from_end` from the least significant end; zero beyond the top.
    pub fn byte_at(padded: Padded, from_end: u64) u8 {
        if (from_end >= padded.len) return 0;
        const position = padded.len - 1 - from_end;
        return if (position < padded.data.len) padded.data[@intCast(position)] else 0;
    }

    /// The `index`-th 64-bit little-endian limb of the value.
    pub fn limb_at(padded: Padded, index: u64) Limb {
        assert(padded.data.len <= padded.len);
        var value: Limb = 0;
        var step: u64 = limb_bytes;
        const base = index *| limb_bytes;
        while (step > 0) {
            step -= 1;
            value = (value << 8) | padded.byte_at(base +| step);
        }
        return value;
    }

    pub fn bit(padded: Padded, index: u64) bool {
        const byte = padded.byte_at(index / 8);
        return (byte >> @as(u3, @intCast(index % 8))) & 1 == 1;
    }

    /// Position of the first non-zero byte, or null when the value is zero.
    fn first_nonzero(padded: Padded) ?u64 {
        assert(padded.data.len <= padded.len);
        for (padded.data, 0..) |byte, position| {
            if (byte != 0) return position;
        }
        return null;
    }

    pub fn bit_length(padded: Padded) u64 {
        const position = padded.first_nonzero() orelse return 0;
        const byte = padded.data[@intCast(position)];
        const bits_in_byte: u64 = 8 - @clz(byte);
        return (padded.len - position - 1) * 8 + bits_in_byte;
    }

    /// Number of limbs needed to hold the value (zero for zero).
    pub fn significant_limbs(padded: Padded) u64 {
        return (padded.bit_length() + limb_bits - 1) / limb_bits;
    }

    /// Writes limbs `0..out.len`; the value must fit.
    pub fn load_limbs(padded: Padded, out: []Limb) void {
        assert(padded.significant_limbs() <= out.len);
        for (out, 0..) |*limb, index| limb.* = padded.limb_at(index);
    }
};

pub fn trimmed_len(limbs: []const Limb) u32 {
    var length = limbs.len;
    while (length > 0 and limbs[length - 1] == 0) length -= 1;
    return @intCast(length);
}

pub fn bit_length_limbs(limbs: []const Limb) u32 {
    const length = trimmed_len(limbs);
    if (length == 0) return 0;
    return length * limb_bits - @clz(limbs[length - 1]);
}

pub fn is_zero(limbs: []const Limb) bool {
    return trimmed_len(limbs) == 0;
}

/// Compares two numbers of equal limb count.
pub fn compare(a: []const Limb, b: []const Limb) std.math.Order {
    assert(a.len == b.len);
    var index = a.len;
    while (index > 0) {
        index -= 1;
        if (a[index] != b[index]) return std.math.order(a[index], b[index]);
    }
    return .eq;
}

/// out = a + b over equal limb counts; returns the carry. `out` may alias an input.
pub fn add(out: []Limb, a: []const Limb, b: []const Limb) u1 {
    assert(out.len == a.len and a.len == b.len);
    var carry: u1 = 0;
    for (out, a, b) |*limb, x, y| {
        const first = @addWithOverflow(x, y);
        const second = @addWithOverflow(first[0], carry);
        limb.* = second[0];
        carry = first[1] | second[1];
    }
    return carry;
}

/// out += b where b has at most out.len limbs; returns the carry.
pub fn add_short(out: []Limb, b: []const Limb) u1 {
    assert(b.len <= out.len);
    var carry: u1 = 0;
    for (out, 0..) |*limb, index| {
        const y: Limb = if (index < b.len) b[index] else 0;
        const first = @addWithOverflow(limb.*, y);
        const second = @addWithOverflow(first[0], carry);
        limb.* = second[0];
        carry = first[1] | second[1];
    }
    return carry;
}

/// out = a - b over equal limb counts; returns the borrow. `out` may alias an input.
pub fn sub(out: []Limb, a: []const Limb, b: []const Limb) u1 {
    assert(out.len == a.len and a.len == b.len);
    var borrow: u1 = 0;
    for (out, a, b) |*limb, x, y| {
        const first = @subWithOverflow(x, y);
        const second = @subWithOverflow(first[0], borrow);
        limb.* = second[0];
        borrow = first[1] | second[1];
    }
    return borrow;
}

/// out = a << shift for shift < 64; returns the bits shifted out. May alias.
pub fn shift_left_bits(out: []Limb, a: []const Limb, shift: u6) Limb {
    assert(out.len == a.len);
    if (shift == 0) {
        @memcpy(out, a);
        return 0;
    }
    const back: u6 = @intCast(limb_bits - @as(u7, shift));
    var index = a.len;
    var spill: Limb = 0;
    if (index > 0) spill = a[index - 1] >> back;
    while (index > 1) {
        index -= 1;
        out[index] = (a[index] << shift) | (a[index - 1] >> back);
    }
    if (index > 0) out[0] = a[0] << shift;
    return spill;
}

/// out = a >> shift_bits for any shift_bits; out.len == a.len. May alias.
pub fn shift_right_bits(out: []Limb, a: []const Limb, shift_bits: u32) void {
    assert(out.len == a.len);
    const whole: usize = shift_bits / limb_bits;
    const part: u6 = @intCast(shift_bits % limb_bits);
    for (0..out.len) |index| {
        const low: Limb = if (index + whole < a.len) a[index + whole] else 0;
        const high: Limb = if (index + whole + 1 < a.len) a[index + whole + 1] else 0;
        if (part == 0) {
            out[index] = low;
        } else {
            const back: u6 = @intCast(limb_bits - @as(u7, part));
            out[index] = (low >> part) | (high << back);
        }
    }
}

pub fn trailing_zero_bits(limbs: []const Limb) u32 {
    var total: u32 = 0;
    for (limbs) |limb| {
        if (limb != 0) return total + @ctz(limb);
        total += limb_bits;
    }
    return total;
}

/// out = low `out.len` limbs of a * b. `out` must not alias the inputs.
pub fn mul_low(out: []Limb, a: []const Limb, b: []const Limb) void {
    assert(out.ptr != a.ptr and out.ptr != b.ptr);
    @memset(out, 0);
    for (a, 0..) |x, i| {
        if (i >= out.len) break;
        var carry: Limb = 0;
        var j: usize = 0;
        while (j < b.len and i + j < out.len) : (j += 1) {
            const wide = @as(u128, x) * b[j] + out[i + j] + carry;
            out[i + j] = @truncate(wide);
            carry = @intCast(wide >> 64);
        }
        if (i + j < out.len) out[i + j] = carry;
    }
}

/// x with a * x == 1 (mod 2^64) for odd a (Newton iteration, 3 bits correct to start).
pub fn inverse_limb(a: Limb) Limb {
    assert(a & 1 == 1);
    var x = a;
    for (0..5) |_| x *%= 2 -% a *% x;
    assert(a *% x == 1);
    return x;
}

/// out = a^-1 mod 2^(64 * out.len) for odd a; `scratch` holds 2 * out.len limbs.
pub fn inverse_mod_pow2(out: []Limb, a: []const Limb, scratch: []Limb) void {
    const count = out.len;
    assert(count > 0 and a.len == count and a[0] & 1 == 1);
    assert(scratch.len >= 2 * count);
    @memset(out, 0);
    out[0] = inverse_limb(a[0]);
    const product = scratch[0..count];
    const next = scratch[count .. 2 * count];
    var precision: usize = 1;
    while (precision < count) : (precision *= 2) {
        mul_low(product, a, out); // 1 + 2^precision * junk
        // product = 2 - product
        var borrow: u1 = 0;
        for (product, 0..) |*limb, index| {
            const two: Limb = if (index == 0) 2 else 0;
            const first = @subWithOverflow(two, limb.*);
            const second = @subWithOverflow(first[0], borrow);
            limb.* = second[0];
            borrow = first[1] | second[1];
        }
        mul_low(next, out, product);
        @memcpy(out, next);
    }
    mul_low(product, a, out);
    assert(product[0] == 1);
}

/// -m0^-1 mod 2^64, the Montgomery constant for an odd modulus limb.
pub fn montgomery_constant(m0: Limb) Limb {
    return 0 -% inverse_limb(m0);
}

/// out = a * b * 2^(-64 n) mod m (CIOS) for odd m with n = m.len limbs, a, b < m.
/// `t` is scratch of n + 2 limbs. `out` may alias `a` or `b`.
pub fn montgomery_mul(
    out: []Limb,
    a: []const Limb,
    b: []const Limb,
    m: []const Limb,
    constant: Limb,
    t: []Limb,
) void {
    switch (m.len) {
        // Small moduli get a compile-time length so LLVM unrolls the loops.
        inline 1...specialized_limbs_max => |count| {
            montgomery_mul_n(count, out, a, b, m, constant, t);
        },
        else => montgomery_mul_n(m.len, out, a, b, m, constant, t),
    }
}

/// Moduli up to this many limbs (512 bits) use length-specialized code.
const specialized_limbs_max = 8;

inline fn montgomery_mul_n(
    n: usize,
    out: []Limb,
    a: []const Limb,
    b: []const Limb,
    m: []const Limb,
    constant: Limb,
    t: []Limb,
) void {
    assert(n > 0 and m.len == n and a.len == n and b.len == n and out.len == n and t.len >= n + 2);
    assert(m[0] & 1 == 1);
    const acc = t[0 .. n + 2];
    @memset(acc, 0);
    for (b) |bi| {
        var carry: Limb = 0;
        for (0..n) |j| {
            const wide = @as(u128, a[j]) * bi + acc[j] + carry;
            acc[j] = @truncate(wide);
            carry = @intCast(wide >> 64);
        }
        const top = @as(u128, acc[n]) + carry;
        acc[n] = @truncate(top);
        acc[n + 1] = @intCast(top >> 64);
        const q = acc[0] *% constant;
        var wide = @as(u128, q) * m[0] + acc[0];
        carry = @intCast(wide >> 64);
        for (1..n) |j| {
            wide = @as(u128, q) * m[j] + acc[j] + carry;
            acc[j - 1] = @truncate(wide);
            carry = @intCast(wide >> 64);
        }
        const high = @as(u128, acc[n]) + carry;
        acc[n - 1] = @truncate(high);
        acc[n] = acc[n + 1] + @as(Limb, @intCast(high >> 64));
    }
    if (acc[n] != 0 or compare(acc[0..n], m) != .lt) {
        _ = sub(out, acc[0..n], m);
    } else {
        @memcpy(out, acc[0..n]);
    }
}

/// out = a * a * 2^(-64 n) mod m for odd m, a < m: a dedicated square (half the products of
/// `montgomery_mul`) followed by word-by-word Montgomery reduction. `t` holds 2 * n limbs.
/// `out` may alias `a`.
pub fn montgomery_sqr(
    out: []Limb,
    a: []const Limb,
    m: []const Limb,
    constant: Limb,
    t: []Limb,
) void {
    switch (m.len) {
        inline 1...specialized_limbs_max => |count| montgomery_sqr_n(count, out, a, m, constant, t),
        else => montgomery_sqr_n(m.len, out, a, m, constant, t),
    }
}

inline fn montgomery_sqr_n(
    n: usize,
    out: []Limb,
    a: []const Limb,
    m: []const Limb,
    constant: Limb,
    t: []Limb,
) void {
    assert(n > 0 and m.len == n and a.len == n and out.len == n and t.len >= 2 * n);
    assert(m[0] & 1 == 1);
    const w = t[0 .. 2 * n];
    @memset(w, 0);
    for (0..n - 1) |i| { // off-diagonal products a[i] * a[j], j > i
        var carry: Limb = 0;
        for (i + 1..n) |j| {
            const wide = @as(u128, a[i]) * a[j] + w[i + j] + carry;
            w[i + j] = @truncate(wide);
            carry = @intCast(wide >> 64);
        }
        w[i + n] = carry;
    }
    assert(shift_left_bits(w, w, 1) == 0);
    var carry: Limb = 0;
    for (0..n) |i| { // diagonal a[i]^2
        const square = @as(u128, a[i]) * a[i];
        const low = @as(u128, w[2 * i]) + @as(Limb, @truncate(square)) + carry;
        w[2 * i] = @truncate(low);
        const high = @as(u128, w[2 * i + 1]) + @as(Limb, @intCast(square >> 64)) + (low >> 64);
        w[2 * i + 1] = @truncate(high);
        carry = @intCast(high >> 64);
    }
    assert(carry == 0);
    var pending: Limb = 0; // carry into position i + n of the next row
    for (0..n) |i| {
        const q = w[i] *% constant;
        var row_carry: Limb = 0;
        for (0..n) |j| {
            const wide = @as(u128, q) * m[j] + w[i + j] + row_carry;
            w[i + j] = @truncate(wide);
            row_carry = @intCast(wide >> 64);
        }
        const top = @as(u128, w[i + n]) + row_carry + pending;
        w[i + n] = @truncate(top);
        pending = @intCast(top >> 64);
    }
    const result = w[n .. 2 * n];
    if (pending != 0 or compare(result, m) != .lt) {
        _ = sub(out, result, m);
    } else {
        @memcpy(out, result);
    }
}

/// One Knuth-D step: rem = (rem * 2^64 + w) mod dn, for dn normalized (top bit set),
/// rem < dn, n = dn.len >= 1. `u` is scratch of n + 1 limbs.
fn reduce_step(rem: []Limb, dn: []const Limb, w: Limb, u: []Limb) void {
    const n = dn.len;
    assert(n > 0 and rem.len == n and u.len >= n + 1);
    assert(dn[n - 1] >> 63 == 1);
    if (n == 1) {
        const numerator = (@as(u128, rem[0]) << 64) | w;
        rem[0] = @intCast(numerator % dn[0]);
        return;
    }
    u[0] = w;
    @memcpy(u[1 .. n + 1], rem);
    const d1: u128 = dn[n - 1];
    const d0: u128 = dn[n - 2];
    const numerator = (@as(u128, u[n]) << 64) | u[n - 1];
    var qhat: u128 = numerator / d1;
    var rhat: u128 = numerator % d1;
    for (0..2) |_| {
        const too_big = qhat > std.math.maxInt(Limb) or qhat * d0 > ((rhat << 64) | u[n - 2]);
        if (!too_big) break;
        qhat -= 1;
        rhat += d1;
        if (rhat > std.math.maxInt(Limb)) break;
    }
    assert(qhat <= std.math.maxInt(Limb));
    if (multiply_subtract(u[0 .. n + 1], dn, @intCast(qhat))) {
        _ = add(u[0..n], u[0..n], dn);
    }
    @memcpy(rem, u[0..n]);
}

/// u -= q * dn (u has dn.len + 1 limbs); returns true when the result went negative.
fn multiply_subtract(u: []Limb, dn: []const Limb, q: Limb) bool {
    const n = dn.len;
    assert(u.len == n + 1);
    var borrow: u64 = 0;
    var carry: Limb = 0;
    for (0..n) |j| {
        const product = @as(u128, q) * dn[j] + carry;
        carry = @intCast(product >> 64);
        const first = @subWithOverflow(u[j], @as(Limb, @truncate(product)));
        const second = @subWithOverflow(first[0], borrow);
        u[j] = second[0];
        borrow = @as(u64, first[1]) + second[1];
    }
    const first = @subWithOverflow(u[n], carry);
    const second = @subWithOverflow(first[0], borrow);
    u[n] = second[0];
    return (@as(u64, first[1]) + second[1]) != 0;
}

/// The i-th limb of (value << shift), counted from the least significant end.
fn shifted_limb(value: Padded, index: u64, shift: u6) Limb {
    const high = value.limb_at(index) << shift;
    if (shift == 0 or index == 0) return high;
    const back: u6 = @intCast(limb_bits - @as(u7, shift));
    return high | (value.limb_at(index - 1) >> back);
}

/// out = (value * 2^(64 * zero_limbs)) mod m for m with n = m.len limbs (top limb non-zero),
/// streaming the value one limb at a time so `value` may be arbitrarily long.
/// `scratch` holds 2 * n + 1 limbs. Zero limbs convert into Montgomery form without R^2.
pub fn reduce_shifted(
    out: []Limb,
    m: []const Limb,
    value: Padded,
    zero_limbs: u32,
    scratch: []Limb,
) void {
    const n = m.len;
    assert(n > 0 and m[n - 1] != 0 and out.len == n and scratch.len >= 2 * n + 1);
    const shift: u6 = @intCast(@clz(m[n - 1]));
    const dn = scratch[0..n];
    assert(shift_left_bits(dn, m, shift) == 0);
    const u = scratch[n .. 2 * n + 1];
    @memset(out, 0);
    // The shifted stream has one more limb than the value: index count..0.
    var index = value.significant_limbs() + 1;
    while (index > 0) {
        index -= 1;
        reduce_step(out, dn, shifted_limb(value, index, shift), u);
    }
    for (0..zero_limbs) |_| reduce_step(out, dn, 0, u);
    shift_right_bits(out, out, shift);
    assert(compare(out, m) == .lt);
}

/// Writes the value right-aligned into `out`, zero filling; the value must fit.
pub fn to_be_bytes(out: []u8, limbs: []const Limb) void {
    @memset(out, 0);
    for (limbs, 0..) |limb, index| {
        for (0..limb_bytes) |byte_index| {
            const byte: u8 = @truncate(limb >> @as(u6, @intCast(byte_index * 8)));
            const distance = index * limb_bytes + byte_index;
            if (distance < out.len) {
                out[out.len - 1 - distance] = byte;
            } else {
                assert(byte == 0);
            }
        }
    }
}

/// A big integer with a compile-time capacity; `len` counts limbs in use (trimmed).
pub fn Fixed(comptime limbs_max: u32) type {
    return struct {
        const Self = @This();
        limbs: [limbs_max]Limb = @splat(0),
        len: u32 = 0,

        pub fn from_u64(value: u64) Self {
            var result: Self = .{};
            result.limbs[0] = value;
            result.len = trimmed_len(result.limbs[0..1]);
            return result;
        }

        pub fn from_be_bytes(bytes: []const u8) Self {
            const padded = Padded.from_slice(bytes);
            assert(padded.significant_limbs() <= limbs_max);
            var result: Self = .{};
            padded.load_limbs(&result.limbs);
            result.len = trimmed_len(&result.limbs);
            return result;
        }

        pub fn to_be_bytes(self: *const Self, out: []u8) void {
            to_be_bytes_free(out, self.limbs[0..self.len]);
        }

        pub fn bit_length(self: *const Self) u32 {
            return bit_length_limbs(self.limbs[0..self.len]);
        }

        pub fn order(self: *const Self, other: *const Self) std.math.Order {
            return compare(&self.limbs, &other.limbs);
        }

        pub fn plus(self: *const Self, other: *const Self) Self {
            var result: Self = .{};
            const carry = add(&result.limbs, &self.limbs, &other.limbs);
            assert(carry == 0);
            result.len = trimmed_len(&result.limbs);
            return result;
        }

        pub fn minus(self: *const Self, other: *const Self) Self {
            assert(self.order(other) != .lt);
            var result: Self = .{};
            const borrow = sub(&result.limbs, &self.limbs, &other.limbs);
            assert(borrow == 0);
            result.len = trimmed_len(&result.limbs);
            return result;
        }

        /// The product must fit the capacity.
        pub fn times(self: *const Self, other: *const Self) Self {
            assert(self.bit_length() + other.bit_length() <= limbs_max * limb_bits + 1);
            var result: Self = .{};
            mul_low(&result.limbs, self.limbs[0..self.len], other.limbs[0..other.len]);
            result.len = trimmed_len(&result.limbs);
            return result;
        }
    };
}

const to_be_bytes_free = to_be_bytes;

// ---------------------------------------------------------------- tests

const testing = std.testing;
const big = std.math.big.int;

fn managed_from_bytes(allocator: std.mem.Allocator, bytes: []const u8) !big.Managed {
    var value = try big.Managed.init(allocator);
    errdefer value.deinit();
    var hex = try allocator.alloc(u8, bytes.len * 2 + 1);
    defer allocator.free(hex);
    hex[0] = '0';
    for (bytes, 0..) |byte, index| {
        hex[1 + index * 2] = "0123456789abcdef"[byte >> 4];
        hex[2 + index * 2] = "0123456789abcdef"[byte & 15];
    }
    try value.setString(16, hex);
    return value;
}

fn managed_to_bytes(value: *const big.Managed, out: []u8) void {
    @memset(out, 0);
    const bits = value.bitCountAbs();
    assert((bits + 7) / 8 <= out.len);
    value.toConst().writeTwosComplement(out, .big);
}

test "bigint: padded view implements right padding and leading zeros" {
    const padded = Padded{ .data = &.{ 0x01, 0x02 }, .len = 4 };
    try testing.expectEqual(@as(u64, 0x0102_0000), padded.limb_at(0));
    try testing.expectEqual(@as(u64, 0), padded.limb_at(1));
    try testing.expectEqual(@as(u64, 25), padded.bit_length());
    try testing.expect(padded.bit(24));
    try testing.expect(!padded.bit(23));
    const zero = Padded{ .data = &.{ 0, 0 }, .len = 9 };
    try testing.expectEqual(@as(u64, 0), zero.bit_length());
    try testing.expectEqual(@as(u64, 0), Padded.from_slice(&.{}).bit_length());
    const wide = Padded.from_slice(&[_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 5 });
    try testing.expectEqual(@as(u64, 73), wide.bit_length());
    try testing.expectEqual(@as(u64, 5), wide.limb_at(0));
    try testing.expectEqual(@as(u64, 0x100), wide.limb_at(1));
}

test "bigint: fixed add, sub, mul, shifts against std big ints" {
    var prng = Prng.init(0xb161);
    const F = Fixed(8);
    for (0..200) |_| {
        var a_bytes: [40]u8 = undefined;
        var b_bytes: [40]u8 = undefined;
        prng.fill(&a_bytes);
        prng.fill(&b_bytes);
        const a_len: usize = @intCast(prng.below(41));
        const b_len: usize = @intCast(prng.below(41));
        const a = F.from_be_bytes(a_bytes[0..a_len]);
        const b = F.from_be_bytes(b_bytes[0..b_len]);

        var ma = try managed_from_bytes(testing.allocator, a_bytes[0..a_len]);
        defer ma.deinit();
        var mb = try managed_from_bytes(testing.allocator, b_bytes[0..b_len]);
        defer mb.deinit();
        var expected = try big.Managed.init(testing.allocator);
        defer expected.deinit();
        var out: [64]u8 = undefined;
        var want: [64]u8 = undefined;

        try expected.mul(&ma, &mb);
        if (a.bit_length() + b.bit_length() <= 512) {
            a.times(&b).to_be_bytes(&out);
            managed_to_bytes(&expected, &want);
            try testing.expectEqualSlices(u8, &want, &out);
        }
        if (a.order(&b) != .lt) {
            try expected.sub(&ma, &mb);
            a.minus(&b).to_be_bytes(&out);
            managed_to_bytes(&expected, &want);
            try testing.expectEqualSlices(u8, &want, &out);
        }
        if (a.bit_length() < 511 and b.bit_length() < 511) {
            try expected.add(&ma, &mb);
            a.plus(&b).to_be_bytes(&out);
            managed_to_bytes(&expected, &want);
            try testing.expectEqualSlices(u8, &want, &out);
        }
    }
}

test "bigint: shifts, inverse, trailing zeros" {
    var limbs = [_]Limb{ 0x8000_0000_0000_0001, 0x1, 0 };
    var shifted: [3]Limb = undefined;
    try testing.expectEqual(@as(Limb, 0), shift_left_bits(&shifted, &limbs, 4));
    try testing.expectEqual(@as(Limb, 0x10), shifted[0]);
    try testing.expectEqual(@as(Limb, 0x18), shifted[1]);
    shift_right_bits(&shifted, &limbs, 65);
    try testing.expectEqual(@as(Limb, 0), shifted[0]);
    shift_right_bits(&shifted, &limbs, 1);
    try testing.expectEqual(@as(Limb, 0xc000_0000_0000_0000), shifted[0]);
    try testing.expectEqual(@as(u32, 0), trailing_zero_bits(&limbs));
    try testing.expectEqual(@as(u32, 128), trailing_zero_bits(&[_]Limb{ 0, 0, 4 }) - 2);

    var prng = Prng.init(77);
    for (0..100) |_| {
        var odd: [5]Limb = undefined;
        for (&odd) |*limb| limb.* = prng.int(u64);
        odd[0] |= 1;
        var inverse: [5]Limb = undefined;
        var scratch: [10]Limb = undefined;
        inverse_mod_pow2(&inverse, &odd, &scratch);
        var product: [5]Limb = undefined;
        mul_low(&product, &odd, &inverse);
        try testing.expectEqual(@as(Limb, 1), product[0]);
        try testing.expect(is_zero(product[1..]));
    }
}

test "bigint: reduce_shifted and montgomery_mul match std big ints" {
    var prng = Prng.init(0x4d6f6e74);
    for (0..300) |_| {
        const n: usize = @intCast(prng.range(1, 6));
        var m: [6]Limb = @splat(0);
        for (m[0..n]) |*limb| limb.* = prng.int(u64);
        if (prng.chance(1, 4)) m[n - 1] >>= @intCast(prng.below(64));
        if (m[n - 1] == 0) m[n - 1] = 1;
        var value_bytes: [64]u8 = undefined;
        prng.fill(&value_bytes);
        const value_len: usize = @intCast(prng.below(65));
        const zero_limbs: u32 = @intCast(prng.below(4));
        var out: [6]Limb = undefined;
        var scratch: [13]Limb = undefined;
        const value = Padded.from_slice(value_bytes[0..value_len]);
        reduce_shifted(out[0..n], m[0..n], value, zero_limbs, &scratch);

        var m_bytes: [48]u8 = undefined;
        to_be_bytes(&m_bytes, m[0..n]);
        var mm = try managed_from_bytes(testing.allocator, &m_bytes);
        defer mm.deinit();
        var v = try managed_from_bytes(testing.allocator, value_bytes[0..value_len]);
        defer v.deinit();
        var shifted = try big.Managed.init(testing.allocator);
        defer shifted.deinit();
        try shifted.shiftLeft(&v, zero_limbs * 64);
        var q = try big.Managed.init(testing.allocator);
        defer q.deinit();
        var r = try big.Managed.init(testing.allocator);
        defer r.deinit();
        try q.divFloor(&r, &shifted, &mm);
        var got: [48]u8 = undefined;
        var want: [48]u8 = undefined;
        to_be_bytes(&got, out[0..n]);
        managed_to_bytes(&r, &want);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "bigint: montgomery_sqr equals montgomery_mul(a, a)" {
    var prng = Prng.init(0x73717572);
    for (0..500) |_| {
        const n: usize = @intCast(prng.range(1, 9));
        var m: [9]Limb = undefined;
        for (m[0..n]) |*limb| limb.* = prng.int(u64);
        m[0] |= 1;
        if (prng.chance(1, 4)) m[n - 1] = std.math.maxInt(Limb);
        if (m[n - 1] == 0) m[n - 1] = 1;
        if (n == 1 and m[0] == 1) continue;
        var a: [9]Limb = undefined;
        for (a[0..n]) |*limb| limb.* = prng.int(u64);
        if (prng.chance(1, 4)) @memset(a[0..n], std.math.maxInt(Limb));
        // Reduce a below m by clearing the top limb until smaller.
        while (compare(a[0..n], m[0..n]) != .lt) a[n - 1] >>= 1;
        const constant = montgomery_constant(m[0]);
        var scratch: [20]Limb = undefined;
        var by_mul: [9]Limb = undefined;
        var by_sqr: [9]Limb = undefined;
        montgomery_mul(by_mul[0..n], a[0..n], a[0..n], m[0..n], constant, &scratch);
        montgomery_sqr(by_sqr[0..n], a[0..n], m[0..n], constant, &scratch);
        try testing.expectEqualSlices(Limb, by_mul[0..n], by_sqr[0..n]);
    }
}

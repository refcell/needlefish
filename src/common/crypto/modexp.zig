//! Modular exponentiation for the MODEXP precompile (0x05): EIP-198 arithmetic, EIP-2565
//! and EIP-7883 pricing helpers, EIP-7823 input bounds.
//!
//! Odd moduli use Montgomery multiplication (CIOS on runtime-length limbs) with a sliding
//! window. An even modulus m = 2^k * q (q odd) is solved as b^e mod q (Montgomery) and
//! b^e mod 2^k (truncated products), then joined with the Chinese remainder theorem.
//! Nothing allocates: scratch lives on the stack, sized by `limbs_max`.
//!
//! Decision: only the modulus is capacity bound (`operand_bytes_max` = 1024 bytes, the
//! EIP-7823 limit). The base streams through `bigint.reduce_shifted` and the exponent is
//! scanned bit by bit, so both may be any length; pre-Osaka callers whose modulus exceeds
//! the capacity get `error.ModulusTooLarge` from `modexp_checked` and must handle it.
//! Gas is pure arithmetic here (`gas_cost`); the evm lane owns charging it.
//! `std.math.big` is used only as a test oracle.

const std = @import("std");
const assert = std.debug.assert;
const bigint = @import("bigint.zig");
const hex = @import("../primitives/hex.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Limb = bigint.Limb;
const Padded = bigint.Padded;

/// EIP-7823: every operand length is at most 1024 bytes from Osaka.
pub const eip7823_input_size_limit = 1024;
pub const header_bytes = 96;
pub const operand_bytes_max = eip7823_input_size_limit;
pub const limbs_max = operand_bytes_max / bigint.limb_bytes;

/// Odd powers base^1, base^3, ..., base^(2^window_bits_max - 1) precomputed for the window.
const window_bits_max = 5;
const table_entries = 1 << (window_bits_max - 1);

comptime {
    assert(limbs_max == 128);
    assert(table_entries == 16);
}

// ---------------------------------------------------------------- gas helpers

pub const Rules = enum { byzantium, berlin, osaka };

/// EIP-198 ADJUSTED_EXPONENT_LENGTH: `multiplier` per exponent byte beyond 32 (8, or 16 with
/// EIP-7883) plus the bit length of the first 32 exponent bytes minus one. May be zero.
pub fn adjusted_exponent_length(exponent_len: u64, exponent_head: u256, multiplier: u64) u64 {
    const head_bits: u64 = 256 - @clz(exponent_head);
    if (exponent_len <= 32) return if (head_bits == 0) 0 else head_bits - 1;
    const extra = multiplier *| (exponent_len - 32);
    return extra +| (@max(head_bits, 1) - 1);
}

pub fn exponent_multiplier(rules: Rules) u64 {
    return switch (rules) {
        .byzantium, .berlin => 8,
        .osaka => 16,
    };
}

/// The iteration count of the gas formula: the adjusted exponent length, at least 1.
pub fn iteration_count(rules: Rules, exponent_len: u64, exponent_head: u256) u64 {
    const multiplier = exponent_multiplier(rules);
    const adjusted = adjusted_exponent_length(exponent_len, exponent_head, multiplier);
    return @max(adjusted, 1);
}

/// The rules' multiplication complexity of the larger of base and modulus length.
pub fn multiplication_complexity(rules: Rules, max_len: u64) u256 {
    const x: u256 = max_len;
    switch (rules) {
        .byzantium => {
            if (max_len <= 64) return x * x;
            if (max_len <= 1024) return x * x / 4 + 96 * x - 3072;
            return x * x / 16 + 480 * x - 199_680;
        },
        .berlin => {
            const words: u256 = (x + 7) / 8;
            return words * words;
        },
        .osaka => {
            if (max_len <= 32) return 16;
            const words: u256 = (x + 7) / 8;
            return 2 * words * words;
        },
    }
}

/// Gas price of one call, saturating at `maxInt(u64)`; mirrors revm's `*_gas_calc`.
pub fn gas_cost(
    rules: Rules,
    base_len: u64,
    exponent_len: u64,
    modulus_len: u64,
    exponent_head: u256,
) u64 {
    const min_price: u256, const divisor: u256 = switch (rules) {
        .byzantium => .{ 0, 20 },
        .berlin => .{ 200, 3 },
        .osaka => .{ 500, 1 },
    };
    const complexity = multiplication_complexity(rules, @max(base_len, modulus_len));
    const iterations = iteration_count(rules, exponent_len, exponent_head);
    // complexity < 2^128 and iterations < 2^64: the product cannot overflow 256 bits.
    const gas = complexity * iterations / divisor;
    assert(complexity < (1 << 128));
    return @intCast(@min(@max(min_price, gas), std.math.maxInt(u64)));
}

// ---------------------------------------------------------------- input parsing

pub const ParseError = error{LengthOverflow};

pub const Parsed = struct {
    base: Padded,
    exponent: Padded,
    modulus: Padded,
    /// The first min(exponent_len, 32) exponent bytes, zero padded, as an integer.
    exponent_head: u256,

    /// Gas price of this call under `rules` (see `gas_cost`).
    pub fn gas(parsed: Parsed, rules: Rules) u64 {
        const head = parsed.exponent_head;
        return gas_cost(rules, parsed.base.len, parsed.exponent.len, parsed.modulus.len, head);
    }

    /// EIP-7823: Err when any operand length exceeds 1024 bytes.
    pub fn check_osaka_limits(parsed: Parsed) error{InputTooLarge}!void {
        const limit = eip7823_input_size_limit;
        if (parsed.base.len > limit or parsed.exponent.len > limit or parsed.modulus.len > limit) {
            return error.InputTooLarge;
        }
    }
};

fn read_length(input: []const u8, offset: usize) u256 {
    var word: [32]u8 = @splat(0);
    if (offset < input.len) {
        const available = @min(32, input.len - offset);
        @memcpy(word[0..available], input[offset..][0..available]);
    }
    return std.mem.readInt(u256, &word, .big);
}

fn operand_at(input: []const u8, offset: u64, len: u64) Padded {
    const start: usize = @intCast(@min(offset, input.len));
    const available = @min(len, input.len - start);
    return .{ .data = input[start..][0..@intCast(available)], .len = len };
}

/// Parses `<base_len><exp_len><mod_len><base><exp><mod>` with the input right-padded by
/// zeros. Operands are views (`Padded`), so nothing is copied or allocated. Base and
/// modulus lengths beyond u64 are rejected; an exponent length beyond u64 saturates (its
/// gas cost saturates too, so the call can never be paid for).
pub fn precompile_modexp_parse(input: []const u8) ParseError!Parsed {
    const max_u64: u256 = std.math.maxInt(u64);
    const base_len = read_length(input, 0);
    const exponent_len = read_length(input, 32);
    const modulus_len = read_length(input, 64);
    if (base_len > max_u64 or modulus_len > max_u64) return error.LengthOverflow;
    const lengths: [3]u64 = .{
        @intCast(base_len),
        @intCast(@min(exponent_len, max_u64)),
        @intCast(modulus_len),
    };
    const base_offset: u64 = header_bytes;
    const exponent_offset = base_offset +| lengths[0];
    const modulus_offset = exponent_offset +| lengths[1];
    var parsed: Parsed = .{
        .base = operand_at(input, base_offset, lengths[0]),
        .exponent = operand_at(input, exponent_offset, lengths[1]),
        .modulus = operand_at(input, modulus_offset, lengths[2]),
        .exponent_head = 0,
    };
    const head_len = @min(parsed.exponent.len, 32);
    for (0..head_len) |position| {
        const data = parsed.exponent.data;
        const byte: u8 = if (position < data.len) data[position] else 0;
        parsed.exponent_head = (parsed.exponent_head << 8) | byte;
    }
    assert(parsed.exponent.data.len <= parsed.exponent.len);
    return parsed;
}

// ---------------------------------------------------------------- arithmetic

pub const Error = error{ModulusTooLarge};

fn window_for(exponent_bits: u64) u6 {
    if (exponent_bits > 239) return 5;
    if (exponent_bits > 79) return 4;
    if (exponent_bits > 23) return 3;
    return if (exponent_bits > 8) 2 else 1;
}

fn mask_top(limbs: []Limb, bits: u32) void {
    assert(bits > 0 and (bits + 63) / 64 == limbs.len);
    const used: u6 = @intCast(bits % 64);
    if (used != 0) limbs[limbs.len - 1] &= (@as(Limb, 1) << used) - 1;
}

pub fn Modexp(comptime capacity_limbs: u32) type {
    return struct {
        pub const capacity_bytes = capacity_limbs * bigint.limb_bytes;

        /// Writes (base ^ exponent) mod modulus, big endian, into `out` (`modulus.len` bytes).
        pub fn run(base: Padded, exponent: Padded, modulus: Padded, out: []u8) Error!void {
            assert(out.len == modulus.len);
            @memset(out, 0);
            const bits = modulus.bit_length();
            if (bits == 0) return; // modulus zero: result zero by EVM rule
            if (bits > capacity_limbs * 64) return error.ModulusTooLarge;
            const count: u32 = @intCast((bits + 63) / 64);
            var m_buffer: [capacity_limbs]Limb = undefined;
            const m = m_buffer[0..count];
            modulus.load_limbs(m);
            if (bits == 1) return; // modulus one: everything is zero
            var result: [capacity_limbs]Limb = undefined;
            const value = result[0..count];
            if (exponent.bit_length() == 0) {
                @memset(value, 0);
                value[0] = 1;
            } else if (m[0] & 1 == 1) {
                pow_odd(value, base, exponent, m);
            } else {
                pow_even(value, base, exponent, m);
            }
            bigint.to_be_bytes(out, value);
        }

        /// out = base ^ exponent mod m for odd m > 1; exponent non-zero.
        fn pow_odd(out: []Limb, base: Padded, exponent: Padded, m: []const Limb) void {
            const n = m.len;
            assert(m[0] & 1 == 1 and (n > 1 or m[0] > 1));
            var reduce_scratch: [2 * capacity_limbs + 1]Limb = undefined;
            var t: [capacity_limbs + 2]Limb = undefined;
            var table: [table_entries][capacity_limbs]Limb = undefined;
            const constant = bigint.montgomery_constant(m[0]);
            // Montgomery form of the base: base * R mod m, R = 2^(64 n).
            bigint.reduce_shifted(table[0][0..n], m, base, @intCast(n), &reduce_scratch);
            const bits = exponent.bit_length();
            const window = window_for(bits);
            if (window > 1) {
                var squared: [capacity_limbs]Limb = undefined;
                const first = table[0][0..n];
                bigint.montgomery_mul(squared[0..n], first, first, m, constant, &t);
                for (1..(@as(usize, 1) << (window - 1))) |index| {
                    const previous = table[index - 1][0..n];
                    const entry = table[index][0..n];
                    bigint.montgomery_mul(entry, previous, squared[0..n], m, constant, &t);
                }
            }
            var accumulator: [capacity_limbs]Limb = undefined;
            const acc = accumulator[0..n];
            exponentiate(acc, &table, exponent, bits, window, m, constant, &t);
            // Leave Montgomery form: multiply by the plain integer 1.
            var one: [capacity_limbs]Limb = @splat(0);
            one[0] = 1;
            bigint.montgomery_mul(out, acc, one[0..n], m, constant, &t);
            assert(bigint.compare(out, m) == .lt);
        }

        /// Left-to-right sliding window over `bits` exponent bits (top bit set).
        fn exponentiate(
            acc: []Limb,
            table: *const [table_entries][capacity_limbs]Limb,
            exponent: Padded,
            bits: u64,
            window: u6,
            m: []const Limb,
            constant: Limb,
            t: []Limb,
        ) void {
            assert(bits > 0 and exponent.bit(bits - 1));
            const n = m.len;
            var started = false;
            var end = bits; // bits [0, end) remain; the loop runs at most `bits` times
            while (end > 0) {
                const top = end - 1;
                if (!exponent.bit(top)) {
                    assert(started);
                    bigint.montgomery_mul(acc, acc, acc, m, constant, t);
                    end -= 1;
                    continue;
                }
                var low: u64 = if (top + 1 >= window) top + 1 - window else 0;
                while (!exponent.bit(low)) low += 1;
                var value: usize = 0;
                var cursor = top + 1;
                while (cursor > low) {
                    cursor -= 1;
                    value = (value << 1) | @intFromBool(exponent.bit(cursor));
                }
                assert(value & 1 == 1 and value < (@as(usize, 1) << window));
                const entry = table[value >> 1][0..n];
                if (started) {
                    for (0..top - low + 1) |_| bigint.montgomery_mul(acc, acc, acc, m, constant, t);
                    bigint.montgomery_mul(acc, acc, entry, m, constant, t);
                } else {
                    @memcpy(acc, entry);
                    started = true;
                }
                end = low;
            }
            assert(started);
        }

        /// out = base ^ exponent mod 2^bits (square and multiply, truncated products).
        fn pow_power_of_two(out: []Limb, base: Padded, exponent: Padded, bits: u32) void {
            const count = out.len;
            assert(count == (bits + 63) / 64 and count <= capacity_limbs);
            var b_buffer: [capacity_limbs]Limb = undefined;
            var product: [capacity_limbs]Limb = undefined;
            const b = b_buffer[0..count];
            for (b, 0..) |*limb, index| limb.* = base.limb_at(index);
            mask_top(b, bits);
            @memset(out, 0);
            out[0] = 1;
            mask_top(out, bits);
            var cursor = exponent.bit_length();
            while (cursor > 0) {
                cursor -= 1;
                bigint.mul_low(product[0..count], out, out);
                @memcpy(out, product[0..count]);
                if (exponent.bit(cursor)) {
                    bigint.mul_low(product[0..count], out, b);
                    @memcpy(out, product[0..count]);
                }
                mask_top(out, bits);
            }
        }

        /// out = base ^ exponent mod m for even m: m = 2^k * q, CRT over q and 2^k.
        fn pow_even(out: []Limb, base: Padded, exponent: Padded, m: []const Limb) void {
            const k = bigint.trailing_zero_bits(m);
            assert(k >= 1 and out.len == m.len);
            var q_buffer: [capacity_limbs]Limb = undefined;
            bigint.shift_right_bits(q_buffer[0..m.len], m, k);
            const q = q_buffer[0..bigint.trimmed_len(q_buffer[0..m.len])];
            const k_limbs = (k + 63) / 64;
            var x2_buffer: [capacity_limbs]Limb = undefined;
            const x2 = x2_buffer[0..k_limbs];
            pow_power_of_two(x2, base, exponent, k);
            if (q.len == 1 and q[0] == 1) { // m = 2^k
                @memset(out, 0);
                @memcpy(out[0..k_limbs], x2);
                return;
            }
            var x1_buffer: [capacity_limbs]Limb = undefined;
            const x1 = x1_buffer[0..q.len];
            pow_odd(x1, base, exponent, q);
            combine(out, x1, x2, q, k);
        }

        /// out = x1 + q * ((x2 - x1) * q^-1 mod 2^k): the value mod q * 2^k congruent to
        /// x1 mod q and x2 mod 2^k.
        fn combine(out: []Limb, x1: []const Limb, x2: []const Limb, q: []const Limb, k: u32) void {
            const k_limbs = x2.len;
            var inverse_input: [capacity_limbs]Limb = @splat(0);
            for (inverse_input[0..k_limbs], 0..) |*limb, index| {
                limb.* = if (index < q.len) q[index] else 0;
            }
            var inverse: [capacity_limbs]Limb = undefined;
            var scratch: [2 * capacity_limbs]Limb = undefined;
            bigint.inverse_mod_pow2(inverse[0..k_limbs], inverse_input[0..k_limbs], &scratch);
            var difference: [capacity_limbs]Limb = undefined;
            var x1_low: [capacity_limbs]Limb = @splat(0);
            for (x1_low[0..k_limbs], 0..) |*limb, index| {
                limb.* = if (index < x1.len) x1[index] else 0;
            }
            _ = bigint.sub(difference[0..k_limbs], x2, x1_low[0..k_limbs]);
            mask_top(difference[0..k_limbs], k);
            var t_buffer: [capacity_limbs]Limb = undefined;
            const t = t_buffer[0..k_limbs];
            bigint.mul_low(t, difference[0..k_limbs], inverse[0..k_limbs]);
            mask_top(t, k);
            bigint.mul_low(out, q, t);
            const carry = bigint.add_short(out, x1);
            assert(carry == 0);
        }
    };
}

pub const Default = Modexp(limbs_max);

/// (base ^ exponent) mod modulus into `out` (`modulus.len` bytes, big endian). A modulus of
/// zero gives all zeros. Returns `error.ModulusTooLarge` beyond `operand_bytes_max` bytes.
pub fn modexp_checked(
    base: []const u8,
    exponent: []const u8,
    modulus: []const u8,
    out: []u8,
) Error!void {
    assert(out.len == modulus.len);
    const operands: [3]Padded = .{
        Padded.from_slice(base),
        Padded.from_slice(exponent),
        Padded.from_slice(modulus),
    };
    return Default.run(operands[0], operands[1], operands[2], out);
}

/// As `modexp_checked` for callers that bounded the modulus (EIP-7823) beforehand.
pub fn modexp(base: []const u8, exponent: []const u8, modulus: []const u8, out: []u8) void {
    assert(modulus.len <= operand_bytes_max);
    modexp_checked(base, exponent, modulus, out) catch unreachable; // length asserted above
}

/// Runs the precompile on parsed operands; `out` is the output (`modulus.len` bytes).
pub fn precompile_modexp_run(parsed: Parsed, out: []u8) Error!void {
    assert(out.len == parsed.modulus.len);
    return Default.run(parsed.base, parsed.exponent, parsed.modulus, out);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const big = std.math.big.int;

fn oracle_bytes(allocator: std.mem.Allocator, bytes: []const u8) !big.Managed {
    var value = try big.Managed.init(allocator);
    errdefer value.deinit();
    const text = try allocator.alloc(u8, bytes.len * 2 + 1);
    defer allocator.free(text);
    text[0] = '0';
    for (bytes, 0..) |byte, index| {
        text[1 + index * 2] = "0123456789abcdef"[byte >> 4];
        text[2 + index * 2] = "0123456789abcdef"[byte & 15];
    }
    try value.setString(16, text);
    return value;
}

/// Simple reference: square and multiply with big-int division after every step.
fn oracle_modexp(
    allocator: std.mem.Allocator,
    base: []const u8,
    exponent: []const u8,
    modulus: []const u8,
    out: []u8,
) !void {
    @memset(out, 0);
    var m = try oracle_bytes(allocator, modulus);
    defer m.deinit();
    if (m.eqlZero()) return;
    var b = try oracle_bytes(allocator, base);
    defer b.deinit();
    var result = try big.Managed.initSet(allocator, 1);
    defer result.deinit();
    var quotient = try big.Managed.init(allocator);
    defer quotient.deinit();
    var remainder = try big.Managed.init(allocator);
    defer remainder.deinit();
    var product = try big.Managed.init(allocator);
    defer product.deinit();
    try quotient.divFloor(&remainder, &result, &m); // 1 mod m
    try result.copy(remainder.toConst());
    try quotient.divFloor(&remainder, &b, &m);
    try b.copy(remainder.toConst());
    for (exponent) |byte| {
        var bit: u4 = 8;
        while (bit > 0) {
            bit -= 1;
            try product.mul(&result, &result);
            try quotient.divFloor(&remainder, &product, &m);
            try result.copy(remainder.toConst());
            if ((byte >> @as(u3, @intCast(bit))) & 1 == 1) {
                try product.mul(&result, &b);
                try quotient.divFloor(&remainder, &product, &m);
                try result.copy(remainder.toConst());
            }
        }
    }
    result.toConst().writeTwosComplement(out, .big);
}

fn expect_matches_oracle(base: []const u8, exponent: []const u8, modulus: []const u8) !void {
    var got: [operand_bytes_max]u8 = undefined;
    var want: [operand_bytes_max]u8 = undefined;
    const out_got = got[0..modulus.len];
    const out_want = want[0..modulus.len];
    try oracle_modexp(testing.allocator, base, exponent, modulus, out_want);
    modexp(base, exponent, modulus, out_got);
    testing.expectEqualSlices(u8, out_want, out_got) catch |err| {
        std.debug.print("modexp mismatch: base={x} exp={x}\n", .{ base, exponent });
        std.debug.print("  mod={x}\n", .{modulus});
        return err;
    };
}

const Vector = struct {
    name: []const u8,
    input: []const u8,
    expected: []const u8,
    gas_berlin: u64,
    gas_byzantium: ?u64 = null,
    gas_osaka: ?u64 = null,
};

test "modexp: public geth vectors (EIP-198, EIP-2565, EIP-7883)" {
    const text = @embedFile("testdata/modexp_vectors.json");
    const parsed_json = try std.json.parseFromSlice([]const Vector, testing.allocator, text, .{});
    defer parsed_json.deinit();
    try testing.expect(parsed_json.value.len >= 20);
    for (parsed_json.value) |vector| {
        var input_buffer: [4096]u8 = undefined;
        const input = try hex.decode_into(&input_buffer, vector.input);
        var expected_buffer: [4096]u8 = undefined;
        const expected = try hex.decode_into(&expected_buffer, vector.expected);
        const parsed = try precompile_modexp_parse(input);
        var out: [operand_bytes_max]u8 = undefined;
        const output = out[0..@intCast(parsed.modulus.len)];
        try precompile_modexp_run(parsed, output);
        testing.expectEqualSlices(u8, expected, output) catch |err| {
            std.debug.print("vector {s}\n", .{vector.name});
            return err;
        };
        try testing.expectEqual(vector.gas_berlin, parsed.gas(.berlin));
        if (vector.gas_byzantium) |gas| {
            try testing.expectEqual(gas, parsed.gas(.byzantium));
        }
        if (vector.gas_osaka) |gas| {
            try testing.expectEqual(gas, parsed.gas(.osaka));
        }
    }
}

test "modexp: edge cases" {
    var out: [4]u8 = undefined;
    // exponent zero: 1 mod m, including even moduli; m = 1 gives zero; m = 0 gives zero.
    modexp(&.{ 0, 0 }, &.{}, &.{ 0, 0, 0, 7 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1 }, &out);
    modexp(&.{5}, &.{ 0, 0 }, &.{ 0, 0, 0, 8 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1 }, &out);
    modexp(&.{5}, &.{ 0, 3 }, &.{ 0, 0, 0, 1 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &out);
    modexp(&.{5}, &.{3}, &.{ 0, 0, 0, 0 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &out);
    // 0^0 = 1; 0^1 = 0; leading zeros everywhere.
    modexp(&.{}, &.{}, &.{ 0, 0, 1, 0 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1 }, &out);
    modexp(&.{0}, &.{ 0, 0, 1 }, &.{ 0, 0, 1, 0 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &out);
    // 3^4 mod 10 = 1; 2^10 mod 1000 = 24 (even, not a power of two).
    modexp(&.{3}, &.{4}, &.{10}, out[0..1]);
    try testing.expectEqual(@as(u8, 1), out[0]);
    modexp(&.{2}, &.{10}, &.{ 0x03, 0xe8 }, out[0..2]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 24 }, out[0..2]);
    // empty modulus writes nothing.
    modexp(&.{1}, &.{1}, &.{}, out[0..0]);
}

test "modexp: modulus beyond capacity is a handled error" {
    var modulus: [operand_bytes_max + 1]u8 = @splat(0);
    modulus[0] = 1;
    var out: [operand_bytes_max + 1]u8 = undefined;
    try testing.expectError(error.ModulusTooLarge, modexp_checked(&.{2}, &.{3}, &modulus, &out));
    modulus[0] = 0; // leading zero byte: the value fits
    modulus[operand_bytes_max] = 11;
    try modexp_checked(&.{2}, &.{3}, &modulus, &out);
    try testing.expectEqual(@as(u8, 8), out[operand_bytes_max]);
}

test "modexp: header parsing pads, bounds, and rejects overflow" {
    var input: [96 + 3]u8 = @splat(0);
    input[31] = 2; // base_len
    input[63] = 1; // exp_len
    input[95] = 3; // mod_len
    input[96] = 0xab; // base: ab 00 (second byte padded)
    const parsed = try precompile_modexp_parse(input[0..97]);
    try testing.expectEqual(@as(u64, 2), parsed.base.len);
    try testing.expectEqual(@as(usize, 1), parsed.base.data.len);
    try testing.expectEqual(@as(u64, 1), parsed.exponent.len);
    try testing.expectEqual(@as(usize, 0), parsed.exponent.data.len);
    try testing.expectEqual(@as(u256, 0), parsed.exponent_head);
    try parsed.check_osaka_limits();

    // empty input is all zero lengths.
    const empty = try precompile_modexp_parse(&.{});
    try testing.expectEqual(@as(u64, 0), empty.modulus.len);

    var huge: [96]u8 = @splat(0);
    huge[0] = 1; // base_len >= 2^248
    try testing.expectError(error.LengthOverflow, precompile_modexp_parse(&huge));
    huge[0] = 0;
    huge[64] = 0x80; // mod_len huge
    try testing.expectError(error.LengthOverflow, precompile_modexp_parse(&huge));
    huge[64] = 0;
    huge[32] = 0xff; // exp_len huge saturates
    const saturated = try precompile_modexp_parse(&huge);
    try testing.expectEqual(std.math.maxInt(u64), saturated.exponent.len);
    try testing.expectError(error.InputTooLarge, saturated.check_osaka_limits());
    try testing.expectEqual(
        std.math.maxInt(u64),
        saturated.gas(.osaka),
    );
}

test "modexp: adjusted exponent length and gas floors" {
    try testing.expectEqual(@as(u64, 0), adjusted_exponent_length(32, 0, 8));
    try testing.expectEqual(@as(u64, 0), adjusted_exponent_length(1, 1, 8));
    try testing.expectEqual(@as(u64, 7), adjusted_exponent_length(1, 0xff, 8));
    try testing.expectEqual(@as(u64, 8 * 8), adjusted_exponent_length(40, 0, 8));
    const all_ones = std.math.maxInt(u256);
    try testing.expectEqual(@as(u64, 16 * 8 + 255), adjusted_exponent_length(40, all_ones, 16));
    try testing.expectEqual(@as(u64, 1), iteration_count(.berlin, 0, 0));
    try testing.expectEqual(@as(u64, 200), gas_cost(.berlin, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 500), gas_cost(.osaka, 1, 1, 1, 1));
    try testing.expectEqual(@as(u64, 0), gas_cost(.byzantium, 0, 0, 0, 0));
}

fn random_operand(prng: *Prng, buffer: []u8, length: usize) []u8 {
    const operand = buffer[0..length];
    switch (prng.below(6)) {
        0 => @memset(operand, 0),
        1 => @memset(operand, 0xff),
        else => prng.fill(operand),
    }
    if (length > 0 and prng.chance(1, 3)) {
        const zeros: usize = @intCast(prng.below(length + 1));
        @memset(operand[0..zeros], 0);
    }
    return operand;
}

fn random_modulus(prng: *Prng, modulus: []u8) void {
    switch (prng.below(8)) {
        0 => { // small odd modulus in a wide field
            @memset(modulus, 0);
            if (modulus.len > 0) modulus[modulus.len - 1] = @intCast(prng.below(256) | 1);
        },
        1 => { // random high part, odd byte shifted by 0..7, then zero bytes
            @memset(modulus, 0);
            if (modulus.len > 0) {
                const zeros: usize = @intCast(prng.below(modulus.len));
                const split = modulus.len - 1 - zeros;
                prng.fill(modulus[0..split]);
                const odd: u8 = @intCast(prng.below(256) | 1);
                modulus[split] = odd << @as(u3, @intCast(prng.below(8)));
            }
        },
        2 => { // 2^k exactly (or zero when there is no room)
            @memset(modulus, 0);
            if (modulus.len > 0) {
                const position: usize = @intCast(prng.below(modulus.len));
                modulus[position] = @intCast(@as(u16, 1) << @intCast(prng.below(8)));
            }
        },
        3 => { // even
            prng.fill(modulus);
            if (modulus.len > 0) modulus[modulus.len - 1] &= 0xfe;
        },
        4 => { // many trailing zero bits
            prng.fill(modulus);
            const zeros: usize = @intCast(prng.below(modulus.len + 1));
            @memset(modulus[modulus.len - zeros ..], 0);
        },
        else => prng.fill(modulus),
    }
    if (modulus.len > 0 and prng.chance(1, 8)) modulus[0] = 0;
}

test "modexp: seeded differential fuzz vs big-int oracle" {
    var prng = Prng.init(0x6d6f64657870);
    var base_buffer: [160]u8 = undefined;
    var exponent_buffer: [48]u8 = undefined;
    var modulus_buffer: [160]u8 = undefined;
    for (0..400) |_| {
        const base_len: usize = @intCast(prng.below(161));
        const exponent_len: usize = @intCast(prng.below(if (prng.chance(1, 4)) 3 else 49));
        const modulus_len: usize = @intCast(prng.below(if (prng.chance(1, 2)) 17 else 161));
        const base = random_operand(&prng, &base_buffer, base_len);
        const exponent = random_operand(&prng, &exponent_buffer, exponent_len);
        const modulus = modulus_buffer[0..modulus_len];
        random_modulus(&prng, modulus);
        try expect_matches_oracle(base, exponent, modulus);
    }
}

test "modexp: full-size 1024-byte operands match the oracle" {
    var prng = Prng.init(0x31303234);
    var base: [operand_bytes_max]u8 = undefined;
    var modulus: [operand_bytes_max]u8 = undefined;
    prng.fill(&base);
    prng.fill(&modulus);
    modulus[0] |= 0x80;
    const exponent = [_]u8{ 0x01, 0x00, 0x01 };
    modulus[operand_bytes_max - 1] |= 1;
    try expect_matches_oracle(&base, &exponent, &modulus);
    modulus[operand_bytes_max - 1] &= 0xf0; // even: CRT with a 4-bit power of two
    try expect_matches_oracle(&base, &exponent, &modulus);
    @memset(modulus[operand_bytes_max - 100 ..], 0); // 800 trailing zero bits
    try expect_matches_oracle(&base, &exponent, &modulus);
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [512]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    const parsed = precompile_modexp_parse(input) catch return;
    parsed.check_osaka_limits() catch return;
    const gas = parsed.gas(.osaka);
    if (gas > 4_000_000) return; // would be out of gas: keep the fuzz fast
    var out: [operand_bytes_max]u8 = undefined;
    try precompile_modexp_run(parsed, out[0..@intCast(parsed.modulus.len)]);
}

test "modexp: coverage-guided fuzz never crashes" {
    try testing.fuzz({}, fuzz_one, .{});
}

test "modexp: seeded input fuzz never crashes and respects bounds" {
    var prng = Prng.init(0x696e707574);
    var input: [400]u8 = undefined;
    for (0..2000) |_| {
        const length: usize = @intCast(prng.below(input.len + 1));
        prng.fill(input[0..length]);
        if (length >= 96 and prng.chance(3, 4)) { // plausible small headers
            for (0..3) |field| {
                @memset(input[field * 32 ..][0..31], 0);
                input[field * 32 + 31] = @intCast(prng.below(40));
            }
        }
        var smith: testing.Smith = .{ .in = input[0..length] };
        try fuzz_one({}, &smith);
    }
}

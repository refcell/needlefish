//! Modular exponentiation for the MODEXP precompile (0x05): EIP-198 arithmetic, EIP-2565
//! and EIP-7883 pricing helpers, EIP-7823 input bounds.
//!
//! Odd moduli use Montgomery multiplication (CIOS on runtime-length limbs) with a sliding
//! window. An even modulus m = 2^k * q (q odd) is solved as b^e mod q (Montgomery) and
//! b^e mod 2^k (truncated products), then joined with the Chinese remainder theorem.
//! Nothing allocates: scratch lives on the stack (`Modexp(limbs_max)`, the Osaka bound) or in a
//! caller-provided `[]u64` (`precompile_modexp_run_with_scratch`, any modulus length).
//!
//! Decision: only the modulus is capacity bound (`operand_bytes_max` = 1024 bytes, the
//! EIP-7823 limit). The base streams through `bigint.reduce_shifted` and the exponent is
//! scanned bit by bit, so both may be any length; the static entry points return
//! `error.ModulusTooLarge` above the capacity and callers must handle it.
//! Pre-Osaka history has valid, affordable moduli above that bound, so the scratch entry
//! points run the same code over slices (`scratch_limbs_needed` sizes them).
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

/// Failures of the caller-provided-scratch entry points.
pub const ScratchError = error{ ModulusTooLarge, ScratchTooSmall };

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

/// Sanity cap on the modulus limb count (128 MiB): keeps every bit count inside u32. Gas for
/// such a modulus exceeds any block gas limit by many orders of magnitude.
const limbs_cap: u64 = 1 << 24;

/// Limbs of the shared temporary pool for an n-limb modulus: `pow_odd` is the largest user
/// (2n + 2 for products, 2^(window_bits_max - 1) table entries, squared, accumulator, one).
fn pool_limbs(n: u64) u64 {
    return (2 * n + 2) + table_entries * n + 3 * n;
}

/// Limbs of scratch `run_in` needs for an n-limb modulus: m, result, q, x1, x2 plus the pool.
fn workspace_limbs(n: u64) u64 {
    return 5 * n + pool_limbs(n);
}

/// u64 limbs of scratch that `precompile_modexp_run_with_scratch` needs for a modulus of
/// `modulus_len` bytes (the operand length from the input header, so it can be sized from
/// gas-bounded lengths before looking at the value). Saturates instead of overflowing.
pub fn scratch_limbs_needed(modulus_len: u64) u64 {
    const remainder = @intFromBool(modulus_len % bigint.limb_bytes != 0);
    const limbs = modulus_len / bigint.limb_bytes + remainder;
    assert(limbs <= modulus_len);
    return workspace_limbs(@min(limbs, std.math.maxInt(u64) / 32));
}

comptime {
    assert(workspace_limbs(1) == 26 + 2);
    assert(workspace_limbs(limbs_max) == 26 * limbs_max + 2);
}

/// Writes (base ^ exponent) mod modulus, big endian, into `out` (`modulus.len` bytes), using
/// `scratch` as the only working memory (no allocation, no recursion). The modulus needs
/// `workspace_limbs(significant limbs)` limbs of scratch; `ModulusTooLarge` is returned
/// above `capacity_bits` significant bits (or the sanity cap), `ScratchTooSmall` when
/// `scratch` is short. Every other input is valid, so no assert depends on operand values.
fn run_in(
    base: Padded,
    exponent: Padded,
    modulus: Padded,
    out: []u8,
    scratch: []Limb,
    capacity_bits: u64,
) ScratchError!void {
    assert(out.len == modulus.len);
    assert(capacity_bits <= limbs_cap * 64);
    @memset(out, 0);
    const bits = modulus.bit_length();
    if (bits == 0) return; // modulus zero: result zero by EVM rule
    if (bits > capacity_bits) return error.ModulusTooLarge;
    const n: usize = @intCast((bits + 63) / 64);
    if (scratch.len < workspace_limbs(n)) return error.ScratchTooSmall;
    const m = scratch[0..n];
    const value = scratch[n .. 2 * n];
    const pool = scratch[5 * n ..][0..pool_limbs(n)];
    modulus.load_limbs(m);
    if (bits == 1) return; // modulus one: everything is zero
    if (exponent.bit_length() == 0) {
        @memset(value, 0);
        value[0] = 1;
    } else if (m[0] & 1 == 1) {
        pow_odd(value, base, exponent, m, pool);
    } else {
        const parts = scratch[2 * n .. 5 * n]; // q, x1, x2
        pow_even(value, base, exponent, m, parts, pool);
    }
    bigint.to_be_bytes(out, value);
}

/// out = base ^ exponent mod m for odd m > 1; exponent non-zero. `pool` is `pool_limbs`.
fn pow_odd(out: []Limb, base: Padded, exponent: Padded, m: []const Limb, pool: []Limb) void {
    const n = m.len;
    assert(m[0] & 1 == 1 and (n > 1 or m[0] > 1));
    assert(out.len == n and pool.len >= pool_limbs(n));
    const t = pool[0 .. 2 * n + 2]; // also the reducer's 2n + 1 scratch before first use
    const table = pool[2 * n + 2 ..][0 .. table_entries * n]; // entry i at [i * n ..][0..n]
    const squared = pool[(2 + table_entries) * n + 2 ..][0..n];
    const acc = pool[(3 + table_entries) * n + 2 ..][0..n];
    const one = pool[(4 + table_entries) * n + 2 ..][0..n];
    const constant = bigint.montgomery_constant(m[0]);
    // Montgomery form of the base: base * R mod m, R = 2^(64 n).
    bigint.reduce_shifted(table[0..n], m, base, @intCast(n), t);
    const bits = exponent.bit_length();
    const window = window_for(bits);
    if (window > 1) {
        bigint.montgomery_sqr(squared, table[0..n], m, constant, t);
        for (1..(@as(usize, 1) << (window - 1))) |index| {
            const previous = table[(index - 1) * n ..][0..n];
            const entry = table[index * n ..][0..n];
            bigint.montgomery_mul(entry, previous, squared, m, constant, t);
        }
    }
    exponentiate(acc, table, exponent, bits, window, m, constant, t);
    // Leave Montgomery form: multiply by the plain integer 1.
    @memset(one, 0);
    one[0] = 1;
    bigint.montgomery_mul(out, acc, one, m, constant, t);
    assert(bigint.compare(out, m) == .lt);
}

/// Left-to-right sliding window over `bits` exponent bits (top bit set).
fn exponentiate(
    acc: []Limb,
    table: []const Limb,
    exponent: Padded,
    bits: u64,
    window: u6,
    m: []const Limb,
    constant: Limb,
    t: []Limb,
) void {
    assert(bits > 0 and exponent.bit(bits - 1));
    const n = m.len;
    assert(table.len == table_entries * n);
    var started = false;
    var end = bits; // bits [0, end) remain; the loop runs at most `bits` times
    while (end > 0) {
        const top = end - 1;
        if (!exponent.bit(top)) {
            assert(started);
            bigint.montgomery_sqr(acc, acc, m, constant, t);
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
        const entry = table[(value >> 1) * n ..][0..n];
        if (started) {
            for (0..top - low + 1) |_| bigint.montgomery_sqr(acc, acc, m, constant, t);
            bigint.montgomery_mul(acc, acc, entry, m, constant, t);
        } else {
            @memcpy(acc, entry);
            started = true;
        }
        end = low;
    }
    assert(started);
}

/// out = base ^ exponent mod 2^bits (square and multiply, truncated products). `pool`
/// supplies two `out.len`-limb temporaries.
fn pow_power_of_two(
    out: []Limb,
    base: Padded,
    exponent: Padded,
    bits: u32,
    pool: []Limb,
) void {
    const count = out.len;
    assert(count == (bits + 63) / 64 and pool.len >= 2 * count);
    const b = pool[0..count];
    const product = pool[count .. 2 * count];
    for (b, 0..) |*limb, index| limb.* = base.limb_at(index);
    mask_top(b, bits);
    @memset(out, 0);
    out[0] = 1;
    mask_top(out, bits);
    var cursor = exponent.bit_length();
    while (cursor > 0) {
        cursor -= 1;
        bigint.mul_low(product, out, out);
        @memcpy(out, product);
        if (exponent.bit(cursor)) {
            bigint.mul_low(product, out, b);
            @memcpy(out, product);
        }
        mask_top(out, bits);
    }
}

/// out = base ^ exponent mod m for even m: m = 2^k * q, CRT over q and 2^k. `parts` holds
/// q, x1, x2 (n limbs each); `pool` is `pool_limbs(n)`.
fn pow_even(
    out: []Limb,
    base: Padded,
    exponent: Padded,
    m: []const Limb,
    parts: []Limb,
    pool: []Limb,
) void {
    const n = m.len;
    const k = bigint.trailing_zero_bits(m);
    assert(k >= 1 and out.len == n and parts.len == 3 * n);
    const q_full = parts[0..n];
    bigint.shift_right_bits(q_full, m, k);
    const q = q_full[0..bigint.trimmed_len(q_full)];
    const k_limbs = (k + 63) / 64;
    assert(k_limbs <= n);
    const x2 = parts[2 * n ..][0..k_limbs];
    pow_power_of_two(x2, base, exponent, k, pool);
    if (q.len == 1 and q[0] == 1) { // m = 2^k
        @memset(out, 0);
        @memcpy(out[0..k_limbs], x2);
        return;
    }
    const x1 = parts[n..][0..q.len];
    pow_odd(x1, base, exponent, q, pool);
    combine(out, x1, x2, q, k, pool);
}

/// out = x1 + q * ((x2 - x1) * q^-1 mod 2^k): the value mod q * 2^k congruent to
/// x1 mod q and x2 mod 2^k. `pool` supplies 7 * x2.len limbs.
fn combine(
    out: []Limb,
    x1: []const Limb,
    x2: []const Limb,
    q: []const Limb,
    k: u32,
    pool: []Limb,
) void {
    const k_limbs = x2.len;
    assert(pool.len >= 7 * k_limbs and k_limbs > 0);
    const inverse_input = pool[0..k_limbs];
    const inverse = pool[k_limbs .. 2 * k_limbs];
    const scratch = pool[2 * k_limbs .. 4 * k_limbs];
    const difference = pool[4 * k_limbs .. 5 * k_limbs];
    const x1_low = pool[5 * k_limbs .. 6 * k_limbs];
    const t = pool[6 * k_limbs .. 7 * k_limbs];
    for (inverse_input, 0..) |*limb, index| {
        limb.* = if (index < q.len) q[index] else 0;
    }
    bigint.inverse_mod_pow2(inverse, inverse_input, scratch);
    for (x1_low, 0..) |*limb, index| {
        limb.* = if (index < x1.len) x1[index] else 0;
    }
    _ = bigint.sub(difference, x2, x1_low);
    mask_top(difference, k);
    bigint.mul_low(t, difference, inverse);
    mask_top(t, k);
    bigint.mul_low(out, q, t);
    const carry = bigint.add_short(out, x1);
    assert(carry == 0);
}

/// Static-capacity implementation: scratch lives on the stack, sized by `capacity_limbs`.
pub fn Modexp(comptime capacity_limbs: u32) type {
    comptime assert(capacity_limbs > 0 and capacity_limbs <= limbs_cap);
    return struct {
        pub const capacity_bytes = capacity_limbs * bigint.limb_bytes;

        /// Writes (base ^ exponent) mod modulus, big endian, into `out` (`modulus.len` bytes).
        pub fn run(base: Padded, exponent: Padded, modulus: Padded, out: []u8) Error!void {
            var buffer: [workspace_limbs(capacity_limbs)]Limb = undefined;
            const capacity_bits: u64 = capacity_limbs * 64;
            // The modulus is checked against the capacity first, so scratch always suffices.
            run_in(base, exponent, modulus, out, &buffer, capacity_bits) catch |err| {
                switch (err) {
                    error.ModulusTooLarge => return error.ModulusTooLarge,
                    error.ScratchTooSmall => unreachable, // buffer covers capacity_limbs
                }
            };
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

/// Runs the precompile on parsed operands with the static 1024-byte capacity (Osaka bound,
/// EIP-7823); `out` is the output (`modulus.len` bytes). Pre-Osaka calls whose modulus has
/// more than `operand_bytes_max` significant bytes return `error.ModulusTooLarge`: use
/// `precompile_modexp_run_with_scratch` for those. No assert is reachable from the operand
/// bytes; the caller only has to size `out` from `parsed.modulus.len`.
pub fn precompile_modexp_run(parsed: Parsed, out: []u8) Error!void {
    assert(out.len == parsed.modulus.len);
    return Default.run(parsed.base, parsed.exponent, parsed.modulus, out);
}

/// As `precompile_modexp_run` for any modulus length (pre-Osaka history), computing in the
/// caller-provided `scratch` instead of the stack. Size it with `scratch_limbs_needed(
/// parsed.modulus.len)` (gas bounds that length, so the EVM lane can size it from an arena or
/// at startup). Returns `error.ScratchTooSmall` when `scratch` is shorter than the
/// significant modulus needs, and `error.ModulusTooLarge` beyond the 128 MiB sanity cap.
pub fn precompile_modexp_run_with_scratch(
    parsed: Parsed,
    out: []u8,
    scratch: []Limb,
) ScratchError!void {
    assert(out.len == parsed.modulus.len);
    return run_in(parsed.base, parsed.exponent, parsed.modulus, out, scratch, limbs_cap * 64);
}

/// Slice form of `precompile_modexp_run_with_scratch`.
pub fn modexp_with_scratch(
    base: []const u8,
    exponent: []const u8,
    modulus: []const u8,
    out: []u8,
    scratch: []Limb,
) ScratchError!void {
    assert(out.len == modulus.len);
    const operands: [3]Padded = .{
        Padded.from_slice(base),
        Padded.from_slice(exponent),
        Padded.from_slice(modulus),
    };
    return run_in(operands[0], operands[1], operands[2], out, scratch, limbs_cap * 64);
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

/// Structured operands (lengths up to 96 bytes) checked against the big-int oracle; the
/// raw-input target above mostly stops at header parsing.
fn fuzz_operands(_: void, smith: *testing.Smith) anyerror!void {
    var base: [96]u8 = undefined;
    var exponent: [16]u8 = undefined;
    var modulus: [96]u8 = undefined;
    const base_len = smith.slice(&base);
    const exponent_len = smith.slice(&exponent);
    const modulus_len = smith.slice(&modulus);
    if (modulus_len == 0) return;
    try expect_matches_oracle(
        base[0..base_len],
        exponent[0..exponent_len],
        modulus[0..modulus_len],
    );
}

test "modexp: coverage-guided fuzz of operands vs big-int oracle" {
    try testing.fuzz({}, fuzz_operands, .{});
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

fn expect_scratch_matches_oracle(
    prng: *Prng,
    base: []const u8,
    exponent: []const u8,
    modulus: []const u8,
) !void {
    const allocator = testing.allocator;
    const got = try allocator.alloc(u8, modulus.len);
    defer allocator.free(got);
    const want = try allocator.alloc(u8, modulus.len);
    defer allocator.free(want);
    const scratch_len: usize = @intCast(scratch_limbs_needed(modulus.len));
    const scratch = try allocator.alloc(Limb, scratch_len);
    defer allocator.free(scratch);
    prng.fill(std.mem.sliceAsBytes(scratch)); // stale garbage must not matter
    try oracle_modexp(allocator, base, exponent, modulus, want);
    try modexp_with_scratch(base, exponent, modulus, got, scratch);
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print("modexp mismatch: mod_len={d} exp={x}\n", .{ modulus.len, exponent });
        return err;
    };
}

test "modexp: pre-Osaka modulus of 1025 bytes (2^1024 * 1) computes 2^1 exactly" {
    // lengths base=1 exp=1 mod=1025; base 02, exp 01, modulus 01 then 1024 zero bytes.
    var input: [96 + 1 + 1 + 1025]u8 = @splat(0);
    input[31] = 1;
    input[63] = 1;
    input[95] = 0x01; // mod_len = 0x401 = 1025
    input[94] = 0x04;
    input[96] = 0x02;
    input[97] = 0x01;
    input[98] = 0x01;
    const parsed = try precompile_modexp_parse(&input);
    try testing.expectEqual(@as(u64, 1025), parsed.modulus.len);
    try testing.expectEqual(@as(u64, 5547), parsed.gas(.berlin));
    try testing.expectError(error.InputTooLarge, parsed.check_osaka_limits());
    var out: [1025]u8 = undefined;
    try testing.expectError(error.ModulusTooLarge, precompile_modexp_run(parsed, &out));
    const needed: usize = @intCast(scratch_limbs_needed(parsed.modulus.len));
    const scratch = try testing.allocator.alloc(Limb, needed);
    defer testing.allocator.free(scratch);
    try precompile_modexp_run_with_scratch(parsed, &out, scratch);
    var expected: [1025]u8 = @splat(0);
    expected[1024] = 2;
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "modexp: scratch entry point rejects short scratch and agrees with the static path" {
    var short: [4]Limb = undefined;
    var out: [16]u8 = undefined;
    const modulus: [16]u8 = .{0x80} ++ @as([14]u8, @splat(0)) ++ .{0x01};
    try testing.expectError(
        error.ScratchTooSmall,
        modexp_with_scratch(&.{2}, &.{3}, &modulus, &out, &short),
    );
    // zero and one moduli need no scratch at all.
    try modexp_with_scratch(&.{2}, &.{3}, &.{ 0, 0 }, out[0..2], short[0..0]);
    var scratch: [workspace_limbs(2)]Limb = undefined;
    try modexp_with_scratch(&.{2}, &.{3}, &modulus, &out, &scratch);
    var again: [16]u8 = undefined;
    modexp(&.{2}, &.{3}, &modulus, &again);
    try testing.expectEqualSlices(u8, &again, &out);
    try testing.expectEqual(workspace_limbs(1), scratch_limbs_needed(1));
    try testing.expectEqual(workspace_limbs(128), scratch_limbs_needed(1024));
    try testing.expectEqual(workspace_limbs(129), scratch_limbs_needed(1025));
    _ = scratch_limbs_needed(std.math.maxInt(u64)); // saturates, never overflows
}

test "modexp: moduli of 1025..3000 bytes match the big-int oracle (odd and even)" {
    var prng = Prng.init(0x62696767);
    var base_buffer: [3200]u8 = undefined;
    var exponent_buffer: [4]u8 = undefined;
    var modulus_buffer: [3000]u8 = undefined;
    for (0..24) |round| {
        const extra: usize = if (round < 3) round else @intCast(prng.below(1976));
        const modulus_len = 1025 + extra;
        const base_len: usize = @intCast(prng.below(3201));
        const exponent_len: usize = @intCast(1 + prng.below(3));
        const base = random_operand(&prng, &base_buffer, base_len);
        const exponent = random_operand(&prng, &exponent_buffer, exponent_len);
        const modulus = modulus_buffer[0..modulus_len];
        random_modulus(&prng, modulus);
        if (round % 4 == 0) modulus[0] |= 0x80; // full width
        if (round % 4 == 1) modulus[modulus_len - 1] |= 1; // odd
        if (round % 4 == 2) modulus[modulus_len - 1] &= 0xfe; // even
        try expect_scratch_matches_oracle(&prng, base, exponent, modulus);
    }
}

test "modexp: scratch path handles wide even moduli, powers of two, and trailing zeros" {
    var prng = Prng.init(0x7061646d);
    var modulus: [1500]u8 = undefined;
    var base: [1500]u8 = undefined;
    prng.fill(&modulus);
    prng.fill(&base);
    modulus[0] |= 0x80;
    const exponent = [_]u8{ 0x01, 0x00, 0x01 };
    modulus[1499] |= 1;
    try expect_scratch_matches_oracle(&prng, &base, &exponent, &modulus);
    modulus[1499] &= 0xf0; // even: CRT with a 4-bit power of two
    try expect_scratch_matches_oracle(&prng, &base, &exponent, &modulus);
    @memset(modulus[1400..], 0); // 800 trailing zero bits
    try expect_scratch_matches_oracle(&prng, &base, &exponent, &modulus);
    @memset(modulus[1..], 0); // exactly 2^11992
    try expect_scratch_matches_oracle(&prng, &base, &exponent, &modulus);
}

test "modexp: scratch path agrees with the static path up to 1024 bytes" {
    var prng = Prng.init(0x73746174);
    var base: [300]u8 = undefined;
    var modulus_buffer: [1024]u8 = undefined;
    var scratch: [workspace_limbs(limbs_max)]Limb = undefined;
    for (0..40) |_| {
        const modulus = modulus_buffer[0..@intCast(1 + prng.below(1024))];
        random_modulus(&prng, modulus);
        prng.fill(&base);
        var exponent: [3]u8 = undefined;
        prng.fill(&exponent);
        var want: [1024]u8 = undefined;
        var got: [1024]u8 = undefined;
        modexp(&base, &exponent, modulus, want[0..modulus.len]);
        try modexp_with_scratch(&base, &exponent, modulus, got[0..modulus.len], &scratch);
        try testing.expectEqualSlices(u8, want[0..modulus.len], got[0..modulus.len]);
    }
}

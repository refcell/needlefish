//! Fee math for the transaction manager (base/base `tx-manager/src/fees.rs`).
//!
//! All values are wei in `u128` with saturating arithmetic, as in base/base: a fee that
//! would overflow pins at `maxInt(u128)` and then fails the fee-limit check instead of
//! wrapping to a tiny fee. Replacement bumps follow geth's mempool rules: at least +10%
//! on tip and fee cap for regular transactions, +100% for blob transactions.

const std = @import("std");
const assert = std.debug.assert;

/// `tip + 2 * base_fee`: survives six consecutive full blocks of base-fee growth.
pub fn gas_fee_cap(base_fee_wei: u128, tip_wei: u128) u128 {
    const fee_cap = tip_wei +| (base_fee_wei *| 2);
    assert(fee_cap >= tip_wei);
    return fee_cap;
}

/// Inverse of `gas_fee_cap`: the base fee that a (fee cap, tip) pair was built from.
pub fn base_fee_from_caps(fee_cap_wei: u128, tip_wei: u128) u128 {
    assert(fee_cap_wei >= tip_wei);
    const base_fee = (fee_cap_wei - tip_wei) / 2;
    assert(base_fee <= fee_cap_wei);
    return base_fee;
}

/// `2 * blob_base_fee`.
pub fn blob_fee_cap(blob_base_fee_wei: u128) u128 {
    const cap = blob_base_fee_wei *| 2;
    assert(cap >= blob_base_fee_wei);
    return cap;
}

/// The smallest replacement value geth accepts for `value`: +10% (regular) or +100%
/// (blob), and always at least +1 so a zero fee still moves.
pub fn threshold(value_wei: u128, is_blob: bool) u128 {
    const bump = if (is_blob) value_wei else value_wei / 10;
    const result = value_wei +| @max(bump, 1);
    assert(result > value_wei or value_wei == std.math.maxInt(u128));
    return result;
}

pub const TipAndCap = struct {
    tip_wei: u128,
    fee_cap_wei: u128,
};

/// Replacement fees: take the network's new suggestion when it already clears the bump
/// threshold, else the threshold itself, keeping `fee_cap >= tip`.
pub fn update_fees(
    old_tip_wei: u128,
    old_fee_cap_wei: u128,
    new_tip_wei: u128,
    new_base_fee_wei: u128,
    is_blob: bool,
) TipAndCap {
    const threshold_tip = threshold(old_tip_wei, is_blob);
    const threshold_fee_cap = threshold(old_fee_cap_wei, is_blob);
    const new_fee_cap = gas_fee_cap(new_base_fee_wei, new_tip_wei);
    const tip = @max(new_tip_wei, threshold_tip);
    const fee_cap = if (new_fee_cap >= threshold_fee_cap)
        gas_fee_cap(new_base_fee_wei, tip)
    else
        @max(threshold_fee_cap, tip);
    assert(tip >= threshold_tip);
    assert(fee_cap >= tip);
    assert(fee_cap >= threshold_fee_cap);
    return .{ .tip_wei = tip, .fee_cap_wei = fee_cap };
}

/// Fee ceiling: once the raw network suggestion reaches `limit_threshold_wei`, a fee may
/// be at most `limit_multiplier` times the suggestion. Below the threshold any fee goes,
/// so cheap networks never block on a ratio.
pub fn within_limit(
    fee_wei: u128,
    suggested_wei: u128,
    limit_multiplier: u64,
    limit_threshold_wei: u128,
) bool {
    assert(limit_multiplier > 0);
    if (suggested_wei < limit_threshold_wei) return true;
    const ceiling = @as(u128, limit_multiplier) *| suggested_wei;
    assert(ceiling >= suggested_wei);
    return fee_wei <= ceiling;
}

const testing = std.testing;
const max = std.math.maxInt(u128);

test "fees: gas_fee_cap" {
    const cases = [_][3]u128{
        .{ 0, 0, 0 },                                   .{ 0, 100, 100 },
        .{ 100, 0, 200 },                               .{ 50, 10, 110 },
        .{ 1_000_000_000, 500_000_000, 2_500_000_000 }, .{ max, 1, max },
        .{ max, max, max },
    };
    for (cases) |case| try testing.expectEqual(case[2], gas_fee_cap(case[0], case[1]));
}

test "fees: blob_fee_cap and base_fee_from_caps" {
    try testing.expectEqual(@as(u128, 0), blob_fee_cap(0));
    try testing.expectEqual(@as(u128, 200), blob_fee_cap(100));
    try testing.expectEqual(max, blob_fee_cap(max / 2 + 1));
    try testing.expectEqual(@as(u128, 50), base_fee_from_caps(110, 10));
    try testing.expectEqual(@as(u128, 0), base_fee_from_caps(10, 10));
}

test "fees: threshold" {
    const Case = struct { value: u128, blob: bool, expected: u128 };
    const cases = [_]Case{
        .{ .value = 0, .blob = false, .expected = 1 },
        .{ .value = 9, .blob = false, .expected = 10 },
        .{ .value = 10, .blob = false, .expected = 11 },
        .{ .value = 1000, .blob = false, .expected = 1100 },
        .{ .value = max, .blob = false, .expected = max },
        .{ .value = 0, .blob = true, .expected = 1 },
        .{ .value = 10, .blob = true, .expected = 20 },
        .{ .value = max / 2 + 1, .blob = true, .expected = max },
    };
    for (cases) |case| try testing.expectEqual(case.expected, threshold(case.value, case.blob));
}

test "fees: update_fees matches base/base cases" {
    const Case = struct { input: [4]u128, blob: bool, tip: u128, cap: u128 };
    const cases = [_]Case{
        .{ .input = .{ 100, 1000, 200, 500 }, .blob = false, .tip = 200, .cap = 1200 },
        .{ .input = .{ 100, 1000, 200, 1 }, .blob = false, .tip = 200, .cap = 1100 },
        .{ .input = .{ 100, 1000, 50, 5000 }, .blob = false, .tip = 110, .cap = 10110 },
        .{ .input = .{ 100, 1000, 50, 1 }, .blob = false, .tip = 110, .cap = 1100 },
        .{ .input = .{ 100, 1000, 300, 1000 }, .blob = true, .tip = 300, .cap = 2300 },
        .{ .input = .{ 100, 1000, 300, 1 }, .blob = true, .tip = 300, .cap = 2000 },
        .{ .input = .{ 100, 1000, 50, 5000 }, .blob = true, .tip = 200, .cap = 10200 },
        .{ .input = .{ 100, 1000, 50, 1 }, .blob = true, .tip = 200, .cap = 2000 },
        .{ .input = .{ 100, 10_000, 150, 1 }, .blob = false, .tip = 150, .cap = 11_000 },
        .{ .input = .{ 1_000, 100, 50, 1 }, .blob = false, .tip = 1_100, .cap = 1_100 },
        .{ .input = .{ 0, 0, 10, 100 }, .blob = false, .tip = 10, .cap = 210 },
    };
    for (cases) |case| {
        const in = case.input;
        const got = update_fees(in[0], in[1], in[2], in[3], case.blob);
        try testing.expectEqual(case.tip, got.tip_wei);
        try testing.expectEqual(case.cap, got.fee_cap_wei);
    }
}

test "fees: within_limit" {
    try testing.expect(within_limit(1_000_000, 50, 5, 100));
    try testing.expect(within_limit(500, 100, 5, 100));
    try testing.expect(!within_limit(501, 100, 5, 100));
    try testing.expect(within_limit(5, 1, 5, 0));
    try testing.expect(!within_limit(6, 1, 5, 0));
    try testing.expect(within_limit(0, 0, 5, 0));
    try testing.expect(!within_limit(1, 0, 5, 0));
    try testing.expect(within_limit(max, max, std.math.maxInt(u64), 0));
}

fn check_update_fees(old_tip: u128, old_cap: u128, tip: u128, base: u128, is_blob: bool) !void {
    const got = update_fees(old_tip, old_cap, tip, base, is_blob);
    try testing.expect(got.fee_cap_wei >= got.tip_wei);
    try testing.expect(got.tip_wei >= threshold(old_tip, is_blob));
    try testing.expect(got.fee_cap_wei >= threshold(old_cap, is_blob));
    // A replacement never lowers either fee below the network suggestion.
    try testing.expect(got.tip_wei >= tip);
}

fn draw_wei(random: std.Random) u128 {
    // Mix tiny, realistic (up to ~1000 gwei) and near-overflow magnitudes.
    return switch (random.uintLessThan(u8, 3)) {
        0 => random.uintLessThan(u128, 16),
        1 => random.uintLessThan(u128, 1_000_000_000_000),
        else => max - random.uintLessThan(u128, 1 << 64),
    };
}

test "fees: seeded fuzz update_fees invariants" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7f_ee5);
    const random = prng.random();
    for (0..20_000) |_| {
        try check_update_fees(
            draw_wei(random),
            draw_wei(random),
            draw_wei(random),
            draw_wei(random),
            random.boolean(),
        );
    }
}

test "fees: fuzz update_fees invariants" {
    try testing.fuzz({}, fuzz_update_fees, .{});
}

fn fuzz_update_fees(_: void, smith: *testing.Smith) anyerror!void {
    const old_tip = smith.value(u128);
    const old_cap = smith.value(u128);
    const tip = smith.value(u128);
    const base = smith.value(u128);
    try check_update_fees(old_tip, old_cap, tip, base, smith.value(bool));
}

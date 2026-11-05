//! FastLZ compressed-length estimation used by Fjord L1 fees and the Jovian DA footprint.
//! Mirrors base/base `crates/common/flz` (a port of op-geth `FlzCompressLen` and solady).
//!
//! Only the compressed length is computed; nothing is written. The hash table lives on
//! the stack (32 KiB), so the function never allocates.

const std = @import("std");
const assert = std.debug.assert;

pub const zero_byte_cost: u64 = 4;
pub const non_zero_byte_cost: u64 = 16;
/// op-geth `rollup_cost.go` fit: estimated size = max(min, coef * fastlz - intercept).
pub const l1_cost_fastlz_coefficient: u64 = 836_500;
pub const l1_cost_intercept: u64 = 42_585_600;
pub const min_tx_size_scaled: u64 = 100 * 1_000_000;

const hash_table_size = 8192;

fn read_u24(input: []const u8, index: u32) u32 {
    return @as(u32, input[index]) | @as(u32, input[index + 1]) << 8 |
        @as(u32, input[index + 2]) << 16;
}

fn hash_u24(value: u32) u13 {
    return @truncate((@as(u64, value) * 2_654_435_769) >> 19);
}

fn literals_size(run: u32, size: u32) u32 {
    const blocks = size + 0x21 * (run / 0x20);
    const rest = run % 0x20;
    return if (rest != 0) blocks + rest + 1 else blocks;
}

fn match_size(length: u32, size: u32) u32 {
    assert(length >= 1);
    const l = length - 1;
    const total = size + 3 * (l / 262);
    return if (l % 262 >= 6) total + 3 else total + 2;
}

/// Length of the common run of `input[p..]` and `input[q..]`, scanning `q < limit`.
/// Matches the reference exactly: on a mismatch the scan stops after counting it.
fn compare_length(input: []const u8, p: u32, q: u32, limit: u32) u32 {
    assert(q <= limit);
    var length: u32 = 0;
    var end = limit - q;
    while (length < end) {
        if (input[p + length] != input[q + length]) end = 0;
        length += 1;
    }
    return length;
}

const HashTable = [hash_table_size]u32;

fn set_next_hash(table: *HashTable, input: []const u8, index: u32) u32 {
    table[hash_u24(read_u24(input, index))] = index;
    return index + 1;
}

/// Bytes FastLZ (level 1) would produce for `input`.
pub fn compress_length(input: []const u8) u32 {
    assert(input.len <= std.math.maxInt(u32));
    const input_len: u32 = @intCast(input.len);
    const index_limit: u32 = if (input_len < 13) 0 else input_len - 13;
    var table: HashTable = @splat(0);
    var index: u32 = 2;
    var anchor: u32 = 0;
    var size: u32 = 0;
    // Every outer iteration advances `index` by at least one: bounded by input.len.
    while (index < index_limit) {
        var reference: u32 = 0;
        while (true) {
            const sequence = read_u24(input, index);
            const slot = hash_u24(sequence);
            reference = table[slot];
            table[slot] = index;
            const distance = index - reference;
            if (index >= index_limit) break;
            index += 1;
            if (distance < hash_table_size and sequence == read_u24(input, reference)) break;
        }
        if (index >= index_limit) break;
        index -= 1;
        if (index > anchor) size = literals_size(index - anchor, size);
        const length = compare_length(input, reference + 3, index + 3, index_limit + 9);
        size = match_size(length, size);
        index = set_next_hash(&table, input, index + length);
        index = set_next_hash(&table, input, index);
        anchor = index;
    }
    assert(anchor <= input_len);
    return literals_size(input_len - anchor, size);
}

/// Estimated compressed size scaled by 1e6: max(min, coef * fastlz_size - intercept).
pub fn estimated_size_from_fastlz_size(fastlz_size: u32) u64 {
    const scaled = @as(u64, fastlz_size) *| l1_cost_fastlz_coefficient;
    return @max(scaled -| l1_cost_intercept, min_tx_size_scaled);
}

pub fn estimated_size(input: []const u8) u64 {
    return estimated_size_from_fastlz_size(compress_length(input));
}

pub fn estimated_size_bytes(input: []const u8) u64 {
    return estimated_size(input) / 1_000_000;
}

/// Fjord data gas: 16 gas per estimated compressed byte.
pub fn data_gas_fjord(input: []const u8) u64 {
    return (estimated_size(input) *| non_zero_byte_cost) / 1_000_000;
}

const testing = std.testing;
const hex = @import("../primitives/hex.zig");
const Prng = @import("../../testing/prng.zig").Prng;

// Vectors from base/base `crates/common/flz` tests (public chain data).
const short_hex_hex =
    "FACADE";
const short_hex_expected: u32 = 4;

const sample_contract_call_hex =
    "02f901550a758302df1483be21b88304743f94f80e51afb613d764fa61751affd3313c190a86bb87" ++
    "0151bd62fd12adb8e41ef24f3f000000000000000000000000000000000000000000000000000000" ++
    "000000006e000000000000000000000000af88d065e77c8cc2239327c5edb3a432268e5831000000" ++
    "000000000000000000000000000000000000000000000000000003c1e50000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000a0000000000000000000000000000000000000000000000000000000" ++
    "00000000148c89ed219d02f1a5be012c689b4f5b731827bebe000000000000000000000000c001a0" ++
    "33fd89cb37c31b2cba46b6466e040c61fc9b2a3675a7f5f493ebd5ad77c497f8a07cdf65680e2383" ++
    "92693019b4092f610222e71b7cec06449cb922b93b6a12744e";
const sample_contract_call_expected: u32 = 202;

const base_0x5dadeb_hex =
    "b9047c02f904788221050883036ee48409c6c87383037f6f941195cf65f83b3a5768f3c496d3a05a" ++
    "d6412c64b78644364c5bb000b90404d123b4d8000000000000000000000000000000000000000000" ++
    "00000000000000000000400000000000000000000000000000000000000000000000000000000000" ++
    "00038000000000000000000000000000000000f6476f90447748c19248ccaa31e6b8bfda4eb9d830" ++
    "f5f47df7f0998f7c2123d9e6137761b75d3184efb0f788e3b1451600000000000000000000000000" ++
    "0000000000000000000000000044364c5bb000000000000000000000000000f38e53bd45c8225a7c" ++
    "94b513beadaa7afe5d222d0000000000000000000000000000000000000000000000000000000000" ++
    "00020000000000000000000000000000000000000000000000000000000000000002400000000000" ++
    "0000000000000000000000000000000000000000000000000002a000000000000000000000000000" ++
    "000000000000000000000000000000000002c0000000000000000000000000000000000000000000" ++
    "00000000000000000002e00000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000030000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000084d6574614d61736b0000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000035697066733a2f2f516d656852577a743347745961776343347564745657" ++
    "557233454c587261436746434259416b66507331696f486100000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000001000000000000000000000000cd0d83d9e840f8e27d5c2e365fd365ff1c" ++
    "05b2480000000000000000000000000000000000000000000000000000000000000ce40000000000" ++
    "000000000000000000000000000000000000000000000000000041e4480d358dbae20880960a0a46" ++
    "4d63b06565a0c9f9b1b37aa94b522247b23ce149c81359bf4239d1a879eeb41047ec710c15f5c0f6" ++
    "7453da59a383e6abd742971c00000000000000000000000000000000000000000000000000000000" ++
    "000000c001a0b57f0ff8516ea29cb26a44ac5055a5420847d1e16a8e7b03b70f0c02291ff2d5a00a" ++
    "d3771e5f39ccacfff0faa8c5d25ef7a1c179f79e66e828ffddcb994c8b512e";
const base_0x5dadeb_expected: u32 = 471;

fn expect_vector(comptime text: []const u8, expected: u32) !void {
    var buffer: [text.len / 2]u8 = undefined;
    try hex.decode(&buffer, text);
    try testing.expectEqual(expected, compress_length(&buffer));
}

test "flz: reference vectors" {
    try testing.expectEqual(@as(u32, 0), compress_length(&.{}));
    const zeros: [1000]u8 = @splat(0);
    try testing.expectEqual(@as(u32, 21), compress_length(&zeros));
    const forty_twos: [1000]u8 = @splat(42);
    try testing.expectEqual(@as(u32, 21), compress_length(&forty_twos));
    try expect_vector(short_hex_hex, short_hex_expected);
    try expect_vector(sample_contract_call_hex, sample_contract_call_expected);
    try expect_vector(base_0x5dadeb_hex, base_0x5dadeb_expected);
}

test "flz: strictly growing without repeats" {
    var input: [256]u8 = undefined;
    var previous: u32 = 0;
    for (0..256) |i| {
        input[i] = @intCast(i);
        const length = compress_length(input[0 .. i + 1]);
        try testing.expect(length > previous);
        previous = length;
    }
}

test "flz: fjord estimates" {
    try testing.expect(estimated_size_bytes(&.{ 1, 2, 3, 4, 5 }) > 0);
    try testing.expect(data_gas_fjord(&.{ 0xfa, 0xca, 0xde }) > 0);
    try testing.expectEqual(min_tx_size_scaled, estimated_size_from_fastlz_size(0));
}

test "flz: seeded fuzz bounds" {
    var prng = Prng.init(0xf12);
    var input: [4096]u8 = undefined;
    for (0..300) |_| {
        const len = prng.below(input.len + 1);
        // Mix random and repetitive content so matches are exercised.
        prng.fill(input[0..len]);
        if (prng.chance(1, 2)) {
            for (input[0..len], 0..) |*byte, i| byte.* = @truncate(i % (prng.below(16) + 1));
        }
        const length = compress_length(input[0..len]);
        // Literal-only encoding is an upper bound: 33 bytes per 32 literals.
        try testing.expect(length <= len + len / 32 + 1);
    }
}

fn fuzz_compress(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    const len = smith.slice(&input);
    const length = compress_length(input[0..len]);
    try testing.expect(length <= len + len / 32 + 1);
}

test "flz: fuzz compress length" {
    try testing.fuzz({}, fuzz_compress, .{});
}

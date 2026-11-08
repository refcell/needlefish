//! EVM-local primitive types: addresses, 32-byte words, and conversions.
//!
//! The primitives lane owns the canonical protocol types in `common.primitives`.
//! The EVM keeps this tiny, dependency-free set so it can land independently; the
//! layouts are plain byte arrays, so converting to the shared types is a no-op.

const std = @import("std");
const assert = std.debug.assert;
const crypto_keccak = @import("../../common/crypto/keccak.zig");

pub const Address = [20]u8;
pub const B256 = [32]u8;

pub const address_zero: Address = @splat(0);
pub const b256_zero: B256 = @splat(0);

/// keccak256 of the empty byte string, the code hash of every account without code.
pub const keccak_empty: B256 = hex_to_b256(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
);

comptime {
    assert(@sizeOf(Address) == 20);
    assert(@sizeOf(B256) == 32);
}

/// The crypto lane's Keccak (lanes in vector registers on x86-64 with AVX-512), not std's.
pub fn keccak256(bytes: []const u8) B256 {
    return crypto_keccak.keccak256(bytes);
}

pub fn b256_to_u256(word: B256) u256 {
    return word_from_be(&word);
}

pub fn u256_to_b256(value: u256) B256 {
    var out: B256 = undefined;
    word_to_be(&out, value);
    return out;
}

/// Big-endian 32 bytes to a word as four 64-bit loads. `std.mem.readInt(u256, .., .big)`
/// lowers to 32 single-byte loads and shifts on aarch64; this is the MLOAD hot path.
pub inline fn word_from_be(bytes: *const [32]u8) u256 {
    const high_high: u256 = std.mem.readInt(u64, bytes[0..8], .big);
    const high_low: u256 = std.mem.readInt(u64, bytes[8..16], .big);
    const low_high: u256 = std.mem.readInt(u64, bytes[16..24], .big);
    const low_low: u256 = std.mem.readInt(u64, bytes[24..32], .big);
    return high_high << 192 | high_low << 128 | low_high << 64 | low_low;
}

/// Inverse of `word_from_be` (MSTORE hot path).
pub inline fn word_to_be(bytes: *[32]u8, value: u256) void {
    std.mem.writeInt(u64, bytes[0..8], @truncate(value >> 192), .big);
    std.mem.writeInt(u64, bytes[8..16], @truncate(value >> 128), .big);
    std.mem.writeInt(u64, bytes[16..24], @truncate(value >> 64), .big);
    std.mem.writeInt(u64, bytes[24..32], @truncate(value), .big);
}

test "primitives: word big-endian conversions match std.mem" {
    var prng = std.Random.DefaultPrng.init(0x3e3e);
    var iteration: u32 = 0;
    while (iteration < 1000) : (iteration += 1) {
        var bytes: [32]u8 = undefined;
        prng.random().bytes(&bytes);
        const value = word_from_be(&bytes);
        try std.testing.expectEqual(std.mem.readInt(u256, &bytes, .big), value);
        var out: [32]u8 = undefined;
        word_to_be(&out, value);
        try std.testing.expectEqualSlices(u8, &bytes, &out);
    }
}

pub fn address_to_u256(address: Address) u256 {
    return std.mem.readInt(u160, &address, .big);
}

/// The low 160 bits of a stack word, as the EVM does for every address operand.
pub fn u256_to_address(value: u256) Address {
    var out: Address = undefined;
    std.mem.writeInt(u160, &out, @truncate(value), .big);
    return out;
}

/// Compile-time or runtime parse of exactly 64 hex digits (no 0x prefix).
pub fn hex_to_b256(comptime hex: []const u8) B256 {
    comptime assert(hex.len == 64);
    var out: B256 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Proof: comptime-checked input.
    return out;
}

pub fn hex_to_address(comptime hex: []const u8) Address {
    comptime assert(hex.len == 40);
    var out: Address = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Proof: comptime-checked input.
    return out;
}

/// An address whose last eight bytes hold `value` (precompiles, system contracts, tests).
pub fn address_from_int(value: u64) Address {
    var out: Address = address_zero;
    std.mem.writeInt(u64, out[12..20], value, .big);
    return out;
}

test "primitives: keccak of empty matches constant" {
    try std.testing.expectEqualSlices(u8, &keccak_empty, &keccak256(""));
}

test "primitives: u256 and address round trip" {
    const value: u256 = (@as(u256, 0xdead) << 200) | 0x1234_5678_9abc_def0;
    try std.testing.expectEqual(value, b256_to_u256(u256_to_b256(value)));
    const address = u256_to_address(value);
    try std.testing.expectEqual(@as(u256, @as(u160, @truncate(value))), address_to_u256(address));
    try std.testing.expectEqual(@as(u8, 0x01), address_from_int(1)[19]);
}

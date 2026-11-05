//! The L1 `ProtocolVersions` upgrade-signal contract: call data, strict ABI decoding of its
//! two views, the contract-backed upgrade IDs, and the public default contract addresses.
//!
//! ```solidity
//! function getSchedule() external view returns (uint64[] memory);
//! function minimumProtocolVersion() external view returns (uint256);
//! ```
//!
//! `getSchedule()[i]` is the activation timestamp of `upgrade_ids[i]`. Decoding fails closed:
//! the array offset must be canonical (32), the length at most `schedule_length_max` (checked
//! before reading entries, as base/base does before allocating), and every entry must be a
//! zero-padded uint64. Entries beyond the IDs this binary knows are ignored.

const std = @import("std");
const assert = std.debug.assert;

const Version = @import("version.zig").Version;

pub const schedule_length_max = 256;
const word_bytes = 32;

fn selector(comptime signature: []const u8) [4]u8 {
    @setEvalBranchQuota(100_000);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(signature, &digest, .{});
    return digest[0..4].*;
}

pub const get_schedule_selector: [4]u8 = selector("getSchedule()");
pub const minimum_protocol_version_selector: [4]u8 = selector("minimumProtocolVersion()");

/// Contract-backed upgrades in schedule order (base/base `BaseUpgrade::CONTRACT_VARIANTS`
/// with their `contract_id` strings).
pub const upgrade_ids = [_][]const u8{
    "regolith",
    "canyon",
    "delta",
    "ecotone",
    "fjord",
    "granite",
    "holocene",
    "pectra_blob_schedule",
    "isthmus",
    "jovian",
    "azul",
    "beryl",
    "cobalt",
    "denim",
    "everest",
};
comptime {
    assert(upgrade_ids.len == 15);
}

/// Public default `ProtocolVersions` addresses by L2 chain ID (base/base README).
pub fn default_contract(chain_id: u64) ?[20]u8 {
    const text: []const u8 = switch (chain_id) {
        8453 => "7480afc8d99a5c645c247db5a1e4a4f440e6e095",
        84532 => "15b721b12cf3b0c4400c8a2935a0ae391c2ef65b",
        763360 => "30e172aac675c9fe5a64792f92c9fd4d3e7ca9da",
        else => return null,
    };
    var address: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&address, text) catch unreachable; // Constant 40-digit hex.
    return address;
}

pub const DecodeError = error{Decode};

/// Decodes `getSchedule()` return data into `out`; returns the entry count.
pub fn decode_schedule(encoded: []const u8, out: *[schedule_length_max]u64) DecodeError!u32 {
    if (encoded.len < 2 * word_bytes) return error.Decode;
    const offset = try word_u64(encoded[0..word_bytes]);
    if (offset != word_bytes) return error.Decode;
    const length = word_u64(encoded[word_bytes .. 2 * word_bytes]) catch return error.Decode;
    if (length > schedule_length_max) return error.Decode;
    const count: u32 = @intCast(length);
    if (encoded.len < (2 + count) * word_bytes) return error.Decode;
    for (out[0..count], 0..) |*entry, index| {
        const start = (2 + index) * word_bytes;
        entry.* = try word_u64(encoded[start..][0..word_bytes]);
    }
    return count;
}

/// Decodes `minimumProtocolVersion()` return data.
pub fn decode_version(encoded: []const u8) DecodeError!Version {
    if (encoded.len < word_bytes) return error.Decode;
    return .{ .packed_value = std.mem.readInt(u256, encoded[0..word_bytes], .big) };
}

fn word_u64(word: []const u8) DecodeError!u64 {
    assert(word.len == word_bytes);
    for (word[0..24]) |byte| if (byte != 0) return error.Decode;
    return std.mem.readInt(u64, word[24..32], .big);
}

/// ABI-encodes a schedule (tests and fakes).
pub fn encode_schedule(timestamps: []const u64, out: []u8) []u8 {
    const size = (2 + timestamps.len) * word_bytes;
    assert(out.len >= size);
    @memset(out[0..size], 0);
    std.mem.writeInt(u64, out[24..32], word_bytes, .big);
    std.mem.writeInt(u64, out[56..64], timestamps.len, .big);
    for (timestamps, 0..) |timestamp, index| {
        const end = (3 + index) * word_bytes;
        std.mem.writeInt(u64, out[end - 8 .. end][0..8], timestamp, .big);
    }
    return out[0..size];
}

test "upgrade_signal: selectors" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("getSchedule()", &digest, .{});
    try std.testing.expectEqualSlices(u8, digest[0..4], &get_schedule_selector);
    std.crypto.hash.sha3.Keccak256.hash("minimumProtocolVersion()", &digest, .{});
    try std.testing.expectEqualSlices(u8, digest[0..4], &minimum_protocol_version_selector);
}

test "upgrade_signal: upgrade ids and default contracts" {
    try std.testing.expectEqualStrings("regolith", upgrade_ids[0]);
    try std.testing.expectEqualStrings("pectra_blob_schedule", upgrade_ids[7]);
    try std.testing.expectEqualStrings("everest", upgrade_ids[upgrade_ids.len - 1]);
    const mainnet = default_contract(8453).?;
    try std.testing.expectEqual(@as(u8, 0x74), mainnet[0]);
    try std.testing.expectEqual(@as(u8, 0x95), mainnet[19]);
    try std.testing.expect(default_contract(1) == null);
}

test "upgrade_signal: schedule decoding" {
    var buffer: [64 + 32 * 4]u8 = undefined;
    var out: [schedule_length_max]u64 = undefined;
    const encoded = encode_schedule(&.{ 0, 1_700_000_000, std.math.maxInt(u64) }, &buffer);
    try std.testing.expectEqual(@as(u32, 3), try decode_schedule(encoded, &out));
    try std.testing.expectEqual(@as(u64, 1_700_000_000), out[1]);
    try std.testing.expectEqual(std.math.maxInt(u64), out[2]);
    try std.testing.expectError(error.Decode, decode_schedule(encoded[0..63], &out));
    try std.testing.expectError(error.Decode, decode_schedule(encoded[0 .. 64 + 32 * 2], &out));
    var bad = buffer;
    bad[31] = 64; // Non-canonical offset.
    try std.testing.expectError(error.Decode, decode_schedule(&bad, &out));
    bad = buffer;
    bad[64 + 23] = 1; // Entry overflows uint64.
    try std.testing.expectError(error.Decode, decode_schedule(bad[0..encoded.len], &out));
    bad = buffer;
    std.mem.writeInt(u64, bad[56..64], schedule_length_max + 1, .big);
    try std.testing.expectError(error.Decode, decode_schedule(&bad, &out));
    bad[40] = 1; // Length beyond u64.
    try std.testing.expectError(error.Decode, decode_schedule(&bad, &out));
    const empty = encode_schedule(&.{}, &buffer);
    try std.testing.expectEqual(@as(u32, 0), try decode_schedule(empty, &out));
}

test "upgrade_signal: version decoding" {
    var word: [32]u8 = @splat(0);
    std.mem.writeInt(u256, &word, Version.pack(1, 2, 3, 0).packed_value, .big);
    try std.testing.expect((try decode_version(&word)).eql(Version.pack(1, 2, 3, 0)));
    try std.testing.expectError(error.Decode, decode_version(word[0..31]));
}

fn decode_arbitrary(encoded: []const u8) !void {
    var out: [schedule_length_max]u64 = undefined;
    const count = decode_schedule(encoded, &out) catch return;
    // Accepted data re-encodes to its canonical prefix.
    var buffer: [64 + 32 * schedule_length_max]u8 = undefined;
    const again = encode_schedule(out[0..count], &buffer);
    try std.testing.expectEqualSlices(u8, again, encoded[0..again.len]);
}

test "upgrade_signal: seeded fuzz schedule decoding" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x5c4ed);
    var buffer: [64 + 32 * 8]u8 = undefined;
    var timestamps: [8]u64 = undefined;
    for (0..3000) |_| {
        const count = prng.below(timestamps.len + 1);
        for (timestamps[0..count]) |*t| t.* = prng.int(u64);
        const encoded = encode_schedule(timestamps[0..count], &buffer);
        // Flip a byte sometimes; decoding must reject or stay canonical.
        if (encoded.len > 0 and prng.chance(1, 2)) {
            encoded[prng.below(encoded.len)] ^= @truncate(prng.range(1, 255));
        }
        try decode_arbitrary(encoded[0 .. encoded.len - prng.below(3)]);
    }
}

fn fuzz_decode(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var buffer: [64 + 32 * 16]u8 = undefined;
    try decode_arbitrary(buffer[0..smith.slice(&buffer)]);
}

test "upgrade_signal: fuzz schedule decoding" {
    try std.testing.fuzz({}, fuzz_decode, .{});
}

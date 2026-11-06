//! Decoders for the reth table values a state import reads (reth 2.5 `Compact` codec, see
//! docs/lanes/snapshot.md). Untrusted input: every malformed value is `error.Malformed`.
//!
//! - `HashedAccounts` (and `PlainAccountState`) value `Account`: two flag bytes read as a
//!   little-endian u16 (bits 0-3 nonce length, 4-9 balance length, 10 code hash present),
//!   then the nonce and balance big-endian with leading zeros dropped, then the 32-byte code
//!   hash if present (absent: no code).
//! - `HashedStorages` duplicate `StorageEntry`: the 32-byte (hashed) slot, then the value
//!   big-endian with leading zeros dropped (the rest of the bytes).
//! - `Bytecodes` value: u32 big-endian length, that many code bytes, a variant byte: 0 raw,
//!   2 analyzed legacy (u64 big-endian original length, then a jump table; the stored code is
//!   padded, the real code is its first original-length bytes), 4 EIP-7702 delegation.
//! - `StageCheckpoints` value: one flag byte (bits 0-3 block number length, bit 4 a unit
//!   checkpoint follows), then the block number big-endian, trimmed.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("../trie/node.zig");

pub const Error = error{Malformed};
pub const Hash = [32]u8;

pub const Account = struct {
    nonce: u64,
    balance: u256,
    /// The empty code hash for an account without code.
    code_hash: Hash,
};

fn trimmed(comptime T: type, bytes: []const u8) Error!T {
    if (bytes.len > @sizeOf(T)) return error.Malformed;
    // The writer strips leading zeros, so a leading zero byte is not canonical.
    if (bytes.len > 0 and bytes[0] == 0) return error.Malformed;
    var value: T = 0;
    for (bytes) |byte| value = value << 8 | byte;
    return value;
}

pub fn decode_account(value: []const u8) Error!Account {
    if (value.len < 2) return error.Malformed;
    const flags = std.mem.readInt(u16, value[0..2], .little);
    if (flags >> 11 != 0) return error.Malformed;
    const nonce_len: usize = flags & 0xf;
    const balance_len: usize = (flags >> 4) & 0x3f;
    const has_code = (flags >> 10) & 1 == 1;
    const total = 2 + nonce_len + balance_len + @as(usize, if (has_code) 32 else 0);
    if (nonce_len > 8 or balance_len > 32 or value.len != total) return error.Malformed;
    const nonce = try trimmed(u64, value[2..][0..nonce_len]);
    const balance = try trimmed(u256, value[2 + nonce_len ..][0..balance_len]);
    const code_hash = if (has_code) value[total - 32 ..][0..32].* else node.empty_code_hash;
    assert(total <= 2 + 8 + 32 + 32);
    return .{ .nonce = nonce, .balance = balance, .code_hash = code_hash };
}

pub const StorageEntry = struct { slot: Hash, value: u256 };

pub fn decode_storage_entry(value: []const u8) Error!StorageEntry {
    if (value.len < 32 or value.len > 64) return error.Malformed;
    const entry: StorageEntry = .{
        .slot = value[0..32].*,
        .value = try trimmed(u256, value[32..]),
    };
    assert(value.len == 32 or entry.value != 0);
    return entry;
}

pub const variant_raw = 0;
pub const variant_analyzed = 2;
pub const variant_eip7702 = 4;

/// The real code bytes of a `Bytecodes` value (a slice of `value`).
pub fn decode_bytecode(value: []const u8) Error![]const u8 {
    if (value.len < 5) return error.Malformed;
    const length = std.mem.readInt(u32, value[0..4], .big);
    if (value.len < 5 + @as(usize, length)) return error.Malformed;
    const code = value[4..][0..length];
    const rest = value[4 + length ..];
    switch (rest[0]) {
        variant_raw => {
            if (rest.len != 1) return error.Malformed;
            return code;
        },
        variant_analyzed => {
            if (rest.len < 9) return error.Malformed;
            const original = std.mem.readInt(u64, rest[1..9], .big);
            if (original > code.len) return error.Malformed;
            // The jump table follows; import recomputes jump destinations, so it is ignored.
            return code[0..@intCast(original)];
        },
        variant_eip7702 => {
            if (rest.len != 1 or code.len != 23) return error.Malformed;
            if (!std.mem.eql(u8, code[0..3], &.{ 0xef, 0x01, 0x00 })) return error.Malformed;
            return code;
        },
        else => return error.Malformed,
    }
}

pub fn decode_stage_block(value: []const u8) Error!u64 {
    if (value.len < 1) return error.Malformed;
    const flags = value[0];
    if (flags >> 5 != 0) return error.Malformed;
    const length: usize = flags & 0xf;
    if (length > 8 or value.len < 1 + length) return error.Malformed;
    const has_unit = flags & 0x10 != 0;
    if (!has_unit and value.len != 1 + length) return error.Malformed;
    return trimmed(u64, value[1..][0..length]);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

// Byte strings from reth-primitives-traits' account tests and their Compact rules.
test "reth: accounts" {
    const empty = try decode_account(&hex("0000"));
    try testing.expectEqual(@as(u64, 0), empty.nonce);
    try testing.expectEqualSlices(u8, &node.empty_code_hash, &empty.code_hash);
    const small = try decode_account(&hex("11000202"));
    try testing.expectEqual(@as(u64, 2), small.nonce);
    try testing.expectEqual(@as(u256, 2), small.balance);
    const ether = try decode_account(&hex("8100010de0b6b3a7640000"));
    try testing.expectEqual(@as(u64, 1), ether.nonce);
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), ether.balance);
    const code: Hash = @splat(0xab);
    const with_code = try decode_account(&(hex("010401") ++ code));
    try testing.expectEqualSlices(u8, &code, &with_code.code_hash);
    try testing.expectEqual(@as(u256, 0), with_code.balance);
    const rejected = [_][]const u8{
        &hex("00"),   &hex("1100020200"), &hex("110002"), &hex("11000002"), &hex("0900"),
        &hex("0008"),
    };
    for (rejected) |bad| try testing.expectError(error.Malformed, decode_account(bad));
}

test "reth: storage entries and stage checkpoints" {
    const slot: Hash = @splat(0x11);
    const entry = try decode_storage_entry(&(slot ++ hex("2a")));
    try testing.expectEqualSlices(u8, &slot, &entry.slot);
    try testing.expectEqual(@as(u256, 42), entry.value);
    try testing.expectError(error.Malformed, decode_storage_entry(&(slot ++ hex("002a"))));
    try testing.expectError(error.Malformed, decode_storage_entry(slot[0..31]));
    try testing.expectEqual(@as(u64, 0x01234567), try decode_stage_block(&hex("0401234567")));
    try testing.expectError(error.Malformed, decode_stage_block(&hex("04012345")));
    try testing.expectError(error.Malformed, decode_stage_block(&hex("0901")));
}

test "reth: bytecodes" {
    // PUSH1 1, padded with a STOP, original length 2, one jump table byte.
    const analyzed = hex("00000003600100" ++ "02" ++ "0000000000000002" ++ "00");
    try testing.expectEqualSlices(u8, &hex("6001"), try decode_bytecode(&analyzed));
    const raw = hex("00000002" ++ "6001" ++ "00");
    try testing.expectEqualSlices(u8, &hex("6001"), try decode_bytecode(&raw));
    const target = "1111111111111111111111111111111111111111";
    const delegation = hex("00000017" ++ "ef0100" ++ target ++ "04");
    try testing.expectEqual(@as(usize, 23), (try decode_bytecode(&delegation)).len);
    const empty = hex("00000001" ++ "00" ++ "02" ++ "0000000000000000");
    try testing.expectEqual(@as(usize, 0), (try decode_bytecode(&empty)).len);
    const rejected = [_][]const u8{
        &hex("0000000360010001"), // EOF / removed variant
        &hex("000000036001000200000000000000040000"), // original longer than code
        &hex("0000000360"), // truncated
        &hex("00000003ef01000400"), // short delegation
    };
    for (rejected) |bad| try testing.expectError(error.Malformed, decode_bytecode(bad));
}

test "reth: seeded fuzz, decoders never crash" {
    var prng = Prng.init(0x7265_7468);
    var buffer: [96]u8 = undefined;
    for (0..4096) |_| {
        const len: usize = @intCast(prng.below(buffer.len));
        prng.fill(buffer[0..len]);
        const bytes = buffer[0..len];
        if (decode_account(bytes)) |account| {
            try testing.expect(account.nonce >> 63 <= 1);
        } else |_| {}
        if (decode_bytecode(bytes)) |code| try testing.expect(code.len <= len) else |_| {}
        _ = decode_storage_entry(bytes) catch {};
        _ = decode_stage_block(bytes) catch {};
    }
}

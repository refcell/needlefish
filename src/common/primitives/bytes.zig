//! Fixed-size byte types: `Address` (20), `B256` (32), `B64`, `Bloom` (256), plus
//! big-endian `u256` conversions and EIP-55 checksummed addresses.
//!
//! Types are `extern struct`s wrapping a byte array so they have a stable layout, can
//! be compared with `std.mem.eql`, and carry methods. Zig's native `u256` is the
//! 256-bit integer type; this file only converts it to and from bytes.

const std = @import("std");
const assert = std.debug.assert;
const hex = @import("hex.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// A fixed-size byte string of `size` bytes with hex helpers.
pub fn FixedBytes(comptime size: usize) type {
    comptime assert(size > 0);
    return extern struct {
        bytes: [size]u8,

        const Self = @This();
        pub const len = size;
        pub const zero: Self = .{ .bytes = @splat(0) };

        pub fn init(bytes: [size]u8) Self {
            return .{ .bytes = bytes };
        }

        /// Copies exactly `size` bytes from `slice`.
        pub fn from_slice(slice: []const u8) Self {
            assert(slice.len == size);
            return .{ .bytes = slice[0..size].* };
        }

        /// Parses `0x`-optional hex of exactly `size` bytes.
        pub fn from_hex(text: []const u8) hex.Error!Self {
            return .{ .bytes = try hex.decode_array(size, text) };
        }

        /// Comptime hex literal; compile error when malformed.
        pub fn comptime_hex(comptime text: []const u8) Self {
            return comptime from_hex(text) catch @compileError("bad hex literal: " ++ text);
        }

        pub fn to_hex(self: Self) [size * 2 + 2]u8 {
            return hex.encode_array(size, self.bytes);
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }

        pub fn is_zero(self: Self) bool {
            return self.eql(zero);
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const text = self.to_hex();
            try writer.writeAll(&text);
        }

        comptime {
            assert(@sizeOf(Self) == size);
            assert(@alignOf(Self) == 1);
        }
    };
}

pub const B64 = FixedBytes(8);
pub const B256 = FixedBytes(32);
pub const Address = FixedBytes(20);

/// Keccak-256 of `data`.
pub fn keccak256(data: []const u8) B256 {
    var out: B256 = undefined;
    Keccak256.hash(data, &out.bytes, .{});
    return out;
}

/// Keccak-256 of the empty string.
pub const keccak_empty = B256.comptime_hex(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
);

/// Keccak-256 of the RLP encoding of an empty list (`0xc0`): the empty ommers hash.
pub const empty_ommers_hash = B256.comptime_hex(
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
);

/// Root of an empty Merkle-Patricia trie: keccak256(rlp("")) = keccak256(0x80).
pub const empty_root_hash = B256.comptime_hex(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
);

/// Big-endian 32-byte encoding of a u256.
pub fn u256_to_bytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

/// Decodes a 32-byte big-endian u256.
pub fn u256_from_bytes(bytes: [32]u8) u256 {
    return std.mem.readInt(u256, &bytes, .big);
}

/// Decodes up to 32 big-endian bytes (leading zeros allowed) as a u256.
pub fn u256_from_be_slice(bytes: []const u8) u256 {
    assert(bytes.len <= 32);
    var padded: [32]u8 = @splat(0);
    @memcpy(padded[32 - bytes.len ..], bytes);
    return std.mem.readInt(u256, &padded, .big);
}

pub fn u256_to_b256(value: u256) B256 {
    return .{ .bytes = u256_to_bytes(value) };
}

pub fn b256_to_u256(value: B256) u256 {
    return u256_from_bytes(value.bytes);
}

/// The address is the low 20 bytes of a 32-byte word.
pub fn address_from_word(word: B256) Address {
    return Address.from_slice(word.bytes[12..32]);
}

/// Left-pads an address into a 32-byte word.
pub fn address_to_word(address: Address) B256 {
    var word = B256.zero;
    word.bytes[12..32].* = address.bytes;
    return word;
}

/// EIP-55 mixed-case checksum encoding (`0x` + 40 chars).
/// With `chain_id` set, uses the EIP-1191 variant (chain id mixed into the hash).
pub fn checksum(address: Address, chain_id: ?u64) [42]u8 {
    var lower: [40]u8 = undefined;
    hex.encode(&lower, &address.bytes);
    var hasher = Keccak256.init(.{});
    var prefix_buffer: [24]u8 = undefined;
    if (chain_id) |id| {
        const prefix = std.fmt.bufPrint(&prefix_buffer, "{d}0x", .{id}) catch unreachable;
        hasher.update(prefix);
    }
    hasher.update(&lower);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var out: [42]u8 = undefined;
    out[0] = '0';
    out[1] = 'x';
    for (lower, 0..) |c, i| {
        const nibble = (digest[i / 2] >> @intCast(4 * (1 - (i % 2)))) & 0x0f;
        out[2 + i] = if (c >= 'a' and nibble >= 8) c - 32 else c;
    }
    assert(std.ascii.eqlIgnoreCase(out[2..], &lower));
    return out;
}

pub const ChecksumError = hex.Error || error{BadChecksum};

/// Parses an address. All-lowercase or all-uppercase input is accepted as-is;
/// mixed case must match the EIP-55 checksum.
pub fn parse_address_checked(text: []const u8) ChecksumError!Address {
    const address = try Address.from_hex(text);
    const digits = hex.strip_prefix(text);
    assert(digits.len == 40);
    var has_lower = false;
    var has_upper = false;
    for (digits) |c| {
        has_lower = has_lower or std.ascii.isLower(c);
        has_upper = has_upper or std.ascii.isUpper(c);
    }
    if (!(has_lower and has_upper)) return address;
    const expected = checksum(address, null);
    if (!std.mem.eql(u8, expected[2..], digits)) return error.BadChecksum;
    return address;
}

/// 2048-bit log bloom filter (yellow paper M3:2048).
pub const Bloom = extern struct {
    bytes: [256]u8,

    pub const zero: Bloom = .{ .bytes = @splat(0) };

    /// Sets the three bits selected by keccak256(input).
    pub fn accrue(bloom: *Bloom, input: []const u8) void {
        bloom.accrue_hash(keccak256(input));
    }

    /// Sets the three bits selected by a precomputed keccak256 hash.
    pub fn accrue_hash(bloom: *Bloom, hash: B256) void {
        inline for (0..3) |i| {
            const bit = (@as(u16, hash.bytes[2 * i]) << 8 | hash.bytes[2 * i + 1]) & 2047;
            bloom.bytes[255 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
        }
    }

    /// True when all three bits for `input` are set (may be a false positive).
    pub fn contains(bloom: Bloom, input: []const u8) bool {
        var probe = Bloom.zero;
        probe.accrue(input);
        return bloom.contains_bloom(probe);
    }

    pub fn contains_bloom(bloom: Bloom, other: Bloom) bool {
        for (bloom.bytes, other.bytes) |a, b| {
            if (a & b != b) return false;
        }
        return true;
    }

    /// Bitwise OR of `other` into `bloom`.
    pub fn merge(bloom: *Bloom, other: Bloom) void {
        const V = @Vector(256, u8);
        const merged: V = @as(V, bloom.bytes) | @as(V, other.bytes);
        bloom.bytes = merged;
    }

    pub fn eql(a: Bloom, b: Bloom) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    comptime {
        assert(@sizeOf(Bloom) == 256);
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "bytes: fixed bytes hex and equality" {
    const a = Address.comptime_hex("0x00000000000000000000000000000000000000ff");
    try testing.expectEqual(@as(u8, 0xff), a.bytes[19]);
    try testing.expect(!a.is_zero());
    try testing.expect(Address.zero.is_zero());
    try testing.expectEqualStrings("0x00000000000000000000000000000000000000ff", &a.to_hex());
    try testing.expectError(error.InvalidLength, Address.from_hex("0x00"));
    var buffer: [80]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{a});
    try testing.expectEqualStrings(&a.to_hex(), text);
}

test "bytes: keccak constants" {
    try testing.expect(keccak256("").eql(keccak_empty));
    try testing.expect(keccak256(&.{0xc0}).eql(empty_ommers_hash));
    try testing.expect(keccak256(&.{0x80}).eql(empty_root_hash));
}

test "bytes: u256 conversions" {
    const value: u256 = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    const bytes = u256_to_bytes(value);
    try testing.expectEqual(@as(u8, 1), bytes[0]);
    try testing.expectEqual(value, u256_from_bytes(bytes));
    try testing.expectEqual(@as(u256, 0x0102), u256_from_be_slice(&.{ 1, 2 }));
    try testing.expectEqual(@as(u256, 0), u256_from_be_slice(&.{}));
    const address = Address.comptime_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    try testing.expect(address_from_word(address_to_word(address)).eql(address));
}

test "bytes: EIP-55 checksum vectors" {
    const vectors = [_][]const u8{
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    };
    for (vectors) |vector| {
        const address = try parse_address_checked(vector);
        try testing.expectEqualStrings(vector, &checksum(address, null));
    }
    try testing.expectError(
        error.BadChecksum,
        parse_address_checked("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
    );
    _ = try parse_address_checked("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
}

test "bytes: EIP-1191 checksum vector" {
    const address = try Address.from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    try testing.expectEqualStrings(
        "0x5aaEB6053f3e94c9b9a09f33669435E7ef1bEAeD",
        &checksum(address, 30),
    );
}

test "bytes: bloom" {
    var bloom = Bloom.zero;
    const address = Address.comptime_hex("0x22341ae42d6dd7384bc8584e50419ea3ac75b83f");
    bloom.accrue(&address.bytes);
    try testing.expect(bloom.contains(&address.bytes));
    var prng = Prng.init(11);
    var misses: u32 = 0;
    for (0..256) |_| {
        var data: [32]u8 = undefined;
        prng.fill(&data);
        if (!bloom.contains(&data)) misses += 1;
    }
    try testing.expect(misses > 200);
    var other = Bloom.zero;
    other.merge(bloom);
    try testing.expect(other.eql(bloom));
    try testing.expect(other.contains_bloom(bloom));
}

fn fuzz_checksum(_: void, smith: *testing.Smith) anyerror!void {
    var input: [64]u8 = undefined;
    const len = smith.slice(&input);
    const address = parse_address_checked(input[0..len]) catch return;
    const text = checksum(address, null);
    try testing.expect((try parse_address_checked(&text)).eql(address));
}

test "bytes: fuzz checksum" {
    try testing.fuzz({}, fuzz_checksum, .{});
}

test "bytes: seeded fuzz checksum round trip" {
    var prng = Prng.init(55);
    for (0..500) |_| {
        var address: Address = undefined;
        prng.fill(&address.bytes);
        const text = checksum(address, null);
        try testing.expect((try parse_address_checked(&text)).eql(address));
        const word = u256_to_b256(prng.int(u256));
        try testing.expect(u256_to_b256(b256_to_u256(word)).eql(word));
    }
}

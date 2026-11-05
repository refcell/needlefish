//! Contract addresses: CREATE (`keccak(rlp([sender, nonce]))[12..]`) and CREATE2
//! (EIP-1014: `keccak(0xff ++ sender ++ salt ++ keccak(init_code))[12..]`).

const std = @import("std");
const assert = std.debug.assert;
const bytes = @import("bytes.zig");
const Address = bytes.Address;
const B256 = bytes.B256;

/// CREATE address of the contract `sender` deploys at `nonce`.
pub fn create_address(sender: Address, nonce: u64) Address {
    // rlp([sender, nonce]): list header, 0x94 ++ sender, then the nonce as an RLP integer.
    var buffer: [1 + 21 + 9]u8 = undefined;
    buffer[1] = 0x80 + 20;
    buffer[2..22].* = sender.bytes;
    var length: usize = 22;
    if (nonce == 0) {
        buffer[length] = 0x80;
        length += 1;
    } else if (nonce < 0x80) {
        buffer[length] = @intCast(nonce);
        length += 1;
    } else {
        const nonce_bytes: usize = 8 - @as(usize, @clz(nonce)) / 8;
        assert(nonce_bytes >= 1 and nonce_bytes <= 8);
        buffer[length] = @intCast(0x80 + nonce_bytes);
        var big: [8]u8 = undefined;
        std.mem.writeInt(u64, &big, nonce, .big);
        @memcpy(buffer[length + 1 ..][0..nonce_bytes], big[8 - nonce_bytes ..]);
        length += 1 + nonce_bytes;
    }
    assert(length - 1 <= 55);
    buffer[0] = @intCast(0xc0 + (length - 1));
    return from_hash(bytes.keccak256(buffer[0..length]));
}

/// CREATE2 address for `sender`, `salt` and the keccak of the init code.
pub fn create2_address(sender: Address, salt: B256, init_code_hash: B256) Address {
    var buffer: [1 + 20 + 32 + 32]u8 = undefined;
    buffer[0] = 0xff;
    buffer[1..21].* = sender.bytes;
    buffer[21..53].* = salt.bytes;
    buffer[53..85].* = init_code_hash.bytes;
    return from_hash(bytes.keccak256(&buffer));
}

fn from_hash(hash: B256) Address {
    return .{ .bytes = hash.bytes[12..32].* };
}

const testing = std.testing;

test "contract address: CREATE" {
    const sender = Address.comptime_hex("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0");
    const cases = [_]struct { nonce: u64, expected: []const u8 }{
        .{ .nonce = 0, .expected = "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d" },
        .{ .nonce = 1, .expected = "343c43a37d37dff08ae8c4a11544c718abb4fcf8" },
        .{ .nonce = 2, .expected = "f778b86fa74e846c4f0a1fbd1335fe81c00a0c91" },
        .{ .nonce = 3, .expected = "fffd933a0bc612844eaf0c6fe3e5b8e9b6c1d19c" },
    };
    for (cases) |case| {
        const expected = try Address.from_hex(case.expected);
        try testing.expect(create_address(sender, case.nonce).eql(expected));
    }
    // Multi-byte nonces take the long integer form; distinct nonces never collide.
    const a = create_address(sender, 0x80);
    const b = create_address(sender, std.math.maxInt(u64));
    try testing.expect(!a.eql(b) and !a.eql(create_address(sender, 0x7f)));
}

test "contract address: CREATE2 (EIP-1014 examples)" {
    const Case = struct { sender: []const u8, salt: []const u8, code: []const u8, out: []const u8 };
    const cases = [_]Case{
        .{
            .sender = "0000000000000000000000000000000000000000",
            .salt = "0000000000000000000000000000000000000000000000000000000000000000",
            .code = "00",
            .out = "4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38",
        },
        .{
            .sender = "deadbeef00000000000000000000000000000000",
            .salt = "000000000000000000000000feed000000000000000000000000000000000000",
            .code = "00",
            .out = "D04116cDd17beBE565EB2422F2497E06cC1C9833",
        },
        .{
            .sender = "00000000000000000000000000000000deadbeef",
            .salt = "00000000000000000000000000000000000000000000000000000000cafebabe",
            .code = "deadbeef",
            .out = "60f3f640a8508fC6a86d45DF051962668E1e8AC7",
        },
    };
    for (cases) |case| {
        var code: [4]u8 = undefined;
        const init_code = try @import("hex.zig").decode_into(&code, case.code);
        const derived = create2_address(
            try Address.from_hex(case.sender),
            try B256.from_hex(case.salt),
            bytes.keccak256(init_code),
        );
        try testing.expect(derived.eql(try Address.from_hex(case.out)));
    }
}

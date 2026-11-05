//! The node's secp256k1 identity key (base/base `peers/src/secrets.rs`). The key file
//! holds 32 bytes as hex (optional `0x`, surrounding whitespace ignored). Library code
//! never touches the filesystem: callers read or write the file through `utilities/io`
//! and pass contents here; generation draws from an injected `std.Random`.

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("secp256k1.zig");
const peer_id = @import("peer_id.zig");
const hex = @import("../../../common/primitives/hex.zig");

pub const Error = error{ InvalidHex, InvalidSecretKey };

/// Hex text length written to a key file (no prefix, no newline).
pub const file_length = secp256k1.secret_key_length * 2;

pub const NodeKey = struct {
    secret: secp256k1.SecretKey,
    public_key: secp256k1.PublicKey,

    pub fn from_secret(secret: secp256k1.SecretKey) Error!NodeKey {
        const public_key = secp256k1.public_key(secret) catch return error.InvalidSecretKey;
        assert(public_key[0] == 0x02 or public_key[0] == 0x03);
        return .{ .secret = secret, .public_key = public_key };
    }

    pub fn peer_id(key: *const NodeKey) peer_id_module.PeerId {
        return peer_id_module.from_public_key(key.public_key);
    }

    /// Writes the key-file text (`file_length` lowercase hex digits).
    pub fn to_file(key: *const NodeKey, output: *[file_length]u8) []const u8 {
        hex.encode(output, &key.secret);
        // `key.secret` was validated when the key was built.
        const derived = secp256k1.public_key(key.secret) catch unreachable;
        assert(std.mem.eql(u8, &derived, &key.public_key));
        return output;
    }
};

const peer_id_module = peer_id;

/// Parses key-file contents.
pub fn parse(contents: []const u8) Error!NodeKey {
    const trimmed = std.mem.trim(u8, contents, " \t\r\n");
    assert(trimmed.len <= contents.len);
    const secret = hex.decode_array(secp256k1.secret_key_length, trimmed) catch
        return error.InvalidHex;
    return NodeKey.from_secret(secret);
}

/// Generates a fresh key. Rejection sampling: a random 32-byte string is a valid scalar
/// with probability ~1 - 2^-128, so the bound of 64 attempts is never reached in practice.
pub fn generate(random: std.Random) NodeKey {
    var attempt: u32 = 0;
    while (attempt < 64) : (attempt += 1) {
        var secret: secp256k1.SecretKey = undefined;
        random.bytes(&secret);
        if (NodeKey.from_secret(secret)) |key| return key else |_| {}
    }
    @panic("node_key: random source produced 64 invalid scalars");
}

const Prng = @import("../../../testing/prng.zig").Prng;

test "node_key: generate, save, load" {
    var prng = Prng.init(0x6b6579);
    const key = generate(prng.random());
    var file: [file_length]u8 = undefined;
    const text = key.to_file(&file);
    const loaded = try parse(text);
    try std.testing.expectEqual(key.secret, loaded.secret);
    try std.testing.expectEqual(key.public_key, loaded.public_key);
    var padded: [file_length + 4]u8 = undefined;
    @memcpy(padded[0..2], "0x");
    @memcpy(padded[2 .. 2 + file_length], text);
    @memcpy(padded[2 + file_length ..], " \n");
    const reloaded = try parse(&padded);
    try std.testing.expect(reloaded.peer_id().eql(&key.peer_id()));
}

test "node_key: rejects bad files" {
    try std.testing.expectError(error.InvalidHex, parse("abc"));
    try std.testing.expectError(error.InvalidHex, parse(""));
    const zeros: [file_length]u8 = @splat('0');
    try std.testing.expectError(error.InvalidSecretKey, parse(&zeros));
}

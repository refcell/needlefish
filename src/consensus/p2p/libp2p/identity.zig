//! libp2p identity keys (libp2p `peer-ids` spec) for the secp256k1 key type OP Stack nodes
//! use. Unlike the ENR scheme in `peers/secp256k1.zig` (Keccak-256, raw `r || s`), libp2p
//! signs the SHA-256 digest of the message and encodes signatures in DER.
//!
//! Signing normalizes to low-s like libsecp256k1; verification accepts both halves, as the
//! rust and go libp2p implementations do. Only secp256k1 public keys are accepted from
//! peers; other key types are `UnsupportedKeyType`.

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../peers/secp256k1.zig");
const protobuf = @import("protobuf.zig");
const Curve = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const SecretKey = secp256k1.SecretKey;
pub const PublicKey = secp256k1.PublicKey;

pub const key_type_secp256k1 = 2;
/// Protobuf `PublicKey { Type = Secp256k1, Data = <33 bytes> }`.
pub const public_key_protobuf_length = 4 + secp256k1.compressed_length;
pub const signature_length_max = Ecdsa.Signature.der_encoded_length_max;

comptime {
    assert(public_key_protobuf_length == 37);
    assert(signature_length_max == 72);
}

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    UnsupportedKeyType,
};

const order_half: u256 = Curve.scalar.field_order / 2;

pub const Signature = struct {
    bytes: [signature_length_max]u8,
    length: u8,

    pub fn slice(signature: *const Signature) []const u8 {
        assert(signature.length >= 8);
        assert(signature.length <= signature_length_max);
        return signature.bytes[0..signature.length];
    }
};

/// DER-encoded, low-s ECDSA signature over SHA-256(`message`).
pub fn sign(secret: SecretKey, message: []const u8) Error!Signature {
    secp256k1.validate_secret_key(secret) catch return error.InvalidSecretKey;
    const secret_key = Ecdsa.SecretKey.fromBytes(secret) catch return error.InvalidSecretKey;
    const key_pair = Ecdsa.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSecretKey;
    var raw = key_pair.sign(message, null) catch return error.InvalidSecretKey;
    const s = std.mem.readInt(u256, &raw.s, .big);
    if (s > order_half) std.mem.writeInt(u256, &raw.s, Curve.scalar.field_order - s, .big);
    assert(std.mem.readInt(u256, &raw.s, .big) <= order_half);
    var result: Signature = .{ .bytes = undefined, .length = 0 };
    const der = raw.toDer(&result.bytes);
    result.length = @intCast(der.len);
    return result;
}

/// Checks a DER signature over SHA-256(`message`) against a compressed key.
pub fn verify(key: PublicKey, message: []const u8, der: []const u8) bool {
    if (der.len > signature_length_max) return false;
    const public = Ecdsa.PublicKey.fromSec1(&key) catch return false;
    const signature = Ecdsa.Signature.fromDer(der) catch return false;
    signature.verify(message, public) catch return false;
    return true;
}

/// Writes the protobuf `PublicKey` for a compressed secp256k1 key.
pub fn encode_public_key(output: []u8, key: PublicKey) []const u8 {
    assert(output.len >= public_key_protobuf_length);
    assert(key[0] == 0x02 or key[0] == 0x03);
    var writer = protobuf.Writer.init(output);
    writer.write_varint_field(1, key_type_secp256k1);
    writer.write_bytes_field(2, &key);
    assert(writer.length == public_key_protobuf_length);
    return writer.written();
}

/// Parses a protobuf `PublicKey`, requiring a valid compressed secp256k1 point.
pub fn decode_public_key(bytes: []const u8) Error!PublicKey {
    var reader = protobuf.Reader.init(bytes);
    var key_type: ?u64 = null;
    var data: ?[]const u8 = null;
    // Each field consumes at least two bytes, so this loop ends.
    while (reader.next() catch return error.InvalidPublicKey) |field| {
        switch (field.number) {
            1 => {
                if (field.wire_type != .varint) return error.InvalidPublicKey;
                key_type = field.value;
            },
            2 => {
                if (field.wire_type != .bytes) return error.InvalidPublicKey;
                data = field.bytes;
            },
            else => {},
        }
    }
    const kind = key_type orelse return error.InvalidPublicKey;
    if (kind != key_type_secp256k1) return error.UnsupportedKeyType;
    const sec1 = data orelse return error.InvalidPublicKey;
    if (sec1.len != secp256k1.compressed_length) return error.InvalidPublicKey;
    const key = secp256k1.compress(sec1) catch return error.InvalidPublicKey;
    assert(std.mem.eql(u8, &key, sec1));
    return key;
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "identity: sign and verify DER with low-s" {
    var prng = Prng.init(0x6964_656e);
    for (0..16) |_| {
        var secret: SecretKey = undefined;
        prng.fill(&secret);
        const key = secp256k1.public_key(secret) catch continue;
        var message: [40]u8 = undefined;
        prng.fill(&message);
        const signature = try sign(secret, &message);
        try std.testing.expectEqual(@as(u8, 0x30), signature.slice()[0]);
        try std.testing.expect(verify(key, &message, signature.slice()));
        const parsed = try Ecdsa.Signature.fromDer(signature.slice());
        try std.testing.expect(std.mem.readInt(u256, &parsed.s, .big) <= order_half);
        message[0] ^= 1;
        try std.testing.expect(!verify(key, &message, signature.slice()));
    }
}

test "identity: public key protobuf round trip" {
    var secret: SecretKey = @splat(0);
    secret[31] = 9;
    const key = try secp256k1.public_key(secret);
    var buffer: [public_key_protobuf_length]u8 = undefined;
    const encoded = encode_public_key(&buffer, key);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x02, 0x12, 0x21 }, encoded[0..4]);
    try std.testing.expectEqual(key, try decode_public_key(encoded));
    var ed25519 = buffer;
    ed25519[1] = 1;
    try std.testing.expectError(error.UnsupportedKeyType, decode_public_key(&ed25519));
    try std.testing.expectError(error.InvalidPublicKey, decode_public_key(buffer[0..10]));
    try std.testing.expectError(error.InvalidPublicKey, decode_public_key(&.{}));
}

fn fuzz_decode_public_key(_: void, input: []const u8) anyerror!void {
    const key = decode_public_key(input) catch return;
    var buffer: [public_key_protobuf_length]u8 = undefined;
    try std.testing.expectEqual(key, try decode_public_key(encode_public_key(&buffer, key)));
}

test "identity: fuzz decode public key" {
    try fuzz.run_bytes({}, fuzz_decode_public_key, .{ .input_size_max = 64 });
}

fn fuzz_verify(_: void, input: []const u8) anyerror!void {
    var secret: SecretKey = @splat(0);
    secret[31] = 3;
    const key = try secp256k1.public_key(secret);
    try std.testing.expect(!verify(key, "message", input));
}

test "identity: fuzz verify rejects garbage" {
    try fuzz.run_bytes({}, fuzz_verify, .{ .input_size_max = 80, .iterations = 64 });
}

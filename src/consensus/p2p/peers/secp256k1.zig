//! secp256k1 primitives the p2p stack needs: key derivation, Keccak-256 ECDSA as used
//! by the ENR `v4` identity scheme and discv5, and ECDH. Backed by `std.crypto` behind
//! this small interface so it can switch to `common/crypto` once the crypto lane lands
//! a secp256k1 implementation.
//!
//! Signatures are 64-byte `r || s`. Signing always produces low-s (s <= n/2), matching
//! libsecp256k1. Verification accepts both halves, like the `enr` and `discv5` crates.

const std = @import("std");
const assert = std.debug.assert;
const Curve = std.crypto.ecc.Secp256k1;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Curve, Keccak256);

pub const secret_key_length = 32;
pub const compressed_length = 33;
pub const uncompressed_length = 65;
pub const signature_length = 64;

pub const SecretKey = [secret_key_length]u8;
pub const PublicKey = [compressed_length]u8;
pub const Signature = [signature_length]u8;
pub const Digest = [32]u8;

pub const Error = error{
    /// Secret key is zero or not below the group order.
    InvalidSecretKey,
    /// Public key bytes do not decode to a point on the curve.
    InvalidPublicKey,
};

/// Half the group order: a signature with `s` above this is the high-s twin.
const order_half: u256 = Curve.scalar.field_order / 2;

/// Checks that `secret` is a valid scalar in `[1, n)`.
pub fn validate_secret_key(secret: SecretKey) Error!void {
    const value = std.mem.readInt(u256, &secret, .big);
    if (value == 0 or value >= Curve.scalar.field_order) return error.InvalidSecretKey;
}

/// Compressed SEC1 public key for `secret`.
pub fn public_key(secret: SecretKey) Error!PublicKey {
    try validate_secret_key(secret);
    const point = Curve.basePoint.mul(secret, .big) catch return error.InvalidSecretKey;
    const compressed = point.toCompressedSec1();
    assert(compressed[0] == 0x02 or compressed[0] == 0x03);
    return compressed;
}

/// Decodes a compressed (33) or uncompressed (65) SEC1 key and returns its compressed form.
pub fn compress(sec1: []const u8) Error!PublicKey {
    if (sec1.len != compressed_length and sec1.len != uncompressed_length) {
        return error.InvalidPublicKey;
    }
    const point = Curve.fromSec1(sec1) catch return error.InvalidPublicKey;
    point.rejectIdentity() catch return error.InvalidPublicKey;
    return point.toCompressedSec1();
}

/// Uncompressed SEC1 key (`0x04 || x || y`) for a compressed key.
pub fn decompress(key: PublicKey) Error![uncompressed_length]u8 {
    const point = Curve.fromSec1(&key) catch return error.InvalidPublicKey;
    point.rejectIdentity() catch return error.InvalidPublicKey;
    const uncompressed = point.toUncompressedSec1();
    assert(uncompressed[0] == 0x04);
    return uncompressed;
}

/// Signs a 32-byte digest deterministically, returning a low-s `r || s` signature.
pub fn sign_digest(secret: SecretKey, digest: Digest) Error!Signature {
    try validate_secret_key(secret);
    const secret_key = Ecdsa.SecretKey.fromBytes(secret) catch return error.InvalidSecretKey;
    const key_pair = Ecdsa.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSecretKey;
    const signature = key_pair.signPrehashed(digest, null) catch return error.InvalidSecretKey;
    var bytes = signature.toBytes();
    const s = std.mem.readInt(u256, bytes[32..64], .big);
    if (s > order_half) {
        std.mem.writeInt(u256, bytes[32..64], Curve.scalar.field_order - s, .big);
    }
    assert(std.mem.readInt(u256, bytes[32..64], .big) <= order_half);
    return bytes;
}

/// Verifies an `r || s` signature over a 32-byte digest.
pub fn verify_digest(key: PublicKey, digest: Digest, signature: Signature) bool {
    const public = Ecdsa.PublicKey.fromSec1(&key) catch return false;
    const parsed = Ecdsa.Signature.fromBytes(signature);
    parsed.verifyPrehashed(digest, public) catch return false;
    return true;
}

/// ECDH: compressed encoding of `secret * remote`. discv5 uses the full compressed point.
pub fn ecdh(secret: SecretKey, remote: PublicKey) Error!PublicKey {
    try validate_secret_key(secret);
    const point = Curve.fromSec1(&remote) catch return error.InvalidPublicKey;
    point.rejectIdentity() catch return error.InvalidPublicKey;
    const shared = point.mul(secret, .big) catch return error.InvalidPublicKey;
    return shared.toCompressedSec1();
}

/// Keccak-256 digest helper shared by the ENR and discv5 code.
pub fn keccak256(parts: []const []const u8) Digest {
    var hasher = Keccak256.init(.{});
    for (parts) |part| hasher.update(part);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

const Prng = @import("../../../testing/prng.zig").Prng;

test "secp256k1: sign and verify round trip with low-s" {
    var prng = Prng.init(0x736563);
    for (0..16) |_| {
        var secret: SecretKey = undefined;
        prng.fill(&secret);
        validate_secret_key(secret) catch continue;
        const key = try public_key(secret);
        var digest: Digest = undefined;
        prng.fill(&digest);
        const signature = try sign_digest(secret, digest);
        try std.testing.expect(verify_digest(key, digest, signature));
        digest[0] ^= 1;
        try std.testing.expect(!verify_digest(key, digest, signature));
    }
}

test "secp256k1: high-s twin still verifies" {
    var secret: SecretKey = @splat(0);
    secret[31] = 7;
    const key = try public_key(secret);
    const digest = keccak256(&.{"needlefish"});
    var signature = try sign_digest(secret, digest);
    const s = std.mem.readInt(u256, signature[32..64], .big);
    std.mem.writeInt(u256, signature[32..64], Curve.scalar.field_order - s, .big);
    try std.testing.expect(verify_digest(key, digest, signature));
}

test "secp256k1: ecdh is symmetric" {
    var a: SecretKey = @splat(0x11);
    var b: SecretKey = @splat(0x22);
    a[0] = 1;
    b[0] = 2;
    const shared_ab = try ecdh(a, try public_key(b));
    const shared_ba = try ecdh(b, try public_key(a));
    try std.testing.expectEqualSlices(u8, &shared_ab, &shared_ba);
}

test "secp256k1: rejects invalid keys" {
    try std.testing.expectError(error.InvalidSecretKey, public_key(@splat(0)));
    try std.testing.expectError(error.InvalidSecretKey, public_key(@splat(0xff)));
    var bad: PublicKey = @splat(0);
    bad[0] = 0x02;
    try std.testing.expectError(error.InvalidPublicKey, decompress(bad));
    try std.testing.expectError(error.InvalidPublicKey, compress(&.{ 1, 2, 3 }));
}

//! secp256k1 primitives the p2p stack needs: key derivation, Keccak-256 ECDSA as used
//! by the ENR `v4` identity scheme and discv5, and ECDH. A thin adapter from compressed
//! SEC1 keys and `r || s` signatures onto `common.crypto.secp256k1` (2-7x faster than
//! `std.crypto` and constant time in secrets).
//!
//! Signatures are 64-byte `r || s`. Signing always produces low-s (s <= n/2) with an
//! RFC 6979 nonce, matching libsecp256k1. Verification accepts both halves, like the
//! `enr` and `discv5` crates.

const std = @import("std");
const assert = std.debug.assert;
const curve = @import("../../../common/crypto/secp256k1/root.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

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

/// The group order n.
const order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

comptime {
    assert(order == std.crypto.ecc.Secp256k1.scalar.field_order);
}

/// Checks that `secret` is a valid scalar in `[1, n)`.
pub fn validate_secret_key(secret: SecretKey) Error!void {
    const value = std.mem.readInt(u256, &secret, .big);
    if (value == 0 or value >= order) return error.InvalidSecretKey;
}

/// Compressed SEC1 public key for `secret`.
pub fn public_key(secret: SecretKey) Error!PublicKey {
    try validate_secret_key(secret);
    const public = curve.public_key(secret) catch return error.InvalidSecretKey;
    // A key derived from a valid scalar is always on the curve.
    const compressed = curve.compress_public_key(&public) orelse unreachable;
    assert(compressed[0] == 0x02 or compressed[0] == 0x03);
    return compressed;
}

/// Decodes a compressed (33) or uncompressed (65) SEC1 key and returns its compressed form.
pub fn compress(sec1: []const u8) Error!PublicKey {
    if (sec1.len == compressed_length) {
        const key: PublicKey = sec1[0..compressed_length].*;
        _ = try decompress(key);
        return key;
    }
    if (sec1.len != uncompressed_length or sec1[0] != 0x04) return error.InvalidPublicKey;
    return curve.compress_public_key(sec1[1..uncompressed_length]) orelse
        error.InvalidPublicKey;
}

/// Uncompressed SEC1 key (`0x04 || x || y`) for a compressed key.
pub fn decompress(key: PublicKey) Error![uncompressed_length]u8 {
    const public = curve.decompress_public_key(&key) orelse return error.InvalidPublicKey;
    var uncompressed: [uncompressed_length]u8 = undefined;
    uncompressed[0] = 0x04;
    uncompressed[1..uncompressed_length].* = public;
    assert(uncompressed[0] == 0x04);
    return uncompressed;
}

/// Signs a 32-byte digest deterministically, returning a low-s `r || s` signature.
pub fn sign_digest(secret: SecretKey, digest: Digest) Error!Signature {
    try validate_secret_key(secret);
    const signature = curve.sign(secret, digest) catch return error.InvalidSecretKey;
    var bytes: Signature = undefined;
    bytes[0..32].* = signature.r;
    bytes[32..64].* = signature.s;
    assert(curve.is_low_s(signature.s));
    return bytes;
}

/// Verifies an `r || s` signature over a 32-byte digest.
pub fn verify_digest(key: PublicKey, digest: Digest, signature: Signature) bool {
    const public = curve.decompress_public_key(&key) orelse return false;
    return curve.verify(digest, signature[0..32].*, signature[32..64].*, &public);
}

/// ECDH: compressed encoding of `secret * remote`. discv5 uses the full compressed point.
pub fn ecdh(secret: SecretKey, remote: PublicKey) Error!PublicKey {
    try validate_secret_key(secret);
    const public = curve.decompress_public_key(&remote) orelse return error.InvalidPublicKey;
    return curve.ecdh(secret, &public) catch |err| switch (err) {
        error.InvalidPrivateKey => error.InvalidSecretKey,
        error.InvalidPublicKey => error.InvalidPublicKey,
    };
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
    std.mem.writeInt(u256, signature[32..64], order - s, .big);
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

test "secp256k1: matches std.crypto on keys, ECDH, and cross verification" {
    const Curve = std.crypto.ecc.Secp256k1;
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Curve, Keccak256);
    var prng = Prng.init(0x5ec9);
    for (0..32) |_| {
        var secret: SecretKey = undefined;
        prng.fill(&secret);
        validate_secret_key(secret) catch continue;
        const key = try public_key(secret);
        const expected = (try Curve.basePoint.mul(secret, .big)).toCompressedSec1();
        try std.testing.expectEqualSlices(u8, &expected, &key);
        var other: SecretKey = undefined;
        prng.fill(&other);
        validate_secret_key(other) catch continue;
        const remote = try public_key(other);
        const shared = try ecdh(secret, remote);
        const point = try Curve.fromSec1(&remote);
        const std_shared = (try point.mul(secret, .big)).toCompressedSec1();
        try std.testing.expectEqualSlices(u8, &std_shared, &shared);
        // Our signatures verify under std, and std's under ours.
        var digest: Digest = undefined;
        prng.fill(&digest);
        const ours = try sign_digest(secret, digest);
        const std_public = try Ecdsa.PublicKey.fromSec1(&key);
        try Ecdsa.Signature.fromBytes(ours).verifyPrehashed(digest, std_public);
        const pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret));
        const theirs = (try pair.signPrehashed(digest, null)).toBytes();
        try std.testing.expect(verify_digest(key, digest, theirs));
        // Uncompressed round trip.
        try std.testing.expectEqualSlices(u8, &key, &try compress(&try decompress(key)));
    }
}

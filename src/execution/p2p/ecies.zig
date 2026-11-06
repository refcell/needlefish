//! ECIES as used by the RLPx handshake (devp2p `rlpx.md`): secp256k1 ECDH, the NIST
//! SP 800-56 concatenation KDF over SHA-256, AES-128-CTR, and HMAC-SHA-256 over
//! `iv || ciphertext || shared_mac_data`.
//!
//!   encrypt(K, m, s2) = R || iv || AES-128-CTR(kE, iv, m) || HMAC-SHA-256(kM, iv || c || s2)
//!
//! `R = r * G` is the sender's ephemeral public key (65 bytes, uncompressed),
//! `kE || kM' = KDF(x(r * K), 32)`, and `kM = SHA-256(kM')`. Randomness comes from the
//! caller, so the codec is deterministic under test.

const std = @import("std");
const assert = std.debug.assert;
const curve = @import("../../common/crypto/secp256k1/root.zig");

const Aes128 = std.crypto.core.aes.Aes128;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const public_key_length = 65;
pub const iv_length = 16;
pub const mac_length = 32;
/// Bytes `encrypt` adds to the plaintext.
pub const overhead = public_key_length + iv_length + mac_length;

pub const Error = error{ InvalidPublicKey, InvalidPrivateKey, TooShort, BadMac };

/// The x coordinate of `private_key * public` (the ECDH shared secret RLPx uses).
pub fn shared_x(private_key: [32]u8, public: *const curve.PublicKey) Error![32]u8 {
    const compressed = curve.ecdh(private_key, public) catch |err| switch (err) {
        error.InvalidPublicKey => return error.InvalidPublicKey,
        error.InvalidPrivateKey => return error.InvalidPrivateKey,
    };
    assert(compressed[0] == 2 or compressed[0] == 3);
    return compressed[1..33].*;
}

/// `kE` (AES-128 key) and `kM` (HMAC key) from the shared secret.
fn derive_keys(shared: [32]u8) struct { encryption: [16]u8, mac: [32]u8 } {
    // Concatenation KDF: SHA-256(counter_be32 || Z), one round for 32 bytes, no s1.
    var hasher = Sha256.init(.{});
    hasher.update(&.{ 0, 0, 0, 1 });
    hasher.update(&shared);
    const key = hasher.finalResult();
    var mac: [32]u8 = undefined;
    Sha256.hash(key[16..32], &mac, .{});
    return .{ .encryption = key[0..16].*, .mac = mac };
}

fn aes128_ctr(key: [16]u8, iv: [iv_length]u8, destination: []u8, source: []const u8) void {
    assert(destination.len == source.len);
    const context = Aes128.initEnc(key);
    std.crypto.core.modes.ctr(@TypeOf(context), context, destination, source, iv, .big);
}

fn tag(mac_key: [32]u8, iv: []const u8, ciphertext: []const u8, shared_mac: []const u8) [32]u8 {
    var hmac = HmacSha256.init(&mac_key);
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.update(shared_mac);
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// Encrypts `plaintext` to `remote` into `output` (`plaintext.len + overhead` bytes).
/// `ephemeral_secret` and `iv` must be fresh random values.
pub fn encrypt(
    remote: *const curve.PublicKey,
    plaintext: []const u8,
    shared_mac: []const u8,
    ephemeral_secret: [32]u8,
    iv: [iv_length]u8,
    output: []u8,
) Error![]u8 {
    assert(output.len >= plaintext.len + overhead);
    const ephemeral = curve.public_key(ephemeral_secret) catch return error.InvalidPrivateKey;
    const keys = derive_keys(try shared_x(ephemeral_secret, remote));
    output[0] = 4;
    output[1..65].* = ephemeral;
    output[65..81].* = iv;
    const ciphertext = output[81..][0..plaintext.len];
    aes128_ctr(keys.encryption, iv, ciphertext, plaintext);
    const mac = tag(keys.mac, &iv, ciphertext, shared_mac);
    output[81 + plaintext.len ..][0..mac_length].* = mac;
    const length = plaintext.len + overhead;
    assert(output[0] == 4);
    return output[0..length];
}

/// Decrypts a message to `private_key` into `output` (`message.len - overhead` bytes).
pub fn decrypt(
    private_key: [32]u8,
    message: []const u8,
    shared_mac: []const u8,
    output: []u8,
) Error![]u8 {
    if (message.len < overhead or message[0] != 4) return error.TooShort;
    const length = message.len - overhead;
    assert(output.len >= length);
    const sender: curve.PublicKey = message[1..65].*;
    const keys = derive_keys(try shared_x(private_key, &sender));
    const iv = message[65..81];
    const ciphertext = message[81..][0..length];
    const expected = tag(keys.mac, iv, ciphertext, shared_mac);
    const received = message[81 + length ..][0..mac_length];
    if (!std.crypto.timing_safe.eql([32]u8, expected, received.*)) return error.BadMac;
    aes128_ctr(keys.encryption, iv.*, output[0..length], ciphertext);
    assert(output.len >= length);
    return output[0..length];
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn random_secret(prng: *Prng) [32]u8 {
    while (true) {
        var secret: [32]u8 = undefined;
        prng.fill(&secret);
        _ = curve.public_key(secret) catch continue;
        return secret;
    }
}

test "ecies: round trip, and any flipped byte or wrong key fails" {
    var prng = Prng.init(1);
    for (0..16) |_| {
        const secret = random_secret(&prng);
        const public = try curve.public_key(secret);
        var plaintext: [200]u8 = undefined;
        const length: usize = @intCast(prng.range(0, plaintext.len));
        prng.fill(plaintext[0..length]);
        var iv: [16]u8 = undefined;
        prng.fill(&iv);
        var sealed: [200 + overhead]u8 = undefined;
        const ephemeral = random_secret(&prng);
        const message = try encrypt(&public, plaintext[0..length], "s2", ephemeral, iv, &sealed);
        try testing.expectEqual(length + overhead, message.len);
        var opened: [200]u8 = undefined;
        const result = try decrypt(secret, message, "s2", &opened);
        try testing.expectEqualSlices(u8, plaintext[0..length], result);
        try testing.expectError(error.BadMac, decrypt(secret, message, "s3", &opened));
        const other = random_secret(&prng);
        try testing.expectError(error.BadMac, decrypt(other, message, "s2", &opened));
        const flip: usize = @intCast(prng.range(65, message.len - 1));
        message[flip] ^= 0x40;
        try testing.expectError(error.BadMac, decrypt(secret, message, "s2", &opened));
    }
}

//! discv5 handshake cryptography for the `v4` identity scheme (devp2p
//! `discv5-theory.md`, "Handshake Steps"): session key derivation and the identity proof.
//!
//!     secret   = ecdh(dest-pubkey, ephemeral-key)          (33-byte compressed point)
//!     prk      = HKDF-Extract(salt = challenge-data, ikm = secret)
//!     key-data = HKDF-Expand(prk, "discovery v5 key agreement" || id-a || id-b, 32)
//!     id-signature = sign(sha256("discovery v5 identity proof" || challenge-data
//!                                 || ephemeral-pubkey || id-b))

const std = @import("std");
const assert = std.debug.assert;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const secp256k1 = @import("../peers/secp256k1.zig");
const packet = @import("packet.zig");

pub const kdf_info_text = "discovery v5 key agreement";
pub const id_signature_text = "discovery v5 identity proof";
/// Challenge data is `masking-iv || static-header || whoareyou-authdata`.
pub const challenge_length = packet.masking_iv_length + packet.static_header_length +
    packet.whoareyou_authdata_length;

pub const SessionKeys = struct {
    initiator_key: packet.Key,
    recipient_key: packet.Key,
};

/// Derives session keys from an ECDH shared secret.
pub fn derive_keys_from_secret(
    shared_secret: secp256k1.PublicKey,
    initiator_id: packet.NodeId,
    recipient_id: packet.NodeId,
    challenge_data: []const u8,
) SessionKeys {
    assert(challenge_data.len == challenge_length);
    assert(shared_secret[0] == 0x02 or shared_secret[0] == 0x03);
    const prk = HkdfSha256.extract(challenge_data, &shared_secret);
    var info: [kdf_info_text.len + 64]u8 = undefined;
    @memcpy(info[0..kdf_info_text.len], kdf_info_text);
    @memcpy(info[kdf_info_text.len..][0..32], &initiator_id);
    @memcpy(info[kdf_info_text.len + 32 ..][0..32], &recipient_id);
    var key_data: [32]u8 = undefined;
    HkdfSha256.expand(&key_data, &info, prk);
    return .{ .initiator_key = key_data[0..16].*, .recipient_key = key_data[16..32].* };
}

/// Initiator side: ECDH of our ephemeral secret with the recipient's static key.
pub fn derive_keys(
    ephemeral_secret: secp256k1.SecretKey,
    recipient_public_key: secp256k1.PublicKey,
    initiator_id: packet.NodeId,
    recipient_id: packet.NodeId,
    challenge_data: []const u8,
) secp256k1.Error!SessionKeys {
    const shared = try secp256k1.ecdh(ephemeral_secret, recipient_public_key);
    return derive_keys_from_secret(shared, initiator_id, recipient_id, challenge_data);
}

fn id_signature_digest(
    challenge_data: []const u8,
    ephemeral_public_key: secp256k1.PublicKey,
    recipient_id: packet.NodeId,
) secp256k1.Digest {
    assert(challenge_data.len == challenge_length);
    var hasher = Sha256.init(.{});
    hasher.update(id_signature_text);
    hasher.update(challenge_data);
    hasher.update(&ephemeral_public_key);
    hasher.update(&recipient_id);
    return hasher.finalResult();
}

pub fn id_sign(
    static_secret: secp256k1.SecretKey,
    challenge_data: []const u8,
    ephemeral_public_key: secp256k1.PublicKey,
    recipient_id: packet.NodeId,
) secp256k1.Error!secp256k1.Signature {
    const digest = id_signature_digest(challenge_data, ephemeral_public_key, recipient_id);
    return secp256k1.sign_digest(static_secret, digest);
}

pub fn id_verify(
    public_key: secp256k1.PublicKey,
    signature: secp256k1.Signature,
    challenge_data: []const u8,
    ephemeral_public_key: secp256k1.PublicKey,
    recipient_id: packet.NodeId,
) bool {
    const digest = id_signature_digest(challenge_data, ephemeral_public_key, recipient_id);
    return secp256k1.verify_digest(public_key, digest, signature);
}

const hex = @import("../../../common/primitives/hex.zig");

// Vectors from devp2p `discv5-wire-test-vectors.md`. The spec's private keys are not
// committed (AGENTS rule 3); only public keys and derived values appear below.
const node_id_a = "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb";
const node_id_b = "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9";
const challenge_hex = "000000000000000000000000000000006469736376350001010102030405060708090a" ++
    "0b0c00180102030405060708090a0b0c0d0e0f100000000000000000";

test "disc crypto: key derivation vector" {
    // ecdh(dest-pubkey 0317931e..., ephemeral-key fb757dc5...), computed offline.
    const shared = try hex.decode_array(33, "022c82f214eb37159111712add00040fcdf73fd4d7d0b7c0f9" ++
        "80da4d099aa59ba4");
    const challenge = try hex.decode_array(challenge_length, challenge_hex);
    const keys = derive_keys_from_secret(
        shared,
        try hex.decode_array(32, node_id_a),
        try hex.decode_array(32, node_id_b),
        &challenge,
    );
    try std.testing.expectEqual(
        try hex.decode_array(16, "dccc82d81bd610f4f76d3ebe97a40571"),
        keys.initiator_key,
    );
    try std.testing.expectEqual(
        try hex.decode_array(16, "ac74bb8773749920b0d3a8881c173ec5"),
        keys.recipient_key,
    );
}

test "disc crypto: id signature vector verifies" {
    // Public key of the vector's static-key fb757dc5..., computed offline.
    const public_key = try hex.decode_array(33, "030e2cb74241c0c4fc8e8166f1a79a05d5b0" ++
        "dd95813a74b094529f317d5c39d235");
    const signature = try hex.decode_array(64, "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06" ++
        "ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6");
    const ephemeral = try hex.decode_array(33, "039961e4c2356d61bedb83052c115d311acb3a96f577729" ++
        "6dcf297351130266231");
    const challenge = try hex.decode_array(challenge_length, challenge_hex);
    const recipient = try hex.decode_array(32, node_id_b);
    try std.testing.expect(id_verify(public_key, signature, &challenge, ephemeral, recipient));
    var wrong = recipient;
    wrong[0] ^= 1;
    try std.testing.expect(!id_verify(public_key, signature, &challenge, ephemeral, wrong));
}

test "disc crypto: both sides derive the same keys and sign/verify" {
    var static_a: secp256k1.SecretKey = @splat(0x0a);
    var static_b: secp256k1.SecretKey = @splat(0x0b);
    var ephemeral: secp256k1.SecretKey = @splat(0x0e);
    static_a[0] = 1;
    static_b[0] = 1;
    ephemeral[0] = 1;
    const public_b = try secp256k1.public_key(static_b);
    const public_ephemeral = try secp256k1.public_key(ephemeral);
    const id_a: packet.NodeId = @splat(0xaa);
    const id_b: packet.NodeId = @splat(0xbb);
    const challenge = try hex.decode_array(challenge_length, challenge_hex);
    const initiator = try derive_keys(ephemeral, public_b, id_a, id_b, &challenge);
    const recipient = try derive_keys(static_b, public_ephemeral, id_a, id_b, &challenge);
    try std.testing.expectEqual(initiator, recipient);
    const signature = try id_sign(static_a, &challenge, public_ephemeral, id_b);
    const public_a = try secp256k1.public_key(static_a);
    try std.testing.expect(id_verify(public_a, signature, &challenge, public_ephemeral, id_b));
}

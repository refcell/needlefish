//! ECDSA secp256k1 signatures as used by Ethereum transactions and authorizations.
//!
//! Recovery and signing here are a correctness-first fallback built on
//! `std.crypto.ecc.Secp256k1`. The crypto lane owns the optimized implementation;
//! callers that need throughput go through `Recoverer` so it can be swapped in.
//! `sign` is deterministic (RFC 6979, HMAC-SHA256) but NOT constant time: it exists
//! for tests and the public devnet accounts only.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;

const Curve = std.crypto.ecc.Secp256k1;
const Scalar = Curve.scalar.Scalar;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Order of the secp256k1 group.
pub const curve_order: u256 =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
pub const curve_order_half: u256 = curve_order / 2;

pub const Signature = struct {
    y_parity: bool,
    r: u256,
    s: u256,

    /// r and s in [1, n).
    pub fn is_in_range(signature: Signature) bool {
        return signature.r > 0 and signature.r < curve_order and
            signature.s > 0 and signature.s < curve_order;
    }

    /// EIP-2: transaction signatures must have s <= n / 2.
    pub fn is_low_s(signature: Signature) bool {
        return signature.s <= curve_order_half;
    }

    /// Legacy `v` value: 27/28 pre-EIP-155, `chain_id * 2 + 35 + parity` after.
    pub fn legacy_v(signature: Signature, chain_id: ?u64) u256 {
        const parity: u256 = @intFromBool(signature.y_parity);
        if (chain_id) |id| return @as(u256, id) * 2 + 35 + parity;
        return 27 + parity;
    }

    /// The 65-byte `r || s || v` form with `v` in {0, 1}.
    pub fn to_bytes(signature: Signature) [65]u8 {
        var out: [65]u8 = undefined;
        out[0..32].* = primitives.u256_to_bytes(signature.r);
        out[32..64].* = primitives.u256_to_bytes(signature.s);
        out[64] = @intFromBool(signature.y_parity);
        return out;
    }
};

pub const LegacyV = struct { y_parity: bool, chain_id: ?u64 };

/// Splits a legacy `v` into parity and optional chain id; null when malformed.
pub fn decode_legacy_v(v: u256) ?LegacyV {
    if (v == 27 or v == 28) return .{ .y_parity = v == 28, .chain_id = null };
    if (v < 35) return null;
    const chain_id = (v - 35) / 2;
    if (chain_id > std.math.maxInt(u64)) return null;
    return .{ .y_parity = (v - 35) % 2 == 1, .chain_id = @intCast(chain_id) };
}

/// Pluggable sender recovery, so hot paths can use the crypto lane's ecrecover.
pub const Recoverer = *const fn (hash: B256, signature: Signature) ?Address;

/// Address of an uncompressed public key (`x || y`, 64 bytes).
pub fn address_from_public_key(public_key: [64]u8) Address {
    const digest = primitives.keccak256(&public_key);
    return Address.from_slice(digest.bytes[12..32]);
}

fn hash_scalar(hash: B256) Scalar {
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = hash.bytes;
    return Scalar.fromBytes48(wide, .big);
}

/// Recovers the uncompressed public key that produced `signature` over `hash`.
/// Accepts high-s; callers enforce EIP-2 where required.
pub fn recover_public_key(hash: B256, signature: Signature) ?[64]u8 {
    if (!signature.is_in_range()) return null;
    const r_bytes = primitives.u256_to_bytes(signature.r);
    const x = Curve.Fe.fromBytes(r_bytes, .big) catch return null;
    const y = Curve.recoverY(x, signature.y_parity) catch return null;
    const point_r = Curve.fromAffineCoordinates(.{ .x = x, .y = y }) catch return null;
    const r_scalar = Scalar.fromBytes(r_bytes, .big) catch return null;
    const s_bytes = primitives.u256_to_bytes(signature.s);
    const s_scalar = Scalar.fromBytes(s_bytes, .big) catch return null;
    const r_inverse = r_scalar.invert();
    const scalar_g = hash_scalar(hash).neg().mul(r_inverse);
    const scalar_r = s_scalar.mul(r_inverse);
    const point_q = Curve.mulDoubleBasePublic(
        Curve.basePoint,
        scalar_g.toBytes(.big),
        point_r,
        scalar_r.toBytes(.big),
        .big,
    ) catch return null;
    const sec1 = point_q.toUncompressedSec1();
    assert(sec1[0] == 0x04);
    return sec1[1..65].*;
}

/// Default `Recoverer`: std-based fallback.
pub fn recover_address(hash: B256, signature: Signature) ?Address {
    const public_key = recover_public_key(hash, signature) orelse return null;
    return address_from_public_key(public_key);
}

/// Public key for a private key; null when the key is zero or >= n.
pub fn public_key_from_private(private_key: [32]u8) ?[64]u8 {
    const d = primitives.u256_from_bytes(private_key);
    if (d == 0 or d >= curve_order) return null;
    const point = Curve.basePoint.mul(private_key, .big) catch return null;
    return point.toUncompressedSec1()[1..65].*;
}

pub fn address_from_private(private_key: [32]u8) ?Address {
    return address_from_public_key(public_key_from_private(private_key) orelse return null);
}

/// RFC 6979 nonce for secp256k1 / HMAC-SHA256. Bounded: each retry has probability
/// below 2^-127, so 16 attempts never fail in practice; exhausting them is a bug.
fn rfc6979_nonce(private_key: [32]u8, hash: B256) [32]u8 {
    const h1 = hash_scalar(hash).toBytes(.big);
    var v: [32]u8 = @splat(0x01);
    var k: [32]u8 = @splat(0x00);
    inline for (.{ 0x00, 0x01 }) |separator| {
        var mac = HmacSha256.init(&k);
        mac.update(&v);
        mac.update(&.{separator});
        mac.update(&private_key);
        mac.update(&h1);
        mac.final(&k);
        HmacSha256.create(&v, &v, &k);
    }
    for (0..16) |_| {
        HmacSha256.create(&v, &v, &k);
        const candidate = primitives.u256_from_bytes(v);
        if (candidate > 0 and candidate < curve_order) return v;
        var mac = HmacSha256.init(&k);
        mac.update(&v);
        mac.update(&.{0x00});
        mac.final(&k);
        HmacSha256.create(&v, &v, &k);
    }
    unreachable; // Probability < 2^-2000.
}

pub const SignError = error{InvalidPrivateKey};

/// Deterministic low-s signature over a 32-byte prehash. Not constant time.
pub fn sign(private_key: [32]u8, hash: B256) SignError!Signature {
    const d = Scalar.fromBytes(private_key, .big) catch return error.InvalidPrivateKey;
    if (d.isZero()) return error.InvalidPrivateKey;
    const k_bytes = rfc6979_nonce(private_key, hash);
    const point = Curve.basePoint.mul(k_bytes, .big) catch unreachable; // k in [1, n).
    const affine = point.affineCoordinates();
    const x_value = primitives.u256_from_bytes(affine.x.toBytes(.big));
    // x >= n happens with probability ~2^-128; reduce like every implementation does.
    const r_value = x_value % curve_order;
    assert(r_value != 0);
    const r_scalar = Scalar.fromBytes(primitives.u256_to_bytes(r_value), .big) catch unreachable;
    const k = Scalar.fromBytes(k_bytes, .big) catch unreachable;
    const s_scalar = k.invert().mul(hash_scalar(hash).add(r_scalar.mul(d)));
    var s_value = primitives.u256_from_bytes(s_scalar.toBytes(.big));
    var y_parity = affine.y.isOdd();
    if (s_value > curve_order_half) {
        s_value = curve_order - s_value;
        y_parity = !y_parity;
    }
    const signature: Signature = .{ .y_parity = y_parity, .r = r_value, .s = s_value };
    assert(signature.is_in_range() and signature.is_low_s());
    return signature;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "signature: dev account address" {
    // First account of the public `test test ... junk` devnet mnemonic.
    const key = try primitives.hex.decode_array(
        32,
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    const expected = Address.comptime_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    try testing.expect(address_from_private(key).?.eql(expected));
}

test "signature: sign and recover" {
    var prng = Prng.init(0x5167);
    for (0..24) |_| {
        var key: [32]u8 = undefined;
        prng.fill(&key);
        key[0] &= 0x7f;
        var hash: B256 = undefined;
        prng.fill(&hash.bytes);
        const signature = try sign(key, hash);
        try testing.expect(recover_address(hash, signature).?.eql(address_from_private(key).?));
        var flipped = signature;
        flipped.y_parity = !flipped.y_parity;
        const wrong = recover_address(hash, flipped);
        try testing.expect(wrong == null or !wrong.?.eql(address_from_private(key).?));
    }
    try testing.expectError(error.InvalidPrivateKey, sign(@splat(0), B256.zero));
    try testing.expect(recover_address(B256.zero, .{ .y_parity = false, .r = 0, .s = 1 }) == null);
}

test "signature: legacy v" {
    const sig: Signature = .{ .y_parity = true, .r = 1, .s = 1 };
    try testing.expectEqual(@as(u256, 28), sig.legacy_v(null));
    try testing.expectEqual(@as(u256, 38), sig.legacy_v(1));
    try testing.expectEqual(@as(?u64, 1), decode_legacy_v(38).?.chain_id);
    try testing.expect(decode_legacy_v(37).?.y_parity == false);
    try testing.expect(decode_legacy_v(29) == null);
    try testing.expect(decode_legacy_v(std.math.maxInt(u256)) == null);
}

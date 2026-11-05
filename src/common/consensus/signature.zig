//! ECDSA secp256k1 signatures as used by Ethereum transactions and authorizations.
//!
//! Recovery and signing delegate to the crypto lane's `secp256k1` (GLV recovery,
//! constant-time RFC 6979 signing). Hot paths still take a `Recoverer` so a batch or
//! cached recoverer can be swapped in.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;

const secp256k1 = @import("../crypto/secp256k1/root.zig");

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

/// Recovers the uncompressed public key that produced `signature` over `hash`.
/// Accepts high-s; callers enforce EIP-2 where required.
pub fn recover_public_key(hash: B256, signature: Signature) ?[64]u8 {
    if (!signature.is_in_range()) return null;
    return secp256k1.ecrecover(
        hash.bytes,
        @intFromBool(signature.y_parity),
        primitives.u256_to_bytes(signature.r),
        primitives.u256_to_bytes(signature.s),
    );
}

/// Default `Recoverer`.
pub fn recover_address(hash: B256, signature: Signature) ?Address {
    const public_key = recover_public_key(hash, signature) orelse return null;
    return address_from_public_key(public_key);
}

/// Public key for a private key; null when the key is zero or >= n.
pub fn public_key_from_private(private_key: [32]u8) ?[64]u8 {
    return secp256k1.public_key(private_key) catch null;
}

pub fn address_from_private(private_key: [32]u8) ?Address {
    return address_from_public_key(public_key_from_private(private_key) orelse return null);
}

pub const SignError = error{
    InvalidPrivateKey,
    /// R.x >= n (probability ~2^-128): Ethereum's one-bit parity cannot express it.
    UnrepresentableSignature,
};

/// Deterministic (RFC 6979) low-s signature over a 32-byte prehash. Constant time.
pub fn sign(private_key: [32]u8, hash: B256) SignError!Signature {
    const raw = try secp256k1.sign(private_key, hash.bytes);
    if (raw.recovery_id & 2 != 0) return error.UnrepresentableSignature;
    const signature: Signature = .{
        .y_parity = raw.recovery_id & 1 == 1,
        .r = primitives.u256_from_bytes(raw.r),
        .s = primitives.u256_from_bytes(raw.s),
    };
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

test "signature: ethereum/tests keyaddrtest vectors" {
    // BasicTests/keyaddrtest.json: brain-wallet key = keccak256(seed), key -> address.
    // `sig_of_emptystring` is not checked: the vector does not say which digest was signed.
    const text = @embedFile("testdata/keyaddrtest.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.value.array.items.len);
    for (parsed.value.array.items) |vector| {
        const object = vector.object;
        const key = try primitives.hex.decode_array(32, object.get("key").?.string);
        const seed = object.get("seed").?.string;
        try testing.expectEqualSlices(u8, &primitives.keccak256(seed).bytes, &key);
        const expected = try Address.from_hex(object.get("addr").?.string);
        try testing.expect(address_from_private(key).?.eql(expected));
    }
}

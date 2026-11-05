//! SEC1 key encoding, plain ECDSA verification, and constant-time ECDH, checked
//! against the Zig standard library secp256k1 as an oracle.

const std = @import("std");
const testing = std.testing;
const secp = @import("root.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const Scalar = secp.scalar.Scalar;
const Fe = secp.field.Fe;
const StdCurve = std.crypto.ecc.Secp256k1;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

const n_int = secp.scalar.n_int;
const p_int = secp.field.p_int;

fn int_bytes(value: u256) [32]u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return bytes;
}

fn random_private_key(prng: *Prng) [32]u8 {
    while (true) {
        var key: [32]u8 = undefined;
        prng.fill(&key);
        const value = std.mem.readInt(u256, &key, .big);
        if (value != 0 and value < n_int) return key;
    }
}

fn sec1_uncompressed(public: *const secp.PublicKey) [65]u8 {
    var sec1: [65]u8 = undefined;
    sec1[0] = 0x04;
    sec1[1..65].* = public.*;
    return sec1;
}

fn std_verify(hash: [32]u8, r: [32]u8, s: [32]u8, public: *const secp.PublicKey) bool {
    const sec1 = sec1_uncompressed(public);
    const std_public = StdEcdsa.PublicKey.fromSec1(&sec1) catch return false;
    const signature: StdEcdsa.Signature = .{ .r = r, .s = s };
    signature.verifyPrehashed(hash, std_public) catch return false;
    return true;
}

test "secp256k1: ecdh is symmetric and matches std" {
    var prng = Prng.init(0x65636468);
    for (0..32) |_| {
        const a = random_private_key(&prng);
        const b = random_private_key(&prng);
        const public_a = try secp.public_key(a);
        const public_b = try secp.public_key(b);
        const shared_ab = try secp.ecdh(a, &public_b);
        const shared_ba = try secp.ecdh(b, &public_a);
        try testing.expectEqual(shared_ab, shared_ba);
        const sec1 = sec1_uncompressed(&public_b);
        const reference = try (try StdCurve.fromSec1(&sec1)).mul(a, .big);
        try testing.expectEqual(reference.toCompressedSec1(), shared_ab);
    }
}

test "secp256k1: mul_ct on edge scalars matches the variable-time path" {
    var prng = Prng.init(0x6d756c5f6374);
    const base_key = random_private_key(&prng);
    const base_public = try secp.public_key(base_key);
    const base = secp.decode_public_key(&base_public).?;
    const edges = [_]u256{
        1,
        2,
        7,
        8,
        9,
        15,
        16,
        17,
        0x88,
        0x8888888888888888,
        1 << 255,
        n_int - 1,
        n_int - 2,
        n_int - 8,
        n_int - 9,
        (1 << 252) - 1,
    };
    for (edges) |value| {
        const k = Scalar.from_int(value);
        const blind = Fe.from_int(prng.int(u256) % p_int);
        const ours = secp.point.mul_ct(base, k, blind).?;
        const reference = secp.point.mul_double_var(Scalar.from_int(0), k, base).to_affine().?;
        try testing.expect(ours.x.equal(reference.x));
        try testing.expect(ours.y.equal(reference.y));
    }
    try testing.expect(secp.point.mul_ct(base, Scalar.from_int(0), Fe.one) == null);
    // A zero blind takes the constant-time inversion fallback.
    const k = Scalar.from_int(12345);
    const unblinded = secp.point.mul_ct(base, k, Fe.zero).?;
    try testing.expect(unblinded.x.equal(secp.point.mul_ct(base, k, Fe.one).?.x));
}

test "secp256k1: verify agrees with sign and std, including high s" {
    var prng = Prng.init(0x766572696679);
    for (0..32) |_| {
        const key = random_private_key(&prng);
        const public = try secp.public_key(key);
        var hash: [32]u8 = undefined;
        prng.fill(&hash);
        const signature = try secp.sign(key, hash);
        try testing.expect(secp.verify(hash, signature.r, signature.s, &public));
        try testing.expect(secp.is_low_s(signature.s));
        const s_high = Scalar.from_bytes(&signature.s).?.neg().to_bytes();
        try testing.expect(!secp.is_low_s(s_high));
        try testing.expectEqual(
            std_verify(hash, signature.r, s_high, &public),
            secp.verify(hash, signature.r, s_high, &public),
        );
        var tampered = hash;
        tampered[prng.int(u8) % 32] ^= @as(u8, 1) << @intCast(prng.int(u8) % 8);
        try testing.expect(!secp.verify(tampered, signature.r, signature.s, &public));
        var random_r: [32]u8 = undefined;
        prng.fill(&random_r);
        try testing.expectEqual(
            std_verify(hash, random_r, signature.s, &public),
            secp.verify(hash, random_r, signature.s, &public),
        );
    }
}

test "secp256k1: verify rejects out-of-range r and s" {
    var prng = Prng.init(0x72616e6765);
    const key = random_private_key(&prng);
    const public = try secp.public_key(key);
    const hash: [32]u8 = @splat(0x42);
    const signature = try secp.sign(key, hash);
    const bad = [_]u256{ 0, n_int, n_int + 1, std.math.maxInt(u256) };
    for (bad) |value| {
        try testing.expect(!secp.verify(hash, int_bytes(value), signature.s, &public));
        try testing.expect(!secp.verify(hash, signature.r, int_bytes(value), &public));
        try testing.expect(!secp.is_low_s(int_bytes(value)));
    }
    var off_curve = public;
    off_curve[63] ^= 1;
    try testing.expect(!secp.verify(hash, signature.r, signature.s, &off_curve));
}

test "secp256k1: SEC1 compression round trip and rejection" {
    var prng = Prng.init(0x7365633121);
    for (0..32) |_| {
        const public = try secp.public_key(random_private_key(&prng));
        const compressed = secp.compress_public_key(&public).?;
        try testing.expectEqual(public, secp.decompress_public_key(&compressed).?);
        const sec1 = sec1_uncompressed(&public);
        const reference = try StdCurve.fromSec1(&sec1);
        try testing.expectEqual(reference.toCompressedSec1(), compressed);
    }
    var bad: secp.CompressedPublicKey = undefined;
    bad[0] = 0x04;
    bad[1..33].* = int_bytes(1);
    try testing.expect(secp.decompress_public_key(&bad) == null);
    bad[0] = 0x02;
    bad[1..33].* = int_bytes(p_int);
    try testing.expect(secp.decompress_public_key(&bad) == null);
    // x = 0: 0^3 + 7 = 7 is a non-residue mod p, so no point exists.
    bad[1..33].* = int_bytes(0);
    try testing.expect(secp.decompress_public_key(&bad) == null);
    var uncompressed: secp.PublicKey = undefined;
    uncompressed[0..32].* = int_bytes(p_int);
    uncompressed[32..64].* = int_bytes(1);
    try testing.expect(secp.compress_public_key(&uncompressed) == null);
    try testing.expectError(
        error.InvalidPublicKey,
        secp.ecdh(random_private_key(&prng), &uncompressed),
    );
    try testing.expectError(error.InvalidPrivateKey, secp.ecdh(int_bytes(0), &uncompressed));
}

fn fuzz_sec1_verify(_: void, smith: *testing.Smith) anyerror!void {
    var compressed: secp.CompressedPublicKey = undefined;
    smith.bytes(&compressed);
    compressed[0] = 0x02 | (compressed[0] & 1);
    const decoded = secp.decompress_public_key(&compressed);
    const reference = StdCurve.fromSec1(&compressed) catch null;
    try testing.expectEqual(reference == null, decoded == null);
    const public = decoded orelse return;
    try testing.expectEqual(compressed, secp.compress_public_key(&public).?);
    var hash: [32]u8 = undefined;
    var r: [32]u8 = undefined;
    var s: [32]u8 = undefined;
    smith.bytes(&hash);
    smith.bytes(&r);
    smith.bytes(&s);
    try testing.expectEqual(std_verify(hash, r, s, &public), secp.verify(hash, r, s, &public));
    var key: [32]u8 = undefined;
    smith.bytes(&key);
    const shared = secp.ecdh(key, &public) catch |err| {
        try testing.expectEqual(error.InvalidPrivateKey, err);
        return;
    };
    const expected = try (try StdCurve.fromSec1(&compressed)).mul(key, .big);
    try testing.expectEqual(expected.toCompressedSec1(), shared);
}

test "secp256k1: coverage-guided fuzz of SEC1, verify, and ecdh vs std" {
    try testing.fuzz({}, fuzz_sec1_verify, .{});
}

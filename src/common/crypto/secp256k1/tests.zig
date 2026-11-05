//! secp256k1 vectors, edge cases, and differential fuzzing against the Zig standard
//! library (`std.crypto.ecc.Secp256k1`, `std.crypto.sign.ecdsa`), which serves only
//! as a slow, independent reference here.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const secp = @import("root.zig");
const keccak = @import("../keccak.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const Scalar = secp.scalar.Scalar;
const Fe = secp.field.Fe;
const StdCurve = std.crypto.ecc.Secp256k1;
const StdScalar = StdCurve.scalar.Scalar;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

const n_int = secp.scalar.n_int;
const p_int = secp.field.p_int;

fn hex(comptime length: usize, comptime text: []const u8) [length]u8 {
    var out: [length]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

fn int_bytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

fn bytes_int(bytes: *const [32]u8) u256 {
    return std.mem.readInt(u256, bytes, .big);
}

/// Reference recovery built only from std: Q = r^-1 (s R - z G).
fn reference_recover(hash: [32]u8, recovery_id: u2, r: [32]u8, s: [32]u8) ?[64]u8 {
    const r_int = bytes_int(&r);
    const s_int = bytes_int(&s);
    if (r_int == 0 or r_int >= n_int or s_int == 0 or s_int >= n_int) return null;
    const x_int: u512 = @as(u512, r_int) + if (recovery_id & 2 != 0) n_int else 0;
    if (x_int >= p_int) return null;
    var sec1: [33]u8 = undefined;
    sec1[0] = 0x02 | @as(u8, recovery_id & 1);
    sec1[1..33].* = int_bytes(@intCast(x_int));
    const r_point = StdCurve.fromSec1(&sec1) catch return null;
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = hash;
    const z = StdScalar.fromBytes48(wide, .big);
    const r_scalar = StdScalar.fromBytes(r, .big) catch unreachable;
    const s_scalar = StdScalar.fromBytes(s, .big) catch unreachable;
    const r_inverse = r_scalar.invert();
    const g_factor = z.mul(r_inverse).neg().toBytes(.big);
    const r_factor = s_scalar.mul(r_inverse).toBytes(.big);
    const q = reference_double_mul(g_factor, r_point, r_factor) orelse return null;
    const encoded = q.toUncompressedSec1();
    return encoded[1..65].*;
}

fn reference_double_mul(g_factor: [32]u8, r_point: StdCurve, r_factor: [32]u8) ?StdCurve {
    const zero: [32]u8 = @splat(0);
    const left: ?StdCurve = if (std.mem.eql(u8, &g_factor, &zero))
        null
    else
        StdCurve.basePoint.mul(g_factor, .big) catch null;
    const right: ?StdCurve = if (std.mem.eql(u8, &r_factor, &zero))
        null
    else
        r_point.mul(r_factor, .big) catch null;
    const sum = if (left) |a| (if (right) |b| a.add(b) else a) else right orelse return null;
    sum.rejectIdentity() catch return null;
    return sum;
}

fn recover_key(hash: [32]u8, recovery_id: u2, r: [32]u8, s: [32]u8) ?[64]u8 {
    const public = secp.recover_point(&hash, recovery_id, &r, &s) orelse return null;
    var encoded: [64]u8 = undefined;
    encoded[0..32].* = public.x.to_bytes();
    encoded[32..64].* = public.y.to_bytes();
    return encoded;
}

fn reference_public_key(private_key: [32]u8) [64]u8 {
    const q = StdCurve.basePoint.mul(private_key, .big) catch unreachable;
    const encoded = q.toUncompressedSec1();
    return encoded[1..65].*;
}

test "secp256k1: dev mnemonic account 0 address" {
    const private_key = hex(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected = hex(20, "f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    try testing.expectEqual(expected, try secp.address(private_key));
}

test "secp256k1: EIP-155 example signature (RFC 6979)" {
    // The signing hash and signature from the EIP-155 specification example.
    const private_key: [32]u8 = @splat(0x46);
    const hash = hex(32, "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
    const signature = try secp.sign(private_key, hash);
    try testing.expectEqual(
        int_bytes(18515461264373351373200002665853028612451056578545711640558177340181847433846),
        signature.r,
    );
    try testing.expectEqual(
        int_bytes(46948507304638947509940763649030358759909902576025900602547168820602576006531),
        signature.s,
    );
    try testing.expectEqual(@as(u2, 0), signature.recovery_id);
    const sender = hex(20, "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    try testing.expectEqual(sender, try secp.address(private_key));
    try testing.expectEqual(sender, secp.recover_tx_address(hash, 0, signature.r, signature.s).?);
}

test "secp256k1: RFC 6979 vector, key 1, sha256(\"Satoshi Nakamoto\")" {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("Satoshi Nakamoto", &hash, .{});
    const signature = try secp.sign(int_bytes(1), hash);
    try testing.expectEqual(
        hex(32, "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"),
        signature.r,
    );
    try testing.expectEqual(
        hex(32, "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"),
        signature.s,
    );
}

test "secp256k1: invalid private keys" {
    try testing.expectError(error.InvalidPrivateKey, secp.public_key(@splat(0)));
    try testing.expectError(error.InvalidPrivateKey, secp.sign(int_bytes(n_int), @splat(1)));
    const largest = try secp.public_key(int_bytes(n_int - 1));
    try testing.expectEqual(reference_public_key(int_bytes(n_int - 1)), largest);
}

test "secp256k1: precompile input validation" {
    const private_key = hex(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const hash = keccak.keccak256("needlefish");
    const signature = try secp.sign(private_key, hash);
    var input: [128]u8 = @splat(0);
    input[0..32].* = hash;
    input[63] = 27 + @as(u8, signature.recovery_id);
    input[64..96].* = signature.r;
    input[96..128].* = signature.s;
    var expected: [32]u8 = @splat(0);
    expected[12..32].* = try secp.address(private_key);
    try testing.expectEqual(expected, secp.precompile_ecrecover(&input).?);
    // Extra trailing input is ignored.
    var extended: [160]u8 = @splat(0xff);
    extended[0..128].* = input;
    try testing.expectEqual(expected, secp.precompile_ecrecover(&extended).?);

    var bad = input;
    bad[63] = 29;
    try testing.expect(secp.precompile_ecrecover(&bad) == null);
    bad = input;
    bad[62] = 1; // v = 256 + 27
    try testing.expect(secp.precompile_ecrecover(&bad) == null);
    bad = input;
    bad[64..96].* = @splat(0); // r = 0
    try testing.expect(secp.precompile_ecrecover(&bad) == null);
    bad = input;
    bad[96..128].* = int_bytes(n_int); // s = n
    try testing.expect(secp.precompile_ecrecover(&bad) == null);
    bad = input;
    bad[64..96].* = int_bytes(n_int); // r = n
    try testing.expect(secp.precompile_ecrecover(&bad) == null);
    try testing.expect(secp.precompile_ecrecover("") == null);
    // Short input is zero-padded.
    var truncated = input;
    @memset(truncated[100..], 0);
    try testing.expectEqual(
        secp.precompile_ecrecover(&truncated),
        secp.precompile_ecrecover(input[0..100]),
    );

    // The precompile accepts high s (it recovers the same key with flipped parity);
    // transaction recovery does not.
    var high = input;
    high[96..128].* = int_bytes(n_int - bytes_int(&signature.s));
    high[63] = 27 + @as(u8, signature.recovery_id ^ 1);
    try testing.expectEqual(expected, secp.precompile_ecrecover(&high).?);
    const flipped: u1 = @truncate(signature.recovery_id ^ 1);
    try testing.expect(
        secp.recover_tx_address(hash, flipped, high[64..96].*, high[96..128].*) == null,
    );
}

test "secp256k1: recovery edge cases" {
    // R.x with no curve point: x = 5 has x^3 + 7 = 132, a non-residue mod p.
    const hash: [32]u8 = @splat(0x11);
    const s = int_bytes(1234567);
    for ([_]u256{ 5, 1, 2, 3 }) |x| {
        const r = int_bytes(x);
        for (0..2) |parity| {
            const expected = reference_recover(hash, @intCast(parity), r, s);
            try testing.expectEqual(expected, secp.ecrecover(hash, @intCast(parity), r, s));
        }
    }
    // Recovery id with bit 1: x = r + n must stay below p.
    const r_small = int_bytes(p_int - n_int - 1);
    const r_large = int_bytes(p_int - n_int);
    for (0..4) |id| {
        const recovery_id: u2 = @intCast(id);
        try testing.expectEqual(
            reference_recover(hash, recovery_id, r_small, s),
            recover_key(hash, recovery_id, r_small, s),
        );
        try testing.expectEqual(
            reference_recover(hash, recovery_id, r_large, s),
            recover_key(hash, recovery_id, r_large, s),
        );
        if (recovery_id & 2 != 0) {
            try testing.expect(recover_key(hash, recovery_id, r_large, s) == null);
        }
    }
    // Hash = 0 and hash = n both give g_factor = 0.
    const r_ok = int_bytes(secp.table.g_x_int);
    for ([_][32]u8{ @splat(0), int_bytes(n_int) }) |zero_hash| {
        try testing.expectEqual(
            reference_recover(zero_hash, 0, r_ok, s),
            secp.ecrecover(zero_hash, 0, r_ok, s),
        );
    }
}

test "secp256k1: recovery of a point at infinity returns null" {
    // With R = k G and z = s k (mod n): Q = r^-1 (s k - z) G = infinity.
    var prng = Prng.init(0x696e66);
    for (0..8) |_| {
        const k = Scalar.from_int(prng.int(u256) % (n_int - 1) + 1);
        const r_point = secp.point.mul_generator_ct(k, Fe.one).?;
        const x_int = r_point.x.to_int();
        if (x_int >= n_int) continue;
        const s = Scalar.from_int(prng.int(u256) % (n_int - 1) + 1);
        const z = s.mul(k);
        const parity: u1 = @intFromBool(r_point.y.is_odd());
        const r = int_bytes(x_int);
        try testing.expect(secp.ecrecover(z.to_bytes(), parity, r, s.to_bytes()) == null);
        try testing.expect(reference_recover(z.to_bytes(), parity, r, s.to_bytes()) == null);
    }
}

test "secp256k1: seeded differential fuzz vs std" {
    var prng = Prng.init(0x736563703235366b);
    for (0..64) |_| {
        var private_key: [32]u8 = undefined;
        prng.fill(&private_key);
        if (bytes_int(&private_key) == 0 or bytes_int(&private_key) >= n_int) continue;
        var hash: [32]u8 = undefined;
        prng.fill(&hash);

        const public = try secp.public_key(private_key);
        try testing.expectEqual(reference_public_key(private_key), public);

        const signature = try secp.sign(private_key, hash);
        try testing.expect(!Scalar.from_bytes(&signature.s).?.is_high());
        var sec1: [65]u8 = undefined;
        sec1[0] = 0x04;
        sec1[1..65].* = public;
        const std_public = try StdEcdsa.PublicKey.fromSec1(&sec1);
        const std_signature: StdEcdsa.Signature = .{ .r = signature.r, .s = signature.s };
        try std_signature.verifyPrehashed(hash, std_public);

        const id = signature.recovery_id;
        const recovered = secp.recover_point(&hash, id, &signature.r, &signature.s);
        try testing.expect(recovered != null);
        try testing.expectEqual(public[0..32].*, recovered.?.x.to_bytes());
        try testing.expectEqual(
            reference_recover(hash, signature.recovery_id, signature.r, signature.s),
            public,
        );
        // The other parity recovers a different key (or none).
        const flipped = ~@as(u1, @truncate(id));
        const other = secp.ecrecover(hash, flipped, signature.r, signature.s);
        try testing.expect(other == null or !std.mem.eql(u8, &other.?, &public));
    }
}

test "secp256k1: seeded differential fuzz of arbitrary recovery inputs" {
    var prng = Prng.init(0x7265636f766572);
    for (0..96) |_| {
        var hash: [32]u8 = undefined;
        var r: [32]u8 = undefined;
        var s: [32]u8 = undefined;
        prng.fill(&hash);
        prng.fill(&r);
        prng.fill(&s);
        if (prng.chance(1, 4)) r = int_bytes(bytes_int(&r) % (p_int - n_int));
        if (prng.chance(1, 8)) s = int_bytes(n_int - prng.below(2));
        const recovery_id: u2 = @intCast(prng.below(4));
        const expected = reference_recover(hash, recovery_id, r, s);
        const ours = secp.recover_point(&hash, recovery_id, &r, &s);
        try testing.expectEqual(expected == null, ours == null);
        if (ours) |public| {
            try testing.expectEqual(expected.?[0..32].*, public.x.to_bytes());
            try testing.expectEqual(expected.?[32..64].*, public.y.to_bytes());
        }
    }
}

test "secp256k1: double-scalar multiplication vs std" {
    var prng = Prng.init(0x646f75626c65);
    for (0..48) |_| {
        const k = Scalar.from_int(prng.int(u256) % (n_int - 1) + 1);
        const base = secp.point.mul_generator_ct(k, Fe.one).?;
        const g_factor = Scalar.from_int(prng.int(u256) % n_int);
        const r_factor = Scalar.from_int(prng.int(u256) % n_int);
        var sec1: [65]u8 = undefined;
        sec1[0] = 0x04;
        sec1[1..33].* = base.x.to_bytes();
        sec1[33..65].* = base.y.to_bytes();
        const std_base = try StdCurve.fromSec1(&sec1);
        const expected = reference_double_mul(g_factor.to_bytes(), std_base, r_factor.to_bytes());
        const ours = secp.point.mul_double_var(g_factor, r_factor, base).to_affine();
        try testing.expectEqual(expected == null, ours == null);
        if (ours) |q| {
            const encoded = expected.?.toUncompressedSec1();
            try testing.expectEqual(encoded[1..33].*, q.x.to_bytes());
            try testing.expectEqual(encoded[33..65].*, q.y.to_bytes());
        }
    }
}

fn fuzz_precompile(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [160]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    var padded: [128]u8 = @splat(0);
    const used = @min(length, padded.len);
    @memcpy(padded[0..used], input[0..used]);
    // Bias toward valid v so the curve code is reached.
    if (length > 64) padded[32..63].* = @splat(0);
    if (length > 64) padded[63] = 27 + (padded[63] & 1);
    const ours = secp.precompile_ecrecover(&padded);
    const v_valid = std.mem.allEqual(u8, padded[32..63], 0) and
        (padded[63] == 27 or padded[63] == 28);
    var expected: ?[32]u8 = null;
    if (v_valid) {
        const parity: u2 = @intCast(padded[63] - 27);
        if (reference_recover(padded[0..32].*, parity, padded[64..96].*, padded[96..128].*)) |key| {
            var word: [32]u8 = @splat(0);
            word[12..32].* = keccak.keccak256(&key)[12..32].*;
            expected = word;
        }
    }
    try testing.expectEqual(expected, ours);
    _ = secp.precompile_ecrecover(input);
}

test "secp256k1: coverage-guided fuzz of precompile_ecrecover vs reference" {
    try testing.fuzz({}, fuzz_precompile, .{});
}

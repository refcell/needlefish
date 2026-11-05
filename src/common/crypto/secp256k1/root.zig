//! secp256k1 for Ethereum: public key recovery (ecrecover, precompile 0x01 semantics),
//! RFC 6979 deterministic signing, and private key -> public key -> address.
//!
//! Recovery runs on public data in variable time (GLV + wNAF Strauss-Shamir).
//! Signing and key derivation touch secrets and use the constant-time path.
//! Mirrors the k256/libsecp256k1 behavior that base/base relies on through revm and
//! alloy: r and s must be in [1, n - 1]; only transaction signatures demand low s.

const std = @import("std");
const assert = std.debug.assert;
const keccak = @import("../keccak.zig");

pub const field = @import("field.zig");
pub const scalar = @import("scalar.zig");
pub const table = @import("table.zig");
pub const modinv = @import("modinv.zig");
pub const point = @import("point.zig");

const Fe = field.Fe;
const Scalar = scalar.Scalar;
const Affine = point.Affine;
const ScalarInverse = modinv.Modulus(scalar.n_int);

/// Uncompressed public key without the 0x04 prefix: x || y, big-endian.
pub const PublicKey = [64]u8;
pub const Address = [20]u8;

pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,
    /// Bit 0: parity of R.y. Bit 1: R.x was >= n (r = R.x - n); practically never set.
    recovery_id: u2,
};

pub const Error = error{InvalidPrivateKey};

comptime {
    // r + n can only be a valid abscissa when r < p - n.
    assert(field.p_int > scalar.n_int);
    assert(field.p_int - scalar.n_int < (1 << 129));
}

fn encode_public_key(public: Affine) PublicKey {
    var encoded: PublicKey = undefined;
    encoded[0..32].* = public.x.to_bytes();
    encoded[32..64].* = public.y.to_bytes();
    return encoded;
}

/// Recovers the public key point from a signature over `hash`.
/// Returns null for r or s outside [1, n - 1], a non-curve R, or Q at infinity.
pub fn recover_point(
    hash: *const [32]u8,
    recovery_id: u2,
    r_bytes: *const [32]u8,
    s_bytes: *const [32]u8,
) ?Affine {
    const r = Scalar.from_bytes(r_bytes) orelse return null;
    const s = Scalar.from_bytes(s_bytes) orelse return null;
    if (r.is_zero() or s.is_zero()) return null;
    const r_int = r.to_int();
    const x_int: u256 = if (recovery_id & 2 == 0) r_int else blk: {
        if (r_int >= field.p_int - scalar.n_int) return null;
        break :blk r_int + scalar.n_int;
    };
    assert(x_int < field.p_int);
    const r_point = point.decompress(Fe.from_int(x_int), recovery_id & 1 == 1) orelse return null;
    const z = Scalar.from_bytes_reduce(hash);
    // r is public, so the variable-time inversion is safe here.
    const r_inverse = Scalar.from_int(ScalarInverse.invert(r_int));
    const g_factor = z.mul(r_inverse).neg();
    const r_factor = s.mul(r_inverse);
    const public = point.mul_double_var(g_factor, r_factor, r_point).to_affine() orelse return null;
    assert(point.on_curve(public));
    return public;
}

/// ecrecover: the uncompressed public key (x || y) that signed `hash`, or null.
pub fn ecrecover(hash: [32]u8, v_parity: u1, r: [32]u8, s: [32]u8) ?PublicKey {
    const public = recover_point(&hash, v_parity, &r, &s) orelse return null;
    return encode_public_key(public);
}

pub fn public_key_to_address(public: *const PublicKey) Address {
    const digest = keccak.keccak256(public);
    return digest[12..32].*;
}

/// ecrecover followed by keccak256(x || y)[12..32].
pub fn ecrecover_address(hash: [32]u8, v_parity: u1, r: [32]u8, s: [32]u8) ?Address {
    const public = ecrecover(hash, v_parity, r, s) orelse return null;
    return public_key_to_address(&public);
}

/// Transaction signature recovery: as `ecrecover_address`, but rejects high s
/// (s > n / 2, EIP-2) like transaction validation does.
pub fn recover_tx_address(hash: [32]u8, v_parity: u1, r: [32]u8, s: [32]u8) ?Address {
    const s_scalar = Scalar.from_bytes(&s) orelse return null;
    if (s_scalar.is_high()) return null;
    return ecrecover_address(hash, v_parity, r, s);
}

/// The ECRECOVER precompile (address 0x01). Input is right-padded with zeros to 128
/// bytes (hash, v, r, s; extra bytes are ignored). v must be exactly 27 or 28 as a
/// 32-byte big-endian word. Returns the address left-padded to 32 bytes, or null for
/// an empty output (gas is charged by the caller either way).
pub fn precompile_ecrecover(input: []const u8) ?[32]u8 {
    var padded: [128]u8 = @splat(0);
    const length = @min(input.len, padded.len);
    @memcpy(padded[0..length], input[0..length]);
    const v_word = padded[32..64];
    const v_high_zero = std.mem.allEqual(u8, v_word[0..31], 0);
    if (!v_high_zero or (v_word[31] != 27 and v_word[31] != 28)) return null;
    const parity: u1 = @intCast(v_word[31] - 27);
    const hash = padded[0..32].*;
    const r = padded[64..96].*;
    const s = padded[96..128].*;
    const recovered = ecrecover_address(hash, parity, r, s) orelse return null;
    var output: [32]u8 = @splat(0);
    output[12..32].* = recovered;
    assert(std.mem.allEqual(u8, output[0..12], 0));
    return output;
}

fn private_scalar(private_key: *const [32]u8) Error!Scalar {
    const d = Scalar.from_bytes(private_key) orelse return error.InvalidPrivateKey;
    if (d.is_zero()) return error.InvalidPrivateKey;
    return d;
}

/// Uncompressed public key (x || y) of a private key, in constant time.
pub fn public_key(private_key: [32]u8) Error!PublicKey {
    const d = try private_scalar(&private_key);
    var blind_bytes: [32]u8 = undefined;
    NonceGenerator.Hmac.create(&blind_bytes, "secp256k1 blinding", &private_key);
    const public = point.mul_generator_ct(d, Fe.from_bytes_unchecked(&blind_bytes)) orelse
        unreachable; // d != 0
    return encode_public_key(public);
}

/// Ethereum address of a private key.
pub fn address(private_key: [32]u8) Error!Address {
    const public = try public_key(private_key);
    return public_key_to_address(&public);
}

/// RFC 6979 HMAC-SHA256 deterministic nonce generator (qlen = hlen = 256).
const NonceGenerator = struct {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

    key: [32]u8,
    value: [32]u8,
    started: bool,

    fn init(private_key: *const [32]u8, hash_reduced: *const [32]u8) NonceGenerator {
        var generator: NonceGenerator = .{ .key = @splat(0), .value = @splat(1), .started = false };
        for ([_]u8{ 0x00, 0x01 }) |separator| {
            var mac = Hmac.init(&generator.key);
            mac.update(&generator.value);
            mac.update(&.{separator});
            mac.update(private_key);
            mac.update(hash_reduced);
            mac.final(&generator.key);
            Hmac.create(&generator.value, &generator.value, &generator.key);
        }
        assert(!generator.started);
        return generator;
    }

    /// Secret blinding bytes derived from the current state without advancing it, so
    /// the RFC 6979 nonce sequence is unchanged.
    fn blinding(generator: *const NonceGenerator) [32]u8 {
        var mac = Hmac.init(&generator.key);
        mac.update(&generator.value);
        mac.update(&.{0x02});
        var bytes: [32]u8 = undefined;
        mac.final(&bytes);
        return bytes;
    }

    fn next(generator: *NonceGenerator) [32]u8 {
        if (generator.started) {
            var mac = Hmac.init(&generator.key);
            mac.update(&generator.value);
            mac.update(&.{0x00});
            mac.final(&generator.key);
            Hmac.create(&generator.value, &generator.value, &generator.key);
        }
        generator.started = true;
        Hmac.create(&generator.value, &generator.value, &generator.key);
        return generator.value;
    }
};

/// k^-1 = b (k b)^-1: the variable-time inversion only sees k b, which is uniformly
/// random and independent of k for a secret random b. Falls back to the
/// constant-time Fermat inversion if b = 0.
fn blinded_inverse(k: Scalar, blind: Scalar) Scalar {
    assert(!k.is_zero());
    if (blind.is_zero()) return k.invert();
    const inverse = Scalar.from_int(ScalarInverse.invert(k.mul(blind).to_int())).mul(blind);
    assert(inverse.mul(k).equal(Scalar.one));
    return inverse;
}

/// Attempts allowed before giving up on the nonce: each retry has probability
/// below 2^-127, so the bound is never reached in practice.
const nonce_attempts_max = 16;

/// Signs a 32-byte message hash with an RFC 6979 nonce. The result has low s
/// (EIP-2) and the matching recovery id. Constant time in the private key and nonce.
pub fn sign(private_key: [32]u8, hash: [32]u8) Error!Signature {
    const d = try private_scalar(&private_key);
    const z = Scalar.from_bytes_reduce(&hash);
    var nonces = NonceGenerator.init(&private_key, &z.to_bytes());
    for (0..nonce_attempts_max) |_| {
        const candidate = nonces.next();
        const k = Scalar.from_bytes(&candidate) orelse continue;
        if (k.is_zero()) continue;
        const blind_bytes = nonces.blinding();
        const blind_field = Fe.from_bytes_unchecked(&blind_bytes);
        const r_point = point.mul_generator_ct(k, blind_field) orelse unreachable; // k != 0
        const x_bytes = r_point.x.to_bytes();
        const r = Scalar.from_bytes_reduce(&x_bytes);
        if (r.is_zero()) continue;
        var s = blinded_inverse(k, Scalar.from_bytes_reduce(&blind_bytes)).mul(z.add(r.mul(d)));
        if (s.is_zero()) continue;
        const x_overflow: u2 = @intFromBool(Scalar.from_bytes(&x_bytes) == null);
        var recovery_id: u2 = (x_overflow << 1) | @intFromBool(r_point.y.is_odd());
        if (s.is_high()) {
            s = s.neg();
            recovery_id ^= 1;
        }
        assert(!s.is_high());
        return .{ .r = r.to_bytes(), .s = s.to_bytes(), .recovery_id = recovery_id };
    }
    // Reaching here requires 16 consecutive nonce failures (probability < 2^-2000).
    unreachable;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}

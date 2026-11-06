//! Agora / `nitro-validator` P-384 inverse-hint transcript (base/base
//! `registrar/src/hints.rs`).
//!
//! Walks the onchain verifier's affine schedule, records each modular inverse as a
//! 48-byte big-endian hint, and delegates point addition and doubling to the
//! projective formulas of `std.crypto.ecc.P384`. The transcript must stay
//! byte-identical to base/base: the onchain verifier consumes it in order.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const x509 = @import("../nitro/x509.zig");

const P384 = std.crypto.ecc.P384;
const Fe = P384.Fe;
const Scalar = P384.scalar.Scalar;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha384 = std.crypto.hash.sha2.Sha384;

pub const scalar_size: u32 = 48;
pub const signature_size: u32 = 96;
/// Fixed-width affine public key encoding `x‖y`.
pub const public_key_size: u32 = 96;
const uncompressed_size: u32 = 97;
const mask_256: u384 = (@as(u384, 1) << 256) - 1;
const curve_order: u384 = P384.scalar.field_order;

comptime {
    assert(public_key_size == 2 * scalar_size);
    assert(types.hint_inverse_size == scalar_size);
}

pub const Error = error{
    HintSignatureLength,
    HintPublicKeyLength,
    HintHashLength,
    HintScalarBounds,
    HintPublicKeyNotOnCurve,
    HintSignatureVerificationFailed,
    HintInvertZero,
    HintPointAtInfinity,
    HintTranscriptOverflow,
    HintCertificateParse,
    HintCertificatePublicKey,
    HintCertificateSignatureAlgorithm,
    HintCertificateSignatureEncoding,
    HintPlanEmpty,
    HintPlanTooLong,
};

/// Affine point; `infinity` marks the group identity (p384 `AffinePoint::IDENTITY`).
pub const Affine = struct {
    x: Fe,
    y: Fe,
    infinity: bool,

    pub const identity: Affine = .{ .x = Fe.zero, .y = Fe.zero, .infinity = true };
    pub const generator: Affine = .{
        .x = P384.basePoint.x,
        .y = P384.basePoint.y,
        .infinity = false,
    };

    pub fn eql(a: Affine, b: Affine) bool {
        if (a.infinity or b.infinity) return a.infinity == b.infinity;
        return a.x.equivalent(b.x) and a.y.equivalent(b.y);
    }

    fn to_projective(point: Affine) P384 {
        if (point.infinity) return P384.identityElement;
        return .{ .x = point.x, .y = point.y, .z = Fe.one };
    }

    /// Normalize without `affineCoordinates`, which also maps affine `(0, 1)` to
    /// the identity; only `z == 0` is the identity here.
    pub fn from_projective(point: P384) Affine {
        if (point.z.isZero()) return identity;
        const z_inverse = point.z.invert();
        const result: Affine = .{
            .x = point.x.mul(z_inverse),
            .y = point.y.mul(z_inverse),
            .infinity = false,
        };
        assert(!result.infinity);
        return result;
    }
};

const FiniteXy = struct { x: Fe, y: Fe };

/// Agora-compatible P-384 inverse-hint generator and transcript collector.
pub const P384Hints = struct {
    out: *[types.hint_stream_size_max]u8,
    count: u32 = 0,

    pub fn init(out: *[types.hint_stream_size_max]u8) P384Hints {
        return .{ .out = out };
    }

    /// Verify a P-384 signature while recording inverses in onchain order.
    ///
    /// `signature` and `public_key` are fixed-width `r‖s` and `x‖y` (96 bytes);
    /// `hash` is at most 48 bytes (left padded, then reduced mod `n`). Returns the
    /// packed transcript inside `out`.
    pub fn collect_verify_hints(
        hash: []const u8,
        signature: []const u8,
        public_key: []const u8,
        out: *[types.hint_stream_size_max]u8,
    ) Error![]const u8 {
        if (signature.len != signature_size) return error.HintSignatureLength;
        if (public_key.len != public_key_size) return error.HintPublicKeyLength;
        if (hash.len > scalar_size) return error.HintHashLength;

        var hints = P384Hints.init(out);
        const r = try scalar_canonical(signature[0..scalar_size]);
        const s = try scalar_canonical(signature[scalar_size..][0..scalar_size]);
        if (r.isZero() or s.isZero()) return error.HintScalarBounds;
        const public_point = try affine_from_xy(public_key[0..public_key_size]);

        var hash_be: [scalar_size]u8 = @splat(0);
        @memcpy(hash_be[scalar_size - hash.len ..], hash);
        const h = scalar_reduce(std.mem.readInt(u384, &hash_be, .big));

        // Solidity records `s⁻¹` twice (once per scalar division): invert once,
        // append twice.
        const s_inverse = try hints.record_scalar_inverse(s);
        try hints.push(s_inverse.toBytes(.big));
        const scalar1 = h.mul(s_inverse);
        const scalar2 = r.mul(s_inverse);

        var points: [64]Affine = undefined;
        try hints.precompute_table(public_point, &points);
        const result = try hints.double_scalar_mul(&points, scalar1, scalar2);
        if (result.infinity) return error.HintPointAtInfinity;
        const x = std.mem.readInt(u384, &result.x.toBytes(.big), .big);
        const x_reduced = scalar_reduce(x);
        if (!x_reduced.equivalent(r)) return error.HintSignatureVerificationFailed;
        assert(hints.count >= 2 and hints.count <= types.hint_inverse_count_max);
        return hints.packed_bytes();
    }

    /// Collect hints for a certificate signature under `parent_public_key` (`x‖y`).
    pub fn collect_cert_signature_hints(
        cert: []const u8,
        parent_public_key: *const [public_key_size]u8,
        out: *[types.hint_stream_size_max]u8,
    ) Error![]const u8 {
        const parsed = try parse_cert_signature(cert);
        assert(parsed.hash.len == scalar_size);
        return collect_verify_hints(&parsed.hash, &parsed.signature, parent_public_key, out);
    }

    /// Hint streams for a registration plan using `root_cert` as trust anchor.
    /// Attestation hints hash `plan.attestation_tbs` (raw COSE `Sig_structure`).
    pub fn for_registration_plan(
        root_cert: []const u8,
        plan: *const types.RegistrationPlan,
        out: *types.RegistrationHints,
    ) Error!void {
        if (plan.cert_count == 0) return error.HintPlanEmpty;
        var certs: [types.cert_plan_count_max][]const u8 = undefined;
        for (plan.cert_plans(), 0..) |*cert_plan, index| certs[index] = cert_plan.cert;
        var digest: [Sha384.digest_length]u8 = undefined;
        Sha384.hash(plan.attestation_tbs, &digest, .{});
        try hints_for_chain(root_cert, certs[0..plan.cert_count], &digest, &plan.signature, out);
        assert(out.cert_count == plan.cert_count);
    }

    /// Fixed-width affine P-384 coordinates (`x‖y`) of a certificate's key.
    pub fn parse_cert_public_key(cert: []const u8) Error![public_key_size]u8 {
        const parsed = x509.ParsedCert.parse(cert) catch return error.HintCertificateParse;
        const key = parsed.public_key;
        if (key.len != uncompressed_size or key[0] != 0x04) {
            return error.HintCertificatePublicKey;
        }
        const result: [public_key_size]u8 = key[1..][0..public_key_size].*;
        _ = try affine_from_xy(&result);
        return result;
    }

    pub const CertSignature = struct {
        /// SHA-384 of the `TBSCertificate` DER.
        hash: [scalar_size]u8,
        /// Fixed-width `r‖s`.
        signature: [signature_size]u8,
    };

    /// The SHA-384 TBS hash and fixed-width `r‖s` signature of `cert`.
    pub fn parse_cert_signature(cert: []const u8) Error!CertSignature {
        const parsed = x509.ParsedCert.parse(cert) catch return error.HintCertificateParse;
        if (!std.mem.eql(u8, parsed.signature_algorithm, &x509.oid_ecdsa_with_sha384)) {
            return error.HintCertificateSignatureAlgorithm;
        }
        const signature = Ecdsa.Signature.fromDer(parsed.signature) catch
            return error.HintCertificateSignatureEncoding;
        var result: CertSignature = undefined;
        result.signature = signature.toBytes();
        Sha384.hash(parsed.tbs, &result.hash, .{});
        assert(parsed.tbs.len > 0);
        return result;
    }

    /// Chain walk: each certificate is verified under its parent's key, starting
    /// from `root_cert`; the attestation is verified under the leaf key.
    pub fn hints_for_chain(
        root_cert: []const u8,
        certs: []const []const u8,
        attestation_hash: []const u8,
        attestation_signature: []const u8,
        out: *types.RegistrationHints,
    ) Error!void {
        if (certs.len > types.cert_plan_count_max) return error.HintPlanTooLong;
        var parent_public_key = try parse_cert_public_key(root_cert);
        out.cert_count = 0;
        for (certs, 0..) |cert, index| {
            const stream = &out.cert_signature_hints[index];
            const hints = try collect_cert_signature_hints(cert, &parent_public_key, &stream.bytes);
            stream.length = @intCast(hints.len);
            out.cert_count += 1;
            parent_public_key = try parse_cert_public_key(cert);
        }
        const attestation = try collect_verify_hints(
            attestation_hash,
            attestation_signature,
            &parent_public_key,
            &out.attestation_hints.bytes,
        );
        out.attestation_hints.length = @intCast(attestation.len);
        assert(out.cert_count == certs.len);
    }

    /// The recorded inverses as concatenated 48-byte big-endian limbs.
    pub fn packed_bytes(hints: *const P384Hints) []const u8 {
        assert(hints.count <= types.hint_inverse_count_max);
        return hints.out[0 .. hints.count * scalar_size];
    }

    fn push(hints: *P384Hints, bytes: [scalar_size]u8) Error!void {
        if (hints.count >= types.hint_inverse_count_max) return error.HintTranscriptOverflow;
        hints.out[hints.count * scalar_size ..][0..scalar_size].* = bytes;
        hints.count += 1;
        assert(hints.count <= types.hint_inverse_count_max);
    }

    fn precompute_table(hints: *P384Hints, public_point: Affine, points: *[64]Affine) Error!void {
        assert(!public_point.infinity);
        points.* = @splat(Affine.identity);
        points[0x01] = public_point;
        points[0x08] = Affine.generator;
        for (0..8) |i| {
            for (0..8) |j| {
                if (i + j < 2) continue;
                const to = (i << 3) | j;
                const from = if (i == 0) (i << 3) | (j - 1) else ((i - 1) << 3) | j;
                const addend = if (i == 0) public_point else Affine.generator;
                assert(from < to);
                points[to] = try hints.add_affine(points[from], addend);
            }
        }
    }

    fn double_scalar_mul(
        hints: *P384Hints,
        points: *const [64]Affine,
        scalar1: Scalar,
        scalar2: Scalar,
    ) Error!Affine {
        const s1 = std.mem.readInt(u384, &scalar1.toBytes(.big), .big);
        const s2 = std.mem.readInt(u384, &scalar2.toBytes(.big), .big);
        assert(s1 < curve_order and s2 < curve_order);
        const s1_high = s1 >> 256;
        const s2_high = s2 >> 256;
        const s1_low = s1 & mask_256;
        const s2_low = s2 & mask_256;

        var point = try hints.twice_affine(Affine.identity);
        point = try hints.window_step(points, point, window_bits(s1_high, s2_high, 183));
        var word: u32 = 4;
        while (word <= 184) : (word += 3) {
            point = try hints.twice3_affine(point);
            point = try hints.window_step(points, point, window3(s1_high, s2_high, 184 - word));
        }

        point = try hints.twice_affine(point);
        point = try hints.window_step(points, point, window_bits(s1_low, s2_low, 255));
        word = 4;
        while (word <= 256) : (word += 3) {
            point = try hints.twice3_affine(point);
            point = try hints.window_step(points, point, window3(s1_low, s2_low, 256 - word));
        }
        return point;
    }

    fn window_step(hints: *P384Hints, points: *const [64]Affine, point: Affine, mask: u64) Error!Affine {
        assert(mask < points.len);
        if (mask == 0) return point;
        return hints.add_affine(points[mask], point);
    }

    pub fn twice_affine(hints: *P384Hints, point: Affine) Error!Affine {
        // Onchain sentinel: `x == 0` is infinity, not only the identity.
        const xy = affine_finite_xy(point) orelse return Affine.identity;
        if (xy.y.isZero()) return Affine.identity;
        return hints.double_affine_recording(point, xy.y);
    }

    /// Triple doubling matching Solidity `_twice3Affine`: the `x == 0` sentinel
    /// applies on entry only; intermediate points with finite `x == 0` continue.
    pub fn twice3_affine(hints: *P384Hints, point: Affine) Error!Affine {
        const xy = affine_finite_xy(point) orelse return Affine.identity;
        if (xy.y.isZero()) return Affine.identity;
        const p1 = try hints.double_affine_recording(point, xy.y);
        const y1 = affine_y_if_continuable(p1) orelse return Affine.identity;
        const p2 = try hints.double_affine_recording(p1, y1);
        const y2 = affine_y_if_continuable(p2) orelse return Affine.identity;
        return hints.double_affine_recording(p2, y2);
    }

    fn double_affine_recording(hints: *P384Hints, point: Affine, y: Fe) Error!Affine {
        assert(!point.infinity);
        try hints.record_field_inverse(y.add(y));
        return Affine.from_projective(point.to_projective().dbl());
    }

    pub fn add_affine(hints: *P384Hints, a: Affine, b: Affine) Error!Affine {
        const a_xy = affine_finite_xy(a);
        const b_xy = affine_finite_xy(b);
        if (a_xy == null and b_xy == null) return Affine.identity;
        if (a_xy == null) return b;
        if (b_xy == null) return a;
        const first = a_xy.?;
        const second = b_xy.?;
        if (first.x.equivalent(second.x)) {
            if (first.y.equivalent(second.y)) return hints.twice_affine(a);
            return Affine.identity;
        }
        try hints.record_field_inverse(first.x.sub(second.x));
        return Affine.from_projective(a.to_projective().add(b.to_projective()));
    }

    fn record_field_inverse(hints: *P384Hints, value: Fe) Error!void {
        if (value.isZero()) return error.HintInvertZero;
        const inverse = value.invert();
        assert(inverse.mul(value).equivalent(Fe.one));
        try hints.push(inverse.toBytes(.big));
    }

    fn record_scalar_inverse(hints: *P384Hints, value: Scalar) Error!Scalar {
        if (value.isZero()) return error.HintInvertZero;
        const inverse = value.invert();
        assert(inverse.mul(value).equivalent(Scalar.one));
        try hints.push(inverse.toBytes(.big));
        return inverse;
    }
};

/// Finite affine coordinates, or null for onchain infinity (identity or `x == 0`).
pub fn affine_finite_xy(point: Affine) ?FiniteXy {
    if (point.infinity) return null;
    if (point.x.isZero()) return null;
    return .{ .x = point.x, .y = point.y };
}

/// Intermediate `_twice3Affine` gate: stop on identity or `y == 0`, not `x == 0`.
fn affine_y_if_continuable(point: Affine) ?Fe {
    if (point.infinity) return null;
    if (point.y.isZero()) return null;
    return point.y;
}

pub fn affine_from_xy(public_key: *const [public_key_size]u8) Error!Affine {
    const x = Fe.fromBytes(public_key[0..scalar_size].*, .big) catch
        return error.HintPublicKeyNotOnCurve;
    const y = Fe.fromBytes(public_key[scalar_size..][0..scalar_size].*, .big) catch
        return error.HintPublicKeyNotOnCurve;
    if (x.isZero() or y.isZero()) return error.HintPublicKeyNotOnCurve;
    _ = P384.fromAffineCoordinates(.{ .x = x, .y = y }) catch
        return error.HintPublicKeyNotOnCurve;
    return .{ .x = x, .y = y, .infinity = false };
}

fn scalar_canonical(bytes: *const [scalar_size]u8) Error!Scalar {
    return Scalar.fromBytes(bytes.*, .big) catch error.HintScalarBounds;
}

/// `Scalar::reduce` of a 384-bit integer: one conditional subtraction, as `n > 2^383`.
fn scalar_reduce(value: u384) Scalar {
    comptime assert(curve_order > (@as(u384, 1) << 383));
    const reduced = if (value >= curve_order) value - curve_order else value;
    assert(reduced < curve_order);
    var bytes: [scalar_size]u8 = undefined;
    std.mem.writeInt(u384, &bytes, reduced, .big);
    return Scalar.fromBytes(bytes, .big) catch unreachable; // reduced < n.
}

fn window3(s1: u384, s2: u384, shift: u32) u64 {
    assert(shift < 384);
    return window_bits((s1 >> @intCast(shift)) & 7, (s2 >> @intCast(shift)) & 7, 0);
}

/// `(low_limb(s1 >> shift) << 3) | low_limb(s2 >> shift)`, as base/base computes it.
fn window_bits(s1: u384, s2: u384, shift: u32) u64 {
    assert(shift < 384);
    const b1: u64 = @truncate(s1 >> @intCast(shift));
    const b2: u64 = @truncate(s2 >> @intCast(shift));
    return (b1 << 3) | b2;
}

test {
    _ = @import("hints_test.zig");
}

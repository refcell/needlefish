//! Tests for the P-384 inverse-hint transcript (base/base `hints.rs` tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const hints_module = @import("hints.zig");
const planner = @import("planner.zig");
const types = @import("types.zig");
const keccak256 = @import("../../../common/crypto/keccak.zig").keccak256;
const fuzz = @import("../../../testing/fuzz.zig");

const P384Hints = hints_module.P384Hints;
const Affine = hints_module.Affine;
const P384 = std.crypto.ecc.P384;
const Fe = P384.Fe;
const Scalar = P384.scalar.Scalar;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha384 = std.crypto.hash.sha2.Sha384;

const fixture_attestation = @embedFile("../nitro/testdata/attestation.bin");

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Literal test vectors.
    return out;
}

/// One real Nitro document is enough for golden parity.
fn fixture_hints(out: *types.RegistrationHints) !void {
    var tbs: [fixture_attestation.len + 64]u8 = undefined;
    const plan =
        try planner.AttestationPlanner.prepare_registration_plan(fixture_attestation, &tbs);
    try P384Hints.for_registration_plan(plan.root_cert, &plan, out);
}

test "registrar hints: nitro fixture hint lengths and hashes" {
    const hints = try testing.allocator.create(types.RegistrationHints);
    defer testing.allocator.destroy(hints);
    try fixture_hints(hints);
    const cert_lengths = [_]u32{ 27120, 27456, 27168, 27408 };
    const cert_keccak = [_][32]u8{
        hex("ee4279867cda2564a8f129cd98b5e785d9008c83ae4957d08bdc1dddc9ee697f"),
        hex("db39b01ca34a9b1e5e3c21028698a9f8d50a11e40ace71cf7a3867a16b545316"),
        hex("dc2f389c144647751c42c7454744f604dd0c89beb5aa271bf7a67d8188cb3187"),
        hex("51bc463dbc9dae38959f20166d74a74fe81016830e7867b39595f4589709b282"),
    };
    try testing.expectEqual(@as(u8, cert_lengths.len), hints.cert_count);
    for (hints.cert_streams(), 0..) |*stream, index| {
        try testing.expectEqual(cert_lengths[index], stream.length);
        try testing.expectEqualSlices(u8, &cert_keccak[index], &keccak256(stream.slice()));
    }
    try testing.expectEqual(@as(u32, 27072), hints.attestation_hints.length);
    try testing.expectEqualSlices(
        u8,
        &hex("6086b00c3a29f1170bc436fabe95b95557d3f134d4adb56324761cd81998808e"),
        &keccak256(hints.attestation_hints.slice()),
    );
    const again = try testing.allocator.create(types.RegistrationHints);
    defer testing.allocator.destroy(again);
    try fixture_hints(again);
    try testing.expect(hints.eql(again));
}

/// On-curve P-384 point with `x == 0` (`y² = b`). Solidity treats it as infinity.
fn on_curve_x_zero_point() Affine {
    const y = hex("c306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793" ++
        "406d80d2b91ad54f9048bd487af1ade1");
    const y_fe = Fe.fromBytes(y, .big) catch unreachable; // Canonical literal.
    _ = P384.fromAffineCoordinates(.{ .x = Fe.zero, .y = y_fe }) catch unreachable; // On curve.
    return .{ .x = Fe.zero, .y = y_fe, .infinity = false };
}

test "registrar hints: affine helpers treat x == 0 as infinity" {
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    const x0 = on_curve_x_zero_point();
    const generator = Affine.generator;
    try testing.expect(!x0.infinity);
    try testing.expect(hints_module.affine_finite_xy(x0) == null);
    try testing.expect(hints_module.affine_finite_xy(Affine.identity) == null);
    try testing.expect(hints_module.affine_finite_xy(generator) != null);

    var hints = P384Hints.init(&buffer);
    try testing.expect((try hints.twice_affine(x0)).eql(Affine.identity));
    try testing.expectEqual(@as(u32, 0), hints.count);
    try testing.expect((try hints.add_affine(x0, generator)).eql(generator));
    try testing.expect((try hints.add_affine(generator, x0)).eql(generator));
    try testing.expect((try hints.add_affine(x0, x0)).eql(Affine.identity));
    try testing.expectEqual(@as(u32, 0), hints.count);
}

test "registrar hints: twice3 continues through intermediate x == 0" {
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    // P = Q/2 where Q is on-curve with x == 0, so the first double lands on x == 0.
    const q = on_curve_x_zero_point();
    var two_bytes: [48]u8 = @splat(0);
    two_bytes[47] = 2;
    const two = Scalar.fromBytes(two_bytes, .big) catch unreachable; // 2 < n.
    const half = two.invert().toBytes(.big);
    const q_projective: P384 = .{ .x = q.x, .y = q.y, .z = Fe.one };
    const p = Affine.from_projective(try q_projective.mul(half, .big));
    const p_projective: P384 = .{ .x = p.x, .y = p.y, .z = Fe.one };
    const midpoint = Affine.from_projective(p_projective.dbl());
    try testing.expect(midpoint.x.isZero()); // Precondition: 2P has x == 0.

    // Reusing twice_affine would treat that midpoint as infinity after one inverse.
    var composed = P384Hints.init(&buffer);
    const a = try composed.twice_affine(p);
    const b = try composed.twice_affine(a);
    _ = try composed.twice_affine(b);
    try testing.expectEqual(@as(u32, 1), composed.count);
    try testing.expect(b.eql(Affine.identity));

    // Solidity `_twice3Affine` applies the x == 0 sentinel on entry only.
    var hints = P384Hints.init(&buffer);
    const out = try hints.twice3_affine(p);
    try testing.expectEqual(@as(u32, 3), hints.count);
    try testing.expect(out.eql(Affine.from_projective(p_projective.dbl().dbl().dbl())));
}

test "registrar hints: collect_verify_hints rejects invalid inputs" {
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    var valid_sig: [96]u8 = @splat(0);
    valid_sig[47] = 1;
    valid_sig[95] = 1;
    var zero_r = valid_sig;
    @memset(zero_r[0..48], 0);
    var order_r = valid_sig;
    std.mem.writeInt(u384, order_r[0..48], P384.scalar.field_order, .big);
    const public_key: [96]u8 = @splat(0);
    const long_hash: [49]u8 = @splat(1);
    const Case = struct {
        hash: []const u8,
        signature: []const u8,
        key: []const u8,
        want: hints_module.Error,
    };
    const key = &public_key;
    const cases = [_]Case{
        .{
            .hash = &.{1},
            .signature = valid_sig[0..95],
            .key = key,
            .want = error.HintSignatureLength,
        },
        .{
            .hash = &.{1},
            .signature = &valid_sig,
            .key = key[0..95],
            .want = error.HintPublicKeyLength,
        },
        .{ .hash = &long_hash, .signature = &valid_sig, .key = key, .want = error.HintHashLength },
        .{ .hash = &.{1}, .signature = &zero_r, .key = key, .want = error.HintScalarBounds },
        .{ .hash = &.{1}, .signature = &order_r, .key = key, .want = error.HintScalarBounds },
        .{
            .hash = &.{1},
            .signature = &valid_sig,
            .key = key,
            .want = error.HintPublicKeyNotOnCurve,
        },
    };
    for (cases) |case| {
        try testing.expectError(
            case.want,
            P384Hints.collect_verify_hints(case.hash, case.signature, case.key, &buffer),
        );
    }

    const key_pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(@splat(7)));
    const signature = try key_pair.sign("attested payload", null);
    const key_bytes = key_pair.public_key.toUncompressedSec1();
    var digest: [48]u8 = undefined;
    Sha384.hash("a different payload", &digest, .{});
    try testing.expectError(
        error.HintSignatureVerificationFailed,
        P384Hints.collect_verify_hints(&digest, &signature.toBytes(), key_bytes[1..], &buffer),
    );
    Sha384.hash("attested payload", &digest, .{});
    const transcript =
        try P384Hints.collect_verify_hints(&digest, &signature.toBytes(), key_bytes[1..], &buffer);
    try testing.expect(transcript.len > 2 * 48 and transcript.len % 48 == 0);
    // The first two hints are both `s⁻¹`.
    try testing.expectEqualSlices(u8, transcript[0..48], transcript[48..96]);
}

test "registrar hints: certificate parsing extracts keys and signatures" {
    var tbs: [fixture_attestation.len + 64]u8 = undefined;
    const plan =
        try planner.AttestationPlanner.prepare_registration_plan(fixture_attestation, &tbs);
    const root_key = try P384Hints.parse_cert_public_key(plan.root_cert);
    const regional = try P384Hints.parse_cert_signature(plan.certs[0].cert);
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    _ = try P384Hints.collect_verify_hints(
        &regional.hash,
        &regional.signature,
        &root_key,
        &buffer,
    );
    try testing.expectError(
        error.HintCertificateParse,
        P384Hints.parse_cert_public_key(plan.root_cert[0 .. plan.root_cert.len - 1]),
    );
}

/// Property: random hashes, signatures, and keys never crash the transcript, and an
/// accepted transcript is a whole number of 48-byte inverses within the bound.
fn fuzz_verify(_: void, smith: *testing.Smith) anyerror!void {
    var hash: [48]u8 = undefined;
    const hash_length = smith.slice(&hash);
    var signature: [96]u8 = undefined;
    smith.bytes(&signature);
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    // A random key is almost never on the curve; use a real one most of the time.
    const key_pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(@splat(9)));
    const key_bytes = key_pair.public_key.toUncompressedSec1();
    const transcript = P384Hints.collect_verify_hints(
        hash[0..hash_length],
        &signature,
        key_bytes[1..],
        &buffer,
    ) catch return;
    try testing.expect(transcript.len % 48 == 0);
    try testing.expect(transcript.len <= types.hint_stream_size_max);
}

test "registrar hints: fuzz verify inputs" {
    try fuzz.run({}, fuzz_verify, .{ .iterations = 64 });
}

/// Property: signatures the std verifier accepts always produce a transcript.
fn fuzz_valid_signatures(_: void, smith: *testing.Smith) anyerror!void {
    var message: [64]u8 = undefined;
    const length = smith.slice(&message);
    var secret: [48]u8 = @splat(0);
    secret[47] = smith.valueRangeAtMost(u8, 1, 255);
    secret[0] = smith.value(u8) & 0x7f;
    const key_pair = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret));
    const signature = try key_pair.sign(message[0..length], null);
    var digest: [48]u8 = undefined;
    Sha384.hash(message[0..length], &digest, .{});
    const key_bytes = key_pair.public_key.toUncompressedSec1();
    var buffer: [types.hint_stream_size_max]u8 = undefined;
    const transcript =
        try P384Hints.collect_verify_hints(&digest, &signature.toBytes(), key_bytes[1..], &buffer);
    try testing.expect(transcript.len >= 2 * 48);
}

test "registrar hints: fuzz valid signatures" {
    try fuzz.run({}, fuzz_valid_signatures, .{ .iterations = 16 });
}

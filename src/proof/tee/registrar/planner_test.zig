//! Tests for registration planning (base/base `planner.rs` tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cbor = @import("cbor.zig");
const planner = @import("planner.zig");
const types = @import("types.zig");
const keccak256 = @import("../../../common/crypto/keccak.zig").keccak256;
const fuzz = @import("../../../testing/fuzz.zig");

const AttestationPlanner = planner.AttestationPlanner;
const CertManagerKeys = planner.CertManagerKeys;

pub const fixture_attestation = @embedFile("../nitro/testdata/attestation.bin");
const tbs_size = fixture_attestation.len + 64;

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Literal test vectors.
    return out;
}

/// Uncompressed secp256k1 `public_key` embedded in the Base `NitroValidator` fixture.
const fixture_public_key = hex("0433a4701fa871b188983d570e2c2d8cf98fd66eb19ba8ca7617bc8e20e152a5" ++
    "d7f0205eae76e608ce855077e4565be69db4471ef72857253742f9602c11ff04e5");
const fixture_signer = hex("3c32c4ad111a12d7d3af032cffaff7789dfa555f");
const fixture_tbs_keccak =
    hex("59be5f503462c721f5cfc602b612d9f633496681e429b172605f966458abd8e1");
// CertManager vectors for root / first CA / leaf on the NitroValidator.t.sol chain.
const regional_ca_hash =
    hex("1bc41a5b307f0e8e2c7a80bbc3b3a9198251c1343a34ab9bc188d351c9fb87b3");
const regional_ca_revocation_id =
    hex("d985a3a751ddd841816eb3d64041272eed9b695a2d61a46408a1950c0bae28e7");
const leaf_hash = hex("a5853761df0df035211f36e112b8fd2310470a8900e99571f484a29cd30379fb");
const leaf_revocation_id =
    hex("21da5f8225989c43b293c87136a4ed8260f0508197467cb2484191d002f13c19");

fn prepare(attestation: []const u8, tbs: []u8) planner.Error!types.RegistrationPlan {
    return AttestationPlanner.prepare_registration_plan(attestation, tbs);
}

/// Substitute `nonce` for the fixture's `nonce: null` and re-wrap the envelope
/// with the original (now non-matching) signature.
fn fixture_with_nonce(nonce: []const u8, out: []u8) []const u8 {
    assert(nonce.len < 24);
    var tbs: [tbs_size]u8 = undefined;
    const cose = cbor.NitroCose.parse_sign1(fixture_attestation, &tbs) catch unreachable;
    const needle = [_]u8{ 0x65, 'n', 'o', 'n', 'c', 'e', 0xf6 };
    const position = std.mem.indexOf(u8, cose.payload, &needle).?;
    var payload_buffer: [fixture_attestation.len + 32]u8 = undefined;
    var payload_length: usize = 0;
    for ([_][]const u8{
        cose.payload[0 .. position + 6],
        &.{0x40 | @as(u8, @intCast(nonce.len))},
        nonce,
        cose.payload[position + 7 ..],
    }) |part| {
        @memcpy(payload_buffer[payload_length..][0..part.len], part);
        payload_length += part.len;
    }
    assert(payload_length > 256 and payload_length <= 0xffff);
    var length: usize = 0;
    const length_be: [2]u8 = @bitCast(std.mem.nativeToBig(u16, @intCast(payload_length)));
    for ([_][]const u8{
        &.{ 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59 },
        &length_be,
        payload_buffer[0..payload_length],
        &.{ 0x58, 96 },
        cose.signature,
    }) |part| {
        @memcpy(out[length..][0..part.len], part);
        length += part.len;
    }
    return out[0..length];
}

test "registrar planner: authenticate rejects unsigned fields and forged payload" {
    var tbs: [tbs_size]u8 = undefined;
    const plan = try prepare(fixture_attestation, &tbs);
    const scratch = try testing.allocator.create(planner.AuthenticateScratch);
    defer testing.allocator.destroy(scratch);
    try AttestationPlanner.authenticate_registration_plan(&plan, scratch);

    var root_copy: [1024]u8 = undefined;
    var cert_copy: [1024]u8 = undefined;
    var nonce_bytes: [32]u8 = @splat(1);
    for (0..12) |field| {
        var tampered = plan;
        switch (field) {
            0 => tampered.signer = @splat(0),
            1 => tampered.nonce = &nonce_bytes,
            2 => tampered.timestamp_ms += 1,
            3 => tampered.pcr0[0] ^= 1,
            4 => tampered.root_cert_hash = @splat(0),
            5 => {
                @memcpy(root_copy[0..plan.root_cert.len], plan.root_cert);
                root_copy[0] ^= 1;
                tampered.root_cert = root_copy[0..plan.root_cert.len];
            },
            6 => tampered.leaf_cert_hash = @splat(0),
            7 => tampered.certs[0].cert_hash = @splat(0),
            8 => tampered.certs[0].revocation_id = @splat(0),
            9 => tampered.certs[0].parent_cert_hash = @splat(0),
            10 => tampered.certs[0].kind = .leaf,
            else => {
                const cert = plan.certs[0].cert;
                @memcpy(cert_copy[0..cert.len], cert);
                cert_copy[0] ^= 1;
                tampered.certs[0].cert = cert_copy[0..cert.len];
            },
        }
        const result = AttestationPlanner.authenticate_registration_plan(&tampered, scratch);
        try testing.expect(std.meta.isError(result));
    }

    var forged_buffer: [fixture_attestation.len + 64]u8 = undefined;
    var forged_tbs: [tbs_size]u8 = undefined;
    const forged = try prepare(fixture_with_nonce(&.{1}, &forged_buffer), &forged_tbs);
    try testing.expectError(
        error.AttestationSignatureRejected,
        AttestationPlanner.authenticate_registration_plan(&forged, scratch),
    );
}

test "registrar planner: authenticate verifies every certificate signature" {
    const scratch = try testing.allocator.create(planner.AuthenticateScratch);
    defer testing.allocator.destroy(scratch);
    var tbs: [tbs_size]u8 = undefined;
    const plan = try prepare(fixture_attestation, &tbs);
    for (plan.cert_plans()) |*cert| {
        var forged: [fixture_attestation.len]u8 = fixture_attestation.*;
        const offset = std.mem.indexOf(u8, &forged, cert.cert).?;
        forged[offset + cert.cert.len - 1] ^= 1;
        var forged_tbs: [tbs_size]u8 = undefined;
        const forged_plan = try prepare(&forged, &forged_tbs);
        const result = AttestationPlanner.authenticate_registration_plan(&forged_plan, scratch);
        if (result) |_| return error.TestUnexpectedResult else |err| switch (err) {
            error.CertificateSignatureInvalid, error.CertificateSignatureEncoding => {},
            else => return err,
        }
    }
}

test "registrar planner: base fixture pins literals" {
    var tbs: [tbs_size]u8 = undefined;
    // Strict COSE rejects trailing bytes the nitro report parser would accept.
    var trailing: [fixture_attestation.len + 1]u8 = undefined;
    @memcpy(trailing[0..fixture_attestation.len], fixture_attestation);
    trailing[fixture_attestation.len] = 0;
    try testing.expectError(error.CoseTrailingData, prepare(&trailing, &tbs));

    const plan = try prepare(fixture_attestation, &tbs);
    try testing.expectEqualSlices(u8, &fixture_signer, &plan.signer);
    const derived = try AttestationPlanner.signer_from_public_key(&fixture_public_key);
    try testing.expectEqualSlices(u8, &fixture_signer, &derived);
    try testing.expect(plan.nonce == null); // Fixture encodes `nonce: null`.
    try testing.expectEqualSlices(u8, &planner.pinned_root_cert_hash, &plan.root_cert_hash);
    try testing.expectEqualSlices(u8, &planner.pinned_root_cert_hash, &keccak256(plan.root_cert));
    try testing.expectEqualSlices(u8, &leaf_hash, &plan.leaf_cert_hash);
    try testing.expectEqualSlices(u8, &fixture_tbs_keccak, &keccak256(plan.attestation_tbs));
    // Raw protected TLV (not reserialized content-only).
    const protected = [_]u8{ 0x44, 0xa1, 0x01, 0x38, 0x22 };
    try testing.expectEqualSlices(u8, &protected, plan.attestation_tbs[12..17]);
    try testing.expectEqual(@as(u8, 0x40), plan.attestation_tbs[17]);

    try testing.expectEqual(@as(u8, 4), plan.cert_count);
    const first = &plan.certs[0];
    try testing.expectEqual(types.CertKind.ca, first.kind);
    try testing.expectEqualStrings("regional CA", first.label.slice());
    try testing.expectEqualSlices(u8, &regional_ca_hash, &first.cert_hash);
    try testing.expectEqualSlices(u8, &regional_ca_revocation_id, &first.revocation_id);
    try testing.expectEqualSlices(u8, &planner.pinned_root_cert_hash, &first.parent_cert_hash);

    const leaf = &plan.certs[3];
    try testing.expectEqual(types.CertKind.leaf, leaf.kind);
    try testing.expectEqualSlices(u8, &leaf_hash, &leaf.cert_hash);
    try testing.expectEqualSlices(u8, &leaf_revocation_id, &leaf.revocation_id);

    var trailing_der: [1025]u8 = undefined;
    @memcpy(trailing_der[0..leaf.cert.len], leaf.cert);
    trailing_der[leaf.cert.len] = 0;
    const with_trailing = trailing_der[0 .. leaf.cert.len + 1];
    try testing.expect(std.meta.isError(CertManagerKeys.keys(with_trailing)));
}

test "registrar planner: v3 layout rejects trailing bytes in version wrapper" {
    // SEQUENCE { [0] EXPLICIT { INTEGER 2, leftover } } == a0050201020500 inside TBS.
    const trailing_wrapper = [_]u8{ 0x30, 0x07, 0xa0, 0x05, 0x02, 0x01, 0x02, 0x05, 0x00 };
    try testing.expectError(
        error.CertificateVersionTrailingData,
        CertManagerKeys.require_v3_layout(&trailing_wrapper, 2),
    );
    const exact_wrapper = [_]u8{ 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x02 };
    try CertManagerKeys.require_v3_layout(&exact_wrapper, 2);
    try testing.expectError(
        error.CertificateVersionNotV3,
        CertManagerKeys.require_v3_layout(&exact_wrapper, 0),
    );
    try testing.expectError(
        error.CertificateVersionMissing,
        CertManagerKeys.require_v3_layout(&.{ 0x30, 0x03, 0x02, 0x01, 0x02 }, 2),
    );
}

test "registrar planner: pins non-null nonce bytes" {
    const nonce = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var buffer: [fixture_attestation.len + 64]u8 = undefined;
    var tbs: [tbs_size]u8 = undefined;
    const plan = try prepare(fixture_with_nonce(&nonce, &buffer), &tbs);
    try testing.expectEqualSlices(u8, &nonce, plan.nonce.?);
    try testing.expectEqualSlices(u8, &fixture_signer, &plan.signer);
}

test "registrar planner: ca labels and signer key checks" {
    try testing.expectEqualStrings("zonal CA", AttestationPlanner.ca_label(2).slice());
    try testing.expectEqualStrings("issuer / instance CA", AttestationPlanner.ca_label(3).slice());
    try testing.expectEqualStrings("non-root CA 4", AttestationPlanner.ca_label(4).slice());
    try testing.expectEqualStrings("non-root CA 32", AttestationPlanner.ca_label(32).slice());
    try testing.expectError(
        error.PublicKeyFormat,
        AttestationPlanner.signer_from_public_key(fixture_public_key[0..64]),
    );
    var off_curve = fixture_public_key;
    off_curve[64] ^= 1;
    try testing.expectError(
        error.PublicKeyInvalid,
        AttestationPlanner.signer_from_public_key(&off_curve),
    );
}

test "registrar planner: der tlv helpers bound lengths" {
    try testing.expectError(error.DerTooShort, CertManagerKeys.der_tlv_at(&.{0x30}, 0));
    const tlv_at = CertManagerKeys.der_tlv_at;
    try testing.expectError(error.DerLengthInvalid, tlv_at(&.{ 0x30, 0x80 }, 0));
    try testing.expectError(
        error.DerLengthInvalid,
        CertManagerKeys.der_tlv_at(&.{ 0x30, 0x85, 0, 0, 0, 0, 1 }, 0),
    );
    try testing.expectError(error.DerLengthMismatch, tlv_at(&.{ 0x30, 0x02, 0 }, 0));
    const content_octets = CertManagerKeys.der_content_octets;
    try testing.expectError(error.DerLengthMismatch, content_octets(&.{ 0x30, 0x00, 0 }));
    const tlv = try CertManagerKeys.der_tlv_at(&.{ 0x30, 0x81, 0x01, 0xaa, 0x05 }, 0);
    try testing.expectEqualSlices(u8, &.{0xaa}, tlv.content);
    try testing.expectEqual(@as(usize, 4), tlv.end);
}

/// Property: corrupting the fixture never crashes planning, and every plan that
/// still builds keeps the pinned root and a CA-then-leaf certificate order.
fn fuzz_prepare(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [fixture_attestation.len]u8 = fixture_attestation.*;
    var flips: u32 = 0;
    while (flips < 3 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        const index = smith.valueRangeLessThan(u32, 0, buffer.len);
        buffer[index] ^= smith.valueRangeAtMost(u8, 1, 255);
    }
    var tbs: [tbs_size]u8 = undefined;
    const plan = prepare(&buffer, &tbs) catch return;
    try testing.expectEqualSlices(u8, &planner.pinned_root_cert_hash, &plan.root_cert_hash);
    try testing.expect(plan.cert_count >= 2);
    for (plan.cert_plans(), 0..) |*cert, index| {
        const want: types.CertKind = if (index + 1 == plan.cert_count) .leaf else .ca;
        try testing.expectEqual(want, cert.kind);
    }
}

test "registrar planner: fuzz mutated fixture" {
    try fuzz.run({}, fuzz_prepare, .{ .iterations = 256 });
}

/// Property: arbitrary DER never crashes the CertManager key derivation.
fn fuzz_keys(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const keys = CertManagerKeys.keys(buffer[0..length]) catch return;
    try testing.expect(!std.mem.allEqual(u8, &keys.revocation_id, 0));
}

test "registrar planner: fuzz cert manager keys" {
    try fuzz.run({}, fuzz_keys, .{ .iterations = 1024 });
}

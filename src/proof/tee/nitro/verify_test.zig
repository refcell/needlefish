//! Tests for `verify.zig`: base/base's `verify.rs` tests against the real Nitro
//! attestation (`testdata/attestation.bin`, public, from `NitroValidator.t.sol`),
//! plus synthetic attestations signed with deterministic test keys.

const std = @import("std");
const testing = std.testing;
const attestation = @import("attestation.zig");
const errors = @import("errors.zig");
const fixture = @import("test_fixture.zig");
const types = @import("types.zig");
const verify_module = @import("verify.zig");

const AttestationVerifier = verify_module.AttestationVerifier;
const AttestationDocument = attestation.AttestationDocument;

const real_report = @embedFile("testdata/attestation.bin");
const leaf_der = @embedFile("testdata/leaf.der");

test "nitro verify: full real attestation report" {
    const options: verify_module.Options = .{ .trusted_certs_prefix_len = 1 };
    const journal = try AttestationVerifier.verify(real_report, options);
    try testing.expectEqual(types.VerificationResult.success, journal.result);
    try testing.expectEqual(@as(u8, 1), journal.trusted_certs_prefix_len);
    try testing.expectEqual(@as(u64, 0x000001937de1c543), journal.timestamp_ms);
    try testing.expectEqualStrings("i-0de38b2b6853cc9e8-enc0193685e7fee7d85", journal.module_id);
    try testing.expectEqual(@as(u8, 5), journal.cert_count);
    try testing.expectEqual(@as(u64, 2519044085), journal.cert_expiries[0]);
    try testing.expectEqual(@as(u64, 1732994568), journal.cert_expiries[4]);
    try testing.expectEqual(@as(u8, 16), journal.pcr_count);
    try testing.expectEqual(@as(usize, 0), journal.user_data.len);
    try testing.expectEqual(@as(usize, 0), journal.nonce.len);
    try testing.expect(journal.public_key.len > 0);

    var buffer: [8192]u8 = undefined;
    const encoded = try journal.encode(&buffer);
    try testing.expectEqual(journal.encoded_size(), encoded.len);
    // Tuple offset, then the static head fields.
    try testing.expectEqual(@as(u64, 32), std.mem.readInt(u64, encoded[24..32], .big));
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, encoded[56..64], .big));
    try testing.expectEqual(journal.timestamp_ms, std.mem.readInt(u64, encoded[120..128], .big));
}

test "nitro verify: zero trusted prefix and VerifierInput entry" {
    const journal = try AttestationVerifier.verify(real_report, .{});
    try testing.expectEqual(types.VerificationResult.success, journal.result);
    const input: types.VerifierInput = .{
        .trusted_certs_prefix_len = 0,
        .attestation_report = real_report,
    };
    const root = verify_module.aws_nitro_root_der;
    const from_input = try AttestationVerifier.verify_input(&input, root);
    try testing.expectEqualSlices(u8, &journal.certs[4], &from_input.certs[4]);
}

test "nitro verify: corrupted attestation rejected" {
    const result = AttestationVerifier.verify(&.{ 0xde, 0xad }, .{});
    // 0xde is a tag head with reserved additional info 30.
    try testing.expectError(error.ReservedAdditionalInfo, result);
    try testing.expectEqual(errors.Category.cbor, errors.category(error.ReservedAdditionalInfo));
}

test "nitro verify: bad COSE signature rejected" {
    var tampered: [real_report.len]u8 = real_report.*;
    tampered[tampered.len - 1] ^= 0x01; // Signature is the last element.
    try testing.expectError(error.CoseSignatureInvalid, AttestationVerifier.verify(&tampered, .{}));
}

test "nitro verify: untrusted root rejected unless the check is disabled" {
    const options: verify_module.Options = .{ .trusted_root_der = leaf_der };
    const result = AttestationVerifier.verify(real_report, options);
    try testing.expectError(error.RootCertNotTrusted, result);
    _ = try AttestationVerifier.verify(real_report, .{ .trusted_root_der = null });
}

test "nitro verify: wrong COSE algorithm rejected" {
    const cose = try attestation.CoseSign1.parse(real_report);
    const signer = try fixture.key_pair(9);
    var buffer: [8192]u8 = undefined;
    const es256 = [_]u8{ 0xa1, 0x01, 0x26 };
    const spec: fixture.CoseSpec = .{ .protected = &es256 };
    const report = try fixture.build_cose(&buffer, cose.payload, &signer, spec);
    const result = AttestationVerifier.verify(report, .{});
    try testing.expectError(error.CoseAlgorithmUnsupported, result);
}

/// A synthetic root and leaf with deterministic keys.
const Synthetic = struct {
    root_key: std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    leaf_key: std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    root_buffer: [1024]u8 = undefined,
    leaf_buffer: [1024]u8 = undefined,
    root: []const u8 = &.{},
    leaf: []const u8 = &.{},

    fn init(synthetic: *Synthetic, leaf_cert_spec: fixture.CertSpec) !void {
        synthetic.root_key = try fixture.key_pair(1);
        synthetic.leaf_key = try fixture.key_pair(2);
        const root_spec: fixture.CertSpec = .{ .issuer = "root", .subject = "root", .ca = true };
        synthetic.root = try fixture.build_cert(
            &synthetic.root_buffer,
            root_spec,
            &synthetic.root_key,
            &synthetic.root_key,
        );
        synthetic.leaf = try fixture.build_cert(
            &synthetic.leaf_buffer,
            leaf_cert_spec,
            &synthetic.leaf_key,
            &synthetic.root_key,
        );
    }

    fn report(
        synthetic: *const Synthetic,
        out: []u8,
        document_buffer: []u8,
        spec: fixture.DocumentSpec,
        cose_spec: fixture.CoseSpec,
    ) ![]const u8 {
        const document = try fixture.build_document(document_buffer, spec);
        return fixture.build_cose(out, document, &synthetic.leaf_key, cose_spec);
    }
};

const leaf_spec: fixture.CertSpec = .{ .issuer = "root", .subject = "leaf", .ca = false };

test "nitro verify: synthetic attestation with optional fields and tag 18" {
    var synthetic: Synthetic = undefined;
    try synthetic.init(leaf_spec);
    var document_buffer: [4096]u8 = undefined;
    var buffer: [8192]u8 = undefined;
    const spec: fixture.DocumentSpec = .{
        .certificate = synthetic.leaf,
        .cabundle = &.{synthetic.root},
        .nonce = "nonce-1",
        .user_data = "user",
        .public_key = &.{ 0x04, 0x05 },
    };
    const report = try synthetic.report(&buffer, &document_buffer, spec, .{ .tagged = true });
    const journal = try AttestationVerifier.verify(report, .{ .trusted_root_der = synthetic.root });
    try testing.expectEqualStrings("nonce-1", journal.nonce);
    try testing.expectEqualStrings("user", journal.user_data);
    try testing.expectEqual(@as(u8, 2), journal.cert_count);
    try testing.expectEqual(@as(u8, 3), journal.pcr_count);
    // The AWS root is the default trust anchor: a self-made root is rejected.
    try testing.expectError(error.RootCertNotTrusted, AttestationVerifier.verify(report, .{}));
}

test "nitro verify: synthetic reject paths" {
    var synthetic: Synthetic = undefined;
    try synthetic.init(leaf_spec);
    var document_buffer: [4096]u8 = undefined;
    var buffer: [8192]u8 = undefined;
    const options: verify_module.Options = .{ .trusted_root_der = synthetic.root };
    const base: fixture.DocumentSpec = .{
        .certificate = synthetic.leaf,
        .cabundle = &.{synthetic.root},
    };

    // Signed by a key other than the leaf's.
    const document = try fixture.build_document(&document_buffer, base);
    const stranger = try fixture.key_pair(7);
    const forged = try fixture.build_cose(&buffer, document, &stranger, .{});
    const forged_result = AttestationVerifier.verify(forged, options);
    try testing.expectError(error.CoseSignatureInvalid, forged_result);

    var debug = base;
    debug.pcr_fill = 0;
    const debug_report = try synthetic.report(&buffer, &document_buffer, debug, .{});
    try testing.expectError(error.PcrsAllZero, AttestationVerifier.verify(debug_report, options));

    var late = base;
    late.timestamp_ms = 2_300_000_000_000; // 2042, after notAfter 2040.
    const late_report = try synthetic.report(&buffer, &document_buffer, late, .{});
    const late_result = AttestationVerifier.verify(late_report, options);
    try testing.expectError(error.CertificateExpired, late_result);
}

test "nitro verify: synthetic expired leaf rejected" {
    var synthetic: Synthetic = undefined;
    var expired = leaf_spec;
    expired.not_after = "210101000000Z";
    try synthetic.init(expired);
    var document_buffer: [4096]u8 = undefined;
    var buffer: [8192]u8 = undefined;
    const spec: fixture.DocumentSpec = .{
        .certificate = synthetic.leaf,
        .cabundle = &.{synthetic.root},
    };
    const report = try synthetic.report(&buffer, &document_buffer, spec, .{});
    const options: verify_module.Options = .{ .trusted_root_der = synthetic.root };
    try testing.expectError(error.CertificateExpired, AttestationVerifier.verify(report, options));
}

/// The base/base `valid_doc` fixture for M-02 checks.
fn valid_doc() AttestationDocument {
    var document: AttestationDocument = undefined;
    document.module_id = "test-module";
    document.timestamp_ms = 1_700_000_000_000;
    document.digest = "SHA384";
    document.pcrs[0] = .{ .index = 0, .value = @splat(1) };
    document.pcr_count = 1;
    document.certificate = &.{0x30};
    document.cabundle[0] = &.{0x30};
    document.cabundle_count = 1;
    document.public_key = null;
    document.user_data = null;
    document.nonce = null;
    return document;
}

fn expect_content(expected: anyerror, document: *const AttestationDocument) !void {
    try testing.expectError(expected, AttestationVerifier.validate_attestation_content(document));
}

test "nitro verify: M-02 content validation" {
    try AttestationVerifier.validate_attestation_content(&valid_doc());
    var document = valid_doc();
    document.module_id = "";
    try expect_content(error.ModuleIdEmpty, &document);
    document = valid_doc();
    document.timestamp_ms = 0;
    try expect_content(error.TimestampZero, &document);
    document = valid_doc();
    document.digest = "SHA256";
    try expect_content(error.DigestUnsupported, &document);
    document = valid_doc();
    document.cabundle_count = 0;
    try expect_content(error.CabundleCount, &document);
    document = valid_doc();
    document.pcr_count = 0;
    try expect_content(error.PcrCount, &document);
    document = valid_doc();
    document.pcrs[0].value = @splat(0);
    document.pcrs[1] = .{ .index = 1, .value = @splat(0) };
    document.pcr_count = 2;
    try expect_content(error.PcrsAllZero, &document);
    document = valid_doc();
    document.pcrs[1] = .{ .index = 32, .value = @splat(0) };
    document.pcr_count = 2;
    try expect_content(error.PcrIndex, &document);
    document.pcrs[1].index = 31;
    try AttestationVerifier.validate_attestation_content(&document);
}

test "nitro verify: M-02 optional field limits" {
    const zeros: [1025]u8 = @splat(0);
    var document = valid_doc();
    document.public_key = &.{};
    try expect_content(error.PublicKeyLength, &document);
    document.public_key = zeros[0..1025];
    try expect_content(error.PublicKeyLength, &document);
    document = valid_doc();
    document.user_data = zeros[0..513];
    try expect_content(error.UserDataLength, &document);
    document = valid_doc();
    document.nonce = zeros[0..513];
    try expect_content(error.NonceLength, &document);
    document = valid_doc();
    document.certificate = zeros[0..1025];
    try expect_content(error.CertificateLength, &document);
    document = valid_doc();
    document.cabundle[0] = &.{};
    try expect_content(error.CabundleCertificateLength, &document);
    document = valid_doc();
    document.public_key = zeros[0..65];
    document.user_data = zeros[0..512];
    document.nonce = zeros[0..256];
    try AttestationVerifier.validate_attestation_content(&document);
}

const fuzz = @import("../../../testing/fuzz.zig");

/// Property: corrupting a real report never crashes verification, and a report that
/// still verifies carries the original signed payload (only the unsigned
/// unprotected header may change).
fn fuzz_verify_mutated(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [real_report.len]u8 = real_report.*;
    var flips: u32 = 0;
    while (flips < 3 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        const index = smith.valueRangeLessThan(u32, 0, buffer.len);
        buffer[index] ^= smith.valueRangeAtMost(u8, 1, 255);
    }
    const journal = AttestationVerifier.verify(&buffer, .{ .trusted_certs_prefix_len = 4 }) catch
        return;
    try testing.expectEqual(types.VerificationResult.success, journal.result);
    const original = try attestation.CoseSign1.parse(real_report);
    const mutated = try attestation.CoseSign1.parse(&buffer);
    try testing.expectEqualSlices(u8, original.payload, mutated.payload);
    try testing.expectEqualSlices(u8, original.signature, mutated.signature);
}

test "nitro verify: fuzz mutated real report" {
    try fuzz.run({}, fuzz_verify_mutated, .{ .iterations = 64 });
}

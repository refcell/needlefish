//! Tests for `x509.zig`, ported from base/base `x509.rs` against the real AWS Nitro
//! certificate chain committed under `testdata/` (public, from `NitroValidator.t.sol`).

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509.zig");
const types = @import("types.zig");
const fuzz = @import("../../../testing/fuzz.zig");

const CertChain = x509.CertChain;
const ChainResult = x509.ChainResult;

const root_der = @embedFile("aws_nitro_root_g1.der");
const inter1_der = @embedFile("testdata/inter1.der");
const inter2_der = @embedFile("testdata/inter2.der");
const inter3_der = @embedFile("testdata/inter3.der");
const leaf_der = @embedFile("testdata/leaf.der");
const full_chain = [_][]const u8{ root_der, inter1_der, inter2_der, inter3_der, leaf_der };

/// 2024-11-30T16:22:45Z, inside every certificate's validity window.
const valid_timestamp_ms: u64 = 0x000001937de1c543;

/// `notAfter` of root, intermediates 1-3, and leaf.
const expected_expiries = [_]u64{ 2519044085, 1734505665, 1733447694, 1733056891, 1732994568 };

fn verify(certs: []const []const u8, prefix: u32, timestamp_ms: u64) !ChainResult {
    const chain = try CertChain.from_der(certs);
    var result: ChainResult = undefined;
    try chain.verify_chain(prefix, timestamp_ms, &result);
    return result;
}

test "nitro x509: root CA self-signed verifies" {
    const result = try verify(&.{root_der}, 0, 1_700_000_000_000);
    try testing.expectEqual(@as(u8, 1), result.count);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root_der, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &result.digests[0]);
    try testing.expectEqual(expected_expiries[0], result.expiries[0]);
}

test "nitro x509: full chain verifies with every trusted prefix" {
    var prefix: u32 = 0;
    while (prefix <= full_chain.len) : (prefix += 1) {
        const result = try verify(&full_chain, prefix, valid_timestamp_ms);
        try testing.expectEqual(@as(u8, 5), result.count);
        // AWS issues progressively shorter-lived certificates down the chain.
        for (1..result.count) |index| {
            try testing.expect(result.expiries[index] <= result.expiries[index - 1]);
        }
        try testing.expectEqualSlices(u64, &expected_expiries, result.expiries[0..5]);
    }
}

test "nitro x509: duplicate root rejected" {
    const certs = [_][]const u8{ root_der, root_der, inter1_der, inter2_der, inter3_der, leaf_der };
    try testing.expectError(error.SelfIssuedNotAnchor, verify(&certs, 1, valid_timestamp_ms));
    try testing.expectError(error.SelfIssuedNotAnchor, verify(&certs, 2, valid_timestamp_ms));
}

test "nitro x509: digests are accumulated path hashes" {
    const result = try verify(&full_chain, 5, 0);
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var root_hash: [32]u8 = undefined;
    Sha256.hash(root_der, &root_hash, .{});
    try testing.expectEqualSlices(u8, &root_hash, &result.digests[0]);
    var inter1_hash: [32]u8 = undefined;
    Sha256.hash(inter1_der, &inter1_hash, .{});
    var hasher = Sha256.init(.{});
    hasher.update(&root_hash);
    hasher.update(&inter1_hash);
    try testing.expectEqualSlices(u8, &hasher.finalResult(), &result.digests[1]);
}

test "nitro x509: leaf public key is an uncompressed P-384 point" {
    const chain = try CertChain.from_der(&full_chain);
    const key = chain.leaf_public_key();
    try testing.expectEqual(@as(usize, 97), key.len);
    try testing.expectEqual(@as(u8, 0x04), key[0]);
}

test "nitro x509: parse errors" {
    try testing.expectError(error.ChainEmpty, CertChain.from_der(&.{}));
    try testing.expectError(error.CertificateMalformed, CertChain.from_der(&.{"\xde\xad\xbe\xef"}));
    var aliased: [inter1_der.len + 23]u8 = undefined;
    @memcpy(aliased[0..inter1_der.len], inter1_der);
    @memcpy(aliased[inter1_der.len..], "chain-4256-trailing-der");
    const certs = [_][]const u8{ root_der, &aliased, inter2_der, inter3_der, leaf_der };
    try testing.expectError(error.CertificateTrailingData, CertChain.from_der(&certs));
    const too_long: [types.chain_length_max + 1][]const u8 = @splat(root_der);
    try testing.expectError(error.ChainTooLong, CertChain.from_der(&too_long));
}

test "nitro x509: trusted prefix skips validation and is bounded" {
    const result = try verify(&.{root_der}, 1, 0);
    try testing.expectEqual(@as(u8, 1), result.count);
    try testing.expectError(error.TrustedPrefixTooLong, verify(&.{root_der}, 5, 0));
}

test "nitro x509: validity window is checked against the attestation timestamp" {
    try testing.expectError(error.CertificateExpired, verify(&full_chain, 0, 2_000_000_000_000));
    try testing.expectError(
        error.CertificateNotYetValid,
        verify(&full_chain, 1, 1_000_000_000_000),
    );
}

test "nitro x509: wrong chain order rejected" {
    const certs = [_][]const u8{ root_der, inter2_der, inter1_der, inter3_der, leaf_der };
    try testing.expectError(error.IssuerMismatch, verify(&certs, 0, valid_timestamp_ms));
}

test "nitro x509: tampered certificate fails parsing or signature verification" {
    var tampered: [inter1_der.len]u8 = inter1_der.*;
    tampered[tampered.len / 2] ^= 0xff;
    const certs = [_][]const u8{ root_der, &tampered, inter2_der, inter3_der, leaf_der };
    if (verify(&certs, 0, valid_timestamp_ms)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
    // Flip a byte inside the signature value itself: parsing succeeds, verification fails.
    var bad_signature: [inter1_der.len]u8 = inter1_der.*;
    bad_signature[bad_signature.len - 5] ^= 0x01;
    const certs_signature = [_][]const u8{
        root_der, &bad_signature, inter2_der, inter3_der, leaf_der,
    };
    const chain = try CertChain.from_der(&certs_signature);
    var result: ChainResult = undefined;
    try testing.expectError(
        error.CertificateSignatureInvalid,
        chain.verify_chain(0, valid_timestamp_ms, &result),
    );
}

test "nitro x509: expiries do not depend on the trusted prefix" {
    const prefix4 = try verify(&full_chain, 4, valid_timestamp_ms);
    const all = try verify(&full_chain, 5, 0);
    try testing.expectEqualSlices(u64, all.expiries[0..5], prefix4.expiries[0..5]);
    try testing.expectEqualSlices(u64, &expected_expiries, all.expiries[0..5]);
}

test "nitro x509: parsed extensions match the Nitro profile" {
    const root = try x509.ParsedCert.parse(root_der);
    try testing.expect(root.basic_constraints.?.ca);
    try testing.expect(root.basic_constraints.?.path_len == null);
    try testing.expect(root.key_usage.? & x509.key_usage_key_cert_sign != 0);
    try testing.expect(root.self_issued());
    const inter1 = try x509.ParsedCert.parse(inter1_der);
    try testing.expectEqual(@as(?u32, 2), inter1.basic_constraints.?.path_len);
    const leaf = try x509.ParsedCert.parse(leaf_der);
    try testing.expect(!leaf.basic_constraints.?.ca);
    try testing.expect(leaf.key_usage.? & x509.key_usage_digital_signature != 0);
    try testing.expect(!leaf.self_issued());
}

test "nitro x509: a CA used as leaf position check" {
    // Root then inter1 as a two-certificate chain: inter1 is the leaf and is a CA.
    const ca_leaf = [_][]const u8{ root_der, inter1_der };
    try testing.expectError(error.LeafIsCa, verify(&ca_leaf, 0, valid_timestamp_ms));
    // The leaf cannot act as a CA for another certificate.
    const leaf_as_ca = [_][]const u8{ leaf_der, leaf_der };
    try testing.expectError(error.CaNotCa, verify(&leaf_as_ca, 0, valid_timestamp_ms));
}

/// Property: random bytes never crash the certificate parser.
fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const cert = x509.ParsedCert.parse(buffer[0..length]) catch return;
    try testing.expect(cert.tbs.len < length);
}

/// Property: corrupted real certificates are rejected or still parse, never crash,
/// and never verify under the original issuer once the signed bytes change.
fn fuzz_mutate(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [inter3_der.len]u8 = inter3_der.*;
    var flips: u32 = 0;
    while (flips < 3 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        const index = smith.valueRangeLessThan(u32, 0, buffer.len);
        buffer[index] ^= smith.valueRangeAtMost(u8, 1, 255);
    }
    const certs = [_][]const u8{ inter2_der, &buffer };
    const chain = CertChain.from_der(&certs) catch return;
    var result: ChainResult = undefined;
    chain.verify_chain(1, valid_timestamp_ms, &result) catch return;
    try testing.expectEqualSlices(u8, inter3_der, &buffer);
}

test "nitro x509: fuzz parse" {
    try fuzz.run({}, fuzz_parse, .{ .iterations = 1024 });
}

test "nitro x509: fuzz mutated certificate" {
    try fuzz.run({}, fuzz_mutate, .{ .iterations = 256 });
}

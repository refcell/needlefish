//! X.509 certificate chain validation for Nitro attestations (base/base `x509.rs`).
//!
//! Verifies root, intermediates, and leaf with P-384 ECDSA-SHA384 only, the
//! algorithm every Nitro chain uses and `CertManager.sol` enforces, plus the M-01
//! audit checks: basicConstraints, keyUsage, path length, issuer/subject chaining,
//! and validity windows against the attestation timestamp.
//!
//! `std.crypto.Certificate.parse` indexes its input without bounds checks, which is
//! unsafe for attacker-controlled DER, and skips basicConstraints and keyUsage. So
//! this file walks the DER itself with a bounds-checked reader and reuses
//! `std.crypto.Certificate.parseTime` for UTCTime/GeneralizedTime and
//! `std.crypto.sign.ecdsa.EcdsaP384Sha384` for signatures.

const std = @import("std");
const assert = std.debug.assert;
const errors = @import("errors.zig");
const types = @import("types.zig");

const Certificate = std.crypto.Certificate;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = errors.Error;

/// 1.2.840.10045.4.3.3 ecdsa-with-SHA384.
pub const oid_ecdsa_with_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
/// 1.2.840.10045.2.1 id-ecPublicKey.
pub const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
/// 1.3.132.0.34 secp384r1.
pub const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };

/// keyUsage bits as the first two content bytes, big endian (RFC 5280 4.2.1.3).
pub const key_usage_digital_signature: u16 = 0x8000;
pub const key_usage_key_cert_sign: u16 = 0x0400;

/// Bound on extensions per certificate; Nitro certificates carry at most five.
const extension_count_max: u32 = 64;

const tag_boolean: u8 = 0x01;
const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_octet_string: u8 = 0x04;
const tag_oid: u8 = 0x06;
const tag_utc_time: u8 = 0x17;
const tag_generalized_time: u8 = 0x18;
const tag_sequence: u8 = 0x30;
const tag_version: u8 = 0xa0;
const tag_extensions: u8 = 0xa3;

const Tlv = struct {
    tag: u8,
    content: []const u8,
};

/// Bounds-checked DER reader over one level of TLVs.
const DerReader = struct {
    bytes: []const u8,
    position: u32 = 0,

    fn init(bytes: []const u8) DerReader {
        assert(bytes.len <= std.math.maxInt(u32));
        return .{ .bytes = bytes };
    }

    fn at_end(reader: *const DerReader) bool {
        assert(reader.position <= reader.bytes.len);
        return reader.position == reader.bytes.len;
    }

    fn peek_tag(reader: *const DerReader) ?u8 {
        assert(reader.position <= reader.bytes.len);
        if (reader.at_end()) return null;
        return reader.bytes[reader.position];
    }

    fn next(reader: *DerReader) Error!Tlv {
        const rest = reader.bytes[reader.position..];
        if (rest.len < 2) return error.CertificateMalformed;
        const tag = rest[0];
        if (tag & 0x1f == 0x1f) return error.CertificateMalformed; // High tag numbers.
        var header: u32 = 2;
        var length: u64 = rest[1];
        if (length >= 0x80) {
            const width: u32 = @intCast(length & 0x7f);
            if (width == 0 or width > 4) return error.CertificateMalformed;
            if (rest.len < 2 + width) return error.CertificateMalformed;
            length = 0;
            for (rest[2..][0..width]) |byte| length = (length << 8) | byte;
            header += width;
        }
        if (length > rest.len - header) return error.CertificateMalformed;
        const end: u32 = header + @as(u32, @intCast(length));
        reader.position += end;
        assert(reader.position <= reader.bytes.len);
        return .{ .tag = tag, .content = rest[header..end] };
    }

    fn expect(reader: *DerReader, tag: u8) Error!Tlv {
        const tlv = try reader.next();
        if (tlv.tag != tag) return error.CertificateMalformed;
        assert(tlv.content.len <= reader.bytes.len);
        return tlv;
    }

    /// The full encoding (header and content) of the next TLV.
    fn expect_raw(reader: *DerReader, tag: u8) Error![]const u8 {
        const start = reader.position;
        _ = try reader.expect(tag);
        assert(reader.position > start);
        return reader.bytes[start..reader.position];
    }
};

pub const BasicConstraints = struct {
    ca: bool,
    path_len: ?u32,
};

/// The fields of one certificate the chain checks need. Slices borrow from `der`.
pub const ParsedCert = struct {
    der: []const u8,
    /// Full DER of `tbsCertificate`, the signed message.
    tbs: []const u8,
    issuer: []const u8,
    subject: []const u8,
    not_before_s: u64,
    not_after_s: u64,
    signature_algorithm: []const u8,
    public_key_algorithm: []const u8,
    /// Named curve OID; empty when the key parameters are not an OID.
    curve: []const u8,
    /// SEC1 point from subjectPublicKey.
    public_key: []const u8,
    /// DER ECDSA signature from signatureValue.
    signature: []const u8,
    basic_constraints: ?BasicConstraints,
    key_usage: ?u16,

    pub fn parse(der: []const u8) Error!ParsedCert {
        var outer = DerReader.init(der);
        const certificate = try outer.expect(tag_sequence);
        if (!outer.at_end()) return error.CertificateTrailingData;
        var reader = DerReader.init(certificate.content);
        var cert: ParsedCert = undefined;
        cert.der = der;
        cert.tbs = try reader.expect_raw(tag_sequence);
        const signature_algorithm = try reader.expect_raw(tag_sequence);
        cert.signature = try bit_string_bytes(try reader.expect(tag_bit_string));
        if (!reader.at_end()) return error.CertificateMalformed;
        cert.signature_algorithm = try algorithm_oid(signature_algorithm);
        try cert.parse_tbs(signature_algorithm);
        assert(cert.tbs.len < der.len);
        return cert;
    }

    fn parse_tbs(cert: *ParsedCert, signature_algorithm: []const u8) Error!void {
        var tbs_outer = DerReader.init(cert.tbs);
        var reader = DerReader.init((try tbs_outer.expect(tag_sequence)).content);
        if (reader.peek_tag() == tag_version) try check_version(try reader.next());
        _ = try reader.expect(tag_integer); // serialNumber
        const tbs_algorithm = try reader.expect_raw(tag_sequence);
        // RFC 5280 4.1.2.3: must match the outer signatureAlgorithm.
        if (!std.mem.eql(u8, tbs_algorithm, signature_algorithm)) {
            return error.CertificateMalformed;
        }
        cert.issuer = try reader.expect_raw(tag_sequence);
        var validity = DerReader.init((try reader.expect(tag_sequence)).content);
        cert.not_before_s = try cert.parse_time(try validity.next());
        cert.not_after_s = try cert.parse_time(try validity.next());
        if (!validity.at_end()) return error.CertificateMalformed;
        cert.subject = try reader.expect_raw(tag_sequence);
        try cert.parse_public_key((try reader.expect(tag_sequence)).content);
        // issuerUniqueID [1] and subjectUniqueID [2], primitive or constructed.
        var unique_ids: u32 = 0;
        while (unique_ids < 2) : (unique_ids += 1) {
            const tag = reader.peek_tag() orelse break;
            if (tag & 0xdf != 0x81 and tag & 0xdf != 0x82) break;
            _ = try reader.next();
        }
        cert.basic_constraints = null;
        cert.key_usage = null;
        if (reader.peek_tag() == tag_extensions) {
            var wrapper = DerReader.init((try reader.next()).content);
            try cert.parse_extensions((try wrapper.expect(tag_sequence)).content);
            if (!wrapper.at_end()) return error.CertificateMalformed;
        }
        if (!reader.at_end()) return error.CertificateMalformed;
    }

    fn parse_public_key(cert: *ParsedCert, content: []const u8) Error!void {
        var reader = DerReader.init(content);
        var algorithm = DerReader.init((try reader.expect(tag_sequence)).content);
        cert.public_key_algorithm = (try algorithm.expect(tag_oid)).content;
        cert.curve = &.{};
        if (algorithm.peek_tag() == tag_oid) cert.curve = (try algorithm.next()).content;
        cert.public_key = try bit_string_bytes(try reader.expect(tag_bit_string));
        if (!reader.at_end()) return error.CertificateMalformed;
        assert(cert.public_key.len < content.len);
    }

    fn parse_extensions(cert: *ParsedCert, content: []const u8) Error!void {
        var reader = DerReader.init(content);
        var count: u32 = 0;
        while (!reader.at_end()) : (count += 1) {
            if (count == extension_count_max) return error.CertificateMalformed;
            var extension = DerReader.init((try reader.expect(tag_sequence)).content);
            const oid = (try extension.expect(tag_oid)).content;
            if (extension.peek_tag() == tag_boolean) _ = try extension.next(); // critical
            const value = (try extension.expect(tag_octet_string)).content;
            if (!extension.at_end()) return error.CertificateMalformed;
            if (std.mem.eql(u8, oid, &oid_basic_constraints)) {
                if (cert.basic_constraints != null) return error.CertificateMalformed;
                cert.basic_constraints = try parse_basic_constraints(value);
            } else if (std.mem.eql(u8, oid, &oid_key_usage)) {
                if (cert.key_usage != null) return error.CertificateMalformed;
                cert.key_usage = try parse_key_usage(value);
            }
        }
        assert(count <= extension_count_max);
    }

    /// Seconds since the Unix epoch. Times before 1970 are rejected: base/base
    /// rejects negative timestamps, and `parseTime` cannot represent them.
    fn parse_time(cert: *const ParsedCert, tlv: Tlv) Error!u64 {
        if (tlv.tag != tag_utc_time and tlv.tag != tag_generalized_time) {
            return error.CertificateTimeInvalid;
        }
        const start: u32 = @intCast(@intFromPtr(tlv.content.ptr) - @intFromPtr(cert.der.ptr));
        assert(start + tlv.content.len <= cert.der.len);
        const std_cert: Certificate = .{ .buffer = cert.der, .index = 0 };
        const element: Certificate.der.Element = .{
            .identifier = @bitCast(tlv.tag),
            .slice = .{ .start = start, .end = start + @as(u32, @intCast(tlv.content.len)) },
        };
        const seconds = std_cert.parseTime(element) catch return error.CertificateTimeInvalid;
        const before_1970 = if (tlv.tag == tag_utc_time)
            tlv.content[0] >= '5' and tlv.content[0] <= '6'
        else
            std.mem.order(u8, tlv.content[0..4], "1970") == .lt;
        if (before_1970) return error.CertificateTimeInvalid;
        return seconds;
    }

    pub fn self_issued(cert: *const ParsedCert) bool {
        assert(cert.issuer.len > 0 and cert.subject.len > 0);
        return std.mem.eql(u8, cert.issuer, cert.subject);
    }
};

fn check_version(tlv: Tlv) Error!void {
    assert(tlv.tag == tag_version);
    var reader = DerReader.init(tlv.content);
    const version = try reader.expect(tag_integer);
    if (!reader.at_end()) return error.CertificateMalformed;
    if (version.content.len != 1 or version.content[0] > 2) return error.CertificateMalformed;
}

/// Content of a BIT STRING with zero unused bits.
fn bit_string_bytes(tlv: Tlv) Error![]const u8 {
    assert(tlv.tag == tag_bit_string);
    if (tlv.content.len < 1 or tlv.content[0] != 0) return error.CertificateMalformed;
    return tlv.content[1..];
}

fn algorithm_oid(algorithm_identifier: []const u8) Error![]const u8 {
    var outer = DerReader.init(algorithm_identifier);
    var reader = DerReader.init((try outer.expect(tag_sequence)).content);
    const oid = try reader.expect(tag_oid);
    assert(oid.content.len < algorithm_identifier.len);
    return oid.content;
}

fn parse_basic_constraints(value: []const u8) Error!BasicConstraints {
    var outer = DerReader.init(value);
    var reader = DerReader.init((try outer.expect(tag_sequence)).content);
    if (!outer.at_end()) return error.CertificateMalformed;
    var constraints: BasicConstraints = .{ .ca = false, .path_len = null };
    if (reader.peek_tag() == tag_boolean) {
        const ca = (try reader.next()).content;
        if (ca.len != 1) return error.CertificateMalformed;
        constraints.ca = ca[0] != 0;
    }
    if (reader.peek_tag() == tag_integer) {
        const integer = (try reader.next()).content;
        if (integer.len == 0 or integer.len > 4 or integer[0] & 0x80 != 0) {
            return error.CertificateMalformed;
        }
        var path_len: u32 = 0;
        for (integer) |byte| path_len = (path_len << 8) | byte;
        constraints.path_len = path_len;
    }
    if (!reader.at_end()) return error.CertificateMalformed;
    return constraints;
}

fn parse_key_usage(value: []const u8) Error!u16 {
    var reader = DerReader.init(value);
    const tlv = try reader.expect(tag_bit_string);
    if (!reader.at_end()) return error.CertificateMalformed;
    if (tlv.content.len < 2 or tlv.content[0] > 7) return error.CertificateMalformed;
    const high: u16 = tlv.content[1];
    const low: u16 = if (tlv.content.len > 2) tlv.content[2] else 0;
    return (high << 8) | low;
}

/// Accumulated path digests, as the on-chain `NitroEnclaveVerifier` computes them:
/// `d[0] = sha256(c[0])`, `d[i] = sha256(d[i-1] || sha256(c[i]))`.
pub fn compute_path_digests(certs_der: []const []const u8, out: [][32]u8) void {
    assert(out.len >= certs_der.len);
    var path_digest: [32]u8 = @splat(0);
    for (certs_der, 0..) |der, index| {
        var cert_digest: [32]u8 = undefined;
        Sha256.hash(der, &cert_digest, .{});
        if (index == 0) {
            path_digest = cert_digest;
        } else {
            var hasher = Sha256.init(.{});
            hasher.update(&path_digest);
            hasher.update(&cert_digest);
            hasher.final(&path_digest);
        }
        out[index] = path_digest;
    }
}

/// Path digests and `notAfter` expiries, one per certificate, root first.
pub const ChainResult = struct {
    digests: [types.chain_length_max][32]u8,
    expiries: [types.chain_length_max]u64,
    count: u8,
};

pub const CertChain = struct {
    certs: [types.chain_length_max]ParsedCert,
    count: u8,

    /// Parse DER certificates in chain order: root, intermediates, leaf.
    pub fn from_der(certs_der: []const []const u8) Error!CertChain {
        if (certs_der.len == 0) return error.ChainEmpty;
        if (certs_der.len > types.chain_length_max) return error.ChainTooLong;
        var chain: CertChain = undefined;
        for (certs_der, 0..) |der, index| {
            chain.certs[index] = try ParsedCert.parse(der);
        }
        chain.count = @intCast(certs_der.len);
        assert(chain.count >= 1 and chain.count <= types.chain_length_max);
        return chain;
    }

    /// Verify every certificate past the first `trusted_prefix_len`, which the
    /// caller already trusts (on-chain cache). Digests and expiries cover all.
    pub fn verify_chain(
        chain: *const CertChain,
        trusted_prefix_len: u32,
        timestamp_ms: u64,
        result: *ChainResult,
    ) Error!void {
        assert(chain.count >= 1 and chain.count <= types.chain_length_max);
        if (trusted_prefix_len > chain.count) return error.TrustedPrefixTooLong;
        var ders: [types.chain_length_max][]const u8 = undefined;
        for (chain.certs[0..chain.count], 0..) |*cert, index| ders[index] = cert.der;
        compute_path_digests(ders[0..chain.count], result.digests[0..chain.count]);
        result.count = chain.count;
        for (chain.certs[0..chain.count], 0..) |*cert, index| {
            result.expiries[index] = cert.not_after_s;
            // Only the trust anchor may be self-issued: a duplicated root would
            // otherwise alter every later accumulated path digest.
            if (index > 0 and cert.self_issued()) return error.SelfIssuedNotAnchor;
            if (index < trusted_prefix_len) continue;
            // A single-certificate chain (root only) is a CA, not a leaf.
            const is_leaf = index == chain.count - 1 and chain.count > 1;
            try validate_cert_content(cert, is_leaf);
            try check_validity(cert, timestamp_ms);
            const parent = if (index == 0) cert else &chain.certs[index - 1];
            if (index > 0) try check_parent(parent, cert, @intCast(chain.count - 1 - index));
            try verify_signature(parent, cert);
        }
    }

    pub fn leaf_public_key(chain: *const CertChain) []const u8 {
        assert(chain.count >= 1);
        const key = chain.certs[chain.count - 1].public_key;
        assert(key.len < chain.certs[chain.count - 1].der.len);
        return key;
    }
};

fn check_parent(parent: *const ParsedCert, child: *const ParsedCert, remaining: u32) Error!void {
    assert(parent != child);
    if (!std.mem.eql(u8, child.issuer, parent.subject)) return error.IssuerMismatch;
    const constraints = parent.basic_constraints orelse return;
    const path_len_max = constraints.path_len orelse return;
    if (remaining > path_len_max) return error.PathLengthExceeded;
}

/// M-01 content checks: P-384 ECDSA-SHA384 only; CAs need `cA` and keyCertSign; the
/// leaf must not be a CA and, if keyUsage is present, must allow digitalSignature.
fn validate_cert_content(cert: *const ParsedCert, is_leaf: bool) Error!void {
    assert(cert.der.len > 0);
    if (!std.mem.eql(u8, cert.signature_algorithm, &oid_ecdsa_with_sha384)) {
        return error.SignatureAlgorithmUnsupported;
    }
    if (!std.mem.eql(u8, cert.public_key_algorithm, &oid_ec_public_key)) {
        return error.PublicKeyAlgorithmUnsupported;
    }
    if (!std.mem.eql(u8, cert.curve, &oid_secp384r1)) return error.CurveUnsupported;
    if (is_leaf) {
        if (cert.basic_constraints) |constraints| {
            if (constraints.ca) return error.LeafIsCa;
        }
        if (cert.key_usage) |usage| {
            if (usage & key_usage_digital_signature == 0) return error.LeafKeyUsage;
        }
        return;
    }
    const constraints = cert.basic_constraints orelse return error.CaMissingBasicConstraints;
    if (!constraints.ca) return error.CaNotCa;
    const usage = cert.key_usage orelse return error.CaMissingKeyUsage;
    if (usage & key_usage_key_cert_sign == 0) return error.CaKeyUsage;
}

fn check_validity(cert: *const ParsedCert, timestamp_ms: u64) Error!void {
    assert(cert.der.len > 0);
    const timestamp_s = timestamp_ms / std.time.ms_per_s;
    if (timestamp_s < cert.not_before_s) return error.CertificateNotYetValid;
    if (timestamp_s > cert.not_after_s) return error.CertificateExpired;
}

/// `parent` signed `child.tbs` with P-384 ECDSA-SHA384 (DER signature).
fn verify_signature(parent: *const ParsedCert, child: *const ParsedCert) Error!void {
    assert(child.tbs.len > 0);
    const public_key = Ecdsa.PublicKey.fromSec1(parent.public_key) catch
        return error.CertificatePublicKeyInvalid;
    const signature = Ecdsa.Signature.fromDer(child.signature) catch
        return error.CertificateSignatureEncoding;
    signature.verify(child.tbs, public_key) catch return error.CertificateSignatureInvalid;
}

test {
    _ = @import("x509_test.zig");
}

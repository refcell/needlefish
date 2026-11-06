//! CRL (certificate revocation list) checks for AWS Nitro intermediate certificates
//! (base/base `registrar/src/crl.rs`).
//!
//! Enabled checks block registration on fetch or parse failures while retaining
//! confirmed revocations from other certificates in the chain. Fetching sits behind
//! `CrlFetcher`, so this file stays pure: the service supplies an HTTP-backed
//! fetcher, tests and the simulator supply canned responses.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const x509 = @import("../nitro/x509.zig");

const DerReader = x509.DerReader;

pub const crl_response_size_max: u32 = 10 * 1024 * 1024;
pub const serial_size_max: u32 = 32;
pub const url_size_max: u32 = 512;
const host_size_max: u32 = 253;
const allowed_host_suffix = ".amazonaws.com";
const allowed_host_keyword = "nitro-enclave";
/// Bound on distribution points, names, and revoked entries walked per structure.
const der_items_max: u32 = 1 << 20;

comptime {
    assert(serial_size_max >= 21); // RFC 5280 serials are at most 20 octets plus sign.
    assert(crl_response_size_max > 0);
}

pub const CrlError = error{
    CrlCertificateParse,
    CrlCertificateTrailingData,
    CrlSerialTooLong,
    CrlHostNotAllowed,
    CrlFetchFailed,
    CrlResponseTooLarge,
    CrlParse,
    CrlTrailingData,
};

pub const FetchError = error{ CrlFetchFailed, CrlResponseTooLarge };

/// Synchronous CRL fetch: write the response body for `url` into `buffer` (at most
/// `crl_response_size_max` bytes) and return the written prefix.
pub const CrlFetcher = struct {
    context: *anyopaque,
    fetch_fn: *const fn (context: *anyopaque, url: []const u8, buffer: []u8) FetchError![]const u8,

    pub fn fetch(fetcher: CrlFetcher, url: []const u8, buffer: []u8) FetchError![]const u8 {
        assert(url.len > 0);
        const body = try fetcher.fetch_fn(fetcher.context, url, buffer);
        assert(body.len <= buffer.len);
        return body;
    }
};

/// Information extracted from one certificate for CRL checking.
pub const CertCrlInfo = struct {
    /// Position of the certificate in the chain (root is 0).
    index: u32,
    /// Serial number, big endian, unsigned, without leading zeros.
    serial_number: [serial_size_max]u8,
    serial_length: u8,
    /// CRL distribution point URL, borrowed from the certificate DER.
    crl_url: ?[]const u8,
    /// Issuer/serial identity used by the hinted `CertManager`.
    revocation_id: types.Hash,

    pub fn serial(info: *const CertCrlInfo) []const u8 {
        assert(info.serial_length >= 1 and info.serial_length <= serial_size_max);
        return info.serial_number[0..info.serial_length];
    }

    /// Extract CRL information from the non-root CA steps of a registration plan.
    /// Returns the filled prefix of `out`.
    pub fn from_cert_plans(
        certs: []const types.CertPlan,
        out: *[types.cert_plan_count_max]CertCrlInfo,
    ) CrlError![]CertCrlInfo {
        assert(certs.len <= types.cert_plan_count_max);
        var count: u32 = 0;
        for (certs, 0..) |*cert_plan, index| {
            if (cert_plan.kind != .ca) continue;
            const parsed = x509.ParsedCert.parse(cert_plan.cert) catch |err| switch (err) {
                error.CertificateTrailingData => return error.CrlCertificateTrailingData,
                else => return error.CrlCertificateParse,
            };
            var info: CertCrlInfo = .{
                .index = @intCast(index + 1),
                .serial_number = undefined,
                .serial_length = 0,
                .crl_url = null,
                .revocation_id = cert_plan.revocation_id,
            };
            const serial_value = normalize_serial(parsed.serial);
            if (serial_value.len > serial_size_max) return error.CrlSerialTooLong;
            @memcpy(info.serial_number[0..serial_value.len], serial_value);
            info.serial_length = @intCast(serial_value.len);
            if (parsed.crl_distribution_points) |value| {
                info.crl_url = extract_crl_distribution_point(value);
            }
            out[count] = info;
            count += 1;
        }
        assert(count <= certs.len);
        return out[0..count];
    }
};

/// INTEGER content as an unsigned big-endian magnitude without leading zeros (zero
/// stays one byte), as `BigUint::to_bytes_be` normalizes.
pub fn normalize_serial(content: []const u8) []const u8 {
    if (content.len == 0) return content;
    var start: usize = 0;
    while (start + 1 < content.len and content[start] == 0) start += 1;
    assert(start < content.len);
    return content[start..];
}

/// First `http://` or `https://` URI in a `CRLDistributionPoints` extension value.
/// Malformed structures yield null, as base/base skips unparsed extensions.
pub fn extract_crl_distribution_point(value: []const u8) ?[]const u8 {
    var outer = DerReader.init(value);
    const points = outer.expect(0x30) catch return null;
    var reader = DerReader.init(points.content);
    var count: u32 = 0;
    while (!reader.at_end() and count < der_items_max) : (count += 1) {
        const point = reader.expect(0x30) catch return null;
        var fields = DerReader.init(point.content);
        // distributionPoint [0] EXPLICIT DistributionPointName.
        if (fields.peek_tag() != 0xa0) continue;
        const name = fields.next() catch return null;
        var choice = DerReader.init(name.content);
        // fullName [0] IMPLICIT GeneralNames.
        if (choice.peek_tag() != 0xa0) continue;
        const full_name = choice.next() catch return null;
        if (first_http_uri(full_name.content)) |uri| return uri;
    }
    return null;
}

fn first_http_uri(general_names: []const u8) ?[]const u8 {
    var reader = DerReader.init(general_names);
    var count: u32 = 0;
    while (!reader.at_end() and count < der_items_max) : (count += 1) {
        const name = reader.next() catch return null;
        // uniformResourceIdentifier [6] IMPLICIT IA5String.
        if (name.tag != 0x86) continue;
        const uri = name.content;
        if (std.mem.startsWith(u8, uri, "http://") or std.mem.startsWith(u8, uri, "https://")) {
            return uri;
        }
    }
    return null;
}

/// Host must be a domain ending in `.amazonaws.com` that contains `nitro-enclave`,
/// compared case-insensitively (URL hosts are lowercased).
pub fn is_allowed_crl_host(url: []const u8) bool {
    var host_buffer: [host_size_max]u8 = undefined;
    const host = url_host(url, &host_buffer) orelse return false;
    assert(host.len > 0);
    return std.mem.endsWith(u8, host, allowed_host_suffix) and
        std.mem.indexOf(u8, host, allowed_host_keyword) != null;
}

/// Lowercased domain of `scheme://[userinfo@]host[:port][/path]`; null for IP
/// literals, empty or oversized hosts, and inputs without a scheme.
fn url_host(url: []const u8, out: *[host_size_max]u8) ?[]const u8 {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return null;
    if (scheme_end == 0) return null;
    const rest = url[scheme_end + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..authority_end];
    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_port = authority[host_start..];
    if (host_port.len > 0 and host_port[0] == '[') return null; // IPv6 literal.
    const host = host_port[0 .. std.mem.indexOfScalar(u8, host_port, ':') orelse host_port.len];
    if (host.len == 0 or host.len > host_size_max) return null;
    var all_numeric = true;
    for (host, 0..) |char, index| {
        out[index] = std.ascii.toLower(char);
        all_numeric = all_numeric and (std.ascii.isDigit(char) or char == '.');
    }
    if (all_numeric) return null; // IPv4 literal: no domain.
    assert(host.len <= out.len);
    return out[0..host.len];
}

/// CRL evidence from a chain, including failures alongside confirmed revocations.
pub const CrlCheckResult = struct {
    /// Indices into the checked `CertCrlInfo` slice confirmed revoked.
    revoked: [types.cert_plan_count_max]u8 = undefined,
    revoked_count: u8 = 0,
    /// Checks that could not determine revocation status, with their info index.
    errors: [types.cert_plan_count_max]IndexedError = undefined,
    error_count: u8 = 0,

    pub const IndexedError = struct { info_index: u8, err: CrlError };

    /// Whether every applicable check succeeded without detecting revocation.
    pub fn is_clean(result: *const CrlCheckResult) bool {
        assert(result.revoked_count <= types.cert_plan_count_max);
        assert(result.error_count <= types.cert_plan_count_max);
        return result.revoked_count == 0 and result.error_count == 0;
    }
};

/// Check every intermediate CRL distribution point without discarding partial
/// evidence. `body_buffer` receives each response in turn.
pub fn check_chain_against_crls(
    cert_infos: []const CertCrlInfo,
    fetcher: CrlFetcher,
    body_buffer: []u8,
) CrlCheckResult {
    assert(cert_infos.len <= types.cert_plan_count_max);
    var result: CrlCheckResult = .{};
    for (cert_infos, 0..) |*info, index| {
        const url = info.crl_url orelse continue;
        const revoked = fetch_and_check_crl(fetcher, url, info.serial(), body_buffer) catch |err| {
            result.errors[result.error_count] = .{ .info_index = @intCast(index), .err = err };
            result.error_count += 1;
            continue;
        };
        if (revoked) {
            result.revoked[result.revoked_count] = @intCast(index);
            result.revoked_count += 1;
        }
    }
    assert(result.revoked_count + result.error_count <= cert_infos.len);
    return result;
}

fn fetch_and_check_crl(
    fetcher: CrlFetcher,
    url: []const u8,
    serial_number: []const u8,
    body_buffer: []u8,
) CrlError!bool {
    assert(serial_number.len > 0);
    if (!is_allowed_crl_host(url)) return error.CrlHostNotAllowed;
    const limit = @min(body_buffer.len, crl_response_size_max);
    const body = try fetcher.fetch(url, body_buffer[0..limit]);
    if (body.len > crl_response_size_max) return error.CrlResponseTooLarge;
    return crl_contains_serial(body, serial_number);
}

/// Whether a DER `CertificateList` revokes `serial_number` (normalized magnitude).
pub fn crl_contains_serial(crl: []const u8, serial_number: []const u8) CrlError!bool {
    var outer = DerReader.init(crl);
    const list = outer.expect(0x30) catch return error.CrlParse;
    if (!outer.at_end()) return error.CrlTrailingData;
    var list_reader = DerReader.init(list.content);
    const tbs = list_reader.expect(0x30) catch return error.CrlParse;
    _ = list_reader.expect(0x30) catch return error.CrlParse; // signatureAlgorithm
    _ = list_reader.expect(0x03) catch return error.CrlParse; // signatureValue
    if (!list_reader.at_end()) return error.CrlParse;
    const revoked = try revoked_certificates(tbs.content) orelse return false;
    var reader = DerReader.init(revoked);
    var count: u32 = 0;
    var found = false;
    while (!reader.at_end()) : (count += 1) {
        if (count >= der_items_max) return error.CrlParse;
        const entry = reader.expect(0x30) catch return error.CrlParse;
        var fields = DerReader.init(entry.content);
        const user_certificate = fields.expect(0x02) catch return error.CrlParse;
        if (fields.at_end()) return error.CrlParse; // revocationDate is required.
        const serial_value = normalize_serial(user_certificate.content);
        found = found or std.mem.eql(u8, serial_value, serial_number);
    }
    return found;
}

/// The `revokedCertificates` content of a `TBSCertList`, or null when absent.
fn revoked_certificates(tbs: []const u8) CrlError!?[]const u8 {
    var reader = DerReader.init(tbs);
    if (reader.peek_tag() == 0x02) _ = reader.next() catch return error.CrlParse; // version
    _ = reader.expect(0x30) catch return error.CrlParse; // signature
    _ = reader.expect(0x30) catch return error.CrlParse; // issuer
    try expect_time(&reader); // thisUpdate
    const next_tag = reader.peek_tag();
    if (next_tag == 0x17 or next_tag == 0x18) try expect_time(&reader); // nextUpdate
    var revoked: ?[]const u8 = null;
    if (reader.peek_tag() == 0x30) revoked = (reader.next() catch return error.CrlParse).content;
    if (reader.peek_tag() == 0xa0) _ = reader.next() catch return error.CrlParse; // extensions
    if (!reader.at_end()) return error.CrlParse;
    return revoked;
}

fn expect_time(reader: *DerReader) CrlError!void {
    const time = reader.next() catch return error.CrlParse;
    if (time.tag != 0x17 and time.tag != 0x18) return error.CrlParse;
    assert(time.content.len <= reader.bytes.len);
}

test {
    _ = @import("crl_test.zig");
}

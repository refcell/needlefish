//! Tests for CRL checking (base/base `crl.rs` tests). A canned fetcher replaces the
//! local HTTP test server.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const crl = @import("crl.zig");
const types = @import("types.zig");
const fuzz = @import("../../../testing/fuzz.zig");

const CertCrlInfo = crl.CertCrlInfo;

const root_der = @embedFile("../nitro/aws_nitro_root_g1.der");
const inter1_der = @embedFile("../nitro/testdata/inter1.der");
const inter2_der = @embedFile("../nitro/testdata/inter2.der");
const inter3_der = @embedFile("../nitro/testdata/inter3.der");
const leaf_der = @embedFile("../nitro/testdata/leaf.der");

const inter1_crl_url = "http://aws-nitro-enclaves-crl.s3.amazonaws.com/crl/" ++
    "ab4960cc-7d63-42bd-9e9f-59338cb67f84.crl";
const inter2_crl_url = "http://crl-us-east-1-aws-nitro-enclaves.s3.us-east-1.amazonaws.com/" ++
    "crl/06d48f8e-2c08-4781-a645-b1de402aefb8.crl";

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Literal test vectors.
    return out;
}

const empty_crl_der = hex("302f301d300a06082a8648ce3d0403033000170d3234303130313030303030305a" ++
    "300a06082a8648ce3d04030303020000");

/// A CRL revoking `serial` (INTEGER content octets), or none when null.
fn build_crl(serial: ?[]const u8, out: *[128]u8) []const u8 {
    const algorithm = hex("300a06082a8648ce3d040303");
    const date = [_]u8{ 0x17, 0x0d } ++ "240101000000Z".*;
    var tbs: [96]u8 = undefined;
    var tbs_length: usize = 0;
    for ([_][]const u8{ &algorithm, &.{ 0x30, 0x00 }, &date }) |part| {
        @memcpy(tbs[tbs_length..][0..part.len], part);
        tbs_length += part.len;
    }
    if (serial) |value| {
        assert(value.len < 8);
        const entry_length: u8 = @intCast(2 + value.len + date.len);
        for ([_][]const u8{
            &.{ 0x30, entry_length + 2, 0x30, entry_length, 0x02, @intCast(value.len) },
            value,
            &date,
        }) |part| {
            @memcpy(tbs[tbs_length..][0..part.len], part);
            tbs_length += part.len;
        }
    }
    var length: usize = 0;
    const body_length: u8 = @intCast(2 + tbs_length + algorithm.len + 4);
    for ([_][]const u8{
        &.{ 0x30, body_length, 0x30, @intCast(tbs_length) },
        tbs[0..tbs_length],
        &algorithm,
        &.{ 0x03, 0x02, 0x00, 0x00 },
    }) |part| {
        @memcpy(out[length..][0..part.len], part);
        length += part.len;
    }
    return out[0..length];
}

/// Canned responses selected by the URL's final path digit; null fails the fetch.
const CannedFetcher = struct {
    responses: []const ?[]const u8,
    calls: u32 = 0,

    fn fetcher(canned: *CannedFetcher) crl.CrlFetcher {
        return .{ .context = canned, .fetch_fn = fetch };
    }

    fn fetch(context: *anyopaque, url: []const u8, buffer: []u8) crl.FetchError![]const u8 {
        const canned: *CannedFetcher = @ptrCast(@alignCast(context));
        canned.calls += 1;
        const index = url[url.len - 1] - '0';
        const body = canned.responses[index] orelse return error.CrlFetchFailed;
        if (body.len > buffer.len) return error.CrlResponseTooLarge;
        @memcpy(buffer[0..body.len], body);
        return buffer[0..body.len];
    }
};

fn test_infos(urls: []const []const u8, serial: u8) [2]CertCrlInfo {
    var infos: [2]CertCrlInfo = undefined;
    for (&infos, 0..) |*info, index| {
        info.* = .{
            .index = @intCast(index),
            .serial_number = undefined,
            .serial_length = 1,
            .crl_url = urls[index],
            .revocation_id = @splat(@intCast(index)),
        };
        info.serial_number[0] = serial;
    }
    return infos;
}

const test_urls = [_][]const u8{
    "http://nitro-enclave.amazonaws.com:8000/0",
    "http://nitro-enclave.amazonaws.com:8000/1",
};

test "registrar crl: partial failure cannot report a clean chain" {
    var crl_buffer: [128]u8 = undefined;
    var canned: CannedFetcher = .{ .responses = &.{ build_crl(null, &crl_buffer), "invalid DER" } };
    const infos = test_infos(&test_urls, 1);
    var body: [1024]u8 = undefined;
    const result = crl.check_chain_against_crls(&infos, canned.fetcher(), &body);
    try testing.expect(!result.is_clean());
    try testing.expectEqual(@as(u8, 0), result.revoked_count);
    try testing.expectEqual(@as(u8, 1), result.error_count);
    try testing.expectEqual(@as(u32, 2), canned.calls);
}

test "registrar crl: chain check retains revocation evidence in either order" {
    for (0..2) |revoked_index| {
        var crl_buffer: [128]u8 = undefined;
        var responses = [_]?[]const u8{ "invalid DER", "invalid DER" };
        responses[revoked_index] = build_crl(&.{ 0x00, 0x80 }, &crl_buffer);
        var canned: CannedFetcher = .{ .responses = &responses };
        const infos = test_infos(&test_urls, 0x80);
        var body: [1024]u8 = undefined;
        const result = crl.check_chain_against_crls(&infos, canned.fetcher(), &body);
        try testing.expect(!result.is_clean());
        try testing.expectEqual(@as(u8, 1), result.error_count);
        try testing.expectEqual(@as(u8, 1), result.revoked_count);
        const revoked = &infos[result.revoked[0]];
        const want = &infos[revoked_index].revocation_id;
        try testing.expectEqualSlices(u8, want, &revoked.revocation_id);
    }
}

test "registrar crl: fetch failures and disallowed hosts are indeterminate" {
    var canned: CannedFetcher = .{ .responses = &.{ null, null } };
    var infos = test_infos(&test_urls, 1);
    infos[1].crl_url = "http://evil.com/crl/1";
    var body: [1024]u8 = undefined;
    const result = crl.check_chain_against_crls(&infos, canned.fetcher(), &body);
    try testing.expectEqual(@as(u8, 2), result.error_count);
    try testing.expectEqual(error.CrlFetchFailed, result.errors[0].err);
    try testing.expectEqual(error.CrlHostNotAllowed, result.errors[1].err);
    try testing.expectEqual(@as(u32, 1), canned.calls);
}

test "registrar crl: extracts distribution point url" {
    const cases = [_]struct { der: []const u8, want: ?[]const u8 }{
        .{ .der = inter1_der, .want = inter1_crl_url },
        .{ .der = inter2_der, .want = inter2_crl_url },
        .{ .der = inter3_der, .want = null },
        .{ .der = root_der, .want = null },
        .{ .der = leaf_der, .want = null },
    };
    const x509 = @import("../nitro/x509.zig");
    for (cases) |case| {
        const parsed = try x509.ParsedCert.parse(case.der);
        const url = if (parsed.crl_distribution_points) |value|
            crl.extract_crl_distribution_point(value)
        else
            null;
        if (case.want) |want| {
            try testing.expectEqualStrings(want, url.?);
        } else {
            try testing.expect(url == null);
        }
    }
}

test "registrar crl: cert plans collect CA serials and urls" {
    var plans: [3]types.CertPlan = undefined;
    for (&plans, [_][]const u8{ inter1_der, inter2_der, leaf_der }, 0..) |*plan, der, index| {
        plan.* = .{
            .kind = if (index == 2) .leaf else .ca,
            .label = try types.Label.init("test"),
            .cert = der,
            .cert_hash = @splat(0),
            .parent_cert_hash = @splat(0),
            .revocation_id = @splat(@intCast(index)),
        };
    }
    var out: [types.cert_plan_count_max]CertCrlInfo = undefined;
    const infos = try CertCrlInfo.from_cert_plans(&plans, &out);
    try testing.expectEqual(@as(usize, 2), infos.len);
    try testing.expectEqual(@as(u32, 1), infos[0].index);
    try testing.expectEqualSlices(u8, &hex("56bfc987fd05ac99c475061b1a65eedc"), infos[0].serial());
    // DER sign padding is stripped: 0x00cb28... becomes cb28....
    try testing.expectEqualSlices(u8, &hex("cb286a4a4a09207f8b0c14950dcd6861"), infos[1].serial());
    try testing.expectEqualStrings(inter2_crl_url, infos[1].crl_url.?);
}

test "registrar crl: trailing DER certificate returns parse error" {
    var cert: [inter1_der.len + 23]u8 = undefined;
    @memcpy(cert[0..inter1_der.len], inter1_der);
    @memcpy(cert[inter1_der.len..], "chain-4256-trailing-der");
    const plan: types.CertPlan = .{
        .kind = .ca,
        .label = try types.Label.init("regional CA"),
        .cert = &cert,
        .cert_hash = @splat(0),
        .parent_cert_hash = @splat(0),
        .revocation_id = @splat(0),
    };
    var out: [types.cert_plan_count_max]CertCrlInfo = undefined;
    try testing.expectError(
        error.CrlCertificateTrailingData,
        CertCrlInfo.from_cert_plans(&.{plan}, &out),
    );
}

test "registrar crl: parse rejects trailing DER" {
    try testing.expect(!try crl.crl_contains_serial(&empty_crl_der, &.{1}));
    var aliased: [empty_crl_der.len + 23]u8 = undefined;
    @memcpy(aliased[0..empty_crl_der.len], &empty_crl_der);
    @memcpy(aliased[empty_crl_der.len..], "chain-4256-trailing-crl");
    try testing.expectError(error.CrlTrailingData, crl.crl_contains_serial(&aliased, &.{1}));
}

test "registrar crl: serial matching normalizes padding" {
    var buffer: [128]u8 = undefined;
    const revoked = build_crl(&.{ 0x00, 0x80 }, &buffer);
    try testing.expect(try crl.crl_contains_serial(revoked, &.{0x80}));
    try testing.expect(!try crl.crl_contains_serial(revoked, &.{0x81}));
    try testing.expectEqualSlices(u8, &.{0}, crl.normalize_serial(&.{ 0, 0 }));
}

test "registrar crl: host allowlist check" {
    const cases = [_]struct { url: []const u8, want: bool }{
        .{ .url = inter1_crl_url, .want = true },
        .{ .url = inter2_crl_url, .want = true },
        .{ .url = "http://AWS-NITRO-ENCLAVES-CRL.S3.AMAZONAWS.COM/crl/test.crl", .want = true },
        .{ .url = "http://evil.com/crl/something.crl", .want = false },
        .{ .url = "http://s3.amazonaws.com/crl.crl", .want = false },
        .{ .url = "http://nitro-enclaves-crl.example.com/crl.crl", .want = false },
        .{ .url = "http://:@nitro-enclave.amazonaws.com:80/x", .want = true },
        .{ .url = "nitro-enclave.amazonaws.com", .want = false },
    };
    for (cases) |case| try testing.expectEqual(case.want, crl.is_allowed_crl_host(case.url));
}

/// Property: arbitrary bytes never crash the CRL, distribution-point, or URL parsers.
fn fuzz_parsers(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    _ = crl.crl_contains_serial(input, &.{1}) catch {};
    if (crl.extract_crl_distribution_point(input)) |uri| {
        try testing.expect(std.mem.startsWith(u8, uri, "http"));
    }
    _ = crl.is_allowed_crl_host(input);
}

test "registrar crl: fuzz parsers" {
    try fuzz.run({}, fuzz_parsers, .{ .iterations = 1024 });
}

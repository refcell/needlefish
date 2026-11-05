//! Client IP resolution through trusted forwarding proxies (base/base `trusted-proxy`).
//!
//! A forwarding header such as `X-Forwarded-For` is honored only when the direct peer is
//! inside a configured trusted CIDR; otherwise the peer address is the client. With no CIDRs,
//! headers are never honored (directly exposed deployments). All occurrences of the header
//! are joined in order and scanned right to left: trusted hops are peeled off and the first
//! untrusted entry is the client, so a client-supplied left part cannot spoof its address.
//! IPv4-mapped IPv6 addresses are canonicalized to IPv4 before matching.

const std = @import("std");
const assert = std.debug.assert;

const Address = @import("../io/common.zig").Address;
const http_parser = @import("../http/parser.zig");

pub const Cidr = struct {
    address: Address,
    prefix_bits: u8,

    /// Parses `a.b.c.d/n` or `v6/n`; a bare address is a host route.
    pub fn parse(text: []const u8) error{InvalidCidr}!Cidr {
        const trimmed = std.mem.trim(u8, text, " \t");
        const slash = std.mem.findScalar(u8, trimmed, '/');
        const host = parse_ip(trimmed[0 .. slash orelse trimmed.len]) catch
            return error.InvalidCidr;
        const bits_max: u8 = if (host.family == .ip4) 32 else 128;
        const prefix_bits = if (slash) |s|
            std.fmt.parseInt(u8, trimmed[s + 1 ..], 10) catch return error.InvalidCidr
        else
            bits_max;
        if (prefix_bits > bits_max) return error.InvalidCidr;
        return .{ .address = host, .prefix_bits = prefix_bits };
    }

    pub fn contains(cidr: Cidr, ip: Address) bool {
        const candidate = canonical(ip);
        if (candidate.family != cidr.address.family) return false;
        const full_bytes = cidr.prefix_bits / 8;
        const rest_bits: u3 = @intCast(cidr.prefix_bits % 8);
        const a = candidate.host_bytes();
        const b = cidr.address.host_bytes();
        if (!std.mem.eql(u8, a[0..full_bytes], b[0..full_bytes])) return false;
        if (rest_bits == 0) return true;
        const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rest_bits));
        return (a[full_bytes] & mask) == (b[full_bytes] & mask);
    }
};

/// Parses a bare IPv4 or IPv6 address (no port), canonicalized.
pub fn parse_ip(text: []const u8) error{InvalidIp}!Address {
    const parsed = std.Io.net.IpAddress.parse(text, 0) catch return error.InvalidIp;
    const address: Address = switch (parsed) {
        .ip4 => |v4| Address.ip4(v4.bytes, 0),
        .ip6 => |v6| Address.ip6(v6.bytes, 0),
    };
    return canonical(address);
}

/// Maps `::ffff:a.b.c.d` to `a.b.c.d` and drops the port.
pub fn canonical(address: Address) Address {
    if (address.family == .ip6) {
        const prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (std.mem.eql(u8, address.bytes[0..12], &prefix)) {
            return Address.ip4(address.bytes[12..16].*, 0);
        }
    }
    return address.with_port(0);
}

pub const Error = error{ MissingHeader, InvalidIp };

pub const Config = struct {
    /// Header name, matched case-insensitively.
    header: []const u8 = "x-forwarded-for",
    cidrs: []const Cidr = &.{},

    pub fn is_trusted_proxy(config: *const Config, ip: Address) bool {
        for (config.cidrs) |cidr| if (cidr.contains(ip)) return true;
        return false;
    }

    /// The rightmost untrusted entry across all header occurrences; when every entry is a
    /// trusted proxy, the outermost (leftmost) one.
    pub fn forwarded_client_ip(
        config: *const Config,
        headers: []const http_parser.Header,
    ) Error!Address {
        var outermost_trusted: ?Address = null;
        var index = headers.len;
        while (index > 0) {
            index -= 1;
            const header = headers[index];
            if (!std.ascii.eqlIgnoreCase(header.name, config.header)) continue;
            var entries = std.mem.splitBackwardsScalar(u8, header.value, ',');
            while (entries.next()) |raw| {
                const entry = std.mem.trim(u8, raw, " \t");
                if (entry.len == 0) continue;
                const ip = parse_ip(entry) catch return error.InvalidIp;
                if (config.is_trusted_proxy(ip)) {
                    outermost_trusted = ip;
                    continue;
                }
                return ip;
            }
        }
        return outermost_trusted orelse error.MissingHeader;
    }

    pub fn try_client_ip(
        config: *const Config,
        peer: Address,
        headers: []const http_parser.Header,
    ) Error!Address {
        const direct = canonical(peer);
        if (!config.is_trusted_proxy(direct)) return direct;
        const forwarded = try config.forwarded_client_ip(headers);
        // A chain made only of trusted hops names no client: use the peer.
        return if (config.is_trusted_proxy(forwarded)) direct else forwarded;
    }

    /// Like `try_client_ip`, falling back to the peer on a missing or malformed header.
    pub fn client_ip(
        config: *const Config,
        peer: Address,
        headers: []const http_parser.Header,
    ) Address {
        return config.try_client_ip(peer, headers) catch canonical(peer);
    }
};

const test_cidrs = [_][]const u8{ "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12" };

fn test_config(cidrs: []Cidr) Config {
    for (cidrs, test_cidrs) |*cidr, text| cidr.* = Cidr.parse(text) catch unreachable;
    return .{ .cidrs = cidrs };
}

fn test_ip(text: []const u8) Address {
    return parse_ip(text) catch unreachable;
}

fn expect_ip(expected: []const u8, actual: Address) !void {
    try std.testing.expect(test_ip(expected).eql(actual));
}

test "trusted_proxy: cidr parse and contains" {
    const cidr = try Cidr.parse(" 172.16.0.0/12 ");
    try std.testing.expect(cidr.contains(test_ip("172.31.255.255")));
    try std.testing.expect(!cidr.contains(test_ip("172.32.0.0")));
    try std.testing.expect(cidr.contains(test_ip("::ffff:172.16.1.1"))); // Mapped IPv4.
    const v6 = try Cidr.parse("2001:db8::/32");
    try std.testing.expect(v6.contains(test_ip("2001:db8:1::5")));
    try std.testing.expect(!v6.contains(test_ip("2001:db9::")));
    try std.testing.expect(!v6.contains(test_ip("10.0.0.1")));
    const all = try Cidr.parse("0.0.0.0/0");
    try std.testing.expect(all.contains(test_ip("8.8.8.8")));
    try std.testing.expect((try Cidr.parse("10.1.2.3")).contains(test_ip("10.1.2.3")));
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("nope/8"));
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("10.0.0.0/x"));
}

test "trusted_proxy: resolves client ip behind trusted proxies" {
    var cidrs: [test_cidrs.len]Cidr = undefined;
    const config = test_config(&cidrs);
    const proxy = test_ip("127.0.0.1");
    const stranger = test_ip("192.0.2.1");
    var headers = [_]http_parser.Header{
        .{ .name = "X-Forwarded-For", .value = "130.1.1.1, 10.0.0.2" },
    };
    try expect_ip("130.1.1.1", config.client_ip(proxy, &headers));
    try expect_ip("192.0.2.1", config.client_ip(stranger, &headers)); // Untrusted peer.
    headers[0].value = "nonsense";
    try expect_ip("127.0.0.1", config.client_ip(proxy, &headers));
    try std.testing.expectError(error.InvalidIp, config.try_client_ip(proxy, &headers));
    try expect_ip("127.0.0.1", config.client_ip(proxy, &.{}));
    try std.testing.expectError(error.MissingHeader, config.try_client_ip(proxy, &.{}));
    headers[0].value = "10.0.0.9, 10.0.0.2"; // Only trusted hops: the peer.
    try expect_ip("127.0.0.1", config.client_ip(proxy, &headers));
    const no_trust: Config = .{};
    headers[0].value = "130.1.1.1";
    try expect_ip("127.0.0.1", no_trust.client_ip(proxy, &headers));
}

test "trusted_proxy: header occurrences join in order, scanned right to left" {
    var cidrs: [test_cidrs.len]Cidr = undefined;
    const config = test_config(&cidrs);
    const proxy = test_ip("10.0.0.1");
    // A spoofed first line loses to the entry our proxy appended last.
    const spoofed = [_]http_parser.Header{
        .{ .name = "x-forwarded-for", .value = "203.0.113.99" },
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-forwarded-for", .value = "198.51.100.7" },
    };
    try expect_ip("198.51.100.7", config.client_ip(proxy, &spoofed));
    // Trusted hops are peeled across lines; garbage left of the client is never parsed.
    const hops = [_]http_parser.Header{
        .{ .name = "x-forwarded-for", .value = "invalid" },
        .{ .name = "x-forwarded-for", .value = "203.0.113.10" },
        .{ .name = "x-forwarded-for", .value = "10.1.1.1, , 172.16.0.5" },
    };
    try expect_ip("203.0.113.10", config.client_ip(proxy, &hops));
    // Custom header name and an IPv4-mapped peer.
    const custom: Config = .{ .header = "x-real-ip", .cidrs = config.cidrs };
    const real = [_]http_parser.Header{.{ .name = "X-Real-IP", .value = "2001:db8::1" }};
    try expect_ip("2001:db8::1", custom.client_ip(test_ip("::ffff:10.0.0.1"), &real));
}

fn resolve_arbitrary(config: *const Config, value: []const u8) !void {
    const peer = test_ip("10.0.0.1");
    const headers = [_]http_parser.Header{.{ .name = "x-forwarded-for", .value = value }};
    const resolved = config.client_ip(peer, &headers);
    // The answer is the peer or an untrusted address that appears in the header.
    if (resolved.eql(peer)) return;
    try std.testing.expect(!config.is_trusted_proxy(resolved));
}

test "trusted_proxy: seeded fuzz" {
    var cidrs: [test_cidrs.len]Cidr = undefined;
    const config = test_config(&cidrs);
    var prng = @import("../../testing/prng.zig").Prng.init(0x7a1);
    const pieces = [_][]const u8{
        "10.0.0.1", "203.0.113.5", ",", " ", "::1", "::ffff:10.2.3.4", "x", "1.2.3",
    };
    var value: [128]u8 = undefined;
    for (0..5000) |_| {
        var size: usize = 0;
        for (0..prng.below(8)) |_| {
            const piece = pieces[prng.below(pieces.len)];
            if (size + piece.len > value.len) break;
            @memcpy(value[size..][0..piece.len], piece);
            size += piece.len;
        }
        try resolve_arbitrary(&config, value[0..size]);
    }
}

fn fuzz_resolve(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var cidrs: [test_cidrs.len]Cidr = undefined;
    const config = test_config(&cidrs);
    var value: [256]u8 = undefined;
    const size = smith.slice(&value);
    try resolve_arbitrary(&config, value[0..size]);
}

test "trusted_proxy: fuzz" {
    try std.testing.fuzz({}, fuzz_resolve, .{});
}

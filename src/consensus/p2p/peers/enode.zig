//! `enode://<pubkey-hex>@<ip>:<tcp>[?discport=<udp>]` node URLs (devp2p) and their
//! conversion to multiaddrs (base/base `BootNode::from_unsigned`).

const std = @import("std");
const assert = std.debug.assert;
const ip = @import("ip.zig");
const multiaddr = @import("multiaddr.zig");
const peer_id = @import("peer_id.zig");
const secp256k1 = @import("secp256k1.zig");
const hex = @import("../../../common/primitives/hex.zig");

pub const scheme = "enode://";
pub const text_length_max = 256;

pub const Error = error{ InvalidText, InvalidPublicKey };

pub const NodeRecord = struct {
    public_key: secp256k1.PublicKey,
    address: ip.Address,
    tcp_port: u16,
    udp_port: u16,

    /// `/ip{4,6}/<ip>/udp/<udp>/tcp/<tcp>/p2p/<id>`, the shape base/base dials.
    pub fn to_multiaddr(record: *const NodeRecord) multiaddr.Multiaddr {
        var address: multiaddr.Multiaddr = .{};
        const peer = peer_id.from_public_key(record.public_key);
        // Four fixed-size components always fit an empty multiaddr.
        switch (record.address) {
            .ip4 => |value| address.push(.{ .ip4 = value }) catch unreachable,
            .ip6 => |value| address.push(.{ .ip6 = value }) catch unreachable,
        }
        address.push(.{ .udp = record.udp_port }) catch unreachable;
        address.push(.{ .tcp = record.tcp_port }) catch unreachable;
        address.push(.{ .p2p = peer.slice() }) catch unreachable;
        assert(address.components == 4);
        return address;
    }
};

pub fn parse(text: []const u8) Error!NodeRecord {
    if (text.len > text_length_max) return error.InvalidText;
    if (!std.mem.startsWith(u8, text, scheme)) return error.InvalidText;
    const body = text[scheme.len..];
    const at = std.mem.indexOfScalar(u8, body, '@') orelse return error.InvalidText;
    var uncompressed: [secp256k1.uncompressed_length]u8 = undefined;
    uncompressed[0] = 0x04;
    hex.decode(uncompressed[1..], body[0..at]) catch return error.InvalidText;
    const public_key = secp256k1.compress(&uncompressed) catch return error.InvalidPublicKey;
    assert(public_key[0] == 0x02 or public_key[0] == 0x03);

    var location = body[at + 1 ..];
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, location, '?')) |mark| {
        query = location[mark + 1 ..];
        location = location[0..mark];
    }
    const colon = std.mem.lastIndexOfScalar(u8, location, ':') orelse return error.InvalidText;
    const host = location[0..colon];
    const tcp_port = parse_port(location[colon + 1 ..]) catch return error.InvalidText;
    const address: ip.Address = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
        .{ .ip6 = ip.parse6(host[1 .. host.len - 1]) catch return error.InvalidText }
    else
        .{ .ip4 = ip.parse4(host) catch return error.InvalidText };
    var udp_port = tcp_port;
    if (query.len > 0) {
        const key = "discport=";
        if (!std.mem.startsWith(u8, query, key)) return error.InvalidText;
        udp_port = parse_port(query[key.len..]) catch return error.InvalidText;
    }
    return .{
        .public_key = public_key,
        .address = address,
        .tcp_port = tcp_port,
        .udp_port = udp_port,
    };
}

fn parse_port(text: []const u8) !u16 {
    if (text.len == 0 or text.len > 5) return error.InvalidText;
    assert(text.len <= 5);
    return std.fmt.parseUnsigned(u16, text, 10);
}

const fuzz = @import("../../../testing/fuzz.zig");

/// From base/base `boot.rs` tests (a public OP Stack boot node).
const example = "enode://2bd2e657bb3c8efffb8ff6db9071d9eb7be70d7c6d7d980ff80fc93b2629675c5f75" ++
    "0bc0a5ef27cd788c2e491b8795a7e9a4a6e72178c14acc6753c0e5d77ae4@34.65.205.244:30305";

test "enode: parse and convert to multiaddr" {
    const record = try parse(example);
    try std.testing.expectEqual(ip.Address{ .ip4 = .{ 34, 65, 205, 244 } }, record.address);
    try std.testing.expectEqual(@as(u16, 30305), record.tcp_port);
    try std.testing.expectEqual(@as(u16, 30305), record.udp_port);
    const address = record.to_multiaddr();
    var text: [multiaddr.text_length_max]u8 = undefined;
    const formatted = address.format(&text);
    const expected_prefix = "/ip4/34.65.205.244/udp/30305/tcp/30305/p2p/16Uiu2HA";
    try std.testing.expect(std.mem.startsWith(u8, formatted, expected_prefix));
    try std.testing.expectEqual(record.public_key, address.peer().?.secp256k1_public_key().?);
}

test "enode: discport and ipv6" {
    const key = example[scheme.len..std.mem.indexOfScalar(u8, example, '@').?];
    var buffer: [text_length_max]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "enode://{s}@[::1]:30303?discport=30301", .{key});
    const record = try parse(text);
    try std.testing.expectEqual(@as(u16, 30303), record.tcp_port);
    try std.testing.expectEqual(@as(u16, 30301), record.udp_port);
    try std.testing.expect(record.address == .ip6);
}

test "enode: rejects malformed" {
    try std.testing.expectError(error.InvalidText, parse("enode://invalid@127.0.0.1:30303"));
    const zeros: [128]u8 = @splat('0');
    var buffer: [text_length_max]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "enode://{s}@127.0.0.1:30303", .{&zeros});
    try std.testing.expectError(error.InvalidPublicKey, parse(text));
    try std.testing.expectError(error.InvalidText, parse(example ++ "?x=1"));
    try std.testing.expectError(error.InvalidText, parse("enr:abc"));
}

fn fuzz_parse(_: void, input: []const u8) anyerror!void {
    const record = parse(input) catch return;
    const address = record.to_multiaddr();
    try std.testing.expect(address.peer() != null);
}

test "enode: fuzz parse" {
    try fuzz.run_bytes({}, fuzz_parse, .{ .input_size_max = 200, .corpus = &.{example} });
}

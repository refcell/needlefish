//! Multiaddrs (multiformats `multiaddr`): binary `(varint code, value)*` and text
//! `/proto/value/...` forms for the protocols an OP Stack node uses: ip4, ip6, tcp, udp,
//! dns, dns4, dns6, p2p, and quic-v1. Stored inline with a fixed capacity.

const std = @import("std");
const assert = std.debug.assert;
const ip = @import("ip.zig");
const peer_id = @import("peer_id.zig");
const varint = @import("varint.zig");
const enr = @import("enr.zig");

pub const size_max = 128;
pub const components_max = 8;
/// Worst case per component is `/p2p/` plus a 61-character base58 id; 72 covers every
/// protocol here, so any valid binary address formats into this bound.
pub const text_length_max = components_max * 72;
/// DNS names are capped well below 255 so a full address fits `size_max`.
pub const dns_length_max = 64;

pub const Code = enum(u16) {
    ip4 = 4,
    tcp = 6,
    udp = 273,
    dns = 53,
    dns4 = 54,
    dns6 = 55,
    ip6 = 41,
    p2p = 421,
    quic_v1 = 460,
};

pub const Component = union(Code) {
    ip4: [4]u8,
    tcp: u16,
    udp: u16,
    dns: []const u8,
    dns4: []const u8,
    dns6: []const u8,
    ip6: [16]u8,
    /// Multihash bytes of the peer id.
    p2p: []const u8,
    quic_v1: void,
};

pub const Error = error{ Malformed, UnsupportedProtocol, TooLong, InvalidText };

pub const Multiaddr = struct {
    bytes: [size_max]u8 = undefined,
    length: u8 = 0,
    components: u8 = 0,

    pub fn slice(address: *const Multiaddr) []const u8 {
        assert(address.length <= size_max);
        return address.bytes[0..address.length];
    }

    pub fn eql(a: *const Multiaddr, b: *const Multiaddr) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }

    pub fn iterator(address: *const Multiaddr) Iterator {
        return .{ .bytes = address.slice() };
    }

    pub fn push(address: *Multiaddr, component: Component) Error!void {
        if (address.components == components_max) return error.TooLong;
        var buffer: [varint.length_max * 2 + dns_length_max]u8 = undefined;
        const encoded = try encode_component(&buffer, component);
        if (address.length + encoded.len > size_max) return error.TooLong;
        @memcpy(address.bytes[address.length..][0..encoded.len], encoded);
        address.length += @intCast(encoded.len);
        address.components += 1;
        assert(address.components <= components_max);
    }

    /// The peer id in a trailing `/p2p/` component, if any.
    pub fn peer(address: *const Multiaddr) ?peer_id.PeerId {
        var components = address.iterator();
        var result: ?peer_id.PeerId = null;
        while (components.next() catch return null) |component| {
            if (component == .p2p) result = peer_id.from_bytes(component.p2p) catch return null;
        }
        return result;
    }

    pub fn format(address: *const Multiaddr, output: []u8) []const u8 {
        assert(output.len >= text_length_max);
        var writer = std.Io.Writer.fixed(output);
        var components = address.iterator();
        // A constructed Multiaddr only holds validated components; text fits by bound.
        while (components.next() catch unreachable) |component| {
            format_component(&writer, component) catch unreachable;
        }
        return writer.buffered();
    }
};

pub const Iterator = struct {
    bytes: []const u8,
    position: usize = 0,

    pub fn next(it: *Iterator) Error!?Component {
        if (it.position == it.bytes.len) return null;
        assert(it.position < it.bytes.len);
        const rest = it.bytes[it.position..];
        const code = varint.decode(rest) catch return error.Malformed;
        const body = rest[code.length..];
        const tag = std.enums.fromInt(Code, code.value) orelse return error.UnsupportedProtocol;
        var consumed: usize = code.length;
        const component: Component = switch (tag) {
            .ip4 => .{ .ip4 = (try take(body, 4, &consumed))[0..4].* },
            .ip6 => .{ .ip6 = (try take(body, 16, &consumed))[0..16].* },
            .tcp => .{ .tcp = std.mem.readInt(u16, (try take(body, 2, &consumed))[0..2], .big) },
            .udp => .{ .udp = std.mem.readInt(u16, (try take(body, 2, &consumed))[0..2], .big) },
            .dns => .{ .dns = try take_dns(body, &consumed) },
            .dns4 => .{ .dns4 = try take_dns(body, &consumed) },
            .dns6 => .{ .dns6 = try take_dns(body, &consumed) },
            .p2p => .{ .p2p = try take_p2p(body, &consumed) },
            .quic_v1 => .quic_v1,
        };
        it.position += consumed;
        assert(it.position <= it.bytes.len);
        return component;
    }
};

fn take(body: []const u8, size: usize, consumed: *usize) Error![]const u8 {
    if (body.len < size) return error.Malformed;
    consumed.* += size;
    return body[0..size];
}

fn take_prefixed(body: []const u8, consumed: *usize) Error![]const u8 {
    const size = varint.decode(body) catch return error.Malformed;
    if (body.len - size.length < size.value) return error.Malformed;
    consumed.* += size.length + size.value;
    return body[size.length..][0..@intCast(size.value)];
}

fn take_dns(body: []const u8, consumed: *usize) Error![]const u8 {
    const name = try take_prefixed(body, consumed);
    try validate_dns(name);
    return name;
}

fn take_p2p(body: []const u8, consumed: *usize) Error![]const u8 {
    const value = try take_prefixed(body, consumed);
    _ = peer_id.from_bytes(value) catch return error.Malformed;
    return value;
}

fn validate_dns(name: []const u8) Error!void {
    if (name.len == 0 or name.len > dns_length_max) return error.Malformed;
    for (name) |character| {
        const ok = std.ascii.isAlphanumeric(character) or character == '-' or character == '.';
        if (!ok) return error.Malformed;
    }
}

fn encode_component(output: []u8, component: Component) Error![]const u8 {
    var length = varint.encode(output, @backingInt(component)).len;
    switch (component) {
        .ip4 => |value| length += copy(output[length..], &value),
        .ip6 => |value| length += copy(output[length..], &value),
        .tcp, .udp => |port| {
            std.mem.writeInt(u16, output[length..][0..2], port, .big);
            length += 2;
        },
        .dns, .dns4, .dns6 => |name| {
            try validate_dns(name);
            length += varint.encode(output[length..], name.len).len;
            length += copy(output[length..], name);
        },
        .p2p => |value| {
            if (value.len > peer_id.length_max) return error.Malformed;
            _ = peer_id.from_bytes(value) catch return error.Malformed;
            length += varint.encode(output[length..], value.len).len;
            length += copy(output[length..], value);
        },
        .quic_v1 => {},
    }
    return output[0..length];
}

fn copy(output: []u8, input: []const u8) usize {
    @memcpy(output[0..input.len], input);
    return input.len;
}

fn format_component(writer: *std.Io.Writer, component: Component) std.Io.Writer.Error!void {
    var buffer: [peer_id.text_length_max]u8 = undefined;
    switch (component) {
        .ip4 => |value| try writer.print("/ip4/{s}", .{ip.format4(&buffer, value)}),
        .ip6 => |value| try writer.print("/ip6/{s}", .{ip.format6(&buffer, value)}),
        .tcp => |port| try writer.print("/tcp/{d}", .{port}),
        .udp => |port| try writer.print("/udp/{d}", .{port}),
        .dns => |name| try writer.print("/dns/{s}", .{name}),
        .dns4 => |name| try writer.print("/dns4/{s}", .{name}),
        .dns6 => |name| try writer.print("/dns6/{s}", .{name}),
        .p2p => |value| {
            const peer = peer_id.from_bytes(value) catch unreachable; // Validated on push.
            try writer.print("/p2p/{s}", .{peer.format(&buffer)});
        },
        .quic_v1 => try writer.writeAll("/quic-v1"),
    }
}

/// Decodes and validates a binary multiaddr. Empty addresses are rejected.
pub fn from_bytes(bytes: []const u8) Error!Multiaddr {
    if (bytes.len == 0) return error.Malformed;
    if (bytes.len > size_max) return error.TooLong;
    var address: Multiaddr = .{};
    var components: Iterator = .{ .bytes = bytes };
    while (try components.next()) |_| {
        if (address.components == components_max) return error.TooLong;
        address.components += 1;
    }
    @memcpy(address.bytes[0..bytes.len], bytes);
    address.length = @intCast(bytes.len);
    return address;
}

/// Parses `/proto/value/...` text.
pub fn parse(text: []const u8) Error!Multiaddr {
    if (text.len == 0 or text.len > text_length_max or text[0] != '/') return error.InvalidText;
    var address: Multiaddr = .{};
    var parts = std.mem.splitScalar(u8, text[1..], '/');
    var peer_storage: peer_id.PeerId = undefined;
    while (parts.next()) |name| {
        const tag = try parse_code(name);
        if (tag == .quic_v1) {
            try address.push(.quic_v1);
            continue;
        }
        const value = parts.next() orelse return error.InvalidText;
        try address.push(try parse_component(tag, value, &peer_storage));
    }
    return address;
}

fn parse_code(name: []const u8) Error!Code {
    if (std.mem.eql(u8, name, "quic-v1")) return .quic_v1;
    if (std.mem.eql(u8, name, "quic_v1")) return error.UnsupportedProtocol;
    return std.meta.stringToEnum(Code, name) orelse error.UnsupportedProtocol;
}

fn parse_component(tag: Code, value: []const u8, peer_storage: *peer_id.PeerId) Error!Component {
    return switch (tag) {
        .ip4 => .{ .ip4 = ip.parse4(value) catch return error.InvalidText },
        .ip6 => .{ .ip6 = ip.parse6(value) catch return error.InvalidText },
        .tcp => .{ .tcp = std.fmt.parseUnsigned(u16, value, 10) catch return error.InvalidText },
        .udp => .{ .udp = std.fmt.parseUnsigned(u16, value, 10) catch return error.InvalidText },
        .dns => .{ .dns = value },
        .dns4 => .{ .dns4 = value },
        .dns6 => .{ .dns6 = value },
        .p2p => blk: {
            peer_storage.* = peer_id.parse(value) catch return error.InvalidText;
            break :blk .{ .p2p = peer_storage.slice() };
        },
        .quic_v1 => unreachable, // Handled by the caller: quic-v1 carries no value.
    };
}

/// `/ip{4,6}/<ip>/tcp/<port>/p2p/<id>` for a record's TCP endpoint (base/base
/// `PeerUtils::enr_to_multiaddr`). Prefers IPv4. Null when the record has no TCP socket.
pub fn from_enr(record: *const enr.Record) ?Multiaddr {
    var address: Multiaddr = .{};
    if (record.ip4()) |value| {
        const port = record.tcp() orelse return null;
        address.push(.{ .ip4 = value }) catch unreachable; // Empty address has room.
        address.push(.{ .tcp = port }) catch unreachable;
    } else if (record.ip6()) |value| {
        const port = record.tcp6() orelse record.tcp() orelse return null;
        address.push(.{ .ip6 = value }) catch unreachable;
        address.push(.{ .tcp = port }) catch unreachable;
    } else return null;
    const peer = peer_id.from_public_key(record.public_key);
    address.push(.{ .p2p = peer.slice() }) catch unreachable; // 3 components, < 70 bytes.
    assert(address.components == 3);
    return address;
}

/// A dialable TCP endpoint extracted from a multiaddr.
pub const TcpEndpoint = struct { address: ip.Address, port: u16 };

pub fn tcp_endpoint(address: *const Multiaddr) ?TcpEndpoint {
    var host: ?ip.Address = null;
    var components = address.iterator();
    while (components.next() catch return null) |component| switch (component) {
        .ip4 => |value| host = .{ .ip4 = value },
        .ip6 => |value| host = .{ .ip6 = value },
        .tcp => |port| return .{ .address = host orelse return null, .port = port },
        else => {},
    };
    return null;
}

const fuzz = @import("../../../testing/fuzz.zig");
const secp256k1 = @import("secp256k1.zig");

test "multiaddr: text round trip" {
    var secret: secp256k1.SecretKey = @splat(0x33);
    secret[0] = 1;
    const peer = peer_id.from_public_key(try secp256k1.public_key(secret));
    var peer_text: [peer_id.text_length_max]u8 = undefined;
    var text_buffer: [text_length_max]u8 = undefined;
    const template = "/ip4/34.65.205.244/udp/30305/tcp/30305/p2p/{s}";
    const text = try std.fmt.bufPrint(&text_buffer, template, .{
        peer.format(&peer_text),
    });
    const address = try parse(text);
    try std.testing.expectEqual(@as(u8, 4), address.components);
    var output: [text_length_max]u8 = undefined;
    try std.testing.expectEqualStrings(text, address.format(&output));
    try std.testing.expect(address.peer().?.eql(&peer));
    const endpoint = tcp_endpoint(&address).?;
    try std.testing.expectEqual(@as(u16, 30305), endpoint.port);
    const decoded = try from_bytes(address.slice());
    try std.testing.expect(decoded.eql(&address));
}

test "multiaddr: binary vectors" {
    // From the multiaddr spec: /ip4/127.0.0.1/udp/1234 and /ip6/::1/tcp/80.
    const a = try parse("/ip4/127.0.0.1/udp/1234");
    const expected_a = [_]u8{ 0x04, 127, 0, 0, 1, 0x91, 0x02, 0x04, 0xd2 };
    try std.testing.expectEqualSlices(u8, &expected_a, a.slice());
    const b = try parse("/ip6/::1/tcp/80/quic-v1");
    var expected: [1 + 16 + 3 + 2]u8 = @splat(0);
    expected[0] = 41;
    expected[16] = 1;
    expected[17] = 6;
    expected[19] = 80;
    expected[20] = 0xcc;
    expected[21] = 0x03;
    try std.testing.expectEqualSlices(u8, &expected, b.slice());
    const c = try parse("/dns4/example.org/tcp/9222");
    var output: [text_length_max]u8 = undefined;
    try std.testing.expectEqualStrings("/dns4/example.org/tcp/9222", c.format(&output));
}

test "multiaddr: rejects malformed" {
    try std.testing.expectError(error.InvalidText, parse(""));
    try std.testing.expectError(error.InvalidText, parse("ip4/1.2.3.4"));
    try std.testing.expectError(error.InvalidText, parse("/ip4/1.2.3"));
    try std.testing.expectError(error.InvalidText, parse("/tcp"));
    try std.testing.expectError(error.UnsupportedProtocol, parse("/onion3/x"));
    try std.testing.expectError(error.Malformed, parse("/dns/bad_name"));
    try std.testing.expectError(error.Malformed, from_bytes(&.{ 0x04, 1, 2 }));
    try std.testing.expectError(error.UnsupportedProtocol, from_bytes(&.{0x7f}));
    try std.testing.expectError(error.Malformed, from_bytes(&.{}));
}

fn fuzz_bytes(_: void, input: []const u8) anyerror!void {
    const address = from_bytes(input) catch return;
    var text: [text_length_max]u8 = undefined;
    const round = try parse(address.format(&text));
    try std.testing.expectEqualSlices(u8, input, round.slice());
}

fn fuzz_text(_: void, input: []const u8) anyerror!void {
    const address = parse(input) catch return;
    var text: [text_length_max]u8 = undefined;
    const round = try parse(address.format(&text));
    try std.testing.expect(round.eql(&address));
}

test "multiaddr: fuzz binary" {
    try fuzz.run_bytes({}, fuzz_bytes, .{ .input_size_max = 140 });
}

test "multiaddr: fuzz text" {
    const corpus: []const []const u8 = &.{ "/ip4/1.2.3.4/tcp/1", "/ip6/::/udp/9/quic-v1" };
    try fuzz.run_bytes({}, fuzz_text, .{ .input_size_max = 96, .corpus = corpus });
}

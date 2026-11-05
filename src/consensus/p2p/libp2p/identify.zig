//! libp2p identify (`/ipfs/id/1.0.0`): after a connection opens, each side sends one
//! length-prefixed protobuf describing itself, then closes the stream.
//!
//!   Identify { optional bytes publicKey = 1; repeated bytes listenAddrs = 2;
//!              repeated string protocols = 3; optional bytes observedAddr = 4;
//!              optional string protocolVersion = 5; optional string agentVersion = 6;
//!              optional bytes signedPeerRecord = 8; }
//!
//! base/base sends protocol version "" (`identify::Config::new(String::new(), key)`).
//! Decoding is zero-copy into bounded arrays; unsupported multiaddrs are skipped, so a
//! peer advertising e.g. websocket addresses still identifies. The public key must match
//! the peer id authenticated by noise (`check_peer`).

const std = @import("std");
const assert = std.debug.assert;
const protobuf = @import("protobuf.zig");
const identity = @import("identity.zig");
const varint = @import("../peers/varint.zig");
const multiaddr = @import("../peers/multiaddr.zig");
const peer_id = @import("../peers/peer_id.zig");

pub const protocol_id = "/ipfs/id/1.0.0";
pub const listen_addresses_max = 16;
pub const protocols_max = 32;
/// libp2p caps identify messages at 4 KiB.
pub const message_size_max = 4096;

pub const Error = error{ InvalidIdentify, TooLarge, PeerMismatch };

pub const Identify = struct {
    public_key: ?[]const u8 = null,
    listen_addresses: [listen_addresses_max]multiaddr.Multiaddr = undefined,
    listen_addresses_count: u32 = 0,
    protocols: [protocols_max][]const u8 = undefined,
    protocols_count: u32 = 0,
    observed_address: ?multiaddr.Multiaddr = null,
    protocol_version: []const u8 = "",
    agent_version: []const u8 = "",

    pub fn listen_slice(message: *const Identify) []const multiaddr.Multiaddr {
        return message.listen_addresses[0..message.listen_addresses_count];
    }

    pub fn protocol_slice(message: *const Identify) []const []const u8 {
        return message.protocols[0..message.protocols_count];
    }

    pub fn supports(message: *const Identify, protocol: []const u8) bool {
        for (message.protocol_slice()) |candidate| {
            if (std.mem.eql(u8, candidate, protocol)) return true;
        }
        return false;
    }

    /// Verifies the advertised key belongs to `peer` (the noise-authenticated id).
    pub fn check_peer(message: *const Identify, peer: *const peer_id.PeerId) Error!void {
        const encoded = message.public_key orelse return error.PeerMismatch;
        const key = identity.decode_public_key(encoded) catch return error.PeerMismatch;
        const derived = peer_id.from_public_key(key);
        if (!derived.eql(peer)) return error.PeerMismatch;
    }
};

/// Decodes one identify message body (without its length prefix).
pub fn decode(input: []const u8) Error!Identify {
    if (input.len > message_size_max) return error.TooLarge;
    var message: Identify = .{};
    var reader = protobuf.Reader.init(input);
    var fields: u32 = 0;
    while (reader.next() catch return error.InvalidIdentify) |field| : (fields += 1) {
        assert(fields < message_size_max);
        if (field.number <= 6 and field.wire_type != .bytes) return error.InvalidIdentify;
        switch (field.number) {
            1 => message.public_key = field.bytes,
            2 => if (message.listen_addresses_count < listen_addresses_max) {
                if (multiaddr.from_bytes(field.bytes)) |address| {
                    message.listen_addresses[message.listen_addresses_count] = address;
                    message.listen_addresses_count += 1;
                } else |_| {}
            },
            3 => if (message.protocols_count < protocols_max) {
                message.protocols[message.protocols_count] = field.bytes;
                message.protocols_count += 1;
            },
            4 => message.observed_address = multiaddr.from_bytes(field.bytes) catch null,
            5 => message.protocol_version = field.bytes,
            6 => message.agent_version = field.bytes,
            else => {},
        }
    }
    assert(message.listen_addresses_count <= listen_addresses_max);
    return message;
}

/// Encodes `message` with its uvarint length prefix. Returns error.TooLarge if the
/// body exceeds `message_size_max`.
pub fn encode_framed(message: *const Identify, output: []u8) Error![]const u8 {
    assert(output.len >= message_size_max + varint.length_max);
    var body: [message_size_max]u8 = undefined;
    const length = encoded_length(message);
    if (length > message_size_max) return error.TooLarge;
    var writer = protobuf.Writer.init(&body);
    if (message.public_key) |key| writer.write_bytes_field(1, key);
    for (message.listen_slice()) |*address| writer.write_bytes_field(2, address.slice());
    for (message.protocol_slice()) |protocol| writer.write_bytes_field(3, protocol);
    if (message.observed_address) |*address| writer.write_bytes_field(4, address.slice());
    writer.write_bytes_field(5, message.protocol_version);
    writer.write_bytes_field(6, message.agent_version);
    assert(writer.written().len == length);
    const prefix = varint.encode(output, length);
    @memcpy(output[prefix.len..][0..length], writer.written());
    return output[0 .. prefix.len + length];
}

fn field_length(bytes_length: usize) usize {
    return 1 + varint.encoded_length(bytes_length) + bytes_length;
}

fn encoded_length(message: *const Identify) usize {
    var length: usize = 0;
    if (message.public_key) |key| length += field_length(key.len);
    for (message.listen_slice()) |*address| length += field_length(address.slice().len);
    for (message.protocol_slice()) |protocol| length += field_length(protocol.len);
    if (message.observed_address) |*address| length += field_length(address.slice().len);
    length += field_length(message.protocol_version.len);
    length += field_length(message.agent_version.len);
    return length;
}

const secp256k1 = @import("../peers/secp256k1.zig");
const fuzz = @import("../../../testing/fuzz.zig");

test "identify: round trip and peer check" {
    var secret: secp256k1.SecretKey = @splat(0x42);
    secret[0] = 1;
    const public_key = try secp256k1.public_key(secret);
    var key_buffer: [identity.public_key_protobuf_length]u8 = undefined;
    var message: Identify = .{
        .public_key = identity.encode_public_key(&key_buffer, public_key),
        .agent_version = "needlefish",
    };
    message.listen_addresses[0] = try multiaddr.parse("/ip4/127.0.0.1/tcp/9222");
    message.listen_addresses_count = 1;
    message.protocols[0] = "/meshsub/1.1.0";
    message.protocols[1] = protocol_id;
    message.protocols_count = 2;
    message.observed_address = try multiaddr.parse("/ip4/10.0.0.2/tcp/50000");
    var output: [message_size_max + varint.length_max]u8 = undefined;
    const framed = try encode_framed(&message, &output);
    const prefix = try varint.decode(framed);
    const decoded = try decode(framed[prefix.length..]);
    try std.testing.expect(decoded.supports("/meshsub/1.1.0"));
    try std.testing.expect(!decoded.supports("/floodsub/1.0.0"));
    try std.testing.expect(decoded.listen_slice()[0].eql(&message.listen_addresses[0]));
    try std.testing.expectEqualStrings("needlefish", decoded.agent_version);
    try std.testing.expectEqualStrings("", decoded.protocol_version);
    try decoded.check_peer(&peer_id.from_public_key(public_key));
    secret[1] = 2;
    const other = peer_id.from_public_key(try secp256k1.public_key(secret));
    try std.testing.expectError(error.PeerMismatch, decoded.check_peer(&other));
}

test "identify: rejects wrong wire types and oversize input" {
    try std.testing.expectError(error.InvalidIdentify, decode(&.{ 0x08, 0x01 }));
    var big: [message_size_max + 1]u8 = @splat(0);
    try std.testing.expectError(error.TooLarge, decode(&big));
    // Unknown field 9 (varint) is skipped; unsupported multiaddr is skipped.
    const decoded = try decode(&.{ 0x48, 0x01, 0x12, 0x02, 0xff, 0xff });
    try std.testing.expectEqual(@as(u32, 0), decoded.listen_addresses_count);
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    const message = decode(input) catch return;
    var output: [message_size_max + varint.length_max]u8 = undefined;
    const framed = encode_framed(&message, &output) catch return;
    const prefix = try varint.decode(framed);
    const again = try decode(framed[prefix.length..]);
    try std.testing.expectEqual(message.protocols_count, again.protocols_count);
    try std.testing.expectEqual(message.listen_addresses_count, again.listen_addresses_count);
}

test "identify: fuzz decode and re-encode" {
    const corpus: []const u8 = &.{ 0x1a, 0x01, 0x61 };
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 512, .corpus = &.{corpus} });
}

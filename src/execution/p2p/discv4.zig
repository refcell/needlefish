//! Node Discovery Protocol v4 (devp2p `discv4.md`), IO-free: the UDP packets an execution
//! client uses to find peers. Base's execution nodes (reth) run discv4, not discv5.
//!
//!   packet = hash(32) || signature(65) || type(1) || rlp(data)
//!   hash = keccak256(signature || type || data)
//!   signature = sign(keccak256(type || data)), r || s || recovery id
//!
//! Decoding verifies the hash and recovers the sender's public key. Per EIP-8, decoders
//! ignore list elements past the ones they know. The caller owns time (`expiration` is
//! unix seconds) and randomness.

const std = @import("std");
const assert = std.debug.assert;
const curve = @import("../../common/crypto/secp256k1/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const rlp = @import("../../common/rlp/root.zig");

pub const PublicKey = curve.PublicKey;
/// discv4 caps packets at 1280 bytes.
pub const packet_size_max = 1280;
const header_length = 32 + 65;
const version = 4;

pub const Type = enum(u8) {
    ping = 0x01,
    pong = 0x02,
    find_node = 0x03,
    neighbors = 0x04,
    enr_request = 0x05,
    enr_response = 0x06,
    _,
};

pub const Error = rlp.Error || error{ BufferTooSmall, BadHash, BadSignature, Truncated };

/// A node's address: IPv4 or IPv6 bytes and its UDP and TCP ports.
pub const Endpoint = struct {
    ip: []const u8,
    udp: u16,
    tcp: u16,
};

pub const Packet = struct {
    hash: [32]u8,
    sender: PublicKey,
    type: Type,
    data: []const u8,
};

/// Signs and frames `data` (one RLP list) as a packet of `type`.
pub fn encode(secret: [32]u8, packet_type: Type, data: []const u8, output: []u8) Error![]u8 {
    const length = header_length + 1 + data.len;
    if (length > packet_size_max or output.len < length) return error.BufferTooSmall;
    output[header_length] = @backingInt(packet_type);
    @memcpy(output[header_length + 1 ..][0..data.len], data);
    const signature = curve.sign(secret, keccak.keccak256(output[header_length..length])) catch
        return error.BadSignature;
    output[32..64].* = signature.r;
    output[64..96].* = signature.s;
    output[96] = @intCast(signature.recovery_id & 1);
    output[0..32].* = keccak.keccak256(output[32..length]);
    assert(output[96] <= 1);
    return output[0..length];
}

/// Verifies `bytes` and returns its sender, type and data.
pub fn decode(bytes: []const u8) Error!Packet {
    if (bytes.len < header_length + 1) return error.Truncated;
    if (bytes.len > packet_size_max) return error.BufferTooSmall;
    const hash = keccak.keccak256(bytes[32..]);
    if (!std.mem.eql(u8, &hash, bytes[0..32])) return error.BadHash;
    if (bytes[96] > 1) return error.BadSignature;
    const signed = keccak.keccak256(bytes[header_length..]);
    const parity: u1 = @intCast(bytes[96]);
    const sender = curve.ecrecover(signed, parity, bytes[32..64].*, bytes[64..96].*) orelse
        return error.BadSignature;
    return .{
        .hash = hash,
        .sender = sender,
        .type = @fromBackingInt(@intCast(bytes[header_length])),
        .data = bytes[header_length + 1 ..],
    };
}

fn endpoint_payload(endpoint: Endpoint) usize {
    return rlp.bytes_length(endpoint.ip) + rlp.int_length(endpoint.udp) +
        rlp.int_length(endpoint.tcp);
}

fn endpoint_length(endpoint: Endpoint) usize {
    return rlp.list_length(endpoint_payload(endpoint));
}

fn write_endpoint(encoder: *rlp.Encoder, endpoint: Endpoint) void {
    assert(endpoint.ip.len == 4 or endpoint.ip.len == 16);
    encoder.list_header(endpoint_payload(endpoint));
    encoder.bytes(endpoint.ip);
    encoder.int(endpoint.udp);
    encoder.int(endpoint.tcp);
}

/// Ping: `[version, from, to, expiration]`.
pub fn encode_ping(output: []u8, from: Endpoint, to: Endpoint, expiration: u64) Error![]u8 {
    const payload = rlp.int_length(@as(u8, version)) + endpoint_length(from) +
        endpoint_length(to) + rlp.int_length(expiration);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(@as(u8, version));
    write_endpoint(&encoder, from);
    write_endpoint(&encoder, to);
    encoder.int(expiration);
    return encoder.written();
}

/// Pong: `[to, ping_hash, expiration]`.
pub fn encode_pong(output: []u8, to: Endpoint, ping_hash: [32]u8, expiration: u64) Error![]u8 {
    const payload = endpoint_length(to) + rlp.bytes_length(&ping_hash) +
        rlp.int_length(expiration);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    write_endpoint(&encoder, to);
    encoder.bytes(&ping_hash);
    encoder.int(expiration);
    return encoder.written();
}

/// FindNode: `[target, expiration]`; the target is a public key.
pub fn encode_find_node(output: []u8, target: *const PublicKey, expiration: u64) Error![]u8 {
    const payload = rlp.bytes_length(target) + rlp.int_length(expiration);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.bytes(target);
    encoder.int(expiration);
    return encoder.written();
}

/// ENRRequest: `[expiration]`.
pub fn encode_enr_request(output: []u8, expiration: u64) Error![]u8 {
    const payload = rlp.int_length(expiration);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(expiration);
    return encoder.written();
}

/// The fields of a Ping we need to answer it.
pub const Ping = struct { from: Endpoint, expiration: u64 };

pub fn decode_ping(data: []const u8) Error!Ping {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    _ = try fields.int(u64);
    const from = try read_endpoint(&fields);
    _ = try fields.raw();
    return .{ .from = from, .expiration = try fields.int(u64) };
}

pub const Pong = struct { ping_hash: [32]u8, expiration: u64 };

pub fn decode_pong(data: []const u8) Error!Pong {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    _ = try fields.raw();
    const ping_hash = try fields.fixed(32);
    return .{ .ping_hash = ping_hash, .expiration = try fields.int(u64) };
}

pub const Node = struct { endpoint: Endpoint, id: PublicKey };

/// Neighbors: `[[node, ...], expiration]`, node = `[ip, udp, tcp, id]`. Iterates nodes.
pub const Neighbors = struct {
    nodes: rlp.Decoder,
    expiration: u64,

    pub fn next(neighbors: *Neighbors) Error!?Node {
        if (neighbors.nodes.is_empty()) return null;
        var fields = try neighbors.nodes.list();
        const endpoint = try read_endpoint_fields(&fields);
        return .{ .endpoint = endpoint, .id = try fields.fixed(64) };
    }
};

pub fn decode_neighbors(data: []const u8) Error!Neighbors {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    const nodes = try fields.list();
    return .{ .nodes = nodes, .expiration = try fields.int(u64) };
}

pub const EnrResponse = struct { request_hash: [32]u8, record: []const u8 };

pub fn decode_enr_response(data: []const u8) Error!EnrResponse {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    const request_hash = try fields.fixed(32);
    return .{ .request_hash = request_hash, .record = try fields.raw() };
}

fn read_endpoint(fields: *rlp.Decoder) Error!Endpoint {
    var inner = try fields.list();
    return read_endpoint_fields(&inner);
}

/// `ip, udp, tcp`; an empty or odd-length ip (some clients send one) reads as no address.
fn read_endpoint_fields(fields: *rlp.Decoder) Error!Endpoint {
    const ip = try fields.bytes();
    const udp = try fields.int(u16);
    const tcp = try fields.int(u16);
    const known = ip.len == 4 or ip.len == 16;
    return .{ .ip = if (known) ip else ip[0..0], .udp = udp, .tcp = tcp };
}

/// The fork id in an ENR's `eth` entry: `[[fork_hash, fork_next], ...]`.
pub const ForkId = struct { hash: [4]u8, next: u64 };

pub fn decode_eth_entry(value: []const u8) Error!ForkId {
    var outer = rlp.Decoder.init(value);
    var entries = try outer.list();
    var fork = try entries.list();
    const hash = try fork.fixed(4);
    return .{ .hash = hash, .next = try fork.int(u64) };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const fuzz = @import("../../testing/fuzz.zig");

fn secret_from(prng: *Prng) [32]u8 {
    while (true) {
        var secret: [32]u8 = undefined;
        prng.fill(&secret);
        _ = curve.public_key(secret) catch continue;
        return secret;
    }
}

test "discv4: packets round trip, recover the sender, and reject tampering" {
    var prng = Prng.init(4);
    const secret = secret_from(&prng);
    const public = try curve.public_key(secret);
    const from: Endpoint = .{ .ip = &.{ 10, 0, 0, 1 }, .udp = 30303, .tcp = 30304 };
    const to: Endpoint = .{ .ip = &(@as([16]u8, @splat(1))), .udp = 1, .tcp = 0 };
    var data: [256]u8 = undefined;
    var wire: [packet_size_max]u8 = undefined;
    const ping = try encode(secret, .ping, try encode_ping(&data, from, to, 1_800_000_000), &wire);
    const packet = try decode(ping);
    try testing.expectEqual(Type.ping, packet.type);
    try testing.expectEqualSlices(u8, &public, &packet.sender);
    const decoded = try decode_ping(packet.data);
    try testing.expectEqualSlices(u8, from.ip, decoded.from.ip);
    try testing.expectEqual(@as(u16, 30304), decoded.from.tcp);
    try testing.expectEqual(@as(u64, 1_800_000_000), decoded.expiration);
    const pong_data = try encode_pong(&data, to, packet.hash, 7);
    const pong = try decode_pong((try decode(try encode(secret, .pong, pong_data, &wire))).data);
    try testing.expectEqualSlices(u8, &packet.hash, &pong.ping_hash);
    try testing.expectEqual(@as(u64, 7), pong.expiration);
    // A flipped bit anywhere fails the hash; a re-hashed forgery fails the signature.
    var forged = wire;
    const length = ping.len;
    forged[50] ^= 1;
    try testing.expectError(error.BadHash, decode(forged[0..length]));
    forged[0..32].* = keccak.keccak256(forged[32..length]);
    const recovered = decode(forged[0..length]) catch null;
    if (recovered) |other| try testing.expect(!std.mem.eql(u8, &public, &other.sender));
}

test "discv4: neighbors and ENR response decode, tolerating extra fields" {
    var buffer: [256]u8 = undefined;
    var writer: rlp.TreeWriter = .{ .buffer = &buffer };
    writer.begin_list();
    writer.begin_list();
    writer.begin_list();
    writer.bytes(&.{ 1, 2, 3, 4 });
    writer.bytes(&.{ 0x76, 0x5f });
    writer.bytes(&.{ 0x76, 0x5f });
    writer.bytes(&(@as([64]u8, @splat(9))));
    writer.end_list();
    writer.end_list();
    writer.bytes(&.{0x05});
    writer.bytes("extra");
    writer.end_list();
    var neighbors = try decode_neighbors(writer.written());
    try testing.expectEqual(@as(u64, 5), neighbors.expiration);
    const node = (try neighbors.next()).?;
    try testing.expectEqual(@as(u16, 30303), node.endpoint.tcp);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, node.endpoint.ip);
    try testing.expectEqual(@as(u8, 9), node.id[63]);
    try testing.expect((try neighbors.next()) == null);
    // `eth` entry of a Base Sepolia record: [[0xc6757f44, 0]].
    const fork = try decode_eth_entry(&.{ 0xc7, 0xc6, 0x84, 0xc6, 0x75, 0x7f, 0x44, 0x80 });
    try testing.expectEqualSlices(u8, &.{ 0xc6, 0x75, 0x7f, 0x44 }, &fork.hash);
    try testing.expectEqual(@as(u64, 0), fork.next);
}

fn fuzz_decoders(_: void, bytes: []const u8) !void {
    if (decode(bytes)) |packet| assert(packet.data.len < bytes.len) else |_| {}
    if (decode_ping(bytes)) |ping| assert(ping.from.ip.len <= 16) else |_| {}
    if (decode_pong(bytes)) |_| {} else |_| {}
    if (decode_enr_response(bytes)) |response| {
        assert(response.record.len < bytes.len);
    } else |_| {}
    if (decode_eth_entry(bytes)) |_| {} else |_| {}
    var neighbors = decode_neighbors(bytes) catch return;
    var count: usize = 0;
    while (neighbors.next() catch null) |node| : (count += 1) {
        assert(node.endpoint.ip.len <= 16);
        assert(count < bytes.len);
    }
}

test "discv4: fuzz the packet decoders" {
    const corpus: []const []const u8 = &.{
        &.{ 0xc7, 0xc6, 0x84, 0xc6, 0x75, 0x7f, 0x44, 0x80 },
        &.{ 0xcb, 0xc9, 0xc8, 0x84, 1, 2, 3, 4, 0x82, 0x76, 0x5f, 0x80, 0x05 },
    };
    try fuzz.run_bytes({}, fuzz_decoders, .{ .input_size_max = 512, .corpus = corpus });
}

//! P2P fuzz targets owned by the dst-fuzz lane.
//!
//! The p2p lane fuzzes each decoder against arbitrary bytes next to its code. These
//! targets add structured generation and properties that need more than one module:
//!   - discv5 packets: encode then decode returns every field and the plaintext; a
//!     decoded packet re-encodes to a byte-identical header; any tampering is rejected
//!     by AES-GCM; hand-built unmasked headers reach every authdata branch.
//!   - discv5 messages: structured messages round-trip; accepted mutations re-encode to
//!     a fixed point.
//!   - ENRs and boot nodes: built records keep their fields through binary, text, and
//!     boot-node parsing; accepted text is canonical base64.
//!   - node keys: accepted key files decode to the hex they contain, in any case, with
//!     any prefix and padding the format allows.
//!   - discv5 service: two real services plus fuzzed and tampered traffic never break
//!     the bounded tables (outbox, sessions, routing table, lookup).
//!   - libp2p: multistream framing survives arbitrary fragmentation; protobuf fields
//!     round-trip; multiaddrs round-trip through text and binary.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const rlp = @import("../common/rlp/root.zig");
const hex = @import("../common/primitives/hex.zig");
const packet = @import("../consensus/p2p/disc/packet.zig");
const messages = @import("../consensus/p2p/disc/messages.zig");
const service_module = @import("../consensus/p2p/disc/service.zig");
const lookup_module = @import("../consensus/p2p/disc/lookup.zig");
const enr = @import("../consensus/p2p/peers/enr.zig");
const boot = @import("../consensus/p2p/peers/boot.zig");
const enode = @import("../consensus/p2p/peers/enode.zig");
const node_key = @import("../consensus/p2p/peers/node_key.zig");
const secp256k1 = @import("../consensus/p2p/peers/secp256k1.zig");
const multiaddr = @import("../consensus/p2p/peers/multiaddr.zig");
const protobuf = @import("../consensus/p2p/libp2p/protobuf.zig");
const multistream = @import("../consensus/p2p/libp2p/multistream.zig");

const Aes128 = std.crypto.core.aes.Aes128;
const Service = service_module.Service;
const Endpoint = service_module.Endpoint;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

// ------------------------------------------------------------------ drawing

// Seeded runs feed `Smith` raw bytes: it reads 8 bytes per value and falls back to the
// range minimum when they miss the range, so narrow ranges, bools, `eos`, and slices
// almost always take their minimum. These helpers reduce a full `u64` instead. Under the
// coverage-guided driver (`smith.in == null`) they defer to `Smith` to keep its hints.

fn draw_range(smith: *Smith, comptime T: type, at_least: T, at_most: T) T {
    assert(at_least <= at_most);
    if (smith.in == null) return smith.valueRangeAtMost(T, at_least, at_most);
    const span = @as(u128, at_most - at_least) + 1;
    const offset: T = @intCast(@as(u128, smith.value(u64)) % span);
    assert(offset <= at_most - at_least);
    return at_least + offset;
}

fn draw_int(smith: *Smith, comptime T: type) T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    if (smith.in == null) return smith.value(T);
    if (@bitSizeOf(T) <= 64) return @truncate(smith.value(u64));
    const high: u128 = smith.value(u64);
    return @truncate(high << 64 | smith.value(u64));
}

fn draw_index(smith: *Smith, length: usize) usize {
    assert(length > 0);
    return @intCast(draw_range(smith, u64, 0, length - 1));
}

fn draw_chance(smith: *Smith, false_weight: u32, true_weight: u32) bool {
    assert(false_weight > 0 and true_weight > 0);
    if (smith.in == null) return smith.boolWeighted(false_weight, true_weight);
    return draw_range(smith, u32, 0, false_weight + true_weight - 1) >= false_weight;
}

/// Loop condition: keep going with odds `continue_weight : stop_weight`.
fn draw_more(smith: *Smith, continue_weight: u32, stop_weight: u32) bool {
    assert(continue_weight > 0 and stop_weight > 0);
    if (smith.in == null) return !smith.eosWeightedSimple(continue_weight, stop_weight);
    return !draw_chance(smith, continue_weight, stop_weight);
}

fn draw_slice(smith: *Smith, buffer: []u8) u32 {
    if (smith.in == null) return smith.slice(buffer);
    const length = draw_range(smith, u32, 0, @intCast(buffer.len));
    smith.bytes(buffer[0..length]);
    return length;
}

// ------------------------------------------------------------------ disc packet

const packet_plaintext_max = 512;

fn random_authdata(smith: *Smith, record: *[enr.size_max]u8) packet.Authdata {
    var node_id: packet.NodeId = undefined;
    smith.bytes(&node_id);
    switch (draw_range(smith, u8, 0, 2)) {
        0 => return .{ .message = node_id },
        1 => {
            var value: packet.Whoareyou = .{
                .id_nonce = undefined,
                .enr_seq = draw_int(smith, u64),
            };
            smith.bytes(&value.id_nonce);
            return .{ .whoareyou = value };
        },
        else => {
            var value: packet.Handshake = .{
                .src_id = node_id,
                .signature = undefined,
                .ephemeral_public_key = undefined,
                .record = undefined,
            };
            smith.bytes(&value.signature);
            smith.bytes(&value.ephemeral_public_key);
            value.record = record[0..draw_slice(smith, record)];
            return .{ .handshake = value };
        },
    }
}

/// An outgoing packet whose encoding always fits: the largest handshake (131 + 300
/// authdata bytes) plus `packet_plaintext_max` stays below `packet.size_max`.
fn random_outgoing(
    smith: *Smith,
    record: *[enr.size_max]u8,
    plaintext: *[packet_plaintext_max]u8,
) packet.Outgoing {
    comptime assert(packet.masking_iv_length + packet.static_header_length + 131 +
        enr.size_max + packet_plaintext_max + packet.tag_length <= packet.size_max);
    var outgoing: packet.Outgoing = .{
        .dest_id = undefined,
        .masking_iv = undefined,
        .nonce = undefined,
        .authdata = random_authdata(smith, record),
    };
    smith.bytes(&outgoing.dest_id);
    smith.bytes(&outgoing.masking_iv);
    smith.bytes(&outgoing.nonce);
    smith.bytes(&outgoing.key);
    outgoing.plaintext = plaintext[0..draw_slice(smith, plaintext)];
    return outgoing;
}

fn expect_authdata_equal(expected: packet.Authdata, actual: packet.Authdata) !void {
    try expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
    switch (expected) {
        .message => |src_id| try expectEqualSlices(u8, &src_id, &actual.message),
        .whoareyou => |value| {
            try expectEqualSlices(u8, &value.id_nonce, &actual.whoareyou.id_nonce);
            try expectEqual(value.enr_seq, actual.whoareyou.enr_seq);
        },
        .handshake => |value| {
            const other = actual.handshake;
            try expectEqualSlices(u8, &value.src_id, &other.src_id);
            try expectEqualSlices(u8, &value.signature, &other.signature);
            try expectEqualSlices(u8, &value.ephemeral_public_key, &other.ephemeral_public_key);
            try expectEqualSlices(u8, value.record, other.record);
        },
    }
}

/// A decoded packet re-encodes to the same masked header from its own fields (the
/// message body is ciphertext under a key we lack, so only its length is compared).
fn check_packet_canonical(local_id: packet.NodeId, bytes: []const u8) !void {
    var decoded: packet.Decoded = undefined;
    packet.decode(&decoded, local_id, bytes) catch return;
    const header_end = packet.masking_iv_length + decoded.header_length;
    try expect(decoded.header_length >= packet.static_header_length);
    try expect(decoded.header_length <= packet.header_length_max);
    try expectEqual(bytes.len, header_end + decoded.message.len);
    try expect(decoded.message.ptr == bytes[header_end..].ptr);
    var opened: [packet.size_max]u8 = undefined;
    _ = packet.open_message(&decoded, @splat(0), &opened) catch {};

    const zeros: [packet.size_max]u8 = @splat(0);
    const is_whoareyou = decoded.authdata == .whoareyou;
    const plaintext_length = if (is_whoareyou) 0 else decoded.message.len - packet.tag_length;
    const outgoing: packet.Outgoing = .{
        .dest_id = local_id,
        .masking_iv = decoded.masking_iv,
        .nonce = decoded.nonce,
        .authdata = decoded.authdata,
        .plaintext = zeros[0..plaintext_length],
    };
    var output: [packet.size_max]u8 = undefined;
    if (decoded.authdata == .handshake and decoded.authdata.handshake.record.len > enr.size_max) {
        // The decoder accepts any record length; the encoder caps it at an ENR's size.
        try std.testing.expectError(error.InvalidAuthdata, packet.encode(&output, &outgoing));
        return;
    }
    const encoded = try packet.encode(&output, &outgoing);
    try expectEqual(bytes.len, encoded.len);
    try expectEqualSlices(u8, bytes[0..header_end], encoded[0..header_end]);
    if (is_whoareyou) try expectEqualSlices(u8, bytes, encoded);
}

/// After any change to an authenticated packet, decryption with the original key fails.
fn check_packet_tampered(
    outgoing: *const packet.Outgoing,
    original: []const u8,
    mutated: []const u8,
) !void {
    try check_packet_canonical(outgoing.dest_id, mutated);
    if (outgoing.authdata == .whoareyou) return;
    if (std.mem.eql(u8, original, mutated)) return;
    var decoded: packet.Decoded = undefined;
    packet.decode(&decoded, outgoing.dest_id, mutated) catch return;
    var opened: [packet.size_max]u8 = undefined;
    if (packet.open_message(&decoded, outgoing.key, &opened)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
}

fn fuzz_packet_round_trip(_: void, smith: *Smith) anyerror!void {
    var record: [enr.size_max]u8 = undefined;
    var plaintext: [packet_plaintext_max]u8 = undefined;
    const outgoing = random_outgoing(smith, &record, &plaintext);
    var output: [packet.size_max]u8 = undefined;
    const encoded = try packet.encode(&output, &outgoing);
    var decoded: packet.Decoded = undefined;
    try packet.decode(&decoded, outgoing.dest_id, encoded);
    try expectEqualSlices(u8, &outgoing.masking_iv, &decoded.masking_iv);
    try expectEqualSlices(u8, &outgoing.nonce, &decoded.nonce);
    try expect_authdata_equal(outgoing.authdata, decoded.authdata);
    var opened: [packet.size_max]u8 = undefined;
    if (outgoing.authdata == .whoareyou) {
        try expectEqual(@as(usize, 0), decoded.message.len);
    } else {
        const plain = try packet.open_message(&decoded, outgoing.key, &opened);
        try expectEqualSlices(u8, outgoing.plaintext, plain);
        var wrong = outgoing.key;
        wrong[draw_index(smith, wrong.len)] ^= draw_int(smith, u8) | 1;
        const result = packet.open_message(&decoded, wrong, &opened);
        try std.testing.expectError(error.AuthenticationFailed, result);
    }
    try check_packet_canonical(outgoing.dest_id, encoded);

    var mutated: [packet.size_max]u8 = undefined;
    @memcpy(mutated[0..encoded.len], encoded);
    var flips: u32 = 0;
    while (flips < 4 and draw_more(smith, 1, 1)) : (flips += 1) {
        mutated[draw_index(smith, encoded.len)] ^= draw_int(smith, u8) | 1;
    }
    var length: u32 = @intCast(encoded.len);
    if (draw_chance(smith, 3, 1)) length = draw_range(smith, u32, 0, length);
    try check_packet_tampered(&outgoing, encoded, mutated[0..length]);
}

test "fuzz_targets_p2p: disc packet round trip and tamper detection" {
    try fuzz.run({}, fuzz_packet_round_trip, .{ .iterations = 512, .input_size_max = 2048 });
}

fn mask(
    local_id: packet.NodeId,
    masking_iv: packet.MaskingIv,
    output: []u8,
    input: []const u8,
) void {
    assert(output.len == input.len);
    const cipher = Aes128.initEnc(local_id[0..packet.key_length].*);
    std.crypto.core.modes.ctr(@TypeOf(cipher), cipher, output, input, masking_iv, .big);
}

/// An unmasked header near the valid space: random bytes would almost never unmask to
/// `discv5`, so the fuzzer would never reach the authdata parser.
fn random_header(smith: *Smith, header: *[packet.header_length_max]u8) []u8 {
    const static = header[0..packet.static_header_length];
    @memcpy(static[0..packet.protocol_id.len], packet.protocol_id);
    if (draw_chance(smith, 15, 1)) {
        static[draw_index(smith, packet.protocol_id.len)] = draw_int(smith, u8);
    }
    const version = if (draw_chance(smith, 15, 1)) draw_int(smith, u16) else packet.version;
    std.mem.writeInt(u16, static[6..8], version, .big);
    static[8] = draw_range(smith, u8, 0, 3);
    smith.bytes(static[9..21]);
    const authdata = header[packet.static_header_length..];
    const handshake_fixed = packet.handshake_authdata_head_length + 64 + 33;
    const authdata_length: u16 = switch (draw_range(smith, u8, 0, 3)) {
        0 => packet.message_authdata_length,
        1 => packet.whoareyou_authdata_length,
        2 => handshake_fixed + draw_range(smith, u16, 0, enr.size_max + 64),
        else => draw_range(smith, u16, 0, 400),
    };
    smith.bytes(authdata[0..authdata_length]);
    if (authdata_length >= packet.handshake_authdata_head_length and draw_chance(smith, 1, 3)) {
        authdata[32] = secp256k1.signature_length;
        authdata[33] = secp256k1.compressed_length;
    }
    const field = if (draw_chance(smith, 7, 1)) authdata_length else draw_int(smith, u16);
    std.mem.writeInt(u16, static[21..23], field, .big);
    return header[0 .. packet.static_header_length + authdata_length];
}

fn fuzz_packet_header(_: void, smith: *Smith) anyerror!void {
    var local_id: packet.NodeId = undefined;
    smith.bytes(&local_id);
    var header_buffer: [packet.header_length_max]u8 = undefined;
    const header = random_header(smith, &header_buffer);
    var bytes: [packet.size_max]u8 = undefined;
    var masking_iv: packet.MaskingIv = undefined;
    smith.bytes(&masking_iv);
    @memcpy(bytes[0..packet.masking_iv_length], &masking_iv);
    const header_end = packet.masking_iv_length + header.len;
    mask(local_id, masking_iv, bytes[packet.masking_iv_length..header_end], header);
    const message_length = draw_slice(smith, bytes[header_end..][0..64]);
    const total = header_end + message_length;
    try check_packet_canonical(local_id, bytes[0..total]);
    var decoded: packet.Decoded = undefined;
    packet.decode(&decoded, local_id, bytes[0..total]) catch return;
    const field = std.mem.readInt(u16, header[21..23], .big);
    if (field + packet.static_header_length == header.len) {
        try expectEqualSlices(u8, header, decoded.header());
    }
}

test "fuzz_targets_p2p: disc packet unmasked header space" {
    try fuzz.run({}, fuzz_packet_header, .{ .iterations = 2048 });
}

fn fuzz_packet_bytes(_: void, smith: *Smith) anyerror!void {
    var local_id: packet.NodeId = @splat(0x5a);
    if (draw_chance(smith, 1, 1)) smith.bytes(&local_id);
    var bytes: [packet.size_max + 16]u8 = undefined;
    const length = draw_slice(smith, &bytes);
    try check_packet_canonical(local_id, bytes[0..length]);
}

test "fuzz_targets_p2p: disc packet arbitrary bytes" {
    try fuzz.run({}, fuzz_packet_bytes, .{ .iterations = 512, .input_size_max = 1400 });
}

// ------------------------------------------------------------------ disc messages

const message_records_max = 4;
const message_bytes_max = 48;

const MessageStorage = struct {
    records: [message_records_max][message_bytes_max + 2]u8 = undefined,
    first: [message_bytes_max]u8 = undefined,
    second: [message_bytes_max]u8 = undefined,
};

fn random_request_id(smith: *Smith) messages.RequestId {
    var id: messages.RequestId = .{};
    id.length = @intCast(draw_slice(smith, &id.bytes));
    return id;
}

fn random_message(smith: *Smith, storage: *MessageStorage) messages.Message {
    const id = random_request_id(smith);
    const first = storage.first[0..draw_slice(smith, &storage.first)];
    const second = storage.second[0..draw_slice(smith, &storage.second)];
    switch (draw_range(smith, u8, 1, 6)) {
        1 => return .{ .ping = .{ .request_id = id, .enr_seq = draw_int(smith, u64) } },
        2 => {
            var pong: messages.Pong = .{
                .request_id = id,
                .enr_seq = draw_int(smith, u64),
                .address = .{ .ip4 = undefined },
                .port = draw_int(smith, u16),
            };
            if (draw_chance(smith, 1, 1)) pong.address = .{ .ip6 = undefined };
            switch (pong.address) {
                inline else => |*address| smith.bytes(address),
            }
            return .{ .pong = pong };
        },
        3 => {
            var findnode: messages.Findnode = .{ .request_id = id };
            const count = draw_range(smith, u8, 0, messages.distances_max);
            for (findnode.distances[0..count]) |*distance| {
                distance.* = draw_range(smith, u16, 0, 256);
            }
            findnode.distances_count = count;
            return .{ .findnode = findnode };
        },
        4 => return .{ .nodes = random_nodes(smith, id, storage) },
        5 => return .{ .talkreq = .{ .request_id = id, .protocol = first, .request = second } },
        else => return .{ .talkresp = .{ .request_id = id, .response = first } },
    }
}

/// NODES records are raw RLP items; byte strings stand in for ENRs.
fn random_nodes(
    smith: *Smith,
    id: messages.RequestId,
    storage: *MessageStorage,
) messages.Nodes {
    var nodes: messages.Nodes = .{ .request_id = id, .total = draw_int(smith, u64) };
    const count = draw_range(smith, u8, 0, message_records_max);
    for (0..count) |index| {
        var data: [message_bytes_max]u8 = undefined;
        const length = draw_slice(smith, &data);
        var encoder = rlp.Encoder.init(&storage.records[index]);
        encoder.bytes(data[0..length]);
        nodes.records[index] = encoder.written();
    }
    nodes.records_count = count;
    return nodes;
}

fn expect_message_equal(expected: *const messages.Message, actual: *const messages.Message) !void {
    try expectEqual(std.meta.activeTag(expected.*), std.meta.activeTag(actual.*));
    try expect(expected.request_id().eql(&actual.request_id()));
    switch (expected.*) {
        .ping => |value| try expectEqual(value.enr_seq, actual.ping.enr_seq),
        .pong => |value| try expect(std.meta.eql(value, actual.pong)),
        .findnode => |*value| try expectEqualSlices(
            u16,
            value.distances_slice(),
            actual.findnode.distances_slice(),
        ),
        .nodes => |*value| {
            try expectEqual(value.total, actual.nodes.total);
            const records = actual.nodes.records_slice();
            try expectEqual(value.records_count, actual.nodes.records_count);
            for (value.records_slice(), records) |a, b| try expectEqualSlices(u8, a, b);
        },
        .talkreq => |value| {
            try expectEqualSlices(u8, value.protocol, actual.talkreq.protocol);
            try expectEqualSlices(u8, value.request, actual.talkreq.request);
        },
        .talkresp => |value| try expectEqualSlices(u8, value.response, actual.talkresp.response),
    }
}

/// Decode tolerates trailing list items, so the property is a fixed point: an accepted
/// input re-encodes to bytes that decode to the same message and re-encode identically.
fn check_message_fixed_point(input: []const u8) !void {
    const message = messages.decode(input) catch return;
    var buffer: [packet.size_max * 2]u8 = undefined;
    const encoded = try messages.encode(&buffer, &message);
    try expect(encoded.len <= input.len);
    const again = try messages.decode(encoded);
    try expect_message_equal(&message, &again);
    var buffer_again: [packet.size_max * 2]u8 = undefined;
    try expectEqualSlices(u8, encoded, try messages.encode(&buffer_again, &again));
}

fn fuzz_messages(_: void, smith: *Smith) anyerror!void {
    var storage: MessageStorage = .{};
    const message = random_message(smith, &storage);
    var buffer: [packet.size_max]u8 = undefined;
    const encoded = try messages.encode(&buffer, &message);
    const decoded = try messages.decode(encoded);
    try expect_message_equal(&message, &decoded);
    try check_message_fixed_point(encoded);
    var flips: u32 = 0;
    while (flips < 3 and draw_more(smith, 1, 1)) : (flips += 1) {
        buffer[draw_index(smith, encoded.len)] ^= draw_int(smith, u8) | 1;
    }
    const cut = draw_range(smith, u32, 0, @intCast(encoded.len));
    try check_message_fixed_point(buffer[0..cut]);
    try check_message_fixed_point(buffer[0..encoded.len]);
}

test "fuzz_targets_p2p: disc messages round trip" {
    try fuzz.run({}, fuzz_messages, .{ .iterations = 2048 });
}

// ------------------------------------------------------------------ ENR and boot nodes

fn random_secret(smith: *Smith) secp256k1.SecretKey {
    var secret: secp256k1.SecretKey = undefined;
    smith.bytes(&secret);
    secp256k1.validate_secret_key(secret) catch {
        secret = @splat(0x11); // A valid scalar: far below the group order.
    };
    return secret;
}

fn random_fields(smith: *Smith) enr.Fields {
    var fields: enr.Fields = .{ .sequence = draw_int(smith, u64) };
    if (draw_chance(smith, 1, 1)) fields.ip4 = @bitCast(draw_int(smith, u32));
    if (draw_chance(smith, 1, 1)) fields.ip6 = @bitCast(draw_int(smith, u128));
    if (draw_chance(smith, 1, 1)) fields.opstack = .{
        .chain_id = draw_int(smith, u64),
        .version = draw_range(smith, u64, 0, 1),
    };
    if (draw_chance(smith, 1, 1)) fields.tcp = draw_int(smith, u16);
    if (draw_chance(smith, 1, 1)) fields.tcp6 = draw_int(smith, u16);
    if (draw_chance(smith, 1, 1)) fields.udp = draw_int(smith, u16);
    if (draw_chance(smith, 1, 1)) fields.udp6 = draw_int(smith, u16);
    return fields;
}

fn check_record_fields(record: *const enr.Record, fields: enr.Fields) !void {
    try expectEqual(fields.sequence, record.sequence);
    try expect(std.meta.eql(fields.ip4, record.ip4()));
    try expect(std.meta.eql(fields.ip6, record.ip6()));
    try expect(std.meta.eql(fields.opstack, record.opstack()));
    try expectEqual(fields.tcp, record.tcp());
    try expectEqual(fields.tcp6, record.tcp6());
    try expectEqual(fields.udp, record.udp());
    try expectEqual(fields.udp6, record.udp6());
    const chain_id: u64 = if (fields.opstack) |value| value.chain_id else 0;
    const validation = enr.validate_chain(record, chain_id);
    if (fields.opstack) |value| {
        const expected: enr.Validation = if (value.version == 0) .valid else .invalid_version;
        try expectEqual(expected, validation);
    } else try expectEqual(enr.Validation.missing_key, validation);
}

/// A dialable address exists exactly when the record has a TCP socket for its IP.
fn check_record_multiaddr(record: *const enr.Record, fields: enr.Fields) !void {
    const node: boot.BootNode = .{ .record = record.* };
    const address = node.to_multiaddr();
    const dialable = if (fields.ip4 != null)
        fields.tcp != null
    else
        fields.ip6 != null and (fields.tcp6 != null or fields.tcp != null);
    try expectEqual(dialable, address != null);
    const value = address orelse return;
    try expectEqualSlices(u8, &record.public_key, &value.peer().?.secp256k1_public_key().?);
    var text: [multiaddr.text_length_max]u8 = undefined;
    const round = try multiaddr.parse(value.format(&text));
    try expect(round.eql(&value));
}

/// Accepted `enr:` text must be canonical: the record re-encodes to the same text.
fn check_record_text(text: []const u8) !void {
    const node = boot.parse(text) catch return;
    switch (node) {
        .record => |*record| {
            var output: [enr.text_length_max]u8 = undefined;
            try expectEqualSlices(u8, text, enr.encode_text(&output, record));
            const again = try enr.decode(record.raw());
            try expectEqualSlices(u8, record.raw(), again.raw());
        },
        .enode => |*record| {
            const again = try enode.parse(text);
            try expect(std.meta.eql(record.*, again));
            const address = record.to_multiaddr();
            const key = address.peer().?.secp256k1_public_key().?;
            try expectEqualSlices(u8, &record.public_key, &key);
        },
    }
}

fn fuzz_record(_: void, smith: *Smith) anyerror!void {
    const secret = random_secret(smith);
    const fields = random_fields(smith);
    const record = try enr.build(secret, fields);
    try check_record_fields(&record, fields);
    const public_key = try secp256k1.public_key(secret);
    try expectEqualSlices(u8, &enr.node_id_from_public_key(public_key), &record.node_id());
    try check_record_multiaddr(&record, fields);
    var text_buffer: [enr.text_length_max]u8 = undefined;
    const text = enr.encode_text(&text_buffer, &record);
    const parsed = try boot.parse(text);
    try expectEqualSlices(u8, record.raw(), parsed.record.raw());
    try check_record_text(text);
    // Flip text characters within the alphabet; the last character carries padding bits.
    var mutated: [enr.text_length_max]u8 = undefined;
    @memcpy(mutated[0..text.len], text);
    const alphabet = std.base64.url_safe_alphabet_chars;
    if (draw_chance(smith, 1, 1)) {
        mutated[text.len - 1] = alphabet[draw_index(smith, alphabet.len)];
    } else {
        const index = draw_range(smith, u32, enr.text_prefix.len, @intCast(text.len - 1));
        mutated[index] = alphabet[draw_index(smith, alphabet.len)];
    }
    try check_record_text(mutated[0..text.len]);
}

test "fuzz_targets_p2p: enr build, text, and boot node round trip" {
    try fuzz.run({}, fuzz_record, .{ .iterations = 48 });
}

fn fuzz_boot_text(_: void, smith: *Smith) anyerror!void {
    var text: [enr.text_length_max + 8]u8 = undefined;
    var length: usize = 0;
    const alphabet = std.base64.url_safe_alphabet_chars;
    switch (draw_range(smith, u8, 0, 2)) {
        0 => length = draw_slice(smith, &text),
        1 => {
            @memcpy(text[0..enr.text_prefix.len], enr.text_prefix);
            length = enr.text_prefix.len + draw_slice(smith, text[enr.text_prefix.len..]);
            for (text[enr.text_prefix.len..length]) |*character| {
                character.* = alphabet[character.* % alphabet.len];
            }
        },
        else => {
            @memcpy(text[0..enode.scheme.len], enode.scheme);
            length = enode.scheme.len + draw_slice(smith, text[enode.scheme.len..]);
            const characters = "0123456789abcdefABCDEF@:.[]?=discport";
            for (text[enode.scheme.len..length]) |*character| {
                character.* = characters[character.* % characters.len];
            }
        },
    }
    try check_record_text(text[0..length]);
}

test "fuzz_targets_p2p: boot node parse survives arbitrary text" {
    try fuzz.run({}, fuzz_boot_text, .{ .iterations = 1024, .input_size_max = 512 });
}

// ------------------------------------------------------------------ node key

/// Accepted key files hold exactly the secret they encode, in canonical lowercase form.
fn check_node_key(contents: []const u8) !void {
    const key = node_key.parse(contents) catch return;
    var file: [node_key.file_length]u8 = undefined;
    const canonical = key.to_file(&file);
    const digits = hex.strip_prefix(std.mem.trim(u8, contents, " \t\r\n"));
    try expectEqual(digits.len, canonical.len);
    for (digits, canonical) |digit, expected| {
        try expectEqual(expected, std.ascii.toLower(digit));
    }
    try expectEqualSlices(u8, &(try secp256k1.public_key(key.secret)), &key.public_key);
    const peer = key.peer_id();
    try expectEqualSlices(u8, &key.public_key, &peer.secp256k1_public_key().?);
}

fn fuzz_node_key(_: void, smith: *Smith) anyerror!void {
    var raw: [96]u8 = undefined;
    try check_node_key(raw[0..draw_slice(smith, &raw)]);

    var secret: secp256k1.SecretKey = undefined;
    smith.bytes(&secret);
    var text: [node_key.file_length + 16]u8 = undefined;
    var length: usize = 0;
    const whitespace = " \t\r\n";
    while (length < 4 and draw_chance(smith, 3, 1)) : (length += 1) {
        text[length] = whitespace[draw_index(smith, whitespace.len)];
    }
    switch (draw_range(smith, u8, 0, 2)) {
        0 => {},
        1 => length += copy(text[length..], "0x"),
        else => length += copy(text[length..], "0X"),
    }
    const digits = text[length..][0..node_key.file_length];
    hex.encode(digits, &secret);
    for (digits) |*digit| {
        if (draw_chance(smith, 3, 1)) digit.* = std.ascii.toUpper(digit.*);
    }
    length += node_key.file_length;
    while (length < text.len and draw_chance(smith, 3, 1)) : (length += 1) {
        text[length] = whitespace[draw_index(smith, whitespace.len)];
    }
    const valid = if (secp256k1.validate_secret_key(secret)) |_| true else |_| false;
    if (node_key.parse(text[0..length])) |key| {
        try expect(valid);
        try expectEqualSlices(u8, &secret, &key.secret);
    } else |err| {
        try expect(!valid);
        try expectEqual(error.InvalidSecretKey, err);
    }
    try check_node_key(text[0..length]);
    text[draw_index(smith, length)] = draw_int(smith, u8);
    try check_node_key(text[0..length]);
}

fn copy(output: []u8, input: []const u8) usize {
    @memcpy(output[0..input.len], input);
    return input.len;
}

test "fuzz_targets_p2p: node key parse" {
    try fuzz.run({}, fuzz_node_key, .{ .iterations = 256 });
}

// ------------------------------------------------------------------ disc service

const service_chain_id = 8453;
const service_steps_max = 40;

/// Records built once: signing in every iteration would dominate the run time.
const ServiceFixture = struct {
    secrets: [3]secp256k1.SecretKey,
    records: [3]enr.Record,

    fn init() !ServiceFixture {
        var fixture: ServiceFixture = undefined;
        for (&fixture.secrets, &fixture.records, 0..) |*secret, *record, index| {
            secret.* = @splat(0x31 + @as(u8, @intCast(index)));
            const octet: u8 = @intCast(index + 1);
            record.* = try enr.build(secret.*, .{
                .ip4 = .{ 10, 0, 0, octet },
                .udp = 9000,
                .tcp = 9222,
                .opstack = .{ .chain_id = service_chain_id },
            });
        }
        return fixture;
    }

    fn endpoint(index: u8) Endpoint {
        return .{ .address = .{ .ip4 = .{ 10, 0, 0, index + 1 } }, .port = 9000 };
    }
};

const service_config: service_module.Config = .{
    .chain_id = service_chain_id,
    .lookup_interval_ns = 200 * std.time.ns_per_ms,
    .sessions_max = 3,
    .pending_max = 4,
    .challenges_max = 3,
    .outbox_max = 6,
    .discovered_max = 3,
    .table = .{
        .bucket_size = 2,
        .replacements_max = 1,
        .nodes_max = 8,
        .subnet_bucket_max = 0,
        .subnet_table_max = 0,
    },
};

fn check_service(service: *Service) !void {
    try expect(service.outbox.count <= service.outbox.items.len);
    try expect(service.discovered.count <= service.discovered.items.len);
    try expect(service.sessions.count <= service.sessions.sessions.len);
    try expect(service.lookup.count <= lookup_module.candidates_max);
    try expect(service.stats.packets_invalid <= service.stats.packets_received);
    const table = &service.table;
    var used: u32 = table.free_count;
    for (table.buckets) |*bucket| {
        try expect(bucket.live_count <= table.config.bucket_size);
        try expect(bucket.replacements_count <= table.config.replacements_max);
        used += bucket.live_count + bucket.replacements_count;
    }
    try expectEqual(@as(u32, table.config.nodes_max), used);
    const sessions = service.sessions.sessions[0..service.sessions.count];
    for (sessions, 0..) |*a, index| {
        for (sessions[index + 1 ..]) |*b| {
            const same_node = std.mem.eql(u8, &a.node_id, &b.node_id);
            try expect(!(same_node and a.endpoint.eql(b.endpoint)));
        }
    }
}

const ServiceRun = struct {
    services: [2]Service,
    now_ns: u64 = 0,
};

/// Moves one queued datagram from `from` to `to`, sometimes damaged on the way.
fn deliver(run: *ServiceRun, smith: *Smith, from: u8, to: u8, damage: bool) void {
    const datagram = run.services[from].pop_outgoing() orelse return;
    var bytes: [packet.size_max]u8 = undefined;
    const length = datagram.length;
    @memcpy(bytes[0..length], datagram.slice());
    if (damage and length > 0 and draw_chance(smith, 5, 1)) {
        bytes[draw_index(smith, length)] ^= draw_int(smith, u8) | 1;
    }
    run.services[to].on_packet(ServiceFixture.endpoint(from), bytes[0..length], run.now_ns);
}

/// Delivers queued traffic both ways undamaged, so handshakes and lookups complete.
fn pump(run: *ServiceRun, smith: *Smith) void {
    var round: u32 = 0;
    while (round < 16) : (round += 1) {
        const idle = run.services[0].outbox.count == 0 and run.services[1].outbox.count == 0;
        if (idle) break;
        deliver(run, smith, 0, 1, false);
        deliver(run, smith, 1, 0, false);
    }
}

/// A packet addressed to node 0 that passes unmasking, so it reaches the session layer.
fn inject_crafted(run: *ServiceRun, smith: *Smith, fixture: *const ServiceFixture) !void {
    var record: [enr.size_max]u8 = undefined;
    var plaintext: [packet_plaintext_max]u8 = undefined;
    var outgoing = random_outgoing(smith, &record, &plaintext);
    outgoing.dest_id = run.services[0].local_id;
    const sender = draw_range(smith, u8, 1, 2);
    const sender_id = fixture.records[sender].node_id();
    switch (outgoing.authdata) {
        .message => |*src_id| src_id.* = sender_id,
        .handshake => |*value| {
            value.src_id = sender_id;
            if (draw_chance(smith, 1, 1)) value.record = fixture.records[sender].raw();
        },
        .whoareyou => {},
    }
    if (draw_chance(smith, 1, 1)) {
        var storage: MessageStorage = .{};
        const message = random_message(smith, &storage);
        outgoing.plaintext = try messages.encode(&plaintext, &message);
    }
    var output: [packet.size_max]u8 = undefined;
    const bytes = try packet.encode(&output, &outgoing);
    run.services[0].on_packet(ServiceFixture.endpoint(sender), bytes, run.now_ns);
}

fn service_step(run: *ServiceRun, smith: *Smith, fixture: *const ServiceFixture) !void {
    switch (draw_range(smith, u8, 0, 8)) {
        0 => run.services[1].add_boot_record(&fixture.records[0], run.now_ns),
        8 => pump(run, smith),
        1 => run.services[0].add_boot_record(&fixture.records[1], run.now_ns),
        2 => run.services[1].add_boot_record(&fixture.records[2], run.now_ns),
        3 => deliver(run, smith, 1, 0, true),
        4 => deliver(run, smith, 0, 1, true),
        5 => {
            var garbage: [160]u8 = undefined;
            const length = draw_slice(smith, &garbage);
            run.services[0].on_packet(ServiceFixture.endpoint(2), garbage[0..length], run.now_ns);
        },
        6 => try inject_crafted(run, smith, fixture),
        else => {
            run.now_ns += draw_range(smith, u64, 1, 800) * std.time.ns_per_ms;
            for (&run.services) |*service| service.tick(run.now_ns);
        },
    }
    while (run.services[0].pop_discovered()) |record| {
        try expect(enr.validate_chain(record, service_chain_id) == .valid);
    }
    _ = run.services[1].pop_discovered();
}

fn fuzz_service(fixture: *const ServiceFixture, smith: *Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var prngs = [2]Prng{ Prng.init(draw_int(smith, u64)), Prng.init(draw_int(smith, u64)) };
    var run: ServiceRun = .{ .services = undefined };
    for (&run.services, &prngs, 0..) |*service, *prng, index| {
        service.* = try Service.init(
            allocator,
            service_config,
            fixture.secrets[index],
            fixture.records[index],
            prng.random(),
        );
    }
    defer for (&run.services) |*service| service.deinit(allocator);
    var step: u32 = 0;
    while (step < service_steps_max and draw_more(smith, 15, 1)) : (step += 1) {
        try service_step(&run, smith, fixture);
        for (&run.services) |*service| try check_service(service);
    }
}

test "fuzz_targets_p2p: disc service keeps bounded tables under fuzzed traffic" {
    const fixture = try ServiceFixture.init();
    // 32 seeded iterations keep this under ~1 s in Debug; coverage runs go deeper.
    try fuzz.run(&fixture, fuzz_service, .{ .iterations = 32, .input_size_max = 8192 });
}

// ------------------------------------------------------------------ libp2p framing

const stream_messages_max = 4;

fn fuzz_multistream(_: void, smith: *Smith) anyerror!void {
    var stream: [stream_messages_max * multistream.frame_length_max]u8 = undefined;
    var spans: [stream_messages_max][2]u32 = undefined;
    var stream_length: usize = 0;
    var count: u32 = 0;
    while (count < stream_messages_max and draw_more(smith, 3, 1)) : (count += 1) {
        var message: [multistream.protocol_length_max]u8 = undefined;
        const length_max: u32 = if (draw_chance(smith, 7, 1)) 64 else message.len;
        const length = draw_range(smith, u32, 1, length_max);
        smith.bytes(message[0..length]);
        const frame = multistream.encode(stream[stream_length..], message[0..length]);
        const decoded = try multistream.decode(frame);
        try expectEqual(@as(u32, @intCast(frame.len)), decoded.length);
        spans[count] = .{ @intCast(stream_length + frame.len - length - 1), length };
        stream_length += frame.len;
    }
    // Arbitrary fragmentation must yield exactly the encoded messages, in order.
    var inbox: multistream.Inbox = .{};
    var offset: usize = 0;
    var received: u32 = 0;
    while (offset < stream_length) {
        const chunk = draw_range(smith, u32, 1, @intCast(stream_length - offset));
        const pushed = try inbox.push(stream[offset..][0..chunk]);
        try expect(pushed.consumed <= chunk);
        try expect(pushed.consumed > 0 or pushed.message != null);
        offset += pushed.consumed;
        const message = pushed.message orelse continue;
        try expect(received < count);
        const span = spans[received];
        try expectEqualSlices(u8, stream[span[0]..][0..span[1]], message);
        received += 1;
    }
    try expectEqual(count, received);
    if (stream_length == 0) return;
    stream[draw_index(smith, stream_length)] ^= draw_int(smith, u8) | 1;
    try push_all(&stream, stream_length, smith);
}

/// Damaged streams: every push makes progress or reports an error; never a panic.
fn push_all(stream: []const u8, stream_length: usize, smith: *Smith) !void {
    var inbox: multistream.Inbox = .{};
    var offset: usize = 0;
    while (offset < stream_length) {
        const chunk = draw_range(smith, u32, 1, @intCast(stream_length - offset));
        const pushed = inbox.push(stream[offset..][0..chunk]) catch return;
        try expect(pushed.consumed > 0 or pushed.message != null);
        if (pushed.message) |message| try expect(message.len < multistream.message_length_max);
        offset += pushed.consumed;
    }
}

test "fuzz_targets_p2p: multistream framing survives fragmentation" {
    try fuzz.run({}, fuzz_multistream, .{ .iterations = 512, .input_size_max = 4096 });
}

const proto_fields_max = 6;

fn fuzz_protobuf(_: void, smith: *Smith) anyerror!void {
    var buffer: [proto_fields_max * 64]u8 = undefined;
    var payloads: [proto_fields_max][32]u8 = undefined;
    var fields: [proto_fields_max]protobuf.Field = undefined;
    var writer = protobuf.Writer.init(&buffer);
    var count: u32 = 0;
    while (count < proto_fields_max and draw_more(smith, 3, 1)) : (count += 1) {
        const number = if (draw_chance(smith, 1, 1))
            draw_range(smith, u32, 1, 31)
        else
            draw_range(smith, u32, 1, std.math.maxInt(u29));
        if (draw_chance(smith, 1, 1)) {
            const value = draw_int(smith, u64);
            writer.write_varint_field(number, value);
            fields[count] = .{
                .number = number,
                .wire_type = .varint,
                .value = value,
                .bytes = "",
            };
        } else {
            const bytes = payloads[count][0..draw_slice(smith, &payloads[count])];
            writer.write_bytes_field(number, bytes);
            fields[count] = .{ .number = number, .wire_type = .bytes, .value = 0, .bytes = bytes };
        }
    }
    var reader = protobuf.Reader.init(writer.written());
    for (fields[0..count]) |expected| {
        const field = (try reader.next()).?;
        try expectEqual(expected.number, field.number);
        try expectEqual(expected.wire_type, field.wire_type);
        try expectEqual(expected.value, field.value);
        try expectEqualSlices(u8, expected.bytes, field.bytes);
    }
    try expect((try reader.next()) == null);
    const written = writer.length;
    if (written == 0) return;
    buffer[draw_index(smith, written)] ^= draw_int(smith, u8) | 1;
    try check_protobuf_reader(buffer[0..draw_range(smith, u32, 0, @intCast(written))]);
}

/// Every field consumes at least two bytes and its payload lies inside the input.
fn check_protobuf_reader(input: []const u8) !void {
    var reader = protobuf.Reader.init(input);
    var fields: usize = 0;
    while (reader.next() catch return) |field| {
        fields += 1;
        try expect(fields * 2 <= input.len);
        try expect(field.number > 0 and field.number <= std.math.maxInt(u29));
        if (field.wire_type != .bytes) continue;
        const start = @intFromPtr(field.bytes.ptr) - @intFromPtr(input.ptr);
        try expect(start + field.bytes.len <= input.len);
    }
}

test "fuzz_targets_p2p: protobuf fields round trip" {
    try fuzz.run({}, fuzz_protobuf, .{ .iterations = 1024 });
}

fn random_component(smith: *Smith, storage: *[34]u8) multiaddr.Component {
    switch (draw_range(smith, u8, 0, 6)) {
        0 => return .{ .ip4 = @bitCast(draw_int(smith, u32)) },
        1 => return .{ .ip6 = @bitCast(draw_int(smith, u128)) },
        2 => return .{ .tcp = draw_int(smith, u16) },
        3 => return .{ .udp = draw_int(smith, u16) },
        4 => return .quic_v1,
        5 => {
            const characters = "abcdefghijklmnopqrstuvwxyz0123456789-.";
            const length = draw_range(smith, u32, 1, storage.len);
            for (storage[0..length]) |*character| {
                character.* = characters[draw_index(smith, characters.len)];
            }
            const name = storage[0..length];
            return switch (draw_range(smith, u8, 0, 2)) {
                0 => .{ .dns = name },
                1 => .{ .dns4 = name },
                else => .{ .dns6 = name },
            };
        },
        else => {
            // A sha256 multihash peer id.
            storage[0] = 0x12;
            storage[1] = 32;
            smith.bytes(storage[2..34]);
            return .{ .p2p = storage[0..34] };
        },
    }
}

fn fuzz_multiaddr(_: void, smith: *Smith) anyerror!void {
    var address: multiaddr.Multiaddr = .{};
    var storage: [multiaddr.components_max][34]u8 = undefined;
    var index: u32 = 0;
    while (index < multiaddr.components_max + 1 and draw_more(smith, 3, 1)) {
        const component = random_component(smith, &storage[@min(index, storage.len - 1)]);
        address.push(component) catch |err| {
            try expectEqual(error.TooLong, err);
            break;
        };
        index += 1;
    }
    try expectEqual(index, address.components);
    if (address.length == 0) return;
    const binary = try multiaddr.from_bytes(address.slice());
    try expect(binary.eql(&address));
    try expectEqual(address.components, binary.components);
    var text: [multiaddr.text_length_max]u8 = undefined;
    const round = try multiaddr.parse(address.format(&text));
    try expect(round.eql(&address));
    var bytes = address.bytes;
    bytes[draw_index(smith, address.length)] ^= draw_int(smith, u8) | 1;
    const mutated = multiaddr.from_bytes(bytes[0..address.length]) catch return;
    const again = try multiaddr.parse(mutated.format(&text));
    try expect(again.eql(&mutated));
}

test "fuzz_targets_p2p: multiaddr text and binary round trip" {
    try fuzz.run({}, fuzz_multiaddr, .{ .iterations = 1024 });
}

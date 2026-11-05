//! discv5 protocol messages (`message-type || rlp(message-data)`): PING, PONG, FINDNODE,
//! NODES, TALKREQ, TALKRESP. Topic messages (REGTOPIC..TOPICNODES) are not used by OP
//! Stack nodes and decode as `UnsupportedType`.
//!
//! Decoding is zero-copy: byte fields and NODES records are slices into the plaintext.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../../common/rlp/root.zig");
const ip = @import("../peers/ip.zig");
const enr = @import("../peers/enr.zig");
const packet = @import("packet.zig");

/// FINDNODE distances per request. Geth sends at most 3; we accept a few more.
pub const distances_max = 16;
/// Records per NODES message. A 1280-byte packet holds at most 4 full-size records;
/// small records (~60 bytes minimum) cap the count well below this bound.
pub const records_max = 20;
pub const request_id_length_max = 8;

pub const Type = enum(u8) {
    ping = 0x01,
    pong = 0x02,
    findnode = 0x03,
    nodes = 0x04,
    talkreq = 0x05,
    talkresp = 0x06,
};

pub const Error = error{ Malformed, UnsupportedType, TooManyItems, TooLarge };

pub const RequestId = struct {
    bytes: [request_id_length_max]u8 = @splat(0),
    length: u8 = 0,

    pub fn from_slice(value: []const u8) Error!RequestId {
        if (value.len > request_id_length_max) return error.Malformed;
        var id: RequestId = .{ .length = @intCast(value.len) };
        @memcpy(id.bytes[0..value.len], value);
        return id;
    }

    pub fn from_int(value: u64) RequestId {
        var id: RequestId = .{};
        std.mem.writeInt(u64, &id.bytes, value, .big);
        id.length = request_id_length_max;
        return id;
    }

    pub fn slice(id: *const RequestId) []const u8 {
        assert(id.length <= request_id_length_max);
        return id.bytes[0..id.length];
    }

    pub fn eql(a: *const RequestId, b: *const RequestId) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }
};

pub const Ping = struct { request_id: RequestId, enr_seq: u64 };
pub const Pong = struct { request_id: RequestId, enr_seq: u64, address: ip.Address, port: u16 };
pub const Findnode = struct {
    request_id: RequestId,
    distances: [distances_max]u16 = undefined,
    distances_count: u8 = 0,

    pub fn distances_slice(findnode: *const Findnode) []const u16 {
        return findnode.distances[0..findnode.distances_count];
    }
};
pub const Nodes = struct {
    request_id: RequestId,
    total: u64,
    records: [records_max][]const u8 = undefined,
    records_count: u8 = 0,

    pub fn records_slice(nodes: *const Nodes) []const []const u8 {
        return nodes.records[0..nodes.records_count];
    }
};
pub const Talkreq = struct { request_id: RequestId, protocol: []const u8, request: []const u8 };
pub const Talkresp = struct { request_id: RequestId, response: []const u8 };

pub const Message = union(Type) {
    ping: Ping,
    pong: Pong,
    findnode: Findnode,
    nodes: Nodes,
    talkreq: Talkreq,
    talkresp: Talkresp,

    pub fn request_id(message: *const Message) RequestId {
        return switch (message.*) {
            inline else => |value| value.request_id,
        };
    }
};

pub fn decode(plaintext: []const u8) Error!Message {
    if (plaintext.len < 2) return error.Malformed;
    const tag = std.enums.fromInt(Type, plaintext[0]) orelse return error.UnsupportedType;
    var outer = rlp.Decoder.init(plaintext[1..]);
    var items = outer.list() catch return error.Malformed;
    outer.finish() catch return error.Malformed;
    const id = try RequestId.from_slice(items.bytes() catch return error.Malformed);
    const message: Message = switch (tag) {
        .ping => .{ .ping = .{ .request_id = id, .enr_seq = try int(&items, u64) } },
        .pong => .{ .pong = try decode_pong(id, &items) },
        .findnode => .{ .findnode = try decode_findnode(id, &items) },
        .nodes => .{ .nodes = try decode_nodes(id, &items) },
        .talkreq => .{ .talkreq = .{
            .request_id = id,
            .protocol = try bytes(&items),
            .request = try bytes(&items),
        } },
        .talkresp => .{ .talkresp = .{ .request_id = id, .response = try bytes(&items) } },
    };
    // Trailing list elements are tolerated for forward compatibility (as in geth).
    assert(@backingInt(message) == plaintext[0]);
    return message;
}

fn int(items: *rlp.Decoder, comptime T: type) Error!T {
    return items.int(T) catch error.Malformed;
}

fn bytes(items: *rlp.Decoder) Error![]const u8 {
    return items.bytes() catch error.Malformed;
}

fn decode_pong(id: RequestId, items: *rlp.Decoder) Error!Pong {
    const enr_seq = try int(items, u64);
    const address_bytes = try bytes(items);
    const address: ip.Address = switch (address_bytes.len) {
        4 => .{ .ip4 = address_bytes[0..4].* },
        16 => .{ .ip6 = address_bytes[0..16].* },
        else => return error.Malformed,
    };
    const port = try int(items, u16);
    return .{ .request_id = id, .enr_seq = enr_seq, .address = address, .port = port };
}

fn decode_findnode(id: RequestId, items: *rlp.Decoder) Error!Findnode {
    var findnode: Findnode = .{ .request_id = id };
    var list = items.list() catch return error.Malformed;
    while (!list.is_empty()) {
        if (findnode.distances_count == distances_max) return error.TooManyItems;
        const distance = try int(&list, u16);
        if (distance > 256) return error.Malformed;
        findnode.distances[findnode.distances_count] = distance;
        findnode.distances_count += 1;
    }
    assert(findnode.distances_count <= distances_max);
    return findnode;
}

fn decode_nodes(id: RequestId, items: *rlp.Decoder) Error!Nodes {
    var nodes: Nodes = .{ .request_id = id, .total = try int(items, u64) };
    var list = items.list() catch return error.Malformed;
    while (!list.is_empty()) {
        if (nodes.records_count == records_max) return error.TooManyItems;
        const record = list.raw() catch return error.Malformed;
        if (record.len > enr.size_max) return error.Malformed;
        nodes.records[nodes.records_count] = record;
        nodes.records_count += 1;
    }
    assert(nodes.records_count <= records_max);
    return nodes;
}

/// Payload length of the message's RLP list (excluding the list header).
fn payload_length(message: *const Message) usize {
    const id_length = rlp.bytes_length(message.request_id().slice());
    return id_length + switch (message.*) {
        .ping => |value| rlp.int_length(value.enr_seq),
        .pong => |value| rlp.int_length(value.enr_seq) + rlp.int_length(value.port) +
            @as(usize, switch (value.address) {
                .ip4 => 5,
                .ip6 => 17,
            }),
        .findnode => |value| rlp.list_length(distances_length(value.distances_slice())),
        .nodes => |value| rlp.int_length(value.total) +
            rlp.list_length(records_length(value.records_slice())),
        .talkreq => |value| rlp.bytes_length(value.protocol) + rlp.bytes_length(value.request),
        .talkresp => |value| rlp.bytes_length(value.response),
    };
}

fn distances_length(distances: []const u16) usize {
    var total: usize = 0;
    for (distances) |distance| total += rlp.int_length(distance);
    return total;
}

fn records_length(records: []const []const u8) usize {
    var total: usize = 0;
    for (records) |record| total += record.len;
    return total;
}

/// Encodes `message-type || rlp(message-data)` into `output`.
pub fn encode(output: []u8, message: *const Message) Error![]const u8 {
    const payload = payload_length(message);
    const total = 1 + rlp.list_length(payload);
    if (total > output.len) return error.TooLarge;
    output[0] = @backingInt(message.*);
    var encoder = rlp.Encoder.init(output[1..total]);
    encoder.list_header(payload);
    encoder.bytes(message.request_id().slice());
    switch (message.*) {
        .ping => |value| encoder.int(value.enr_seq),
        .pong => |value| {
            encoder.int(value.enr_seq);
            switch (value.address) {
                .ip4 => |address| encoder.bytes(&address),
                .ip6 => |address| encoder.bytes(&address),
            }
            encoder.int(value.port);
        },
        .findnode => |value| {
            encoder.list_header(distances_length(value.distances_slice()));
            for (value.distances_slice()) |distance| encoder.int(distance);
        },
        .nodes => |value| {
            encoder.int(value.total);
            encoder.list_header(records_length(value.records_slice()));
            for (value.records_slice()) |record| encoder.raw(record);
        },
        .talkreq => |value| {
            encoder.bytes(value.protocol);
            encoder.bytes(value.request);
        },
        .talkresp => |value| encoder.bytes(value.response),
    }
    assert(encoder.remaining() == 0);
    return output[0..total];
}

/// Largest plaintext that fits one ordinary message packet.
pub const plaintext_length_max = packet.size_max - packet.masking_iv_length -
    packet.static_header_length - packet.message_authdata_length - packet.tag_length;

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "disc messages: ping vector plaintext" {
    // PING from the wire vectors: req-id 0x00000001, enr-seq 2.
    const expected = [_]u8{ 0x01, 0xc6, 0x84, 0x00, 0x00, 0x00, 0x01, 0x02 };
    const message: Message = .{ .ping = .{
        .request_id = try RequestId.from_slice(&.{ 0, 0, 0, 1 }),
        .enr_seq = 2,
    } };
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &expected, try encode(&buffer, &message));
    const decoded = try decode(&expected);
    try std.testing.expectEqual(@as(u64, 2), decoded.ping.enr_seq);
}

test "disc messages: round trip every type" {
    const id = RequestId.from_int(0x0102);
    var findnode: Findnode = .{ .request_id = id };
    for ([_]u16{ 256, 255, 0 }) |distance| {
        findnode.distances[findnode.distances_count] = distance;
        findnode.distances_count += 1;
    }
    var nodes: Nodes = .{ .request_id = id, .total = 2 };
    nodes.records[0] = &.{ 0xc2, 0x01, 0x02 };
    nodes.records_count = 1;
    const cases = [_]Message{
        .{ .ping = .{ .request_id = id, .enr_seq = 0 } },
        .{ .pong = .{
            .request_id = id,
            .enr_seq = 9,
            .address = .{ .ip4 = .{ 1, 2, 3, 4 } },
            .port = 9000,
        } },
        .{ .pong = .{
            .request_id = id,
            .enr_seq = 9,
            .address = .{ .ip6 = @splat(7) },
            .port = 1,
        } },
        .{ .findnode = findnode },
        .{ .nodes = nodes },
        .{ .talkreq = .{ .request_id = id, .protocol = "eth2", .request = "hello" } },
        .{ .talkresp = .{ .request_id = id, .response = "" } },
    };
    var buffer: [plaintext_length_max]u8 = undefined;
    var again: [plaintext_length_max]u8 = undefined;
    for (cases) |case| {
        const encoded = try encode(&buffer, &case);
        const decoded = try decode(encoded);
        try std.testing.expectEqualSlices(u8, encoded, try encode(&again, &decoded));
    }
}

test "disc messages: rejects malformed" {
    try std.testing.expectError(error.Malformed, decode(&.{0x01}));
    try std.testing.expectError(error.UnsupportedType, decode(&.{ 0x07, 0xc0 }));
    try std.testing.expectError(error.Malformed, decode(&.{ 0x01, 0xc0 }));
    // Request id longer than 8 bytes.
    const long_id = [_]u8{ 0x01, 0xcb, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x01 };
    try std.testing.expectError(error.Malformed, decode(&long_id));
    // Distance above 256.
    const far = [_]u8{ 0x03, 0xc5, 0x80, 0xc3, 0x82, 0x01, 0x01 };
    try std.testing.expectError(error.Malformed, decode(&far));
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    const message = decode(input) catch return;
    var buffer: [packet.size_max * 2]u8 = undefined;
    const encoded = try encode(&buffer, &message);
    const again = try decode(encoded);
    var buffer_again: [packet.size_max * 2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, encoded, try encode(&buffer_again, &again));
}

test "disc messages: fuzz decode" {
    const corpus: []const []const u8 = &.{&.{ 0x01, 0xc6, 0x84, 0x00, 0x00, 0x00, 0x01, 0x02 }};
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 512, .corpus = corpus });
}

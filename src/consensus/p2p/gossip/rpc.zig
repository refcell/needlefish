//! Hand-written protobuf codec for the gossipsub v1.1 RPC (libp2p pubsub `rpc.proto`):
//!
//!   RPC            { repeated SubOpts subscriptions = 1; repeated Message publish = 2;
//!                    optional ControlMessage control = 3; }
//!   SubOpts        { optional bool subscribe = 1; optional string topicid = 2; }
//!   Message        { from = 1; data = 2; seqno = 3; topic = 4; signature = 5; key = 6; }
//!   ControlMessage { ihave = 1; iwant = 2; graft = 3; prune = 4; idontwant = 5; }
//!   ControlIHave   { optional string topicID = 1; repeated bytes messageIDs = 2; }
//!   ControlIWant   { repeated bytes messageIDs = 1; }
//!   ControlGraft   { optional string topicID = 1; }
//!   ControlPrune   { optional string topicID = 1; repeated PeerInfo peers = 2;
//!                    optional uint64 backoff = 3; }
//!   PeerInfo       { optional bytes peerID = 1; optional bytes signedPeerRecord = 2; }
//!   ControlIDontWant { repeated bytes messageIDs = 1; }
//!
//! Decoding is zero-copy: every byte field is a slice into the input. Repeated fields
//! land in fixed-capacity arrays sized by a comptime `Limits`; exceeding one is an
//! error, so a decoded RPC never allocates. Message ids and prune peers share one pool
//! each, addressed by `Range`. Unknown fields (wire types 0, 1, 2, 5) are skipped;
//! groups (3, 4), malformed varints, and truncated lengths are rejected. Repeated
//! `control` fields merge (protobuf semantics); duplicate scalar fields keep the last.
//! Topic is `required` in the proto but stays optional here so absent topics round
//! trip; topic validation belongs to the gossip layer.
//!
//! On a libp2p stream each RPC is prefixed by its uvarint length (`frame_*`).

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The input ended inside a key, varint, fixed value, or length-delimited field.
    Truncated,
    /// A varint is longer than 10 bytes or does not fit in a `u64`.
    VarintOverflow,
    /// A field number is zero or above the protobuf maximum.
    InvalidFieldNumber,
    /// Wire types 3 and 4 (deprecated groups).
    GroupWireType,
    /// Wire types 6 and 7.
    InvalidWireType,
    /// A known field arrived with the wrong wire type.
    WrongWireType,
    TooManySubscriptions,
    TooManyPublish,
    TooManyIHave,
    TooManyIWant,
    TooManyGraft,
    TooManyPrune,
    TooManyIDontWant,
    TooManyMessageIds,
    TooManyPeers,
};

pub const VarintError = error{ Truncated, VarintOverflow };

pub const FrameError = error{
    /// The length prefix is longer than 10 bytes or does not fit in a `u64`.
    VarintOverflow,
    /// The length prefix exceeds the caller's maximum frame size.
    FrameTooLarge,
};

/// Default maximum RPC frame: OP Stack gossip `max_transmit_size` (10 MiB).
pub const frame_size_max_default: u32 = 10 * (1 << 20);

/// Longest encoding of a `u64` varint.
pub const varint_length_max = 10;

const field_number_max: u64 = (1 << 29) - 1;

/// Per-RPC decode capacities. Totals across the whole RPC, including merged controls.
pub const Limits = struct {
    subscriptions_max: u32 = 128,
    publish_max: u32 = 64,
    ihave_max: u32 = 64,
    iwant_max: u32 = 64,
    graft_max: u32 = 64,
    prune_max: u32 = 64,
    idontwant_max: u32 = 64,
    /// Total message ids across all IHAVE, IWANT, and IDONTWANT entries.
    message_ids_max: u32 = 5000,
    /// Total peer-exchange records across all PRUNE entries.
    peers_max: u32 = 64,
};

pub const SubOpts = struct {
    subscribe: ?bool = null,
    topic_id: ?[]const u8 = null,
};

pub const Message = struct {
    from: ?[]const u8 = null,
    data: ?[]const u8 = null,
    seqno: ?[]const u8 = null,
    topic: ?[]const u8 = null,
    signature: ?[]const u8 = null,
    key: ?[]const u8 = null,
};

pub const PeerInfo = struct {
    peer_id: ?[]const u8 = null,
    signed_peer_record: ?[]const u8 = null,
};

/// A contiguous run in a shared pool (`message_ids` or `peers`).
pub const Range = struct {
    start: u32 = 0,
    count: u32 = 0,
};

pub const IHave = struct { topic_id: ?[]const u8 = null, message_ids: Range = .{} };
pub const IWant = struct { message_ids: Range = .{} };
pub const Graft = struct { topic_id: ?[]const u8 = null };
pub const Prune = struct { topic_id: ?[]const u8 = null, peers: Range = .{}, backoff: ?u64 = null };
pub const IDontWant = struct { message_ids: Range = .{} };

const WireType = enum(u3) { varint = 0, fixed64 = 1, length = 2, fixed32 = 5 };

/// One decoded field. Unknown fields are skipped by simply ignoring them.
const Field = struct {
    number: u32,
    wire: WireType,
    varint: u64 = 0,
    bytes: []const u8 = &.{},

    fn expect_bytes(field: Field) Error![]const u8 {
        assert(field.number > 0);
        if (field.wire != .length) return error.WrongWireType;
        return field.bytes;
    }

    fn expect_varint(field: Field) Error!u64 {
        assert(field.number > 0);
        if (field.wire != .varint) return error.WrongWireType;
        return field.varint;
    }
};

/// Decodes one protobuf varint (non-minimal encodings accepted, as protobuf does).
pub fn decode_varint(input: []const u8, length: *usize) VarintError!u64 {
    var value: u64 = 0;
    var index: usize = 0;
    while (index < varint_length_max) : (index += 1) {
        if (index >= input.len) return error.Truncated;
        const byte = input[index];
        if (index == varint_length_max - 1 and byte > 1) return error.VarintOverflow;
        value |= @as(u64, byte & 0x7f) << @intCast(7 * index);
        if (byte & 0x80 == 0) {
            length.* = index + 1;
            assert(length.* <= varint_length_max);
            return value;
        }
    }
    assert(index == varint_length_max);
    return error.VarintOverflow;
}

pub fn varint_length(value: u64) u32 {
    var remaining = value;
    var length: u32 = 1;
    while (remaining >= 0x80) : (length += 1) remaining >>= 7;
    assert(length >= 1);
    assert(length <= varint_length_max);
    return length;
}

/// Sequential field reader over one message body.
const Reader = struct {
    input: []const u8,
    position: usize = 0,

    fn next(reader: *Reader) Error!?Field {
        assert(reader.position <= reader.input.len);
        if (reader.position == reader.input.len) return null;
        const key = try reader.read_varint();
        const number = key >> 3;
        if (number == 0 or number > field_number_max) return error.InvalidFieldNumber;
        var field: Field = .{ .number = @intCast(number), .wire = .varint };
        switch (@as(u3, @truncate(key))) {
            0 => field.varint = try reader.read_varint(),
            1 => {
                field.wire = .fixed64;
                _ = try reader.read_fixed(8);
            },
            2 => {
                field.wire = .length;
                const length = try reader.read_varint();
                if (length > reader.input.len - reader.position) return error.Truncated;
                field.bytes = try reader.read_fixed(@intCast(length));
            },
            3, 4 => return error.GroupWireType,
            5 => {
                field.wire = .fixed32;
                _ = try reader.read_fixed(4);
            },
            6, 7 => return error.InvalidWireType,
        }
        assert(reader.position <= reader.input.len);
        return field;
    }

    fn read_varint(reader: *Reader) Error!u64 {
        var length: usize = 0;
        const value = try decode_varint(reader.input[reader.position..], &length);
        assert(length > 0);
        reader.position += length;
        assert(reader.position <= reader.input.len);
        return value;
    }

    fn read_fixed(reader: *Reader, length: usize) Error![]const u8 {
        assert(reader.position <= reader.input.len);
        if (reader.input.len - reader.position < length) return error.Truncated;
        const bytes = reader.input[reader.position..][0..length];
        reader.position += length;
        return bytes;
    }
};

/// Sequential writer into a caller buffer sized by `encoded_length`.
const Writer = struct {
    output: []u8,
    position: usize = 0,

    fn varint(writer: *Writer, value: u64) void {
        assert(writer.output.len - writer.position >= varint_length(value));
        var remaining = value;
        while (remaining >= 0x80) : (remaining >>= 7) {
            writer.output[writer.position] = @as(u8, @truncate(remaining)) | 0x80;
            writer.position += 1;
        }
        writer.output[writer.position] = @intCast(remaining);
        writer.position += 1;
    }

    fn key(writer: *Writer, number: u32, wire: WireType) void {
        assert(number > 0 and number <= field_number_max);
        writer.varint((@as(u64, number) << 3) | @backingInt(wire));
    }

    fn header(writer: *Writer, number: u32, length: u64) void {
        writer.key(number, .length);
        writer.varint(length);
        assert(writer.output.len - writer.position >= length);
    }

    fn bytes(writer: *Writer, number: u32, value: ?[]const u8) void {
        const slice = value orelse return;
        writer.header(number, slice.len);
        @memcpy(writer.output[writer.position..][0..slice.len], slice);
        writer.position += slice.len;
    }

    fn uint(writer: *Writer, number: u32, value: u64) void {
        writer.key(number, .varint);
        writer.varint(value);
    }
};

fn key_length(number: u32) u64 {
    assert(number > 0);
    return varint_length(@as(u64, number) << 3);
}

/// Bytes a length-delimited field with `length` payload bytes occupies.
fn length_field_length(number: u32, length: u64) u64 {
    const total = key_length(number) + varint_length(length) + length;
    assert(total > length);
    return total;
}

fn bytes_field_length(number: u32, value: ?[]const u8) u64 {
    const slice = value orelse return 0;
    return length_field_length(number, slice.len);
}

fn uint_field_length(number: u32, value: ?u64) u64 {
    const integer = value orelse return 0;
    return key_length(number) + varint_length(integer);
}

fn optional_eql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

pub fn message_length(message: Message) u64 {
    const length = bytes_field_length(1, message.from) + bytes_field_length(2, message.data) +
        bytes_field_length(3, message.seqno) + bytes_field_length(4, message.topic) +
        bytes_field_length(5, message.signature) + bytes_field_length(6, message.key);
    assert(length <= std.math.maxInt(u64) / 2);
    return length;
}

pub fn message_eql(a: Message, b: Message) bool {
    return optional_eql(a.from, b.from) and optional_eql(a.data, b.data) and
        optional_eql(a.seqno, b.seqno) and optional_eql(a.topic, b.topic) and
        optional_eql(a.signature, b.signature) and optional_eql(a.key, b.key);
}

fn decode_message(body: []const u8) Error!Message {
    var reader: Reader = .{ .input = body };
    var message: Message = .{};
    var fields: usize = 0;
    while (try reader.next()) |field| : (fields += 1) {
        assert(fields < body.len);
        switch (field.number) {
            1 => message.from = try field.expect_bytes(),
            2 => message.data = try field.expect_bytes(),
            3 => message.seqno = try field.expect_bytes(),
            4 => message.topic = try field.expect_bytes(),
            5 => message.signature = try field.expect_bytes(),
            6 => message.key = try field.expect_bytes(),
            else => {},
        }
    }
    assert(reader.position == body.len);
    return message;
}

fn decode_sub_opts(body: []const u8) Error!SubOpts {
    var reader: Reader = .{ .input = body };
    var sub_opts: SubOpts = .{};
    var fields: usize = 0;
    while (try reader.next()) |field| : (fields += 1) {
        assert(fields < body.len);
        switch (field.number) {
            1 => sub_opts.subscribe = try field.expect_varint() != 0,
            2 => sub_opts.topic_id = try field.expect_bytes(),
            else => {},
        }
    }
    assert(reader.position == body.len);
    return sub_opts;
}

fn decode_peer_info(body: []const u8) Error!PeerInfo {
    var reader: Reader = .{ .input = body };
    var peer: PeerInfo = .{};
    var fields: usize = 0;
    while (try reader.next()) |field| : (fields += 1) {
        assert(fields < body.len);
        switch (field.number) {
            1 => peer.peer_id = try field.expect_bytes(),
            2 => peer.signed_peer_record = try field.expect_bytes(),
            else => {},
        }
    }
    assert(reader.position == body.len);
    return peer;
}

fn sub_opts_length(sub_opts: SubOpts) u64 {
    const subscribe: ?u64 = if (sub_opts.subscribe) |flag| @intFromBool(flag) else null;
    return uint_field_length(1, subscribe) + bytes_field_length(2, sub_opts.topic_id);
}

fn peer_info_length(peer: PeerInfo) u64 {
    return bytes_field_length(1, peer.peer_id) + bytes_field_length(2, peer.signed_peer_record);
}

/// A gossipsub RPC with fixed capacities from `limits`. Large (about 100 KiB with the
/// defaults): keep one per connection or decoder, not on deep stacks.
pub fn Rpc(comptime limits: Limits) type {
    comptime {
        assert(limits.message_ids_max > 0);
        assert(limits.peers_max > 0);
    }
    return struct {
        const Self = @This();

        subscriptions: [limits.subscriptions_max]SubOpts = undefined,
        subscriptions_count: u32 = 0,
        publish: [limits.publish_max]Message = undefined,
        publish_count: u32 = 0,
        ihave: [limits.ihave_max]IHave = undefined,
        ihave_count: u32 = 0,
        iwant: [limits.iwant_max]IWant = undefined,
        iwant_count: u32 = 0,
        graft: [limits.graft_max]Graft = undefined,
        graft_count: u32 = 0,
        prune: [limits.prune_max]Prune = undefined,
        prune_count: u32 = 0,
        idontwant: [limits.idontwant_max]IDontWant = undefined,
        idontwant_count: u32 = 0,
        message_ids: [limits.message_ids_max][]const u8 = undefined,
        message_ids_count: u32 = 0,
        peers: [limits.peers_max]PeerInfo = undefined,
        peers_count: u32 = 0,
        /// Set when a `control` field is present (it may be empty). Encoding emits
        /// `control` when this is set or any control entry exists.
        has_control: bool = false,

        pub fn reset(rpc: *Self) void {
            rpc.subscriptions_count = 0;
            rpc.publish_count = 0;
            rpc.ihave_count = 0;
            rpc.iwant_count = 0;
            rpc.graft_count = 0;
            rpc.prune_count = 0;
            rpc.idontwant_count = 0;
            rpc.message_ids_count = 0;
            rpc.peers_count = 0;
            rpc.has_control = false;
            assert(rpc.control_entries() == 0);
            assert(!rpc.control_present());
        }

        pub fn subscriptions_slice(rpc: *const Self) []const SubOpts {
            return rpc.subscriptions[0..rpc.subscriptions_count];
        }

        pub fn publish_slice(rpc: *const Self) []const Message {
            return rpc.publish[0..rpc.publish_count];
        }

        pub fn ihave_slice(rpc: *const Self) []const IHave {
            return rpc.ihave[0..rpc.ihave_count];
        }

        pub fn iwant_slice(rpc: *const Self) []const IWant {
            return rpc.iwant[0..rpc.iwant_count];
        }

        pub fn graft_slice(rpc: *const Self) []const Graft {
            return rpc.graft[0..rpc.graft_count];
        }

        pub fn prune_slice(rpc: *const Self) []const Prune {
            return rpc.prune[0..rpc.prune_count];
        }

        pub fn idontwant_slice(rpc: *const Self) []const IDontWant {
            return rpc.idontwant[0..rpc.idontwant_count];
        }

        /// Message ids addressed by `range` (from an IHAVE, IWANT, or IDONTWANT).
        pub fn ids(rpc: *const Self, range: Range) []const []const u8 {
            assert(range.start + range.count <= rpc.message_ids_count);
            return rpc.message_ids[range.start..][0..range.count];
        }

        /// Peers addressed by `range` (from a PRUNE).
        pub fn peer_infos(rpc: *const Self, range: Range) []const PeerInfo {
            assert(range.start + range.count <= rpc.peers_count);
            return rpc.peers[range.start..][0..range.count];
        }

        fn control_entries(rpc: *const Self) u32 {
            return rpc.ihave_count + rpc.iwant_count + rpc.graft_count + rpc.prune_count +
                rpc.idontwant_count;
        }

        fn control_present(rpc: *const Self) bool {
            return rpc.has_control or rpc.control_entries() > 0;
        }

        // Builders. Each copies slices by reference: the RPC borrows caller memory.

        pub fn add_subscription(rpc: *Self, sub_opts: SubOpts) Error!void {
            if (rpc.subscriptions_count == limits.subscriptions_max) {
                return error.TooManySubscriptions;
            }
            rpc.subscriptions[rpc.subscriptions_count] = sub_opts;
            rpc.subscriptions_count += 1;
            assert(rpc.subscriptions_count <= limits.subscriptions_max);
        }

        pub fn add_publish(rpc: *Self, message: Message) Error!void {
            if (rpc.publish_count == limits.publish_max) return error.TooManyPublish;
            rpc.publish[rpc.publish_count] = message;
            rpc.publish_count += 1;
            assert(rpc.publish_count <= limits.publish_max);
        }

        fn push_ids(rpc: *Self, message_ids: []const []const u8) Error!Range {
            const free = limits.message_ids_max - rpc.message_ids_count;
            if (message_ids.len > free) return error.TooManyMessageIds;
            const range: Range = .{
                .start = rpc.message_ids_count,
                .count = @intCast(message_ids.len),
            };
            @memcpy(rpc.message_ids[range.start..][0..range.count], message_ids);
            rpc.message_ids_count += range.count;
            assert(rpc.message_ids_count <= limits.message_ids_max);
            return range;
        }

        fn push_id(rpc: *Self, message_id: []const u8) Error!void {
            if (rpc.message_ids_count == limits.message_ids_max) return error.TooManyMessageIds;
            rpc.message_ids[rpc.message_ids_count] = message_id;
            rpc.message_ids_count += 1;
            assert(rpc.message_ids_count <= limits.message_ids_max);
        }

        pub fn add_ihave(
            rpc: *Self,
            topic_id: ?[]const u8,
            message_ids: []const []const u8,
        ) Error!void {
            if (rpc.ihave_count == limits.ihave_max) return error.TooManyIHave;
            const range = try rpc.push_ids(message_ids);
            rpc.ihave[rpc.ihave_count] = .{ .topic_id = topic_id, .message_ids = range };
            rpc.ihave_count += 1;
            assert(rpc.control_present());
        }

        pub fn add_iwant(rpc: *Self, message_ids: []const []const u8) Error!void {
            if (rpc.iwant_count == limits.iwant_max) return error.TooManyIWant;
            const range = try rpc.push_ids(message_ids);
            rpc.iwant[rpc.iwant_count] = .{ .message_ids = range };
            rpc.iwant_count += 1;
            assert(rpc.control_present());
        }

        pub fn add_graft(rpc: *Self, topic_id: ?[]const u8) Error!void {
            if (rpc.graft_count == limits.graft_max) return error.TooManyGraft;
            rpc.graft[rpc.graft_count] = .{ .topic_id = topic_id };
            rpc.graft_count += 1;
            assert(rpc.control_present());
        }

        pub fn add_prune(
            rpc: *Self,
            topic_id: ?[]const u8,
            peers: []const PeerInfo,
            backoff: ?u64,
        ) Error!void {
            if (rpc.prune_count == limits.prune_max) return error.TooManyPrune;
            if (peers.len > limits.peers_max - rpc.peers_count) return error.TooManyPeers;
            const range: Range = .{ .start = rpc.peers_count, .count = @intCast(peers.len) };
            @memcpy(rpc.peers[range.start..][0..range.count], peers);
            rpc.peers_count += range.count;
            rpc.prune[rpc.prune_count] = .{
                .topic_id = topic_id,
                .peers = range,
                .backoff = backoff,
            };
            rpc.prune_count += 1;
            assert(rpc.peers_count <= limits.peers_max);
        }

        pub fn add_idontwant(rpc: *Self, message_ids: []const []const u8) Error!void {
            if (rpc.idontwant_count == limits.idontwant_max) return error.TooManyIDontWant;
            const range = try rpc.push_ids(message_ids);
            rpc.idontwant[rpc.idontwant_count] = .{ .message_ids = range };
            rpc.idontwant_count += 1;
            assert(rpc.control_present());
        }

        // Decoding.

        /// Decodes `input` into `rpc`, replacing its contents. Slices borrow `input`.
        /// On error `rpc` holds a partial decode and must be reset or re-decoded.
        pub fn decode(rpc: *Self, input: []const u8) Error!void {
            rpc.reset();
            var reader: Reader = .{ .input = input };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < input.len);
                switch (field.number) {
                    1 => try rpc.add_subscription(try decode_sub_opts(try field.expect_bytes())),
                    2 => try rpc.add_publish(try decode_message(try field.expect_bytes())),
                    3 => try rpc.decode_control(try field.expect_bytes()),
                    else => {},
                }
            }
            assert(reader.position == input.len);
        }

        fn decode_control(rpc: *Self, body: []const u8) Error!void {
            rpc.has_control = true;
            var reader: Reader = .{ .input = body };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < body.len);
                switch (field.number) {
                    1 => try rpc.decode_ihave(try field.expect_bytes()),
                    2 => try rpc.decode_id_list(try field.expect_bytes(), .iwant),
                    3 => try rpc.decode_graft(try field.expect_bytes()),
                    4 => try rpc.decode_prune(try field.expect_bytes()),
                    5 => try rpc.decode_id_list(try field.expect_bytes(), .idontwant),
                    else => {},
                }
            }
            assert(reader.position == body.len);
        }

        fn decode_ihave(rpc: *Self, body: []const u8) Error!void {
            if (rpc.ihave_count == limits.ihave_max) return error.TooManyIHave;
            var entry: IHave = .{ .message_ids = .{ .start = rpc.message_ids_count } };
            var reader: Reader = .{ .input = body };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < body.len);
                switch (field.number) {
                    1 => entry.topic_id = try field.expect_bytes(),
                    2 => try rpc.push_id(try field.expect_bytes()),
                    else => {},
                }
            }
            entry.message_ids.count = rpc.message_ids_count - entry.message_ids.start;
            rpc.ihave[rpc.ihave_count] = entry;
            rpc.ihave_count += 1;
            assert(rpc.ihave_count <= limits.ihave_max);
        }

        /// IWANT and IDONTWANT share a shape: `repeated bytes messageIDs = 1`.
        fn decode_id_list(rpc: *Self, body: []const u8, comptime kind: IdList) Error!void {
            switch (kind) {
                .iwant => if (rpc.iwant_count == limits.iwant_max) return error.TooManyIWant,
                .idontwant => if (rpc.idontwant_count == limits.idontwant_max) {
                    return error.TooManyIDontWant;
                },
            }
            var range: Range = .{ .start = rpc.message_ids_count };
            var reader: Reader = .{ .input = body };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < body.len);
                if (field.number == 1) try rpc.push_id(try field.expect_bytes());
            }
            range.count = rpc.message_ids_count - range.start;
            switch (kind) {
                .iwant => {
                    rpc.iwant[rpc.iwant_count] = .{ .message_ids = range };
                    rpc.iwant_count += 1;
                },
                .idontwant => {
                    rpc.idontwant[rpc.idontwant_count] = .{ .message_ids = range };
                    rpc.idontwant_count += 1;
                },
            }
            assert(reader.position == body.len);
        }

        fn decode_graft(rpc: *Self, body: []const u8) Error!void {
            if (rpc.graft_count == limits.graft_max) return error.TooManyGraft;
            var entry: Graft = .{};
            var reader: Reader = .{ .input = body };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < body.len);
                if (field.number == 1) entry.topic_id = try field.expect_bytes();
            }
            rpc.graft[rpc.graft_count] = entry;
            rpc.graft_count += 1;
            assert(rpc.graft_count <= limits.graft_max);
        }

        fn decode_prune(rpc: *Self, body: []const u8) Error!void {
            if (rpc.prune_count == limits.prune_max) return error.TooManyPrune;
            var entry: Prune = .{ .peers = .{ .start = rpc.peers_count } };
            var reader: Reader = .{ .input = body };
            var fields: usize = 0;
            while (try reader.next()) |field| : (fields += 1) {
                assert(fields < body.len);
                switch (field.number) {
                    1 => entry.topic_id = try field.expect_bytes(),
                    2 => {
                        const peer = try decode_peer_info(try field.expect_bytes());
                        if (rpc.peers_count == limits.peers_max) return error.TooManyPeers;
                        rpc.peers[rpc.peers_count] = peer;
                        rpc.peers_count += 1;
                    },
                    3 => entry.backoff = try field.expect_varint(),
                    else => {},
                }
            }
            entry.peers.count = rpc.peers_count - entry.peers.start;
            rpc.prune[rpc.prune_count] = entry;
            rpc.prune_count += 1;
            assert(rpc.prune_count <= limits.prune_max);
        }

        const IdList = enum { iwant, idontwant };

        // Encoding.

        fn ids_length(rpc: *const Self, number: u32, range: Range) u64 {
            var length: u64 = 0;
            for (rpc.ids(range)) |message_id| length += length_field_length(number, message_id.len);
            return length;
        }

        fn ihave_length(rpc: *const Self, entry: IHave) u64 {
            return bytes_field_length(1, entry.topic_id) + rpc.ids_length(2, entry.message_ids);
        }

        fn prune_length(rpc: *const Self, entry: Prune) u64 {
            var length = bytes_field_length(1, entry.topic_id) +
                uint_field_length(3, entry.backoff);
            for (rpc.peer_infos(entry.peers)) |peer| {
                length += length_field_length(2, peer_info_length(peer));
            }
            return length;
        }

        fn control_length(rpc: *const Self) u64 {
            var length: u64 = 0;
            for (rpc.ihave_slice()) |entry| {
                length += length_field_length(1, rpc.ihave_length(entry));
            }
            for (rpc.iwant_slice()) |entry| {
                length += length_field_length(2, rpc.ids_length(1, entry.message_ids));
            }
            for (rpc.graft_slice()) |entry| {
                length += length_field_length(3, bytes_field_length(1, entry.topic_id));
            }
            for (rpc.prune_slice()) |entry| {
                length += length_field_length(4, rpc.prune_length(entry));
            }
            for (rpc.idontwant_slice()) |entry| {
                length += length_field_length(5, rpc.ids_length(1, entry.message_ids));
            }
            return length;
        }

        /// Exact number of bytes `encode` writes.
        pub fn encoded_length(rpc: *const Self) u64 {
            var length: u64 = 0;
            for (rpc.subscriptions_slice()) |sub_opts| {
                length += length_field_length(1, sub_opts_length(sub_opts));
            }
            for (rpc.publish_slice()) |message| {
                length += length_field_length(2, message_length(message));
            }
            if (rpc.control_present()) length += length_field_length(3, rpc.control_length());
            return length;
        }

        /// Encodes into the front of `output` (at least `encoded_length()` bytes), in
        /// field-number order, returning the written prefix.
        pub fn encode(rpc: *const Self, output: []u8) []u8 {
            const length = rpc.encoded_length();
            assert(output.len >= length);
            var writer: Writer = .{ .output = output[0..@intCast(length)] };
            for (rpc.subscriptions_slice()) |sub_opts| {
                writer.header(1, sub_opts_length(sub_opts));
                if (sub_opts.subscribe) |flag| writer.uint(1, @intFromBool(flag));
                writer.bytes(2, sub_opts.topic_id);
            }
            for (rpc.publish_slice()) |message| {
                writer.header(2, message_length(message));
                writer.bytes(1, message.from);
                writer.bytes(2, message.data);
                writer.bytes(3, message.seqno);
                writer.bytes(4, message.topic);
                writer.bytes(5, message.signature);
                writer.bytes(6, message.key);
            }
            if (rpc.control_present()) {
                writer.header(3, rpc.control_length());
                rpc.encode_control(&writer);
            }
            assert(writer.position == length);
            return output[0..writer.position];
        }

        fn encode_ids(rpc: *const Self, writer: *Writer, number: u32, range: Range) void {
            for (rpc.ids(range)) |message_id| writer.bytes(number, message_id);
        }

        fn encode_control(rpc: *const Self, writer: *Writer) void {
            const start = writer.position;
            for (rpc.ihave_slice()) |entry| {
                writer.header(1, rpc.ihave_length(entry));
                writer.bytes(1, entry.topic_id);
                rpc.encode_ids(writer, 2, entry.message_ids);
            }
            for (rpc.iwant_slice()) |entry| {
                writer.header(2, rpc.ids_length(1, entry.message_ids));
                rpc.encode_ids(writer, 1, entry.message_ids);
            }
            for (rpc.graft_slice()) |entry| {
                writer.header(3, bytes_field_length(1, entry.topic_id));
                writer.bytes(1, entry.topic_id);
            }
            for (rpc.prune_slice()) |entry| {
                writer.header(4, rpc.prune_length(entry));
                writer.bytes(1, entry.topic_id);
                for (rpc.peer_infos(entry.peers)) |peer| {
                    writer.header(2, peer_info_length(peer));
                    writer.bytes(1, peer.peer_id);
                    writer.bytes(2, peer.signed_peer_record);
                }
                if (entry.backoff) |backoff| writer.uint(3, backoff);
            }
            for (rpc.idontwant_slice()) |entry| {
                writer.header(5, rpc.ids_length(1, entry.message_ids));
                rpc.encode_ids(writer, 1, entry.message_ids);
            }
            assert(writer.position - start == rpc.control_length());
        }

        /// Encodes with a uvarint length prefix (one libp2p stream frame).
        pub fn encode_framed(rpc: *const Self, output: []u8) []u8 {
            const length = rpc.encoded_length();
            const prefix = frame_header(output, length).len;
            const body = rpc.encode(output[prefix..]);
            assert(body.len == length);
            return output[0 .. prefix + body.len];
        }

        // Equality (semantic: compares contents, not pool layout).

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (a.subscriptions_count != b.subscriptions_count) return false;
            if (a.publish_count != b.publish_count) return false;
            if (a.control_present() != b.control_present()) return false;
            for (a.subscriptions_slice(), b.subscriptions_slice()) |x, y| {
                if (x.subscribe != y.subscribe) return false;
                if (!optional_eql(x.topic_id, y.topic_id)) return false;
            }
            for (a.publish_slice(), b.publish_slice()) |x, y| {
                if (!message_eql(x, y)) return false;
            }
            return control_eql(a, b);
        }

        fn ids_eql(a: *const Self, b: *const Self, x: Range, y: Range) bool {
            if (x.count != y.count) return false;
            for (a.ids(x), b.ids(y)) |p, q| if (!std.mem.eql(u8, p, q)) return false;
            return true;
        }

        fn control_eql(a: *const Self, b: *const Self) bool {
            if (a.ihave_count != b.ihave_count or a.iwant_count != b.iwant_count) return false;
            if (a.graft_count != b.graft_count or a.prune_count != b.prune_count) return false;
            if (a.idontwant_count != b.idontwant_count) return false;
            for (a.ihave_slice(), b.ihave_slice()) |x, y| {
                if (!optional_eql(x.topic_id, y.topic_id)) return false;
                if (!ids_eql(a, b, x.message_ids, y.message_ids)) return false;
            }
            for (a.iwant_slice(), b.iwant_slice()) |x, y| {
                if (!ids_eql(a, b, x.message_ids, y.message_ids)) return false;
            }
            for (a.graft_slice(), b.graft_slice()) |x, y| {
                if (!optional_eql(x.topic_id, y.topic_id)) return false;
            }
            for (a.idontwant_slice(), b.idontwant_slice()) |x, y| {
                if (!ids_eql(a, b, x.message_ids, y.message_ids)) return false;
            }
            for (a.prune_slice(), b.prune_slice()) |x, y| {
                if (!optional_eql(x.topic_id, y.topic_id) or x.backoff != y.backoff) return false;
                if (x.peers.count != y.peers.count) return false;
                for (a.peer_infos(x.peers), b.peer_infos(y.peers)) |p, q| {
                    if (!optional_eql(p.peer_id, q.peer_id)) return false;
                    if (!optional_eql(p.signed_peer_record, q.signed_peer_record)) return false;
                }
            }
            return true;
        }
    };
}

/// RPC with the default limits.
pub const RpcDefault = Rpc(.{});

// Framing: libp2p pubsub streams carry uvarint-length-delimited RPCs.

pub const Frame = struct {
    /// The RPC bytes (a slice of the input).
    payload: []const u8,
    /// Bytes consumed: prefix plus payload.
    length: usize,
};

/// Writes the uvarint length prefix for a `payload_length`-byte frame.
pub fn frame_header(output: []u8, payload_length: u64) []u8 {
    var writer: Writer = .{ .output = output };
    writer.varint(payload_length);
    assert(writer.position == varint_length(payload_length));
    return output[0..writer.position];
}

/// Splits one frame off the front of `input`. Returns null when more bytes are needed;
/// rejects prefixes above `frame_size_max` before any payload is buffered.
pub fn frame_decode(input: []const u8, frame_size_max: u32) FrameError!?Frame {
    var prefix: usize = 0;
    const payload_length = decode_varint(input, &prefix) catch |err| switch (err) {
        error.Truncated => return null,
        error.VarintOverflow => return error.VarintOverflow,
    };
    assert(prefix > 0 and prefix <= varint_length_max);
    if (payload_length > frame_size_max) return error.FrameTooLarge;
    if (input.len - prefix < payload_length) return null;
    const length = prefix + @as(usize, @intCast(payload_length));
    assert(length <= input.len);
    return .{ .payload = input[prefix..length], .length = length };
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

/// Comptime string repetition (Zig 0.17 dropped the `**` operator).
fn repeat(comptime unit: []const u8, comptime count: usize) *const [unit.len * count]u8 {
    comptime {
        var out: [unit.len * count]u8 = undefined;
        for (0..count) |index| @memcpy(out[index * unit.len ..][0..unit.len], unit);
        const final = out;
        return &final;
    }
}

/// Small limits so tests and fuzzing reach every capacity error cheaply.
const TestRpc = Rpc(.{
    .subscriptions_max = 4,
    .publish_max = 4,
    .ihave_max = 3,
    .iwant_max = 3,
    .graft_max = 3,
    .prune_max = 3,
    .idontwant_max = 3,
    .message_ids_max = 16,
    .peers_max = 4,
});

fn expect_encoding(rpc: anytype, expected: []const u8) !void {
    var buffer: [512]u8 = undefined;
    try std.testing.expectEqual(@as(u64, expected.len), rpc.encoded_length());
    try std.testing.expectEqualSlices(u8, expected, rpc.encode(&buffer));
}

const vector_full =
    "\x0a\x05\x08\x01\x12\x01t" ++ // subscriptions: {subscribe: true, topicid: "t"}
    "\x12\x07\x12\x02hi\x22\x01t" ++ // publish: {data: "hi", topic: "t"}
    "\x1a\x26" ++ // control (38 bytes)
    "\x0a\x09\x0a\x01t\x12\x01a\x12\x01b" ++ // ihave: {topicID: "t", ids: [a, b]}
    "\x12\x03\x0a\x01c" ++ // iwant: {ids: [c]}
    "\x1a\x03\x0a\x01g" ++ // graft: {topicID: "g"}
    "\x22\x0a\x0a\x01p\x12\x03\x0a\x01x\x18\x3c" ++ // prune: {"p", [{peerID: "x"}], 60}
    "\x2a\x03\x0a\x01d"; // idontwant: {ids: [d]}

test "rpc: hand-constructed vector decodes and re-encodes exactly" {
    var rpc: TestRpc = .{};
    try rpc.decode(vector_full);
    const t = std.testing;
    try t.expectEqual(@as(u32, 1), rpc.subscriptions_count);
    try t.expectEqual(@as(?bool, true), rpc.subscriptions[0].subscribe);
    try t.expectEqualStrings("t", rpc.subscriptions[0].topic_id.?);
    try t.expectEqualStrings("hi", rpc.publish[0].data.?);
    try t.expectEqual(@as(?[]const u8, null), rpc.publish[0].from);
    try t.expectEqual(@as(usize, 2), rpc.ids(rpc.ihave[0].message_ids).len);
    try t.expectEqualStrings("b", rpc.ids(rpc.ihave[0].message_ids)[1]);
    try t.expectEqualStrings("c", rpc.ids(rpc.iwant[0].message_ids)[0]);
    try t.expectEqualStrings("g", rpc.graft[0].topic_id.?);
    try t.expectEqual(@as(?u64, 60), rpc.prune[0].backoff);
    try t.expectEqualStrings("x", rpc.peer_infos(rpc.prune[0].peers)[0].peer_id.?);
    try t.expectEqualStrings("d", rpc.ids(rpc.idontwant[0].message_ids)[0]);
    try expect_encoding(&rpc, vector_full);
}

test "rpc: builder produces the hand-constructed vector" {
    var rpc: TestRpc = .{};
    try rpc.add_subscription(.{ .subscribe = true, .topic_id = "t" });
    try rpc.add_publish(.{ .data = "hi", .topic = "t" });
    try rpc.add_ihave("t", &.{ "a", "b" });
    try rpc.add_iwant(&.{"c"});
    try rpc.add_graft("g");
    try rpc.add_prune("p", &.{.{ .peer_id = "x" }}, 60);
    try rpc.add_idontwant(&.{"d"});
    try expect_encoding(&rpc, vector_full);
}

test "rpc: empty rpc and empty control" {
    var rpc: TestRpc = .{};
    try rpc.decode("");
    try expect_encoding(&rpc, "");
    try rpc.decode("\x1a\x00");
    try std.testing.expect(rpc.has_control);
    try expect_encoding(&rpc, "\x1a\x00");
    // Two control fields merge; an empty subscription and publish survive.
    try rpc.decode("\x1a\x02\x1a\x00\x0a\x00\x1a\x02\x1a\x00\x12\x00");
    try std.testing.expectEqual(@as(u32, 2), rpc.graft_count);
    try expect_encoding(&rpc, "\x0a\x00\x12\x00\x1a\x04\x1a\x00\x1a\x00");
}

test "rpc: unknown fields of every wire type are skipped at every level" {
    const unknown = "\x48\x96\x01" ++ "\x51" ++ "12345678" ++ "\x5a\x02\xaa\xbb" ++
        "\x65" ++ "abcd";
    const input = unknown ++
        "\x0a\x1a\x08\x01" ++ unknown ++ "\x12\x01t" ++
        "\x12\x1c" ++ unknown ++ "\x12\x02hi\x22\x01t" ++
        "\x1a\x34" ++ unknown ++ "\x1a\x08" ++ "\x48\x01" ++ "\x5a\x01z" ++ "\x0a\x01g" ++ unknown;
    var rpc: TestRpc = .{};
    try rpc.decode(input);
    try expect_encoding(&rpc, "\x0a\x05\x08\x01\x12\x01t\x12\x07\x12\x02hi\x22\x01t" ++
        "\x1a\x05\x1a\x03\x0a\x01g");
}

test "rpc: rejects malformed input" {
    var rpc: TestRpc = .{};
    const t = std.testing;
    try t.expectError(error.GroupWireType, rpc.decode("\x0b"));
    try t.expectError(error.GroupWireType, rpc.decode("\x0c"));
    try t.expectError(error.InvalidWireType, rpc.decode("\x0e"));
    try t.expectError(error.InvalidWireType, rpc.decode("\x0f"));
    try t.expectError(error.InvalidFieldNumber, rpc.decode("\x02\x00"));
    try t.expectError(error.InvalidFieldNumber, rpc.decode("\x80\x80\x80\x80\x10\x00"));
    try t.expectError(error.Truncated, rpc.decode("\x0a\x05\x08"));
    try t.expectError(error.Truncated, rpc.decode("\x0a"));
    try t.expectError(error.Truncated, rpc.decode("\x48\x80"));
    try t.expectError(error.Truncated, rpc.decode("\x51\x00\x00"));
    try t.expectError(error.Truncated, rpc.decode("\x65\x00"));
    const long: [11]u8 = @splat(0xff);
    try t.expectError(error.VarintOverflow, rpc.decode("\x48" ++ long));
    const too_big = "\x48\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02";
    try t.expectError(error.VarintOverflow, rpc.decode(too_big));
    try t.expectError(error.WrongWireType, rpc.decode("\x08\x01"));
    try t.expectError(error.WrongWireType, rpc.decode("\x0a\x02\x10\x01"));
    try t.expectError(error.WrongWireType, rpc.decode("\x1a\x04\x22\x02\x08\x00"));
    try t.expectError(error.WrongWireType, rpc.decode("\x1a\x04\x22\x02\x1a\x00"));
    // A nested length that overruns its parent is truncated, not read from the parent.
    try t.expectError(error.Truncated, rpc.decode("\x1a\x02\x1a\x05\x0a\x01g"));
}

test "rpc: limits are enforced" {
    var rpc: TestRpc = .{};
    const t = std.testing;
    try t.expectError(error.TooManySubscriptions, rpc.decode(comptime repeat("\x0a\x00", 5)));
    try t.expectError(error.TooManyPublish, rpc.decode(comptime repeat("\x12\x00", 5)));
    try t.expectError(error.TooManyIHave, rpc.decode("\x1a\x08" ++ comptime repeat("\x0a\x00", 4)));
    try t.expectError(error.TooManyIWant, rpc.decode("\x1a\x08" ++ comptime repeat("\x12\x00", 4)));
    try t.expectError(error.TooManyGraft, rpc.decode("\x1a\x08" ++ comptime repeat("\x1a\x00", 4)));
    try t.expectError(error.TooManyPrune, rpc.decode("\x1a\x08" ++ comptime repeat("\x22\x00", 4)));
    const idontwants = "\x1a\x08" ++ comptime repeat("\x2a\x00", 4);
    try t.expectError(error.TooManyIDontWant, rpc.decode(idontwants));
    // Limits are totals across merged control fields.
    const grafts = comptime repeat("\x1a\x04" ++ repeat("\x1a\x00", 2), 2);
    try t.expectError(error.TooManyGraft, rpc.decode(grafts));
    const ids_17 = "\x1a\x24\x12\x22" ++ comptime repeat("\x0a\x00", 17);
    try t.expectError(error.TooManyMessageIds, rpc.decode(ids_17));
    const peers_5 = "\x1a\x0c\x22\x0a" ++ comptime repeat("\x12\x00", 5);
    try t.expectError(error.TooManyPeers, rpc.decode(peers_5));
    try rpc.decode("\x1a\x22\x12\x20" ++ comptime repeat("\x0a\x00", 16));
    try t.expectEqual(@as(u32, 16), rpc.message_ids_count);
    rpc.reset();
    const ids: [17][]const u8 = @splat("m");
    try t.expectError(error.TooManyMessageIds, rpc.add_iwant(&ids));
    try t.expectError(error.TooManyPeers, rpc.add_prune(null, &(@as([5]PeerInfo, @splat(.{}))), 1));
}

test "rpc: framing" {
    var rpc: TestRpc = .{};
    try rpc.decode(vector_full);
    var buffer: [256]u8 = undefined;
    const framed = rpc.encode_framed(&buffer);
    try std.testing.expectEqual(@as(u8, vector_full.len), framed[0]);
    const t = std.testing;
    const frame = (try frame_decode(framed, frame_size_max_default)).?;
    try t.expectEqualSlices(u8, vector_full, frame.payload);
    try t.expectEqual(framed.len, frame.length);
    try t.expectEqual(@as(?Frame, null), try frame_decode(framed[0 .. framed.len - 1], 1024));
    try t.expectEqual(@as(?Frame, null), try frame_decode("", 1024));
    try t.expectEqual(@as(?Frame, null), try frame_decode("\x80\x80", 1024));
    try t.expectError(error.FrameTooLarge, frame_decode(framed, vector_full.len - 1));
    const huge = "\x81\x80\x80\x05";
    try t.expectError(error.FrameTooLarge, frame_decode(huge, frame_size_max_default));
    const long: [11]u8 = @splat(0xff);
    try t.expectError(error.VarintOverflow, frame_decode(&long, frame_size_max_default));
    var header: [varint_length_max]u8 = undefined;
    try t.expectEqualSlices(u8, "\xac\x02", frame_header(&header, 300));
}

/// Fills `rpc` with random content whose byte fields point into `pool`.
fn random_rpc(rpc: *TestRpc, prng: *Prng, pool: []const u8) void {
    rpc.reset();
    const Gen = struct {
        fn bytes(p: *Prng, source: []const u8) ?[]const u8 {
            if (p.chance(1, 4)) return null;
            const start: usize = @intCast(p.below(source.len));
            const length: usize = @intCast(p.range(0, @min(source.len - start, 40)));
            return source[start..][0..length];
        }
    };
    const g = Gen.bytes;
    var ids: [4][]const u8 = undefined;
    for (&ids) |*id| id.* = g(prng, pool) orelse "";
    var peers: [2]PeerInfo = undefined;
    for (&peers) |*peer| {
        peer.* = .{ .peer_id = g(prng, pool), .signed_peer_record = g(prng, pool) };
    }
    const actions = prng.below(16);
    for (0..actions) |_| {
        const n: usize = @intCast(prng.below(ids.len + 1));
        const backoff: ?u64 = if (prng.chance(1, 2)) null else prng.int(u64);
        const result = switch (prng.below(7)) {
            0 => rpc.add_subscription(.{
                .subscribe = if (prng.chance(1, 3)) null else prng.chance(1, 2),
                .topic_id = g(prng, pool),
            }),
            1 => rpc.add_publish(.{
                .from = g(prng, pool),
                .data = g(prng, pool),
                .seqno = g(prng, pool),
                .topic = g(prng, pool),
                .signature = g(prng, pool),
                .key = g(prng, pool),
            }),
            2 => rpc.add_ihave(g(prng, pool), ids[0..n]),
            3 => rpc.add_iwant(ids[0..n]),
            4 => rpc.add_graft(g(prng, pool)),
            5 => rpc.add_prune(g(prng, pool), peers[0..@min(n, 2)], backoff),
            else => rpc.add_idontwant(ids[0..n]),
        };
        result catch {}; // A full capacity just drops the entry.
    }
    rpc.has_control = rpc.has_control or prng.chance(1, 8);
}

test "rpc: seeded round trip of random rpcs" {
    var prng = Prng.init(0x7270_6321);
    var pool: [256]u8 = undefined;
    prng.fill(&pool);
    var original: TestRpc = .{};
    var decoded: TestRpc = .{};
    var buffer: [8192]u8 = undefined;
    for (0..512) |_| {
        random_rpc(&original, &prng, &pool);
        const encoded = original.encode(&buffer);
        try std.testing.expectEqual(original.encoded_length(), encoded.len);
        try decoded.decode(encoded);
        try std.testing.expect(original.eql(&decoded));
        try std.testing.expect(decoded.eql(&original));
    }
}

test "rpc: default limits hold a full gossipsub heartbeat" {
    var rpc: RpcDefault = .{};
    const ids: [5000][]const u8 = @splat("0123456789abcdef0123");
    try rpc.add_ihave("/optimism/8453/2/blocks", ids[0..4999]);
    try rpc.add_iwant(ids[0..1]);
    try std.testing.expectError(error.TooManyMessageIds, rpc.add_idontwant(ids[0..1]));
    try std.testing.expectEqual(@as(u32, 5000), rpc.message_ids_count);
}

fn decode_round_trip(comptime R: type, input: []const u8) !void {
    const first = try std.testing.allocator.create(R);
    defer std.testing.allocator.destroy(first);
    const second = try std.testing.allocator.create(R);
    defer std.testing.allocator.destroy(second);
    first.* = .{};
    second.* = .{};
    first.decode(input) catch return;
    var buffer: [fuzz.input_size_limit]u8 = undefined;
    // Re-encoding drops unknown and duplicate fields and minimizes varints: never longer.
    try std.testing.expect(first.encoded_length() <= input.len);
    const encoded = first.encode(&buffer);
    try second.decode(encoded);
    try std.testing.expect(first.eql(second));
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    try decode_round_trip(TestRpc, input);
    try decode_round_trip(RpcDefault, input);
}

test "rpc: fuzz decode -> encode -> decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .corpus = &.{vector_full} });
}

fn fuzz_mutate(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var pool: [256]u8 = undefined;
    prng.fill(&pool);
    var rpc: TestRpc = .{};
    random_rpc(&rpc, &prng, &pool);
    var buffer: [8192]u8 = undefined;
    const encoded = rpc.encode(&buffer);
    // Flip or truncate a valid encoding: the decoder must stay in bounds and consistent.
    const flips = smith.valueRangeAtMost(u8, 0, 8);
    for (0..flips) |_| {
        if (encoded.len == 0) break;
        encoded[smith.index(encoded.len)] = smith.value(u8);
    }
    const length = smith.valueRangeAtMost(u32, 0, @intCast(encoded.len));
    try decode_round_trip(TestRpc, encoded[0..length]);
}

test "rpc: fuzz mutated encodings" {
    try fuzz.run({}, fuzz_mutate, .{});
}

//! yamux stream multiplexer (hashicorp yamux `spec.md`, libp2p `/yamux/1.0.0`). Every frame
//! has a 12-byte big-endian header `version(0) | type | flags | stream id | length`:
//!
//!   - Data (0): `length` payload bytes follow.
//!   - WindowUpdate (1): `length` is a receive-window credit for the stream.
//!   - Ping (2): `length` is an opaque value; SYN asks, ACK answers. Stream id 0.
//!   - GoAway (3): `length` is an error code. Stream id 0.
//!
//! Flags: SYN opens a stream, ACK accepts it, FIN half-closes, RST resets. The client
//! (dialer) uses odd stream ids and the server even ones. Every stream starts with a 256 KiB
//! receive window in each direction.
//!
//! `Session` is an IO-free state machine with a comptime-sized stream table and receive
//! buffers carved from one caller-supplied slice at init, so nothing allocates afterwards.
//! `receive` consumes bytes from the peer in any fragmentation; `write` frames stream data
//! within the send window; `flush` writes pending control frames (SYN/ACK/FIN/RST, window
//! updates, pings, go-away). Window updates are sent once half the window is consumed.

const std = @import("std");
const assert = std.debug.assert;

pub const protocol_id = "/yamux/1.0.0";
pub const version = 0;
pub const header_length = 12;
/// Initial (and our fixed) per-stream receive window, and the per-stream buffer size.
pub const receive_window_bytes: u32 = 256 * 1024;
/// We advertise consumed credit back once it reaches this much.
pub const window_update_threshold_bytes: u32 = receive_window_bytes / 2;

pub const flag_syn: u16 = 0x1;
pub const flag_ack: u16 = 0x2;
pub const flag_fin: u16 = 0x4;
pub const flag_rst: u16 = 0x8;
const flags_known: u16 = flag_syn | flag_ack | flag_fin | flag_rst;

pub const FrameType = enum(u8) { data = 0, window_update = 1, ping = 2, go_away = 3 };

pub const GoAwayCode = enum(u32) { normal = 0, protocol_error = 1, internal_error = 2 };

pub const Error = error{
    /// The peer violated the protocol (bad version or type, stream id rules, flow control).
    ProtocolError,
    /// The session already failed; flush the go-away and close the connection.
    SessionFailed,
    /// Every stream slot is in use.
    StreamLimit,
    /// The 32-bit stream id space for our role is used up.
    StreamIdsExhausted,
    /// No open stream has this id (never opened, reset, or fully closed).
    UnknownStream,
    /// The stream was closed for writing.
    StreamClosed,
    /// A go-away was sent or received; no new streams.
    GoAway,
    /// A ping is already awaiting its answer.
    PingOutstanding,
    /// Too many stream resets are waiting to be flushed.
    ResetQueueFull,
};

pub const Header = struct {
    frame_type: FrameType,
    flags: u16,
    stream_id: u32,
    length: u32,

    pub fn encode(header: Header, output: *[header_length]u8) void {
        assert(header.flags & ~flags_known == 0);
        output[0] = version;
        output[1] = @backingInt(header.frame_type);
        std.mem.writeInt(u16, output[2..4], header.flags, .big);
        std.mem.writeInt(u32, output[4..8], header.stream_id, .big);
        std.mem.writeInt(u32, output[8..12], header.length, .big);
        assert(output[0] == version);
    }

    /// Unknown flag bits are ignored, like the reference implementations.
    pub fn decode(bytes: *const [header_length]u8) Error!Header {
        if (bytes[0] != version) return error.ProtocolError;
        if (bytes[1] > @backingInt(FrameType.go_away)) return error.ProtocolError;
        const header: Header = .{
            .frame_type = @fromBackingInt(@intCast(bytes[1])),
            .flags = std.mem.readInt(u16, bytes[2..4], .big) & flags_known,
            .stream_id = std.mem.readInt(u32, bytes[4..8], .big),
            .length = std.mem.readInt(u32, bytes[8..12], .big),
        };
        assert(header.flags & ~flags_known == 0);
        return header;
    }
};

pub const Role = enum {
    /// Dialer: odd stream ids.
    client,
    /// Listener: even stream ids.
    server,
};

pub const StreamStatus = struct {
    /// Received bytes waiting for `read`.
    readable: u32,
    /// Bytes `write` may send before the peer grants more window.
    send_window: u32,
    /// We closed for writing (FIN queued or sent).
    local_closed: bool,
    /// The peer closed for writing.
    remote_closed: bool,
};

pub const Written = struct {
    /// Bytes of `data` placed in `frame`; zero when the send window is exhausted.
    data_length: u32,
    frame: []const u8,
};

const Stream = struct {
    /// Zero marks a free slot.
    id: u32 = 0,
    inbound: bool = false,
    accepted: bool = false,
    /// Receive ring buffer over this slot's region of the session memory.
    buffer_start: u32 = 0,
    buffer_length: u32 = 0,
    /// Credit the peer still has; credit consumed by `read` but not yet advertised.
    receive_window: u32 = receive_window_bytes,
    receive_pending: u32 = 0,
    send_window: u32 = receive_window_bytes,
    /// Flags (SYN/ACK/FIN) to put on the next outbound frame.
    pending_flags: u16 = 0,
    local_fin: bool = false,
    local_fin_sent: bool = false,
    remote_fin: bool = false,
};

pub fn Session(comptime stream_count_max: u16) type {
    comptime assert(stream_count_max > 0);
    comptime assert(stream_count_max <= 1024);
    const reset_queue_max = 2 * @as(u32, stream_count_max);

    return struct {
        const Self = @This();

        pub const memory_length = @as(usize, stream_count_max) * receive_window_bytes;
        pub const streams_max = stream_count_max;

        role: Role,
        memory: []u8,
        streams: [stream_count_max]Stream = @splat(.{}),
        next_stream_id: u32,
        remote_stream_id_last: u32 = 0,
        reset_queue: [reset_queue_max]u32 = undefined,
        reset_count: u32 = 0,
        ping_ack_pending: ?u32 = null,
        ping_request_pending: ?u32 = null,
        ping_outstanding: ?u32 = null,
        pong: ?u32 = null,
        go_away_pending: ?GoAwayCode = null,
        go_away_sent: bool = false,
        remote_go_away: ?u32 = null,
        failed: bool = false,
        header_buffer: [header_length]u8 = undefined,
        header_fill: u8 = 0,
        data_remaining: u32 = 0,
        /// Stream slot receiving the current data frame, or null to discard it.
        data_slot: ?u16 = null,
        data_fin: bool = false,

        /// `memory` holds every stream's receive buffer: exactly `memory_length` bytes.
        pub fn init(role: Role, memory: []u8) Self {
            assert(memory.len == memory_length);
            const session: Self = .{
                .role = role,
                .memory = memory,
                .next_stream_id = if (role == .client) 1 else 2,
            };
            assert(session.next_stream_id % 2 == @intFromBool(role == .client));
            return session;
        }

        /// Opens an outbound stream; SYN goes out with the first `write` or `flush`.
        pub fn open(session: *Self) Error!u32 {
            if (session.failed) return error.SessionFailed;
            if (session.remote_go_away != null or session.go_away_pending != null or
                session.go_away_sent) return error.GoAway;
            const slot = session.free_slot() orelse return error.StreamLimit;
            if (session.next_stream_id > std.math.maxInt(u32) - 2) {
                return error.StreamIdsExhausted;
            }
            const id = session.next_stream_id;
            session.next_stream_id += 2;
            session.streams[slot] = .{ .id = id, .pending_flags = flag_syn };
            assert(session.find(id) == slot);
            return id;
        }

        /// The lowest-id inbound stream not yet accepted.
        pub fn accept(session: *Self) ?u32 {
            var best: ?u16 = null;
            for (&session.streams, 0..) |*stream, slot| {
                if (stream.id == 0 or !stream.inbound or stream.accepted) continue;
                if (best == null or stream.id < session.streams[best.?].id) {
                    best = @intCast(slot);
                }
            }
            const slot = best orelse return null;
            session.streams[slot].accepted = true;
            assert(session.streams[slot].id % 2 != session.next_stream_id % 2);
            return session.streams[slot].id;
        }

        pub fn status(session: *const Self, id: u32) ?StreamStatus {
            const slot = session.find(id) orelse return null;
            const stream = &session.streams[slot];
            assert(stream.id == id);
            return .{
                .readable = stream.buffer_length,
                .send_window = stream.send_window,
                .local_closed = stream.local_fin,
                .remote_closed = stream.remote_fin,
            };
        }

        /// Copies received bytes into `output`; the credit is returned via `flush`.
        pub fn read(session: *Self, id: u32, output: []u8) Error!u32 {
            const slot = session.find(id) orelse return error.UnknownStream;
            const stream = &session.streams[slot];
            const length: u32 = @intCast(@min(output.len, stream.buffer_length));
            const region = session.stream_buffer(slot);
            const first = @min(length, receive_window_bytes - stream.buffer_start);
            @memcpy(output[0..first], region[stream.buffer_start..][0..first]);
            @memcpy(output[first..length], region[0 .. length - first]);
            stream.buffer_start = (stream.buffer_start + length) % receive_window_bytes;
            stream.buffer_length -= length;
            stream.receive_pending += length;
            session.assert_window(slot);
            session.release_if_closed(slot);
            return length;
        }

        /// Frames up to the send window of `data` as one Data frame into `output`.
        pub fn write(session: *Self, id: u32, data: []const u8, output: []u8) Error!Written {
            assert(data.len > 0);
            assert(output.len > header_length);
            if (session.failed) return error.SessionFailed;
            const slot = session.find(id) orelse return error.UnknownStream;
            const stream = &session.streams[slot];
            if (stream.local_fin) return error.StreamClosed;
            const room = output.len - header_length;
            const length: u32 = @intCast(@min(@min(data.len, room), stream.send_window));
            if (length == 0) return .{ .data_length = 0, .frame = output[0..0] };
            const header: Header = .{
                .frame_type = .data,
                .flags = stream.pending_flags,
                .stream_id = id,
                .length = length,
            };
            header.encode(output[0..header_length]);
            @memcpy(output[header_length..][0..length], data[0..length]);
            stream.pending_flags = 0;
            stream.send_window -= length;
            return .{ .data_length = length, .frame = output[0 .. header_length + length] };
        }

        /// Half-closes the stream for writing; FIN goes out with the next `flush`.
        pub fn close(session: *Self, id: u32) Error!void {
            const slot = session.find(id) orelse return error.UnknownStream;
            const stream = &session.streams[slot];
            if (stream.local_fin) return;
            stream.local_fin = true;
            stream.pending_flags |= flag_fin;
            assert(!stream.local_fin_sent);
        }

        /// Drops the stream now; RST goes out with the next `flush`.
        pub fn reset(session: *Self, id: u32) Error!void {
            const slot = session.find(id) orelse return error.UnknownStream;
            if (session.reset_count == reset_queue_max) return error.ResetQueueFull;
            session.queue_reset(id);
            session.release(slot);
            assert(session.find(id) == null);
        }

        pub fn ping(session: *Self, opaque_value: u32) Error!void {
            if (session.failed) return error.SessionFailed;
            if (session.ping_outstanding != null) return error.PingOutstanding;
            session.ping_outstanding = opaque_value;
            session.ping_request_pending = opaque_value;
        }

        /// The answered ping value, once.
        pub fn take_pong(session: *Self) ?u32 {
            const value = session.pong orelse return null;
            session.pong = null;
            assert(session.ping_outstanding == null);
            return value;
        }

        /// Announces that we accept no new streams; existing streams continue.
        pub fn go_away(session: *Self, code: GoAwayCode) void {
            if (session.go_away_sent or session.go_away_pending != null) return;
            session.go_away_pending = code;
            assert(!session.go_away_sent);
        }

        /// Consumes every byte of `input`. On error the session is failed and a go-away
        /// with the matching code is pending for `flush`.
        pub fn receive(session: *Self, input: []const u8) Error!void {
            if (session.failed) return error.SessionFailed;
            var offset: usize = 0;
            // Every pass consumes at least one byte.
            while (offset < input.len) {
                const before = offset;
                if (session.data_remaining > 0) {
                    offset += session.receive_data(input[offset..]);
                } else {
                    const take = @min(header_length - session.header_fill, input.len - offset);
                    const fill = session.header_fill;
                    @memcpy(session.header_buffer[fill..][0..take], input[offset..][0..take]);
                    session.header_fill += @intCast(take);
                    offset += take;
                    if (session.header_fill == header_length) {
                        session.header_fill = 0;
                        session.handle_header() catch |err| return session.fail(err);
                    }
                }
                assert(offset > before);
            }
            assert(offset == input.len);
        }

        fn fail(session: *Self, err: Error) Error {
            assert(!session.failed);
            session.failed = true;
            if (!session.go_away_sent) {
                session.go_away_pending = switch (err) {
                    error.ProtocolError => .protocol_error,
                    else => .internal_error,
                };
            }
            return err;
        }

        fn receive_data(session: *Self, input: []const u8) usize {
            assert(session.data_remaining > 0);
            assert(input.len > 0);
            const take: u32 = @intCast(@min(session.data_remaining, input.len));
            if (session.data_slot) |slot| session.append(slot, input[0..take]);
            session.data_remaining -= take;
            if (session.data_remaining == 0) {
                if (session.data_slot) |slot| {
                    session.data_slot = null;
                    if (session.data_fin) session.apply_remote_fin(slot);
                }
                session.data_fin = false;
            }
            return take;
        }

        fn append(session: *Self, slot: u16, bytes: []const u8) void {
            const stream = &session.streams[slot];
            assert(stream.buffer_length + bytes.len <= receive_window_bytes);
            const region = session.stream_buffer(slot);
            const end = (stream.buffer_start + stream.buffer_length) % receive_window_bytes;
            const first = @min(bytes.len, receive_window_bytes - end);
            @memcpy(region[end..][0..first], bytes[0..first]);
            @memcpy(region[0 .. bytes.len - first], bytes[first..]);
            stream.buffer_length += @intCast(bytes.len);
            assert(stream.buffer_length <= receive_window_bytes);
        }

        fn handle_header(session: *Self) Error!void {
            const header = try Header.decode(&session.header_buffer);
            assert(session.data_remaining == 0);
            switch (header.frame_type) {
                .ping => {
                    if (header.stream_id != 0) return error.ProtocolError;
                    if (header.flags & flag_syn != 0) {
                        session.ping_ack_pending = header.length;
                    } else if (header.flags & flag_ack != 0) {
                        if (session.ping_outstanding == header.length) {
                            session.ping_outstanding = null;
                            session.pong = header.length;
                        }
                    }
                },
                .go_away => {
                    if (header.stream_id != 0) return error.ProtocolError;
                    session.remote_go_away = header.length;
                },
                .data, .window_update => {
                    if (header.stream_id == 0) return error.ProtocolError;
                    try session.handle_stream_frame(header);
                },
            }
        }

        fn handle_stream_frame(session: *Self, header: Header) Error!void {
            assert(header.stream_id != 0);
            const is_data = header.frame_type == .data;
            const found = if (header.flags & flag_syn != 0)
                try session.open_inbound(header.stream_id)
            else
                session.find(header.stream_id);
            const slot = found orelse {
                // Unknown, refused, or already reset: drop any payload.
                if (is_data) session.data_remaining = header.length;
                return;
            };
            if (header.flags & flag_rst != 0) {
                session.release(slot);
                if (is_data) session.data_remaining = header.length;
                return;
            }
            const stream = &session.streams[slot];
            if (!is_data) {
                const window = @as(u64, stream.send_window) + header.length;
                if (window > std.math.maxInt(u32)) return error.ProtocolError;
                stream.send_window = @intCast(window);
            } else if (header.length > 0) {
                if (stream.remote_fin) return error.ProtocolError;
                if (header.length > stream.receive_window) return error.ProtocolError;
                stream.receive_window -= header.length;
                session.data_remaining = header.length;
                session.data_slot = slot;
                session.data_fin = header.flags & flag_fin != 0;
                return;
            }
            if (header.flags & flag_fin != 0) session.apply_remote_fin(slot);
        }

        /// Validates a SYN and takes a slot, or queues a RST and returns null when full.
        fn open_inbound(session: *Self, id: u32) Error!?u16 {
            const remote_parity: u32 = if (session.role == .client) 0 else 1;
            if (id % 2 != remote_parity) return error.ProtocolError;
            if (id <= session.remote_stream_id_last) return error.ProtocolError;
            session.remote_stream_id_last = id;
            const free = session.free_slot();
            if (free == null or session.go_away_sent or session.go_away_pending != null) {
                if (session.reset_count == reset_queue_max) return error.ResetQueueFull;
                session.queue_reset(id);
                return null;
            }
            const slot = free.?;
            session.streams[slot] = .{ .id = id, .inbound = true, .pending_flags = flag_ack };
            assert(session.find(id) == slot);
            return slot;
        }

        fn apply_remote_fin(session: *Self, slot: u16) void {
            assert(session.streams[slot].id != 0);
            session.streams[slot].remote_fin = true;
            session.release_if_closed(slot);
        }

        fn release_if_closed(session: *Self, slot: u16) void {
            const stream = &session.streams[slot];
            assert(stream.id != 0);
            if (stream.local_fin_sent and stream.remote_fin and stream.buffer_length == 0) {
                session.release(slot);
            }
        }

        fn release(session: *Self, slot: u16) void {
            assert(session.streams[slot].id != 0);
            session.streams[slot] = .{};
            if (session.data_slot == slot) session.data_slot = null;
            assert(session.streams[slot].id == 0);
        }

        fn queue_reset(session: *Self, id: u32) void {
            assert(id != 0);
            assert(session.reset_count < reset_queue_max);
            session.reset_queue[session.reset_count] = id;
            session.reset_count += 1;
        }

        /// Writes pending control frames into `output` (as many as fit, in order: ping
        /// answers, pings, resets, per-stream window updates with SYN/ACK/FIN, go-away).
        pub fn flush(session: *Self, output: []u8) []const u8 {
            var length: usize = 0;
            if (session.ping_ack_pending) |value| {
                if (!emit(output, &length, .ping, flag_ack, 0, value)) return output[0..length];
                session.ping_ack_pending = null;
            }
            if (session.ping_request_pending) |value| {
                if (!emit(output, &length, .ping, flag_syn, 0, value)) return output[0..length];
                session.ping_request_pending = null;
            }
            while (session.reset_count > 0) {
                const id = session.reset_queue[0];
                if (!emit(output, &length, .window_update, flag_rst, id, 0)) {
                    return output[0..length];
                }
                session.reset_count -= 1;
                const count = session.reset_count;
                const queue = &session.reset_queue;
                std.mem.copyForwards(u32, queue[0..count], queue[1..][0..count]);
            }
            for (0..stream_count_max) |slot| {
                if (!session.flush_stream(@intCast(slot), output, &length)) {
                    return output[0..length];
                }
            }
            if (session.go_away_pending) |code| {
                if (emit(output, &length, .go_away, 0, 0, @backingInt(code))) {
                    session.go_away_pending = null;
                    session.go_away_sent = true;
                }
            }
            assert(length % header_length == 0);
            return output[0..length];
        }

        /// Returns false when `output` is full.
        fn flush_stream(session: *Self, slot: u16, output: []u8, length: *usize) bool {
            const stream = &session.streams[slot];
            if (stream.id == 0) return true;
            const credit_due = stream.receive_pending >= window_update_threshold_bytes;
            if (stream.pending_flags == 0 and !credit_due) return true;
            const id = stream.id;
            const flags = stream.pending_flags;
            const credit = stream.receive_pending;
            if (!emit(output, length, .window_update, flags, id, credit)) return false;
            stream.receive_window += credit;
            stream.receive_pending = 0;
            stream.pending_flags = 0;
            if (flags & flag_fin != 0) stream.local_fin_sent = true;
            session.assert_window(slot);
            session.release_if_closed(slot);
            return true;
        }

        fn emit(
            output: []u8,
            length: *usize,
            frame_type: FrameType,
            flags: u16,
            stream_id: u32,
            value: u32,
        ) bool {
            assert(length.* <= output.len);
            if (output.len - length.* < header_length) return false;
            const header: Header = .{
                .frame_type = frame_type,
                .flags = flags,
                .stream_id = stream_id,
                .length = value,
            };
            header.encode(output[length.*..][0..header_length]);
            length.* += header_length;
            return true;
        }

        fn find(session: *const Self, id: u32) ?u16 {
            if (id == 0) return null;
            for (&session.streams, 0..) |*stream, slot| {
                if (stream.id == id) return @intCast(slot);
            }
            return null;
        }

        fn free_slot(session: *const Self) ?u16 {
            for (&session.streams, 0..) |*stream, slot| {
                if (stream.id == 0) return @intCast(slot);
            }
            return null;
        }

        fn stream_buffer(session: *Self, slot: u16) []u8 {
            assert(slot < stream_count_max);
            const start = @as(usize, slot) * receive_window_bytes;
            return session.memory[start..][0..receive_window_bytes];
        }

        /// Credit conservation: window + buffered + unadvertised (+ in-flight) == window size.
        fn assert_window(session: *const Self, slot: u16) void {
            const stream = &session.streams[slot];
            const in_flight: u64 = if (session.data_slot == slot) session.data_remaining else 0;
            const total = @as(u64, stream.receive_window) + stream.buffer_length +
                stream.receive_pending + in_flight;
            assert(total == receive_window_bytes);
        }
    };
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;
const testing = std.testing;

const TestSession = Session(4);

const Pair = struct {
    client: TestSession,
    server: TestSession,
    memory: []u8,

    fn init() !Pair {
        const memory = try testing.allocator.alloc(u8, 2 * TestSession.memory_length);
        return .{
            .client = TestSession.init(.client, memory[0..TestSession.memory_length]),
            .server = TestSession.init(.server, memory[TestSession.memory_length..]),
            .memory = memory,
        };
    }

    fn deinit(pair: *Pair) void {
        testing.allocator.free(pair.memory);
    }

    /// Delivers `from`'s pending control frames to `to`.
    fn pump(from: *TestSession, to: *TestSession) !void {
        var buffer: [64 * header_length]u8 = undefined;
        try to.receive(from.flush(&buffer));
    }

    fn send(from: *TestSession, to: *TestSession, id: u32, data: []const u8) !u32 {
        var buffer: [header_length + 4096]u8 = undefined;
        var sent: u32 = 0;
        while (sent < data.len) {
            const written = try from.write(id, data[sent..], &buffer);
            if (written.data_length == 0) break;
            try to.receive(written.frame);
            sent += written.data_length;
        }
        return sent;
    }
};

test "yamux: header round trip and rejects" {
    const header: Header = .{
        .frame_type = .window_update,
        .flags = flag_syn | flag_fin,
        .stream_id = 0x01020304,
        .length = 0x0a0b0c0d,
    };
    var bytes: [header_length]u8 = undefined;
    header.encode(&bytes);
    const expected = [_]u8{ 0, 1, 0, 5, 1, 2, 3, 4, 0x0a, 0x0b, 0x0c, 0x0d };
    try testing.expectEqualSlices(u8, &expected, &bytes);
    try testing.expectEqual(header, try Header.decode(&bytes));
    bytes[0] = 1;
    try testing.expectError(error.ProtocolError, Header.decode(&bytes));
    bytes[0] = 0;
    bytes[1] = 4;
    try testing.expectError(error.ProtocolError, Header.decode(&bytes));
}

test "yamux: open, accept, data, and close" {
    var pair = try Pair.init();
    defer pair.deinit();
    const id = try pair.client.open();
    try testing.expectEqual(@as(u32, 1), id);
    try testing.expectEqual(@as(u32, 5), try Pair.send(&pair.client, &pair.server, id, "hello"));
    try testing.expectEqual(@as(?u32, 1), pair.server.accept());
    try testing.expectEqual(@as(?u32, null), pair.server.accept());
    var buffer: [16]u8 = undefined;
    try testing.expectEqual(@as(u32, 5), try pair.server.read(1, &buffer));
    try testing.expectEqualStrings("hello", buffer[0..5]);
    try Pair.pump(&pair.server, &pair.client); // ACK
    try testing.expectEqual(@as(u32, 3), try Pair.send(&pair.server, &pair.client, id, "hey"));
    try pair.client.close(id);
    try Pair.pump(&pair.client, &pair.server);
    try testing.expect(pair.server.status(id).?.remote_closed);
    try testing.expectError(error.StreamClosed, pair.client.write(id, "x", &buffer));
    try pair.server.close(id);
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(@as(?StreamStatus, null), pair.server.status(id));
    // The client still holds unread data, so the stream lives until it is read.
    try testing.expect(pair.client.status(id) != null);
    try testing.expectEqual(@as(u32, 3), try pair.client.read(id, &buffer));
    try testing.expectEqual(@as(?StreamStatus, null), pair.client.status(id));
}

test "yamux: flow control blocks and window updates unblock" {
    var pair = try Pair.init();
    defer pair.deinit();
    const id = try pair.client.open();
    const data = try testing.allocator.alloc(u8, receive_window_bytes + 1000);
    defer testing.allocator.free(data);
    @memset(data, 0xab);
    const sent = try Pair.send(&pair.client, &pair.server, id, data);
    try testing.expectEqual(receive_window_bytes, sent);
    try testing.expectEqual(@as(u32, 0), pair.client.status(id).?.send_window);
    try testing.expectEqual(receive_window_bytes, pair.server.status(id).?.readable);
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(@as(u32, 0), pair.client.status(id).?.send_window);
    var sink: [4096]u8 = undefined;
    var drained: u32 = 0;
    while (drained < window_update_threshold_bytes) {
        drained += try pair.server.read(id, &sink);
    }
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(drained, pair.client.status(id).?.send_window);
    const resent = try Pair.send(&pair.client, &pair.server, id, data[0..1000]);
    try testing.expectEqual(@as(u32, 1000), resent);
}

test "yamux: peer exceeding the window is a protocol error" {
    var pair = try Pair.init();
    defer pair.deinit();
    var frame: [header_length]u8 = undefined;
    const header: Header = .{
        .frame_type = .data,
        .flags = flag_syn,
        .stream_id = 1,
        .length = receive_window_bytes + 1,
    };
    header.encode(&frame);
    try testing.expectError(error.ProtocolError, pair.server.receive(&frame));
    try testing.expectError(error.SessionFailed, pair.server.receive(&frame));
    var buffer: [64]u8 = undefined;
    const flushed = pair.server.flush(&buffer);
    const go_away = try Header.decode(flushed[flushed.len - header_length ..][0..header_length]);
    try testing.expectEqual(FrameType.go_away, go_away.frame_type);
    try testing.expectEqual(@backingInt(GoAwayCode.protocol_error), go_away.length);
}

test "yamux: stream id parity and reuse are enforced" {
    var pair = try Pair.init();
    defer pair.deinit();
    var frame: [header_length]u8 = undefined;
    var syn: Header = .{
        .frame_type = .window_update,
        .flags = flag_syn,
        .stream_id = 2,
        .length = 0,
    };
    syn.encode(&frame);
    try testing.expectError(error.ProtocolError, pair.server.receive(&frame));
    var other = try Pair.init();
    defer other.deinit();
    syn.stream_id = 3;
    syn.encode(&frame);
    try other.server.receive(&frame);
    try testing.expectError(error.ProtocolError, other.server.receive(&frame));
}

test "yamux: reset" {
    var pair = try Pair.init();
    defer pair.deinit();
    const id = try pair.client.open();
    _ = try Pair.send(&pair.client, &pair.server, id, "data");
    try testing.expectEqual(@as(?u32, id), pair.server.accept());
    try pair.server.reset(id);
    try testing.expectEqual(@as(?StreamStatus, null), pair.server.status(id));
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(@as(?StreamStatus, null), pair.client.status(id));
    var buffer: [32]u8 = undefined;
    try testing.expectError(error.UnknownStream, pair.client.write(id, "x", &buffer));
    try testing.expectError(error.UnknownStream, pair.client.reset(id));
}

test "yamux: stream limit locally and refused remotely" {
    var pair = try Pair.init();
    defer pair.deinit();
    var ids: [TestSession.streams_max]u32 = undefined;
    for (&ids) |*id| id.* = try pair.client.open();
    try testing.expectError(error.StreamLimit, pair.client.open());
    try Pair.pump(&pair.client, &pair.server);
    try pair.client.reset(ids[0]);
    try Pair.pump(&pair.client, &pair.server);
    // The server still holds 3 streams; fill it with one more, then overflow it.
    const extra = try pair.client.open();
    try Pair.pump(&pair.client, &pair.server);
    try testing.expect(pair.server.status(extra) != null);
    var big = try Pair.init();
    defer big.deinit();
    const Dialer = Session(8);
    var dialer = Dialer.init(.client, try testing.allocator.alloc(u8, Dialer.memory_length));
    defer testing.allocator.free(dialer.memory);
    for (0..5) |_| _ = try dialer.open();
    var buffer: [16 * header_length]u8 = undefined;
    try big.server.receive(dialer.flush(&buffer));
    try testing.expectEqual(@as(?StreamStatus, null), big.server.status(9));
    try dialer.receive(big.server.flush(&buffer));
    try testing.expectEqual(@as(?StreamStatus, null), dialer.status(9));
    try testing.expect(dialer.status(7) != null);
}

test "yamux: ping and go away" {
    var pair = try Pair.init();
    defer pair.deinit();
    try pair.client.ping(42);
    try testing.expectError(error.PingOutstanding, pair.client.ping(43));
    try Pair.pump(&pair.client, &pair.server);
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(@as(?u32, 42), pair.client.take_pong());
    try testing.expectEqual(@as(?u32, null), pair.client.take_pong());
    pair.server.go_away(.normal);
    try testing.expectError(error.GoAway, pair.server.open());
    try Pair.pump(&pair.server, &pair.client);
    try testing.expectEqual(@as(?u32, 0), pair.client.remote_go_away);
    try testing.expectError(error.GoAway, pair.client.open());
}

test "yamux: fragmented frames" {
    var pair = try Pair.init();
    defer pair.deinit();
    const id = try pair.client.open();
    var buffer: [header_length + 64]u8 = undefined;
    const written = try pair.client.write(id, "fragmented payload", &buffer);
    for (written.frame) |byte| try pair.server.receive(&.{byte});
    var out: [64]u8 = undefined;
    const length = try pair.server.read(id, &out);
    try testing.expectEqualStrings("fragmented payload", out[0..length]);
}

fn fuzz_header(_: void, input: []const u8) anyerror!void {
    if (input.len < header_length) return;
    const header = Header.decode(input[0..header_length]) catch return;
    var bytes: [header_length]u8 = undefined;
    header.encode(&bytes);
    try testing.expectEqual(header, try Header.decode(&bytes));
}

test "yamux: fuzz header decode" {
    try fuzz.run_bytes({}, fuzz_header, .{ .input_size_max = 16 });
}

const FuzzContext = struct { memory: []u8 };

fn check_invariants(session: *const TestSession) !void {
    for (&session.streams, 0..) |*stream, slot| {
        if (stream.id == 0) continue;
        session.assert_window(@intCast(slot));
        try testing.expect(stream.buffer_length <= receive_window_bytes);
    }
}

fn fuzz_session_bytes(context: FuzzContext, input: []const u8) anyerror!void {
    var session = TestSession.init(.server, context.memory);
    session.receive(input) catch {};
    try check_invariants(&session);
    var buffer: [64 * header_length]u8 = undefined;
    _ = session.flush(&buffer);
}

/// Builds structurally valid frames from the fuzz input to reach deep session states.
fn fuzz_session_frames(context: FuzzContext, input: []const u8) anyerror!void {
    var session = TestSession.init(.server, context.memory);
    var frame: [header_length + 64]u8 = @splat(0x5a);
    var output: [64 * header_length]u8 = undefined;
    var offset: usize = 0;
    while (offset + 4 <= input.len) : (offset += 4) {
        const header: Header = .{
            .frame_type = @fromBackingInt(@intCast(input[offset] % 4)),
            .flags = input[offset + 1] & flags_known,
            .stream_id = input[offset + 2] % 12,
            .length = input[offset + 3],
        };
        header.encode(frame[0..header_length]);
        const length = if (header.frame_type == .data) @min(header.length, 64) else 0;
        session.receive(frame[0 .. header_length + length]) catch return;
        try check_invariants(&session);
        if (input[offset] & 0x80 != 0) {
            var sink: [64]u8 = undefined;
            if (session.accept()) |id| _ = try session.read(id, &sink);
            _ = session.flush(&output);
        }
    }
}

test "yamux: fuzz session" {
    const memory = try testing.allocator.alloc(u8, TestSession.memory_length);
    defer testing.allocator.free(memory);
    const context: FuzzContext = .{ .memory = memory };
    const options: fuzz.Options = .{ .input_size_max = 512, .iterations = 128 };
    try fuzz.run_bytes(context, fuzz_session_bytes, options);
    try fuzz.run_bytes(context, fuzz_session_frames, options);
}

test "yamux: seeded random traffic between two sessions" {
    var pair = try Pair.init();
    defer pair.deinit();
    var prng = Prng.init(0x7961_6d78);
    var payload: [512]u8 = undefined;
    var sink: [512]u8 = undefined;
    var sent_total: u64 = 0;
    var received_total: u64 = 0;
    for (0..512) |_| {
        switch (prng.below(5)) {
            0 => _ = pair.client.open() catch {},
            1 => {
                const slot: usize = @intCast(prng.below(TestSession.streams_max));
                const id = pair.client.streams[slot].id;
                if (id == 0 or pair.client.streams[slot].local_fin) continue;
                const length: usize = @intCast(prng.range(1, payload.len));
                sent_total += try Pair.send(&pair.client, &pair.server, id, payload[0..length]);
            },
            2 => {
                _ = pair.server.accept();
                for (&pair.server.streams) |*stream| {
                    if (stream.id != 0) received_total += try pair.server.read(stream.id, &sink);
                }
            },
            3 => {
                try Pair.pump(&pair.client, &pair.server);
                try Pair.pump(&pair.server, &pair.client);
            },
            else => {
                const slot: usize = @intCast(prng.below(TestSession.streams_max));
                const id = pair.client.streams[slot].id;
                if (id != 0) try pair.client.close(id);
            },
        }
    }
    try testing.expect(received_total <= sent_total);
    try check_invariants(&pair.client);
    try check_invariants(&pair.server);
}

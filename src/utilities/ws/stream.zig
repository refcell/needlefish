//! The WebSocket frame engine shared by the client and the server connections.
//!
//! A `Stream` owns one connected socket after TCP setup: a recv is always in flight, sends are
//! queued in a bounded buffer and flushed one at a time (so pings are answered while the
//! owner streams), unfragmented messages are delivered straight from the receive buffer and
//! fragmented ones are reassembled in a message buffer. Protocol violations fail the
//! connection without a close frame. Teardown shuts the socket down, waits for in-flight
//! operations, closes it, and reports once through `Hooks.closed`.
//!
//! `Hooks` is a namespace with `handshake(*Stream)` (called while `state == .handshaking`
//! with new bytes buffered; it calls `consume` and `open` or `fail`), `message(*Stream,
//! Message)`, and `closed(*Stream, Closed)`. Owners embed the stream and recover themselves
//! with `@fieldParentPtr`.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../io/common.zig");
const frame = @import("frame.zig");

pub const Opcode = frame.Opcode;

pub const Error = error{
    ConnectFailed,
    HandshakeFailed,
    ConnectionClosed,
    RecvFailed,
    SendFailed,
    ProtocolError,
    MessageTooLarge,
    InvalidUtf8,
    /// The peer did not drain its send buffer fast enough (server broadcast).
    SlowConsumer,
};

pub const SendError = error{ NotOpen, SendBufferFull };

pub const Message = struct { opcode: Opcode, payload: []const u8 };

pub const Closed = struct {
    /// The peer's close code; null when no close frame (or one without a code) arrived.
    code: ?u16,
    /// Why the connection failed; null after a clean close handshake or `abort`.
    err: ?Error,
};

pub const State = enum { idle, handshaking, open, closing, shutting_down };

pub fn Stream(comptime IO: type, comptime Hooks: type) type {
    return struct {
        const Self = @This();
        const Fd = IO.Fd;

        io: *IO,
        role: frame.Role,
        fd: ?Fd = null,
        state: State = .idle,
        recv_completion: IO.Completion = .{},
        send_completion: IO.Completion = .{},
        recv_pending: bool = false,
        send_pending: bool = false,
        recv_buffer: []u8,
        recv_size: u32 = 0,
        send_buffer: []u8,
        send_size: u32 = 0,
        send_offset: u32 = 0,
        message_buffer: []u8,
        message_size: u32 = 0,
        message_opcode: ?Opcode = null,
        close_sent: bool = false,
        close_received: bool = false,
        close_code: ?u16 = null,
        failure: ?Error = null,
        /// Pong frames received over the stream's lifetime (keepalive liveness checks).
        pongs_received: u64 = 0,
        random_state: u64,

        pub fn init(
            io: *IO,
            role: frame.Role,
            recv_buffer: []u8,
            send_buffer: []u8,
            message_buffer: []u8,
            seed: u64,
        ) Self {
            assert(recv_buffer.len >= message_buffer.len + frame.header_size_max);
            assert(send_buffer.len > frame.header_size_max + 125);
            return .{
                .io = io,
                .role = role,
                .recv_buffer = recv_buffer,
                .send_buffer = send_buffer,
                .message_buffer = message_buffer,
                .random_state = seed,
            };
        }

        /// Takes ownership of a connected socket and starts receiving the handshake.
        pub fn start(stream: *Self, fd: Fd) void {
            assert(stream.state == .idle);
            assert(stream.fd == null and !stream.recv_pending and !stream.send_pending);
            stream.fd = fd;
            stream.state = .handshaking;
            stream.recv_size = 0;
            stream.send_size = 0;
            stream.send_offset = 0;
            stream.message_size = 0;
            stream.message_opcode = null;
            stream.close_sent = false;
            stream.close_received = false;
            stream.close_code = null;
            stream.failure = null;
            stream.recv();
        }

        pub fn buffered(stream: *const Self) []u8 {
            return stream.recv_buffer[0..stream.recv_size];
        }

        /// Drops `size` bytes from the front of the receive buffer (the handshake head).
        pub fn consume(stream: *Self, size: u32) void {
            assert(size <= stream.recv_size);
            const remaining = stream.recv_size - size;
            std.mem.copyForwards(
                u8,
                stream.recv_buffer[0..remaining],
                stream.recv_buffer[size..stream.recv_size],
            );
            stream.recv_size = remaining;
        }

        /// Ends the handshake phase; frames are processed from now on.
        pub fn open(stream: *Self) void {
            assert(stream.state == .handshaking);
            stream.state = .open;
        }

        /// Queues raw bytes (the handshake request or response).
        pub fn send_raw(stream: *Self, bytes: []const u8) SendError!void {
            assert(stream.state == .handshaking);
            if (bytes.len > stream.send_buffer.len - stream.send_size) return error.SendBufferFull;
            @memcpy(stream.send_buffer[stream.send_size..][0..bytes.len], bytes);
            stream.send_size += @intCast(bytes.len);
            stream.flush();
        }

        pub fn send(stream: *Self, opcode: Opcode, payload: []const u8) SendError!void {
            assert(opcode == .text or opcode == .binary);
            if (stream.state != .open) return error.NotOpen;
            try stream.queue_frame(opcode, payload);
        }

        /// Queues a ping control frame; the peer's pong bumps `pongs_received`.
        pub fn ping(stream: *Self, payload: []const u8) SendError!void {
            assert(payload.len <= 125); // RFC 6455 5.5: control payloads are short.
            if (stream.state != .open) return error.NotOpen;
            try stream.queue_frame(.ping, payload);
        }

        /// Starts the close handshake; `closed` follows once the peer echoes it.
        pub fn close(stream: *Self, code: frame.CloseCode) void {
            if (stream.state != .open) return;
            var payload: [2]u8 = undefined;
            std.mem.writeInt(u16, &payload, @backingInt(code), .big);
            stream.queue_frame(.close, &payload) catch return stream.abort();
            stream.close_sent = true;
            stream.state = .closing;
        }

        /// Tears the connection down without a close handshake.
        pub fn abort(stream: *Self) void {
            switch (stream.state) {
                .idle, .shutting_down => return,
                else => stream.begin_shutdown(),
            }
        }

        pub fn fail(stream: *Self, err: Error) void {
            if (stream.state == .idle) return;
            if (stream.failure == null) stream.failure = err;
            stream.begin_shutdown();
        }

        /// Fails the connection once queued bytes (e.g. an HTTP error response) are sent.
        pub fn fail_after_flush(stream: *Self, err: Error) void {
            assert(stream.state == .handshaking or stream.state == .open);
            if (stream.failure == null) stream.failure = err;
            stream.close_received = true; // Stop reading; shut down when the buffer drains.
            stream.state = .closing;
            if (!stream.send_pending and stream.send_offset == stream.send_size) {
                stream.begin_shutdown();
            }
        }

        fn queue_frame(stream: *Self, opcode: Opcode, payload: []const u8) SendError!void {
            assert(stream.fd != null);
            const free = stream.send_buffer.len - stream.send_size;
            if (frame.header_size_max + payload.len > free) return error.SendBufferFull;
            var mask: ?[4]u8 = null;
            if (stream.role == .client) {
                var key: [4]u8 = undefined;
                std.mem.writeInt(u32, &key, @truncate(stream.next_random()), .little);
                mask = key;
            }
            var header: [frame.header_size_max]u8 = undefined;
            const header_size = frame.encode_header(&header, true, opcode, payload.len, mask);
            const out = stream.send_buffer[stream.send_size..];
            @memcpy(out[0..header_size], header[0..header_size]);
            const body = out[header_size..][0..payload.len];
            @memcpy(body, payload);
            if (mask) |key| frame.apply_mask(key, body, 0);
            stream.send_size += @intCast(header_size + payload.len);
            stream.flush();
        }

        fn flush(stream: *Self) void {
            if (stream.send_pending or stream.send_offset == stream.send_size) return;
            assert(stream.send_offset < stream.send_size);
            stream.send_pending = true;
            const bytes = stream.send_buffer[stream.send_offset..stream.send_size];
            stream.io.send(*Self, stream, on_send, &stream.send_completion, stream.fd.?, bytes);
        }

        fn on_send(
            stream: *Self,
            completion: *IO.Completion,
            result: io_common.SendError!usize,
        ) void {
            assert(completion == &stream.send_completion);
            assert(stream.send_pending);
            stream.send_pending = false;
            if (stream.state == .shutting_down) return stream.maybe_finish();
            const size = result catch return stream.fail(error.SendFailed);
            stream.send_offset += @intCast(size);
            assert(stream.send_offset <= stream.send_size);
            // Compact while no send is in flight so sent bytes never fill the buffer.
            const remaining = stream.send_size - stream.send_offset;
            std.mem.copyForwards(
                u8,
                stream.send_buffer[0..remaining],
                stream.send_buffer[stream.send_offset..stream.send_size],
            );
            stream.send_offset = 0;
            stream.send_size = remaining;
            if (stream.close_received and remaining == 0) return stream.begin_shutdown();
            stream.flush();
        }

        fn recv(stream: *Self) void {
            assert(!stream.recv_pending);
            const free = stream.recv_buffer[stream.recv_size..];
            assert(free.len > 0);
            stream.recv_pending = true;
            stream.io.recv(*Self, stream, on_recv, &stream.recv_completion, stream.fd.?, free);
        }

        fn on_recv(
            stream: *Self,
            completion: *IO.Completion,
            result: io_common.RecvError!usize,
        ) void {
            assert(completion == &stream.recv_completion);
            assert(stream.recv_pending);
            stream.recv_pending = false;
            if (stream.state == .shutting_down) return stream.maybe_finish();
            const size = result catch return stream.fail(error.RecvFailed);
            if (size == 0) return stream.fail(error.ConnectionClosed);
            stream.recv_size += @intCast(size);
            if (stream.state == .handshaking) {
                Hooks.handshake(stream);
                if (stream.state == .handshaking) return stream.recv_more();
            }
            stream.process_frames();
            switch (stream.state) {
                .open, .closing => {
                    if (stream.close_received) return; // Waiting for the close echo to flush.
                    stream.recv_more();
                },
                else => {},
            }
        }

        fn recv_more(stream: *Self) void {
            if (stream.recv_size == stream.recv_buffer.len) {
                const too_large = if (stream.state == .handshaking)
                    error.HandshakeFailed
                else
                    error.MessageTooLarge;
                return stream.fail(too_large);
            }
            stream.recv();
        }

        fn process_frames(stream: *Self) void {
            const limits: frame.Limits = .{ .payload_size_max = stream.message_buffer.len };
            var offset: u32 = 0;
            // Each iteration consumes at least the 2-byte frame header.
            var iterations: u32 = 0;
            while (iterations <= stream.recv_size) : (iterations += 1) {
                if (stream.state != .open and stream.state != .closing) return;
                if (stream.close_received) break;
                const input = stream.recv_buffer[offset..stream.recv_size];
                const decoded = frame.decode_frame(input, stream.role, limits) catch |err| {
                    const failure = if (err == error.PayloadTooLarge)
                        error.MessageTooLarge
                    else
                        error.ProtocolError;
                    return stream.fail(failure);
                };
                switch (decoded) {
                    .incomplete => break,
                    .frame => |f| {
                        offset += @intCast(f.size);
                        stream.handle_frame(f.header, f.payload);
                    },
                }
            }
            if (stream.state == .shutting_down or stream.state == .idle) return;
            stream.consume(offset);
        }

        fn handle_frame(stream: *Self, header: frame.Header, payload: []const u8) void {
            switch (header.opcode) {
                .ping => stream.queue_frame(.pong, payload) catch {}, // Drop under pressure.
                .pong => stream.pongs_received +%= 1,
                .close => stream.handle_close(payload),
                .text, .binary => {
                    if (stream.message_opcode != null) return stream.fail(error.ProtocolError);
                    if (header.fin) return stream.deliver(header.opcode, payload);
                    stream.message_opcode = header.opcode;
                    stream.message_size = 0;
                    stream.append_fragment(payload);
                },
                .continuation => {
                    const opcode = stream.message_opcode orelse
                        return stream.fail(error.ProtocolError);
                    stream.append_fragment(payload);
                    if (!header.fin or stream.state == .shutting_down) return;
                    stream.message_opcode = null;
                    stream.deliver(opcode, stream.message_buffer[0..stream.message_size]);
                },
                _ => unreachable, // The decoder rejects unknown opcodes.
            }
        }

        fn append_fragment(stream: *Self, payload: []const u8) void {
            if (payload.len > stream.message_buffer.len - stream.message_size) {
                return stream.fail(error.MessageTooLarge);
            }
            @memcpy(stream.message_buffer[stream.message_size..][0..payload.len], payload);
            stream.message_size += @intCast(payload.len);
        }

        fn deliver(stream: *Self, opcode: Opcode, payload: []const u8) void {
            assert(opcode == .text or opcode == .binary);
            if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
                return stream.fail(error.InvalidUtf8);
            }
            Hooks.message(stream, .{ .opcode = opcode, .payload = payload });
        }

        fn handle_close(stream: *Self, payload: []const u8) void {
            const close_frame = frame.parse_close(payload) catch {
                return stream.fail(error.ProtocolError);
            };
            stream.close_code = if (close_frame) |c| c.code else null;
            stream.close_received = true;
            if (!stream.close_sent) {
                // Echo the status code (RFC 6455 section 5.5.1).
                const echo = if (close_frame != null) payload[0..2] else payload[0..0];
                stream.queue_frame(.close, echo) catch {};
                stream.close_sent = true;
            }
            stream.state = .closing;
            if (!stream.send_pending and stream.send_offset == stream.send_size) {
                stream.begin_shutdown();
            }
        }

        fn begin_shutdown(stream: *Self) void {
            if (stream.state == .shutting_down) return stream.maybe_finish();
            stream.state = .shutting_down;
            if (stream.fd) |fd| stream.io.shutdown_now(fd);
            stream.maybe_finish();
        }

        fn maybe_finish(stream: *Self) void {
            assert(stream.state == .shutting_down);
            if (stream.recv_pending or stream.send_pending) return;
            if (stream.fd) |fd| stream.io.close_now(fd);
            stream.fd = null;
            stream.state = .idle;
            Hooks.closed(stream, .{ .code = stream.close_code, .err = stream.failure });
        }

        pub fn next_random(stream: *Self) u64 {
            stream.random_state +%= 0x9e3779b97f4a7c15;
            var z = stream.random_state;
            z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
            z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
            return z ^ (z >> 31);
        }
    };
}

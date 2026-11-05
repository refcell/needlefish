//! WebSocket client on the completion-based IO (RFC 6455), e.g. for a flashblocks feed.
//!
//! One connection; a recv is always in flight once open, and sends are queued in a bounded
//! send buffer and flushed one at a time, so pings are answered while the caller streams.
//! Unfragmented messages are delivered straight from the receive buffer (no copy); fragmented
//! messages are reassembled in a message buffer. Protocol violations fail the connection
//! (no close frame is sent for them). Teardown shuts the socket down, waits for in-flight
//! operations to complete, then closes it and calls `on_close` exactly once.
//!
//! Masking keys and the handshake nonce come from a SplitMix64 stream seeded by
//! `Options.seed`, so simulator runs are reproducible. Production callers should seed it
//! from OS entropy.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../io/common.zig");
const http_parser = @import("../http/parser.zig");
const frame = @import("frame.zig");

pub const Address = io_common.Address;
pub const Opcode = frame.Opcode;

pub const Options = struct {
    message_size_max: u32 = 1 << 20,
    send_buffer_size: u32 = 64 * 1024,
    /// `Host` header value. Defaults to the server address when empty.
    host: []const u8 = "",
    target: []const u8 = "/",
    seed: u64 = 0,
};

pub const Error = error{
    ConnectFailed,
    HandshakeFailed,
    ConnectionClosed,
    RecvFailed,
    SendFailed,
    ProtocolError,
    MessageTooLarge,
    InvalidUtf8,
};

pub const SendError = error{ NotOpen, SendBufferFull };

pub const Message = struct { opcode: Opcode, payload: []const u8 };

pub const Closed = struct {
    /// The peer's close code; null when no close frame (or one without a code) arrived.
    code: ?u16,
    /// Why the connection failed; null after a clean close handshake or `abort`.
    err: ?Error,
};

pub fn Handlers(comptime ClientType: type, comptime Context: type) type {
    return struct {
        on_open: *const fn (Context, *ClientType) void,
        /// `message.payload` is valid only during the callback.
        on_message: *const fn (Context, *ClientType, Message) void,
        on_close: *const fn (Context, *ClientType, Closed) void,
    };
}

const handshake_head_size_max = 8 * 1024;

pub fn Client(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Fd = IO.Fd;

        pub const State = enum { idle, connecting, handshaking, open, closing, shutting_down };

        io: *IO,
        allocator: std.mem.Allocator,
        address: Address,
        options: Options,
        context: Context,
        handlers: *const Handlers(Self, Context),
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
        key: [frame.key_size]u8 = undefined,
        random_state: u64,
        close_sent: bool = false,
        close_received: bool = false,
        close_code: ?u16 = null,
        failure: ?Error = null,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            address: Address,
            options: Options,
            context: Context,
            handlers: *const Handlers(Self, Context),
        ) !Self {
            assert(options.message_size_max > 0);
            assert(options.send_buffer_size > frame.header_size_max + 125);
            const recv_size = @max(
                options.message_size_max + frame.header_size_max,
                handshake_head_size_max,
            );
            const recv_buffer = try allocator.alloc(u8, recv_size);
            errdefer allocator.free(recv_buffer);
            const send_buffer = try allocator.alloc(u8, options.send_buffer_size);
            errdefer allocator.free(send_buffer);
            const message_buffer = try allocator.alloc(u8, options.message_size_max);
            return .{
                .io = io,
                .allocator = allocator,
                .address = address,
                .options = options,
                .context = context,
                .handlers = handlers,
                .recv_buffer = recv_buffer,
                .send_buffer = send_buffer,
                .message_buffer = message_buffer,
                .random_state = options.seed,
            };
        }

        pub fn deinit(client: *Self) void {
            assert(client.state == .idle);
            assert(client.fd == null);
            client.allocator.free(client.message_buffer);
            client.allocator.free(client.send_buffer);
            client.allocator.free(client.recv_buffer);
            client.* = undefined;
        }

        /// Opens the connection. `on_open` or `on_close` follows. `client` must not move
        /// until `on_close` has run.
        pub fn connect(client: *Self) void {
            assert(client.state == .idle);
            assert(client.fd == null);
            client.recv_size = 0;
            client.send_size = 0;
            client.send_offset = 0;
            client.message_size = 0;
            client.message_opcode = null;
            client.close_sent = false;
            client.close_received = false;
            client.close_code = null;
            client.failure = null;
            const fd = client.io.open_socket_tcp(client.address.family) catch {
                client.state = .shutting_down;
                return client.fail(error.ConnectFailed);
            };
            client.fd = fd;
            client.state = .connecting;
            client.send_pending = true;
            const completion = &client.send_completion;
            client.io.connect(*Self, client, on_connect, completion, fd, client.address);
        }

        pub fn send_text(client: *Self, payload: []const u8) SendError!void {
            if (client.state != .open) return error.NotOpen;
            try client.queue_frame(.text, payload);
        }

        pub fn send_binary(client: *Self, payload: []const u8) SendError!void {
            if (client.state != .open) return error.NotOpen;
            try client.queue_frame(.binary, payload);
        }

        /// Starts the close handshake; `on_close` runs once the server echoes it.
        pub fn close(client: *Self, code: frame.CloseCode) void {
            if (client.state != .open) return;
            var payload: [2]u8 = undefined;
            std.mem.writeInt(u16, &payload, @backingInt(code), .big);
            client.queue_frame(.close, &payload) catch {
                // No room for the close frame: give up on the handshake.
                return client.abort();
            };
            client.close_sent = true;
            client.state = .closing;
        }

        /// Tears the connection down without a close handshake (e.g. a close timeout).
        pub fn abort(client: *Self) void {
            switch (client.state) {
                .idle, .shutting_down => return,
                else => client.begin_shutdown(),
            }
        }

        fn on_connect(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.ConnectError!void,
        ) void {
            assert(completion == &client.send_completion);
            assert(client.send_pending);
            client.send_pending = false;
            if (client.state == .shutting_down) return client.maybe_finish();
            assert(client.state == .connecting);
            result catch return client.fail(error.ConnectFailed);
            client.write_handshake() catch return client.fail(error.HandshakeFailed);
            client.state = .handshaking;
            client.flush();
            client.recv();
        }

        fn write_handshake(client: *Self) std.Io.Writer.Error!void {
            var nonce: [16]u8 = undefined;
            std.mem.writeInt(u64, nonce[0..8], client.next_random(), .little);
            std.mem.writeInt(u64, nonce[8..16], client.next_random(), .little);
            client.key = frame.client_key(nonce);
            var writer: std.Io.Writer = .fixed(client.send_buffer);
            try writer.print("GET {s} HTTP/1.1\r\n", .{client.options.target});
            if (client.options.host.len > 0) {
                try writer.print("Host: {s}\r\n", .{client.options.host});
            } else {
                try writer.print("Host: {f}\r\n", .{client.address});
            }
            try writer.writeAll("Upgrade: websocket\r\nConnection: Upgrade\r\n");
            try writer.print("Sec-WebSocket-Key: {s}\r\n", .{&client.key});
            try writer.writeAll("Sec-WebSocket-Version: 13\r\n\r\n");
            client.send_size = @intCast(writer.end);
            client.send_offset = 0;
        }

        fn queue_frame(client: *Self, opcode: Opcode, payload: []const u8) SendError!void {
            assert(client.fd != null);
            const free = client.send_buffer.len - client.send_size;
            if (frame.header_size_max + payload.len > free) return error.SendBufferFull;
            var mask: [4]u8 = undefined;
            std.mem.writeInt(u32, &mask, @truncate(client.next_random()), .little);
            var header: [frame.header_size_max]u8 = undefined;
            const header_size = frame.encode_header(&header, true, opcode, payload.len, mask);
            const out = client.send_buffer[client.send_size..];
            @memcpy(out[0..header_size], header[0..header_size]);
            const body = out[header_size..][0..payload.len];
            @memcpy(body, payload);
            frame.apply_mask(mask, body, 0);
            client.send_size += @intCast(header_size + payload.len);
            client.flush();
        }

        fn flush(client: *Self) void {
            if (client.send_pending or client.send_offset == client.send_size) return;
            assert(client.send_offset < client.send_size);
            client.send_pending = true;
            const bytes = client.send_buffer[client.send_offset..client.send_size];
            client.io.send(*Self, client, on_send, &client.send_completion, client.fd.?, bytes);
        }

        fn on_send(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.SendError!usize,
        ) void {
            assert(completion == &client.send_completion);
            assert(client.send_pending);
            client.send_pending = false;
            if (client.state == .shutting_down) return client.maybe_finish();
            const size = result catch return client.fail(error.SendFailed);
            client.send_offset += @intCast(size);
            assert(client.send_offset <= client.send_size);
            // Compact while no send is in flight so the buffer never fills with sent bytes.
            const remaining = client.send_size - client.send_offset;
            std.mem.copyForwards(
                u8,
                client.send_buffer[0..remaining],
                client.send_buffer[client.send_offset..client.send_size],
            );
            client.send_offset = 0;
            client.send_size = remaining;
            if (client.close_received and remaining == 0) return client.begin_shutdown();
            client.flush();
        }

        fn recv(client: *Self) void {
            assert(!client.recv_pending);
            const free = client.recv_buffer[client.recv_size..];
            assert(free.len > 0);
            client.recv_pending = true;
            client.io.recv(*Self, client, on_recv, &client.recv_completion, client.fd.?, free);
        }

        fn on_recv(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.RecvError!usize,
        ) void {
            assert(completion == &client.recv_completion);
            assert(client.recv_pending);
            client.recv_pending = false;
            if (client.state == .shutting_down) return client.maybe_finish();
            const size = result catch return client.fail(error.RecvFailed);
            if (size == 0) return client.fail(error.ConnectionClosed);
            client.recv_size += @intCast(size);
            if (client.state == .handshaking) {
                client.handle_handshake();
                if (client.state == .handshaking) return client.recv_more();
            }
            client.process_frames();
            switch (client.state) {
                .open, .closing => {
                    if (client.close_received) return; // Waiting for the close echo to flush.
                    client.recv_more();
                },
                else => {},
            }
        }

        fn recv_more(client: *Self) void {
            if (client.recv_size == client.recv_buffer.len) {
                const too_large = if (client.state == .handshaking)
                    error.HandshakeFailed
                else
                    error.MessageTooLarge;
                return client.fail(too_large);
            }
            client.recv();
        }

        fn handle_handshake(client: *Self) void {
            const limits: http_parser.Limits = .{
                .head_size_max = handshake_head_size_max,
                .body_size_max = 0,
            };
            const input = client.recv_buffer[0..client.recv_size];
            const parsed = http_parser.parse_response(input, limits, .GET) catch {
                return client.fail(error.HandshakeFailed);
            };
            const complete = switch (parsed) {
                .incomplete => return,
                .complete => |complete| complete,
            };
            if (!client.handshake_valid(&complete.message)) {
                return client.fail(error.HandshakeFailed);
            }
            const consumed: u32 = @intCast(complete.consumed);
            const leftover = client.recv_size - consumed;
            std.mem.copyForwards(
                u8,
                client.recv_buffer[0..leftover],
                client.recv_buffer[consumed..client.recv_size],
            );
            client.recv_size = leftover;
            client.state = .open;
            client.handlers.on_open(client.context, client);
        }

        fn handshake_valid(client: *const Self, response: *const http_parser.Response) bool {
            if (response.status != 101) return false;
            const upgrade = response.headers.get("upgrade") orelse return false;
            if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return false;
            const connection = response.headers.get("connection") orelse return false;
            if (std.ascii.findIgnoreCase(connection, "upgrade") == null) return false;
            const accept = response.headers.get("sec-websocket-accept") orelse return false;
            const expected = frame.accept_key(&client.key);
            return std.mem.eql(u8, accept, &expected);
        }

        fn process_frames(client: *Self) void {
            const limits: frame.Limits = .{ .payload_size_max = client.options.message_size_max };
            var offset: u32 = 0;
            // Each iteration consumes at least the 2-byte frame header.
            var iterations: u32 = 0;
            while (iterations <= client.recv_size) : (iterations += 1) {
                if (client.state != .open and client.state != .closing) return;
                if (client.close_received) break;
                const input = client.recv_buffer[offset..client.recv_size];
                const decoded = frame.decode_frame(input, .client, limits) catch |err| {
                    const failure = if (err == error.PayloadTooLarge)
                        error.MessageTooLarge
                    else
                        error.ProtocolError;
                    return client.fail(failure);
                };
                switch (decoded) {
                    .incomplete => break,
                    .frame => |f| {
                        offset += @intCast(f.size);
                        client.handle_frame(f.header, f.payload);
                    },
                }
            }
            if (client.state == .shutting_down or client.state == .idle) return;
            const remaining = client.recv_size - offset;
            std.mem.copyForwards(
                u8,
                client.recv_buffer[0..remaining],
                client.recv_buffer[offset..client.recv_size],
            );
            client.recv_size = remaining;
        }

        fn handle_frame(client: *Self, header: frame.Header, payload: []const u8) void {
            switch (header.opcode) {
                .ping => client.queue_frame(.pong, payload) catch {}, // Drop under pressure.
                .pong => {},
                .close => client.handle_close(payload),
                .text, .binary => {
                    if (client.message_opcode != null) return client.fail(error.ProtocolError);
                    if (header.fin) return client.deliver(header.opcode, payload);
                    client.message_opcode = header.opcode;
                    client.message_size = 0;
                    client.append_fragment(payload);
                },
                .continuation => {
                    const opcode = client.message_opcode orelse
                        return client.fail(error.ProtocolError);
                    client.append_fragment(payload);
                    if (!header.fin or client.state == .shutting_down) return;
                    client.message_opcode = null;
                    client.deliver(opcode, client.message_buffer[0..client.message_size]);
                },
                _ => unreachable, // The decoder rejects unknown opcodes.
            }
        }

        fn append_fragment(client: *Self, payload: []const u8) void {
            if (payload.len > client.message_buffer.len - client.message_size) {
                return client.fail(error.MessageTooLarge);
            }
            @memcpy(client.message_buffer[client.message_size..][0..payload.len], payload);
            client.message_size += @intCast(payload.len);
        }

        fn deliver(client: *Self, opcode: Opcode, payload: []const u8) void {
            assert(opcode == .text or opcode == .binary);
            if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
                return client.fail(error.InvalidUtf8);
            }
            client.handlers.on_message(client.context, client, .{
                .opcode = opcode,
                .payload = payload,
            });
        }

        fn handle_close(client: *Self, payload: []const u8) void {
            const close_frame = frame.parse_close(payload) catch {
                return client.fail(error.ProtocolError);
            };
            client.close_code = if (close_frame) |c| c.code else null;
            client.close_received = true;
            if (!client.close_sent) {
                // Echo the status code (RFC 6455 section 5.5.1).
                const echo = if (close_frame != null) payload[0..2] else payload[0..0];
                client.queue_frame(.close, echo) catch {};
                client.close_sent = true;
            }
            client.state = .closing;
            if (!client.send_pending and client.send_offset == client.send_size) {
                client.begin_shutdown();
            }
        }

        fn fail(client: *Self, err: Error) void {
            if (client.failure == null) client.failure = err;
            client.begin_shutdown();
        }

        fn begin_shutdown(client: *Self) void {
            if (client.state == .shutting_down and client.fd != null) {
                return client.maybe_finish();
            }
            client.state = .shutting_down;
            if (client.fd) |fd| client.io.shutdown_now(fd);
            client.maybe_finish();
        }

        fn maybe_finish(client: *Self) void {
            assert(client.state == .shutting_down);
            if (client.recv_pending or client.send_pending) return;
            if (client.fd) |fd| client.io.close_now(fd);
            client.fd = null;
            client.state = .idle;
            client.handlers.on_close(client.context, client, .{
                .code = client.close_code,
                .err = client.failure,
            });
        }

        fn next_random(client: *Self) u64 {
            client.random_state +%= 0x9e3779b97f4a7c15;
            var z = client.random_state;
            z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
            z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
            return z ^ (z >> 31);
        }
    };
}

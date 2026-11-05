//! WebSocket server on the completion-based IO (RFC 6455): subscriptions and feeds.
//!
//! A fixed pool of connections is allocated at `init`; extra connections are closed on
//! accept. Each connection performs the HTTP upgrade handshake, then runs the shared frame
//! engine (`stream.zig`). Connections are addressed by `ConnectionId` (slot index plus a
//! generation), so a stale id never reaches a reused slot. `broadcast` queues one message to
//! every open connection and disconnects consumers whose send buffer is full (`SlowConsumer`),
//! so one slow subscriber never stalls the feed.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../io/common.zig");
const http_parser = @import("../http/parser.zig");
const frame = @import("frame.zig");
const stream_module = @import("stream.zig");

pub const Address = io_common.Address;
pub const Opcode = frame.Opcode;
pub const Error = stream_module.Error;
pub const SendError = stream_module.SendError;
pub const Message = stream_module.Message;
pub const Closed = stream_module.Closed;

pub const Options = struct {
    connections_max: u32 = 64,
    message_size_max: u32 = 1 << 20,
    send_buffer_size: u32 = 1 << 20,
    backlog: u31 = 128,
};

pub const ConnectionId = struct { index: u32, generation: u32 };

pub fn Handlers(comptime ServerType: type, comptime Context: type) type {
    return struct {
        on_open: *const fn (Context, *ServerType, ConnectionId) void,
        /// `message.payload` is valid only during the callback.
        on_message: *const fn (Context, *ServerType, ConnectionId, Message) void,
        on_close: *const fn (Context, *ServerType, ConnectionId, Closed) void,
    };
}

const handshake_head_size_max = 8 * 1024;
const accept_backoff_ns = 10 * std.time.ns_per_ms;

pub fn Server(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Fd = IO.Fd;
        const Stream = stream_module.Stream(IO, Hooks);

        const Connection = struct {
            server: *Self,
            index: u32,
            generation: u32 = 0,
            stream: Stream,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        context: Context,
        handlers: *const Handlers(Self, Context),
        options: Options,
        listener: Fd = undefined,
        address: Address = undefined,
        accept_completion: IO.Completion = .{},
        /// `accept_completion` is in flight (an accept or the accept backoff timeout).
        accept_pending: bool = false,
        listener_open: bool = false,
        listening: bool = false,
        connections: []Connection,
        memory: []u8,
        connections_rejected: u64 = 0,
        slow_consumers_dropped: u64 = 0,

        /// `server` must not move after `init`.
        pub fn init(
            server: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            context: Context,
            handlers: *const Handlers(Self, Context),
            options: Options,
        ) !void {
            assert(options.connections_max > 0);
            const recv_size = @max(
                options.message_size_max + frame.header_size_max,
                handshake_head_size_max,
            );
            const per_connection = recv_size + options.send_buffer_size +
                options.message_size_max;
            const memory = try allocator.alloc(u8, per_connection * options.connections_max);
            errdefer allocator.free(memory);
            const connections = try allocator.alloc(Connection, options.connections_max);
            for (connections, 0..) |*connection, index| {
                const base = memory[index * per_connection ..][0..per_connection];
                connection.* = .{
                    .server = server,
                    .index = @intCast(index),
                    .stream = Stream.init(
                        io,
                        .server,
                        base[0..recv_size],
                        base[recv_size..][0..options.send_buffer_size],
                        base[recv_size + options.send_buffer_size ..],
                        index,
                    ),
                };
            }
            server.* = .{
                .io = io,
                .allocator = allocator,
                .context = context,
                .handlers = handlers,
                .options = options,
                .connections = connections,
                .memory = memory,
            };
        }

        /// Requires `stopped()`.
        pub fn deinit(server: *Self) void {
            assert(server.stopped());
            server.allocator.free(server.connections);
            server.allocator.free(server.memory);
            server.* = undefined;
        }

        /// Binds, listens, and starts accepting. Returns the bound address.
        pub fn listen(server: *Self, address: Address) !Address {
            assert(!server.listening);
            server.listener = try server.io.open_socket_tcp(address.family);
            errdefer server.io.close_now(server.listener);
            server.address = try server.io.listen(server.listener, address, server.options.backlog);
            server.listening = true;
            server.listener_open = true;
            server.accept();
            return server.address;
        }

        /// Stops accepting and aborts every connection; each gets its `on_close`. The
        /// in-flight accept is canceled; run the IO until `stopped()` before `deinit`.
        pub fn stop(server: *Self) void {
            server.listening = false;
            if (server.accept_pending) {
                server.io.cancel(&server.accept_completion);
            } else {
                server.close_listener();
            }
            for (server.connections) |*connection| connection.stream.abort();
        }

        /// True once the listener is closed and every connection has reported `on_close`.
        pub fn stopped(server: *const Self) bool {
            if (server.accept_pending or server.listener_open) return false;
            for (server.connections) |*connection| {
                if (connection.stream.state != .idle) return false;
            }
            return true;
        }

        fn close_listener(server: *Self) void {
            if (!server.listener_open) return;
            server.listener_open = false;
            server.io.close_now(server.listener);
        }

        pub fn connections_open(server: *const Self) u32 {
            var count: u32 = 0;
            for (server.connections) |*connection| {
                count += @intFromBool(connection.stream.state == .open);
            }
            return count;
        }

        pub fn send(
            server: *Self,
            id: ConnectionId,
            opcode: Opcode,
            payload: []const u8,
        ) SendError!void {
            const connection = server.lookup(id) orelse return error.NotOpen;
            try connection.stream.send(opcode, payload);
        }

        pub fn close(server: *Self, id: ConnectionId, code: frame.CloseCode) void {
            const connection = server.lookup(id) orelse return;
            connection.stream.close(code);
        }

        /// Queues `payload` to every open connection. Returns how many accepted it; the rest
        /// were too far behind and are being disconnected.
        pub fn broadcast(server: *Self, opcode: Opcode, payload: []const u8) u32 {
            var delivered: u32 = 0;
            for (server.connections) |*connection| {
                if (connection.stream.state != .open) continue;
                if (connection.stream.send(opcode, payload)) |_| {
                    delivered += 1;
                } else |_| {
                    server.slow_consumers_dropped += 1;
                    connection.stream.fail(error.SlowConsumer);
                }
            }
            return delivered;
        }

        fn lookup(server: *Self, id: ConnectionId) ?*Connection {
            if (id.index >= server.connections.len) return null;
            const connection = &server.connections[id.index];
            if (connection.generation != id.generation) return null;
            if (connection.stream.state == .idle) return null;
            return connection;
        }

        fn accept(server: *Self) void {
            assert(!server.accept_pending);
            server.accept_pending = true;
            server.io.accept(*Self, server, on_accept, &server.accept_completion, server.listener);
        }

        fn on_accept(
            server: *Self,
            completion: *IO.Completion,
            result: io_common.AcceptError!Fd,
        ) void {
            assert(completion == &server.accept_completion);
            assert(server.accept_pending);
            server.accept_pending = false;
            if (!server.listening) {
                if (result) |fd| server.io.close_now(fd) else |_| {}
                return server.close_listener();
            }
            const fd = result catch {
                // Back off instead of spinning on a persistent error like EMFILE.
                server.accept_pending = true;
                server.io.timeout(*Self, server, on_accept_backoff, completion, accept_backoff_ns);
                return;
            };
            server.accept();
            for (server.connections) |*connection| {
                if (connection.stream.state != .idle) continue;
                connection.generation +%= 1;
                connection.stream.start(fd);
                return;
            }
            server.connections_rejected += 1;
            server.io.close_now(fd);
        }

        fn on_accept_backoff(
            server: *Self,
            completion: *IO.Completion,
            result: io_common.TimeoutError!void,
        ) void {
            _ = completion;
            result catch {}; // Canceled by `stop`, handled below.
            assert(server.accept_pending);
            server.accept_pending = false;
            if (!server.listening) return server.close_listener();
            server.accept();
        }

        fn connection_id(connection: *const Connection) ConnectionId {
            return .{ .index = connection.index, .generation = connection.generation };
        }

        const Hooks = struct {
            fn owner(stream: *Stream) *Connection {
                return @fieldParentPtr("stream", stream);
            }

            pub fn handshake(stream: *Stream) void {
                const connection = owner(stream);
                const limits: http_parser.Limits = .{
                    .head_size_max = handshake_head_size_max,
                    .body_size_max = 0,
                };
                const parsed = http_parser.parse_request(stream.buffered(), limits) catch {
                    return reject(stream);
                };
                const complete = switch (parsed) {
                    .incomplete => return,
                    .complete => |complete| complete,
                };
                const key = handshake_key(&complete.message) orelse return reject(stream);
                var response: [256]u8 = undefined;
                const bytes = std.fmt.bufPrint(
                    &response,
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
                        "Connection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
                    .{&frame.accept_key(key)},
                ) catch unreachable; // The response has a fixed size.
                stream.consume(@intCast(complete.consumed));
                stream.send_raw(bytes) catch unreachable; // The send buffer starts empty.
                stream.open();
                const server = connection.server;
                server.handlers.on_open(server.context, server, connection_id(connection));
            }

            fn reject(stream: *Stream) void {
                // Best effort 400; the stream shuts down after the send completes or fails.
                stream.send_raw("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n" ++
                    "Connection: close\r\n\r\n") catch {};
                stream.fail_after_flush(error.HandshakeFailed);
            }

            pub fn message(stream: *Stream, incoming: Message) void {
                const connection = owner(stream);
                const server = connection.server;
                const id = connection_id(connection);
                server.handlers.on_message(server.context, server, id, incoming);
            }

            pub fn closed(stream: *Stream, result: Closed) void {
                const connection = owner(stream);
                const server = connection.server;
                const id = connection_id(connection);
                server.handlers.on_close(server.context, server, id, result);
            }
        };
    };
}

/// The client's `Sec-WebSocket-Key` if `request` is a valid upgrade request.
pub fn handshake_key(request: *const http_parser.Request) ?[]const u8 {
    if (request.method != .GET) return null;
    const upgrade = request.headers.get("upgrade") orelse return null;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return null;
    const connection = request.headers.get("connection") orelse return null;
    if (std.ascii.findIgnoreCase(connection, "upgrade") == null) return null;
    const version = request.headers.get("sec-websocket-version") orelse return null;
    if (!std.mem.eql(u8, version, "13")) return null;
    const key = request.headers.get("sec-websocket-key") orelse return null;
    if (key.len != frame.key_size) return null;
    return key;
}

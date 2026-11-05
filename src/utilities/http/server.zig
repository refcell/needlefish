//! HTTP/1.1 server on the completion-based IO.
//!
//! A fixed pool of connections, each with its own receive and send buffers, is allocated at
//! `init`; nothing allocates afterwards. Each connection has one operation in flight at a
//! time (recv, send, or close), which keeps its state machine simple. Requests are handled
//! synchronously by a comptime `handler` that writes the body into a `ResponseBuilder`.
//! Pipelined requests already in the receive buffer are answered in order before reading
//! more. When the pool is full, new connections are closed immediately.
//!
//! Timeouts: the owner calls `tick()` from its event loop (every few hundred milliseconds).
//! A connection waiting for a new request longer than `idle_timeout_ns`, or making no
//! progress on a partial request or a response for `io_timeout_ns`, is shut down; its pending
//! operation then completes and the connection closes normally. There are no per-connection
//! timers, so nothing is left in flight after `stop`.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../io/common.zig");
const parser = @import("parser.zig");

pub const Address = io_common.Address;

const head_reserve_size = 1024;
const extra_headers_max = 8;
const accept_backoff_ns = 10 * std.time.ns_per_ms;

pub const Options = struct {
    connections_max: u32 = 64,
    recv_buffer_size: u32 = 64 * 1024,
    send_buffer_size: u32 = 256 * 1024,
    backlog: u31 = 128,
    limits: parser.Limits = .{ .head_size_max = 8 * 1024, .body_size_max = 56 * 1024 },
    /// Keep-alive connections with no request in progress. Zero disables.
    idle_timeout_ns: u64 = 60 * std.time.ns_per_s,
    /// No progress on a partially received request or an unsent response. Zero disables.
    io_timeout_ns: u64 = 30 * std.time.ns_per_s,
};

pub fn reason_phrase(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        else => "Unknown",
    };
}

/// Builds one response in the connection's send buffer. The body is written first through
/// `writer()`; the head is placed directly in front of it when the response is finished, so
/// the body is never copied.
pub const ResponseBuilder = struct {
    buffer: []u8,
    body: std.Io.Writer,
    status: u16 = 200,
    content_type: []const u8 = "application/json",
    extra_headers: [extra_headers_max]parser.Header = undefined,
    extra_headers_count: u32 = 0,

    pub fn init(buffer: []u8) ResponseBuilder {
        assert(buffer.len > head_reserve_size);
        return .{ .buffer = buffer, .body = .fixed(buffer[head_reserve_size..]) };
    }

    pub fn writer(builder: *ResponseBuilder) *std.Io.Writer {
        return &builder.body;
    }

    pub fn header(builder: *ResponseBuilder, name: []const u8, value: []const u8) void {
        assert(builder.extra_headers_count < extra_headers_max);
        builder.extra_headers[builder.extra_headers_count] = .{ .name = name, .value = value };
        builder.extra_headers_count += 1;
    }

    /// Discards the body written so far and replies with a short plain-text error.
    pub fn fail(builder: *ResponseBuilder, status: u16) void {
        assert(status >= 400);
        builder.body = .fixed(builder.buffer[head_reserve_size..]);
        builder.status = status;
        builder.content_type = "text/plain";
        builder.extra_headers_count = 0;
        builder.body.writeAll(reason_phrase(status)) catch unreachable; // Fits by construction.
    }

    /// Returns the bytes to send: head followed by body. A body that overflowed the buffer
    /// becomes a 500 response.
    fn finish(builder: *ResponseBuilder, keep_alive: bool) []const u8 {
        if (builder.body.end == builder.body.buffer.len) builder.fail(500);
        var head_buffer: [head_reserve_size]u8 = undefined;
        var head: std.Io.Writer = .fixed(&head_buffer);
        builder.write_head(&head, keep_alive) catch {
            // Extra headers too large for the reserve: drop them and send a bare 500.
            builder.fail(500);
            head = .fixed(&head_buffer);
            builder.write_head(&head, false) catch unreachable;
        };
        const head_bytes = head.buffered();
        const start = head_reserve_size - head_bytes.len;
        @memcpy(builder.buffer[start..head_reserve_size], head_bytes);
        const end = head_reserve_size + builder.body.end;
        assert(end <= builder.buffer.len);
        return builder.buffer[start..end];
    }

    fn write_head(builder: *ResponseBuilder, head: *std.Io.Writer, keep_alive: bool) !void {
        try head.print("HTTP/1.1 {d} {s}\r\n", .{ builder.status, reason_phrase(builder.status) });
        try head.print("Content-Type: {s}\r\n", .{builder.content_type});
        try head.print("Content-Length: {d}\r\n", .{builder.body.end});
        if (!keep_alive) try head.writeAll("Connection: close\r\n");
        for (builder.extra_headers[0..builder.extra_headers_count]) |extra| {
            try head.print("{s}: {s}\r\n", .{ extra.name, extra.value });
        }
        try head.writeAll("\r\n");
    }
};

/// The request handler signature for a server with context type `Context`.
pub fn Handler(comptime Context: type) type {
    return fn (Context, *const parser.Request, *ResponseBuilder) void;
}

/// `handler(context, request, response)` is called once per request.
pub fn Server(comptime IO: type, comptime Context: type, comptime handler: Handler(Context)) type {
    return struct {
        const Self = @This();
        const Fd = IO.Fd;

        const State = enum { free, receiving, sending, closing };

        const Connection = struct {
            server: *Self,
            fd: Fd = undefined,
            state: State = .free,
            completion: IO.Completion = .{},
            recv_buffer: []u8,
            recv_size: u32 = 0,
            send_buffer: []u8,
            send_remaining: []const u8 = "",
            /// Bytes of `recv_buffer` used by the request being answered.
            consumed: u32 = 0,
            keep_alive: bool = false,
            last_progress_ns: u64 = 0,
            timed_out: bool = false,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        context: Context,
        options: Options,
        listener: Fd = undefined,
        address: Address = undefined,
        accept_completion: IO.Completion = .{},
        stopping: bool = false,
        connections: []Connection,
        memory: []u8,
        requests_handled: u64 = 0,
        connections_rejected: u64 = 0,
        connections_timed_out: u64 = 0,

        /// `server` must not move after `init`.
        pub fn init(
            server: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            context: Context,
            options: Options,
        ) !void {
            assert(options.connections_max > 0);
            assert(options.send_buffer_size > head_reserve_size);
            const limits = options.limits;
            assert(options.recv_buffer_size >= limits.head_size_max + limits.body_size_max);
            const per_connection = options.recv_buffer_size + options.send_buffer_size;
            const memory_size = @as(usize, per_connection) * options.connections_max;
            const memory = try allocator.alloc(u8, memory_size);
            errdefer allocator.free(memory);
            const connections = try allocator.alloc(Connection, options.connections_max);
            for (connections, 0..) |*connection, index| {
                const base = memory[index * per_connection ..][0..per_connection];
                connection.* = .{
                    .server = server,
                    .recv_buffer = base[0..options.recv_buffer_size],
                    .send_buffer = base[options.recv_buffer_size..],
                };
            }
            server.* = .{
                .io = io,
                .allocator = allocator,
                .context = context,
                .options = options,
                .connections = connections,
                .memory = memory,
            };
        }

        pub fn deinit(server: *Self) void {
            server.allocator.free(server.connections);
            server.allocator.free(server.memory);
            server.* = undefined;
        }

        /// Binds, listens, and starts accepting. Returns the bound address.
        pub fn listen(server: *Self, address: Address) !Address {
            server.listener = try server.io.open_socket_tcp(address.family);
            errdefer server.io.close_now(server.listener);
            server.address = try server.io.listen(server.listener, address, server.options.backlog);
            server.accept();
            return server.address;
        }

        /// Stops accepting new connections. Open connections finish their current request.
        pub fn stop(server: *Self) void {
            assert(!server.stopping);
            server.stopping = true;
            server.io.close_now(server.listener);
        }

        pub fn connections_open(server: *const Self) u32 {
            var count: u32 = 0;
            for (server.connections) |*connection| count += @intFromBool(connection.state != .free);
            return count;
        }

        /// Shuts down connections that exceeded their timeout. Call periodically.
        pub fn tick(server: *Self) void {
            const now_ns = server.io.now_monotonic_ns();
            for (server.connections) |*connection| {
                if (connection.timed_out) continue;
                const timeout_ns = switch (connection.state) {
                    .free, .closing => continue,
                    .receiving => if (connection.recv_size == 0)
                        server.options.idle_timeout_ns
                    else
                        server.options.io_timeout_ns,
                    .sending => server.options.io_timeout_ns,
                };
                if (timeout_ns == 0) continue;
                if (now_ns -| connection.last_progress_ns < timeout_ns) continue;
                connection.timed_out = true;
                server.connections_timed_out += 1;
                server.io.shutdown_now(connection.fd);
            }
        }

        fn accept(server: *Self) void {
            server.io.accept(*Self, server, on_accept, &server.accept_completion, server.listener);
        }

        fn on_accept(
            server: *Self,
            completion: *IO.Completion,
            result: io_common.AcceptError!Fd,
        ) void {
            assert(completion == &server.accept_completion);
            if (server.stopping) {
                if (result) |fd| server.io.close_now(fd) else |_| {}
                return;
            }
            const fd = result catch {
                // Back off instead of spinning on a persistent error like EMFILE.
                server.io.timeout(*Self, server, on_accept_backoff, completion, accept_backoff_ns);
                return;
            };
            server.accept();
            const connection = server.connection_acquire() orelse {
                server.connections_rejected += 1;
                server.io.close_now(fd);
                return;
            };
            connection.fd = fd;
            connection.recv_size = 0;
            connection.timed_out = false;
            connection.last_progress_ns = server.io.now_monotonic_ns();
            connection_recv(connection);
        }

        fn on_accept_backoff(
            server: *Self,
            completion: *IO.Completion,
            result: io_common.TimeoutError!void,
        ) void {
            _ = completion;
            result catch {};
            if (!server.stopping) server.accept();
        }

        fn connection_acquire(server: *Self) ?*Connection {
            for (server.connections) |*connection| {
                if (connection.state == .free) {
                    connection.state = .receiving;
                    return connection;
                }
            }
            return null;
        }

        fn connection_recv(connection: *Connection) void {
            assert(connection.recv_size < connection.recv_buffer.len);
            connection.state = .receiving;
            const free = connection.recv_buffer[connection.recv_size..];
            const io = connection.server.io;
            io.recv(*Connection, connection, on_recv, &connection.completion, connection.fd, free);
        }

        fn on_recv(
            connection: *Connection,
            completion: *IO.Completion,
            result: io_common.RecvError!usize,
        ) void {
            assert(completion == &connection.completion);
            assert(connection.state == .receiving);
            const size = result catch return connection_close(connection);
            if (size == 0) return connection_close(connection);
            connection.last_progress_ns = connection.server.io.now_monotonic_ns();
            connection.recv_size += @intCast(size);
            assert(connection.recv_size <= connection.recv_buffer.len);
            connection_process(connection);
        }

        /// Answers the next buffered request, or reads more if none is complete.
        fn connection_process(connection: *Connection) void {
            const server = connection.server;
            const buffered = connection.recv_buffer[0..connection.recv_size];
            const parsed = parser.parse_request(buffered, server.options.limits) catch |err| {
                const status: u16 = switch (err) {
                    error.BodyTooLarge, error.HeadTooLarge => 413,
                    else => 400,
                };
                return connection_reply_error(connection, status);
            };
            switch (parsed) {
                .incomplete => {
                    if (connection.recv_size == connection.recv_buffer.len) {
                        return connection_reply_error(connection, 413);
                    }
                    connection_recv(connection);
                },
                .complete => |complete| {
                    var builder = ResponseBuilder.init(connection.send_buffer);
                    handler(server.context, &complete.message, &builder);
                    server.requests_handled += 1;
                    connection.consumed = complete.consumed;
                    connection.keep_alive = complete.message.keep_alive and !server.stopping;
                    connection_send(connection, builder.finish(connection.keep_alive));
                },
            }
        }

        fn connection_reply_error(connection: *Connection, status: u16) void {
            var builder = ResponseBuilder.init(connection.send_buffer);
            builder.fail(status);
            // The rest of the buffer cannot be trusted after a framing error: close after.
            connection.consumed = connection.recv_size;
            connection.keep_alive = false;
            connection_send(connection, builder.finish(false));
        }

        fn connection_send(connection: *Connection, bytes: []const u8) void {
            assert(bytes.len > 0);
            connection.state = .sending;
            connection.send_remaining = bytes;
            const io = connection.server.io;
            io.send(*Connection, connection, on_send, &connection.completion, connection.fd, bytes);
        }

        fn on_send(
            connection: *Connection,
            completion: *IO.Completion,
            result: io_common.SendError!usize,
        ) void {
            assert(completion == &connection.completion);
            assert(connection.state == .sending);
            const size = result catch return connection_close(connection);
            assert(size <= connection.send_remaining.len);
            connection.last_progress_ns = connection.server.io.now_monotonic_ns();
            connection.send_remaining = connection.send_remaining[size..];
            if (connection.send_remaining.len > 0) {
                return connection_send(connection, connection.send_remaining);
            }
            if (!connection.keep_alive) return connection_close(connection);
            // Drop the answered request; pipelined bytes move to the front.
            const rest = connection.recv_buffer[connection.consumed..connection.recv_size];
            std.mem.copyForwards(u8, connection.recv_buffer[0..rest.len], rest);
            connection.recv_size = @intCast(rest.len);
            connection.consumed = 0;
            connection_process(connection);
        }

        fn connection_close(connection: *Connection) void {
            assert(connection.state != .free);
            assert(connection.state != .closing);
            connection.state = .closing;
            const io = connection.server.io;
            io.close(*Connection, connection, on_close, &connection.completion, connection.fd);
        }

        fn on_close(
            connection: *Connection,
            completion: *IO.Completion,
            result: io_common.CloseError!void,
        ) void {
            assert(completion == &connection.completion);
            assert(connection.state == .closing);
            result catch {}; // The descriptor is released either way.
            connection.state = .free;
            connection.recv_size = 0;
        }
    };
}

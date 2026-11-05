//! HTTP/1.1 server on the completion-based IO.
//!
//! A fixed pool of connections, each with its own receive and send buffers, is allocated at
//! `init`; nothing allocates afterwards. Each connection has one operation in flight at a
//! time (recv, send, or close), which keeps its state machine simple. Requests are handled
//! synchronously by a comptime `handler` that writes the body into a `ResponseBuilder`.
//! Pipelined requests already in the receive buffer are answered in order before reading
//! more. When the pool is full, new connections are closed immediately.
//!
//! Large responses: an optional pool of larger send buffers (`large_send_buffers_max` x
//! `large_send_buffer_size`) is shared by all connections, reserved at `init` and committed
//! by the OS only when written (`lazy_alloc`). A handler that asks the response writer for
//! more capacity than the connection's buffer has left (`std.Io.Writer.ensureUnusedCapacity`
//! or any other rebase) moves the response written so far into a free large buffer, which
//! the connection holds until that response is sent. Plain writes past the end still fail,
//! so only handlers that size their output up front use the pool. With none free, the
//! rebase fails like a full buffer.
//!
//! Deferred responses: a handler that cannot answer synchronously (a proxy waiting on an
//! upstream) calls `ResponseBuilder.defer_response()` and keeps the returned `Deferred` token.
//! The connection is parked with no operation in flight and the request bytes kept in its
//! receive buffer, so the request's slices stay valid until the response is resumed with
//! `resume_deferred`. A stale token (the connection timed out or the server stopped) is
//! rejected. A parked connection that is not resumed within `io_timeout_ns` is answered with
//! 504 and closed; `stop` answers parked connections with 503.
//!
//! Timeouts: the owner calls `tick()` from its event loop (every few hundred milliseconds).
//! A connection waiting for a new request longer than `idle_timeout_ns`, or making no
//! progress on a partial request or a response for `io_timeout_ns`, is shut down; its pending
//! operation then completes and the connection closes normally. There are no per-connection
//! timers, so nothing is left in flight after `stop`.

const std = @import("std");
const lazy_alloc = @import("../lazy_alloc/root.zig");
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
    /// Shared large send buffers (see the module comment). Zero disables.
    large_send_buffers_max: u32 = 0,
    /// Size of each large send buffer, head reserve included; above `send_buffer_size`.
    large_send_buffer_size: u32 = 0,
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
        429 => "Too Many Requests",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "Unknown",
    };
}

/// Hands a response a larger send buffer of at least `size_bytes`, or null if none is free.
pub const Grow = struct {
    context: *anyopaque,
    acquire: *const fn (context: *anyopaque, size_bytes: usize) ?[]u8,
};

/// Identifies a parked (deferred) response: connection slot and its generation, so a token
/// outlives neither a timeout nor a reuse of the slot.
pub const Deferred = struct {
    index: u32,
    generation: u32,
};

/// Parks the connection that owns a response (set by the server; null outside it).
pub const Park = struct {
    context: *anyopaque,
    park: *const fn (context: *anyopaque) Deferred,
};

/// Builds one response in the connection's send buffer. The body is written first through
/// `writer()`; the head is placed directly in front of it when the response is finished, so
/// the body is never copied (except once, when it moves into a larger buffer via `grow`).
/// The builder must not move once the body has been written to.
pub const ResponseBuilder = struct {
    buffer: []u8,
    /// Source of a larger buffer for a rebase of the body writer (null: rebases fail).
    grow: ?Grow = null,
    grown: bool = false,
    /// The client's socket address (unspecified 0.0.0.0:0 if the backend cannot tell).
    /// Behind a load balancer, resolve the real client with `trusted_proxy`.
    peer: Address = Address.ip4(.{ 0, 0, 0, 0 }, 0),
    body: std.Io.Writer,
    status: u16 = 200,
    content_type: []const u8 = "application/json",
    extra_headers: [extra_headers_max]parser.Header = undefined,
    extra_headers_count: u32 = 0,
    /// How to park this response's connection (null: deferral is not supported).
    park: ?Park = null,
    /// Set by `defer_response`: the server sends nothing when the handler returns.
    deferred: ?Deferred = null,

    pub fn init(buffer: []u8) ResponseBuilder {
        assert(buffer.len > head_reserve_size);
        return .{ .buffer = buffer, .body = body_writer(buffer) };
    }

    const body_vtable: std.Io.Writer.VTable = .{
        .drain = std.Io.Writer.fixedDrain,
        .flush = std.Io.Writer.noopFlush,
        .rebase = body_rebase,
    };

    /// A fixed writer over the body part of `buffer` whose rebase can grow (`grow`).
    fn body_writer(buffer: []u8) std.Io.Writer {
        assert(buffer.len > head_reserve_size);
        return .{ .vtable = &body_vtable, .buffer = buffer[head_reserve_size..] };
    }

    /// Moves the body into a larger buffer with `capacity` bytes free after it. Everything
    /// written so far is kept, so `preserve` holds trivially and offsets stay valid.
    fn body_rebase(body: *std.Io.Writer, preserve: usize, capacity: usize) error{WriteFailed}!void {
        const builder: *ResponseBuilder = @alignCast(@fieldParentPtr("body", body));
        assert(preserve <= body.end);
        assert(body.buffer.len - body.end < capacity);
        if (builder.grown) return error.WriteFailed;
        const grow = builder.grow orelse return error.WriteFailed;
        const size_bytes = std.math.add(usize, head_reserve_size + body.end, capacity) catch
            return error.WriteFailed;
        const large = grow.acquire(grow.context, size_bytes) orelse return error.WriteFailed;
        assert(large.len >= size_bytes);
        const written = body.end;
        @memcpy(large[head_reserve_size..][0..written], body.buffer[0..written]);
        builder.buffer = large;
        builder.grown = true;
        body.buffer = large[head_reserve_size..];
        assert(body.end == written);
        assert(body.buffer.len - body.end >= capacity);
    }

    /// Answers later: the server parks the connection when the handler returns, and the
    /// response is written by `resume_deferred(token, ...)`. Anything written to this builder
    /// is discarded. The request stays valid until then. May be called once per request.
    pub fn defer_response(builder: *ResponseBuilder) Deferred {
        const park = builder.park.?; // Deferral needs a server-provided builder.
        assert(builder.deferred == null);
        const token = park.park(park.context);
        builder.deferred = token;
        return token;
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
        builder.body = body_writer(builder.buffer);
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

        /// `deferred`: parked by `defer_response`, no operation in flight.
        const State = enum { free, receiving, sending, closing, deferred };

        const Connection = struct {
            server: *Self,
            fd: Fd = undefined,
            state: State = .free,
            completion: IO.Completion = .{},
            recv_buffer: []u8,
            recv_size: u32 = 0,
            send_buffer: []u8,
            send_remaining: []const u8 = "",
            /// The large send buffer holding the response being sent, if any.
            large_index: ?u32 = null,
            /// Bytes of `recv_buffer` used by the request being answered.
            consumed: u32 = 0,
            keep_alive: bool = false,
            last_progress_ns: u64 = 0,
            timed_out: bool = false,
            peer: Address = undefined,
            /// Bumped whenever a deferred response is resumed or abandoned.
            generation: u32 = 0,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        context: Context,
        options: Options,
        listener: Fd = undefined,
        address: Address = undefined,
        accept_completion: IO.Completion = .{},
        /// `accept_completion` is in flight (an accept or the accept backoff timeout).
        accept_pending: bool = false,
        listener_open: bool = false,
        stopping: bool = false,
        connections: []Connection,
        memory: []u8,
        /// `large_send_buffers_max` buffers of `large_send_buffer_size` bytes.
        large_memory: []u8,
        requests_handled: u64 = 0,
        /// Responses moved into a large send buffer.
        responses_grown: u64 = 0,
        connections_rejected: u64 = 0,
        connections_timed_out: u64 = 0,
        /// Deferred responses answered by the server (504 timeout or 503 on stop).
        deferred_abandoned: u64 = 0,

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
            const memory = try lazy_alloc.alloc(allocator, u8, memory_size);
            errdefer lazy_alloc.free(allocator, memory);
            if (options.large_send_buffers_max > 0) {
                assert(options.large_send_buffer_size > options.send_buffer_size);
            }
            const large_size = @as(usize, options.large_send_buffer_size) *
                options.large_send_buffers_max;
            const large_memory = try lazy_alloc.alloc(allocator, u8, large_size);
            errdefer lazy_alloc.free(allocator, large_memory);
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
                .large_memory = large_memory,
            };
        }

        /// Frees the pools. If the IO keeps running afterwards, call `stop()` and run the IO
        /// until `stopped()` first: an accept or connection operation still in flight would
        /// otherwise complete into freed memory (owners that tear down the IO together with
        /// the server may skip this).
        pub fn deinit(server: *Self) void {
            assert(server.connections.len > 0);
            server.allocator.free(server.connections);
            lazy_alloc.free(server.allocator, server.memory);
            lazy_alloc.free(server.allocator, server.large_memory);
            server.* = undefined;
        }

        /// Binds, listens, and starts accepting. Returns the bound address.
        pub fn listen(server: *Self, address: Address) !Address {
            server.listener = try server.io.open_socket_tcp(address.family);
            errdefer server.io.close_now(server.listener);
            server.address = try server.io.listen(server.listener, address, server.options.backlog);
            server.listener_open = true;
            server.accept();
            return server.address;
        }

        /// Stops accepting new connections and shuts down idle keep-alive connections; a
        /// request in progress is answered, then its connection closes. The in-flight accept
        /// is canceled and the listener closes from its callback. Run the IO until
        /// `stopped()` before `deinit`.
        pub fn stop(server: *Self) void {
            assert(!server.stopping);
            server.stopping = true;
            for (server.connections) |*connection| {
                const idle = connection.state == .receiving and connection.recv_size == 0;
                if (idle) server.io.shutdown_now(connection.fd);
                if (connection.state == .deferred) connection_abandon(connection, 503);
            }
            if (server.accept_pending) {
                server.io.cancel(&server.accept_completion);
            } else {
                server.close_listener();
            }
        }

        /// True once the listener is closed and no connection is open.
        pub fn stopped(server: *const Self) bool {
            return !server.accept_pending and !server.listener_open and
                server.connections_open() == 0;
        }

        fn close_listener(server: *Self) void {
            if (!server.listener_open) return;
            server.listener_open = false;
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
                    .sending, .deferred => server.options.io_timeout_ns,
                };
                if (timeout_ns == 0) continue;
                if (now_ns -| connection.last_progress_ns < timeout_ns) continue;
                if (connection.state == .deferred) {
                    server.connections_timed_out += 1;
                    connection_abandon(connection, 504);
                    continue;
                }
                connection.timed_out = true;
                server.connections_timed_out += 1;
                server.io.shutdown_now(connection.fd);
            }
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
            if (server.stopping) {
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
            const connection = server.connection_acquire() orelse {
                server.connections_rejected += 1;
                server.io.close_now(fd);
                return;
            };
            connection.fd = fd;
            connection.recv_size = 0;
            connection.timed_out = false;
            connection.last_progress_ns = server.io.now_monotonic_ns();
            connection.peer = server.io.peer_address(fd) orelse Address.ip4(.{ 0, 0, 0, 0 }, 0);
            connection_recv(connection);
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
            if (server.stopping) return server.close_listener();
            server.accept();
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
                    assert(connection.large_index == null);
                    var builder = connection_builder(connection);
                    builder.park = .{ .context = connection, .park = connection_park };
                    connection.consumed = complete.consumed;
                    connection.keep_alive = complete.message.keep_alive;
                    handler(server.context, &complete.message, &builder);
                    server.requests_handled += 1;
                    // Deferred: parked (or already resumed from inside the handler).
                    if (builder.deferred != null) return;
                    connection.keep_alive = connection.keep_alive and !server.stopping;
                    connection_send(connection, builder.finish(connection.keep_alive));
                },
            }
        }

        /// A builder over the connection's send buffer, growable if large buffers exist.
        fn connection_builder(connection: *Connection) ResponseBuilder {
            assert(connection.large_index == null);
            assert(connection.state == .receiving or connection.state == .deferred);
            var builder = ResponseBuilder.init(connection.send_buffer);
            builder.peer = connection.peer;
            if (connection.server.options.large_send_buffers_max > 0) {
                builder.grow = .{ .context = connection, .acquire = large_acquire };
            }
            return builder;
        }

        /// `Park.park`: parks the connection whose handler is running.
        fn connection_park(context: *anyopaque) Deferred {
            const connection: *Connection = @ptrCast(@alignCast(context));
            assert(connection.state == .receiving);
            assert(connection.consumed > 0);
            // A body the handler wrote (and maybe grew) before deferring is discarded.
            connection.large_index = null;
            connection.state = .deferred;
            connection.last_progress_ns = connection.server.io.now_monotonic_ns();
            const first = @intFromPtr(connection.server.connections.ptr);
            const index = (@intFromPtr(connection) - first) / @sizeOf(Connection);
            assert(index < connection.server.connections.len);
            return .{ .index = @intCast(index), .generation = connection.generation };
        }

        /// The parked connection for `token`, or null if the token is stale.
        fn deferred_connection(server: *Self, token: Deferred) ?*Connection {
            if (token.index >= server.connections.len) return null;
            const connection = &server.connections[token.index];
            if (connection.state != .deferred) return null;
            if (connection.generation != token.generation) return null;
            return connection;
        }

        /// True while `token` can still be resumed (its request slices are still valid).
        pub fn deferred_valid(server: *Self, token: Deferred) bool {
            return server.deferred_connection(token) != null;
        }

        /// Writes and sends the deferred response for `token` with `write(context, builder)`,
        /// then serves pipelined requests as usual. Returns false (and calls nothing) if the
        /// token is stale: the connection timed out or the server stopped.
        pub fn resume_deferred(
            server: *Self,
            token: Deferred,
            write_context: anytype,
            comptime write: fn (@TypeOf(write_context), *ResponseBuilder) void,
        ) bool {
            const connection = server.deferred_connection(token) orelse return false;
            assert(connection.large_index == null);
            connection.generation +%= 1;
            var builder = connection_builder(connection);
            write(write_context, &builder);
            assert(builder.deferred == null);
            connection.keep_alive = connection.keep_alive and !server.stopping;
            connection_send(connection, builder.finish(connection.keep_alive));
            assert(connection.state == .sending);
            return true;
        }

        /// Answers a parked connection with `status` and closes it; its token goes stale.
        fn connection_abandon(connection: *Connection, status: u16) void {
            assert(connection.state == .deferred);
            assert(status >= 500);
            connection.generation +%= 1;
            connection.server.deferred_abandoned += 1;
            connection_reply_error(connection, status);
        }

        /// `Grow.acquire` for a connection's response: the first large buffer no other
        /// connection holds, if it is big enough.
        fn large_acquire(context: *anyopaque, size_bytes: usize) ?[]u8 {
            const connection: *Connection = @ptrCast(@alignCast(context));
            const server = connection.server;
            assert(connection.large_index == null);
            assert(connection.state == .receiving or connection.state == .deferred);
            const buffer_size = server.options.large_send_buffer_size;
            if (size_bytes > buffer_size) return null;
            var index: u32 = 0;
            while (index < server.options.large_send_buffers_max) : (index += 1) {
                if (server.large_held(index)) continue;
                connection.large_index = index;
                server.responses_grown += 1;
                return server.large_memory[@as(usize, index) * buffer_size ..][0..buffer_size];
            }
            return null;
        }

        fn large_held(server: *const Self, index: u32) bool {
            assert(index < server.options.large_send_buffers_max);
            for (server.connections) |*connection| {
                if (connection.large_index == index) return true;
            }
            return false;
        }

        /// The response is sent (or abandoned): its large buffer is free again.
        fn connection_release_large(connection: *Connection) void {
            assert(connection.state != .free and connection.state != .closing);
            connection.large_index = null;
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
            connection_release_large(connection);
            if (!connection.keep_alive) return connection_close(connection);
            // Drop the answered request; pipelined bytes move to the front.
            const rest = connection.recv_buffer[connection.consumed..connection.recv_size];
            std.mem.copyForwards(u8, connection.recv_buffer[0..rest.len], rest);
            connection.recv_size = @intCast(rest.len);
            connection.consumed = 0;
            connection.state = .receiving;
            connection_process(connection);
        }

        fn connection_close(connection: *Connection) void {
            assert(connection.state != .free);
            assert(connection.state != .closing);
            connection_release_large(connection);
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

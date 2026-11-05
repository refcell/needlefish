//! HTTP/1.1 client on the completion-based IO: one persistent keep-alive connection, one
//! request in flight at a time.
//!
//! The connection opens lazily on the first request and is reused while the server keeps it
//! alive. If a reused connection turns out to be dead (closed or reset before any response
//! byte arrives) the request is retried once on a fresh connection; requests are only resent
//! when no response was observed, so a request is never processed twice by a live server
//! that answered it. Buffers are allocated at `init`.
//!
//! Request timeout: the owner calls `tick()` periodically; a request older than
//! `request_timeout_ns` has its socket shut down and completes with `error.Timeout` once the
//! pending operation returns (a connect in progress is bounded by the OS connect timeout).

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../io/common.zig");
const parser = @import("parser.zig");

pub const Address = io_common.Address;

pub const Options = struct {
    send_buffer_size: u32 = 256 * 1024,
    recv_buffer_size: u32 = 1024 * 1024 + 8 * 1024,
    limits: parser.Limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 * 1024 },
    /// `Host` header value. Defaults to the server address when empty.
    host: []const u8 = "",
    /// Zero disables the timeout.
    request_timeout_ns: u64 = 30 * std.time.ns_per_s,
};

pub const Error = error{
    ConnectFailed,
    ConnectionClosed,
    SendFailed,
    RecvFailed,
    InvalidResponse,
    ResponseTooLarge,
    Timeout,
};

pub const RequestError = error{ Busy, RequestTooLarge };

fn typed_context(comptime Context: type, opaque_context: ?*anyopaque) Context {
    if (Context == void) return {};
    return @ptrCast(@alignCast(opaque_context));
}

pub fn Client(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Fd = IO.Fd;
        const Callback = *const fn (?*anyopaque, *Self, Error!*const parser.Response) void;

        const State = enum { idle, connecting, sending, receiving };

        io: *IO,
        allocator: std.mem.Allocator,
        address: Address,
        options: Options,
        fd: ?Fd = null,
        state: State = .idle,
        completion: IO.Completion = .{},
        send_buffer: []u8,
        request_size: u32 = 0,
        send_offset: u32 = 0,
        recv_buffer: []u8,
        recv_size: u32 = 0,
        method: parser.Method = .POST,
        /// The connection served at least one response before this request.
        reused: bool = false,
        retried: bool = false,
        started_ns: u64 = 0,
        timed_out: bool = false,
        callback: Callback = undefined,
        context: ?*anyopaque = null,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            address: Address,
            options: Options,
        ) !Self {
            const limits = options.limits;
            assert(options.recv_buffer_size >= limits.head_size_max + limits.body_size_max);
            const send_buffer = try allocator.alloc(u8, options.send_buffer_size);
            errdefer allocator.free(send_buffer);
            const recv_buffer = try allocator.alloc(u8, options.recv_buffer_size);
            return .{
                .io = io,
                .allocator = allocator,
                .address = address,
                .options = options,
                .send_buffer = send_buffer,
                .recv_buffer = recv_buffer,
            };
        }

        pub fn deinit(client: *Self) void {
            assert(client.state == .idle);
            if (client.fd) |fd| client.io.close_now(fd);
            client.allocator.free(client.recv_buffer);
            client.allocator.free(client.send_buffer);
            client.* = undefined;
        }

        pub fn busy(client: *const Self) bool {
            return client.state != .idle;
        }

        /// Sends one request. `callback` runs once with the response (valid only during the
        /// callback) or an error. It may issue the next request. `client` must not move
        /// while a request is in flight.
        pub fn request(
            client: *Self,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!*const parser.Response) void,
            method: parser.Method,
            target: []const u8,
            headers: []const parser.Header,
            body: []const u8,
        ) RequestError!void {
            if (client.state != .idle) return error.Busy;
            assert(method != .other);
            try client.write_request(method, target, headers, body);
            client.method = method;
            client.context = io_common.opaque_context(Context, context);
            client.callback = &struct {
                fn erased(
                    opaque_context: ?*anyopaque,
                    self: *Self,
                    result: Error!*const parser.Response,
                ) void {
                    callback(typed_context(Context, opaque_context), self, result);
                }
            }.erased;
            client.retried = false;
            client.timed_out = false;
            client.started_ns = client.io.now_monotonic_ns();
            client.start();
        }

        /// Times out the request in flight if it is older than `request_timeout_ns`.
        pub fn tick(client: *Self) void {
            if (client.state == .idle or client.timed_out) return;
            const timeout_ns = client.options.request_timeout_ns;
            if (timeout_ns == 0) return;
            if (client.io.now_monotonic_ns() -| client.started_ns < timeout_ns) return;
            client.timed_out = true;
            if (client.fd) |fd| client.io.shutdown_now(fd);
        }

        fn write_request(
            client: *Self,
            method: parser.Method,
            target: []const u8,
            headers: []const parser.Header,
            body: []const u8,
        ) RequestError!void {
            var writer: std.Io.Writer = .fixed(client.send_buffer);
            write_request_bytes(&writer, client, method, target, headers, body) catch
                return error.RequestTooLarge;
            client.request_size = @intCast(writer.end);
            assert(client.request_size > 0);
        }

        fn write_request_bytes(
            writer: *std.Io.Writer,
            client: *const Self,
            method: parser.Method,
            target: []const u8,
            headers: []const parser.Header,
            body: []const u8,
        ) std.Io.Writer.Error!void {
            try writer.print("{s} {s} HTTP/1.1\r\n", .{ @tagName(method), target });
            if (client.options.host.len > 0) {
                try writer.print("Host: {s}\r\n", .{client.options.host});
            } else {
                try writer.print("Host: {f}\r\n", .{client.address});
            }
            for (headers) |header| try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
            if (body.len > 0 or method == .POST or method == .PUT) {
                try writer.print("Content-Length: {d}\r\n", .{body.len});
            }
            try writer.writeAll("\r\n");
            try writer.writeAll(body);
        }

        fn start(client: *Self) void {
            client.send_offset = 0;
            client.recv_size = 0;
            if (client.fd) |_| {
                client.reused = true;
                return client.send();
            }
            client.reused = false;
            const fd = client.io.open_socket_tcp(client.address.family) catch {
                return client.finish(error.ConnectFailed);
            };
            client.fd = fd;
            client.state = .connecting;
            client.io.connect(*Self, client, on_connect, &client.completion, fd, client.address);
        }

        fn on_connect(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.ConnectError!void,
        ) void {
            assert(completion == &client.completion);
            assert(client.state == .connecting);
            if (client.timed_out) {
                client.disconnect();
                return client.finish(error.Timeout);
            }
            result catch {
                client.disconnect();
                return client.finish(error.ConnectFailed);
            };
            client.send();
        }

        fn send(client: *Self) void {
            assert(client.send_offset < client.request_size);
            client.state = .sending;
            const bytes = client.send_buffer[client.send_offset..client.request_size];
            client.io.send(*Self, client, on_send, &client.completion, client.fd.?, bytes);
        }

        fn on_send(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.SendError!usize,
        ) void {
            assert(completion == &client.completion);
            assert(client.state == .sending);
            const size = result catch return client.fail_or_retry(error.SendFailed);
            client.send_offset += @intCast(size);
            assert(client.send_offset <= client.request_size);
            if (client.send_offset < client.request_size) return client.send();
            client.recv();
        }

        fn recv(client: *Self) void {
            client.state = .receiving;
            const free = client.recv_buffer[client.recv_size..];
            assert(free.len > 0);
            client.io.recv(*Self, client, on_recv, &client.completion, client.fd.?, free);
        }

        fn on_recv(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.RecvError!usize,
        ) void {
            assert(completion == &client.completion);
            assert(client.state == .receiving);
            const size = result catch return client.fail_or_retry(error.RecvFailed);
            if (size == 0) return client.fail_or_retry(error.ConnectionClosed);
            client.recv_size += @intCast(size);
            const buffered = client.recv_buffer[0..client.recv_size];
            const limits = client.options.limits;
            const parsed = parser.parse_response(buffered, limits, client.method) catch {
                client.disconnect();
                return client.finish(error.InvalidResponse);
            };
            switch (parsed) {
                .incomplete => {
                    if (client.recv_size == client.recv_buffer.len) {
                        client.disconnect();
                        return client.finish(error.ResponseTooLarge);
                    }
                    client.recv();
                },
                .complete => |complete| {
                    // Extra bytes after a response mean the stream is out of sync.
                    const leftover = complete.consumed != client.recv_size;
                    if (!complete.message.keep_alive or leftover) client.disconnect();
                    client.state = .idle;
                    client.callback(client.context, client, &complete.message);
                },
            }
        }

        fn fail_or_retry(client: *Self, err: Error) void {
            client.disconnect();
            // A stale keep-alive socket fails before any response byte: retry once.
            const retry = client.reused and !client.retried and !client.timed_out;
            if (retry and client.recv_size == 0) {
                client.retried = true;
                return client.start();
            }
            client.finish(err);
        }

        fn disconnect(client: *Self) void {
            if (client.fd) |fd| client.io.close_now(fd);
            client.fd = null;
        }

        fn finish(client: *Self, err: Error) void {
            client.state = .idle;
            client.callback(client.context, client, if (client.timed_out) error.Timeout else err);
        }
    };
}

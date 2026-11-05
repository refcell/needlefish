//! WebSocket client on the completion-based IO (RFC 6455), e.g. for a flashblocks feed.
//!
//! TCP connect plus the HTTP upgrade handshake; everything after that is the shared frame
//! engine in `stream.zig` (concurrent recv/send, ping replies, fragments, close handshake,
//! shutdown-based teardown). `on_close` runs exactly once per `connect`.
//!
//! Masking keys and the handshake nonce come from a SplitMix64 stream seeded by
//! `Options.seed`, so simulator runs are reproducible. Production callers should seed it
//! from OS entropy.

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
    message_size_max: u32 = 1 << 20,
    send_buffer_size: u32 = 64 * 1024,
    /// `Host` header value. Defaults to the server address when empty.
    host: []const u8 = "",
    target: []const u8 = "/",
    seed: u64 = 0,
};

pub fn Handlers(comptime ClientType: type, comptime Context: type) type {
    return struct {
        on_open: *const fn (Context, *ClientType) void,
        /// `message.payload` is valid only during the callback.
        on_message: *const fn (Context, *ClientType, Message) void,
        on_close: *const fn (Context, *ClientType, Closed) void,
    };
}

pub const handshake_head_size_max = 8 * 1024;

pub fn Client(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Stream = stream_module.Stream(IO, Hooks);

        io: *IO,
        allocator: std.mem.Allocator,
        address: Address,
        options: Options,
        context: Context,
        handlers: *const Handlers(Self, Context),
        stream: Stream,
        connect_completion: IO.Completion = .{},
        connect_fd: ?IO.Fd = null,
        connect_aborted: bool = false,
        key: [frame.key_size]u8 = undefined,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            address: Address,
            options: Options,
            context: Context,
            handlers: *const Handlers(Self, Context),
        ) !Self {
            assert(options.message_size_max > 0);
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
                .stream = Stream.init(
                    io,
                    .client,
                    recv_buffer,
                    send_buffer,
                    message_buffer,
                    options.seed,
                ),
            };
        }

        pub fn deinit(client: *Self) void {
            assert(client.idle());
            client.allocator.free(client.stream.message_buffer);
            client.allocator.free(client.stream.send_buffer);
            client.allocator.free(client.stream.recv_buffer);
            client.* = undefined;
        }

        pub fn idle(client: *const Self) bool {
            return client.connect_fd == null and client.stream.state == .idle;
        }

        pub fn state(client: *const Self) stream_module.State {
            return client.stream.state;
        }

        /// Opens the connection. `on_open` or `on_close` follows. `client` must not move
        /// until `on_close` has run.
        pub fn connect(client: *Self) void {
            assert(client.idle());
            client.connect_aborted = false;
            const fd = client.io.open_socket_tcp(client.address.family) catch {
                return client.report_connect_failure();
            };
            client.connect_fd = fd;
            const completion = &client.connect_completion;
            client.io.connect(*Self, client, on_connect, completion, fd, client.address);
        }

        pub fn send_text(client: *Self, payload: []const u8) SendError!void {
            try client.stream.send(.text, payload);
        }

        pub fn send_binary(client: *Self, payload: []const u8) SendError!void {
            try client.stream.send(.binary, payload);
        }

        /// Sends an empty ping (keepalive); compare `pongs_received` later for the reply.
        pub fn ping(client: *Self) SendError!void {
            try client.stream.ping("");
        }

        pub fn pongs_received(client: *const Self) u64 {
            return client.stream.pongs_received;
        }

        /// Starts the close handshake; `on_close` runs once the server echoes it.
        pub fn close(client: *Self, code: frame.CloseCode) void {
            client.stream.close(code);
        }

        /// Tears the connection down without a close handshake (e.g. a close timeout).
        pub fn abort(client: *Self) void {
            if (client.connect_fd) |fd| {
                // Wake the pending connect; on_connect reports the close.
                client.connect_aborted = true;
                client.io.shutdown_now(fd);
                return;
            }
            client.stream.abort();
        }

        fn on_connect(
            client: *Self,
            completion: *IO.Completion,
            result: io_common.ConnectError!void,
        ) void {
            assert(completion == &client.connect_completion);
            const fd = client.connect_fd.?;
            client.connect_fd = null;
            const connected = if (result) |_| !client.connect_aborted else |_| false;
            if (!connected) {
                client.io.close_now(fd);
                if (client.connect_aborted) {
                    return client.handlers.on_close(client.context, client, .{
                        .code = null,
                        .err = null,
                    });
                }
                return client.report_connect_failure();
            }
            client.stream.start(fd);
            var request: [handshake_head_size_max]u8 = undefined;
            const bytes = client.write_handshake(&request) catch {
                return client.stream.fail(error.HandshakeFailed);
            };
            client.stream.send_raw(bytes) catch return client.stream.fail(error.HandshakeFailed);
        }

        fn report_connect_failure(client: *Self) void {
            client.handlers.on_close(client.context, client, .{
                .code = null,
                .err = error.ConnectFailed,
            });
        }

        fn write_handshake(client: *Self, buffer: []u8) std.Io.Writer.Error![]const u8 {
            var nonce: [16]u8 = undefined;
            std.mem.writeInt(u64, nonce[0..8], client.stream.next_random(), .little);
            std.mem.writeInt(u64, nonce[8..16], client.stream.next_random(), .little);
            client.key = frame.client_key(nonce);
            var writer: std.Io.Writer = .fixed(buffer);
            try writer.print("GET {s} HTTP/1.1\r\n", .{client.options.target});
            if (client.options.host.len > 0) {
                try writer.print("Host: {s}\r\n", .{client.options.host});
            } else {
                try writer.print("Host: {f}\r\n", .{client.address});
            }
            try writer.writeAll("Upgrade: websocket\r\nConnection: Upgrade\r\n");
            try writer.print("Sec-WebSocket-Key: {s}\r\n", .{&client.key});
            try writer.writeAll("Sec-WebSocket-Version: 13\r\n\r\n");
            return writer.buffered();
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

        const Hooks = struct {
            fn owner(stream: *Stream) *Self {
                return @fieldParentPtr("stream", stream);
            }

            pub fn handshake(stream: *Stream) void {
                const client = owner(stream);
                const limits: http_parser.Limits = .{
                    .head_size_max = handshake_head_size_max,
                    .body_size_max = 0,
                };
                const parsed = http_parser.parse_response(stream.buffered(), limits, .GET) catch {
                    return stream.fail(error.HandshakeFailed);
                };
                const complete = switch (parsed) {
                    .incomplete => return,
                    .complete => |complete| complete,
                };
                if (!client.handshake_valid(&complete.message)) {
                    return stream.fail(error.HandshakeFailed);
                }
                stream.consume(@intCast(complete.consumed));
                stream.open();
                client.handlers.on_open(client.context, client);
            }

            pub fn message(stream: *Stream, incoming: Message) void {
                const client = owner(stream);
                client.handlers.on_message(client.context, client, incoming);
            }

            pub fn closed(stream: *Stream, result: Closed) void {
                const client = owner(stream);
                client.handlers.on_close(client.context, client, result);
            }
        };
    };
}

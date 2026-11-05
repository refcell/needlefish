//! WebSocket client tests against a scripted raw-socket server on SimIo.

const std = @import("std");
const assert = std.debug.assert;

const io = @import("../io/root.zig");
const io_common = @import("../io/common.zig");
const http_parser = @import("../http/parser.zig");
const frame = @import("frame.zig");
const client_module = @import("client.zig");

const SimIo = io.SimIo;
const Address = io.Address;
const Completion = SimIo.Completion;

const Behavior = enum { echo, reject_handshake, bad_frame };

/// Accepts one connection, completes the handshake, sends a ping and a fragmented "hello",
/// then echoes data frames and answers a close frame.
const Server = struct {
    io: *SimIo,
    listener: SimIo.Fd,
    behavior: Behavior = .echo,
    fd: SimIo.Fd = 0,
    completion: Completion = .{},
    recv_buffer: [4096]u8 = undefined,
    recv_size: usize = 0,
    send_buffer: [4096]u8 = undefined,
    send_size: usize = 0,
    send_offset: usize = 0,
    handshaken: bool = false,
    got_pong: bool = false,
    got_close: bool = false,
    finished: bool = false,

    fn start(server: *Server) void {
        server.io.accept(*Server, server, on_accept, &server.completion, server.listener);
    }

    fn on_accept(
        server: *Server,
        completion: *Completion,
        result: io_common.AcceptError!SimIo.Fd,
    ) void {
        server.fd = result catch unreachable;
        server.recv(completion);
    }

    fn recv(server: *Server, completion: *Completion) void {
        const free = server.recv_buffer[server.recv_size..];
        server.io.recv(*Server, server, on_recv, completion, server.fd, free);
    }

    fn on_recv(
        server: *Server,
        completion: *Completion,
        result: io_common.RecvError!usize,
    ) void {
        const size = result catch 0;
        if (size == 0) {
            server.io.close_now(server.fd);
            server.finished = true;
            return;
        }
        server.recv_size += size;
        if (!server.handshaken) {
            server.handshake();
        } else {
            server.handle_frames();
        }
        if (server.send_size > server.send_offset) return server.send(completion);
        server.recv(completion);
    }

    fn handshake(server: *Server) void {
        const input = server.recv_buffer[0..server.recv_size];
        const parsed = http_parser.parse_request(input, .{}) catch unreachable;
        const request = switch (parsed) {
            .incomplete => return,
            .complete => |c| c,
        };
        server.recv_size = 0;
        server.handshaken = true;
        var out: std.Io.Writer = .fixed(&server.send_buffer);
        if (server.behavior == .reject_handshake) {
            const reply = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            out.writeAll(reply) catch unreachable;
            server.send_size = out.end;
            return;
        }
        const key = request.message.headers.get("sec-websocket-key").?;
        out.print(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\n\r\n",
            .{&frame.accept_key(key)},
        ) catch unreachable;
        server.send_size = out.end;
        if (server.behavior == .bad_frame) {
            server.push_raw(&.{ 0xc1, 0x00 }); // Reserved bit set.
            return;
        }
        server.push_frame(true, .ping, "are-you-there");
        server.push_frame(false, .text, "hel");
        server.push_frame(true, .continuation, "lo");
    }

    fn handle_frames(server: *Server) void {
        var offset: usize = 0;
        while (offset < server.recv_size) {
            const input = server.recv_buffer[offset..server.recv_size];
            const decoded = frame.decode_frame(input, .server, .{}) catch unreachable;
            const f = switch (decoded) {
                .incomplete => break,
                .frame => |f| f,
            };
            offset += f.size;
            switch (f.header.opcode) {
                .pong => server.got_pong = std.mem.eql(u8, f.payload, "are-you-there"),
                .text, .binary => server.push_frame(true, f.header.opcode, f.payload),
                .close => {
                    server.got_close = true;
                    server.push_frame(true, .close, f.payload);
                },
                else => {},
            }
        }
        const rest = server.recv_buffer[offset..server.recv_size];
        std.mem.copyForwards(u8, &server.recv_buffer, rest);
        server.recv_size -= offset;
    }

    fn push_frame(server: *Server, fin: bool, opcode: frame.Opcode, payload: []const u8) void {
        var header: [frame.header_size_max]u8 = undefined;
        const size = frame.encode_header(&header, fin, opcode, payload.len, null);
        server.push_raw(header[0..size]);
        server.push_raw(payload);
    }

    fn push_raw(server: *Server, bytes: []const u8) void {
        @memcpy(server.send_buffer[server.send_size..][0..bytes.len], bytes);
        server.send_size += bytes.len;
    }

    fn send(server: *Server, completion: *Completion) void {
        const bytes = server.send_buffer[server.send_offset..server.send_size];
        server.io.send(*Server, server, on_send, completion, server.fd, bytes);
    }

    fn on_send(
        server: *Server,
        completion: *Completion,
        result: io_common.SendError!usize,
    ) void {
        const size = result catch {
            server.io.close_now(server.fd);
            server.finished = true;
            return;
        };
        server.send_offset += size;
        if (server.send_offset < server.send_size) return server.send(completion);
        server.send_offset = 0;
        server.send_size = 0;
        server.recv(completion);
    }
};

const Recorder = struct {
    opened: bool = false,
    messages: [4][32]u8 = undefined,
    sizes: [4]usize = @splat(0),
    count: u32 = 0,
    closed: ?client_module.Closed = null,
    close_calls: u32 = 0,

    const WsClient = client_module.Client(SimIo, *Recorder);
    const handlers: client_module.Handlers(WsClient, *Recorder) = .{
        .on_open = on_open,
        .on_message = on_message,
        .on_close = on_close,
    };

    fn on_open(recorder: *Recorder, client: *WsClient) void {
        recorder.opened = true;
        client.send_text("echo-me") catch unreachable;
    }

    fn on_message(recorder: *Recorder, client: *WsClient, incoming: client_module.Message) void {
        const index = recorder.count;
        @memcpy(recorder.messages[index][0..incoming.payload.len], incoming.payload);
        recorder.sizes[index] = incoming.payload.len;
        recorder.count += 1;
        if (recorder.count == 2) client.close(.normal);
    }

    fn on_close(recorder: *Recorder, client: *WsClient, closed: client_module.Closed) void {
        _ = client;
        recorder.close_calls += 1;
        recorder.closed = closed;
    }

    fn received(recorder: *const Recorder, index: usize) []const u8 {
        return recorder.messages[index][0..recorder.sizes[index]];
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,
    server: Server,
    recorder: Recorder = .{},
    client: Recorder.WsClient,

    fn init(harness: *Harness, seed: u64, behavior: Behavior) !void {
        harness.world = try io.SimWorld.init(std.testing.allocator, .{
            .seed = seed,
            .segment_size_max = 7, // Split frames across many recvs.
        });
        const server_host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try SimIo.init(&harness.server_io, std.testing.allocator, &harness.world, .{
            .host = server_host,
        });
        try SimIo.init(&harness.client_io, std.testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        const listener = try harness.server_io.open_socket_tcp(.ip4);
        const bound = try harness.server_io.listen(listener, server_host.with_port(8546), 4);
        harness.server = .{ .io = &harness.server_io, .listener = listener, .behavior = behavior };
        harness.recorder = .{};
        harness.client = try Recorder.WsClient.init(
            std.testing.allocator,
            &harness.client_io,
            bound,
            .{ .message_size_max = 1024, .send_buffer_size = 1024, .seed = seed },
            &harness.recorder,
            &Recorder.handlers,
        );
        harness.server.start();
    }

    fn run(harness: *Harness) !void {
        var rounds: u32 = 0;
        while (harness.recorder.closed == null and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        try std.testing.expect(harness.recorder.closed != null);
    }

    fn deinit(harness: *Harness) void {
        harness.client.deinit();
        harness.server_io.close_now(harness.server.listener);
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }
};

test "ws: client handshake, ping, fragments, echo, and close" {
    for (0..8) |seed| {
        var harness: Harness = undefined;
        try harness.init(seed, .echo);
        defer harness.deinit();
        harness.client.connect();
        try harness.run();
        const recorder = &harness.recorder;
        try std.testing.expect(recorder.opened);
        try std.testing.expectEqual(@as(u32, 2), recorder.count);
        // The fragmented "hello" was sent before the echo, so it arrives first.
        try std.testing.expectEqualStrings("hello", recorder.received(0));
        try std.testing.expectEqualStrings("echo-me", recorder.received(1));
        try std.testing.expectEqual(@as(?u16, 1000), recorder.closed.?.code);
        try std.testing.expectEqual(@as(?client_module.Error, null), recorder.closed.?.err);
        try std.testing.expectEqual(@as(u32, 1), recorder.close_calls);
        try std.testing.expect(harness.server.got_pong and harness.server.got_close);
        try std.testing.expect(harness.client.idle());
    }
}

test "ws: client failures" {
    const cases = [_]struct { Behavior, client_module.Error }{
        .{ .reject_handshake, error.HandshakeFailed },
        .{ .bad_frame, error.ProtocolError },
    };
    for (cases) |case| {
        var harness: Harness = undefined;
        try harness.init(3, case[0]);
        defer harness.deinit();
        harness.client.connect();
        try harness.run();
        const closed = harness.recorder.closed.?;
        try std.testing.expectEqual(@as(?client_module.Error, case[1]), closed.err);
        try std.testing.expect(!harness.recorder.opened or case[0] == .bad_frame);
        try std.testing.expectEqual(@as(u32, 1), harness.recorder.close_calls);
    }
}

test "ws: client connect refused" {
    var harness: Harness = undefined;
    try harness.init(4, .echo);
    defer harness.deinit();
    harness.client.address = harness.client.address.with_port(1);
    harness.client.connect();
    try harness.run();
    try std.testing.expectEqual(
        @as(?client_module.Error, error.ConnectFailed),
        harness.recorder.closed.?.err,
    );
}

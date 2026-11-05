//! `shutdown_now` on every backend: a pending recv on the shut-down descriptor completes
//! with 0, and the peer's recv sees end of stream.

const std = @import("std");

const root = @import("root.zig");
const common = @import("common.zig");
const sim = @import("sim.zig");

const Address = common.Address;

fn Shutdown(comptime IO: type) type {
    return struct {
        const Self = @This();
        io: *IO,
        client_fd: IO.Fd,
        server_fd: ?IO.Fd = null,
        accept_completion: IO.Completion = .{},
        connect_completion: IO.Completion = .{},
        client_recv: IO.Completion = .{},
        server_recv: IO.Completion = .{},
        client_buffer: [16]u8 = undefined,
        server_buffer: [16]u8 = undefined,
        connected: bool = false,
        client_result: ?common.RecvError!usize = null,
        server_result: ?common.RecvError!usize = null,

        fn on_accept(
            self: *Self,
            completion: *IO.Completion,
            result: common.AcceptError!IO.Fd,
        ) void {
            _ = completion;
            const fd = result catch unreachable;
            self.server_fd = fd;
            self.io.recv(*Self, self, on_server_recv, &self.server_recv, fd, &self.server_buffer);
        }

        fn on_connect(
            self: *Self,
            completion: *IO.Completion,
            result: common.ConnectError!void,
        ) void {
            _ = completion;
            result catch unreachable;
            self.connected = true;
            const buffer = &self.client_buffer;
            self.io.recv(*Self, self, on_client_recv, &self.client_recv, self.client_fd, buffer);
        }

        fn on_client_recv(
            self: *Self,
            completion: *IO.Completion,
            result: common.RecvError!usize,
        ) void {
            _ = completion;
            self.client_result = result;
        }

        fn on_server_recv(
            self: *Self,
            completion: *IO.Completion,
            result: common.RecvError!usize,
        ) void {
            _ = completion;
            self.server_result = result;
        }
    };
}

fn run(comptime IO: type, io: *IO, listen_address: Address) !void {
    const State = Shutdown(IO);
    const listener = try io.open_socket_tcp(.ip4);
    defer io.close_now(listener);
    const bound = try io.listen(listener, listen_address, 4);
    var state: State = .{ .io = io, .client_fd = try io.open_socket_tcp(.ip4) };
    io.accept(*State, &state, State.on_accept, &state.accept_completion, listener);
    io.connect(*State, &state, State.on_connect, &state.connect_completion, state.client_fd, bound);
    var rounds: u32 = 0;
    while ((state.server_fd == null or !state.connected) and rounds < 500) : (rounds += 1) {
        try io.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expect(state.connected and state.server_fd != null);
    // Both recvs are pending; shutting down the client wakes its own recv and sends FIN.
    io.shutdown_now(state.client_fd);
    rounds = 0;
    while ((state.client_result == null or state.server_result == null) and rounds < 500) {
        rounds += 1;
        try io.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 0), try state.client_result.?);
    try std.testing.expectEqual(@as(usize, 0), try state.server_result.?);
    io.close_now(state.client_fd);
    io.close_now(state.server_fd.?);
}

test "io: shutdown_now wakes pending recv on SimIo" {
    var world = try sim.World.init(std.testing.allocator, .{ .seed = 11 });
    defer world.deinit();
    var io: sim.SimIo = undefined;
    const host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
    try sim.SimIo.init(&io, std.testing.allocator, &world, .{ .host = host });
    defer io.deinit();
    try run(sim.SimIo, &io, host);
}

test "io: shutdown_now wakes pending recv on the OS backend" {
    var io = try root.init_for_test();
    defer io.deinit();
    try run(root.IO, &io, Address.loopback(0));
}

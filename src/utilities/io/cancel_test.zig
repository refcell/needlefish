//! `cancel` on every backend: pending accept, recv, and timeout complete with
//! `error.Canceled`; idle completions are unaffected; a canceled completion is reusable.

const std = @import("std");

const root = @import("root.zig");
const common = @import("common.zig");
const sim = @import("sim.zig");

const Address = common.Address;

fn Probe(comptime IO: type) type {
    return struct {
        const Self = @This();
        accept_result: ?common.AcceptError!IO.Fd = null,
        connect_result: ?common.ConnectError!void = null,
        recv_result: ?common.RecvError!usize = null,
        timeout_result: ?common.TimeoutError!void = null,
        calls: u32 = 0,

        fn on_accept(
            self: *Self,
            completion: *IO.Completion,
            result: common.AcceptError!IO.Fd,
        ) void {
            _ = completion;
            self.calls += 1;
            self.accept_result = result;
        }

        fn on_connect(
            self: *Self,
            completion: *IO.Completion,
            result: common.ConnectError!void,
        ) void {
            _ = completion;
            self.calls += 1;
            self.connect_result = result;
        }

        fn on_recv(
            self: *Self,
            completion: *IO.Completion,
            result: common.RecvError!usize,
        ) void {
            _ = completion;
            self.calls += 1;
            self.recv_result = result;
        }

        fn on_timeout(
            self: *Self,
            completion: *IO.Completion,
            result: common.TimeoutError!void,
        ) void {
            _ = completion;
            self.calls += 1;
            self.timeout_result = result;
        }
    };
}

fn run_until(comptime IO: type, io: *IO, probe: *const Probe(IO), calls: u32) !void {
    var rounds: u32 = 0;
    while (probe.calls < calls and rounds < 1000) : (rounds += 1) {
        try io.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(calls, probe.calls);
}

fn run(comptime IO: type, io: *IO, listen_address: Address) !void {
    var probe: Probe(IO) = .{};
    const P = Probe(IO);
    var idle: IO.Completion = .{};
    io.cancel(&idle); // Nothing in flight: no effect.

    // A timeout far in the future.
    var timer: IO.Completion = .{};
    io.timeout(*P, &probe, P.on_timeout, &timer, std.time.ns_per_s * 3600);
    io.cancel(&timer);
    try run_until(IO, io, &probe, 1);
    try std.testing.expectError(error.Canceled, probe.timeout_result.?);

    // An accept with no client, first after it reached the backend.
    const listener = try io.open_socket_tcp(.ip4);
    defer io.close_now(listener);
    const bound = try io.listen(listener, listen_address, 4);
    var accept: IO.Completion = .{};
    io.accept(*P, &probe, P.on_accept, &accept, listener);
    try io.run_for_ns(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 1), probe.calls);
    io.cancel(&accept);
    try run_until(IO, io, &probe, 2);
    try std.testing.expectError(error.Canceled, probe.accept_result.?);

    // The same completion is reusable: accept a real connection, then cancel an idle recv.
    io.accept(*P, &probe, P.on_accept, &accept, listener);
    const client = try io.open_socket_tcp(.ip4);
    defer io.close_now(client);
    var connect: IO.Completion = .{};
    io.connect(*P, &probe, P.on_connect, &connect, client, bound);
    try run_until(IO, io, &probe, 4);
    try probe.connect_result.?;
    const server_fd = try probe.accept_result.?;
    defer io.close_now(server_fd);
    var buffer: [16]u8 = undefined;
    var recv: IO.Completion = .{};
    io.recv(*P, &probe, P.on_recv, &recv, client, &buffer);
    try io.run_for_ns(std.time.ns_per_ms);
    io.cancel(&recv);
    io.cancel(&recv); // Idempotent.
    try run_until(IO, io, &probe, 5);
    try std.testing.expectError(error.Canceled, probe.recv_result.?);
    try io.run_for_ns(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 5), probe.calls); // Exactly one callback each.
}

test "io: cancel on SimIo" {
    var world = try sim.World.init(std.testing.allocator, .{ .seed = 12 });
    defer world.deinit();
    var io: sim.SimIo = undefined;
    const host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
    try sim.SimIo.init(&io, std.testing.allocator, &world, .{ .host = host });
    defer io.deinit();
    try run(sim.SimIo, &io, host);
}

test "io: cancel on the OS backend" {
    var io = try root.init_for_test();
    defer io.deinit();
    try run(root.IO, &io, Address.loopback(0));
}

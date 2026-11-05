//! UDP on every backend: bind, send a datagram, poll it with `recvfrom_now`, and see the
//! sender's address. SimIo also drops datagrams across partitions and to unbound ports.

const std = @import("std");

const root = @import("root.zig");
const common = @import("common.zig");
const sim = @import("sim.zig");

const Prng = @import("../../testing/prng.zig").Prng;

const Address = common.Address;

/// Sends "ping" from a to b and polls b until it arrives (or `rounds_max` passes).
fn exchange(comptime IO: type, io: *IO, a_fd: IO.Fd, b_fd: IO.Fd, b: Address, a: Address) !void {
    try std.testing.expect(io.sendto_now(a_fd, "ping", b));
    var buffer: [common.datagram_size_max]u8 = undefined;
    var rounds: u32 = 0;
    const received = while (rounds < 500) : (rounds += 1) {
        if (io.recvfrom_now(b_fd, &buffer)) |datagram| break datagram;
        try io.run_for_ns(std.time.ns_per_ms);
    } else return error.NoDatagram;
    try std.testing.expectEqualStrings("ping", buffer[0..received.length]);
    try std.testing.expectEqual(a.port, received.from.port);
    try std.testing.expect(io.recvfrom_now(b_fd, &buffer) == null);
}

test "io: UDP datagrams on SimIo, with partitions and unbound targets" {
    var world = try sim.World.init(std.testing.allocator, .{ .seed = 3 });
    defer world.deinit();
    var a_io: sim.SimIo = undefined;
    var b_io: sim.SimIo = undefined;
    try sim.SimIo.init(&a_io, std.testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
    });
    defer a_io.deinit();
    try sim.SimIo.init(&b_io, std.testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
    });
    defer b_io.deinit();
    const a_fd = try a_io.open_socket_udp(.ip4);
    const a = try a_io.bind_udp(a_fd, Address.ip4(.{ 10, 0, 0, 1 }, 9000));
    const b_fd = try b_io.open_socket_udp(.ip4);
    const b = try b_io.bind_udp(b_fd, Address.ip4(.{ 10, 0, 0, 2 }, 9000));
    try std.testing.expectError(error.AddressInUse, b_io.bind_udp(
        try b_io.open_socket_udp(.ip4),
        Address.ip4(.{ 10, 0, 0, 2 }, 9000),
    ));
    // Cross-node delivery goes through the world clock: send from a, poll on b.
    try std.testing.expect(a_io.sendto_now(a_fd, "ping", b));
    var buffer: [64]u8 = undefined;
    try std.testing.expect(b_io.recvfrom_now(b_fd, &buffer) == null); // Not arrived yet.
    world.run_for_ns(50 * std.time.ns_per_ms);
    const datagram = b_io.recvfrom_now(b_fd, &buffer).?;
    try std.testing.expectEqualStrings("ping", buffer[0..datagram.length]);
    try std.testing.expect(datagram.from.eql(a));
    // Partitioned and unbound targets drop silently.
    world.partition(a_io.index, b_io.index);
    try std.testing.expect(a_io.sendto_now(a_fd, "lost", b));
    world.heal_all();
    try std.testing.expect(a_io.sendto_now(a_fd, "void", Address.ip4(.{ 10, 0, 0, 2 }, 1)));
    world.run_for_ns(50 * std.time.ns_per_ms);
    try std.testing.expect(b_io.recvfrom_now(b_fd, &buffer) == null);
    // Closing the socket discards datagrams still in flight to it.
    try std.testing.expect(a_io.sendto_now(a_fd, "late", b));
    b_io.close_now(b_fd);
    for (world.datagrams) |in_flight| try std.testing.expect(!in_flight.used);
    a_io.close_now(a_fd);
}

test "io: UDP datagrams over loopback on the OS backend" {
    var io = try root.init_for_test();
    defer io.deinit();
    const a_fd = try io.open_socket_udp(.ip4);
    defer io.close_now(a_fd);
    const b_fd = try io.open_socket_udp(.ip4);
    defer io.close_now(b_fd);
    const a = try io.bind_udp(a_fd, Address.loopback(0));
    const b = try io.bind_udp(b_fd, Address.loopback(0));
    try std.testing.expect(a.port != 0 and b.port != 0 and a.port != b.port);
    try exchange(root.IO, &io, a_fd, b_fd, b, a);
    try exchange(root.IO, &io, b_fd, a_fd, a, b);
}

// Completion-based recvfrom/sendto.

const received_max = 64;

fn Endpoint(comptime IO: type) type {
    return struct {
        const Self = @This();

        io: *IO,
        fd: IO.Fd,
        address: Address = undefined,
        recv_completion: IO.Completion = .{},
        send_completion: IO.Completion = .{},
        buffer: [2048]u8 = undefined,
        recv_size: usize = 2048,
        received: [received_max]u64 = undefined,
        received_count: u32 = 0,
        last_from: ?Address = null,
        last_size: usize = 0,
        receiving: bool = false,
        canceled: bool = false,
        sends_done: u32 = 0,
        send_error: ?common.SendError = null,
        recv_error: ?common.RecvError = null,

        fn open(io: *IO, host: Address) !Self {
            const fd = try io.open_socket_udp(.ip4);
            var self: Self = .{ .io = io, .fd = fd };
            self.address = try io.bind_udp(fd, host);
            return self;
        }

        fn start_recv(self: *Self) void {
            std.debug.assert(!self.receiving);
            self.receiving = true;
            const buffer = self.buffer[0..self.recv_size];
            self.io.recvfrom(*Self, self, on_recv, &self.recv_completion, self.fd, buffer);
        }

        fn on_recv(
            self: *Self,
            completion: *IO.Completion,
            result: common.RecvError!common.Datagram,
        ) void {
            _ = completion;
            self.receiving = false;
            const datagram = result catch |err| {
                if (err == error.Canceled) self.canceled = true else self.recv_error = err;
                return;
            };
            self.last_from = datagram.from;
            self.last_size = datagram.length;
            if (datagram.length >= 8 and self.received_count < received_max) {
                const value = std.mem.readInt(u64, self.buffer[0..8], .little);
                self.received[self.received_count] = value;
                self.received_count += 1;
            }
            self.start_recv();
        }

        fn send(self: *Self, bytes: []const u8, to: Address) void {
            self.io.sendto(*Self, self, on_send, &self.send_completion, self.fd, bytes, to);
        }

        fn on_send(self: *Self, completion: *IO.Completion, result: common.SendError!usize) void {
            _ = completion;
            const size = result catch |err| {
                self.send_error = err;
                return;
            };
            std.debug.assert(size > 0);
            self.sends_done += 1;
        }
    };
}

test "os io: udp loopback datagram" {
    var io = try root.init_for_test();
    defer io.deinit();
    const E = Endpoint(root.IO);
    const loopback = Address.ip4(.{ 127, 0, 0, 1 }, 0);
    var a = try E.open(&io, loopback);
    defer io.close_now(a.fd);
    var b = try E.open(&io, loopback);
    defer io.close_now(b.fd);
    try std.testing.expect(a.address.port != 0 and a.address.port != b.address.port);
    b.start_recv();
    var message: [8]u8 = undefined;
    std.mem.writeInt(u64, &message, 0xdead_beef, .little);
    a.send(&message, b.address);
    var rounds: u32 = 0;
    while (rounds < 200 and (b.received_count == 0 or a.sends_done == 0)) : (rounds += 1) {
        try io.run_for_ns(5 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(u32, 1), a.sends_done);
    try std.testing.expectEqual(@as(u32, 1), b.received_count);
    try std.testing.expectEqual(@as(u64, 0xdead_beef), b.received[0]);
    try std.testing.expect(b.last_from.?.eql(a.address));
    // Cancel the re-armed receive so the IO drains before the sockets close.
    io.cancel(&b.recv_completion);
    rounds = 0;
    while (rounds < 200 and b.receiving) : (rounds += 1) try io.run_for_ns(std.time.ns_per_ms);
    try std.testing.expect(b.canceled);
}

const SimEndpoint = Endpoint(sim.SimIo);

const Pair = struct {
    world: sim.World,
    io_a: sim.SimIo,
    io_b: sim.SimIo,

    fn init(pair: *Pair, options: sim.Options) !void {
        const allocator = std.testing.allocator;
        pair.world = try sim.World.init(allocator, options);
        errdefer pair.world.deinit();
        try pair.io_a.init(allocator, &pair.world, .{ .host = Address.ip4(.{ 10, 0, 0, 1 }, 0) });
        errdefer pair.io_a.deinit();
        try pair.io_b.init(allocator, &pair.world, .{ .host = Address.ip4(.{ 10, 0, 0, 2 }, 0) });
    }

    fn deinit(pair: *Pair) void {
        pair.io_b.deinit();
        pair.io_a.deinit();
        pair.world.deinit();
    }
};

fn send_numbered(endpoint: *SimEndpoint, value: u64, to: Address) !void {
    var message: [8]u8 = undefined;
    std.mem.writeInt(u64, &message, value, .little);
    endpoint.send(&message, to);
    // sendto completes on the next tick and copies the payload, so the stack buffer is safe
    // only after the callback: drive the world until then.
    const done = endpoint.sends_done;
    var rounds: u32 = 0;
    while (endpoint.sends_done == done and endpoint.send_error == null) : (rounds += 1) {
        try std.testing.expect(rounds < 4);
        _ = endpoint.io.world.tick();
    }
}

test "sim udp: recvfrom/sendto completions deliver after latency with the sender address" {
    var pair: Pair = undefined;
    try pair.init(.{ .seed = 1 });
    defer pair.deinit();
    var b = try SimEndpoint.open(&pair.io_b, Address.ip4(.{ 0, 0, 0, 0 }, 9000));
    try std.testing.expect(b.address.eql(Address.ip4(.{ 10, 0, 0, 2 }, 9000)));
    var a = try SimEndpoint.open(&pair.io_a, Address.ip4(.{ 0, 0, 0, 0 }, 0));
    b.start_recv();
    try send_numbered(&a, 7, b.address);
    try std.testing.expectEqual(@as(u32, 0), b.received_count); // Still in flight.
    pair.world.run_for_ns(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 1), b.received_count);
    try std.testing.expectEqual(@as(u64, 7), b.received[0]);
    try std.testing.expect(b.last_from.?.same_host(Address.ip4(.{ 10, 0, 0, 1 }, 0)));
    try std.testing.expect(b.last_from.?.port != 0);
    // Reply to the learned address.
    a.start_recv();
    try send_numbered(&b, 8, b.last_from.?);
    pair.world.run_for_ns(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u64, 8), a.received[0]);
}

test "sim udp: completion errors, truncation, unbound drop" {
    var pair: Pair = undefined;
    try pair.init(.{ .seed = 2 });
    defer pair.deinit();
    var a = try SimEndpoint.open(&pair.io_a, Address.ip4(.{ 10, 0, 0, 1 }, 0));
    var b = try SimEndpoint.open(&pair.io_b, Address.ip4(.{ 10, 0, 0, 2 }, 0));
    const big: [common.datagram_size_max + 1]u8 = @splat(1);
    a.send(&big, b.address);
    pair.world.run_for_ns(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(?common.SendError, error.MessageTooBig), a.send_error);
    a.send_error = null;
    // An unbound socket has no port: sends and receives fail instead of hanging.
    var unbound: SimEndpoint = .{ .io = &pair.io_a, .fd = try pair.io_a.open_socket_udp(.ip4) };
    unbound.send("x", b.address);
    unbound.start_recv();
    pair.world.run_for_ns(std.time.ns_per_ms);
    try std.testing.expect(unbound.send_error.? == error.SocketNotConnected);
    try std.testing.expect(unbound.recv_error.? == error.SocketNotConnected);
    try send_numbered(&a, 1, Address.ip4(.{ 10, 0, 0, 2 }, 1)); // Nobody bound: dropped.
    try std.testing.expectEqual(@as(u64, 1), pair.world.datagram_stats.dropped_unbound);
    // Truncate to a short buffer, like the OS.
    b.recv_size = 4;
    b.start_recv();
    const full: [64]u8 = @splat(0xab);
    a.send(&full, b.address);
    pair.world.run_for_ns(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 4), b.last_size);
    try std.testing.expect(b.receiving); // Re-armed.
    pair.io_b.cancel(&b.recv_completion);
    _ = pair.world.tick();
    try std.testing.expect(b.canceled and !b.receiving);
}

test "sim udp: independent latencies reorder datagrams; none are lost by default" {
    var pair: Pair = undefined;
    try pair.init(.{ .seed = 3, .latency_min_ns = 0, .latency_max_ns = 10 * std.time.ns_per_ms });
    defer pair.deinit();
    var a = try SimEndpoint.open(&pair.io_a, Address.ip4(.{ 10, 0, 0, 1 }, 0));
    var b = try SimEndpoint.open(&pair.io_b, Address.ip4(.{ 10, 0, 0, 2 }, 0));
    b.start_recv();
    var value: u64 = 0;
    while (value < 16) : (value += 1) try send_numbered(&a, value, b.address);
    pair.world.run_for_ns(50 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 16), b.received_count);
    var seen: u64 = 0;
    var in_order = true;
    for (b.received[0..16], 0..) |got, index| {
        seen |= @as(u64, 1) << @intCast(got);
        if (got != index) in_order = false;
    }
    try std.testing.expectEqual(@as(u64, 0xffff), seen);
    try std.testing.expect(!in_order);
}

test "sim udp: partitions and loss drop datagrams; close frees the port" {
    var pair: Pair = undefined;
    try pair.init(.{ .seed = 4 });
    defer pair.deinit();
    var a = try SimEndpoint.open(&pair.io_a, Address.ip4(.{ 10, 0, 0, 1 }, 0));
    var b = try SimEndpoint.open(&pair.io_b, Address.ip4(.{ 10, 0, 0, 2 }, 0));
    b.start_recv();
    pair.world.partition(pair.io_a.index, pair.io_b.index);
    try send_numbered(&a, 1, b.address);
    pair.world.heal_all();
    pair.world.run_for_ns(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), b.received_count);
    try std.testing.expectEqual(@as(u64, 1), pair.world.datagram_stats.dropped_partition);
    pair.world.options.datagram_loss_ppm = 1_000_000;
    try send_numbered(&a, 2, b.address);
    try std.testing.expectEqual(@as(u64, 1), pair.world.datagram_stats.dropped_loss);
    pair.world.options.datagram_loss_ppm = 0;
    try send_numbered(&a, 3, b.address);
    pair.world.run_for_ns(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 1), b.received_count);
    try std.testing.expectEqual(@as(u64, 3), b.received[0]);
    pair.io_b.cancel(&b.recv_completion);
    _ = pair.world.tick();
    pair.io_b.close_now(b.fd);
    const again = try pair.io_b.open_socket_udp(.ip4);
    const rebound = try pair.io_b.bind_udp(again, b.address);
    try std.testing.expect(rebound.eql(b.address));
}

fn received_total_of(endpoints: []const SimEndpoint) u64 {
    var total: u64 = 0;
    for (endpoints) |*endpoint| total += endpoint.received_count;
    return total;
}

fn run_fuzz(seed: u64, received_out: *[2]u32) !void {
    var pair: Pair = undefined;
    try pair.init(.{ .seed = seed, .datagram_loss_ppm = 50_000, .datagrams_max = 8 });
    defer pair.deinit();
    var prng = Prng.init(seed);
    var endpoints = [2]SimEndpoint{
        try SimEndpoint.open(&pair.io_a, Address.ip4(.{ 10, 0, 0, 1 }, 0)),
        try SimEndpoint.open(&pair.io_b, Address.ip4(.{ 10, 0, 0, 2 }, 0)),
    };
    for (&endpoints) |*endpoint| endpoint.start_recv();
    var step: u32 = 0;
    while (step < 200) : (step += 1) {
        const from: usize = @intCast(prng.below(2));
        const to = endpoints[from ^ 1].address;
        switch (prng.below(8)) {
            0 => pair.world.partition(pair.io_a.index, pair.io_b.index),
            1 => pair.world.heal_all(),
            2 => pair.world.run_for_ns(prng.range(1, 3 * std.time.ns_per_ms)),
            else => {
                // A full in-flight table refuses the send (SystemResources): not counted.
                try send_numbered(&endpoints[from], step, to);
                endpoints[from].send_error = null;
            },
        }
    }
    pair.world.heal_all();
    pair.world.run_for_ns(20 * std.time.ns_per_ms);
    const stats = pair.world.datagram_stats;
    const dropped = stats.dropped_loss + stats.dropped_partition + stats.dropped_closed;
    try std.testing.expectEqual(@as(u64, 0), stats.dropped_unbound);
    try std.testing.expectEqual(stats.received, received_total_of(&endpoints));
    var received_total: u64 = 0;
    for (&endpoints, 0..) |*endpoint, index| {
        received_out[index] = endpoint.received_count;
        received_total += endpoint.received_count;
        for (endpoint.received[0..@min(endpoint.received_count, received_max)]) |value| {
            try std.testing.expect(value < 200);
        }
        pair.world.nodes[index].?.cancel(&endpoint.recv_completion);
    }
    try std.testing.expect(received_total + dropped == stats.sent);
    _ = pair.world.tick();
}

test "sim udp: seeded fuzz conserves datagrams and replays per seed" {
    var seed: u64 = 1;
    while (seed <= 16) : (seed += 1) {
        var first: [2]u32 = undefined;
        var second: [2]u32 = undefined;
        try run_fuzz(seed, &first);
        try run_fuzz(seed, &second);
        try std.testing.expectEqualSlices(u32, &first, &second);
    }
}

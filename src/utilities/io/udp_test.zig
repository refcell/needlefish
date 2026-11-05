//! UDP on every backend: bind, send a datagram, poll it with `recvfrom_now`, and see the
//! sender's address. SimIo also drops datagrams across partitions and to unbound ports.

const std = @import("std");

const root = @import("root.zig");
const common = @import("common.zig");
const sim = @import("sim.zig");

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

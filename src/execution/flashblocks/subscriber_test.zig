//! Subscriber tests: the reconnect backoff against a dead address (base/base: 1 s doubling
//! to a 10 s cap), the resume target, and option validation. The feed, keepalive, and
//! resume behavior under faults are covered by the consumer simulation.

const std = @import("std");
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const subscriber_module = @import("subscriber.zig");

const SimIo = io.SimIo;
const Address = io.Address;
const s = std.time.ns_per_s;

const Sink = struct {
    received: u32 = 0,

    pub fn on_flashblock(sink: *Sink, flashblock: flashblocks.Flashblock) void {
        _ = flashblock;
        sink.received += 1;
    }
};

const Subscriber = subscriber_module.Subscriber(SimIo, *Sink);

test "subscriber: capped exponential backoff while the feed is down" {
    var world = try io.SimWorld.init(testing.allocator, .{ .seed = 7 });
    defer world.deinit();
    var client_io: SimIo = undefined;
    try SimIo.init(&client_io, testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 1, 1 }, 0),
    });
    defer client_io.deinit();
    var sink: Sink = .{};
    var subscriber: Subscriber = undefined;
    const dead = Address.ip4(.{ 10, 0, 0, 9 }, 7111);
    try subscriber.init(testing.allocator, &client_io, dead, .{
        .message_size_max = 4096,
        .decode_arena_bytes = 4096,
    }, &sink);
    subscriber.start();
    const expected = [_]u64{ 1 * s, 2 * s, 4 * s, 8 * s, 10 * s, 10 * s };
    var seen: [expected.len]u64 = undefined;
    var attempts: u64 = 0;
    var rounds: u32 = 0;
    while (attempts < expected.len and rounds < 100_000) : (rounds += 1) {
        world.run_for_ns(std.time.ns_per_ms);
        if (subscriber.stats.reconnect_attempts > attempts) {
            seen[attempts] = subscriber.stats.last_backoff_ns;
            attempts = subscriber.stats.reconnect_attempts;
        }
    }
    try testing.expectEqualSlices(u64, &expected, &seen);
    try testing.expectEqual(@as(u64, 0), subscriber.stats.connections);
    try testing.expect(subscriber.stats.upstream_errors >= expected.len);
    try testing.expectEqual(@as(u32, 0), sink.received);
    subscriber.stop();
    rounds = 0;
    while (!subscriber.idle() and rounds < 1000) : (rounds += 1) {
        world.run_for_ns(std.time.ns_per_ms);
    }
    try testing.expect(subscriber.idle());
    subscriber.deinit();
}

test "subscriber: options validation and resume target" {
    const valid: subscriber_module.Options = .{};
    try valid.validate();
    var options = valid;
    options.path = "/ws?x=1";
    try testing.expectError(error.InvalidOptions, options.validate());
    options = valid;
    options.ping_interval_ns = 0;
    try testing.expectError(error.InvalidOptions, options.validate());
    options = valid;
    options.backoff.max_attempts = 3;
    try testing.expectError(error.InvalidOptions, options.validate());
    options = valid;
    options.path = "";
    try testing.expectError(error.InvalidOptions, options.validate());
}

const publish = @import("../../builder/publish/root.zig");

test "subscriber: keepalive pings, stall detection, and reconnect" {
    const ms = std.time.ns_per_ms;
    var world = try io.SimWorld.init(testing.allocator, .{ .seed = 11 });
    defer world.deinit();
    var server_io: SimIo = undefined;
    const server_host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
    try SimIo.init(&server_io, testing.allocator, &world, .{ .host = server_host });
    defer server_io.deinit();
    var client_io: SimIo = undefined;
    try SimIo.init(&client_io, testing.allocator, &world, .{
        .host = Address.ip4(.{ 10, 0, 1, 1 }, 0),
    });
    defer client_io.deinit();
    const Publisher = publish.Publisher(SimIo);
    var publisher: Publisher = undefined;
    try publisher.init(testing.allocator, &server_io, .{
        .connections_max = 2,
        .payload_size_max = 4096,
        .ring_entries_max = 4,
        .ring_bytes_max = 16 * 1024,
        .send_buffer_size = 64 * 1024,
    });
    const bound = try publisher.listen(server_host.with_port(7111));
    var sink: Sink = .{};
    var subscriber: Subscriber = undefined;
    try subscriber.init(testing.allocator, &client_io, bound, .{
        .ping_interval_ns = 50 * ms,
        .backoff = .{
            .max_attempts = null,
            .initial_delay_ns = 20 * ms,
            .max_delay_ns = 100 * ms,
            .jitter = false,
        },
        .message_size_max = 4096,
        .decode_arena_bytes = 4096,
    }, &sink);
    subscriber.start();
    world.run_for_ns(1000 * ms);
    // A healthy feed: pongs keep coming and the connection stays up.
    try testing.expectEqual(@as(u64, 1), subscriber.stats.connections);
    try testing.expectEqual(@as(u64, 0), subscriber.stats.pong_timeouts);
    try testing.expect(subscriber.client.pongs_received() >= 15);
    // A stalled connection: the unanswered ping triggers a reconnect once healed.
    world.partition(server_io.index, client_io.index);
    world.run_for_ns(300 * ms);
    try testing.expect(subscriber.stats.pong_timeouts >= 1);
    world.heal_all();
    world.run_for_ns(1000 * ms);
    try testing.expect(subscriber.connected());
    try testing.expect(subscriber.stats.connections >= 2);
    subscriber.stop();
    publisher.stop();
    var rounds: u32 = 0;
    while (rounds < 1000 and !(subscriber.idle() and publisher.stopped())) : (rounds += 1) {
        world.run_for_ns(ms);
    }
    subscriber.deinit();
    publisher.deinit();
}

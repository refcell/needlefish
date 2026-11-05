//! Deterministic simulation of the flashblocks consumer against the builder's publisher:
//! `builder/publish.Publisher(SimIo)` serves a feed while a `Subscriber(SimIo)` feeds a
//! `Processor`, under connection resets, partitions (stalled connections the keepalive
//! must detect), floods that evict the subscriber as slow, and reconnects that resume the
//! feed. Invariants, checked after every simulated millisecond: each pending block equals
//! the concatenation of the deltas published for it, in order; once caught up, the latest
//! pending block is the newest published one and every flashblock was applied exactly once
//! (no duplicates, gaps, or restarts).

const std = @import("std");
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const publish = @import("../../builder/publish/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const processor_module = @import("processor.zig");
const subscriber_module = @import("subscriber.zig");
const state = @import("state.zig");
const test_feed = @import("test_feed.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const SimIo = io.SimIo;
const Address = io.Address;
const Publisher = publish.Publisher(SimIo);
const Processor = processor_module.Processor(state.Noop);

const published_max = 400;
const blocks_max = published_max;
const ms = std.time.ns_per_ms;

const Consumer = struct {
    const Subscriber = subscriber_module.Subscriber(SimIo, *Consumer);

    harness: *Harness,
    subscriber: Subscriber = undefined,
    noop: state.Noop = .{},
    processor: Processor = undefined,
    failure: ?anyerror = null,

    pub fn on_flashblock(consumer: *Consumer, flashblock: flashblocks.Flashblock) void {
        consumer.processor.on_flashblock(flashblock);
        consumer.check() catch |err| {
            if (consumer.failure == null) consumer.failure = err;
        };
    }

    fn check(consumer: *const Consumer) !void {
        const pending = &consumer.processor.pending;
        try test_feed.expect_pending(pending);
        var position: u32 = 0;
        while (position < pending.count) : (position += 1) {
            const block = pending.at(position);
            const published = consumer.harness.published_count(block.block_number);
            try testing.expect(block.flashblock_count <= published);
        }
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_io: SimIo,
    publisher: Publisher,
    consumer: Consumer,
    prng: Prng,
    first_block: u64 = 1000,
    /// Flashblocks published per block, from `first_block`.
    lengths: [blocks_max]u32 = @splat(0),
    block: u64 = 1000,
    published: u32 = 0,

    fn init(harness: *Harness, seed: u64) !void {
        harness.* = .{
            .world = undefined,
            .server_io = undefined,
            .client_io = undefined,
            .publisher = undefined,
            .consumer = .{ .harness = harness },
            .prng = Prng.init(seed),
        };
        harness.world = try io.SimWorld.init(testing.allocator, .{
            .seed = seed,
            .reset_ppm = 400,
            .pipe_size_bytes = 32 * 1024,
        });
        errdefer harness.world.deinit();
        const server_host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try SimIo.init(&harness.server_io, testing.allocator, &harness.world, .{
            .host = server_host,
        });
        var options: publish.publisher.Options = .{
            .connections_max = 4,
            .payload_size_max = 8 * 1024,
            .ring_entries_max = published_max,
            .ring_bytes_max = published_max * 2048,
        };
        // The smallest send buffer a full replay fits in: lag disconnects come early.
        options.send_buffer_size = @intCast(options.replay_bytes_max());
        try harness.publisher.init(testing.allocator, &harness.server_io, options);
        const bound = try harness.publisher.listen(server_host.with_port(7111));
        try SimIo.init(&harness.client_io, testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 1, 1 }, 0),
        });
        try harness.init_consumer(seed, bound);
    }

    fn init_consumer(harness: *Harness, seed: u64, bound: Address) !void {
        const consumer = &harness.consumer;
        consumer.processor = try Processor.init(testing.allocator, .{
            .max_depth = 5,
            .limits = .{
                .blocks_max = 8,
                .flashblocks_per_block_max = 64,
                .transactions_per_block_max = 256,
                .transaction_bytes_per_block_max = 16 * 1024,
            },
            .cache = .{ .entries_max = 16, .bytes_max = 64 * 1024 },
            .decode_arena_bytes = 128 * 1024,
        }, &consumer.noop);
        try consumer.subscriber.init(testing.allocator, &harness.client_io, bound, .{
            .path = "/ws",
            .ping_interval_ns = 50 * ms,
            .backoff = .{
                .max_attempts = null,
                .initial_delay_ns = 10 * ms,
                .max_delay_ns = 200 * ms,
                .jitter = false,
            },
            .message_size_max = 16 * 1024,
            .decode_arena_bytes = 128 * 1024,
            .seed = seed,
        }, consumer);
    }

    fn deinit(harness: *Harness) void {
        harness.consumer.subscriber.stop();
        harness.publisher.stop();
        harness.world.heal_all();
        var rounds: u32 = 0;
        while (rounds < 2000 and !harness.quiet()) : (rounds += 1) {
            harness.world.run_for_ns(ms);
        }
        harness.consumer.subscriber.deinit();
        harness.consumer.processor.deinit(testing.allocator);
        harness.publisher.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }

    fn quiet(harness: *const Harness) bool {
        return harness.publisher.stopped() and harness.consumer.subscriber.idle();
    }

    fn published_count(harness: *const Harness, block_number: u64) u32 {
        if (block_number < harness.first_block) return 0;
        const offset = block_number - harness.first_block;
        if (offset >= harness.lengths.len) return 0;
        return harness.lengths[offset];
    }

    fn publish_next(harness: *Harness) !void {
        const offset = harness.block - harness.first_block;
        if (harness.lengths[offset] > 0 and harness.prng.chance(1, 5)) harness.block += 1;
        const block_offset = harness.block - harness.first_block;
        const index = harness.lengths[block_offset];
        const parent_last = if (block_offset == 0) 0 else harness.lengths[block_offset - 1] - 1;
        var built: test_feed.Built = .{};
        built.build(harness.block, index, test_feed.block_hash(harness.block - 1, parent_last));
        _ = try harness.publisher.publish(built.flashblock);
        harness.lengths[block_offset] += 1;
        harness.published += 1;
    }

    fn step(harness: *Harness) !void {
        harness.world.run_for_ns(ms);
        if (harness.consumer.failure) |err| return err;
        try harness.consumer.check();
    }

    fn caught_up(harness: *const Harness) bool {
        const block = harness.consumer.processor.pending.latest() orelse return false;
        return block.block_number == harness.block and
            block.flashblock_count == harness.published_count(harness.block);
    }
};

/// Returns (reconnects, pong timeouts).
fn run_simulation(seed: u64) ![2]u64 {
    const harness = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(harness);
    try harness.init(seed);
    defer harness.deinit();
    const subscriber = &harness.consumer.subscriber;
    subscriber.start();
    // Publish only once subscribed: the first connection has no resume position.
    var rounds: u32 = 0;
    while (!subscriber.connected() and rounds < 5000) : (rounds += 1) try harness.step();
    try testing.expect(subscriber.connected());
    const publishes = harness.prng.range(published_max / 2, published_max);
    var partitioned = false;
    while (harness.published < publishes) {
        const burst = if (harness.prng.chance(1, 30)) harness.prng.range(4, 40) else 1;
        for (0..burst) |_| {
            if (harness.published == publishes) break;
            try harness.publish_next();
        }
        if (partitioned and harness.prng.chance(1, 30)) {
            harness.world.heal_all();
            partitioned = false;
        } else if (!partitioned and harness.prng.chance(1, 60)) {
            harness.world.partition(harness.server_io.index, harness.client_io.index);
            partitioned = true;
        }
        for (0..harness.prng.range(1, 10)) |_| try harness.step();
    }
    harness.world.heal_all();
    rounds = 0;
    while (!harness.caught_up() and rounds < 30_000) : (rounds += 1) try harness.step();
    try testing.expect(harness.caught_up());
    const stats = harness.consumer.processor.stats;
    try testing.expectEqual(@as(u64, harness.published), stats.applied);
    try testing.expectEqual(@as(u64, 0), stats.duplicates);
    try testing.expectEqual(@as(u64, 0), stats.unexpected_order);
    try testing.expectEqual(@as(u64, 0), stats.missing_first);
    const subscriber_stats = subscriber.stats;
    try testing.expectEqual(@as(u64, 0), subscriber_stats.decode_errors);
    return .{ subscriber_stats.connections - 1, subscriber_stats.pong_timeouts };
}

test "consumer: simulated feed with resets, partitions, and floods" {
    var prng = Prng.init(0xc0_53e);
    var reconnects: u64 = 0;
    var pong_timeouts: u64 = 0;
    for (0..5) |_| {
        const seed = prng.int(u64);
        const result = run_simulation(seed) catch |err| {
            std.debug.print("consumer sim seed {d} failed\n", .{seed});
            return err;
        };
        reconnects += result[0];
        pong_timeouts += result[1];
    }
    // Faults happened, so exactly-once assembly held across reconnects and stalls.
    try testing.expect(reconnects > 0);
    try testing.expect(pong_timeouts > 0);
}

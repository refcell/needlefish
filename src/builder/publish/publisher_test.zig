//! Publisher tests: resume-query parsing, and a deterministic simulation with several
//! subscribers that are reset, partitioned, and flooded, then reconnect with a resume
//! position. Invariant: every subscriber sees flashblocks in strictly increasing position
//! order, byte-identical to what was published, and catches up to the newest one; with a
//! ring large enough to cover every outage it sees every flashblock exactly once.

const std = @import("std");
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const ws = @import("../../utilities/ws/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const publisher_module = @import("publisher.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const SimIo = io.SimIo;
const Address = io.Address;
const Position = publisher_module.Position;
const parse_resume_position = publisher_module.parse_resume_position;

fn at(block_number: u64, flashblock_index: u64) Position {
    return .{ .block_number = block_number, .flashblock_index = flashblock_index };
}

fn expect_resume(expected: ?Position, target: []const u8) !void {
    try testing.expectEqual(expected, parse_resume_position(target));
}

test "publisher: parse resume position like base/base" {
    try expect_resume(at(5, 2), "/?block_number=5&flashblock_index=2");
    try expect_resume(at(5, 2), "/ws?flashblock_index=2&x=1&block_number=5");
    try expect_resume(at(7, 2), "/?block_number=5&block_number=7&flashblock_index=2");
    try expect_resume(at(5, 2), "/?block_number=+5&flashblock_index=2#f");
    try expect_resume(null, "/");
    try expect_resume(null, "/?block_number=5");
    try expect_resume(null, "/?block_number=5&flashblock_index=-1");
    try expect_resume(null, "/?block_number=1_0&flashblock_index=2");
    try expect_resume(null, "/?block_number=5&flashblock_index=2&block_number=x");
    try expect_resume(null, "/?block_number=5#&flashblock_index=2");
    try expect_resume(null, "/?block_number&flashblock_index=2");
}

fn parse_any(text: []const u8) !void {
    const position = parse_resume_position(text) orelse return;
    // A parsed position means both keys appear after the '?'.
    const query = text[std.mem.indexOfScalar(u8, text, '?').?..];
    try testing.expect(std.mem.indexOf(u8, query, "block_number=") != null);
    try testing.expect(std.mem.indexOf(u8, query, "flashblock_index=") != null);
    _ = position;
}

test "publisher: seeded fuzz resume query" {
    const pieces = [_][]const u8{
        "block_number=", "flashblock_index=", "&", "=", "?", "#", "1", "99", "+", "_", "x",
    };
    var prng = Prng.init(0x9e5_0e);
    var text: [96]u8 = undefined;
    for (0..5_000) |_| {
        var length: usize = 0;
        text[0] = '/';
        length = 1;
        for (0..prng.below(10)) |_| {
            const piece = pieces[prng.below(pieces.len)];
            if (length + piece.len > text.len) break;
            @memcpy(text[length..][0..piece.len], piece);
            length += piece.len;
        }
        try parse_any(text[0..length]);
    }
}

test "publisher: fuzz resume query" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var text: [128]u8 = undefined;
            try parse_any(text[0..smith.slice(&text)]);
        }
    }.run, .{});
}

const Publisher = publisher_module.Publisher(SimIo);

/// A flashblock whose diff carries a filler transaction, so payload sizes vary.
fn make_flashblock(position: Position, filler: []const u8) flashblocks.Flashblock {
    return .{
        .payload_id = @splat(@truncate(position.block_number)),
        .index = position.flashblock_index,
        .base = null,
        .diff = .{
            .state_root = .zero,
            .receipts_root = .zero,
            .logs_bloom = .zero,
            .gas_used = position.flashblock_index,
            .block_hash = .zero,
            .transactions = &.{filler},
            .withdrawals = &.{},
            .withdrawals_root = .zero,
        },
        .metadata = .{ .block_number = position.block_number },
    };
}

const published_max = 400;
const subscribers_max = 4;
const message_size_max = 8 * 1024;

const Subscriber = struct {
    const Client = ws.Client(SimIo, *Subscriber);
    const handlers: ws.client.Handlers(Client, *Subscriber) = .{
        .on_open = on_open,
        .on_message = on_message,
        .on_close = on_close,
    };

    harness: *Harness = undefined,
    client: Client = undefined,
    last: ?Position = null,
    received: u32 = 0,
    connections: u32 = 0,
    connected: bool = false,
    reconnect_at_ns: ?u64 = null,
    failure: ?anyerror = null,
    target: [96]u8 = undefined,

    fn on_open(subscriber: *Subscriber, client: *Client) void {
        _ = client;
        subscriber.connected = true;
        subscriber.connections += 1;
    }

    fn on_message(subscriber: *Subscriber, client: *Client, message: ws.client.Message) void {
        _ = client;
        subscriber.check(message) catch |err| {
            if (subscriber.failure == null) subscriber.failure = err;
        };
    }

    fn check(subscriber: *Subscriber, message: ws.client.Message) !void {
        try testing.expectEqual(ws.Opcode.text, message.opcode);
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const flashblock = try flashblocks.decode_message(arena_state.allocator(), message.payload);
        const position = at(flashblock.metadata.block_number, flashblock.index);
        if (subscriber.last) |last| try testing.expect(last.less_than(position));
        const harness = subscriber.harness;
        const sequence = harness.sequence_of(position) orelse return error.UnknownPosition;
        try testing.expectEqualSlices(u8, harness.published_json(sequence), message.payload);
        if (harness.ring_covers_outages) {
            // Exactly once and gap-free: the next one after the previous.
            const expected: u32 = if (subscriber.last) |last|
                harness.sequence_of(last).? + 1
            else
                sequence;
            try testing.expectEqual(expected, sequence);
        }
        subscriber.last = position;
        subscriber.received += 1;
    }

    fn on_close(subscriber: *Subscriber, client: *Client, closed: ws.client.Closed) void {
        _ = client;
        _ = closed;
        subscriber.connected = false;
        const harness = subscriber.harness;
        const now_ns = harness.world.now_ns;
        if (harness.stopping) return;
        subscriber.reconnect_at_ns = now_ns + harness.prng.range(1, 50) * std.time.ns_per_ms;
    }

    fn connect(subscriber: *Subscriber) void {
        subscriber.reconnect_at_ns = null;
        // A fresh subscriber resumes from (0, 0) so it also gets what was published
        // before its handshake finished.
        const last = subscriber.last orelse at(0, 0);
        subscriber.client.options.target = std.fmt.bufPrint(
            &subscriber.target,
            "/ws?block_number={d}&flashblock_index={d}",
            .{ last.block_number, last.flashblock_index },
        ) catch unreachable; // Two u64s fit in 96 bytes.
        subscriber.client.connect();
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: SimIo,
    client_ios: [subscribers_max]SimIo,
    publisher: Publisher,
    bound: Address,
    subscribers: [subscribers_max]Subscriber,
    prng: Prng,
    ring_covers_outages: bool,
    stopping: bool = false,
    published_positions: [published_max]Position = undefined,
    published_offsets: [published_max + 1]u32 = undefined,
    published_bytes: []u8,
    published_count: u32 = 0,

    fn init(harness: *Harness, seed: u64, ring_covers_outages: bool) !void {
        harness.prng = Prng.init(seed);
        harness.ring_covers_outages = ring_covers_outages;
        harness.stopping = false;
        harness.published_count = 0;
        harness.published_offsets[0] = 0;
        harness.published_bytes = try testing.allocator.alloc(u8, published_max * 2048);
        errdefer testing.allocator.free(harness.published_bytes);
        harness.world = try io.SimWorld.init(testing.allocator, .{
            .seed = seed,
            .reset_ppm = if (ring_covers_outages) 0 else 300,
            .pipe_size_bytes = 32 * 1024,
        });
        const server_host = Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try SimIo.init(&harness.server_io, testing.allocator, &harness.world, .{
            .host = server_host,
        });
        try harness.publisher.init(testing.allocator, &harness.server_io, .{
            .connections_max = subscribers_max + 1,
            .send_buffer_size = 16 * 1024,
            .payload_size_max = message_size_max,
            .ring_entries_max = if (ring_covers_outages) published_max else 12,
            .ring_bytes_max = if (ring_covers_outages) published_max * 2048 else 12 * 2048,
        });
        harness.bound = try harness.publisher.listen(server_host.with_port(7111));
        for (&harness.subscribers, &harness.client_ios, 0..) |*subscriber, *client_io, index| {
            const host = Address.ip4(.{ 10, 0, 1, @intCast(index + 1) }, 0);
            try SimIo.init(client_io, testing.allocator, &harness.world, .{ .host = host });
            subscriber.* = .{ .harness = harness };
            subscriber.client = try Subscriber.Client.init(
                testing.allocator,
                client_io,
                harness.bound,
                .{
                    .message_size_max = message_size_max,
                    .send_buffer_size = 1024,
                    .seed = seed + index,
                },
                subscriber,
                &Subscriber.handlers,
            );
        }
    }

    fn deinit(harness: *Harness) void {
        harness.stopping = true;
        harness.publisher.stop();
        for (&harness.subscribers) |*subscriber| subscriber.client.abort();
        harness.world.heal_all();
        var rounds: u32 = 0;
        while (rounds < 1000 and !harness.quiet()) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        for (&harness.subscribers) |*subscriber| subscriber.client.deinit();
        harness.publisher.deinit();
        for (&harness.client_ios) |*client_io| client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
        testing.allocator.free(harness.published_bytes);
    }

    fn quiet(harness: *const Harness) bool {
        if (!harness.publisher.stopped()) return false;
        for (&harness.subscribers) |*subscriber| if (!subscriber.client.idle()) return false;
        return true;
    }

    fn sequence_of(harness: *const Harness, position: Position) ?u32 {
        // Positions are strictly increasing: binary search.
        var low: u32 = 0;
        var high: u32 = harness.published_count;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const candidate = harness.published_positions[middle];
            if (candidate.less_than(position)) low = middle + 1 else high = middle;
        }
        if (low == harness.published_count) return null;
        if (!std.meta.eql(harness.published_positions[low], position)) return null;
        return low;
    }

    fn published_json(harness: *const Harness, sequence: u32) []const u8 {
        const start = harness.published_offsets[sequence];
        return harness.published_bytes[start..harness.published_offsets[sequence + 1]];
    }

    fn publish_next(harness: *Harness, position: *Position) !void {
        if (harness.prng.chance(1, 6)) {
            position.* = at(position.block_number + 1, 0);
        } else {
            position.flashblock_index += 1;
        }
        var filler: [1024]u8 = undefined;
        const filler_length = harness.prng.below(filler.len);
        harness.prng.fill(filler[0..filler_length]);
        const flashblock = make_flashblock(position.*, filler[0..filler_length]);
        const sequence = harness.published_count;
        const start = harness.published_offsets[sequence];
        const json = try flashblocks.encode_json(flashblock, harness.published_bytes[start..]);
        const size = try harness.publisher.publish(flashblock);
        try testing.expectEqual(@as(u32, @intCast(json.len)), size);
        harness.published_positions[sequence] = position.*;
        harness.published_offsets[sequence + 1] = start + size;
        harness.published_count += 1;
    }

    /// One millisecond of simulated time plus the subscribers' reconnects.
    fn step(harness: *Harness) void {
        harness.world.run_for_ns(std.time.ns_per_ms);
        const now_ns = harness.world.now_ns;
        for (&harness.subscribers) |*subscriber| {
            const due = subscriber.reconnect_at_ns orelse continue;
            if (due <= now_ns and subscriber.client.idle()) subscriber.connect();
        }
    }

    fn caught_up(harness: *const Harness) bool {
        const newest = harness.published_positions[harness.published_count - 1];
        for (&harness.subscribers) |*subscriber| {
            const last = subscriber.last orelse return false;
            if (!std.meta.eql(last, newest)) return false;
        }
        return true;
    }
};

fn run_simulation(seed: u64, ring_covers_outages: bool) !void {
    var harness: Harness = undefined;
    try harness.init(seed, ring_covers_outages);
    defer harness.deinit();
    for (&harness.subscribers) |*subscriber| subscriber.connect();
    var position = at(100, 0);
    const publishes = harness.prng.range(published_max / 2, published_max);
    var partitioned: ?u32 = null;
    while (harness.published_count < publishes) {
        // A burst without running the loop can overflow subscriber send buffers.
        const burst = if (harness.prng.chance(1, 30)) harness.prng.range(4, 30) else 1;
        for (0..burst) |_| {
            if (harness.published_count == publishes) break;
            try harness.publish_next(&position);
        }
        if (partitioned) |node| {
            if (harness.prng.chance(1, 40)) {
                harness.world.heal(harness.server_io.index, node);
                partitioned = null;
            }
        } else if (harness.prng.chance(1, 80)) {
            const node = harness.client_ios[harness.prng.below(subscribers_max)].index;
            harness.world.partition(harness.server_io.index, node);
            partitioned = node;
        }
        for (0..harness.prng.range(1, 10)) |_| harness.step();
    }
    harness.world.heal_all();
    var rounds: u32 = 0;
    while (!harness.caught_up() and rounds < 20_000) : (rounds += 1) harness.step();
    for (&harness.subscribers) |*subscriber| {
        if (subscriber.failure) |err| return err;
    }
    try testing.expect(harness.caught_up());
    const metrics = &harness.publisher.metrics;
    try testing.expect(metrics.messages_sent.get() > 0);
    if (ring_covers_outages) {
        // Fresh subscribers resume from (0, 0), older than the ring: counted as stale.
        try testing.expect(metrics.replay_stale_position.get() >= subscribers_max);
        for (&harness.subscribers) |*subscriber| {
            try testing.expectEqual(harness.published_count, subscriber.received);
        }
    }
}

test "publisher: simulated subscribers survive resets, partitions, and floods" {
    var prng = Prng.init(0xf1a5_b10c);
    for (0..6) |_| {
        const seed = prng.int(u64);
        run_simulation(seed, true) catch |err| {
            std.debug.print("publisher sim seed {d} (full ring) failed\n", .{seed});
            return err;
        };
        run_simulation(seed, false) catch |err| {
            std.debug.print("publisher sim seed {d} (small ring) failed\n", .{seed});
            return err;
        };
    }
}

test "publisher: replay on resume and eviction of a stalled subscriber" {
    var harness: Harness = undefined;
    try harness.init(42, true);
    defer harness.deinit();
    var position = at(7, 0);
    for (0..5) |_| try harness.publish_next(&position);
    // Connect with a resume position: everything after the second flashblock replays.
    const subscriber = &harness.subscribers[0];
    subscriber.last = harness.published_positions[1];
    subscriber.connect();
    var rounds: u32 = 0;
    while (subscriber.received < 3 and rounds < 2000) : (rounds += 1) harness.step();
    try testing.expectEqual(@as(u32, 3), subscriber.received);
    try testing.expectEqual(@as(u64, 3), harness.publisher.metrics.replay_messages_sent.get());
    try testing.expectEqual(@as(i64, 1), harness.publisher.metrics.connections_active.get());
    // Stall it with a partition and flood: it is dropped as lagging, then catches up.
    harness.world.partition(harness.server_io.index, harness.client_ios[0].index);
    for (0..40) |_| try harness.publish_next(&position);
    try testing.expect(harness.publisher.metrics.lagged.get() >= 1);
    harness.world.heal_all();
    rounds = 0;
    while (subscriber.received < 43 and rounds < 20_000) : (rounds += 1) harness.step();
    if (subscriber.failure) |err| return err;
    try testing.expectEqual(@as(u32, 43), subscriber.received);
    try testing.expect(subscriber.connections >= 2);
}

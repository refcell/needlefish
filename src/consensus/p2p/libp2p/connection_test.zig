//! Tests for `connection.zig`: two connections wired back to back in memory.
//! Handshakes are slow in Debug (secp256k1, X25519), so each test runs as few as it can.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const connection_module = @import("connection.zig");
const multistream = @import("multistream.zig");
const noise = @import("noise.zig");
const identify = @import("identify.zig");
const ping = @import("ping.zig");
const peer_id = @import("../peers/peer_id.zig");
const multiaddr = @import("../peers/multiaddr.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const rpc = @import("../gossip/rpc.zig");
const fuzz = @import("../../../testing/fuzz.zig");
pub const Prng = @import("../../../testing/prng.zig").Prng;

const Connection = connection_module.Connection;
const Config = connection_module.Config;
const CloseReason = connection_module.CloseReason;
const IdentifySummary = connection_module.IdentifySummary;
const PeerId = connection_module.PeerId;

const ns_per_ms = std.time.ns_per_ms;
const frame_size_max: u32 = 2 * 1024 * 1024;

var flush_buffer: [96 * 1024]u8 = undefined;

fn test_config(prng: *Prng, agent: []const u8) Config {
    var config: Config = .{
        .identity_secret = undefined,
        .static_seed = undefined,
        .ephemeral_seed = undefined,
        .random_seed = prng.int(u64),
        .now_ns = 0,
        .agent_version = agent,
        .gossip_frame_size_max = frame_size_max,
    };
    for (0..64) |_| {
        prng.fill(&config.identity_secret);
        secp256k1.validate_secret_key(config.identity_secret) catch continue;
        break;
    }
    prng.fill(&config.static_seed);
    prng.fill(&config.ephemeral_seed);
    return config;
}

fn expected_peer(config: Config) !PeerId {
    return peer_id.from_public_key(try secp256k1.public_key(config.identity_secret));
}

/// Everything one connection reported. Gossip payloads are checked against the frames
/// the other side sent, in order, as they arrive.
const Record = struct {
    established: ?PeerId = null,
    identified: ?IdentifySummary = null,
    gossip_count: u32 = 0,
    ping_rtt_ns: ?u64 = null,
    closed: ?CloseReason = null,
    expected: []const []const u8 = &.{},
    mismatches: u32 = 0,

    fn drain(record: *Record, connection: *Connection) void {
        for (0..connection_module.event_count_max + 1) |_| {
            const event = connection.pop_event() orelse return;
            switch (event) {
                .established => |peer| record.established = peer,
                .identified => |summary| record.identified = summary,
                .gossip_frame => |payload| record.on_gossip(payload),
                .ping_rtt_ns => |rtt| record.ping_rtt_ns = rtt,
                .closed => |reason| record.closed = reason,
            }
        }
        unreachable; // The queue holds at most `event_count_max` events.
    }

    fn on_gossip(record: *Record, payload: []const u8) void {
        const index = record.gossip_count;
        record.gossip_count += 1;
        if (index >= record.expected.len) {
            record.mismatches += 1;
            return;
        }
        const frame = record.expected[index];
        const header = (rpc.frame_decode(frame, frame_size_max) catch unreachable).?;
        if (!std.mem.eql(u8, header.payload, payload)) record.mismatches += 1;
    }
};

pub const Mutation = struct {
    prng: *Prng,
    /// Flip the byte at this offset of the combined stream, if any.
    flip_at: ?u64 = null,
    flipped: bool = false,
    delivered: u64 = 0,
    chunk_max: u32,

    fn apply(mutation: *Mutation, bytes: []u8) void {
        defer mutation.delivered += bytes.len;
        const at = mutation.flip_at orelse return;
        if (mutation.flipped or at < mutation.delivered) return;
        if (at >= mutation.delivered + bytes.len) return;
        bytes[@intCast(at - mutation.delivered)] ^= 0x20;
        mutation.flipped = true;
    }
};

pub const Pair = struct {
    dialer: Connection,
    listener: Connection,
    dialer_record: Record = .{},
    listener_record: Record = .{},
    now_ns: u64 = 0,

    pub fn init(prng: *Prng) !Pair {
        var listener_config = test_config(prng, "needlefish-listener");
        const address = [_]multiaddr.Multiaddr{try multiaddr.parse("/ip4/127.0.0.1/tcp/9222")};
        listener_config.listen_addresses = &address;
        var dialer = try Connection.init(testing.allocator, .dialer, test_config(prng, "nf-d"));
        errdefer dialer.deinit();
        const listener = try Connection.init(testing.allocator, .listener, listener_config);
        return .{ .dialer = dialer, .listener = listener };
    }

    pub fn deinit(pair: *Pair) void {
        pair.dialer.deinit();
        pair.listener.deinit();
    }

    /// Moves bytes both ways until neither side has anything to send.
    pub fn pump(pair: *Pair, mutation: *Mutation) !void {
        for (0..4096) |_| {
            const forward = transfer(pair, .forward, mutation);
            const backward = transfer(pair, .backward, mutation);
            if (forward == 0 and backward == 0) return;
        }
        return error.PumpDidNotSettle;
    }

    fn transfer(pair: *Pair, direction: enum { forward, backward }, mutation: *Mutation) usize {
        const from = if (direction == .forward) &pair.dialer else &pair.listener;
        const to = if (direction == .forward) &pair.listener else &pair.dialer;
        const record = if (direction == .forward) &pair.listener_record else &pair.dialer_record;
        var moved: usize = 0;
        for (0..1024) |_| {
            pair.now_ns += ns_per_ms;
            const length = from.flush(&flush_buffer).len;
            if (length == 0) break;
            moved += length;
            const bytes = flush_buffer[0..length];
            mutation.apply(bytes);
            var offset: usize = 0;
            while (offset < length) {
                const chunk: usize = @intCast(mutation.prng.range(1, mutation.chunk_max));
                const take = @min(chunk, length - offset);
                const consumed = to.receive(bytes[offset..][0..take], pair.now_ns) catch {
                    record.drain(to);
                    return moved;
                };
                assert(consumed == take);
                record.drain(to);
                offset += take;
            }
        }
        return moved;
    }
};

fn make_frame(prng: *Prng, payload_length: u32) ![]u8 {
    var header: [rpc.varint_length_max]u8 = undefined;
    const prefix = rpc.frame_header(&header, payload_length);
    const frame = try testing.allocator.alloc(u8, prefix.len + payload_length);
    @memcpy(frame[0..prefix.len], prefix);
    prng.fill(frame[prefix.len..]);
    return frame;
}

fn expect_established(pair: *Pair, dialer_config: ?Config) !void {
    try testing.expect(pair.dialer.is_established());
    try testing.expect(pair.listener.is_established());
    const dialer_peer = pair.dialer.local_peer();
    const listener_peer = pair.listener.local_peer();
    try testing.expect(pair.dialer.remote_peer().?.eql(&listener_peer));
    try testing.expect(pair.listener.remote_peer().?.eql(&dialer_peer));
    try testing.expect(pair.dialer_record.established.?.eql(&listener_peer));
    try testing.expect(pair.listener_record.established.?.eql(&dialer_peer));
    if (dialer_config) |config| try testing.expect(dialer_peer.eql(&try expected_peer(config)));
}

test "connection: handshake, identify, gossip both ways with a 1 MiB frame, ping" {
    var prng = Prng.init(0x636f_6e6e);
    var pair = try Pair.init(&prng);
    defer pair.deinit();
    var mutation: Mutation = .{ .prng = &prng, .chunk_max = 64 * 1024 };
    try testing.expectError(error.NotEstablished, pair.dialer.send_gossip(&.{ 1, 0 }));
    try pair.pump(&mutation);
    try expect_established(&pair, null);

    const dialer_identified = pair.dialer_record.identified.?;
    try testing.expectEqualStrings("needlefish-listener", dialer_identified.agent_version);
    try testing.expectEqualStrings("", dialer_identified.protocol_version);
    try testing.expectEqual(@as(u32, 1), dialer_identified.listen_address_count);
    try testing.expectEqual(@as(u32, 4), dialer_identified.protocol_count);
    try testing.expect(dialer_identified.supports_meshsub);
    try testing.expectEqualStrings("nf-d", pair.listener_record.identified.?.agent_version);
    try testing.expect(pair.listener.remote_identify_message().?.supports(ping.protocol_id));
    try testing.expect(pair.dialer_record.ping_rtt_ns.? > 0);
    try testing.expect(pair.listener_record.ping_rtt_ns.? > 0);

    const small = try make_frame(&prng, 100);
    defer testing.allocator.free(small);
    const large = try make_frame(&prng, 1024 * 1024);
    defer testing.allocator.free(large);
    const empty = try make_frame(&prng, 0);
    defer testing.allocator.free(empty);
    const forward = [_][]const u8{ small, large, empty };
    const backward = [_][]const u8{ large, small };
    pair.listener_record.expected = &forward;
    pair.dialer_record.expected = &backward;
    for (forward) |frame| try pair.dialer.send_gossip(frame);
    for (backward) |frame| try pair.listener.send_gossip(frame);
    try pair.pump(&mutation);
    try testing.expectEqual(@as(u32, forward.len), pair.listener_record.gossip_count);
    try testing.expectEqual(@as(u32, backward.len), pair.dialer_record.gossip_count);
    try testing.expectEqual(@as(u32, 0), pair.listener_record.mismatches);
    try testing.expectEqual(@as(u32, 0), pair.dialer_record.mismatches);

    try testing.expectError(error.InvalidFrame, pair.dialer.send_gossip(small[0 .. small.len - 1]));
    try testing.expectError(error.InvalidFrame, pair.dialer.send_gossip(&.{}));
    const oversize = try make_frame(&prng, frame_size_max + 1);
    defer testing.allocator.free(oversize);
    try testing.expectError(error.InvalidFrame, pair.dialer.send_gossip(oversize));
    const full = try make_frame(&prng, frame_size_max - 16);
    defer testing.allocator.free(full);
    try pair.dialer.send_gossip(full);
    try testing.expectError(error.QueueFull, pair.dialer.send_gossip(small));
    try testing.expect(pair.dialer_record.closed == null and pair.listener_record.closed == null);
}

test "connection: byte-at-a-time delivery" {
    var prng = Prng.init(0x6279_7465);
    var pair = try Pair.init(&prng);
    defer pair.deinit();
    var mutation: Mutation = .{ .prng = &prng, .chunk_max = 1 };
    try pair.pump(&mutation);
    try expect_established(&pair, null);
    try testing.expect(pair.dialer_record.identified != null);
    try testing.expect(pair.listener_record.identified != null);
    const frame = try make_frame(&prng, 300);
    defer testing.allocator.free(frame);
    const frames = [_][]const u8{ frame, frame };
    pair.listener_record.expected = &frames;
    try pair.dialer.send_gossip(frame);
    try pair.dialer.send_gossip(frame);
    try pair.pump(&mutation);
    try testing.expectEqual(@as(u32, 2), pair.listener_record.gossip_count);
    try testing.expectEqual(@as(u32, 0), pair.listener_record.mismatches);
}

test "connection: tampered ciphertext closes, unanswered ping times out" {
    var prng = Prng.init(0x7461_6d70);
    var pair = try Pair.init(&prng);
    defer pair.deinit();
    var mutation: Mutation = .{ .prng = &prng, .chunk_max = 4096 };
    try pair.pump(&mutation);
    try expect_established(&pair, null);
    const frame = try make_frame(&prng, 50);
    defer testing.allocator.free(frame);
    try pair.dialer.send_gossip(frame);
    const length = pair.dialer.flush(&flush_buffer).len;
    try testing.expect(length > 50);
    flush_buffer[length - 1] ^= 0x01;
    try testing.expectError(error.Closed, pair.listener.receive(flush_buffer[0..length], 1));
    pair.listener_record.drain(&pair.listener);
    try testing.expectEqual(CloseReason.decrypt_failed, pair.listener_record.closed.?);
    try testing.expectEqual(CloseReason.decrypt_failed, pair.listener.closed_reason().?);
    try testing.expectError(error.Closed, pair.listener.receive(&.{0}, 2));
    try testing.expectEqual(@as(usize, 0), pair.listener.flush(&flush_buffer).len);

    // The dialer keeps pinging into the void and gives up after the timeout.
    const start = pair.now_ns;
    pair.dialer.tick(start + ping.interval_ns);
    try testing.expect(pair.dialer.flush(&flush_buffer).len > 0);
    pair.dialer.tick(start + ping.interval_ns + ping.timeout_ns / 2);
    try testing.expect(pair.dialer.closed_reason() == null);
    pair.dialer.tick(start + ping.interval_ns + ping.timeout_ns);
    pair.dialer_record.drain(&pair.dialer);
    try testing.expectEqual(CloseReason.ping_timeout, pair.dialer_record.closed.?);
}

/// Feeds `input` to `fake` until it settles or fails.
fn feed_dialer(fake: *multistream.Dialer, input: []const u8) multistream.Error!bool {
    var offset: usize = 0;
    var reply: [multistream.frame_length_max]u8 = undefined;
    while (offset < input.len) {
        const step = try fake.receive(input[offset..], &reply);
        offset += step.consumed;
        if (step.outcome == .selected) return true;
    }
    return false;
}

test "connection: unsupported security protocol fails cleanly, handshake timeout" {
    var prng = Prng.init(0x6e61_6e61);
    var listener = try Connection.init(testing.allocator, .listener, test_config(&prng, "l"));
    defer listener.deinit();
    var fake_dialer = multistream.Dialer.init(&.{"/tls/1.0.0"});
    var opening: [2 * multistream.frame_length_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try listener.receive(&.{}, 0));
    const hello = fake_dialer.start(&opening);
    try testing.expectEqual(hello.len, try listener.receive(hello, 0));
    const answer = listener.flush(&flush_buffer);
    try testing.expectError(error.NegotiationFailed, feed_dialer(&fake_dialer, answer));
    listener.tick(connection_module.handshake_timeout_ns - 1);
    try testing.expect(listener.closed_reason() == null);
    listener.tick(connection_module.handshake_timeout_ns);
    try testing.expectEqual(CloseReason.handshake_timeout, listener.closed_reason().?);
    try testing.expectError(error.Closed, listener.receive(&.{0}, 0));

    var dialer = try Connection.init(testing.allocator, .dialer, test_config(&prng, "d"));
    defer dialer.deinit();
    var fake_listener = multistream.Listener.init(&.{"/tls/1.0.0"});
    var replies: [4 * multistream.frame_length_max]u8 = undefined;
    var replies_length = fake_listener.start(&replies).len;
    const proposal = dialer.flush(&flush_buffer);
    var offset: usize = 0;
    while (offset < proposal.len) {
        const step = try fake_listener.receive(proposal[offset..], replies[replies_length..]);
        offset += step.consumed;
        replies_length += step.output.len;
    }
    try testing.expectError(error.Closed, dialer.receive(replies[0..replies_length], 0));
    try testing.expectEqual(CloseReason.negotiation_failed, dialer.closed_reason().?);
    try testing.expectError(error.Closed, dialer.send_gossip(&.{ 1, 0 }));
}

test "connection: seeded fuzz of a mutated byte stream" {
    var prng = Prng.init(0x6d75_7461);
    var pair = try Pair.init(&prng);
    defer pair.deinit();
    const pristine_dialer = pair.dialer;
    const pristine_listener = pair.listener;
    const dialer_opening = try Opening.save(&pristine_dialer);
    const listener_opening = try Opening.save(&pristine_listener);
    const frame = try make_frame(&prng, 2000);
    defer testing.allocator.free(frame);
    const frames = [_][]const u8{frame};
    var flipped_count: u32 = 0;
    var closed_count: u32 = 0;
    for (0..16) |iteration| {
        restore(&pair.dialer, &pristine_dialer, &dialer_opening);
        restore(&pair.listener, &pristine_listener, &listener_opening);
        pair.dialer_record = .{ .expected = &frames };
        pair.listener_record = .{ .expected = &frames };
        pair.now_ns = 0;
        var mutation: Mutation = .{
            .prng = &prng,
            .chunk_max = @intCast(prng.range(1, 2048)),
            // Iteration 0 runs clean; the others flip one byte somewhere in ~8 KiB.
            .flip_at = if (iteration == 0) null else prng.below(8 * 1024),
        };
        try pair.pump(&mutation);
        if (pair.dialer.is_established()) pair.dialer.send_gossip(frame) catch {};
        if (pair.listener.is_established()) pair.listener.send_gossip(frame) catch {};
        try pair.pump(&mutation);
        flipped_count += @intFromBool(mutation.flipped);
        closed_count += @intFromBool(pair.dialer_record.closed != null or
            pair.listener_record.closed != null);
        try check_invariants(&pair, mutation.flipped);
    }
    // Most flips land inside the ~4 KiB the connections exchange, and every flip there is
    // detected by multistream, noise, or the AEAD.
    try testing.expect(flipped_count > 0);
    try testing.expect(closed_count > 0);
}

/// The only buffer contents a fresh connection depends on: its queued opening bytes.
/// Restoring the struct plus these bytes rewinds a connection to just after `init`.
const Opening = struct {
    bytes: [256]u8 = undefined,
    length: u32,

    fn save(connection: *const Connection) !Opening {
        var opening: Opening = .{ .length = connection.raw_tx_length };
        if (opening.length > opening.bytes.len) return error.OpeningTooLong;
        @memcpy(opening.bytes[0..opening.length], connection.raw_tx[0..opening.length]);
        return opening;
    }
};

fn restore(connection: *Connection, pristine: *const Connection, opening: *const Opening) void {
    connection.* = pristine.*;
    @memcpy(connection.raw_tx[0..opening.length], opening.bytes[0..opening.length]);
}

fn check_invariants(pair: *Pair, flipped: bool) !void {
    // Delivered gossip is never corrupted, whatever was flipped.
    try testing.expectEqual(@as(u32, 0), pair.dialer_record.mismatches);
    try testing.expectEqual(@as(u32, 0), pair.listener_record.mismatches);
    try testing.expectEqual(pair.dialer_record.closed, pair.dialer.closed_reason());
    try testing.expectEqual(pair.listener_record.closed, pair.listener.closed_reason());
    if (!flipped) {
        try expect_established(pair, null);
        try testing.expectEqual(@as(u32, 1), pair.dialer_record.gossip_count);
        try testing.expectEqual(@as(u32, 1), pair.listener_record.gossip_count);
    }
    if (pair.dialer.remote_peer()) |remote| {
        const listener_peer = pair.listener.local_peer();
        try testing.expect(remote.eql(&listener_peer));
    }
    // After the handshake timeout every connection is established or closed.
    const late = pair.now_ns + connection_module.handshake_timeout_ns;
    pair.dialer.tick(late);
    pair.listener.tick(late);
    for ([_]*Connection{ &pair.dialer, &pair.listener }) |connection| {
        try testing.expect(connection.is_established() or connection.closed_reason() != null);
    }
}

const ListenerFixture = struct {
    pristine: Connection,
    opening: Opening,
    live: *Connection,
};

fn fuzz_listener(fixture: *ListenerFixture, input: []const u8) anyerror!void {
    restore(fixture.live, &fixture.pristine, &fixture.opening);
    const connection = fixture.live;
    const half = input.len / 2;
    for ([_][]const u8{ input[0..half], input[half..] }) |part| {
        const consumed = connection.receive(part, 1) catch |err| {
            try testing.expectEqual(error.Closed, err);
            try testing.expect(connection.closed_reason() != null);
            break;
        };
        try testing.expectEqual(part.len, consumed);
        _ = connection.flush(&flush_buffer);
    }
    connection.tick(connection_module.handshake_timeout_ns + 1);
    try testing.expect(connection.closed_reason() != null);
    try testing.expect(!connection.is_established());
}

test "connection: fuzz listener input" {
    var prng = Prng.init(0x6675_7a7a);
    var config = test_config(&prng, "fuzz");
    config.gossip_frame_size_max = 1024;
    var live = try Connection.init(testing.allocator, .listener, config);
    defer live.deinit();
    var fixture: ListenerFixture = .{
        .pristine = live,
        .opening = try Opening.save(&live),
        .live = &live,
    };
    const header = [_]u8{multistream.header.len + 1} ++ multistream.header.* ++ "\n".*;
    const proposal = [_]u8{noise.protocol_id.len + 1} ++ noise.protocol_id.* ++ "\n".*;
    const message_1 = [_]u8{ 0x00, 0x20 } ++ @as([32]u8, @splat(9));
    const corpus = [_][]const u8{
        &(header ++ proposal ++ message_1),
        &(header ++ proposal),
        &header,
    };
    try fuzz.run_bytes(&fixture, fuzz_listener, .{
        .input_size_max = 512,
        .iterations = 256,
        .corpus = &corpus,
    });
}

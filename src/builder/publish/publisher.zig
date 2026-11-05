//! The flashblocks WebSocket publisher. Mirrors base/base `publisher.rs`, `listener.rs`,
//! and `broadcast.rs` on the completion-based IO:
//!
//! - `publish` encodes a flashblock as JSON (a text frame, like base/base), records it in
//!   the replay ring, and queues it to every subscriber. A subscriber whose send buffer
//!   cannot take the message is disconnected (`SlowConsumer`, base/base's "lagged"); it
//!   reconnects and resumes from the ring.
//! - A subscriber that connects with `?block_number=N&flashblock_index=I` first receives
//!   every ringed flashblock after `(N, I)`. Replay runs inside `on_open` on the event
//!   loop, so no live message can interleave or be lost between replay and live
//!   streaming (base/base needs a dedup set for that; a single-threaded loop does not).
//!   A cutoff older than the ring's oldest entry still replays what is left and counts
//!   `replay_stale_position`.
//!
//! All memory is allocated at `init`: the ws connection pool, the ring, the encode buffer,
//! and per-connection open timestamps.

const std = @import("std");
const assert = std.debug.assert;

const ws = @import("../../utilities/ws/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const ring_module = @import("ring.zig");

pub const Ring = ring_module.Ring;
pub const Position = ring_module.Position;
pub const Address = ws.server.Address;

pub const Options = struct {
    connections_max: u32 = 64,
    /// Bytes queued per subscriber before it counts as lagging and is disconnected. Must
    /// hold a full replay plus one live message (`validate`), because replay queues the
    /// whole backlog at once inside `on_open`.
    send_buffer_size: u32 = 4 << 20,
    /// Largest encoded flashblock; also sizes the encode buffer.
    payload_size_max: u32 = 1 << 20,
    /// base/base `DEFAULT_RING_BUFFER_CAPACITY`.
    ring_entries_max: u32 = 16,
    ring_bytes_max: u32 = 2 << 20,
    /// Subscribers only send control frames; their data messages are ignored.
    inbound_message_size_max: u32 = 4096,
    backlog: u31 = 128,

    pub fn validate(options: Options) error{InvalidOptions}!void {
        if (options.connections_max == 0 or options.ring_entries_max == 0) {
            return error.InvalidOptions;
        }
        if (options.payload_size_max == 0) return error.InvalidOptions;
        if (options.payload_size_max > options.ring_bytes_max) return error.InvalidOptions;
        if (options.send_buffer_size < replay_bytes_max(options)) return error.InvalidOptions;
    }

    /// The most a new subscriber can have queued: the upgrade response, every ringed
    /// message, and one live message, each with a frame header.
    pub fn replay_bytes_max(options: Options) u64 {
        const frames: u64 = @as(u64, options.ring_entries_max) + 1;
        return handshake_response_size_max + frames * ws.frame.header_size_max +
            options.ring_bytes_max + options.payload_size_max;
    }
};

/// The 101 response the ws server queues before `on_open` (fixed text plus the key).
const handshake_response_size_max = 256;

/// base/base `PublishingMetrics` (prefix `base_builder_`).
pub const Metrics = struct {
    messages_sent: metrics.Counter = .{},
    replay_messages_sent: metrics.Counter = .{},
    replay_stale_position: metrics.Counter = .{},
    connections_active: metrics.Gauge = .{},
    /// Subscribers disconnected for lagging. base/base's `ws_lagged_count` counts skipped
    /// messages instead; a disconnected subscriber skips nothing here (it resumes).
    lagged_disconnects: metrics.Counter = .{},
    send_errors: metrics.Counter = .{},
    handshake_errors: metrics.Counter = .{},
    payload_size_bytes: metrics.Histogram = .init(&payload_size_buckets),
    connection_duration_s: metrics.Histogram = .init(&connection_duration_buckets_s),

    pub fn register(m: *Metrics, registry: anytype) metrics.RegisterError!void {
        try registry.counter(
            "base_builder_messages_sent_count",
            "Total messages sent to subscribers",
            &m.messages_sent,
        );
        try registry.counter(
            "base_builder_replay_messages_sent_count",
            "Total replay messages sent during reconnection",
            &m.replay_messages_sent,
        );
        try registry.counter(
            "base_builder_replay_stale_position_count",
            "Total stale-position replays (eviction gaps)",
            &m.replay_stale_position,
        );
        try registry.gauge(
            "base_builder_ws_connections_active",
            "Active WebSocket connections",
            &m.connections_active,
        );
        try registry.counter(
            "base_builder_ws_lagged_disconnect_count",
            "Total subscribers disconnected for lagging",
            &m.lagged_disconnects,
        );
        try registry.counter(
            "base_builder_ws_send_error_count",
            "Total WebSocket send errors",
            &m.send_errors,
        );
        try registry.counter(
            "base_builder_ws_handshake_error_count",
            "Total WebSocket handshake errors",
            &m.handshake_errors,
        );
        try registry.histogram(
            "base_builder_ws_payload_byte_size",
            "Payload byte size histogram",
            &m.payload_size_bytes,
        );
        try registry.histogram(
            "base_builder_ws_connection_duration",
            "WebSocket connection duration",
            &m.connection_duration_s,
        );
    }
};

const payload_size_buckets = [_]f64{
    256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304,
};
const connection_duration_buckets_s = [_]f64{
    1, 10, 60, 300, 1800, 3600, 21600, 86400,
};

pub const PublishError = error{PayloadTooLarge};

pub fn Publisher(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Server = ws.Server(IO, *Self);
        const handlers: ws.server.Handlers(Server, *Self) = .{
            .on_open = on_open,
            .on_message = on_message,
            .on_close = on_close,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        server: Server,
        ring: Ring,
        encode_buffer: []u8,
        /// Monotonic open time per connection slot; null while not open.
        opened_at_ns: []?u64,
        metrics: Metrics = .{},

        /// `publisher` must not move after `init`.
        pub fn init(
            publisher: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            options: Options,
        ) !void {
            try options.validate();
            assert(options.payload_size_max <= options.ring_bytes_max);
            var ring = try Ring.init(allocator, options.ring_entries_max, options.ring_bytes_max);
            errdefer ring.deinit(allocator);
            const encode_buffer = try allocator.alloc(u8, options.payload_size_max);
            errdefer allocator.free(encode_buffer);
            const opened_at_ns = try allocator.alloc(?u64, options.connections_max);
            errdefer allocator.free(opened_at_ns);
            @memset(opened_at_ns, null);
            publisher.* = .{
                .io = io,
                .allocator = allocator,
                .server = undefined,
                .ring = ring,
                .encode_buffer = encode_buffer,
                .opened_at_ns = opened_at_ns,
            };
            try publisher.server.init(allocator, io, publisher, &handlers, .{
                .connections_max = options.connections_max,
                .message_size_max = options.inbound_message_size_max,
                .send_buffer_size = options.send_buffer_size,
                .backlog = options.backlog,
            });
        }

        /// Requires `stopped()`.
        pub fn deinit(publisher: *Self) void {
            assert(publisher.stopped());
            publisher.server.deinit();
            publisher.allocator.free(publisher.opened_at_ns);
            publisher.allocator.free(publisher.encode_buffer);
            publisher.ring.deinit(publisher.allocator);
            publisher.* = undefined;
        }

        pub fn listen(publisher: *Self, address: Address) !Address {
            return publisher.server.listen(address);
        }

        /// Disconnects every subscriber; run the IO until `stopped()` before `deinit`.
        pub fn stop(publisher: *Self) void {
            publisher.server.stop();
        }

        pub fn stopped(publisher: *const Self) bool {
            return publisher.server.stopped();
        }

        pub fn subscribers(publisher: *const Self) u32 {
            return publisher.server.connections_open();
        }

        /// Encodes and publishes `flashblock` at `(metadata.block_number, index)`. Returns
        /// the encoded size in bytes (base/base `publish` returns the JSON length).
        pub fn publish(publisher: *Self, flashblock: flashblocks.Flashblock) PublishError!u32 {
            const json = flashblocks.encode_json(flashblock, publisher.encode_buffer) catch
                return error.PayloadTooLarge;
            const position: Position = .{
                .block_number = flashblock.metadata.block_number,
                .flashblock_index = flashblock.index,
            };
            publisher.publish_encoded(position, json);
            return @intCast(json.len);
        }

        /// Publishes an already-encoded JSON message.
        pub fn publish_encoded(publisher: *Self, position: Position, json: []const u8) void {
            assert(json.len <= publisher.encode_buffer.len);
            assert(json.len > 0);
            _ = publisher.ring.push(position, json);
            const open = publisher.server.connections_open();
            const dropped_before = publisher.server.slow_consumers_dropped;
            const delivered = publisher.server.broadcast(.text, json);
            const dropped = publisher.server.slow_consumers_dropped - dropped_before;
            assert(delivered + dropped == open);
            publisher.metrics.messages_sent.add(delivered);
            publisher.metrics.lagged_disconnects.add(dropped);
            publisher.metrics.payload_size_bytes.observe(@floatFromInt(json.len));
        }

        fn on_open(publisher: *Self, server: *Server, id: ws.server.ConnectionId) void {
            assert(id.index < publisher.opened_at_ns.len);
            assert(publisher.opened_at_ns[id.index] == null);
            publisher.opened_at_ns[id.index] = publisher.io.now_monotonic_ns();
            publisher.metrics.connections_active.add(1);
            const target = server.request_target(id) orelse return;
            const cutoff = parse_resume_position(target) orelse return;
            publisher.replay(server, id, cutoff);
        }

        fn replay(
            publisher: *Self,
            server: *Server,
            id: ws.server.ConnectionId,
            cutoff: Position,
        ) void {
            const ring = &publisher.ring;
            if (ring.oldest_position()) |oldest| {
                if (cutoff.less_than(oldest)) publisher.metrics.replay_stale_position.increment();
            }
            var index = ring.first_after(cutoff);
            assert(index <= ring.len());
            while (index < ring.len()) : (index += 1) {
                const entry = ring.get(index);
                // `Options.validate` sizes the send buffer for the whole ring plus the
                // upgrade response, and the stream was opened just now.
                server.send(id, .text, entry.payload) catch unreachable;
                publisher.metrics.replay_messages_sent.increment();
            }
        }

        fn on_message(
            publisher: *Self,
            server: *Server,
            id: ws.server.ConnectionId,
            incoming: ws.server.Message,
        ) void {
            _ = publisher;
            _ = server;
            _ = id;
            _ = incoming; // Subscribers have nothing to say; base/base ignores data frames.
        }

        fn on_close(
            publisher: *Self,
            server: *Server,
            id: ws.server.ConnectionId,
            closed: ws.server.Closed,
        ) void {
            _ = server;
            assert(id.index < publisher.opened_at_ns.len);
            const opened_at_ns = publisher.opened_at_ns[id.index] orelse {
                // Never opened: the handshake failed or the server stopped first.
                if (closed.err) |err| {
                    const handshake = err == error.HandshakeFailed;
                    if (handshake) publisher.metrics.handshake_errors.increment();
                }
                return;
            };
            publisher.opened_at_ns[id.index] = null;
            publisher.metrics.connections_active.add(-1);
            assert(publisher.metrics.connections_active.get() >= 0);
            const now_ns = publisher.io.now_monotonic_ns();
            publisher.metrics.connection_duration_s.observe_ns(now_ns -| opened_at_ns);
            if (closed.err) |err| {
                if (err == error.SendFailed) publisher.metrics.send_errors.increment();
            }
        }
    };
}

/// base/base `parse_resume_position`: both `block_number` and `flashblock_index` query
/// parameters must parse as u64; a later duplicate key overrides an earlier one, and an
/// unparsable value clears it (Rust `value.parse().ok()`).
pub fn parse_resume_position(target: []const u8) ?Position {
    const question = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    // `http::Uri::query` stops at a fragment.
    const query_end = std.mem.indexOfScalarPos(u8, target, question, '#') orelse target.len;
    const query = target[question + 1 .. query_end];
    var block_number: ?u64 = null;
    var flashblock_index: ?u64 = null;
    var pairs = std.mem.splitScalar(u8, query, '&');
    // The split yields at most `query.len + 1` pairs.
    while (pairs.next()) |pair| {
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..equals];
        const value = pair[equals + 1 ..];
        if (std.mem.eql(u8, key, "block_number")) {
            block_number = flashblocks.FlashblockId.parse_decimal(value);
        } else if (std.mem.eql(u8, key, "flashblock_index")) {
            flashblock_index = flashblocks.FlashblockId.parse_decimal(value);
        }
    }
    return .{
        .block_number = block_number orelse return null,
        .flashblock_index = flashblock_index orelse return null,
    };
}

test {
    _ = @import("publisher_test.zig");
}

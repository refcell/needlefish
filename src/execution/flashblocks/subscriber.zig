//! The flashblocks WebSocket subscriber. Mirrors base/base `subscription.rs`
//! (`FlashblocksSubscriber`) on the completion-based IO:
//!
//! - connects to the feed, decodes every text or binary message with
//!   `common/flashblocks.decode_message`, and hands the flashblock to the receiver;
//! - pings every `ping_interval_ns` and reconnects when the previous ping got no pong;
//! - reconnects after every close or failed connect, waiting a capped exponential backoff
//!   (base/base: 1 s doubling to 10 s, reset once a connection opens) via IO timeouts.
//!
//! Unlike base/base, a reconnect resumes the feed: the target carries
//! `?block_number=N&flashblock_index=I` of the last decoded flashblock, which the builder
//! publisher (`builder/publish`) replays after. base/base reconnects to the plain URL and
//! relies on the processor to drop what it missed. Every close waits one backoff delay
//! (base/base reconnects at once after an upstream close), so a flapping feed cannot spin.
//!
//! All memory (the ws client buffers and the decode arena) is allocated at `init`.

const std = @import("std");
const assert = std.debug.assert;

const io_module = @import("../../utilities/io/root.zig");
const ws = @import("../../utilities/ws/root.zig");
const retry = @import("../../utilities/retry/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");

pub const Address = io_module.Address;

/// The last decoded flashblock, sent back as the resume position.
pub const Position = struct { block_number: u64, flashblock_index: u64 };

pub const path_size_max = 256;

pub const Options = struct {
    /// Request path of the feed, without a query (resume parameters are appended).
    path: []const u8 = "/",
    /// `Host` header; the server address when empty.
    host: []const u8 = "",
    /// base/base `subscriber_ping_interval` default.
    ping_interval_ns: u64 = 30 * std.time.ns_per_s,
    backoff: retry.Config = .{
        .max_attempts = null,
        .initial_delay_ns = std.time.ns_per_s,
        .max_delay_ns = 10 * std.time.ns_per_s,
        .jitter = false,
    },
    message_size_max: u32 = 1 << 20,
    send_buffer_size: u32 = 4096,
    /// Decoding one message (brotli output up to 5 MiB plus the parsed fields).
    decode_arena_bytes: u32 = 16 << 20,
    /// Seeds the ws masking keys and handshake nonces.
    seed: u64 = 0,
    resume_feed: bool = true,

    pub fn validate(options: Options) error{InvalidOptions}!void {
        if (options.path.len == 0 or options.path.len > path_size_max) {
            return error.InvalidOptions;
        }
        if (std.mem.indexOfAny(u8, options.path, "?#") != null) return error.InvalidOptions;
        if (options.ping_interval_ns == 0) return error.InvalidOptions;
        if (options.message_size_max == 0 or options.decode_arena_bytes == 0) {
            return error.InvalidOptions;
        }
        if (options.backoff.max_attempts != null) return error.InvalidOptions;
    }
};

/// base/base flashblocks `Metrics` for the subscription.
pub const Stats = struct {
    connections: u64 = 0,
    reconnect_attempts: u64 = 0,
    upstream_messages: u64 = 0,
    upstream_errors: u64 = 0,
    decode_errors: u64 = 0,
    pong_timeouts: u64 = 0,
    last_backoff_ns: u64 = 0,
};

const Phase = enum { idle, connecting, open, waiting };
const TimerKind = enum { ping, backoff };

/// `Receiver` is a pointer type with `fn on_flashblock(Receiver, flashblocks.Flashblock)
/// void`; the flashblock's slices are valid only during the call.
pub fn Subscriber(comptime IO: type, comptime Receiver: type) type {
    return struct {
        const Self = @This();
        pub const Client = ws.Client(IO, *Self);
        const handlers: ws.client.Handlers(Client, *Self) = .{
            .on_open = on_open,
            .on_message = on_message,
            .on_close = on_close,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        options: Options,
        receiver: Receiver,
        client: Client,
        backoff: retry.Backoff,
        phase: Phase = .idle,
        stopping: bool = false,
        timer: IO.Completion = .{},
        timer_armed: bool = false,
        timer_kind: TimerKind = .backoff,
        awaiting_pong: bool = false,
        pongs_at_ping: u64 = 0,
        last: ?Position = null,
        target_buffer: [path_size_max + 64]u8 = undefined,
        decode_buffer: []u8,
        stats: Stats = .{},

        /// `subscriber` must not move after `init`.
        pub fn init(
            subscriber: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            address: Address,
            options: Options,
            receiver: Receiver,
        ) !void {
            try options.validate();
            const decode_buffer = try allocator.alloc(u8, options.decode_arena_bytes);
            errdefer allocator.free(decode_buffer);
            subscriber.* = .{
                .io = io,
                .allocator = allocator,
                .options = options,
                .receiver = receiver,
                .client = undefined,
                .backoff = .init(options.backoff, options.seed),
                .decode_buffer = decode_buffer,
            };
            subscriber.client = try Client.init(allocator, io, address, .{
                .message_size_max = options.message_size_max,
                .send_buffer_size = options.send_buffer_size,
                .host = options.host,
                .target = options.path,
                .seed = options.seed,
            }, subscriber, &handlers);
            assert(subscriber.phase == .idle);
        }

        /// Requires `idle()`.
        pub fn deinit(subscriber: *Self) void {
            assert(subscriber.idle());
            subscriber.client.deinit();
            subscriber.allocator.free(subscriber.decode_buffer);
            subscriber.* = undefined;
        }

        /// Starts the subscription (base/base `start`).
        pub fn start(subscriber: *Self) void {
            assert(subscriber.phase == .idle);
            assert(!subscriber.stopping);
            subscriber.connect();
        }

        /// Closes the connection and the timer; run the IO until `idle()`.
        pub fn stop(subscriber: *Self) void {
            subscriber.stopping = true;
            subscriber.client.abort();
            if (subscriber.timer_armed) subscriber.io.cancel(&subscriber.timer);
        }

        pub fn idle(subscriber: *const Self) bool {
            return subscriber.client.idle() and !subscriber.timer_armed;
        }

        pub fn connected(subscriber: *const Self) bool {
            return subscriber.phase == .open;
        }

        fn connect(subscriber: *Self) void {
            assert(!subscriber.timer_armed);
            assert(subscriber.client.idle());
            subscriber.phase = .connecting;
            subscriber.client.options.target = subscriber.target();
            subscriber.client.connect();
        }

        /// The request target: the path, plus the resume position once one is known.
        fn target(subscriber: *Self) []const u8 {
            const path = subscriber.options.path;
            const last = subscriber.last orelse return path;
            if (!subscriber.options.resume_feed) return path;
            const text = std.fmt.bufPrint(
                &subscriber.target_buffer,
                "{s}?block_number={d}&flashblock_index={d}",
                .{ path, last.block_number, last.flashblock_index },
            ) catch unreachable; // The path is at most `path_size_max`; two u64s fit in 64.
            assert(text.len > path.len);
            return text;
        }

        fn on_open(subscriber: *Self, client: *Client) void {
            assert(client == &subscriber.client);
            assert(subscriber.phase == .connecting);
            assert(!subscriber.timer_armed);
            subscriber.phase = .open;
            subscriber.stats.connections += 1;
            subscriber.backoff.reset();
            subscriber.awaiting_pong = false;
            if (subscriber.stopping) return client.abort();
            subscriber.arm(.ping, subscriber.options.ping_interval_ns);
        }

        fn on_message(subscriber: *Self, client: *Client, message: ws.client.Message) void {
            assert(client == &subscriber.client);
            assert(subscriber.phase == .open);
            subscriber.stats.upstream_messages += 1;
            if (message.opcode != .text and message.opcode != .binary) return;
            var fixed: std.heap.FixedBufferAllocator = .init(subscriber.decode_buffer);
            const arena = fixed.allocator();
            const flashblock = flashblocks.decode_message(arena, message.payload) catch {
                subscriber.stats.decode_errors += 1;
                return;
            };
            subscriber.last = .{
                .block_number = flashblock.metadata.block_number,
                .flashblock_index = flashblock.index,
            };
            subscriber.receiver.on_flashblock(flashblock);
        }

        fn on_close(subscriber: *Self, client: *Client, closed: ws.client.Closed) void {
            assert(client == &subscriber.client);
            assert(subscriber.phase == .connecting or subscriber.phase == .open);
            if (closed.err != null) subscriber.stats.upstream_errors += 1;
            subscriber.phase = .waiting;
            if (subscriber.stopping) {
                subscriber.phase = .idle;
                return;
            }
            if (subscriber.timer_armed) {
                // The keepalive timer: once canceled, `on_timer` schedules the reconnect.
                assert(subscriber.timer_kind == .ping);
                subscriber.io.cancel(&subscriber.timer);
                return;
            }
            subscriber.schedule_reconnect();
        }

        fn schedule_reconnect(subscriber: *Self) void {
            assert(subscriber.phase == .waiting);
            // Unbounded schedule (`Options.validate`): there is always a next delay.
            const delay_ns = subscriber.backoff.next_delay_ns().?;
            subscriber.stats.reconnect_attempts += 1;
            subscriber.stats.last_backoff_ns = delay_ns;
            subscriber.arm(.backoff, delay_ns);
        }

        fn arm(subscriber: *Self, kind: TimerKind, delay_ns: u64) void {
            assert(!subscriber.timer_armed);
            assert(delay_ns > 0);
            subscriber.timer_armed = true;
            subscriber.timer_kind = kind;
            subscriber.io.timeout(*Self, subscriber, on_timer, &subscriber.timer, delay_ns);
        }

        fn on_timer(
            subscriber: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &subscriber.timer);
            assert(subscriber.timer_armed);
            subscriber.timer_armed = false;
            result catch {}; // Canceled: the phase below says what to do next.
            if (subscriber.stopping) {
                if (subscriber.phase == .waiting) subscriber.phase = .idle;
                return;
            }
            switch (subscriber.timer_kind) {
                .backoff => {
                    assert(subscriber.phase == .waiting);
                    subscriber.connect();
                },
                .ping => subscriber.keepalive(),
            }
        }

        /// base/base's ping tick: reconnect when the last ping went unanswered.
        fn keepalive(subscriber: *Self) void {
            switch (subscriber.phase) {
                .open => {},
                // Closed while the ping timer ran: reconnect now that the timer is free.
                .waiting => return subscriber.schedule_reconnect(),
                .idle, .connecting => unreachable, // The ping timer runs only once open.
            }
            const client = &subscriber.client;
            if (subscriber.awaiting_pong and client.pongs_received() == subscriber.pongs_at_ping) {
                subscriber.stats.pong_timeouts += 1;
                return client.abort(); // `on_close` schedules the reconnect.
            }
            subscriber.pongs_at_ping = client.pongs_received();
            client.ping() catch return client.abort();
            subscriber.awaiting_pong = true;
            subscriber.arm(.ping, subscriber.options.ping_interval_ns);
        }
    };
}

test {
    _ = @import("subscriber_test.zig");
}

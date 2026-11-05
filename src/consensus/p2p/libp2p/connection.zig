//! One libp2p connection over a byte stream (the TCP transport minus the socket):
//!
//!   multistream-select `/noise` -> Noise XX -> (encrypted) multistream-select
//!   `/yamux/1.0.0` -> yamux session -> per stream multistream-select of
//!   `/meshsub/1.1.0` (or `/meshsub/1.0.0`), `/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0`.
//!
//! The dialer is the noise initiator, the multistream dialer of both upgrades, and the
//! yamux client. As dialer we wait for each echo before sending protocol bytes (strict
//! multistream V1); as listener we accept protocol bytes that follow a proposal
//! (compatible with rust-libp2p's V1Lazy).
//!
//! IO-free: `receive` consumes inbound bytes in any fragmentation, `flush` writes outbound
//! bytes into the caller's buffer, `tick` drives timers, and `pop_event` reports what
//! happened. Every buffer is carved from one allocation at `init`; nothing allocates
//! afterwards. Gossip frames are opaque to the connection: outbound frames come framed from
//! `gossip.Router.drain`, inbound bytes are re-split with `rpc.frame_decode` and each RPC is
//! reported as one `gossip_frame` event for `Router.on_rpc`.
//!
//! On connect each side opens an identify stream (the accepting side writes one framed
//! Identify and closes) and a ping stream (the opening side pings every 15 s; a ping
//! unanswered for 20 s closes the connection). A connection not established within
//! `handshake_timeout_ns` (10 s, libp2p's default upgrade timeout) is closed. Any protocol
//! violation by the peer closes the connection with a `closed` event naming the reason.

const std = @import("std");
const assert = std.debug.assert;
const multistream = @import("multistream.zig");
const noise = @import("noise.zig");
const yamux = @import("yamux.zig");
const identify = @import("identify.zig");
const ping = @import("ping.zig");
const identity = @import("identity.zig");
const peer_id = @import("../peers/peer_id.zig");
const multiaddr = @import("../peers/multiaddr.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const varint = @import("../peers/varint.zig");
const rpc = @import("../gossip/rpc.zig");

pub const PeerId = peer_id.PeerId;

pub const meshsub_v1_1 = "/meshsub/1.1.0";
pub const meshsub_v1_0 = "/meshsub/1.0.0";
/// Time from `init` until the yamux muxer must be negotiated.
pub const handshake_timeout_ns: u64 = 10 * std.time.ns_per_s;
/// yamux streams per connection (identify, ping, and meshsub need about six).
pub const stream_count_max = 16;
/// Inbound streams beyond this are reset so the peer cannot starve our outbound streams.
pub const inbound_stream_count_max = 12;
/// An inbound stream that has not selected a protocol this long after we accepted it is
/// reset, so stalled negotiations cannot pin the inbound slots (rust-libp2p's 10 s
/// substream upgrade timeout).
pub const stream_negotiation_timeout_ns: u64 = 10 * std.time.ns_per_s;
pub const event_count_max = 64;
/// Slots kept free of gossip frames for established, identified, ping, and closed.
const event_reserve = 4;
/// Per-stream outbound buffer for negotiation, identify, and ping bytes.
pub const stream_buffer_bytes = 8 * 1024;
/// Outbound buffers for the connection-level negotiations and noise handshake.
const upgrade_buffer_bytes = 8 * 1024;
/// Smallest buffer `flush` accepts.
pub const flush_length_min = 64;
const identify_framed_max = identify.message_size_max + varint.length_max;

pub const Session = yamux.Session(stream_count_max);

const security_protocols = [_][]const u8{noise.protocol_id};
const muxer_protocols = [_][]const u8{yamux.protocol_id};
const gossip_protocols = [_][]const u8{ meshsub_v1_1, meshsub_v1_0 };
const identify_protocols = [_][]const u8{identify.protocol_id};
const ping_protocols = [_][]const u8{ping.protocol_id};
const supported_protocols = [_][]const u8{
    meshsub_v1_1, meshsub_v1_0, identify.protocol_id, ping.protocol_id,
};

comptime {
    assert(inbound_stream_count_max < stream_count_max);
    assert(event_reserve < event_count_max);
    assert(stream_buffer_bytes >= 2 * multistream.frame_length_max + identify_framed_max);
    assert(upgrade_buffer_bytes >= 2 * multistream.frame_length_max +
        noise.handshake_output_length_max);
    assert(flush_length_min > noise.prefix_length + noise.tag_length + yamux.header_length);
}

pub const Role = enum { dialer, listener };

pub const Config = struct {
    /// libp2p identity (secp256k1) secret key.
    identity_secret: identity.SecretKey,
    /// Noise X25519 static key seed (fresh per connection is fine).
    static_seed: [32]u8,
    /// Noise X25519 ephemeral key seed; must be fresh randomness per connection.
    ephemeral_seed: [32]u8,
    /// Seeds ping payloads.
    random_seed: u64,
    /// Start of the handshake timeout.
    now_ns: u64,
    agent_version: []const u8 = "needlefish",
    /// base/base advertises an empty protocol version.
    protocol_version: []const u8 = "",
    listen_addresses: []const multiaddr.Multiaddr = &.{},
    /// The remote address as we see it, if known.
    observed_address: ?multiaddr.Multiaddr = null,
    /// Largest gossip RPC accepted or sent (base/base `MAX_GOSSIP_SIZE`, 10 MiB).
    gossip_frame_size_max: u32 = rpc.frame_size_max_default,
    /// Outbound gossip queue; null means one maximum frame.
    gossip_send_queue_bytes: ?u32 = null,
};

pub const CloseReason = enum {
    handshake_timeout,
    ping_timeout,
    ping_failed,
    /// multistream-select failed for the security or muxer upgrade.
    negotiation_failed,
    handshake_failed,
    decrypt_failed,
    cipher_exhausted,
    muxer_error,
    identify_invalid,
    /// The identify public key does not match the noise-authenticated peer.
    peer_mismatch,
    gossip_frame_invalid,
    /// The peer sent more negotiation messages than our outbound buffers hold.
    buffer_overflow,
    /// The remote sent a yamux go-away: it is shutting down (or failed).
    remote_go_away,
    local,
};

pub const IdentifySummary = struct {
    agent_version: []const u8,
    protocol_version: []const u8,
    listen_address_count: u32,
    protocol_count: u32,
    supports_meshsub: bool,
};

pub const Event = union(enum) {
    /// The yamux session is up; carries the authenticated remote peer.
    established: PeerId,
    identified: IdentifySummary,
    /// One RPC without its length prefix (input for `Router.on_rpc`). Valid until the
    /// next `receive` or `tick` after every gossip event was popped.
    gossip_frame: []const u8,
    ping_rtt_ns: u64,
    closed: CloseReason,
};

pub const Error = error{Closed};

pub const SendError = error{
    Closed,
    NotEstablished,
    /// Not exactly one well-formed frame within `gossip_frame_size_max`.
    InvalidFrame,
    /// The peer rejected every meshsub version.
    ProtocolUnsupported,
    QueueFull,
    /// No yamux stream could be opened (stream limit or go-away).
    StreamUnavailable,
};

const Phase = enum { security, handshake, muxer, established, closed };

const Negotiator = union(enum) {
    none,
    dialer: multistream.Dialer,
    listener: multistream.Listener,

    fn receive(negotiator: *Negotiator, input: []const u8, output: []u8) !multistream.Step {
        return switch (negotiator.*) {
            .dialer => |*dialer| dialer.receive(input, output),
            .listener => |*listener| listener.receive(input, output),
            .none => unreachable, // Callers only negotiate while a negotiator is set.
        };
    }

    fn selected(negotiator: *const Negotiator) []const u8 {
        return switch (negotiator.*) {
            .dialer => |*dialer| dialer.selected(),
            .listener => |*listener| listener.selected(),
            .none => unreachable, // Only called right after `selected`.
        };
    }
};

const Kind = enum {
    free,
    /// Accepted, still negotiating.
    inbound,
    gossip_in,
    gossip_out,
    identify_in,
    identify_out,
    ping_in,
    ping_out,
};

/// Application state of one yamux stream.
const Channel = struct {
    id: u32 = 0,
    kind: Kind = .free,
    negotiated: bool = false,
    negotiator: Negotiator = .none,
    /// Pending outbound bytes at `[tx_head, tx_head + tx_length)` of the stream buffer.
    tx_head: u32 = 0,
    tx_length: u32 = 0,
    close_after_tx: bool = false,
    echo: [ping.payload_length]u8 = undefined,
    echo_fill: u8 = 0,
    /// When we accepted the (inbound) stream, for `stream_negotiation_timeout_ns`.
    accepted_ns: u64 = 0,
};

/// A byte queue over a fixed region: linear with compaction for small buffers.
const Linear = struct {
    fn append(buffer: []u8, length: *u32, bytes: []const u8) bool {
        assert(length.* <= buffer.len);
        if (buffer.len - length.* < bytes.len) return false;
        @memcpy(buffer[length.*..][0..bytes.len], bytes);
        length.* += @intCast(bytes.len);
        return true;
    }

    fn take(buffer: []u8, length: *u32, output: []u8) usize {
        assert(length.* <= buffer.len);
        const count = @min(output.len, length.*);
        @memcpy(output[0..count], buffer[0..count]);
        std.mem.copyForwards(u8, buffer[0 .. length.* - count], buffer[count..length.*]);
        length.* -= @intCast(count);
        return count;
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    phase: Phase,
    close_reason: ?CloseReason = null,
    started_ns: u64,
    now_ns: u64,
    gossip_frame_size_max: u32,

    security: Negotiator,
    handshake: noise.Handshake,
    transport: noise.Transport = undefined,
    remote: ?PeerId = null,
    local: PeerId,
    muxer: Negotiator = .none,
    session: Session,

    memory: []u8,
    cipher_rx: []u8,
    cipher_rx_fill: u32 = 0,
    plaintext: []u8,
    raw_tx: []u8,
    raw_tx_length: u32 = 0,
    secure_tx: []u8,
    secure_tx_length: u32 = 0,
    stream_tx: []u8,
    identify_rx: []u8,
    identify_rx_fill: u32 = 0,
    gossip_rx: []u8,
    gossip_rx_decoded: u32 = 0,
    gossip_rx_end: u32 = 0,
    gossip_tx: []u8,
    gossip_tx_head: u32 = 0,
    gossip_tx_length: u32 = 0,

    channels: [stream_count_max]Channel = @splat(.{}),
    gossip_in_slot: ?u8 = null,
    gossip_out_slot: ?u8 = null,
    gossip_unsupported: bool = false,
    ping_slot: ?u8 = null,
    ping_unsupported: bool = false,
    pinger: ping.Pinger = .{},
    prng: std.Random.DefaultPrng,
    remote_identify: ?identify.Identify = null,
    identify_local: [identify_framed_max]u8 = undefined,
    identify_local_length: u32 = 0,

    events: [event_count_max]Event = undefined,
    event_head: u32 = 0,
    event_count: u32 = 0,
    gossip_events_pending: u32 = 0,
    /// `close` queued a go-away; the connection closes once it is flushed.
    closing: bool = false,
    /// Inbound streams reset for not negotiating within `stream_negotiation_timeout_ns`.
    stream_negotiation_timeouts: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, role: Role, config: Config) !Connection {
        assert(config.gossip_frame_size_max > 0);
        assert(config.listen_addresses.len <= identify.listen_addresses_max);
        const frame_bytes = config.gossip_frame_size_max + rpc.varint_length_max;
        const queue_bytes = config.gossip_send_queue_bytes orelse frame_bytes;
        assert(queue_bytes >= frame_bytes);
        const sizes = [_]usize{
            Session.memory_length,
            noise.prefix_length + noise.message_length_max,
            noise.message_length_max,
            upgrade_buffer_bytes,
            upgrade_buffer_bytes,
            stream_count_max * stream_buffer_bytes,
            identify_framed_max,
            frame_bytes,
            queue_bytes,
        };
        var total: usize = 0;
        for (sizes) |size| total += size;
        const memory = try allocator.alloc(u8, total);
        errdefer allocator.free(memory);
        var regions: [sizes.len][]u8 = undefined;
        var offset: usize = 0;
        for (sizes, &regions) |size, *region| {
            region.* = memory[offset..][0..size];
            offset += size;
        }
        assert(offset == total);
        var connection: Connection = .{
            .allocator = allocator,
            .role = role,
            .phase = .security,
            .started_ns = config.now_ns,
            .now_ns = config.now_ns,
            .gossip_frame_size_max = config.gossip_frame_size_max,
            .security = .none,
            .handshake = try noise.Handshake.init(
                if (role == .dialer) .initiator else .responder,
                .{
                    .identity_secret = config.identity_secret,
                    .static_seed = config.static_seed,
                    .ephemeral_seed = config.ephemeral_seed,
                },
            ),
            .local = peer_id.from_public_key(try secp256k1.public_key(config.identity_secret)),
            .session = Session.init(if (role == .dialer) .client else .server, regions[0]),
            .memory = memory,
            .cipher_rx = regions[1],
            .plaintext = regions[2],
            .raw_tx = regions[3],
            .secure_tx = regions[4],
            .stream_tx = regions[5],
            .identify_rx = regions[6],
            .gossip_rx = regions[7],
            .gossip_tx = regions[8],
            .prng = std.Random.DefaultPrng.init(config.random_seed),
        };
        try connection.encode_local_identify(config);
        connection.security = start_negotiator(
            role,
            &security_protocols,
            connection.raw_tx,
            &connection.raw_tx_length,
        );
        assert(connection.raw_tx_length > 0);
        return connection;
    }

    pub fn deinit(connection: *Connection) void {
        assert(connection.memory.len > 0);
        connection.allocator.free(connection.memory);
        connection.* = undefined;
    }

    fn encode_local_identify(connection: *Connection, config: Config) !void {
        const public_key = try secp256k1.public_key(config.identity_secret);
        var key_buffer: [identity.public_key_protobuf_length]u8 = undefined;
        var message: identify.Identify = .{
            .public_key = identity.encode_public_key(&key_buffer, public_key),
            .observed_address = config.observed_address,
            .protocol_version = config.protocol_version,
            .agent_version = config.agent_version,
        };
        for (config.listen_addresses, 0..) |address, index| {
            message.listen_addresses[index] = address;
        }
        message.listen_addresses_count = @intCast(config.listen_addresses.len);
        for (supported_protocols, 0..) |protocol, index| message.protocols[index] = protocol;
        message.protocols_count = supported_protocols.len;
        const framed = try identify.encode_framed(&message, &connection.identify_local);
        connection.identify_local_length = @intCast(framed.len);
        assert(connection.identify_local_length > 0);
    }

    /// Starts a multistream negotiation, writing its opening bytes to `buffer`.
    fn start_negotiator(
        role: Role,
        protocols: []const []const u8,
        buffer: []u8,
        length: *u32,
    ) Negotiator {
        var opening: [2 * multistream.frame_length_max]u8 = undefined;
        var negotiator: Negotiator = undefined;
        const bytes = switch (role) {
            .dialer => blk: {
                negotiator = .{ .dialer = multistream.Dialer.init(protocols) };
                break :blk negotiator.dialer.start(&opening);
            },
            .listener => blk: {
                negotiator = .{ .listener = multistream.Listener.init(protocols) };
                break :blk negotiator.listener.start(&opening);
            },
        };
        // Callers start negotiators on empty or nearly empty buffers sized for two frames.
        const appended = Linear.append(buffer, length, bytes);
        assert(appended);
        return negotiator;
    }

    // Accessors.

    pub fn remote_peer(connection: *const Connection) ?PeerId {
        return connection.remote;
    }

    pub fn local_peer(connection: *const Connection) PeerId {
        return connection.local;
    }

    pub fn is_established(connection: *const Connection) bool {
        return connection.phase == .established;
    }

    pub fn closed_reason(connection: *const Connection) ?CloseReason {
        assert((connection.close_reason != null) == (connection.phase == .closed));
        return connection.close_reason;
    }

    /// The remote identify message; slices stay valid for the connection's lifetime.
    pub fn remote_identify_message(connection: *const Connection) ?*const identify.Identify {
        if (connection.remote_identify) |*message| return message;
        return null;
    }

    /// Closes the connection locally; the caller drops the socket.
    /// Closes the connection. When established, a yamux go-away (normal) is queued first
    /// and the connection closes once `flush` has written it; otherwise it closes now.
    pub fn close(connection: *Connection) void {
        if (connection.phase != .established) return connection.fail(.local);
        if (connection.closing) return;
        connection.closing = true;
        connection.session.go_away(.normal);
        assert(connection.phase == .established);
    }

    /// True once `close` queued a go-away that has not been flushed yet.
    pub fn is_closing(connection: *const Connection) bool {
        return connection.closing and connection.phase != .closed;
    }

    fn fail(connection: *Connection, reason: CloseReason) void {
        if (connection.phase == .closed) return;
        connection.phase = .closed;
        connection.close_reason = reason;
        connection.push_event(.{ .closed = reason });
        assert(connection.event_count <= event_count_max);
    }

    // Events.

    pub fn pop_event(connection: *Connection) ?Event {
        if (connection.event_count == 0) return null;
        const event = connection.events[connection.event_head];
        connection.event_head = (connection.event_head + 1) % event_count_max;
        connection.event_count -= 1;
        if (event == .gossip_frame) {
            assert(connection.gossip_events_pending > 0);
            connection.gossip_events_pending -= 1;
        }
        return event;
    }

    fn push_event(connection: *Connection, event: Event) void {
        // Gossip frames stop at `event_count_max - event_reserve`, pings at two below the
        // maximum, and established, identified, and closed happen once each.
        assert(connection.event_count < event_count_max);
        const tail = (connection.event_head + connection.event_count) % event_count_max;
        connection.events[tail] = event;
        connection.event_count += 1;
        if (event == .gossip_frame) connection.gossip_events_pending += 1;
    }

    // Inbound.

    /// Consumes inbound bytes. Returns `error.Closed` if the connection is (now) closed;
    /// the `closed` event carries the reason. `input` may be empty to resume delivery of
    /// gossip frames held back by a full event queue.
    pub fn receive(connection: *Connection, input: []const u8, now_ns: u64) Error!usize {
        if (connection.phase == .closed) return error.Closed;
        connection.now_ns = @max(connection.now_ns, now_ns);
        var consumed: usize = 0;
        // Every step consumes at least one byte unless it closes the connection.
        while (consumed < input.len and connection.phase != .closed) {
            const used = connection.receive_step(input[consumed..]);
            assert(used > 0 or connection.phase == .closed);
            consumed += used;
        }
        assert(consumed <= input.len);
        if (connection.phase == .established) connection.service();
        if (connection.phase == .closed) return error.Closed;
        return consumed;
    }

    fn receive_step(connection: *Connection, input: []const u8) usize {
        assert(input.len > 0);
        return switch (connection.phase) {
            .security => connection.step_security(input),
            .handshake => connection.step_handshake(input),
            .muxer, .established => connection.step_cipher(input),
            .closed => unreachable, // The receive loop stops on close.
        };
    }

    fn step_security(connection: *Connection, input: []const u8) usize {
        assert(connection.phase == .security);
        var reply: [multistream.frame_length_max]u8 = undefined;
        const step = connection.security.receive(input, &reply) catch {
            connection.fail(.negotiation_failed);
            return 0;
        };
        if (!connection.append_raw(step.output)) return 0;
        if (step.outcome == .selected) {
            assert(std.mem.eql(u8, connection.security.selected(), noise.protocol_id));
            var output: [noise.handshake_output_length_max]u8 = undefined;
            const first = connection.handshake.start(&output) catch {
                connection.fail(.handshake_failed);
                return 0;
            };
            if (!connection.append_raw(first)) return 0;
            connection.security = .none;
            connection.phase = .handshake;
        }
        assert(step.consumed > 0);
        return step.consumed;
    }

    fn step_handshake(connection: *Connection, input: []const u8) usize {
        assert(connection.phase == .handshake);
        var output: [noise.handshake_output_length_max]u8 = undefined;
        const step = connection.handshake.receive(input, &output) catch {
            connection.fail(.handshake_failed);
            return 0;
        };
        if (!connection.append_raw(step.output)) return 0;
        if (step.done) {
            connection.transport = connection.handshake.finish();
            connection.remote = connection.transport.remote_peer;
            connection.phase = .muxer;
            connection.muxer = start_negotiator(
                connection.role,
                &muxer_protocols,
                connection.secure_tx,
                &connection.secure_tx_length,
            );
        }
        assert(step.consumed > 0);
        return step.consumed;
    }

    fn append_raw(connection: *Connection, bytes: []const u8) bool {
        if (Linear.append(connection.raw_tx, &connection.raw_tx_length, bytes)) return true;
        connection.fail(.buffer_overflow);
        assert(connection.phase == .closed);
        return false;
    }

    /// Accumulates one noise transport frame, then decrypts and dispatches it.
    fn step_cipher(connection: *Connection, input: []const u8) usize {
        assert(connection.phase == .muxer or connection.phase == .established);
        const fill = connection.cipher_rx_fill;
        var total: u32 = noise.prefix_length;
        if (fill >= noise.prefix_length) {
            const prefix = connection.cipher_rx[0..noise.prefix_length];
            const length = std.mem.readInt(u16, prefix, .big);
            if (length < noise.tag_length) {
                connection.fail(.decrypt_failed);
                return 0;
            }
            total += length;
        }
        assert(fill < total);
        const take: u32 = @intCast(@min(total - fill, input.len));
        @memcpy(connection.cipher_rx[fill..][0..take], input[0..take]);
        connection.cipher_rx_fill += take;
        if (connection.cipher_rx_fill == total and total > noise.prefix_length) {
            connection.cipher_rx_fill = 0;
            connection.open_frame(connection.cipher_rx[0..total]);
        }
        assert(take > 0);
        return take;
    }

    fn open_frame(connection: *Connection, frame: []const u8) void {
        assert(frame.len >= noise.prefix_length + noise.tag_length);
        const opened = connection.transport.decrypt_frame(frame, connection.plaintext) catch {
            connection.fail(.decrypt_failed);
            return;
        };
        // `frame` is complete, so the frame decrypts or fails; it is never incomplete.
        const plaintext = opened.?.plaintext;
        assert(opened.?.consumed == frame.len);
        var offset: usize = 0;
        // Each negotiation step consumes at least one byte.
        while (offset < plaintext.len and connection.phase == .muxer) {
            offset += connection.step_muxer(plaintext[offset..]);
        }
        if (offset == plaintext.len or connection.phase != .established) return;
        connection.session.receive(plaintext[offset..]) catch connection.fail(.muxer_error);
    }

    fn step_muxer(connection: *Connection, input: []const u8) usize {
        assert(connection.phase == .muxer);
        var reply: [multistream.frame_length_max]u8 = undefined;
        const step = connection.muxer.receive(input, &reply) catch {
            connection.fail(.negotiation_failed);
            return input.len;
        };
        if (!Linear.append(connection.secure_tx, &connection.secure_tx_length, step.output)) {
            connection.fail(.buffer_overflow);
            return input.len;
        }
        if (step.outcome == .selected) {
            assert(std.mem.eql(u8, connection.muxer.selected(), yamux.protocol_id));
            connection.muxer = .none;
            connection.establish();
        }
        assert(step.consumed > 0);
        return step.consumed;
    }

    fn establish(connection: *Connection) void {
        assert(connection.phase == .muxer);
        assert(connection.remote != null);
        connection.phase = .established;
        connection.push_event(.{ .established = connection.remote.? });
        // The session is fresh, so both opens find free slots.
        _ = connection.open_channel(.identify_out, &identify_protocols).?;
        connection.ping_slot = connection.open_channel(.ping_out, &ping_protocols).?;
    }

    // Streams.

    fn service(connection: *Connection) void {
        assert(connection.phase == .established);
        // A peer that says go-away is leaving: stop gossiping with it now (rust-libp2p
        // closes the connection too). Gossip is redundant, so dropped frames are fine.
        if (connection.session.remote_go_away != null) return connection.fail(.remote_go_away);
        connection.sweep();
        connection.compact_gossip_rx();
        connection.accept_streams();
        for (0..stream_count_max) |slot| {
            if (connection.phase != .established) return;
            connection.service_channel(@intCast(slot));
        }
        if (connection.phase != .established) return;
        connection.decode_gossip();
        connection.poll_ping();
    }

    /// Releases channels whose yamux stream is gone (reset or fully closed).
    fn sweep(connection: *Connection) void {
        for (&connection.channels, 0..) |*channel, slot| {
            if (channel.kind == .free) continue;
            if (connection.session.status(channel.id) == null) {
                connection.release_channel(@intCast(slot));
            }
        }
    }

    fn release_channel(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(channel.kind != .free);
        switch (channel.kind) {
            // Drop a partial inbound frame but keep frames already handed out.
            .gossip_in => {
                connection.gossip_rx_end = connection.gossip_rx_decoded;
                connection.gossip_in_slot = null;
            },
            // Queued bytes may continue a frame the old stream half sent: drop them.
            .gossip_out => {
                connection.gossip_tx_head = 0;
                connection.gossip_tx_length = 0;
                connection.gossip_out_slot = null;
            },
            .ping_out => {
                connection.ping_slot = null;
                connection.pinger = .{ .next_ns = connection.now_ns + ping.interval_ns };
            },
            else => {},
        }
        channel.* = .{};
        assert(channel.kind == .free);
    }

    fn free_channel(connection: *const Connection) ?u8 {
        for (&connection.channels, 0..) |*channel, slot| {
            if (channel.kind == .free) return @intCast(slot);
        }
        return null;
    }

    fn channel_buffer(connection: *Connection, slot: u8) []u8 {
        assert(slot < stream_count_max);
        const start = @as(usize, slot) * stream_buffer_bytes;
        return connection.stream_tx[start..][0..stream_buffer_bytes];
    }

    /// Opens an outbound stream and starts proposing `protocols` on it.
    fn open_channel(connection: *Connection, kind: Kind, protocols: []const []const u8) ?u8 {
        assert(connection.phase == .established);
        connection.sweep();
        const slot = connection.free_channel() orelse return null;
        const id = connection.session.open() catch return null;
        const channel = &connection.channels[slot];
        channel.* = .{ .id = id, .kind = kind };
        var length: u32 = 0;
        const buffer = connection.channel_buffer(slot);
        channel.negotiator = start_negotiator(.dialer, protocols, buffer, &length);
        channel.tx_length = length;
        assert(channel.tx_head == 0);
        return slot;
    }

    fn accept_streams(connection: *Connection) void {
        // At most one accept per yamux slot.
        for (0..stream_count_max) |_| {
            const id = connection.session.accept() orelse return;
            const slot = connection.free_channel();
            if (slot == null or connection.inbound_count() >= inbound_stream_count_max) {
                connection.session.reset(id) catch connection.fail(.muxer_error);
                if (connection.phase == .closed) return;
                continue;
            }
            const channel = &connection.channels[slot.?];
            channel.* = .{ .id = id, .kind = .inbound, .accepted_ns = connection.now_ns };
            var length: u32 = 0;
            const buffer = connection.channel_buffer(slot.?);
            channel.negotiator = start_negotiator(.listener, &supported_protocols, buffer, &length);
            channel.tx_length = length;
        }
    }

    fn inbound_count(connection: *const Connection) u32 {
        var count: u32 = 0;
        for (&connection.channels) |*channel| {
            const inbound = switch (channel.kind) {
                .inbound, .gossip_in, .identify_in, .ping_in => true,
                else => false,
            };
            count += @intFromBool(inbound);
        }
        assert(count <= stream_count_max);
        return count;
    }

    fn service_channel(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        if (channel.kind == .free) return;
        if (connection.session.status(channel.id) == null) {
            connection.release_channel(slot);
            return;
        }
        if (!channel.negotiated) {
            connection.negotiate_channel(slot);
            if (channel.kind == .free or connection.phase != .established) return;
            if (!channel.negotiated and channel.kind == .inbound and
                connection.now_ns - channel.accepted_ns >= stream_negotiation_timeout_ns)
            {
                connection.stream_negotiation_timeouts += 1;
                return connection.reject_channel(slot);
            }
            if (!channel.negotiated) return connection.reject_if_remote_closed(slot);
        }
        switch (channel.kind) {
            .gossip_in => connection.read_gossip(slot),
            .identify_out => connection.read_identify(slot),
            .ping_out => connection.read_echo(slot),
            .ping_in => connection.echo_ping(slot),
            .gossip_out, .identify_in => connection.discard(slot),
            .free, .inbound => unreachable, // Negotiated channels have a protocol kind.
        }
        if (connection.phase != .established or channel.kind == .free) return;
        connection.close_if_remote_closed(slot);
    }

    /// Feeds stream bytes one at a time so no byte past the negotiation is consumed and
    /// every reply fits the stream buffer; negotiation is a few dozen bytes.
    fn negotiate_channel(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(!channel.negotiated);
        var steps: u32 = 0;
        while (steps < yamux.receive_window_bytes) : (steps += 1) {
            const free = stream_buffer_bytes - channel.tx_head - channel.tx_length;
            if (free < multistream.frame_length_max) return;
            var byte: [1]u8 = undefined;
            const got = connection.stream_read(slot, &byte) orelse return;
            if (got == 0) return;
            var reply: [multistream.frame_length_max]u8 = undefined;
            const step = channel.negotiator.receive(&byte, &reply) catch {
                connection.reject_channel(slot);
                return;
            };
            assert(step.consumed == 1);
            connection.channel_append(slot, step.output);
            if (step.outcome == .selected) {
                connection.on_selected(slot);
                return;
            }
        }
    }

    fn channel_append(connection: *Connection, slot: u8, bytes: []const u8) void {
        const channel = &connection.channels[slot];
        const buffer = connection.channel_buffer(slot);
        if (channel.tx_head > 0) {
            const live = buffer[channel.tx_head..][0..channel.tx_length];
            std.mem.copyForwards(u8, buffer[0..live.len], live);
            channel.tx_head = 0;
        }
        // Callers check room before producing `bytes`.
        const appended = Linear.append(buffer, &channel.tx_length, bytes);
        assert(appended);
    }

    /// The peer refused all our proposals or broke multistream on this stream.
    fn reject_channel(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        switch (channel.kind) {
            .gossip_out => connection.gossip_unsupported = true,
            .ping_out => connection.ping_unsupported = true,
            else => {},
        }
        connection.session.reset(channel.id) catch connection.fail(.muxer_error);
        connection.release_channel(slot);
        assert(connection.channels[slot].kind == .free);
    }

    fn on_selected(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        const protocol = channel.negotiator.selected();
        channel.negotiator = .none;
        channel.negotiated = true;
        if (channel.kind != .inbound) {
            // Identify: the peer writes, we only read.
            if (channel.kind == .identify_out) {
                // The read that completed the negotiation cannot release the stream: we never
                // sent a FIN on it.
                connection.session.close(channel.id) catch unreachable;
            }
            return;
        }
        if (std.mem.eql(u8, protocol, identify.protocol_id)) {
            channel.kind = .identify_in;
            const local = connection.identify_local[0..connection.identify_local_length];
            connection.channel_append(slot, local);
            channel.close_after_tx = true;
        } else if (std.mem.eql(u8, protocol, ping.protocol_id)) {
            channel.kind = .ping_in;
        } else if (connection.gossip_in_slot == null) {
            assert(std.mem.startsWith(u8, protocol, "/meshsub/"));
            channel.kind = .gossip_in;
            connection.gossip_in_slot = slot;
        } else {
            // One inbound meshsub stream per peer; keep the first.
            connection.reject_channel(slot);
        }
    }

    /// Reads from the channel's stream. Null when yamux already released the stream (both
    /// sides closed and drained); the channel is released too.
    fn stream_read(connection: *Connection, slot: u8, output: []u8) ?u32 {
        const channel = &connection.channels[slot];
        assert(channel.kind != .free);
        return connection.session.read(channel.id, output) catch {
            connection.release_channel(slot);
            return null;
        };
    }

    /// A negotiation the peer abandoned by closing its side.
    fn reject_if_remote_closed(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(!channel.negotiated);
        const status = connection.session.status(channel.id) orelse return;
        if (status.remote_closed and status.readable == 0) connection.reject_channel(slot);
    }

    fn close_if_remote_closed(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        const status = connection.session.status(channel.id) orelse return;
        if (!status.remote_closed or status.readable > 0 or status.local_closed) return;
        if (channel.kind == .gossip_out or channel.tx_length > 0) return;
        connection.session.close(channel.id) catch unreachable; // The stream exists.
        channel.close_after_tx = false;
    }

    fn read_gossip(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(channel.kind == .gossip_in);
        const end = connection.gossip_rx_end;
        if (end == connection.gossip_rx.len) return;
        const got = connection.stream_read(slot, connection.gossip_rx[end..]) orelse return;
        connection.gossip_rx_end += got;
        assert(connection.gossip_rx_end <= connection.gossip_rx.len);
    }

    fn compact_gossip_rx(connection: *Connection) void {
        if (connection.gossip_events_pending > 0) return;
        const decoded = connection.gossip_rx_decoded;
        if (decoded == 0) return;
        const end = connection.gossip_rx_end;
        const rx = connection.gossip_rx;
        std.mem.copyForwards(u8, rx[0 .. end - decoded], rx[decoded..end]);
        connection.gossip_rx_end = end - decoded;
        connection.gossip_rx_decoded = 0;
    }

    fn decode_gossip(connection: *Connection) void {
        // Bounded by the event queue capacity.
        for (0..event_count_max) |_| {
            if (connection.event_count >= event_count_max - event_reserve) return;
            const start = connection.gossip_rx_decoded;
            const pending = connection.gossip_rx[start..connection.gossip_rx_end];
            const decoded = rpc.frame_decode(pending, connection.gossip_frame_size_max);
            const frame = (decoded catch return connection.fail(.gossip_frame_invalid)) orelse
                return;
            assert(frame.length <= pending.len);
            connection.push_event(.{ .gossip_frame = frame.payload });
            connection.gossip_rx_decoded += @intCast(frame.length);
        }
    }

    fn read_identify(connection: *Connection, slot: u8) void {
        assert(connection.channels[slot].kind == .identify_out);
        if (connection.remote_identify != null) return connection.discard(slot);
        const fill = connection.identify_rx_fill;
        const got = connection.stream_read(slot, connection.identify_rx[fill..]) orelse return;
        connection.identify_rx_fill += got;
        const buffered = connection.identify_rx[0..connection.identify_rx_fill];
        const prefix = varint.decode(buffered) catch |err| {
            if (err == error.Truncated and buffered.len < varint.length_max) return;
            return connection.fail(.identify_invalid);
        };
        if (prefix.value > identify.message_size_max) return connection.fail(.identify_invalid);
        const end = prefix.length + @as(usize, @intCast(prefix.value));
        if (buffered.len < end) return;
        const message = identify.decode(buffered[prefix.length..end]) catch
            return connection.fail(.identify_invalid);
        message.check_peer(&connection.remote.?) catch return connection.fail(.peer_mismatch);
        connection.remote_identify = message;
        connection.push_event(.{ .identified = .{
            .agent_version = message.agent_version,
            .protocol_version = message.protocol_version,
            .listen_address_count = message.listen_addresses_count,
            .protocol_count = message.protocols_count,
            .supports_meshsub = message.supports(meshsub_v1_1) or message.supports(meshsub_v1_0),
        } });
    }

    fn read_echo(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(channel.kind == .ping_out);
        const fill = channel.echo_fill;
        const got = connection.stream_read(slot, channel.echo[fill..]) orelse return;
        channel.echo_fill += @intCast(got);
        if (channel.echo_fill < ping.payload_length) return;
        channel.echo_fill = 0;
        const rtt_ns = connection.pinger.on_echo(&channel.echo, connection.now_ns) catch
            return connection.fail(.ping_failed);
        if (connection.event_count < event_count_max - 2) {
            connection.push_event(.{ .ping_rtt_ns = rtt_ns });
        }
    }

    fn echo_ping(connection: *Connection, slot: u8) void {
        const channel = &connection.channels[slot];
        assert(channel.kind == .ping_in);
        connection.channel_append(slot, &.{});
        const buffer = connection.channel_buffer(slot);
        const got = connection.stream_read(slot, buffer[channel.tx_length..]) orelse return;
        channel.tx_length += got;
        assert(channel.tx_length <= stream_buffer_bytes);
    }

    /// Drops bytes on streams where the peer has nothing to say.
    fn discard(connection: *Connection, slot: u8) void {
        assert(connection.channels[slot].kind != .free);
        // A stream buffers at most one receive window; the scratch holds a quarter of it.
        for (0..yamux.receive_window_bytes / noise.plaintext_length_max + 2) |_| {
            const got = connection.stream_read(slot, connection.plaintext) orelse return;
            if (got == 0) return;
        }
    }

    fn poll_ping(connection: *Connection) void {
        if (connection.ping_unsupported) return;
        if (connection.ping_slot == null) {
            const pinger = &connection.pinger;
            if (pinger.outstanding or connection.now_ns < pinger.next_ns) return;
            connection.ping_slot = connection.open_channel(.ping_out, &ping_protocols);
            return;
        }
        const slot = connection.ping_slot.?;
        const channel = &connection.channels[slot];
        assert(channel.kind == .ping_out);
        if (!channel.negotiated) return;
        const free = stream_buffer_bytes - channel.tx_head - channel.tx_length;
        if (free < ping.payload_length) return;
        const random = connection.prng.random();
        const payload = connection.pinger.poll(random, connection.now_ns) orelse return;
        connection.channel_append(slot, payload);
    }

    // Timers.

    /// Drives the handshake timeout, ping interval, and ping timeout.
    pub fn tick(connection: *Connection, now_ns: u64) void {
        if (connection.phase == .closed) return;
        connection.now_ns = @max(connection.now_ns, now_ns);
        if (connection.phase != .established) {
            if (connection.now_ns - connection.started_ns >= handshake_timeout_ns) {
                connection.fail(.handshake_timeout);
            }
            return;
        }
        if (connection.pinger.timed_out(connection.now_ns)) {
            connection.fail(.ping_timeout);
            return;
        }
        connection.service();
    }

    // Outbound.

    /// Queues one framed gossip RPC (uvarint length + RPC) on the outbound meshsub stream.
    pub fn send_gossip(connection: *Connection, frame: []const u8) SendError!void {
        if (connection.phase == .closed or connection.closing) return error.Closed;
        if (connection.phase != .established) return error.NotEstablished;
        const decoded = rpc.frame_decode(frame, connection.gossip_frame_size_max) catch
            return error.InvalidFrame;
        if (decoded == null or decoded.?.length != frame.len) return error.InvalidFrame;
        if (connection.gossip_unsupported) return error.ProtocolUnsupported;
        const capacity = connection.gossip_tx.len;
        if (capacity - connection.gossip_tx_length < frame.len) return error.QueueFull;
        if (connection.gossip_out_slot == null) {
            const slot = connection.open_channel(.gossip_out, &gossip_protocols) orelse
                return error.StreamUnavailable;
            connection.gossip_out_slot = slot;
        }
        const tail = (connection.gossip_tx_head + connection.gossip_tx_length) % capacity;
        const first = @min(frame.len, capacity - tail);
        @memcpy(connection.gossip_tx[tail..][0..first], frame[0..first]);
        @memcpy(connection.gossip_tx[0 .. frame.len - first], frame[first..]);
        connection.gossip_tx_length += @intCast(frame.len);
        assert(connection.gossip_tx_length <= capacity);
    }

    /// Free bytes in the outbound gossip queue: `send_gossip` accepts any frame this large.
    pub fn gossip_send_room(connection: *const Connection) u32 {
        assert(connection.gossip_tx_length <= connection.gossip_tx.len);
        return @intCast(connection.gossip_tx.len - connection.gossip_tx_length);
    }

    /// Writes outbound bytes into `output` and returns them. Call until it returns empty.
    pub fn flush(connection: *Connection, output: []u8) []const u8 {
        assert(output.len >= flush_length_min);
        if (connection.phase == .closed) return output[0..0];
        var length = Linear.take(connection.raw_tx, &connection.raw_tx_length, output);
        if (connection.raw_tx_length > 0) return output[0..length];
        if (connection.phase == .security or connection.phase == .handshake) {
            return output[0..length];
        }
        const overhead = noise.prefix_length + noise.tag_length;
        // Every frame carries at least one plaintext byte.
        for (0..output.len / (overhead + 1) + 1) |_| {
            if (output.len - length <= overhead + yamux.header_length) break;
            const room = @min(noise.plaintext_length_max, output.len - length - overhead);
            const plain = connection.fill_plaintext(connection.plaintext[0..room]);
            if (plain == 0 or connection.phase == .closed) break;
            const sealed = connection.transport.encrypt_frame(
                connection.plaintext[0..plain],
                output[length..],
            ) catch {
                connection.fail(.cipher_exhausted);
                break;
            };
            length += sealed.len;
        }
        if (connection.phase == .established) connection.sweep();
        // The go-away is in `output`; nothing more will be sent.
        if (connection.closing and connection.phase == .established and
            connection.session.go_away_sent and connection.secure_tx_length == 0)
        {
            connection.fail(.local);
        }
        assert(length <= output.len);
        return output[0..length];
    }

    fn fill_plaintext(connection: *Connection, buffer: []u8) usize {
        assert(buffer.len > yamux.header_length);
        var fill = Linear.take(connection.secure_tx, &connection.secure_tx_length, buffer);
        if (connection.secure_tx_length > 0 or connection.phase != .established) return fill;
        fill += connection.session.flush(buffer[fill..]).len;
        for (0..stream_count_max) |slot| {
            if (connection.phase != .established) return fill;
            fill += connection.write_channel(@intCast(slot), buffer[fill..]);
        }
        assert(fill <= buffer.len);
        return fill;
    }

    fn write_channel(connection: *Connection, slot: u8, buffer: []u8) usize {
        const channel = &connection.channels[slot];
        if (channel.kind == .free) return 0;
        var fill: usize = 0;
        if (channel.tx_length > 0 and buffer.len > yamux.header_length) {
            const buffer_tx = connection.channel_buffer(slot);
            const data = buffer_tx[channel.tx_head..][0..channel.tx_length];
            const written = connection.session.write(channel.id, data, buffer) catch |err| {
                connection.on_write_error(slot, err);
                return 0;
            };
            channel.tx_head += written.data_length;
            channel.tx_length -= written.data_length;
            if (channel.tx_length == 0) channel.tx_head = 0;
            fill += written.frame.len;
        }
        const gossip_ready = channel.kind == .gossip_out and channel.negotiated and
            channel.tx_length == 0;
        if (gossip_ready) fill += connection.write_gossip(slot, buffer[fill..]);
        if (channel.kind == .free) return fill;
        if (channel.close_after_tx and channel.tx_length == 0) {
            // A released stream fails with UnknownStream; the sweep frees the channel.
            connection.session.close(channel.id) catch {};
            channel.close_after_tx = false;
        }
        assert(fill <= buffer.len);
        return fill;
    }

    fn write_gossip(connection: *Connection, slot: u8, buffer: []u8) usize {
        const channel = &connection.channels[slot];
        assert(channel.kind == .gossip_out);
        if (connection.gossip_tx_length == 0 or buffer.len <= yamux.header_length) return 0;
        const capacity = connection.gossip_tx.len;
        const head = connection.gossip_tx_head;
        const contiguous = @min(connection.gossip_tx_length, capacity - head);
        const data = connection.gossip_tx[head..][0..contiguous];
        const written = connection.session.write(channel.id, data, buffer) catch |err| {
            connection.on_write_error(slot, err);
            return 0;
        };
        connection.gossip_tx_head = @intCast((head + written.data_length) % capacity);
        connection.gossip_tx_length -= written.data_length;
        return written.frame.len;
    }

    fn on_write_error(connection: *Connection, slot: u8, err: yamux.Error) void {
        assert(connection.channels[slot].kind != .free);
        switch (err) {
            error.SessionFailed => connection.fail(.muxer_error),
            // The peer reset or closed the stream: drop what it will never read.
            else => connection.release_channel(slot),
        }
    }
};

const harness = @import("connection_test.zig");

test {
    _ = harness;
}

fn busy_channels(connection: *const Connection) u32 {
    var count: u32 = 0;
    for (&connection.channels) |*channel| count += @intFromBool(channel.kind != .free);
    return count;
}

test "connection: unknown stream protocol gets na and the stream is dropped" {
    var prng = harness.Prng.init(0x756e_6b6e);
    var pair = try harness.Pair.init(&prng);
    defer pair.deinit();
    var mutation: harness.Mutation = .{ .prng = &prng, .chunk_max = 4096 };
    try pair.pump(&mutation);
    try std.testing.expect(pair.dialer.is_established());
    const dialer_busy = busy_channels(&pair.dialer);
    const listener_busy = busy_channels(&pair.listener);
    const slot = pair.dialer.open_channel(.identify_out, &.{"/unknown/1.0.0"}).?;
    try std.testing.expectEqual(dialer_busy + 1, busy_channels(&pair.dialer));
    try pair.pump(&mutation);
    try std.testing.expectEqual(Kind.free, pair.dialer.channels[slot].kind);
    try std.testing.expectEqual(dialer_busy, busy_channels(&pair.dialer));
    try std.testing.expectEqual(listener_busy, busy_channels(&pair.listener));
    try std.testing.expect(pair.dialer.closed_reason() == null);
    try std.testing.expect(pair.listener.closed_reason() == null);
}

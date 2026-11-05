//! TCP transport for `p2p.Service` over `utilities/io` (io_uring, kqueue, or SimIo).
//!
//! `Transport(IO)` owns a listener and a fixed table of links. Each link is one TCP socket
//! running the IO-free libp2p `Connection` pipeline (multistream -> noise -> yamux ->
//! meshsub/identify/ping). The transport executes the service's dial/disconnect commands,
//! reports connection lifecycle to the service, moves gossip frames both ways, and ticks
//! the service on a timer. One recv and one send are in flight per link at most.
//!
//! Closing: an open link calls `shutdown_now`, which completes its pending recv with end of
//! stream, and stays quarantined with its descriptor allocated until its in-flight
//! completions return; only then `close_now` frees the descriptor, so a reused descriptor
//! never meets a stale recv. A link still connecting closes at once (a late connect
//! result is ignored).
//!
//! Discovery: with `Config.discovery_listen` set, the transport binds a UDP socket and,
//! on every timer tick, drains received datagrams into `Service.on_datagram` (at most
//! `datagrams_per_tick_max`) and sends everything `Service.pop_datagram` queued.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const service_module = @import("service.zig");
const connection_module = @import("libp2p/connection.zig");
const multiaddr = @import("peers/multiaddr.zig");
const ip = @import("peers/ip.zig");
const peer_id = @import("peers/peer_id.zig");
const rpc = @import("gossip/rpc.zig");
const router_module = @import("gossip/router.zig");

const Service = service_module.Service;
const Connection = connection_module.Connection;

pub const Config = struct {
    listen: io_module.Address,
    identity_secret: [32]u8,
    /// Seeds per-connection noise keys and ping payloads. Production passes OS entropy.
    seed: u64,
    links_max: u32 = 32,
    tick_interval_ns: u64 = 50 * std.time.ns_per_ms,
    /// Largest gossip RPC (base/base `MAX_GOSSIP_SIZE`); bounds per-connection memory.
    gossip_frame_size_max: u32 = rpc.frame_size_max_default,
    backlog: u31 = 64,
    /// UDP address for discv5; null leaves datagrams to the caller.
    discovery_listen: ?io_module.Address = null,
};

/// Datagrams moved each way per timer tick (bounds the work of one tick).
const datagrams_per_tick_max = 256;

const socket_buffer_bytes = 16 * 1024;

pub fn Transport(comptime IO: type) type {
    return struct {
        const Self = @This();

        const State = enum { free, connecting, open, closing };

        const Link = struct {
            transport: *Self = undefined,
            state: State = .free,
            fd: IO.Fd = undefined,
            /// The descriptor is shut down and awaits `close_now` once the link is idle.
            fd_shut: bool = false,
            outbound: bool = false,
            dial_address: multiaddr.Multiaddr = .{},
            connection: Connection = undefined,
            connection_live: bool = false,
            slot: ?service_module.Slot = null,
            peer: peer_id.PeerId = undefined,
            recv_completion: IO.Completion = .{},
            send_completion: IO.Completion = .{},
            recv_inflight: bool = false,
            send_inflight: bool = false,
            recv_buffer: [socket_buffer_bytes]u8 = undefined,
            send_buffer: [socket_buffer_bytes]u8 = undefined,
            send_offset: usize = 0,
            send_length: usize = 0,
            /// The connection closed with bytes (e.g. its go-away) still being sent.
            close_after_send: bool = false,
            close_deadline_ns: u64 = 0,
        };

        /// How long a graceful close may wait for its last bytes before a hard close.
        const close_linger_ns = 2 * std.time.ns_per_s;

        allocator: std.mem.Allocator,
        io: *IO,
        service: *Service,
        config: Config,
        prng: std.Random.DefaultPrng,
        listener: IO.Fd = undefined,
        listen_address: io_module.Address = undefined,
        udp: ?IO.Fd = null,
        udp_address: io_module.Address = undefined,
        accept_completion: IO.Completion = .{},
        timer_completion: IO.Completion = .{},
        links: []Link,
        drain_buffer: []u8,
        stopped: bool = false,
        stats: Stats = .{},

        pub const Stats = struct {
            accepted: u64 = 0,
            dialed: u64 = 0,
            dial_failures: u64 = 0,
            closed: u64 = 0,
            bytes_received: u64 = 0,
            bytes_sent: u64 = 0,
            /// Connections we closed with a go-away, and ones the remote closed that way.
            local_go_aways: u64 = 0,
            remote_go_aways: u64 = 0,
            datagrams_received: u64 = 0,
            datagrams_sent: u64 = 0,
            datagrams_dropped: u64 = 0,
        };

        /// Allocates every link and buffer up front. `transport` must not move afterwards.
        pub fn init(
            transport: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            service: *Service,
            config: Config,
        ) !void {
            assert(config.links_max > 0 and config.tick_interval_ns > 0);
            assert(config.gossip_frame_size_max >= router_module.Router.drain_buffer_min);
            const links = try allocator.alloc(Link, config.links_max);
            errdefer allocator.free(links);
            for (links) |*link| link.* = .{};
            const drain_buffer = try allocator.alloc(u8, config.gossip_frame_size_max);
            transport.* = .{
                .allocator = allocator,
                .io = io,
                .service = service,
                .config = config,
                .prng = std.Random.DefaultPrng.init(config.seed),
                .links = links,
                .drain_buffer = drain_buffer,
            };
            for (links) |*link| link.transport = transport;
        }

        /// Frees memory. Call after `stop` and after the IO loop drained the completions.
        pub fn deinit(transport: *Self) void {
            for (transport.links) |*link| {
                if (link.connection_live) link.connection.deinit();
                if (link.fd_shut) transport.io.close_now(link.fd);
            }
            transport.allocator.free(transport.drain_buffer);
            transport.allocator.free(transport.links);
        }

        /// Opens the listener and starts the accept loop and the service timer.
        pub fn start(transport: *Self) !void {
            const family: io_module.Address.Family = transport.config.listen.family;
            transport.listener = try transport.io.open_socket_tcp(family);
            errdefer transport.io.close_now(transport.listener);
            transport.listen_address = try transport.io.listen(
                transport.listener,
                transport.config.listen,
                transport.config.backlog,
            );
            if (transport.config.discovery_listen) |address| {
                const udp = try transport.io.open_socket_udp(address.family);
                errdefer transport.io.close_now(udp);
                transport.udp_address = try transport.io.bind_udp(udp, address);
                transport.udp = udp;
            }
            transport.submit_accept();
            transport.submit_timer();
        }

        /// Closes every link and the listener; no new operations are submitted.
        pub fn stop(transport: *Self) void {
            if (transport.stopped) return;
            transport.stopped = true;
            for (transport.links) |*link| {
                if (link.state == .open or link.state == .connecting) transport.teardown(link);
            }
            transport.io.close_now(transport.listener);
            if (transport.udp) |udp| transport.io.close_now(udp);
            transport.udp = null;
        }

        fn now_ns(transport: *const Self) u64 {
            return transport.io.now_realtime_ns();
        }

        // ------------------------------------------------------------------ timer

        fn submit_timer(transport: *Self) void {
            transport.io.timeout(
                *Self,
                transport,
                on_timer,
                &transport.timer_completion,
                transport.config.tick_interval_ns,
            );
        }

        fn on_timer(
            transport: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            _ = completion;
            result catch {};
            if (transport.stopped) return;
            const now = transport.now_ns();
            transport.receive_datagrams(now);
            transport.service.tick(now);
            transport.send_datagrams();
            transport.execute_commands();
            for (transport.links) |*link| {
                if (link.state != .open) continue;
                if (link.close_after_send) {
                    if (now >= link.close_deadline_ns) transport.teardown(link);
                    continue;
                }
                link.connection.tick(now);
                transport.pump(link);
            }
            transport.submit_timer();
        }

        /// Feeds queued UDP datagrams to discovery.
        fn receive_datagrams(transport: *Self, now: u64) void {
            const udp = transport.udp orelse return;
            var buffer: [io_module.datagram_size_max]u8 = undefined;
            var received: u32 = 0;
            while (received < datagrams_per_tick_max) : (received += 1) {
                const datagram = transport.io.recvfrom_now(udp, &buffer) orelse break;
                transport.stats.datagrams_received += 1;
                const from = endpoint_of(datagram.from);
                transport.service.on_datagram(from, buffer[0..datagram.length], now);
            }
            assert(received <= datagrams_per_tick_max);
        }

        /// Sends every datagram discovery queued (lost ones are discv5's to retry).
        fn send_datagrams(transport: *Self) void {
            const udp = transport.udp orelse return;
            var sent: u32 = 0;
            while (sent < datagrams_per_tick_max) : (sent += 1) {
                const datagram = transport.service.pop_datagram() orelse break;
                const target = address_of(datagram.endpoint);
                if (transport.io.sendto_now(udp, datagram.slice(), target)) {
                    transport.stats.datagrams_sent += 1;
                } else {
                    transport.stats.datagrams_dropped += 1;
                }
            }
            assert(sent <= datagrams_per_tick_max);
        }

        /// Runs the service's dial/disconnect commands and pumps fresh gossip output.
        pub fn execute_commands(transport: *Self) void {
            var executed: u32 = 0;
            while (transport.service.pop_command()) |command| : (executed += 1) {
                assert(executed < 1024);
                switch (command) {
                    .dial => |address| transport.dial(&address),
                    .disconnect => |slot| {
                        const link = transport.link_of_slot(slot) orelse continue;
                        // Graceful: yamux go-away first, socket closed once it is sent.
                        link.connection.close();
                        transport.stats.local_go_aways += 1;
                        transport.pump(link);
                    },
                }
            }
        }

        /// Pushes pending gossip (e.g. after `Service.publish_block`) to every connection.
        pub fn pump_all(transport: *Self) void {
            for (transport.links) |*link| {
                if (link.state == .open) transport.pump(link);
            }
        }

        fn link_of_slot(transport: *Self, slot: service_module.Slot) ?*Link {
            for (transport.links) |*link| {
                if (link.state == .open and link.slot == slot) return link;
            }
            return null;
        }

        fn free_link(transport: *Self) ?*Link {
            for (transport.links) |*link| {
                if (link.state == .free) return link;
            }
            return null;
        }

        // ---------------------------------------------------------------- dialing

        fn dial(transport: *Self, address: *const multiaddr.Multiaddr) void {
            if (transport.stopped) return transport.dial_failed(address);
            const endpoint = multiaddr.tcp_endpoint(address) orelse
                return transport.dial_failed(address);
            const link = transport.free_link() orelse return transport.dial_failed(address);
            const target = switch (endpoint.address) {
                .ip4 => |bytes| io_module.Address.ip4(bytes, endpoint.port),
                .ip6 => |bytes| io_module.Address.ip6(bytes, endpoint.port),
            };
            const fd = transport.io.open_socket_tcp(target.family) catch {
                return transport.dial_failed(address);
            };
            transport.assert_descriptor_fresh(fd);
            link.* = .{
                .transport = transport,
                .state = .connecting,
                .fd = fd,
                .outbound = true,
                .dial_address = address.*,
                .recv_inflight = true,
            };
            transport.stats.dialed += 1;
            transport.io.connect(*Link, link, on_connect, &link.recv_completion, fd, target);
        }

        fn dial_failed(transport: *Self, address: *const multiaddr.Multiaddr) void {
            transport.stats.dial_failures += 1;
            transport.service.on_dial_failed(address);
        }

        fn on_connect(
            link: *Link,
            completion: *IO.Completion,
            result: io_module.ConnectError!void,
        ) void {
            _ = completion;
            const transport = link.transport;
            link.recv_inflight = false;
            if (link.state == .closing) return transport.release_if_idle(link);
            assert(link.state == .connecting);
            result catch return transport.teardown(link);
            transport.open(link, .dialer);
        }

        // -------------------------------------------------------------- accepting

        fn submit_accept(transport: *Self) void {
            transport.io.accept(
                *Self,
                transport,
                on_accept,
                &transport.accept_completion,
                transport.listener,
            );
        }

        fn on_accept(
            transport: *Self,
            completion: *IO.Completion,
            result: io_module.AcceptError!IO.Fd,
        ) void {
            _ = completion;
            if (transport.stopped) {
                if (result) |fd| transport.io.close_now(fd) else |_| {}
                return;
            }
            transport.submit_accept();
            const fd = result catch return;
            const link = transport.free_link() orelse return transport.io.close_now(fd);
            const remote = ip_of(transport.io.peer_address(fd));
            if (!transport.service.reserve_inbound(remote)) return transport.io.close_now(fd);
            transport.stats.accepted += 1;
            transport.assert_descriptor_fresh(fd);
            link.* = .{ .transport = transport, .state = .connecting, .fd = fd };
            transport.open(link, .listener);
        }

        // ------------------------------------------------------------ connections

        fn open(transport: *Self, link: *Link, role: connection_module.Role) void {
            const random = transport.prng.random();
            var config: connection_module.Config = .{
                .identity_secret = transport.config.identity_secret,
                .static_seed = undefined,
                .ephemeral_seed = undefined,
                .random_seed = random.int(u64),
                .now_ns = transport.now_ns(),
                .gossip_frame_size_max = transport.config.gossip_frame_size_max,
                .gossip_send_queue_bytes = 2 * transport.config.gossip_frame_size_max,
            };
            random.bytes(&config.static_seed);
            random.bytes(&config.ephemeral_seed);
            link.connection = Connection.init(transport.allocator, role, config) catch {
                return transport.teardown(link);
            };
            link.connection_live = true;
            link.state = .open;
            transport.submit_recv(link);
            transport.pump(link);
        }

        fn submit_recv(transport: *Self, link: *Link) void {
            assert(!link.recv_inflight and link.state == .open);
            link.recv_inflight = true;
            transport.io.recv(
                *Link,
                link,
                on_recv,
                &link.recv_completion,
                link.fd,
                &link.recv_buffer,
            );
        }

        fn on_recv(
            link: *Link,
            completion: *IO.Completion,
            result: io_module.RecvError!usize,
        ) void {
            _ = completion;
            const transport = link.transport;
            link.recv_inflight = false;
            if (link.state != .open) return transport.release_if_idle(link);
            const size = result catch return transport.teardown(link);
            if (size == 0) return transport.teardown(link);
            transport.stats.bytes_received += size;
            const bytes = link.recv_buffer[0..size];
            _ = link.connection.receive(bytes, transport.now_ns()) catch {};
            transport.pump(link);
            if (link.state == .open) transport.submit_recv(link);
        }

        /// Delivers connection events to the service, forwards gossip, and flushes bytes.
        fn pump(transport: *Self, link: *Link) void {
            assert(link.state == .open);
            var events: u32 = 0;
            while (link.connection.pop_event()) |event| : (events += 1) {
                assert(events <= 1024);
                transport.on_event(link, event);
                if (link.state != .open) return;
            }
            // Gossip slices stay valid until the next receive; resume held-back frames.
            if (link.connection.is_established()) {
                _ = link.connection.receive(&.{}, transport.now_ns()) catch {};
                while (link.connection.pop_event()) |event| : (events += 1) {
                    assert(events <= 2048);
                    transport.on_event(link, event);
                    if (link.state != .open) return;
                }
            }
            transport.forward_gossip(link);
            transport.flush(link);
            if (link.state == .open and link.connection.closed_reason() != null) {
                transport.finish_close(link);
            }
        }

        /// The connection is closed: close the socket now, or after the in-flight send
        /// delivers its last bytes (bounded by `close_linger_ns`).
        fn finish_close(transport: *Self, link: *Link) void {
            assert(link.state == .open);
            if (!link.send_inflight) return transport.teardown(link);
            if (link.close_after_send) return;
            link.close_after_send = true;
            link.close_deadline_ns = transport.now_ns() + close_linger_ns;
        }

        fn on_event(transport: *Self, link: *Link, event: connection_module.Event) void {
            const now = transport.now_ns();
            switch (event) {
                .established => |peer| {
                    if (!transport.resolve_duplicate(link, &peer)) return transport.teardown(link);
                    const direction: @import("libp2p/connections.zig").Direction =
                        if (link.outbound) .outbound else .inbound;
                    link.peer = peer;
                    const remote = ip_of(transport.io.peer_address(link.fd));
                    link.slot = transport.service.on_connected(peer, direction, remote, now) catch {
                        // The service already released the pending reservation.
                        return transport.teardown_quiet(link);
                    };
                },
                .gossip_frame => |frame| {
                    const slot = link.slot orelse return;
                    transport.service.on_gossip_frame(slot, frame, now);
                },
                .closed => |reason| {
                    switch (reason) {
                        .remote_go_away => transport.stats.remote_go_aways += 1,
                        else => {},
                    }
                    transport.finish_close(link);
                },
                .identified => {
                    const slot = link.slot orelse return;
                    const message = link.connection.remote_identify_message() orelse return;
                    transport.service.on_identified(slot, message);
                },
                .ping_rtt_ns => |rtt_ns| {
                    const slot = link.slot orelse return;
                    transport.service.on_ping(slot, rtt_ns);
                },
            }
        }

        /// Simultaneous dials leave two connections to one peer. Both sides keep the one
        /// dialed by the smaller peer id, so they agree without coordination. Returns
        /// whether `link` survives (an older duplicate is closed if `link` wins).
        fn resolve_duplicate(transport: *Self, link: *Link, peer: *const peer_id.PeerId) bool {
            const local = link.connection.local_peer();
            const local_dials_kept = std.mem.order(u8, local.slice(), peer.slice()) == .lt;
            for (transport.links) |*other| {
                if (other == link or other.state != .open or other.slot == null) continue;
                if (!other.peer.eql(peer)) continue;
                if (link.outbound == other.outbound) return false;
                if (link.outbound != local_dials_kept) return false;
                transport.teardown(other);
                return true;
            }
            return true;
        }

        fn forward_gossip(transport: *Self, link: *Link) void {
            const slot = link.slot orelse return;
            if (!link.connection.is_established()) return;
            var frames: u32 = 0;
            while (frames < 64) : (frames += 1) {
                // Drain only when a maximum frame fits, so the router never drops one.
                if (link.connection.gossip_send_room() < transport.drain_buffer.len) return;
                const frame = transport.service.drain_gossip(slot, transport.drain_buffer) orelse
                    return;
                link.connection.send_gossip(frame) catch return;
            }
        }

        fn flush(transport: *Self, link: *Link) void {
            if (link.send_inflight or link.state != .open) return;
            const output = link.connection.flush(&link.send_buffer);
            if (output.len == 0) return;
            assert(output.ptr == &link.send_buffer);
            link.send_offset = 0;
            link.send_length = output.len;
            transport.submit_send(link);
        }

        fn submit_send(transport: *Self, link: *Link) void {
            assert(link.send_offset < link.send_length);
            link.send_inflight = true;
            transport.io.send(
                *Link,
                link,
                on_send,
                &link.send_completion,
                link.fd,
                link.send_buffer[link.send_offset..link.send_length],
            );
        }

        fn on_send(
            link: *Link,
            completion: *IO.Completion,
            result: io_module.SendError!usize,
        ) void {
            _ = completion;
            const transport = link.transport;
            link.send_inflight = false;
            if (link.state != .open) return transport.release_if_idle(link);
            const sent = result catch return transport.teardown(link);
            transport.stats.bytes_sent += sent;
            link.send_offset += sent;
            assert(link.send_offset <= link.send_length);
            if (link.send_offset < link.send_length) return transport.submit_send(link);
            if (link.close_after_send) return transport.teardown(link);
            transport.flush(link);
        }

        // ---------------------------------------------------------------- closing

        /// Reports the closed link to the service, closes the socket, and frees the link
        /// once no completion is in flight.
        fn teardown(transport: *Self, link: *Link) void {
            if (link.state == .closing or link.state == .free) return;
            const now = transport.now_ns();
            if (link.slot) |slot| {
                transport.service.on_disconnected(slot, now);
            } else if (link.outbound) {
                transport.dial_failed(&link.dial_address);
            } else {
                transport.service.on_handshake_failed(.inbound);
            }
            transport.teardown_quiet(link);
        }

        /// Closes without telling the service (it already knows).
        fn teardown_quiet(transport: *Self, link: *Link) void {
            assert(link.state == .open or link.state == .connecting);
            transport.stats.closed += 1;
            link.slot = null;
            if (link.connection_live) {
                link.connection.deinit();
                link.connection_live = false;
            }
            const was_connecting = link.state == .connecting;
            link.state = .closing;
            if (was_connecting) {
                transport.io.close_now(link.fd);
            } else {
                transport.io.shutdown_now(link.fd);
                link.fd_shut = true;
            }
            transport.release_if_idle(link);
        }

        /// A new descriptor never aliases a shut one whose completions are still in flight.
        fn assert_descriptor_fresh(transport: *const Self, fd: IO.Fd) void {
            for (transport.links) |*link| {
                if (link.fd_shut) assert(link.fd != fd);
            }
        }

        fn release_if_idle(transport: *Self, link: *Link) void {
            assert(link.state == .closing);
            if (link.recv_inflight or link.send_inflight) return;
            if (link.fd_shut) {
                transport.io.close_now(link.fd);
                link.fd_shut = false;
            }
            link.state = .free;
            assert(!link.fd_shut);
        }

        pub fn open_count(transport: *const Self) u32 {
            var count: u32 = 0;
            for (transport.links) |*link| count += @intFromBool(link.state == .open);
            return count;
        }
    };
}

/// The IP of a socket address (the gater and IP colocation scoring key on it).
fn ip_of(address: ?io_module.Address) ?ip.Address {
    const value = address orelse return null;
    return switch (value.family) {
        .ip4 => .{ .ip4 = value.bytes[0..4].* },
        .ip6 => .{ .ip6 = value.bytes },
    };
}

fn endpoint_of(address: io_module.Address) disc_endpoint {
    return switch (address.family) {
        .ip4 => .{ .address = .{ .ip4 = address.bytes[0..4].* }, .port = address.port },
        .ip6 => .{ .address = .{ .ip6 = address.bytes }, .port = address.port },
    };
}

fn address_of(endpoint: disc_endpoint) io_module.Address {
    return switch (endpoint.address) {
        .ip4 => |bytes| io_module.Address.ip4(bytes, endpoint.port),
        .ip6 => |bytes| io_module.Address.ip6(bytes, endpoint.port),
    };
}

const disc_endpoint = @import("disc/table.zig").Endpoint;

test {
    _ = @import("transport_test.zig");
}

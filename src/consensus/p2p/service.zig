//! `p2p.Service`: the IO-free network state machine consensus wires in. It composes
//! discv5 discovery, unsafe-block gossip (router + validation), the connection gater,
//! connection limits, and peer-score monitoring, mirroring base/base
//! `service/src/actors/network` (+ `gossip/src/driver.rs`, `disc/src/driver.rs`).
//!
//! The transport (TCP + libp2p connection pipeline, later over `utilities/io`) talks to
//! it through plain calls:
//!   UDP:         `on_datagram`, `pop_datagram`
//!   dialing:     `pop_command` (dial / disconnect), `on_dial_failed`
//!   connections: `reserve_inbound` before a handshake, `on_handshake_failed`,
//!                `on_connected` -> connection slot, `on_disconnected`
//!   gossip:      `on_gossip_frame(slot, frame)`, `drain_gossip(slot, buffer)`
//!   consensus:   `publish_block`, `pop_block`
//!   time:        `tick(now_ns)`
//! Every valid discovered record is dialed when the gater and limits allow (base/base
//! dials all of them). With bans enabled (`--p2p.ban.peers`, off by default), every 15 s
//! peers under the ban threshold are disconnected and banned in discovery for the ban
//! duration (base/base `PeerMonitoring`).

const std = @import("std");
const assert = std.debug.assert;
const disc = @import("disc/root.zig");
const gossip_handler = @import("gossip/handler.zig");
const router_module = @import("gossip/router.zig");
const block = @import("gossip/block.zig");
const gater_module = @import("peers/gater.zig");
const connections = @import("libp2p/connections.zig");
const enr = @import("peers/enr.zig");
const ip = @import("peers/ip.zig");
const multiaddr = @import("peers/multiaddr.zig");
const identify = @import("libp2p/identify.zig");
const peer_id = @import("peers/peer_id.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const primitives = @import("../../common/primitives/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");

const ns_per_s = std.time.ns_per_s;
const ns_per_ms = std.time.ns_per_ms;

pub const Slot = router_module.Slot;
pub const BlockGossip = gossip_handler.BlockGossip;

pub const Config = struct {
    rollup: *const rollup_config.RollupConfig,
    unsafe_block_signer: primitives.Address,
    block_time_s: u64 = 2,
    disc: disc.service.Config,
    /// base/base CLI defaults: 500 redials per 60 min (`--p2p.redial`, `.period`).
    gater: gater_module.Config = .{ .peer_redialing = 500 },
    limits: connections.Limits = .{},
    /// base/base `PeerMonitoring` (`--p2p.ban.peers`, default off; `--p2p.ban.threshold`,
    /// `--p2p.ban.duration`).
    ban_enabled: bool = false,
    ban_threshold: f64 = -100,
    ban_duration_ns: u64 = 3600 * ns_per_s,
    heartbeat_interval_ns: u64 = 500 * ns_per_ms,
    score_inspect_interval_ns: u64 = 15 * ns_per_s,
    gater_prune_interval_ns: u64 = 60 * ns_per_s,
    pending_dial_prune_interval_ns: u64 = 5 * ns_per_s,
    mcache: @import("gossip/mcache.zig").Config = .{},
    mesh: gossip_handler.Mesh = .{},
    score_level: @import("peers/score.zig").Level = .light,
    topic_scoring: bool = true,
};

pub const Command = union(enum) {
    /// Open a TCP connection and run the libp2p pipeline as dialer.
    dial: multiaddr.Multiaddr,
    /// Close the connection in `slot`; the transport then calls `on_disconnected`.
    disconnect: Slot,
};

/// Why a dial did not start or failed (base/base `dial_peer_error` labels).
pub const DialError = enum(u8) {
    invalid_enr,
    already_connected,
    connection_error,
    invalid_multiaddr,
    already_dialing,
    threshold_reached,
    blocked_peer,
    blocked_address,
    blocked_subnet,
};

/// Why an inbound connection was refused (base/base `inbound_connection_error` labels).
pub const InboundError = enum(u8) {
    blocked_peer,
    blocked_address,
    blocked_subnet,
    invalid_ip_address,
};

pub const Stats = struct {
    dials: u64 = 0,
    dials_refused: u64 = 0,
    inbound_refused: u64 = 0,
    dial_errors: [std.meta.fieldNames(DialError).len]u64 = @splat(0),
    inbound_errors: [std.meta.fieldNames(InboundError).len]u64 = @splat(0),
    banned: u64 = 0,
    invalid_rpcs: u64 = 0,
};

const commands_max = 128;

/// What identify and ping told us about a connected peer, bounded for static storage.
pub const PeerInfo = struct {
    pub const text_max = 64;
    pub const protocols_max = 8;
    pub const addresses_max = 4;

    agent_version: Text = .{},
    protocol_version: Text = .{},
    protocols: [protocols_max]Text = @splat(.{}),
    protocols_count: u8 = 0,
    addresses: [addresses_max]multiaddr.Multiaddr = undefined,
    addresses_count: u8 = 0,
    latency_ns: u64 = 0,

    /// A string truncated to `text_max` bytes.
    pub const Text = struct {
        bytes: [text_max]u8 = undefined,
        length: u8 = 0,

        pub fn init(value: []const u8) Text {
            var text: Text = .{};
            text.length = @intCast(@min(value.len, text_max));
            @memcpy(text.bytes[0..text.length], value[0..text.length]);
            return text;
        }

        pub fn slice(text: *const Text) []const u8 {
            assert(text.length <= text_max);
            return text.bytes[0..text.length];
        }
    };

    pub fn from_identify(message: *const identify.Identify) PeerInfo {
        var info: PeerInfo = .{
            .agent_version = .init(message.agent_version),
            .protocol_version = .init(message.protocol_version),
        };
        for (message.protocol_slice()) |protocol| {
            if (info.protocols_count == protocols_max) break;
            info.protocols[info.protocols_count] = .init(protocol);
            info.protocols_count += 1;
        }
        for (message.listen_slice()) |address| {
            if (info.addresses_count == addresses_max) break;
            info.addresses[info.addresses_count] = address;
            info.addresses_count += 1;
        }
        assert(info.protocols_count <= protocols_max);
        return info;
    }
};

const Connected = struct {
    active: bool = false,
    peer: peer_id.PeerId = undefined,
    direction: connections.Direction = .inbound,
    disconnecting: bool = false,
    info: PeerInfo = .{},
};

pub const Service = struct {
    config: Config,
    discovery: disc.service.Service,
    gossip: *BlockGossip,
    gater: gater_module.Gater,
    limits: connections.Manager,
    connected: [router_module.peers_max]Connected = @splat(.{}),
    commands: [commands_max]Command = undefined,
    commands_head: u32 = 0,
    commands_count: u32 = 0,
    next_heartbeat_ns: u64 = 0,
    next_inspect_ns: u64 = 0,
    next_gater_prune_ns: u64 = 0,
    next_dial_prune_ns: u64 = 0,
    /// Time of the latest `tick` (for calls that carry no time, like admin RPC).
    now_ns: u64 = 0,
    stats: Stats = .{},

    /// Heap-allocated: the gossip handler and discovery keep internal pointers.
    pub fn create(
        allocator: std.mem.Allocator,
        config: Config,
        node_secret: secp256k1.SecretKey,
        local_record: enr.Record,
        random: std.Random,
    ) !*Service {
        assert(config.ban_duration_ns > 0 and config.heartbeat_interval_ns > 0);
        const service = try allocator.create(Service);
        errdefer allocator.destroy(service);
        service.* = .{
            .config = config,
            .discovery = undefined,
            .gossip = undefined,
            .gater = undefined,
            .limits = undefined,
        };
        service.discovery = try disc.service.Service.init(
            allocator,
            config.disc,
            node_secret,
            local_record,
            random,
        );
        errdefer service.discovery.deinit(allocator);
        service.gossip = try BlockGossip.create(allocator, .{
            .rollup = config.rollup,
            .unsafe_block_signer = config.unsafe_block_signer,
            .block_time_s = config.block_time_s,
            .mcache = config.mcache,
            .mesh = config.mesh,
            .score_level = config.score_level,
            .topic_scoring = config.topic_scoring,
        }, random);
        errdefer service.gossip.destroy(allocator);
        service.gater = try gater_module.Gater.init(allocator, config.gater);
        errdefer service.gater.deinit(allocator);
        assert(config.limits.established_max + config.limits.bypass_max <=
            router_module.peers_max);
        service.limits = try connections.Manager.init(allocator, config.limits);
        return service;
    }

    pub fn destroy(service: *Service, allocator: std.mem.Allocator) void {
        service.limits.deinit(allocator);
        service.gater.deinit(allocator);
        service.gossip.destroy(allocator);
        service.discovery.deinit(allocator);
        allocator.destroy(service);
    }

    // ------------------------------------------------------------------ commands

    pub fn pop_command(service: *Service) ?Command {
        if (service.commands_count == 0) return null;
        const command = service.commands[service.commands_head];
        service.commands_head = (service.commands_head + 1) % commands_max;
        service.commands_count -= 1;
        return command;
    }

    fn push_command(service: *Service, command: Command) bool {
        if (service.commands_count == commands_max) return false;
        const index = (service.commands_head + service.commands_count) % commands_max;
        service.commands[index] = command;
        service.commands_count += 1;
        assert(service.commands_count <= commands_max);
        return true;
    }

    // ------------------------------------------------------------------ discovery

    pub fn add_boot_record(service: *Service, record: *const enr.Record, now_ns: u64) void {
        service.discovery.add_boot_record(record, now_ns);
    }

    pub fn on_datagram(
        service: *Service,
        from: disc.table.Endpoint,
        bytes: []const u8,
        now_ns: u64,
    ) void {
        service.discovery.on_packet(from, bytes, now_ns);
        service.dial_discovered(now_ns);
    }

    pub fn pop_datagram(service: *Service) ?*const disc.service.Datagram {
        return service.discovery.pop_outgoing();
    }

    fn dial_discovered(service: *Service, now_ns: u64) void {
        var processed: u32 = 0;
        while (service.discovery.pop_discovered()) |record| : (processed += 1) {
            assert(processed < 1024);
            const address = multiaddr.from_enr(record) orelse {
                service.count_dial_error(.invalid_enr);
                continue;
            };
            service.dial(&address, now_ns);
        }
    }

    /// Dials `address` unless the gater, limits, or an existing connection forbid it.
    pub fn dial(service: *Service, address: *const multiaddr.Multiaddr, now_ns: u64) void {
        service.gater.can_connect_outbound(address, now_ns) catch |err| {
            service.stats.dials_refused += 1;
            service.count_dial_error(dial_error_of(err));
            return;
        };
        // `can_connect_outbound` rejects addresses without a peer id.
        const peer = address.peer().?;
        if (service.slot_of(&peer) != null) return service.count_dial_error(.already_connected);
        const protected = service.gater.protected_peers.contains(peer);
        service.limits.begin_bypass(.outbound, protected) catch {
            service.stats.dials_refused += 1;
            return;
        };
        if (!service.gater.dialing(address, now_ns) or
            !service.push_command(.{ .dial = address.* }))
        {
            service.gater.remove_dial(peer);
            service.limits.abort(.outbound);
            service.stats.dials_refused += 1;
            service.count_dial_error(.connection_error);
            return;
        }
        service.gater.dialed_address(address, now_ns);
        service.stats.dials += 1;
    }

    fn count_dial_error(service: *Service, reason: DialError) void {
        service.stats.dial_errors[@backingInt(reason)] += 1;
    }

    fn count_inbound_error(service: *Service, reason: InboundError) void {
        service.stats.inbound_errors[@backingInt(reason)] += 1;
    }

    pub fn on_dial_failed(service: *Service, address: *const multiaddr.Multiaddr) void {
        const peer = address.peer() orelse return;
        service.count_dial_error(.connection_error);
        service.gater.remove_dial(peer);
        service.limits.abort(.outbound);
    }

    // ---------------------------------------------------------------- connections

    /// Reserves a pending inbound slot before the handshake; false means refuse. The
    /// address is null when the transport does not know it.
    pub fn reserve_inbound(service: *Service, address: ?ip.Address) bool {
        if (address) |value| {
            for (service.gater.blocked_addresses.slice()) |blocked| {
                if (!std.meta.eql(blocked, value)) continue;
                service.stats.inbound_refused += 1;
                service.count_inbound_error(.blocked_address);
                return false;
            }
        }
        service.limits.begin(.inbound) catch {
            service.stats.inbound_refused += 1;
            return false;
        };
        return true;
    }

    pub fn on_handshake_failed(service: *Service, direction: connections.Direction) void {
        service.limits.abort(direction);
    }

    pub const ConnectError = gater_module.Error || connections.Error || error{RouterFull};

    /// A libp2p connection with `peer` finished its handshake. Returns the slot used by
    /// every later call; on error the transport closes the connection.
    pub fn on_connected(
        service: *Service,
        peer: peer_id.PeerId,
        direction: connections.Direction,
        address: ?ip.Address,
        now_ns: u64,
    ) ConnectError!Slot {
        if (direction == .outbound) service.gater.remove_dial(peer);
        if (direction == .inbound) {
            if (address) |value| {
                service.gater.can_connect_inbound(peer, value) catch |err| {
                    service.limits.abort(direction);
                    service.stats.inbound_refused += 1;
                    service.count_inbound_error(inbound_error_of(err));
                    return err;
                };
            } else {
                // Allowed (the transport may not know it), but counted like base/base.
                service.count_inbound_error(.invalid_ip_address);
            }
        }
        const protected = service.gater.protected_peers.contains(peer);
        try service.limits.establish_bypass(peer, direction, protected);
        const router = &service.gossip.router;
        const slot = router.add_peer(peer, direction == .outbound, address, now_ns) orelse {
            service.limits.close(peer, direction);
            return error.RouterFull;
        };
        service.connected[slot] = .{ .active = true, .peer = peer, .direction = direction };
        return slot;
    }

    /// Records the peer's identify message (agent, protocols, listen addresses).
    pub fn on_identified(service: *Service, slot: Slot, message: *const identify.Identify) void {
        const connection = &service.connected[slot];
        assert(connection.active);
        const latency_ns = connection.info.latency_ns;
        connection.info = .from_identify(message);
        connection.info.latency_ns = latency_ns;
    }

    /// Records the latest ping round trip.
    pub fn on_ping(service: *Service, slot: Slot, rtt_ns: u64) void {
        const connection = &service.connected[slot];
        assert(connection.active);
        connection.info.latency_ns = rtt_ns;
    }

    pub fn on_disconnected(service: *Service, slot: Slot, now_ns: u64) void {
        const connection = &service.connected[slot];
        assert(connection.active);
        service.limits.close(connection.peer, connection.direction);
        service.gossip.router.remove_peer(slot, now_ns);
        connection.* = .{};
    }

    pub fn slot_of(service: *const Service, peer: *const peer_id.PeerId) ?Slot {
        for (&service.connected, 0..) |*connection, slot| {
            if (connection.active and connection.peer.eql(peer)) return @intCast(slot);
        }
        return null;
    }

    pub fn connected_count(service: *const Service) u32 {
        var count: u32 = 0;
        for (service.connected) |connection| count += @intFromBool(connection.active);
        return count;
    }

    // --------------------------------------------------------------------- gossip

    pub fn on_gossip_frame(service: *Service, slot: Slot, frame: []const u8, now_ns: u64) void {
        assert(service.connected[slot].active);
        service.gossip.on_rpc(slot, frame, now_ns) catch |err| switch (err) {
            error.Graylisted => {},
            error.InvalidRpc => {
                service.stats.invalid_rpcs += 1;
                service.request_disconnect(slot);
            },
        };
    }

    pub fn drain_gossip(service: *Service, slot: Slot, buffer: []u8) ?[]const u8 {
        assert(service.connected[slot].active);
        return service.gossip.router.drain(slot, buffer);
    }

    pub fn publish_block(
        service: *Service,
        secret_key: [32]u8,
        parent_beacon_block_root: ?primitives.B256,
        payload: block.ExecutionPayload,
        now_ns: u64,
    ) BlockGossip.PublishError!router_module.Id {
        return service.gossip.publish(secret_key, parent_beacon_block_root, payload, now_ns);
    }

    pub fn pop_block(service: *Service, scratch: []u8) ?block.Envelope {
        return service.gossip.pop_block(scratch);
    }

    /// Asks the transport to close every connection to `peer`. False if none exists.
    pub fn disconnect_peer(service: *Service, peer: *const peer_id.PeerId) bool {
        const slot = service.slot_of(peer) orelse return false;
        service.request_disconnect(slot);
        return true;
    }

    fn request_disconnect(service: *Service, slot: Slot) void {
        const connection = &service.connected[slot];
        if (connection.disconnecting) return;
        if (service.push_command(.{ .disconnect = slot })) connection.disconnecting = true;
    }

    // ----------------------------------------------------------------------- time

    pub fn tick(service: *Service, now_ns: u64) void {
        service.now_ns = @max(service.now_ns, now_ns);
        service.discovery.tick(now_ns);
        service.dial_discovered(now_ns);
        if (now_ns >= service.next_heartbeat_ns) {
            service.next_heartbeat_ns = now_ns + service.config.heartbeat_interval_ns;
            service.gossip.heartbeat(now_ns);
        }
        if (now_ns >= service.next_inspect_ns) {
            service.next_inspect_ns = now_ns + service.config.score_inspect_interval_ns;
            service.ban_low_scores(now_ns);
        }
        if (now_ns >= service.next_gater_prune_ns) {
            service.next_gater_prune_ns = now_ns + service.config.gater_prune_interval_ns;
            service.gater.prune(now_ns);
        }
        if (now_ns >= service.next_dial_prune_ns) {
            service.next_dial_prune_ns = now_ns + service.config.pending_dial_prune_interval_ns;
            service.prune_expired_dials(now_ns);
        }
    }

    /// Disconnects peers under the ban threshold and bans them in discovery.
    fn ban_low_scores(service: *Service, now_ns: u64) void {
        if (!service.config.ban_enabled) return;
        for (&service.connected, 0..) |*connection, slot| {
            if (!connection.active or connection.disconnecting) continue;
            const value = service.gossip.router.peer_score_value(@intCast(slot));
            if (value >= service.config.ban_threshold) continue;
            // Protected peers are never disconnected (base/base `can_disconnect`).
            if (!service.gater.can_disconnect(connection.peer)) continue;
            service.stats.banned += 1;
            service.request_disconnect(@intCast(slot));
            const key = connection.peer.secp256k1_public_key() orelse continue;
            const node_id = enr.node_id_from_public_key(key);
            service.discovery.ban_node(node_id, now_ns + service.config.ban_duration_ns);
        }
    }

    fn prune_expired_dials(service: *Service, now_ns: u64) void {
        var expired: [32]peer_id.PeerId = undefined;
        for (service.gater.expired_dials(now_ns, &expired)) |peer| {
            service.gater.remove_dial(peer);
        }
    }
};

fn dial_error_of(err: gater_module.Error) DialError {
    return switch (err) {
        error.InvalidMultiaddr, error.InvalidIpAddress => .invalid_multiaddr,
        error.AlreadyDialing => .already_dialing,
        error.ThresholdReached => .threshold_reached,
        error.PeerBlocked => .blocked_peer,
        error.AddressBlocked => .blocked_address,
        error.SubnetBlocked => .blocked_subnet,
    };
}

fn inbound_error_of(err: gater_module.Error) InboundError {
    return switch (err) {
        error.PeerBlocked => .blocked_peer,
        error.AddressBlocked => .blocked_address,
        error.SubnetBlocked => .blocked_subnet,
        error.InvalidMultiaddr,
        error.InvalidIpAddress,
        error.AlreadyDialing,
        error.ThresholdReached,
        => .invalid_ip_address,
    };
}

test {
    _ = @import("service_test.zig");
}

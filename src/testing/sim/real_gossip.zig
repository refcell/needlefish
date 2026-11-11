//! Real unsafe-block gossip in the cluster (`Config.real_gossip`): the sequencer and every
//! verifier node run the consensus lane's IO-free `p2p.Service` (gossipsub router, block
//! validation, signer check, snappy + SSZ, seen cache, peer scoring), and its framed RPCs
//! cross simulated connections instead of model `unsafe_block` messages. The sequencer
//! signs each block the reference engine executed; the first verifier hands what its
//! service pops to the real driver, the others relay.
//!
//! Connections behave like TCP under the cluster's faults, not like datagrams:
//!   - frames arrive whole and in order, after a seeded latency from the network config;
//!     a network "drop" is a retransmission that adds `retransmit_ns`;
//!   - a partition stalls a connection: frames wait and arrive after healing, unless the
//!     link stays cut for `stall_timeout_ns`, which resets the connection;
//!   - a crash resets every connection of the node at once and its service is rebuilt
//!     from scratch on restart (same node key, as a restarted process);
//!   - a reset pair redials after `redial_delay_ns` once the link is up again.
//! Discovery stays off (discv5 has its own DST in `consensus/p2p`): the lower peer of
//! every pair dials the other through `Service.dial` (gater, limits, pending slots), and
//! the dial command it emits completes the next step when both ends are up and linked.
//! All randomness comes from one seeded stream, so the gossip is part of the seed.

const std = @import("std");
const assert = std.debug.assert;

const service_module = @import("../../consensus/p2p/service.zig");
const enr = @import("../../consensus/p2p/peers/enr.zig");
const multiaddr = @import("../../consensus/p2p/peers/multiaddr.zig");
const peer_id = @import("../../consensus/p2p/peers/peer_id.zig");
const p2p_secp256k1 = @import("../../consensus/p2p/peers/secp256k1.zig");
const ip = @import("../../consensus/p2p/peers/ip.zig");
const rpc = @import("../../consensus/p2p/gossip/rpc.zig");
const block = @import("../../consensus/p2p/gossip/block.zig");
const snappy = @import("../../consensus/p2p/gossip/snappy.zig");
const router_module = @import("../../consensus/p2p/gossip/router.zig");
const score = @import("../../consensus/p2p/peers/score.zig");
const validity = @import("../../consensus/p2p/gossip/validity.zig");
const gossip_bridge = @import("../../consensus/service/gossip_bridge.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const Prng = @import("../prng.zig").Prng;
const network_module = @import("network.zig");
const nodes = @import("nodes.zig");

pub const Envelope = block.Envelope;
const Service = service_module.Service;
const Slot = service_module.Slot;
const NodeId = network_module.NodeId;
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

/// The sequencer plus every verifier node.
pub const peers_max = 1 + network_module.node_count_max - nodes.node_verifier_first;
const pairs_max = peers_max * (peers_max - 1) / 2;
/// Frames and bytes one direction of a connection holds in flight (a stalled TCP send
/// buffer); overflowing resets the connection.
const queue_frames_max = 256;
const queue_bytes = 128 * 1024;
/// Frames drained per connection direction per step; blocks popped per node per step.
const frames_per_step_max = 64;
pub const blocks_per_step_max = 16;
pub const stall_timeout_ns = 10 * ns_per_s;
pub const redial_delay_ns = 1 * ns_per_s;
pub const retransmit_ns = 200 * ns_per_ms;
/// Gossip validation's timestamp window around the receiver's clock.
pub const timestamp_future_max_ns = validity.timestamp_future_max_seconds * ns_per_s;
pub const timestamp_age_max_ns = validity.timestamp_age_max_seconds * ns_per_s;
/// The sequencer's block signing key (the rollup's unsafe block signer).
pub const sequencer_key: [32]u8 = @splat(0x05);

comptime {
    assert(peers_max >= 2 and peers_max <= router_module.peers_max);
    assert(queue_bytes >= 4 * 1024 and queue_frames_max >= 16);
}

/// What the gossip layer sees of the cluster this step.
pub const World = struct {
    global_ns: u64,
    /// Per peer: running (not crashed), and its local clock (with skew).
    up: [peers_max]bool = @splat(false),
    local_ns: [peers_max]u64 = @splat(0),
    /// Both directions between two peers' nodes deliver (no partition).
    linked: [peers_max][peers_max]bool = @splat(@splat(false)),
};

pub const Stats = struct {
    published: u64 = 0,
    publish_failures: u64 = 0,
    frames_sent: u64 = 0,
    frames_delivered: u64 = 0,
    connects: u64 = 0,
    resets_crash: u64 = 0,
    resets_stall: u64 = 0,
    resets_overflow: u64 = 0,
    resets_requested: u64 = 0,
    /// Blocks not published because they were already older than the gossip window.
    stale_skipped: u64 = 0,
    /// Blocks each peer's service handed out (validated and decoded).
    popped: [peers_max]u64 = @splat(0),
};

const Frame = struct { start: u64, length: u32, deliver_ns: u64 };

/// One direction of a connection: frames in order, bytes in a ring.
const Queue = struct {
    frames: [queue_frames_max]Frame = undefined,
    head: u32 = 0,
    count: u32 = 0,
    /// Absolute byte positions; `bytes[position % queue_bytes]`.
    write: u64 = 0,
    last_deliver_ns: u64 = 0,

    fn oldest(queue: *const Queue) ?*const Frame {
        if (queue.count == 0) return null;
        return &queue.frames[queue.head];
    }

    /// False when the frame does not fit (the caller resets the connection).
    fn push(queue: *Queue, bytes: []u8, frame: []const u8, deliver_ns: u64) bool {
        assert(bytes.len == queue_bytes);
        assert(frame.len > 0);
        if (frame.len > queue_bytes or queue.count == queue_frames_max) return false;
        var start = queue.write;
        const offset = start % queue_bytes;
        // Never straddle the end of the ring: skip to its start instead.
        if (offset + frame.len > queue_bytes) start += queue_bytes - offset;
        const floor = if (queue.oldest()) |first| first.start else start;
        if (start + frame.len - floor > queue_bytes) return false;
        const at: usize = @intCast(start % queue_bytes);
        @memcpy(bytes[at..][0..frame.len], frame);
        const index = (queue.head + queue.count) % queue_frames_max;
        queue.frames[index] = .{
            .start = start,
            .length = @intCast(frame.len),
            .deliver_ns = deliver_ns,
        };
        queue.count += 1;
        queue.write = start + frame.len;
        queue.last_deliver_ns = deliver_ns;
        assert(queue.write - floor <= queue_bytes);
        return true;
    }

    fn pop(queue: *Queue) void {
        assert(queue.count > 0);
        queue.head = (queue.head + 1) % queue_frames_max;
        queue.count -= 1;
    }

    fn slice(queue: *const Queue, bytes: []const u8, frame: *const Frame) []const u8 {
        _ = queue;
        const at: usize = @intCast(frame.start % queue_bytes);
        assert(at + frame.length <= bytes.len);
        return bytes[at..][0..frame.length];
    }
};

/// A connection between peers `a < b`. Slot `i` is the slot on peer `a` (0) or `b` (1).
const Pair = struct {
    a: u8,
    b: u8,
    connected: bool = false,
    slots: [2]Slot = undefined,
    /// When the link was first seen cut while connected.
    blocked_since_ns: ?u64 = null,
    redial_ns: u64 = 0,
    connects: u64 = 0,
    first_connect_ns: ?u64 = null,
    /// queues[0]: a -> b, queues[1]: b -> a.
    queues: [2]Queue = .{ .{}, .{} },
};

const Peer = struct {
    secret: p2p_secp256k1.SecretKey,
    record: enr.Record,
    id: peer_id.PeerId,
    address: ip.Address,
    multiaddr: multiaddr.Multiaddr,
    prng: Prng,
    service: ?*Service = null,
    restarts: u64 = 0,
};

pub const RealGossip = struct {
    allocator: std.mem.Allocator,
    rollup: *const protocol.RollupConfig,
    signer: primitives.Address,
    peer_count: u8,
    peers: [peers_max]Peer,
    pairs: [pairs_max]Pair,
    pair_count: u8,
    /// `pair_count * 2` rings of `queue_bytes`.
    bytes: []u8,
    drain_buffer: []u8,
    pop_scratch: []u8,
    publish_storage: []u8,
    prng: Prng,
    latency_ns_min: u64,
    latency_ns_max: u64,
    drop_ppm: u32,
    /// Seconds since the Unix epoch at simulated time zero: the rollup's genesis.
    epoch_ns: u64,
    stats: Stats = .{},
    /// Per peer: the highest block number its service handed out.
    head_popped: [peers_max]u64 = @splat(0),

    /// Peer 0 is the sequencer node; peer `k > 0` is verifier `k - 1`.
    pub fn node_of(peer: u8) NodeId {
        assert(peer < peers_max);
        return if (peer == 0) nodes.node_sequencer else nodes.node_verifier_first + peer - 1;
    }

    pub fn create(
        allocator: std.mem.Allocator,
        seed: u64,
        peer_count: u8,
        rollup: *const protocol.RollupConfig,
        network: network_module.Config,
    ) !*RealGossip {
        assert(peer_count >= 2 and peer_count <= peers_max);
        assert(network.latency_ns_min <= network.latency_ns_max);
        const gossip = try allocator.create(RealGossip);
        errdefer allocator.destroy(gossip);
        const pair_count: u8 = @intCast(@as(u32, peer_count) * (peer_count - 1) / 2);
        const bytes = try allocator.alloc(u8, @as(usize, pair_count) * 2 * queue_bytes);
        errdefer allocator.free(bytes);
        const drain_buffer = try allocator.alloc(u8, router_module.Router.drain_buffer_min);
        errdefer allocator.free(drain_buffer);
        const pop_scratch = try allocator.alloc(u8, snappy.gossip_size_max);
        errdefer allocator.free(pop_scratch);
        const publish_storage = try allocator.alloc(u8, 64 * 1024);
        errdefer allocator.free(publish_storage);
        gossip.* = .{
            .allocator = allocator,
            .rollup = rollup,
            .signer = .{ .bytes = try common_secp256k1.address(sequencer_key) },
            .peer_count = peer_count,
            .peers = undefined,
            .pairs = undefined,
            .pair_count = pair_count,
            .bytes = bytes,
            .drain_buffer = drain_buffer,
            .pop_scratch = pop_scratch,
            .publish_storage = publish_storage,
            .prng = Prng.init(seed ^ 0x676f_7373_6970),
            .latency_ns_min = network.latency_ns_min,
            .latency_ns_max = network.latency_ns_max,
            .drop_ppm = network.drop_ppm,
            .epoch_ns = rollup.genesis.l2_time * ns_per_s,
        };
        try gossip.init_peers();
        var index: u8 = 0;
        for (0..peer_count) |a| {
            for (a + 1..peer_count) |b| {
                gossip.pairs[index] = .{ .a = @intCast(a), .b = @intCast(b) };
                index += 1;
            }
        }
        assert(index == pair_count);
        return gossip;
    }

    fn init_peers(gossip: *RealGossip) !void {
        var key_prng = gossip.prng;
        _ = gossip.prng.int(u64); // The key stream is a copy; move the main one past it.
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            var secret: p2p_secp256k1.SecretKey = undefined;
            while (true) {
                key_prng.fill(&secret);
                p2p_secp256k1.validate_secret_key(secret) catch continue;
                break;
            }
            const address: [4]u8 = .{ 10, 0, 0, @intCast(index + 1) };
            const record = try enr.build(secret, .{
                .ip4 = address,
                .udp = 9000,
                .tcp = 9222,
                .opstack = .{ .chain_id = gossip.rollup.l2_chain_id },
            });
            peer.* = .{
                .secret = secret,
                .record = record,
                .id = peer_id.from_public_key(record.public_key),
                .address = .{ .ip4 = address },
                .multiaddr = multiaddr.from_enr(&record).?, // Proof: ip4 and tcp are set.
                .prng = Prng.init(key_prng.int(u64)),
            };
        }
    }

    pub fn destroy(gossip: *RealGossip) void {
        const allocator = gossip.allocator;
        for (gossip.peers[0..gossip.peer_count]) |*peer| {
            if (peer.service) |service| service.destroy(allocator);
        }
        allocator.free(gossip.publish_storage);
        allocator.free(gossip.pop_scratch);
        allocator.free(gossip.drain_buffer);
        allocator.free(gossip.bytes);
        allocator.destroy(gossip);
    }

    fn service_config(gossip: *const RealGossip) service_module.Config {
        return .{
            .rollup = gossip.rollup,
            .unsafe_block_signer = gossip.signer,
            .block_time_s = gossip.rollup.block_time,
            .disc = .{
                .chain_id = gossip.rollup.l2_chain_id,
                .table = .{ .subnet_bucket_max = 0, .subnet_table_max = 0 },
            },
            .mcache = .{ .entries_max = 64, .arena_bytes = 1 << 20 },
            .accepted_bytes = 1 << 20,
        };
    }

    /// A peer's view of Unix time, from its (possibly skewed) local clock.
    fn unix_ns(gossip: *const RealGossip, world: *const World, peer: u8) u64 {
        return gossip.epoch_ns + world.local_ns[peer];
    }

    /// The sequencer signs and publishes the block `envelope` (its executed payload).
    pub fn publish(
        gossip: *RealGossip,
        world: *const World,
        envelope: *const gossip_bridge.Envelope,
    ) void {
        assert(envelope.payload.block_number > 0);
        const service = gossip.peers[0].service orelse return;
        assert(world.up[0]);
        const result = if (gossip_bridge.encode_gossip(
            gossip.rollup,
            envelope,
            gossip.publish_storage,
        )) |payload| service.publish_block(
            sequencer_key,
            envelope.parent_beacon_block_root,
            payload,
            gossip.unix_ns(world, 0),
        ) else |err| err;
        if (result) |_| {
            gossip.stats.published += 1;
        } else |_| {
            gossip.stats.publish_failures += 1;
        }
    }

    /// Whether `peer` graylists the sequencer: its score for the sequencer's connection is
    /// below the graylist threshold, so it ignores every RPC the sequencer sends. One
    /// rejected block does it (P4 weight -140.4475, threshold -40), and base/base's decay
    /// (`score_decay`: to 99% per 600 s) keeps it there for hours. A sequencer that falls
    /// more than 60 s behind and catches up publishes such blocks (`timestamp_past`).
    pub fn graylists_sequencer(gossip: *const RealGossip, peer: u8) bool {
        assert(peer > 0 and peer < gossip.peer_count);
        const service = gossip.peers[peer].service orelse return false;
        for (gossip.pairs[0..gossip.pair_count]) |*pair| {
            if (pair.a != 0 or pair.b != peer or !pair.connected) continue;
            const value = service.gossip.router.peer_score_value(pair.slots[1]);
            return value < score.thresholds.graylist_threshold;
        }
        return false;
    }

    /// Failure diagnosis: per-peer heads and connections, per-service gossip counters.
    pub fn print_state(gossip: *const RealGossip, published: u64) void {
        const stats = &gossip.stats;
        std.debug.print(
            "  real gossip: published={d} (failures {d}, stale {d}) connects={d} " ++
                "resets crash={d} stall={d} overflow={d} requested={d}\n",
            .{
                published,             stats.publish_failures, stats.stale_skipped,
                stats.connects,        stats.resets_crash,     stats.resets_stall,
                stats.resets_overflow, stats.resets_requested,
            },
        );
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            const service = peer.service orelse {
                std.debug.print("    peer {d}: down\n", .{index});
                continue;
            };
            const handler_stats = &service.gossip.stats;
            std.debug.print(
                "    peer {d}: head={d} popped={d} connected={d} restarts={d} " ++
                    "graylists_sequencer={} {any}\n",
                .{
                    index,
                    gossip.head_popped[index],
                    stats.popped[index],
                    service.connected_count(),
                    peer.restarts,
                    index > 0 and gossip.graylists_sequencer(@intCast(index)),
                    handler_stats.*,
                },
            );
        }
    }

    /// Whether a block with `timestamp_s` is already past the gossip age window on the
    /// sequencer's clock, less a margin for delivery latency.
    pub fn stale(gossip: *const RealGossip, world: *const World, timestamp_s: u64) bool {
        const margin_ns = 5 * ns_per_s;
        comptime assert(timestamp_age_max_ns > margin_ns);
        const age_max_ns = timestamp_age_max_ns - margin_ns;
        return timestamp_s * ns_per_s + age_max_ns < gossip.unix_ns(world, 0);
    }

    /// The next validated block `peer` received, valid until the next call.
    pub fn pop_block(gossip: *RealGossip, peer: u8) ?block.Envelope {
        assert(peer > 0 and peer < gossip.peer_count);
        const service = gossip.peers[peer].service orelse return null;
        const envelope = service.pop_block(gossip.pop_scratch) orelse return null;
        gossip.stats.popped[peer] += 1;
        const number = envelope.payload.block_number;
        gossip.head_popped[peer] = @max(gossip.head_popped[peer], number);
        return envelope;
    }

    /// One simulator step: crashes and restarts, service timers, connection lifecycle,
    /// then frames out of every router and into the receiving services.
    pub fn step(gossip: *RealGossip, world: *const World) !void {
        try gossip.step_processes(world);
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            const service = peer.service orelse continue;
            service.tick(gossip.unix_ns(world, @intCast(index)));
        }
        gossip.run_commands(world);
        for (gossip.pairs[0..gossip.pair_count], 0..) |*pair, index| {
            gossip.step_pair(world, pair, @intCast(index));
        }
    }

    fn step_processes(gossip: *RealGossip, world: *const World) !void {
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            const peer_index: u8 = @intCast(index);
            if (!world.up[index]) {
                if (peer.service == null) continue;
                for (gossip.pairs[0..gossip.pair_count]) |*pair| {
                    if (pair.connected and (pair.a == peer_index or pair.b == peer_index)) {
                        gossip.stats.resets_crash += 1;
                        gossip.reset(world, pair);
                    }
                }
                peer.service.?.destroy(gossip.allocator);
                peer.service = null;
                peer.restarts += 1;
                continue;
            }
            if (peer.service != null) continue;
            peer.service = try Service.create(
                gossip.allocator,
                gossip.service_config(),
                peer.secret,
                peer.record,
                peer.prng.random(),
            );
        }
    }

    /// Dials the pairs' `step_pair` started, and disconnects a service requested (invalid
    /// RPCs, bans).
    fn run_commands(gossip: *RealGossip, world: *const World) void {
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            const service = peer.service orelse continue;
            var commands: u32 = 0;
            while (service.pop_command()) |command| : (commands += 1) {
                assert(commands < 1024);
                switch (command) {
                    .dial => |address| gossip.complete_dial(world, @intCast(index), &address),
                    .disconnect => |slot| {
                        const pair = gossip.pair_with_slot(@intCast(index), slot) orelse
                            continue;
                        gossip.stats.resets_requested += 1;
                        gossip.reset(world, pair);
                    },
                }
            }
        }
    }

    fn peer_of(gossip: *const RealGossip, id: *const peer_id.PeerId) ?u8 {
        for (gossip.peers[0..gossip.peer_count], 0..) |*peer, index| {
            if (peer.id.eql(id)) return @intCast(index);
        }
        return null;
    }

    fn complete_dial(
        gossip: *RealGossip,
        world: *const World,
        dialer: u8,
        address: *const multiaddr.Multiaddr,
    ) void {
        const dialer_service = gossip.peers[dialer].service.?;
        const target = gossip.peer_of(&address.peer().?).?; // Proof: only peers are dialed.
        assert(dialer < target);
        const pair = for (gossip.pairs[0..gossip.pair_count]) |*pair| {
            if (pair.a == dialer and pair.b == target) break pair;
        } else unreachable; // Proof: `create` makes one pair for every a < b.
        const ready = world.up[target] and world.linked[dialer][target] and !pair.connected;
        if (!ready or !gossip.connect(world, pair)) {
            dialer_service.on_dial_failed(address);
        }
    }

    fn pair_with_slot(gossip: *RealGossip, peer: u8, slot: Slot) ?*Pair {
        for (gossip.pairs[0..gossip.pair_count]) |*pair| {
            if (!pair.connected) continue;
            if (pair.a == peer and pair.slots[0] == slot) return pair;
            if (pair.b == peer and pair.slots[1] == slot) return pair;
        }
        return null;
    }

    fn step_pair(gossip: *RealGossip, world: *const World, pair: *Pair, index: u8) void {
        const linked = world.linked[pair.a][pair.b];
        assert(linked == world.linked[pair.b][pair.a]);
        if (!pair.connected) {
            if (linked and world.global_ns >= pair.redial_ns) gossip.dial(world, pair);
            return;
        }
        if (!linked) {
            const since = pair.blocked_since_ns orelse world.global_ns;
            pair.blocked_since_ns = since;
            if (world.global_ns - since >= stall_timeout_ns) {
                gossip.stats.resets_stall += 1;
                return gossip.reset(world, pair);
            }
        } else {
            pair.blocked_since_ns = null;
        }
        for (0..2) |direction| {
            if (!gossip.drain(world, pair, index, @intCast(direction))) return;
            if (linked) gossip.deliver(world, pair, index, @intCast(direction));
        }
    }

    /// Starts a dial from `a` to `b`; `complete_dial` finishes it.
    fn dial(gossip: *RealGossip, world: *const World, pair: *Pair) void {
        assert(!pair.connected);
        pair.redial_ns = world.global_ns + redial_delay_ns;
        const dialer = gossip.peers[pair.a].service orelse return;
        if (gossip.peers[pair.b].service == null) return;
        dialer.dial(&gossip.peers[pair.b].multiaddr, gossip.unix_ns(world, pair.a));
    }

    /// The handshake of a dial: false when the listener refuses or a side fails, in which
    /// case the caller fails the dial (the dialer's pending slot is still held).
    fn connect(gossip: *RealGossip, world: *const World, pair: *Pair) bool {
        assert(!pair.connected);
        const dialer = gossip.peers[pair.a].service.?;
        const listener = gossip.peers[pair.b].service.?;
        const address_a = gossip.peers[pair.a].address;
        const address_b = gossip.peers[pair.b].address;
        if (!listener.reserve_inbound(address_a)) return false;
        const now_b = gossip.unix_ns(world, pair.b);
        const id_a = gossip.peers[pair.a].id;
        const slot_b = listener.on_connected(id_a, .inbound, address_a, now_b) catch
            return false;
        const now_a = gossip.unix_ns(world, pair.a);
        const id_b = gossip.peers[pair.b].id;
        const slot_a = dialer.on_connected(id_b, .outbound, address_b, now_a) catch {
            listener.on_disconnected(slot_b, now_b);
            return true; // The dialer released its pending slot itself.
        };
        pair.* = .{
            .a = pair.a,
            .b = pair.b,
            .connected = true,
            .slots = .{ slot_a, slot_b },
            .redial_ns = pair.redial_ns,
            .connects = pair.connects + 1,
            .first_connect_ns = pair.first_connect_ns orelse world.global_ns,
        };
        gossip.stats.connects += 1;
        return true;
    }

    /// Closes the connection on every side still running and drops what was in flight.
    fn reset(gossip: *RealGossip, world: *const World, pair: *Pair) void {
        assert(pair.connected);
        const ends = [2]u8{ pair.a, pair.b };
        for (ends, 0..) |peer, side| {
            const service = gossip.peers[peer].service orelse continue;
            service.on_disconnected(pair.slots[side], gossip.unix_ns(world, peer));
        }
        pair.connected = false;
        pair.blocked_since_ns = null;
        pair.queues = .{ .{}, .{} };
        pair.redial_ns = world.global_ns + redial_delay_ns;
    }

    fn ring(gossip: *RealGossip, index: u8, direction: u1) []u8 {
        const at = (@as(usize, index) * 2 + direction) * queue_bytes;
        return gossip.bytes[at..][0..queue_bytes];
    }

    /// Moves the sender's pending RPCs into the connection. False after a reset.
    fn drain(gossip: *RealGossip, world: *const World, pair: *Pair, index: u8, direction: u1) bool {
        const from = if (direction == 0) pair.a else pair.b;
        const service = gossip.peers[from].service.?;
        const queue = &pair.queues[direction];
        var frames: u32 = 0;
        while (frames < frames_per_step_max) : (frames += 1) {
            const framed = service.drain_gossip(pair.slots[direction], gossip.drain_buffer) orelse
                break;
            const frame = (rpc.frame_decode(framed, rpc.frame_size_max_default) catch
                unreachable).?; // Proof: the router just encoded one whole frame.
            var deliver_ns = world.global_ns + gossip.prng.range(
                gossip.latency_ns_min,
                gossip.latency_ns_max,
            );
            if (gossip.prng.chance(gossip.drop_ppm, 1_000_000)) deliver_ns += retransmit_ns;
            deliver_ns = @max(deliver_ns, queue.last_deliver_ns);
            if (!queue.push(gossip.ring(index, direction), frame.payload, deliver_ns)) {
                gossip.stats.resets_overflow += 1;
                gossip.reset(world, pair);
                return false;
            }
            gossip.stats.frames_sent += 1;
        }
        return true;
    }

    fn deliver(
        gossip: *RealGossip,
        world: *const World,
        pair: *Pair,
        index: u8,
        direction: u1,
    ) void {
        const to: u8 = if (direction == 0) pair.b else pair.a;
        const slot = pair.slots[1 - @as(u8, direction)];
        const service = gossip.peers[to].service.?;
        const queue = &pair.queues[direction];
        const bytes = gossip.ring(index, direction);
        while (queue.oldest()) |frame| {
            if (frame.deliver_ns > world.global_ns) break;
            service.on_gossip_frame(slot, queue.slice(bytes, frame), gossip.unix_ns(world, to));
            queue.pop();
            gossip.stats.frames_delivered += 1;
        }
    }
};

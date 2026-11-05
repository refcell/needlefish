//! IO-free gossipsub v1.1 router: mesh maintenance, IHAVE/IWANT gossip, message
//! forwarding after application validation, and peer scoring. Mirrors the libp2p
//! gossipsub behaviour base/base configures (`gossip/src/config.rs`): D=8, Dlo=6,
//! Dhi=12, Dlazy=6, 500 ms heartbeat, mcache 12/3, seen TTL 65 s, flood publish off,
//! anonymous messages (no from/seqno/signature), `validate_messages` mode.
//!
//! Inputs: `add_peer`, `remove_peer`, `on_rpc` (one decoded stream frame), `publish`,
//! `validate`, `heartbeat`. Outputs: `pop_event` (messages awaiting validation) and
//! `drain(peer, buffer)`, which encodes the next framed RPC for a peer into a caller
//! buffer: the transport pulls when the stream is writable, giving backpressure for free.
//! Peers are slots `0..peers_max`; peer sets are `u64` bitsets.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("rpc.zig");
const seen_cache = @import("seen.zig");
const mcache = @import("mcache.zig");
const peer_score = @import("peer_score.zig");
const score = @import("../peers/score.zig");
const peer_id = @import("../peers/peer_id.zig");
const ip = @import("../peers/ip.zig");

pub const Id = seen_cache.Id;
pub const peers_max = 64;
pub const topics_max = peer_score.topics_max;
pub const topic_length_max = 128;
pub const PeerSet = u64;
pub const Slot = u8;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

/// Computes a message id; `context` is `Config.message_id_context` (e.g. scratch space).
pub const MessageIdFn = *const fn (
    context: ?*anyopaque,
    topic: []const u8,
    data: []const u8,
) Id;

pub const Config = struct {
    d: u32 = 8,
    d_low: u32 = 6,
    d_high: u32 = 12,
    d_lazy: u32 = 6,
    d_score: u32 = 4,
    /// Outbound peers kept in each mesh (libp2p `mesh_outbound_min`).
    d_out: u32 = 2,
    heartbeat_interval_ns: u64 = 500 * ns_per_ms,
    seen_ttl_ns: u64 = 130 * 500 * ns_per_ms,
    prune_backoff_ns: u64 = 60 * ns_per_s,
    graft_flood_threshold_ns: u64 = 10 * ns_per_s,
    iwant_followup_ns: u64 = 3 * ns_per_s,
    mesh_delivery_window_ns: u64 = 2 * ns_per_s,
    /// IHAVE messages accepted per peer per heartbeat (libp2p `max_ihave_messages`).
    ihave_messages_max: u32 = 10,
    opportunistic_graft_ticks: u32 = 60,
    opportunistic_graft_peers: u32 = 2,
    message_size_max: u32 = 10 * (1 << 20),
    message_id: MessageIdFn,
    message_id_context: ?*anyopaque = null,
    thresholds: score.Thresholds = score.thresholds,
    /// Null disables scoring (every peer scores 0).
    peer_params: ?score.PeerParams = null,
    mcache: mcache.Config = .{},
};

pub const Validation = enum { accept, reject, ignore };

pub const Event = struct {
    id: Id,
    topic: u8,
    source: Slot,
};

const queue_max = 256;
const ihave_out_max = 64;
const iwant_out_max = 64;
const promises_max = 32;
const deliveries_max = 1024;
const events_max = 256;
const no_source: Slot = std.math.maxInt(Slot);

const Promise = struct { id: Id, deadline_ns: u64 };

const Retained = struct {
    used: bool = false,
    id: peer_id.PeerId = undefined,
    counters: peer_score.Counters = .{},
    expires_ns: u64 = 0,
};

const Peer = struct {
    active: bool = false,
    id: peer_id.PeerId = undefined,
    outbound: bool = false,
    address: ?ip.Address = null,
    topics: u8 = 0,
    counters: peer_score.Counters = .{},
    score: f64 = 0,
    backoff_until_ns: [topics_max]u64 = @splat(0),
    ihave_received: u32 = 0,
    promises: [promises_max]Promise = undefined,
    promises_count: u32 = 0,
    send_subscriptions: bool = false,
    graft_pending: u8 = 0,
    prune_pending: u8 = 0,
    ihave: [ihave_out_max]Id = undefined,
    ihave_topic: [ihave_out_max]u8 = undefined,
    ihave_count: u32 = 0,
    iwant: [iwant_out_max]Id = undefined,
    iwant_count: u32 = 0,
    queue: [queue_max]Id = undefined,
    queue_head: u32 = 0,
    queue_count: u32 = 0,
    dropped: u64 = 0,

    fn has_output(peer: *const Peer) bool {
        return peer.send_subscriptions or peer.graft_pending != 0 or
            peer.prune_pending != 0 or peer.ihave_count > 0 or peer.iwant_count > 0 or
            peer.queue_count > 0;
    }

    fn enqueue(peer: *Peer, id: *const Id) void {
        if (peer.queue_count == queue_max) {
            // Slow peer: drop the oldest queued message.
            peer.queue_head = (peer.queue_head + 1) % queue_max;
            peer.queue_count -= 1;
            peer.dropped += 1;
        }
        peer.queue[(peer.queue_head + peer.queue_count) % queue_max] = id.*;
        peer.queue_count += 1;
        assert(peer.queue_count <= queue_max);
    }
};

const DeliveryState = enum(u8) { pending, valid, invalid, ignored };

const Delivery = struct {
    id: Id,
    topic: u8,
    state: DeliveryState,
    source: Slot,
    first_ns: u64,
    /// Peers that delivered (or were sent) this message.
    peers: PeerSet,
};

const Topic = struct {
    name: [topic_length_max]u8 = undefined,
    length: u8 = 0,
    subscribed: bool = false,

    fn slice(topic: *const Topic) []const u8 {
        return topic.name[0..topic.length];
    }
};

const Rpc = rpc.RpcDefault;
const limits: rpc.Limits = .{};

pub const Router = struct {
    config: Config,
    random: std.Random,
    peers: []Peer,
    topics: [topics_max]Topic = @splat(.{}),
    topics_count: u8 = 0,
    mesh: [topics_max]PeerSet = @splat(0),
    seen: *seen_cache.SeenCache(8192),
    cache: mcache.Cache,
    deliveries: []Delivery,
    deliveries_head: u32 = 0,
    deliveries_count: u32 = 0,
    events: [events_max]Event = undefined,
    events_head: u32 = 0,
    events_count: u32 = 0,
    scratch: *Rpc,
    id_slices: *[limits.message_ids_max][]const u8,
    heartbeats: u64 = 0,
    last_decay_ns: u64 = 0,
    retained: [peers_max]Retained = @splat(.{}),

    pub fn init(allocator: std.mem.Allocator, config: Config, random: std.Random) !Router {
        assert(config.d_low <= config.d and config.d <= config.d_high);
        assert(config.d_high < peers_max and config.d_score <= config.d);
        assert(config.d_out <= config.d / 2);
        const peers = try allocator.alloc(Peer, peers_max);
        errdefer allocator.free(peers);
        @memset(peers, .{});
        const seen = try allocator.create(seen_cache.SeenCache(8192));
        errdefer allocator.destroy(seen);
        seen.* = .{};
        var cache = try mcache.Cache.init(allocator, config.mcache);
        errdefer cache.deinit(allocator);
        const deliveries = try allocator.alloc(Delivery, deliveries_max);
        errdefer allocator.free(deliveries);
        const scratch = try allocator.create(Rpc);
        errdefer allocator.destroy(scratch);
        scratch.reset();
        const id_slices = try allocator.create([limits.message_ids_max][]const u8);
        return .{
            .config = config,
            .random = random,
            .peers = peers,
            .seen = seen,
            .cache = cache,
            .deliveries = deliveries,
            .scratch = scratch,
            .id_slices = id_slices,
        };
    }

    pub fn deinit(router: *Router, allocator: std.mem.Allocator) void {
        allocator.destroy(router.id_slices);
        allocator.destroy(router.scratch);
        allocator.free(router.deliveries);
        router.cache.deinit(allocator);
        allocator.destroy(router.seen);
        allocator.free(router.peers);
        router.* = undefined;
    }

    // Topics.

    pub fn topic_index(router: *const Router, name: []const u8) ?u8 {
        for (router.topics[0..router.topics_count], 0..) |*topic, index| {
            if (std.mem.eql(u8, topic.slice(), name)) return @intCast(index);
        }
        return null;
    }

    pub fn topic_name(router: *const Router, topic: u8) []const u8 {
        assert(topic < router.topics_count);
        return router.topics[topic].slice();
    }

    /// Subscribes to `name`; the mesh forms at the next heartbeat.
    pub fn subscribe(router: *Router, name: []const u8) error{TooManyTopics}!u8 {
        assert(name.len > 0 and name.len <= topic_length_max);
        const index = router.topic_index(name) orelse blk: {
            if (router.topics_count == topics_max) return error.TooManyTopics;
            const topic = &router.topics[router.topics_count];
            @memcpy(topic.name[0..name.len], name);
            topic.length = @intCast(name.len);
            router.topics_count += 1;
            break :blk router.topics_count - 1;
        };
        router.topics[index].subscribed = true;
        for (router.peers) |*target| {
            if (target.active) target.send_subscriptions = true;
        }
        return index;
    }

    // Peers.

    /// Adds a connected peer. A peer that reconnects within `retain_score` gets its old
    /// score counters back, so disconnecting does not launder a bad score.
    pub fn add_peer(
        router: *Router,
        id: peer_id.PeerId,
        outbound: bool,
        address: ?ip.Address,
        now_ns: u64,
    ) ?Slot {
        const slot = for (router.peers, 0..) |*candidate, index| {
            if (!candidate.active) break index;
        } else return null;
        const target = &router.peers[slot];
        target.* = .{ .active = true, .id = id, .outbound = outbound, .address = address };
        // `retain` copied the counters after leaving every mesh.
        target.send_subscriptions = router.subscribed_count() > 0;
        for (&router.retained) |*retained| {
            if (!retained.used or !retained.id.eql(&id)) continue;
            retained.used = false;
            if (now_ns < retained.expires_ns) target.counters = retained.counters;
        }
        for (&target.counters.topics) |*counter| assert(!counter.in_mesh);
        assert(target.queue_count == 0);
        return @intCast(slot);
    }

    pub fn remove_peer(router: *Router, slot: Slot, now_ns: u64) void {
        const target = router.peer(slot);
        var topic: u8 = 0;
        while (topic < router.topics_count) : (topic += 1) {
            if (in_set(router.mesh[topic], slot)) router.mesh_remove(slot, topic);
        }
        for (router.deliveries_slice_mut()) |*delivery| delivery.peers &= ~bit(slot);
        if (router.config.peer_params) |params| {
            router.retain(target, now_ns + params.retain_score_ns);
        }
        target.* = .{};
        assert(!target.active);
    }

    /// Keeps a departed peer's counters; when full, replaces the soonest-expiring entry.
    fn retain(router: *Router, target: *const Peer, expires_ns: u64) void {
        var victim: usize = 0;
        for (&router.retained, 0..) |*retained, index| {
            if (!retained.used) {
                victim = index;
                break;
            }
            if (retained.expires_ns < router.retained[victim].expires_ns) victim = index;
        }
        router.retained[victim] = .{
            .used = true,
            .id = target.id,
            .counters = target.counters,
            .expires_ns = expires_ns,
        };
        assert(router.retained[victim].used);
    }

    pub fn peer(router: *const Router, slot: Slot) *Peer {
        assert(slot < peers_max);
        assert(router.peers[slot].active);
        return &router.peers[slot];
    }

    pub fn peer_score_value(router: *const Router, slot: Slot) f64 {
        return router.peer(slot).score;
    }

    pub fn mesh_peers(router: *const Router, topic: u8) PeerSet {
        assert(topic < router.topics_count);
        return router.mesh[topic];
    }

    pub fn has_output(router: *const Router, slot: Slot) bool {
        return router.peer(slot).has_output();
    }

    pub fn pop_event(router: *Router) ?Event {
        if (router.events_count == 0) return null;
        const event = router.events[router.events_head];
        router.events_head = (router.events_head + 1) % events_max;
        router.events_count -= 1;
        return event;
    }

    /// Payload of a message announced by an event, while it is cached.
    pub fn message_data(router: *const Router, id: *const Id) ?[]const u8 {
        const entry = router.cache.find(id) orelse return null;
        return router.cache.data(entry);
    }

    fn subscribed_count(router: *const Router) u32 {
        var count: u32 = 0;
        for (router.topics[0..router.topics_count]) |topic| count += @intFromBool(topic.subscribed);
        return count;
    }

    fn mesh_add(router: *Router, slot: Slot, topic: u8, now_ns: u64) void {
        assert(!in_set(router.mesh[topic], slot));
        router.mesh[topic] |= bit(slot);
        router.peer(slot).counters.graft(topic, now_ns);
    }

    fn mesh_remove(router: *Router, slot: Slot, topic: u8) void {
        assert(in_set(router.mesh[topic], slot));
        router.mesh[topic] &= ~bit(slot);
        const counters = &router.peer(slot).counters;
        if (router.config.peer_params) |params| {
            if (params.topic) |*params_topic| {
                counters.prune(params_topic, topic);
                return;
            }
        }
        counters.topics[topic].in_mesh = false;
    }

    fn prune_peer(router: *Router, slot: Slot, topic: u8, now_ns: u64) void {
        if (in_set(router.mesh[topic], slot)) router.mesh_remove(slot, topic);
        const target = router.peer(slot);
        target.backoff_until_ns[topic] = now_ns + router.config.prune_backoff_ns;
        target.prune_pending |= @as(u8, 1) << @intCast(topic);
        target.graft_pending &= ~(@as(u8, 1) << @intCast(topic));
    }

    fn graft_peer(router: *Router, slot: Slot, topic: u8, now_ns: u64) void {
        router.mesh_add(slot, topic, now_ns);
        const target = router.peer(slot);
        target.graft_pending |= @as(u8, 1) << @intCast(topic);
        target.prune_pending &= ~(@as(u8, 1) << @intCast(topic));
    }

    fn deliveries_slice_mut(router: *Router) []Delivery {
        // The ring is only scanned as a whole, so order does not matter here.
        return router.deliveries[0..router.deliveries_count];
    }

    fn find_delivery(router: *Router, id: *const Id) ?*Delivery {
        for (router.deliveries_slice_mut()) |*delivery| {
            if (std.mem.eql(u8, &delivery.id, id)) return delivery;
        }
        return null;
    }

    fn add_delivery(router: *Router, delivery: Delivery) void {
        if (router.deliveries_count < deliveries_max) {
            router.deliveries[router.deliveries_count] = delivery;
            router.deliveries_count += 1;
            return;
        }
        // Full: overwrite the oldest (slots are reused round robin).
        router.deliveries[router.deliveries_head] = delivery;
        router.deliveries_head = (router.deliveries_head + 1) % deliveries_max;
    }

    fn push_event(router: *Router, event: Event) bool {
        if (router.events_count == events_max) return false;
        router.events[(router.events_head + router.events_count) % events_max] = event;
        router.events_count += 1;
        return true;
    }

    fn topic_params(router: *const Router) ?*const score.TopicParams {
        if (router.config.peer_params) |*params| {
            if (params.topic) |*topic| return topic;
        }
        return null;
    }

    // Inbound RPCs.

    pub const RpcError = error{ InvalidRpc, Graylisted };

    pub fn on_rpc(router: *Router, slot: Slot, frame: []const u8, now_ns: u64) RpcError!void {
        const source = router.peer(slot);
        if (source.score < router.config.thresholds.graylist_threshold) return error.Graylisted;
        router.scratch.decode(frame) catch return error.InvalidRpc;
        const message = router.scratch;
        for (message.subscriptions_slice()) |sub_opts| router.on_subscription(slot, sub_opts);
        for (message.publish_slice()) |published| router.on_message(slot, published, now_ns);
        for (message.graft_slice()) |graft| router.on_graft(slot, graft.topic_id, now_ns);
        for (message.prune_slice()) |prune| router.on_prune(slot, prune, now_ns);
        for (message.ihave_slice()) |ihave| router.on_ihave(slot, ihave, now_ns);
        for (message.iwant_slice()) |iwant| router.on_iwant(slot, message.ids(iwant.message_ids));
        assert(router.peer(slot).active);
    }

    fn on_subscription(router: *Router, slot: Slot, sub_opts: rpc.SubOpts) void {
        const name = sub_opts.topic_id orelse return;
        const topic = router.topic_index(name) orelse return;
        const target = router.peer(slot);
        const mask = @as(u8, 1) << @intCast(topic);
        if (sub_opts.subscribe orelse false) {
            target.topics |= mask;
        } else {
            target.topics &= ~mask;
            if (in_set(router.mesh[topic], slot)) router.mesh_remove(slot, topic);
        }
    }

    fn on_message(router: *Router, slot: Slot, message: rpc.Message, now_ns: u64) void {
        const name = message.topic orelse return;
        const topic = router.topic_index(name) orelse return;
        if (!router.topics[topic].subscribed) return;
        const data = message.data orelse &.{};
        if (data.len > router.config.message_size_max) return;
        const id = router.config.message_id(router.config.message_id_context, name, data);
        if (!router.seen.insert(&id, now_ns)) return router.on_duplicate(slot, &id, now_ns);
        router.fulfil_promises(&id);
        _ = router.cache.put(&id, topic, data, false) orelse return;
        router.add_delivery(.{
            .id = id,
            .topic = topic,
            .state = .pending,
            .source = slot,
            .first_ns = now_ns,
            .peers = bit(slot),
        });
        if (!router.push_event(.{ .id = id, .topic = topic, .source = slot })) {
            // Validation queue full: treat as ignored (no penalty), like a throttled drop.
            router.validate(&id, .ignore);
        }
    }

    fn on_duplicate(router: *Router, slot: Slot, id: *const Id, now_ns: u64) void {
        const delivery = router.find_delivery(id) orelse return;
        if (in_set(delivery.peers, slot)) return;
        delivery.peers |= bit(slot);
        const counters = &router.peer(slot).counters;
        switch (delivery.state) {
            .valid => if (now_ns -| delivery.first_ns <= router.config.mesh_delivery_window_ns) {
                if (router.topic_params()) |params| counters.mesh_delivery(params, delivery.topic);
            },
            .invalid => counters.invalid_delivery(delivery.topic),
            // Pending deliveries are credited when validation completes.
            .pending, .ignored => {},
        }
    }

    fn fulfil_promises(router: *Router, id: *const Id) void {
        for (router.peers) |*target| {
            if (!target.active) continue;
            var index: u32 = 0;
            while (index < target.promises_count) {
                if (std.mem.eql(u8, &target.promises[index].id, id)) {
                    target.promises_count -= 1;
                    target.promises[index] = target.promises[target.promises_count];
                } else index += 1;
            }
        }
    }

    fn on_graft(router: *Router, slot: Slot, topic_id: ?[]const u8, now_ns: u64) void {
        const topic = router.topic_index(topic_id orelse return) orelse return;
        if (in_set(router.mesh[topic], slot)) return;
        const target = router.peer(slot);
        if (!router.topics[topic].subscribed) return router.prune_peer(slot, topic, now_ns);
        if (now_ns < target.backoff_until_ns[topic]) {
            // GRAFT during backoff is a protocol violation; flooding it is worse.
            target.counters.behaviour_penalty += 1;
            const flood_end = target.backoff_until_ns[topic] -| router.config.prune_backoff_ns +
                router.config.graft_flood_threshold_ns;
            if (now_ns < flood_end) target.counters.behaviour_penalty += 1;
            return router.prune_peer(slot, topic, now_ns);
        }
        if (target.score < 0) return router.prune_peer(slot, topic, now_ns);
        if (@popCount(router.mesh[topic]) >= router.config.d_high and !target.outbound) {
            return router.prune_peer(slot, topic, now_ns);
        }
        router.mesh_add(slot, topic, now_ns);
    }

    fn on_prune(router: *Router, slot: Slot, prune: rpc.Prune, now_ns: u64) void {
        const topic = router.topic_index(prune.topic_id orelse return) orelse return;
        if (in_set(router.mesh[topic], slot)) router.mesh_remove(slot, topic);
        const backoff_ns = if (prune.backoff) |seconds|
            std.math.mul(u64, @min(seconds, 3600), ns_per_s) catch unreachable
        else
            router.config.prune_backoff_ns;
        const target = router.peer(slot);
        target.backoff_until_ns[topic] = @max(target.backoff_until_ns[topic], now_ns + backoff_ns);
    }

    fn on_ihave(router: *Router, slot: Slot, ihave: rpc.IHave, now_ns: u64) void {
        const target = router.peer(slot);
        if (target.score < router.config.thresholds.gossip_threshold) return;
        const topic = router.topic_index(ihave.topic_id orelse return) orelse return;
        if (!router.topics[topic].subscribed) return;
        target.ihave_received += 1;
        if (target.ihave_received > router.config.ihave_messages_max) return;
        const first_new = target.iwant_count;
        for (router.scratch.ids(ihave.message_ids)) |raw| {
            if (target.iwant_count == iwant_out_max) break;
            if (raw.len != seen_cache.id_length) continue;
            const id: *const Id = raw[0..seen_cache.id_length];
            if (router.seen.contains(id)) continue;
            target.iwant[target.iwant_count] = id.*;
            target.iwant_count += 1;
        }
        // Like libp2p, track one promise per IHAVE, for a random requested id.
        if (target.iwant_count == first_new or target.promises_count == promises_max) return;
        const pick = first_new + router.random.uintLessThan(u32, target.iwant_count - first_new);
        target.promises[target.promises_count] = .{
            .id = target.iwant[pick],
            .deadline_ns = now_ns + router.config.iwant_followup_ns,
        };
        target.promises_count += 1;
    }

    fn on_iwant(router: *Router, slot: Slot, ids: []const []const u8) void {
        const target = router.peer(slot);
        if (target.score < router.config.thresholds.gossip_threshold) return;
        for (ids) |raw| {
            if (raw.len != seen_cache.id_length) continue;
            const id: *const Id = raw[0..seen_cache.id_length];
            const entry = router.cache.find(id) orelse continue;
            if (!entry.validated) continue;
            // Retransmission limit 1: never send a peer a message it sent us or got.
            const delivery = router.find_delivery(id) orelse continue;
            if (in_set(delivery.peers, slot)) continue;
            delivery.peers |= bit(slot);
            target.enqueue(id);
        }
    }

    // Validation and publishing.

    /// Reports the application's verdict on a message from `pop_event`.
    pub fn validate(router: *Router, id: *const Id, result: Validation) void {
        const delivery = router.find_delivery(id) orelse return;
        if (delivery.state != .pending) return;
        const entry = router.cache.find(id);
        switch (result) {
            .accept => {
                delivery.state = .valid;
                if (entry) |cached| cached.validated = true;
                router.credit_deliveries(delivery);
                router.forward(delivery);
            },
            .reject => {
                delivery.state = .invalid;
                if (entry) |cached| router.cache.forget(cached);
                router.penalize_deliveries(delivery);
            },
            .ignore => {
                delivery.state = .ignored;
                if (entry) |cached| router.cache.forget(cached);
            },
        }
        assert(delivery.state != .pending);
    }

    fn credit_deliveries(router: *Router, delivery: *const Delivery) void {
        const params = router.topic_params() orelse return;
        var peers = delivery.peers;
        while (peers != 0) : (peers &= peers - 1) {
            const slot: Slot = @intCast(@ctz(peers));
            const counters = &router.peer(slot).counters;
            if (slot == delivery.source) {
                counters.first_delivery(params, delivery.topic);
            } else {
                counters.mesh_delivery(params, delivery.topic);
            }
        }
    }

    fn penalize_deliveries(router: *Router, delivery: *const Delivery) void {
        var peers = delivery.peers;
        while (peers != 0) : (peers &= peers - 1) {
            const slot: Slot = @intCast(@ctz(peers));
            router.peer(slot).counters.invalid_delivery(delivery.topic);
        }
    }

    fn forward(router: *Router, delivery: *Delivery) void {
        var targets = router.mesh[delivery.topic] & ~delivery.peers;
        delivery.peers |= targets;
        while (targets != 0) : (targets &= targets - 1) {
            router.peers[@ctz(targets)].enqueue(&delivery.id);
        }
    }

    pub const PublishError = error{ NotSubscribed, Duplicate, TooLarge, CacheFull };

    /// Publishes a locally produced message (already validated by the producer).
    pub fn publish(router: *Router, topic: u8, data: []const u8, now_ns: u64) PublishError!Id {
        assert(topic < router.topics_count);
        if (!router.topics[topic].subscribed) return error.NotSubscribed;
        if (data.len > router.config.message_size_max) return error.TooLarge;
        const name = router.topics[topic].slice();
        const id = router.config.message_id(router.config.message_id_context, name, data);
        if (!router.seen.insert(&id, now_ns)) return error.Duplicate;
        _ = router.cache.put(&id, topic, data, true) orelse return error.CacheFull;
        var delivery: Delivery = .{
            .id = id,
            .topic = topic,
            .state = .valid,
            .source = no_source,
            .first_ns = now_ns,
            .peers = 0,
        };
        // Without a mesh (e.g. right after joining), send to up to D topic peers.
        if (router.mesh[topic] == 0) {
            const threshold = router.config.thresholds.publish_threshold;
            const eligible = router.candidates(topic, threshold);
            delivery.peers = router.pick_random(eligible, router.config.d);
            var targets = delivery.peers;
            while (targets != 0) : (targets &= targets - 1) {
                router.peers[@ctz(targets)].enqueue(&id);
            }
        }
        router.forward(&delivery);
        router.add_delivery(delivery);
        return id;
    }

    /// Active peers subscribed to `topic` with score >= `threshold`.
    fn candidates(router: *const Router, topic: u8, threshold: f64) PeerSet {
        var set: PeerSet = 0;
        for (router.peers, 0..) |*target, slot| {
            if (!target.active or target.topics & (@as(u8, 1) << @intCast(topic)) == 0) continue;
            if (target.score < threshold) continue;
            set |= bit(@intCast(slot));
        }
        return set;
    }

    /// A uniformly random subset of `set` with at most `count` members.
    fn pick_random(router: *Router, set: PeerSet, count: u32) PeerSet {
        var remaining = set;
        var result: PeerSet = 0;
        var picked: u32 = 0;
        while (remaining != 0 and picked < count) : (picked += 1) {
            const choice = router.random.uintLessThan(u32, @popCount(remaining));
            const slot = nth_bit(remaining, choice);
            result |= bit(slot);
            remaining &= ~bit(slot);
        }
        assert(@popCount(result) <= count);
        return result;
    }

    // Heartbeat.

    pub fn heartbeat(router: *Router, now_ns: u64) void {
        router.heartbeats += 1;
        router.update_scores(now_ns);
        router.expire_promises(now_ns);
        var topic: u8 = 0;
        while (topic < router.topics_count) : (topic += 1) {
            if (!router.topics[topic].subscribed) continue;
            router.maintain_mesh(topic, now_ns);
            router.emit_gossip(topic);
        }
        for (router.peers) |*target| target.ihave_received = 0;
        router.cache.shift();
        router.seen.expire(now_ns, router.config.seen_ttl_ns);
        router.check_invariants();
    }

    fn update_scores(router: *Router, now_ns: u64) void {
        const params = router.config.peer_params orelse return;
        const decay_due = now_ns -| router.last_decay_ns >= params.decay_interval_ns;
        if (decay_due) router.last_decay_ns = now_ns;
        for (router.peers) |*target| {
            if (!target.active) continue;
            if (decay_due) target.counters.decay(&params, now_ns);
            const colocated = router.peers_on_address(target.address);
            target.score = target.counters.compute(&params, colocated, now_ns);
        }
    }

    fn peers_on_address(router: *const Router, address: ?ip.Address) u32 {
        const wanted = address orelse return 1;
        var count: u32 = 0;
        for (router.peers) |*target| {
            if (!target.active) continue;
            const other = target.address orelse continue;
            if (std.meta.eql(other, wanted)) count += 1;
        }
        assert(count >= 1);
        return count;
    }

    fn expire_promises(router: *Router, now_ns: u64) void {
        for (router.peers) |*target| {
            if (!target.active) continue;
            var index: u32 = 0;
            while (index < target.promises_count) {
                if (now_ns >= target.promises[index].deadline_ns) {
                    target.counters.behaviour_penalty += 1;
                    target.promises_count -= 1;
                    target.promises[index] = target.promises[target.promises_count];
                } else index += 1;
            }
        }
    }

    fn maintain_mesh(router: *Router, topic: u8, now_ns: u64) void {
        const config = &router.config;
        var mesh = router.mesh[topic];
        while (mesh != 0) : (mesh &= mesh - 1) {
            const slot: Slot = @intCast(@ctz(mesh));
            if (router.peers[slot].score < 0) router.prune_peer(slot, topic, now_ns);
        }
        const size = @popCount(router.mesh[topic]);
        if (size < config.d_low) {
            const available = router.graftable(topic, now_ns, 0);
            var picked = router.pick_random(available, config.d - size);
            while (picked != 0) : (picked &= picked - 1) {
                router.graft_peer(@intCast(@ctz(picked)), topic, now_ns);
            }
        } else if (size > config.d_high) {
            router.trim_mesh(topic, now_ns);
        }
        router.ensure_outbound_quota(topic, now_ns);
        if (router.heartbeats % config.opportunistic_graft_ticks == 0) {
            router.opportunistic_graft(topic, now_ns);
        }
        assert(router.mesh[topic] & ~router.active_set() == 0);
    }

    fn outbound_set(router: *const Router) PeerSet {
        var set: PeerSet = 0;
        for (router.peers, 0..) |*target, slot| {
            if (target.active and target.outbound) set |= bit(@intCast(slot));
        }
        return set;
    }

    fn active_set(router: *const Router) PeerSet {
        var set: PeerSet = 0;
        for (router.peers, 0..) |*target, slot| {
            if (target.active) set |= bit(@intCast(slot));
        }
        return set;
    }

    /// Grafts outbound peers until the mesh holds at least `d_out` of them (an attacker
    /// controls who dials us, not whom we dial).
    fn ensure_outbound_quota(router: *Router, topic: u8, now_ns: u64) void {
        const outbound = router.outbound_set();
        const have = @popCount(router.mesh[topic] & outbound);
        if (@popCount(router.mesh[topic]) < router.config.d_low) return;
        if (have >= router.config.d_out) return;
        const available = router.graftable(topic, now_ns, 0) & outbound;
        var picked = router.pick_random(available, router.config.d_out - have);
        while (picked != 0) : (picked &= picked - 1) {
            router.graft_peer(@intCast(@ctz(picked)), topic, now_ns);
        }
    }

    /// Topic peers not in the mesh, out of backoff, with score >= `threshold`.
    fn graftable(router: *const Router, topic: u8, now_ns: u64, threshold: f64) PeerSet {
        var set = router.candidates(topic, threshold) & ~router.mesh[topic];
        var scan = set;
        while (scan != 0) : (scan &= scan - 1) {
            const slot: Slot = @intCast(@ctz(scan));
            if (now_ns < router.peers[slot].backoff_until_ns[topic]) set &= ~bit(slot);
        }
        return set;
    }

    /// Keeps the `d_score` best-scoring peers plus random others up to D; prunes the rest.
    fn trim_mesh(router: *Router, topic: u8, now_ns: u64) void {
        var keep: PeerSet = 0;
        var round: u32 = 0;
        while (round < router.config.d_score) : (round += 1) {
            keep |= router.best_peer(router.mesh[topic] & ~keep) orelse break;
        }
        const others = router.mesh[topic] & ~keep;
        keep |= router.pick_random(others, router.config.d - @popCount(keep));
        keep = router.swap_in_outbound(topic, keep);
        var prune = router.mesh[topic] & ~keep;
        while (prune != 0) : (prune &= prune - 1) {
            router.prune_peer(@intCast(@ctz(prune)), topic, now_ns);
        }
        assert(@popCount(router.mesh[topic]) == router.config.d);
    }

    /// Replaces random inbound members of `keep` with outbound mesh peers until `keep`
    /// holds `d_out` outbound peers (or no outbound peer is left).
    fn swap_in_outbound(router: *Router, topic: u8, keep: PeerSet) PeerSet {
        const outbound = router.outbound_set();
        const have = @popCount(keep & outbound);
        if (have >= router.config.d_out) return keep;
        const wanted = router.config.d_out - have;
        const added = router.pick_random(router.mesh[topic] & outbound & ~keep, wanted);
        const removed = router.pick_random(keep & ~outbound, @popCount(added));
        assert(@popCount(removed) == @popCount(added));
        return (keep & ~removed) | added;
    }

    fn best_peer(router: *const Router, set: PeerSet) ?PeerSet {
        if (set == 0) return null;
        var best: Slot = @intCast(@ctz(set));
        var scan = set;
        while (scan != 0) : (scan &= scan - 1) {
            const slot: Slot = @intCast(@ctz(scan));
            if (router.peers[slot].score > router.peers[best].score) best = slot;
        }
        return bit(best);
    }

    fn opportunistic_graft(router: *Router, topic: u8, now_ns: u64) void {
        const mesh = router.mesh[topic];
        if (@popCount(mesh) < 2) return;
        const median = router.median_score(mesh);
        if (median >= router.config.thresholds.opportunistic_graft_threshold) return;
        const above = router.graftable(topic, now_ns, median) & ~router.below_or_equal(median);
        var picked = router.pick_random(above, router.config.opportunistic_graft_peers);
        while (picked != 0) : (picked &= picked - 1) {
            router.graft_peer(@intCast(@ctz(picked)), topic, now_ns);
        }
    }

    fn below_or_equal(router: *const Router, value: f64) PeerSet {
        var set: PeerSet = 0;
        for (router.peers, 0..) |*target, slot| {
            if (target.active and target.score <= value) set |= bit(@intCast(slot));
        }
        return set;
    }

    fn median_score(router: *const Router, set: PeerSet) f64 {
        var scores: [peers_max]f64 = undefined;
        var count: usize = 0;
        var scan = set;
        while (scan != 0) : (scan &= scan - 1) {
            scores[count] = router.peers[@ctz(scan)].score;
            count += 1;
        }
        assert(count > 0);
        std.sort.pdq(f64, scores[0..count], {}, std.sort.asc(f64));
        return scores[count / 2];
    }

    fn emit_gossip(router: *Router, topic: u8) void {
        var ids: [ihave_out_max]Id = undefined;
        const gossip = router.cache.gossip_ids(topic, &ids);
        if (gossip.len == 0) return;
        const pool = router.candidates(topic, router.config.thresholds.gossip_threshold) &
            ~router.mesh[topic];
        const count = @max(router.config.d_lazy, @popCount(pool) / 4);
        var targets = router.pick_random(pool, count);
        while (targets != 0) : (targets &= targets - 1) {
            const target = &router.peers[@ctz(targets)];
            for (gossip) |*id| {
                if (target.ihave_count == ihave_out_max) break;
                target.ihave[target.ihave_count] = id.*;
                target.ihave_topic[target.ihave_count] = topic;
                target.ihave_count += 1;
            }
        }
    }

    fn check_invariants(router: *const Router) void {
        var active: PeerSet = 0;
        for (router.peers, 0..) |*target, slot| {
            if (target.active) active |= bit(@intCast(slot));
        }
        for (router.mesh[0..router.topics_count]) |mesh| assert(mesh & ~active == 0);
        assert(router.events_count <= events_max);
    }

    // Outbound.

    /// Encodes the next framed RPC for `slot` into `output`, or null when nothing is
    /// pending. `output` must hold at least `drain_buffer_min` bytes; a message larger
    /// than `output` is dropped.
    pub fn drain(router: *Router, slot: Slot, output: []u8) ?[]const u8 {
        assert(output.len >= drain_buffer_min);
        const target = router.peer(slot);
        if (!target.has_output()) return null;
        const message = router.scratch;
        message.reset();
        router.drain_control(target) catch unreachable; // Bounded by Limits, see below.
        const budget = output.len - rpc.varint_length_max;
        while (target.queue_count > 0) {
            const id = &target.queue[target.queue_head];
            const entry = router.cache.find(id);
            if (entry) |cached| {
                const outgoing: rpc.Message = .{
                    .topic = router.topics[cached.topic].slice(),
                    .data = router.cache.data(cached),
                };
                const extra = 1 + rpc.varint_length_max + rpc.message_length(outgoing);
                const full = message.publish_count == limits.publish_max or
                    message.encoded_length() + extra > budget;
                if (full and message.encoded_length() > 0) break;
                if (!full) message.add_publish(outgoing) catch unreachable;
            }
            target.queue_head = (target.queue_head + 1) % queue_max;
            target.queue_count -= 1;
        }
        if (message.encoded_length() == 0) return null;
        return message.encode_framed(output);
    }

    pub const drain_buffer_min = 64 * 1024;

    // Control output is bounded well inside the RPC limits: <= topics_max subscriptions,
    // grafts, and prunes; <= ihave_out_max + iwant_out_max message ids.
    comptime {
        assert(topics_max <= limits.subscriptions_max and topics_max <= limits.graft_max);
        assert(ihave_out_max + iwant_out_max <= limits.message_ids_max);
    }

    fn drain_control(router: *Router, target: *Peer) rpc.Error!void {
        const message = router.scratch;
        if (target.send_subscriptions) {
            for (router.topics[0..router.topics_count]) |*topic| {
                const sub_opts: rpc.SubOpts = .{
                    .subscribe = topic.subscribed,
                    .topic_id = topic.slice(),
                };
                try message.add_subscription(sub_opts);
            }
            target.send_subscriptions = false;
        }
        var topic: u8 = 0;
        while (topic < router.topics_count) : (topic += 1) {
            const mask = @as(u8, 1) << @intCast(topic);
            const name = router.topics[topic].slice();
            if (target.graft_pending & mask != 0) try message.add_graft(name);
            if (target.prune_pending & mask != 0) {
                try message.add_prune(name, &.{}, router.config.prune_backoff_ns / ns_per_s);
            }
        }
        target.graft_pending = 0;
        target.prune_pending = 0;
        try router.drain_ihave(target);
        if (target.iwant_count > 0) {
            for (target.iwant[0..target.iwant_count], 0..) |*id, index| {
                router.id_slices[index] = id;
            }
            try message.add_iwant(router.id_slices[0..target.iwant_count]);
            target.iwant_count = 0;
        }
    }

    fn drain_ihave(router: *Router, target: *Peer) rpc.Error!void {
        var topic: u8 = 0;
        while (topic < router.topics_count) : (topic += 1) {
            var count: usize = 0;
            for (target.ihave[0..target.ihave_count], 0..) |*id, index| {
                if (target.ihave_topic[index] != topic) continue;
                router.id_slices[count] = id;
                count += 1;
            }
            if (count > 0) {
                const name = router.topics[topic].slice();
                try router.scratch.add_ihave(name, router.id_slices[0..count]);
            }
        }
        target.ihave_count = 0;
    }
};

fn bit(slot: Slot) PeerSet {
    assert(slot < peers_max);
    return @as(PeerSet, 1) << @intCast(slot);
}

fn in_set(set: PeerSet, slot: Slot) bool {
    return set & bit(slot) != 0;
}

fn nth_bit(set: PeerSet, n: u32) Slot {
    assert(n < @popCount(set));
    var remaining = set;
    var skipped: u32 = 0;
    while (skipped < n) : (skipped += 1) remaining &= remaining - 1;
    return @intCast(@ctz(remaining));
}

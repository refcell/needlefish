//! Router tests: a seeded in-memory cluster (DST style), scoring against an attacker,
//! the IHAVE/IWANT path, determinism, and fuzzing of inbound RPCs.

const std = @import("std");
const router_module = @import("router.zig");
const rpc = @import("rpc.zig");
const score = @import("../peers/score.zig");
const peer_id = @import("../peers/peer_id.zig");
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

const Router = router_module.Router;
const Id = router_module.Id;
const Slot = router_module.Slot;
const ns_per_ms = std.time.ns_per_ms;

fn test_message_id(_: ?*anyopaque, topic: []const u8, data: []const u8) Id {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(topic);
    hasher.update(data);
    const digest = hasher.finalResult();
    return digest[0..20].*;
}

fn test_peer_id(index: usize) peer_id.PeerId {
    var bytes: [34]u8 = undefined;
    bytes[0] = 0x12;
    bytes[1] = 32;
    @memset(bytes[2..], @truncate(index + 1));
    return peer_id.from_bytes(&bytes) catch unreachable;
}

const topic_name = "/optimism/8453/3/blocks";
const nodes_max = 24;

const Cluster = struct {
    routers: [nodes_max]Router = undefined,
    prngs: [nodes_max]Prng = undefined,
    /// slots[a][b]: the slot router `a` uses for node `b`, if connected.
    slots: [nodes_max][nodes_max]?Slot = @splat(@splat(null)),
    nodes: usize,
    /// Nodes whose payloads honest validators reject (first byte 0xBA marks them).
    received: [nodes_max]u32 = @splat(0),
    digest: std.crypto.hash.sha2.Sha256 = .init(.{}),
    now_ns: u64 = 0,
    buffer: []u8,

    fn init(cluster: *Cluster, nodes: usize, seed: u64, config: router_module.Config) !void {
        cluster.* = .{ .nodes = nodes, .buffer = try std.testing.allocator.alloc(u8, 1 << 20) };
        for (0..nodes) |index| {
            cluster.prngs[index] = Prng.init(seed +% index);
            cluster.routers[index] = try Router.init(
                std.testing.allocator,
                config,
                cluster.prngs[index].random(),
            );
            _ = try cluster.routers[index].subscribe(topic_name);
        }
    }

    fn deinit(cluster: *Cluster) void {
        for (cluster.routers[0..cluster.nodes]) |*router| router.deinit(std.testing.allocator);
        std.testing.allocator.free(cluster.buffer);
    }

    fn connect(cluster: *Cluster, a: usize, b: usize) void {
        if (a == b or cluster.slots[a][b] != null) return;
        cluster.slots[a][b] = cluster.routers[a].add_peer(test_peer_id(b), true, null, 0).?;
        cluster.slots[b][a] = cluster.routers[b].add_peer(test_peer_id(a), false, null, 0).?;
    }

    fn connect_random(cluster: *Cluster, degree: usize, prng: *Prng) void {
        for (0..cluster.nodes) |a| {
            for (0..degree) |_| cluster.connect(a, prng.below(cluster.nodes));
        }
    }

    /// Delivers every pending frame, then validates every pending message, until quiet.
    fn flush(cluster: *Cluster) !void {
        var rounds: u32 = 0;
        while (rounds < 64) : (rounds += 1) {
            var moved = false;
            for (0..cluster.nodes) |a| {
                for (0..cluster.nodes) |b| {
                    const slot = cluster.slots[a][b] orelse continue;
                    const frame = cluster.routers[a].drain(slot, cluster.buffer) orelse continue;
                    moved = true;
                    const header = (try rpc.frame_decode(frame, rpc.frame_size_max_default)).?;
                    const from = cluster.slots[b][a].?;
                    cluster.routers[b].on_rpc(from, header.payload, cluster.now_ns) catch {};
                }
                moved = cluster.validate_all(a) or moved;
            }
            if (!moved) return;
        }
        return error.NotQuiet;
    }

    fn validate_all(cluster: *Cluster, node: usize) bool {
        const router = &cluster.routers[node];
        var any = false;
        while (router.pop_event()) |event| {
            any = true;
            const data = router.message_data(&event.id).?;
            const verdict: router_module.Validation = if (data.len > 0 and data[0] == 0xBA)
                .reject
            else
                .accept;
            if (verdict == .accept) {
                cluster.received[node] += 1;
                cluster.digest.update(&event.id);
                cluster.digest.update(std.mem.asBytes(&node));
            }
            router.validate(&event.id, verdict);
        }
        return any;
    }

    fn heartbeat(cluster: *Cluster) !void {
        cluster.now_ns += 500 * ns_per_ms;
        for (cluster.routers[0..cluster.nodes]) |*router| router.heartbeat(cluster.now_ns);
        try cluster.flush();
    }
};

fn scored_config() router_module.Config {
    return .{
        .message_id = test_message_id,
        .peer_params = score.peer_params(.light, true, 2),
        .mcache = .{ .entries_max = 256, .arena_bytes = 1 << 20 },
    };
}

fn run_propagation(seed: u64) ![32]u8 {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(20, seed, scored_config());
    defer cluster.deinit();
    var prng = Prng.init(seed);
    cluster.connect_random(5, &prng);
    for (0..10) |_| try cluster.heartbeat();
    for (cluster.routers[0..20]) |*router| {
        const mesh = @popCount(router.mesh_peers(0));
        try std.testing.expect(mesh >= 1 and mesh <= 12);
    }
    var payload: [64]u8 = undefined;
    for (0..10) |round| {
        prng.fill(&payload);
        payload[0] = @truncate(round);
        const origin = prng.below(20);
        _ = try cluster.routers[origin].publish(0, &payload, cluster.now_ns);
        cluster.received[origin] += 1;
        try cluster.flush();
        try cluster.heartbeat();
    }
    for (cluster.received[0..20]) |count| try std.testing.expectEqual(@as(u32, 10), count);
    return cluster.digest.finalResult();
}

test "router: messages reach every node and runs are deterministic" {
    const first = try run_propagation(0x676f_7373);
    const second = try run_propagation(0x676f_7373);
    try std.testing.expectEqualSlices(u8, &first, &second);
}

test "router: invalid messages sink the sender's score and remove it from meshes" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(8, 77, scored_config());
    defer cluster.deinit();
    for (0..8) |a| for (a + 1..8) |b| cluster.connect(a, b);
    for (0..4) |_| try cluster.heartbeat();
    var payload: [32]u8 = @splat(0xBA);
    for (0..4) |round| {
        payload[1] = @truncate(round);
        _ = try cluster.routers[7].publish(0, &payload, cluster.now_ns);
        try cluster.flush();
    }
    for (0..4) |_| try cluster.heartbeat();
    for (0..7) |node| {
        const router = &cluster.routers[node];
        const slot = cluster.slots[node][7].?;
        try std.testing.expect(router.peer_score_value(slot) < 0);
        try std.testing.expect(router.mesh_peers(0) & (@as(u64, 1) << @intCast(slot)) == 0);
    }
}

test "router: IHAVE and IWANT deliver messages without a mesh" {
    var config = scored_config();
    config.d = 0;
    config.d_low = 0;
    config.d_score = 0;
    config.d_out = 0;
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(2, 9, config);
    defer cluster.deinit();
    cluster.connect(0, 1);
    try cluster.heartbeat();
    _ = try cluster.routers[0].publish(0, "hello gossip", cluster.now_ns);
    try cluster.flush();
    try std.testing.expectEqual(@as(u32, 0), cluster.received[1]);
    try cluster.heartbeat();
    try std.testing.expectEqual(@as(u32, 1), cluster.received[1]);
    try std.testing.expectEqual(@as(u64, 0), cluster.routers[0].mesh_peers(0));
}

test "router: graft during backoff is penalized and pruned" {
    var prng = Prng.init(1);
    var router = try Router.init(std.testing.allocator, scored_config(), prng.random());
    defer router.deinit(std.testing.allocator);
    _ = try router.subscribe(topic_name);
    const slot = router.add_peer(test_peer_id(1), false, null, 0).?;
    var message: rpc.RpcDefault = undefined;
    message.reset();
    try message.add_subscription(.{ .subscribe = true, .topic_id = topic_name });
    try message.add_graft(topic_name);
    var buffer: [4096]u8 = undefined;
    try router.on_rpc(slot, message.encode(&buffer), 0);
    try std.testing.expect(router.mesh_peers(0) != 0);
    message.reset();
    try message.add_prune(topic_name, &.{}, 60);
    try router.on_rpc(slot, message.encode(&buffer), 1);
    try std.testing.expectEqual(@as(u64, 0), router.mesh_peers(0));
    message.reset();
    try message.add_graft(topic_name);
    try router.on_rpc(slot, message.encode(&buffer), 2);
    try std.testing.expectEqual(@as(u64, 0), router.mesh_peers(0));
    try std.testing.expectEqual(@as(f64, 2), router.peer(slot).counters.behaviour_penalty);
    var output: [Router.drain_buffer_min]u8 = undefined;
    const frame = router.drain(slot, &output).?;
    const header = (try rpc.frame_decode(frame, rpc.frame_size_max_default)).?;
    try message.decode(header.payload);
    try std.testing.expectEqual(@as(usize, 1), message.prune_slice().len);
}

test "router: reconnecting keeps a bad score until retention expires" {
    var prng = Prng.init(2);
    var router = try Router.init(std.testing.allocator, scored_config(), prng.random());
    defer router.deinit(std.testing.allocator);
    _ = try router.subscribe(topic_name);
    var slot = router.add_peer(test_peer_id(5), false, null, 0).?;
    router.peer(slot).counters.behaviour_penalty = 20;
    router.heartbeat(1);
    const bad = router.peer_score_value(slot);
    try std.testing.expect(bad < 0);
    router.remove_peer(slot, 2);
    slot = router.add_peer(test_peer_id(5), false, null, 3).?;
    router.heartbeat(4);
    try std.testing.expect(router.peer_score_value(slot) < 0);
    const retain_ns = router.config.peer_params.?.retain_score_ns;
    router.remove_peer(slot, 5);
    slot = router.add_peer(test_peer_id(5), false, null, 6 + retain_ns).?;
    router.heartbeat(7 + retain_ns);
    try std.testing.expectEqual(@as(f64, 0), router.peer_score_value(slot));
}

test "router: mesh keeps the outbound quota when trimmed" {
    var prng = Prng.init(3);
    var router = try Router.init(std.testing.allocator, scored_config(), prng.random());
    defer router.deinit(std.testing.allocator);
    _ = try router.subscribe(topic_name);
    var message: rpc.RpcDefault = undefined;
    message.reset();
    try message.add_subscription(.{ .subscribe = true, .topic_id = topic_name });
    try message.add_graft(topic_name);
    var buffer: [4096]u8 = undefined;
    const frame = message.encode(&buffer);
    var outbound: u64 = 0;
    for (0..20) |index| {
        const is_outbound = index >= 17;
        const slot = router.add_peer(test_peer_id(index), is_outbound, null, 0).?;
        if (is_outbound) outbound |= @as(u64, 1) << @intCast(slot);
        try router.on_rpc(slot, frame, 0);
    }
    for (0..50) |round| {
        router.heartbeat(round * 500 * ns_per_ms);
        const mesh = router.mesh_peers(0);
        try std.testing.expect(@popCount(mesh) <= 12);
        try std.testing.expect(@popCount(mesh & outbound) >= 2);
    }
}

test "router: IDONTWANT is sent for large messages and honored when forwarding" {
    var prng = Prng.init(4);
    var router = try Router.init(std.testing.allocator, scored_config(), prng.random());
    defer router.deinit(std.testing.allocator);
    _ = try router.subscribe(topic_name);
    var message: rpc.RpcDefault = undefined;
    message.reset();
    try message.add_subscription(.{ .subscribe = true, .topic_id = topic_name });
    try message.add_graft(topic_name);
    var buffer: [8192]u8 = undefined;
    const join = message.encode(&buffer);
    var slots: [3]Slot = undefined;
    for (&slots, 0..) |*slot, index| {
        slot.* = router.add_peer(test_peer_id(index), true, null, 0).?;
        try router.on_rpc(slot.*, join, 0);
        router.set_idontwant_capable(slot.*, true);
    }
    var output: [Router.drain_buffer_min]u8 = undefined;
    for (slots) |slot| while (router.drain(slot, &output)) |_| {};
    const data: [2000]u8 = @splat(0xab);
    const id = test_message_id(null, topic_name, &data);
    // Peer 2 says it does not want the message before we have it.
    message.reset();
    try message.add_idontwant(&.{&id});
    try router.on_rpc(slots[2], message.encode(&buffer), 1);
    message.reset();
    try message.add_publish(.{ .topic = topic_name, .data = &data });
    try router.on_rpc(slots[0], message.encode(&buffer), 2);
    // Peer 1 gets IDONTWANT right away; the source and peer 2 do not.
    const frame = router.drain(slots[1], &output).?;
    var decoded: rpc.RpcDefault = undefined;
    try decoded.decode((try rpc.frame_decode(frame, rpc.frame_size_max_default)).?.payload);
    try std.testing.expectEqual(@as(usize, 1), decoded.idontwant_slice().len);
    try std.testing.expect(router.drain(slots[0], &output) == null);
    const event = router.pop_event().?;
    router.validate(&event.id, .accept);
    // Forwarded to peer 1 only.
    try std.testing.expect(router.drain(slots[1], &output) != null);
    try std.testing.expect(router.drain(slots[2], &output) == null);
}

const FuzzContext = struct {};

fn fuzz_on_rpc(_: FuzzContext, input: []const u8) anyerror!void {
    var prng = Prng.init(input.len);
    var router = try Router.init(std.testing.allocator, scored_config(), prng.random());
    defer router.deinit(std.testing.allocator);
    _ = try router.subscribe(topic_name);
    const slot = router.add_peer(test_peer_id(3), true, null, 0).?;
    router.on_rpc(slot, input, 0) catch {};
    while (router.pop_event()) |event| router.validate(&event.id, .accept);
    router.heartbeat(500 * ns_per_ms);
    var output: [Router.drain_buffer_min]u8 = undefined;
    var frames: u32 = 0;
    while (router.drain(slot, &output)) |frame| : (frames += 1) {
        const header = (try rpc.frame_decode(frame, rpc.frame_size_max_default)).?;
        var decoded: rpc.RpcDefault = undefined;
        try decoded.decode(header.payload);
        try std.testing.expect(frames < 64);
    }
}

test "router: fuzz inbound RPCs" {
    var seed_rpc: rpc.RpcDefault = undefined;
    seed_rpc.reset();
    try seed_rpc.add_subscription(.{ .subscribe = true, .topic_id = topic_name });
    try seed_rpc.add_publish(.{ .topic = topic_name, .data = "block" });
    try seed_rpc.add_graft(topic_name);
    const id: [20]u8 = @splat(7);
    try seed_rpc.add_ihave(topic_name, &.{&id});
    try seed_rpc.add_iwant(&.{&id});
    var buffer: [1024]u8 = undefined;
    const corpus = seed_rpc.encode(&buffer);
    const options: fuzz.Options = .{ .input_size_max = 1024, .corpus = &.{corpus} };
    try fuzz.run_bytes(FuzzContext{}, fuzz_on_rpc, options);
}

/// One hostile control RPC: `iwant` ids (the last one real), a full IDONTWANT, 64 IHAVEs of
/// fresh ids, and a GRAFT followed by a PRUNE.
fn control_flood_frame(random: std.Random, real: *const Id, output: []u8) ![]const u8 {
    const State = struct {
        var ids: [5000][20]u8 = undefined;
        var views: [5000][]const u8 = undefined;
    };
    for (&State.ids, &State.views) |*id, *view| {
        random.bytes(id);
        view.* = id;
    }
    State.views[3999] = real;
    var message: rpc.RpcDefault = undefined;
    message.reset();
    try message.add_iwant(State.views[0..4000]);
    for (0..16) |index| try message.add_idontwant(State.views[4000 + index * 32 ..][0..32]);
    for (0..8) |index| {
        try message.add_ihave(topic_name, State.views[4512 + index * 60 ..][0..60]);
    }
    try message.add_graft(topic_name);
    try message.add_prune(topic_name, &.{}, 60);
    return message.encode(output);
}

test "router: control-message floods are bounded per peer; honest gossip still flows" {
    var config = scored_config();
    // No mesh: the honest peer gets every message only through IHAVE and IWANT.
    config.d = 0;
    config.d_low = 0;
    config.d_score = 0;
    config.d_out = 0;
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(3, 0xc0de, config);
    defer cluster.deinit();
    cluster.connect(0, 1);
    cluster.connect(0, 2);
    try cluster.heartbeat();
    const victim = &cluster.routers[0];
    const attacker = cluster.slots[0][2].?;
    var prng = Prng.init(0xc0de);
    const frame = try std.testing.allocator.alloc(u8, 256 * 1024);
    defer std.testing.allocator.free(frame);
    const rounds = 20;
    var payload: [48]u8 = @splat(0x11);
    for (0..rounds) |round| {
        payload[0] = @truncate(round);
        _ = try victim.publish(0, &payload, cluster.now_ns);
        const real = test_message_id(null, topic_name, &payload);
        for (0..5) |_| {
            const bytes = try control_flood_frame(prng.random(), &real, frame);
            victim.on_rpc(attacker, bytes, cluster.now_ns) catch {}; // Graylisted later.
            const target = victim.peer(attacker);
            try std.testing.expect(target.iwant_ids_received <= config.iwant_ids_max);
            try std.testing.expect(target.idontwant_ids_received <= config.idontwant_ids_max);
            try std.testing.expect(target.queue_count <= 1 + round);
        }
        try cluster.flush();
        try cluster.heartbeat();
    }
    try std.testing.expectEqual(@as(u32, rounds), cluster.received[1]);
    try std.testing.expect(victim.stats.control_ids_ignored > 0);
    // GRAFT during the PRUNE backoff, every round: the attacker's score sinks.
    try std.testing.expect(victim.peer_score_value(attacker) < config.thresholds.gossip_threshold);
    try std.testing.expectEqual(@as(u64, 0), victim.mesh_peers(0));
}

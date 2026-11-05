//! Deterministic simulation of p2p nodes over SimIo: each node runs `p2p.Service` and
//! `Transport(SimIo)`, so dialing, the full libp2p pipeline (noise, yamux, meshsub), and
//! block gossip run over simulated TCP with latency and partitions. Discovery datagrams
//! are moved in-process until io has UDP.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const service_module = @import("service.zig");
const transport_module = @import("transport.zig");
const enr = @import("peers/enr.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const peer_id = @import("peers/peer_id.zig");
const ssz = @import("gossip/ssz_payload.zig");
const validity = @import("gossip/validity.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus_types = @import("../../common/consensus/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const build_options = @import("build_options");

const SimIo = io_module.SimIo;
const World = io_module.SimWorld;
const Service = service_module.Service;
const Transport = transport_module.Transport(SimIo);
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;
const chain_id = 8453;
const nodes = 4;
const nodes_max = 16;
const port = 9222;
const frame_size_max = 256 * 1024;
const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };

const Node = struct {
    io: SimIo,
    secret: secp256k1.SecretKey,
    service: *Service,
    transport: Transport,
    record: enr.Record,
    prng: Prng,
};

const Cluster = struct {
    world: World,
    storage: [nodes_max]Node,
    count: usize,
    rollup: rollup_config.RollupConfig,
    sequencer_secret: [32]u8,
    tx_storage: [512]u8 = undefined,

    fn init(cluster: *Cluster, seed: u64) !void {
        return cluster.init_options(seed, nodes, 0, 0);
    }

    fn all(cluster: *Cluster) []Node {
        return cluster.storage[0..cluster.count];
    }

    fn init_options(
        cluster: *Cluster,
        seed: u64,
        count: usize,
        reset_ppm: u32,
        datagram_loss_ppm: u32,
    ) !void {
        assert(count >= 2 and count <= nodes_max);
        cluster.count = count;
        const allocator = std.testing.allocator;
        cluster.rollup = .{ .l2_chain_id = chain_id };
        cluster.rollup.upgrades.set(.ecotone, 0);
        cluster.sequencer_secret = @splat(0);
        cluster.sequencer_secret[31] = 5;
        cluster.world = try World.init(allocator, .{
            .seed = seed,
            .latency_min_ns = 1 * ns_per_ms,
            .latency_max_ns = 20 * ns_per_ms,
            .pipe_size_bytes = 64 * 1024,
            .reset_ppm = reset_ppm,
            .datagram_loss_ppm = datagram_loss_ppm,
            .connections_max = 256,
            .nodes_max = nodes_max,
        });
        var key_prng = Prng.init(seed ^ 0x6b65_7973);
        for (cluster.all(), 0..) |*node, index| try cluster.init_node(node, index, &key_prng);
        for (cluster.all()[1..]) |*node| {
            node.service.add_boot_record(&cluster.storage[0].record, node.io.now_realtime_ns());
        }
    }

    fn init_node(cluster: *Cluster, node: *Node, index: usize, key_prng: *Prng) !void {
        const allocator = std.testing.allocator;
        var secret: secp256k1.SecretKey = undefined;
        while (true) {
            key_prng.fill(&secret);
            secp256k1.validate_secret_key(secret) catch continue;
            break;
        }
        const host: [4]u8 = .{ 10, 0, @intCast(index), 1 };
        node.record = try enr.build(secret, .{
            .ip4 = host,
            .udp = 9000,
            .tcp = port,
            .opstack = .{ .chain_id = chain_id },
        });
        try SimIo.init(&node.io, allocator, &cluster.world, .{
            .host = io_module.Address.ip4(host, 0),
        });
        node.secret = secret;
        try cluster.start_node(node, index);
    }

    /// Creates the node's service and transport on its (possibly crashed) SimIo.
    fn start_node(cluster: *Cluster, node: *Node, index: usize) !void {
        const allocator = std.testing.allocator;
        const secret = node.secret;
        const host = node.record.ip4().?;
        node.prng = Prng.init(index + 101);
        const signer: primitives.Address = .{
            .bytes = try common_secp256k1.address(cluster.sequencer_secret),
        };
        node.service = try Service.create(allocator, .{
            .rollup = &cluster.rollup,
            .unsafe_block_signer = signer,
            .disc = .{
                .chain_id = chain_id,
                .lookup_interval_ns = 1000 * ns_per_ms,
                .table = .{ .subnet_bucket_max = 0, .subnet_table_max = 0 },
            },
            .mcache = .{ .entries_max = 64, .arena_bytes = 1 << 20 },
            .ban_enabled = true,
        }, secret, node.record, node.prng.random());
        try node.transport.init(allocator, &node.io, node.service, .{
            .listen = io_module.Address.ip4(host, port),
            .identity_secret = secret,
            .seed = index + 7,
            .links_max = 8,
            .gossip_frame_size_max = frame_size_max,
            .discovery_listen = io_module.Address.ip4(host, 9000),
        });
        try node.transport.start();
    }

    /// Crashes a node (pending IO vanishes, peers see resets) and boots it again fresh.
    fn crash_restart(cluster: *Cluster, index: usize) !void {
        const node = &cluster.storage[index];
        node.io.crash();
        node.transport.deinit();
        node.service.destroy(std.testing.allocator);
        try cluster.start_node(node, index);
        const boot = &cluster.storage[if (index == 0) 1 else 0].record;
        node.service.add_boot_record(boot, node.io.now_realtime_ns());
    }

    fn deinit(cluster: *Cluster) void {
        for (cluster.all()) |*node| node.transport.stop();
        cluster.world.run_for_ns(100 * ns_per_ms);
        for (cluster.all()) |*node| {
            // Every canceled UDP completion returned and the socket closed.
            assert(!node.transport.busy());
            node.transport.deinit();
            node.service.destroy(std.testing.allocator);
            node.io.deinit();
        }
        cluster.world.deinit();
    }

    fn run(cluster: *Cluster, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ns_per_ms) {
            cluster.world.run_for_ns(10 * ns_per_ms);
            for (cluster.all()) |*node| node.transport.execute_commands();
        }
    }

    fn payload(cluster: *Cluster, number: u64) !ssz.ExecutionPayload {
        const deposit: consensus_types.Envelope = .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(@truncate(number)) },
            .from = .zero,
            .to = .create,
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = "needlefish",
        } };
        const encoded = deposit.encode_to(cluster.tx_storage[256..]);
        var result: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = number,
            .timestamp = cluster.storage[0].io.now_realtime_ns() / ns_per_s,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = ssz.Transactions.encode(cluster.tx_storage[0..256], &.{encoded}),
        };
        result.block_hash = try validity.block_hash(&cluster.rollup, &result, beacon_root);
        return result;
    }

    fn publish(cluster: *Cluster, from: usize, number: u64) !void {
        return cluster.publish_signed(from, number, cluster.sequencer_secret);
    }

    fn publish_signed(cluster: *Cluster, from: usize, number: u64, secret: [32]u8) !void {
        const value = try cluster.payload(number);
        const node = &cluster.storage[from];
        const now = node.io.now_realtime_ns();
        _ = try node.service.publish_block(secret, beacon_root, value, now);
        node.transport.execute_commands();
        node.transport.pump_all();
    }

    fn received(cluster: *Cluster, index: usize, number: u64, scratch: []u8) bool {
        const envelope = cluster.storage[index].service.pop_block(scratch) orelse return false;
        return envelope.payload.block_number == number;
    }
};

test "p2p transport: nodes discover, connect over libp2p, and gossip a block" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(1);
    defer cluster.deinit();
    cluster.run(8 * ns_per_s);
    for (cluster.all()) |*node| try std.testing.expect(node.transport.open_count() >= 2);
    // Discovery ran over SimIo UDP: every node received and sent datagrams.
    for (cluster.all()) |*node| {
        try std.testing.expect(node.transport.stats.datagrams_received > 0);
        try std.testing.expect(node.transport.stats.datagrams_sent > 0);
    }
    // Identify reached the service: every connected peer reports our agent and meshsub.
    for (cluster.all()) |*node| {
        for (&node.service.connected) |*connection| {
            if (!connection.active) continue;
            try std.testing.expectEqualStrings("needlefish", connection.info.agent_version.slice());
            try std.testing.expect(connection.info.protocols_count > 0);
        }
    }
    try cluster.publish(2, 7);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (0..cluster.count) |index| {
        if (index == 2) continue;
        try std.testing.expect(cluster.received(index, 7, scratch));
    }
}

test "p2p transport: a blocked address cannot connect inbound and is not dialed" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(2);
    defer cluster.deinit();
    const boot = cluster.storage[0].service;
    const blocked = cluster.storage[3].record.ip4().?;
    try std.testing.expect(boot.gater.block_address(.{ .ip4 = blocked }));
    cluster.run(8 * ns_per_s);
    const blocked_peer = peer_id.from_public_key(
        try secp256k1.public_key(cluster.storage[3].secret),
    );
    try std.testing.expect(boot.slot_of(&blocked_peer) == null);
    const address_reason = @backingInt(service_module.InboundError.blocked_address);
    const dial_reason = @backingInt(service_module.DialError.blocked_address);
    const stats = &boot.stats;
    const refusals = stats.inbound_errors[address_reason] + stats.dial_errors[dial_reason];
    try std.testing.expect(refusals > 0);
    // Node 3 still meshes with the others, and the transport reports real peer IPs.
    try std.testing.expect(cluster.storage[3].transport.open_count() >= 1);
    for (&boot.connected, 0..) |*connection, slot| {
        if (!connection.active) continue;
        try std.testing.expect(boot.gossip.router.peer(@intCast(slot)).address != null);
    }
}

test "p2p transport: a partitioned node gets the block after the partition heals" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(2);
    defer cluster.deinit();
    cluster.run(8 * ns_per_s);
    const isolated = 3;
    for (0..cluster.count) |index| {
        if (index == isolated) continue;
        const peer_index = cluster.storage[index].io.index;
        cluster.world.partition(peer_index, cluster.storage[isolated].io.index);
    }
    try cluster.publish(0, 9);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    try std.testing.expect(cluster.received(1, 9, scratch));
    try std.testing.expect(cluster.received(2, 9, scratch));
    try std.testing.expect(!cluster.received(isolated, 9, scratch));
    cluster.world.heal_all();
    cluster.run(2 * ns_per_s);
    try std.testing.expect(cluster.received(isolated, 9, scratch));
}

test "p2p transport: blocks keep flowing through random connection resets" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init_options(5, nodes, 5_000, 0);
    defer cluster.deinit();
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    cluster.run(8 * ns_per_s);
    const blocks = 10;
    var delivered: [nodes]u32 = @splat(0);
    for (0..blocks) |number| {
        try cluster.publish(0, number + 1);
        cluster.run(2 * ns_per_s);
        for (1..nodes) |index| {
            while (cluster.storage[index].service.pop_block(scratch)) |_| delivered[index] += 1;
        }
    }
    var resets: u64 = 0;
    for (cluster.all()) |*node| resets += node.transport.stats.closed;
    try std.testing.expect(resets > 0);
    for (delivered[1..]) |count| try std.testing.expectEqual(@as(u32, blocks), count);
    for (cluster.all()) |*node| try std.testing.expect(node.transport.open_count() >= 2);
}

test "p2p transport: a node gossiping badly signed blocks is banned by its peers" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(6);
    defer cluster.deinit();
    cluster.run(8 * ns_per_s);
    const attacker = 3;
    var wrong_secret: [32]u8 = @splat(0);
    wrong_secret[31] = 9;
    for (0..4) |number| {
        try cluster.publish_signed(attacker, number + 1, wrong_secret);
        cluster.run(500 * ns_per_ms);
    }
    cluster.run(16 * ns_per_s);
    const attacker_id = cluster.storage[attacker].record.node_id();
    for (cluster.all()[0..attacker]) |*node| {
        try std.testing.expect(node.service.stats.banned >= 1);
        const now = node.io.now_realtime_ns();
        try std.testing.expect(node.service.discovery.is_banned(attacker_id, now));
        try std.testing.expect(node.transport.open_count() >= 1);
    }
    // Like base/base, a ban is a discovery ban plus a disconnect: the attacker may redial,
    // but gossipsub retained its negative score, so it stays graylisted and is banned again.
    const attacker_peer = peer_id.from_public_key(
        try secp256k1.public_key(cluster.storage[attacker].secret),
    );
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (cluster.all()[0..attacker]) |*node| {
        try std.testing.expect(node.service.pop_block(scratch) == null);
        const slot = node.service.slot_of(&attacker_peer) orelse continue;
        try std.testing.expect(node.service.gossip.router.peer_score_value(slot) < 0);
    }
    // Bans disconnect gracefully: the attacker hears yamux go-aways.
    try std.testing.expect(cluster.storage[attacker].transport.stats.remote_go_aways >= 1);
    var local_go_aways: u64 = 0;
    for (cluster.all()[0..attacker]) |*node| local_go_aways += node.transport.stats.local_go_aways;
    try std.testing.expect(local_go_aways >= 1);
    // The honest nodes still gossip valid blocks among themselves.
    try cluster.publish(0, 50);
    cluster.run(1 * ns_per_s);
    try std.testing.expect(cluster.received(1, 50, scratch));
    try std.testing.expect(cluster.received(2, 50, scratch));
}

test "p2p transport: a crashed node restarts, reconnects, and receives blocks" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(7);
    defer cluster.deinit();
    cluster.run(8 * ns_per_s);
    try cluster.crash_restart(2);
    cluster.run(10 * ns_per_s);
    try std.testing.expect(cluster.storage[2].transport.open_count() >= 2);
    try cluster.publish(0, 77);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (1..cluster.count) |index| try std.testing.expect(cluster.received(index, 77, scratch));
}

test "p2p transport: eight nodes with resets gossip every block (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init_options(8, 8, 2_000, 0);
    defer cluster.deinit();
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    cluster.run(12 * ns_per_s);
    var delivered: [nodes_max]u32 = @splat(0);
    for (0..10) |number| {
        try cluster.publish(0, number + 1);
        cluster.run(2 * ns_per_s);
        for (1..cluster.count) |index| {
            while (cluster.storage[index].service.pop_block(scratch)) |_| delivered[index] += 1;
        }
    }
    for (delivered[1..cluster.count]) |count| try std.testing.expectEqual(@as(u32, 10), count);
}

test "p2p transport: seed sweep, every node gets every block (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (3..19) |seed| {
        const cluster = try std.testing.allocator.create(Cluster);
        defer std.testing.allocator.destroy(cluster);
        try cluster.init(seed);
        defer cluster.deinit();
        cluster.run(8 * ns_per_s);
        try cluster.publish(seed % nodes, seed);
        cluster.run(1 * ns_per_s);
        for (0..cluster.count) |index| {
            if (index == seed % nodes) continue;
            if (!cluster.received(index, seed, scratch)) {
                std.debug.print("seed {d}: node {d} missed the block\n", .{ seed, index });
                return error.BlockNotDelivered;
            }
        }
    }
}

test "p2p transport: discovery fills tables and connects through 10% datagram loss" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init_options(21, nodes, 0, 100_000);
    defer cluster.deinit();
    cluster.run(10 * ns_per_s);
    for (cluster.all()) |*node| {
        // discv5 retried lost handshakes and lookups until every node knew the others.
        try std.testing.expect(node.service.discovery.table.live_count() >= nodes - 1);
        try std.testing.expect(node.transport.open_count() >= 2);
    }
    try cluster.publish(1, 21);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (0..cluster.count) |index| {
        if (index != 1) try std.testing.expect(cluster.received(index, 21, scratch));
    }
}

test "p2p transport: sixteen-node discovery swarm heals a partition and gossips (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init_options(31, nodes_max, 0, 50_000);
    defer cluster.deinit();
    // Nodes 12..15 start cut off from everyone else, including the bootnode.
    for (12..nodes_max) |cut| {
        for (0..12) |index| {
            cluster.world.partition(cluster.storage[index].io.index, cluster.storage[cut].io.index);
        }
    }
    cluster.run(6 * ns_per_s);
    for (cluster.all()[12..]) |*node| {
        try std.testing.expectEqual(@as(u32, 0), node.transport.open_count());
    }
    cluster.world.heal_all();
    cluster.run(20 * ns_per_s);
    for (cluster.all()) |*node| try std.testing.expect(node.transport.open_count() >= 2);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (0..3) |round| {
        const number = 100 + round;
        try cluster.publish(round, number);
        cluster.run(2 * ns_per_s);
        for (0..cluster.count) |index| {
            if (index == round) continue;
            if (!cluster.received(index, number, scratch)) {
                std.debug.print("block {d}: node {d} missed it\n", .{ number, index });
                return error.BlockNotDelivered;
            }
        }
    }
}

test "p2p transport: chaos seed sweep with loss, resets, and a partition (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (40..48) |seed| {
        const cluster = try std.testing.allocator.create(Cluster);
        defer std.testing.allocator.destroy(cluster);
        try cluster.init_options(seed, 5, 2_000, 50_000);
        defer cluster.deinit();
        cluster.run(10 * ns_per_s);
        // Cut one node off for a while, then heal and let it rejoin.
        const cut = seed % 5;
        for (cluster.all(), 0..) |*node, index| {
            if (index == cut) continue;
            cluster.world.partition(node.io.index, cluster.storage[cut].io.index);
        }
        cluster.run(3 * ns_per_s);
        cluster.world.heal_all();
        cluster.run(6 * ns_per_s);
        const from = (seed + 1) % 5;
        try cluster.publish(from, seed);
        cluster.run(2 * ns_per_s);
        for (0..cluster.count) |index| {
            if (index == from) continue;
            if (!cluster.received(index, seed, scratch)) {
                std.debug.print("chaos seed {d}: node {d} missed the block\n", .{ seed, index });
                return error.BlockNotDelivered;
            }
        }
    }
}

/// Sends one junk gossipsub frame (random protobuf bytes) on every open link of `node`.
fn send_junk_frames(node: *Node, random: std.Random) u32 {
    const rpc = @import("gossip/rpc.zig");
    var sent: u32 = 0;
    for (node.transport.links) |*link| {
        if (link.state != .open or !link.connection_live) continue;
        if (!link.connection.is_established()) continue;
        var frame: [rpc.varint_length_max + 256]u8 = undefined;
        const length = random.uintAtMost(usize, 255) + 1;
        const prefix = rpc.frame_header(&frame, length);
        random.bytes(frame[prefix.len..][0..length]);
        link.connection.send_gossip(frame[0 .. prefix.len + length]) catch continue;
        sent += 1;
    }
    node.transport.pump_all();
    return sent;
}

/// Pops every queued block on node `index`; true if one of them is `number`.
fn drain_has(cluster: *Cluster, index: usize, number: u64, scratch: []u8) bool {
    var found = false;
    for (0..64) |_| {
        const envelope = cluster.storage[index].service.pop_block(scratch) orelse break;
        if (envelope.payload.block_number == number) found = true;
    }
    return found;
}

test "p2p transport: an authenticated peer sending junk RPCs is dropped, blocks keep flowing" {
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(0x6a75_6e6b);
    defer cluster.deinit();
    cluster.run(8 * ns_per_s);
    const attacker = nodes - 1;
    var prng = Prng.init(0x6a75);
    const random = prng.random();
    var junk_sent: u32 = 0;
    var wrong_key: [32]u8 = @splat(0);
    wrong_key[31] = 9;
    for (0..6) |round| {
        // 2 s of attack: junk frames every 100 ms, a badly signed block every 500 ms.
        for (0..20) |step| {
            junk_sent += send_junk_frames(&cluster.storage[attacker], random);
            if (step % 5 == 0) {
                cluster.publish_signed(attacker, 1000 + round * 4 + step / 5, wrong_key) catch {};
            }
            cluster.run(100 * ns_per_ms);
        }
        const number = 10 + round;
        try cluster.publish(0, number);
        cluster.run(1 * ns_per_s);
        for (1..attacker) |index| {
            if (!drain_has(cluster, index, number, scratch)) {
                std.debug.print("junk rpc: node {d} missed block {d}\n", .{ index, number });
                return error.BlockNotDelivered;
            }
        }
    }
    try std.testing.expect(junk_sent > 0);
    const attacker_key = try secp256k1.public_key(cluster.storage[attacker].secret);
    const attacker_peer = peer_id.from_public_key(attacker_key);
    var invalid_rpcs: u64 = 0;
    var invalid_signer: u64 = 0;
    for (cluster.all()[0..attacker]) |*node| {
        invalid_rpcs += node.service.stats.invalid_rpcs;
        const reason = @backingInt(validity.Reason.invalid_signer);
        invalid_signer += node.service.gossip.stats.failed[reason];
        // Honest nodes stay connected to at least one other honest node.
        var honest_links: u32 = 0;
        for (&node.service.connected) |*connection| {
            if (!connection.active) continue;
            honest_links += @intFromBool(!connection.peer.eql(&attacker_peer));
        }
        try std.testing.expect(honest_links >= 1);
    }
    // Undecodable frames got the attacker disconnected; its blocks were rejected.
    try std.testing.expect(invalid_rpcs > 0);
    try std.testing.expect(invalid_signer > 0);
}

test "p2p transport: stop cancels the UDP completions, then closes the socket" {
    const cluster = try std.testing.allocator.create(Cluster);
    defer std.testing.allocator.destroy(cluster);
    try cluster.init(0x7564_70);
    defer cluster.deinit();
    cluster.run(3 * ns_per_s);
    const transport = &cluster.storage[1].transport;
    try std.testing.expect(transport.stats.datagrams_received > 0);
    try std.testing.expect(transport.busy()); // Running: the recvfrom stays in flight.
    transport.stop();
    // The canceled recvfrom has not returned yet, so the socket is still open.
    try std.testing.expect(transport.busy());
    try std.testing.expect(transport.udp != null);
    cluster.world.run_for_ns(10 * ns_per_ms);
    try std.testing.expect(!transport.busy());
    try std.testing.expect(transport.udp == null);
    // The rest keep discovering through the stopped node's absence.
    const received = cluster.storage[2].transport.stats.datagrams_received;
    cluster.run(2 * ns_per_s);
    try std.testing.expect(cluster.storage[2].transport.stats.datagrams_received > received);
}

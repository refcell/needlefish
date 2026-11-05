//! Deterministic simulation of p2p nodes over SimIo: each node runs `p2p.Service` and
//! `Transport(SimIo)`, so dialing, the full libp2p pipeline (noise, yamux, meshsub), and
//! block gossip run over simulated TCP with latency and partitions. Discovery datagrams
//! are moved in-process until io has UDP.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const service_module = @import("service.zig");
const transport_module = @import("transport.zig");
const disc = @import("disc/root.zig");
const enr = @import("peers/enr.zig");
const secp256k1 = @import("peers/secp256k1.zig");
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
const nodes_max = 8;
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
        return cluster.init_options(seed, nodes, 0);
    }

    fn all(cluster: *Cluster) []Node {
        return cluster.storage[0..cluster.count];
    }

    fn init_options(cluster: *Cluster, seed: u64, count: usize, reset_ppm: u32) !void {
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
            .connections_max = 128,
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
        }, secret, node.record, node.prng.random());
        try node.transport.init(allocator, &node.io, node.service, .{
            .listen = io_module.Address.ip4(host, port),
            .identity_secret = secret,
            .seed = index + 7,
            .links_max = 8,
            .gossip_frame_size_max = frame_size_max,
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
            node.transport.deinit();
            node.service.destroy(std.testing.allocator);
            node.io.deinit();
        }
        cluster.world.deinit();
    }

    fn node_of_host(cluster: *Cluster, address: [4]u8) ?usize {
        for (cluster.all(), 0..) |*node, index| {
            if (std.mem.eql(u8, &node.record.ip4().?, &address)) return index;
        }
        return null;
    }

    fn deliver_datagrams(cluster: *Cluster) void {
        for (cluster.all()) |*from| {
            while (from.service.pop_datagram()) |datagram| {
                const to = cluster.node_of_host(datagram.endpoint.address.ip4) orelse continue;
                const target = &cluster.storage[to];
                if (cluster.world.partitioned(from.io.index, target.io.index)) continue;
                const source: disc.table.Endpoint = .{
                    .address = .{ .ip4 = from.record.ip4().? },
                    .port = 9000,
                };
                const now = cluster.storage[to].io.now_realtime_ns();
                cluster.storage[to].service.on_datagram(source, datagram.slice(), now);
            }
        }
    }

    fn run(cluster: *Cluster, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ns_per_ms) {
            cluster.world.run_for_ns(10 * ns_per_ms);
            cluster.deliver_datagrams();
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
    try cluster.publish(2, 7);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (0..cluster.count) |index| {
        if (index == 2) continue;
        try std.testing.expect(cluster.received(index, 7, scratch));
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
    try cluster.init_options(5, nodes, 5_000);
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
    try std.testing.expectEqual(@as(u32, 0), cluster.storage[attacker].transport.open_count());
    // The honest nodes still gossip valid blocks among themselves.
    try cluster.publish(0, 50);
    cluster.run(1 * ns_per_s);
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
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
    try cluster.init_options(8, nodes_max, 2_000);
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

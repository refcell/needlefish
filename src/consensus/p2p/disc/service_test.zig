//! Discovery service tests, including a deterministic simulation: N nodes on a seeded
//! virtual UDP network with random latency (hence reordering) and packet loss. Every node
//! knows only one boot node; after a few lookup rounds every node must have discovered
//! most of the cluster. The same seed must produce the same execution.

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const service_module = @import("service.zig");
const Service = service_module.Service;
const Endpoint = service_module.Endpoint;
const enr = @import("../peers/enr.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const packet = @import("packet.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const chain_id = 8453;
const node_count_max = 24;
const in_flight_max = 4096;
const ns_per_ms = std.time.ns_per_ms;

const Flight = struct {
    deliver_ns: u64,
    sequence: u64,
    from: u8,
    to: u8,
    length: u16,
    bytes: [packet.size_max]u8,
};

fn flight_less(_: void, a: Flight, b: Flight) std.math.Order {
    if (a.deliver_ns != b.deliver_ns) return std.math.order(a.deliver_ns, b.deliver_ns);
    return std.math.order(a.sequence, b.sequence);
}

const Cluster = struct {
    allocator: std.mem.Allocator,
    node_count: u8,
    services: [node_count_max]Service = undefined,
    prngs: [node_count_max]Prng = undefined,
    network_prng: Prng,
    queue: std.PriorityQueue(Flight, void, flight_less),
    sequence: u64 = 0,
    drop_ppm: u32,
    discovered: [node_count_max][node_count_max]bool = @splat(@splat(false)),
    trace: std.hash.Wyhash = std.hash.Wyhash.init(0),

    fn endpoint(index: u8) Endpoint {
        return .{ .address = .{ .ip4 = .{ 10, 0, index, 1 } }, .port = 9000 };
    }

    fn index_of(target: Endpoint) ?u8 {
        const address = switch (target.address) {
            .ip4 => |value| value,
            .ip6 => return null,
        };
        return address[2];
    }

    fn init(allocator: std.mem.Allocator, seed: u64, node_count: u8, drop_ppm: u32) !*Cluster {
        assert(node_count >= 2 and node_count <= node_count_max);
        const cluster = try allocator.create(Cluster);
        cluster.* = .{
            .allocator = allocator,
            .node_count = node_count,
            .network_prng = Prng.init(seed),
            .queue = .empty,
            .drop_ppm = drop_ppm,
        };
        try cluster.queue.ensureTotalCapacity(allocator, in_flight_max);
        var key_prng = Prng.init(seed ^ 0x6b65_7973);
        for (0..node_count) |index| {
            var secret: secp256k1.SecretKey = undefined;
            while (true) {
                key_prng.fill(&secret);
                secp256k1.validate_secret_key(secret) catch continue;
                break;
            }
            const octet: u8 = @intCast(index);
            const record = try enr.build(secret, .{
                .ip4 = .{ 10, 0, octet, 1 },
                .udp = 9000,
                .tcp = 9222,
                .opstack = .{ .chain_id = chain_id },
            });
            cluster.prngs[index] = Prng.init(seed +% index);
            cluster.services[index] = try Service.init(allocator, .{
                .chain_id = chain_id,
                .lookup_interval_ns = 1000 * ns_per_ms,
                .table = .{ .subnet_bucket_max = 0, .subnet_table_max = 0 },
            }, secret, record, cluster.prngs[index].random());
        }
        return cluster;
    }

    fn deinit(cluster: *Cluster) void {
        for (cluster.services[0..cluster.node_count]) |*service| service.deinit(cluster.allocator);
        cluster.queue.deinit(cluster.allocator);
        cluster.allocator.destroy(cluster);
    }

    fn collect(cluster: *Cluster, from: u8, now_ns: u64) void {
        const service = &cluster.services[from];
        while (service.pop_outgoing()) |datagram| {
            cluster.trace.update(datagram.slice());
            const to = index_of(datagram.endpoint) orelse continue;
            if (to >= cluster.node_count) continue;
            if (cluster.network_prng.below(1_000_000) < cluster.drop_ppm) continue;
            if (cluster.queue.count() == in_flight_max) continue;
            var flight: Flight = .{
                .deliver_ns = now_ns + cluster.network_prng.range(1, 40) * ns_per_ms,
                .sequence = cluster.sequence,
                .from = from,
                .to = to,
                .length = datagram.length,
                .bytes = undefined,
            };
            @memcpy(flight.bytes[0..datagram.length], datagram.slice());
            cluster.sequence += 1;
            cluster.queue.push(cluster.allocator, flight) catch unreachable; // Capacity reserved.
        }
        while (service.pop_discovered()) |record| {
            for (cluster.services[0..cluster.node_count], 0..) |*other, index| {
                if (std.mem.eql(u8, &other.local_id, &record.node_id())) {
                    cluster.discovered[from][index] = true;
                }
            }
        }
    }

    fn run(cluster: *Cluster, duration_ns: u64) void {
        const step_ns = 10 * ns_per_ms;
        var now_ns: u64 = 0;
        while (now_ns < duration_ns) : (now_ns += step_ns) {
            while (cluster.queue.peek()) |flight| {
                if (flight.deliver_ns > now_ns) break;
                const due = cluster.queue.pop().?;
                const service = &cluster.services[due.to];
                service.on_packet(endpoint(due.from), due.bytes[0..due.length], due.deliver_ns);
                cluster.collect(due.to, now_ns);
            }
            for (0..cluster.node_count) |index| {
                cluster.services[index].tick(now_ns);
                cluster.collect(@intCast(index), now_ns);
            }
        }
    }

    fn boot_all_from(cluster: *Cluster, boot: u8) void {
        for (0..cluster.node_count) |index| {
            if (index == boot) continue;
            const service = &cluster.services[index];
            service.add_boot_record(&cluster.services[boot].local_record, 0);
            cluster.collect(@intCast(index), 0);
        }
    }

    fn discovered_fraction_min(cluster: *const Cluster) f64 {
        var minimum: f64 = 1.0;
        for (0..cluster.node_count) |index| {
            var count: u32 = 0;
            for (0..cluster.node_count) |other| {
                if (other != index and cluster.discovered[index][other]) count += 1;
            }
            const fraction = @as(f64, @floatFromInt(count)) /
                @as(f64, @floatFromInt(cluster.node_count - 1));
            minimum = @min(minimum, fraction);
        }
        return minimum;
    }
};

test "disc service: two nodes handshake and exchange records" {
    const cluster = try Cluster.init(std.testing.allocator, 1, 2, 0);
    defer cluster.deinit();
    cluster.boot_all_from(0);
    cluster.run(3000 * ns_per_ms);
    // One handshake per node: requests queued behind it never time out on a clean link.
    for (cluster.services[0..2]) |*service| {
        try std.testing.expectEqual(@as(u64, 0), service.stats.requests_timed_out);
    }
    try std.testing.expect(cluster.services[0].stats.handshakes_completed >= 1);
    try std.testing.expect(cluster.services[1].table.get(cluster.services[0].local_id) != null);
    try std.testing.expect(cluster.services[0].table.get(cluster.services[1].local_id) != null);
    try std.testing.expect(cluster.discovered[1][0]);
    try std.testing.expect(cluster.discovered[0][1]);
}

test "disc service: banned nodes are evicted and ignored until the ban expires" {
    const cluster = try Cluster.init(std.testing.allocator, 3, 2, 0);
    defer cluster.deinit();
    cluster.boot_all_from(0);
    cluster.run(1000 * ns_per_ms);
    const banned_id = cluster.services[1].local_id;
    try std.testing.expect(cluster.services[0].table.get(banned_id) != null);
    cluster.services[0].ban_node(banned_id, std.math.maxInt(u64));
    try std.testing.expect(cluster.services[0].table.get(banned_id) == null);
    try std.testing.expect(cluster.services[0].is_banned(banned_id, 0));
    cluster.run(6000 * ns_per_ms);
    try std.testing.expect(cluster.services[0].table.get(banned_id) == null);
    try std.testing.expect(cluster.services[0].stats.packets_banned > 0);
    // Re-banning keeps the later expiry; a short ban lapses.
    cluster.services[0].ban_node(banned_id, 10);
    try std.testing.expect(cluster.services[0].is_banned(banned_id, 11));
    const other_id: enr.NodeId = @splat(0x77);
    cluster.services[0].ban_node(other_id, 10);
    try std.testing.expect(cluster.services[0].is_banned(other_id, 9));
    try std.testing.expect(!cluster.services[0].is_banned(other_id, 10));
}

fn expect_convergence(node_count: u8, duration_ms: u64, live_min: u32) !void {
    const cluster = try Cluster.init(std.testing.allocator, 0x5eed, node_count, 20_000);
    defer cluster.deinit();
    cluster.boot_all_from(0);
    cluster.run(duration_ms * ns_per_ms);
    const fraction = cluster.discovered_fraction_min();
    if (fraction < 0.75) {
        std.debug.print("disc sim: min discovered fraction {d:.2}\n", .{fraction});
        return error.TestUnexpectedResult;
    }
    for (cluster.services[0..cluster.node_count]) |*service| {
        try std.testing.expect(service.table.live_count() >= live_min);
    }
}

test "disc service: simulated cluster converges through one boot node" {
    try expect_convergence(6, 6000, 3);
}

test "disc service: large simulated cluster converges (-Dslow-tests)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try expect_convergence(16, 20_000, 8);
}

test "disc service: 10% packet loss, retries keep every node discovered" {
    const cluster = try Cluster.init(std.testing.allocator, 0x1055, 6, 100_000);
    defer cluster.deinit();
    cluster.boot_all_from(0);
    cluster.run(8000 * ns_per_ms);
    var retried: u64 = 0;
    for (cluster.services[0..cluster.node_count]) |*service| {
        retried += service.stats.requests_retried;
        try std.testing.expect(service.table.live_count() >= 5);
    }
    try std.testing.expect(retried > 0);
    try std.testing.expect(cluster.discovered_fraction_min() >= 0.99);
}

test "disc service: same seed, same execution" {
    var hashes: [2]u64 = undefined;
    for (&hashes) |*hash| {
        const cluster = try Cluster.init(std.testing.allocator, 0xd57, 4, 50_000);
        defer cluster.deinit();
        cluster.boot_all_from(0);
        cluster.run(2000 * ns_per_ms);
        hash.* = cluster.trace.final();
    }
    try std.testing.expectEqual(hashes[0], hashes[1]);
}

test "disc service: rejects records for other chains and garbage packets" {
    var prng = Prng.init(7);
    var secret: secp256k1.SecretKey = @splat(0x21);
    secret[0] = 1;
    const local = try enr.build(secret, .{ .ip4 = .{ 10, 0, 0, 1 }, .udp = 9000 });
    const config: service_module.Config = .{ .chain_id = chain_id };
    var service = try Service.init(std.testing.allocator, config, secret, local, prng.random());
    defer service.deinit(std.testing.allocator);
    var other_secret: secp256k1.SecretKey = @splat(0x22);
    other_secret[0] = 1;
    const foreign = try enr.build(other_secret, .{
        .ip4 = .{ 10, 0, 1, 1 },
        .udp = 9000,
        .opstack = .{ .chain_id = 10 },
    });
    service.add_boot_record(&foreign, 0);
    try std.testing.expect(service.pop_discovered() == null);
    try std.testing.expect(service.pop_outgoing() != null);
    var garbage: [200]u8 = undefined;
    for (0..64) |_| {
        prng.fill(&garbage);
        service.on_packet(Cluster.endpoint(1), &garbage, 0);
    }
    try std.testing.expectEqual(@as(u64, 64), service.stats.packets_invalid);
}

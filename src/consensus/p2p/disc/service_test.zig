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
const messages = @import("messages.zig");
const session_module = @import("session.zig");
const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const chain_id = 8453;
const node_count_max = 24;
const in_flight_max = 4096;
const ns_per_ms = std.time.ns_per_ms;

const Flight = struct {
    deliver_ns: u64,
    sequence: u64,
    from: u8,
    from_port: u16,
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
    /// Port-translating NAT in front of one node: peers that sent to its advertised port
    /// get replies from that port (conntrack); everything else leaves from :9000.
    nat_index: ?u8 = null,
    nat_port: u16 = 0,
    nat_flows: [node_count_max]bool = @splat(false),

    fn endpoint(index: u8) Endpoint {
        return endpoint_port(index, 9000);
    }

    fn endpoint_port(index: u8, port: u16) Endpoint {
        return .{ .address = .{ .ip4 = .{ 10, 0, index, 1 } }, .port = port };
    }

    fn source_port(cluster: *Cluster, from: u8, to: u8, to_port: u16) u16 {
        const nat = cluster.nat_index orelse return 9000;
        if (to == nat and to_port == cluster.nat_port) cluster.nat_flows[from] = true;
        if (from == nat and cluster.nat_flows[to]) return cluster.nat_port;
        return 9000;
    }

    fn index_of(target: Endpoint) ?u8 {
        const address = switch (target.address) {
            .ip4 => |value| value,
            .ip6 => return null,
        };
        return address[2];
    }

    fn init(allocator: std.mem.Allocator, seed: u64, node_count: u8, drop_ppm: u32) !*Cluster {
        return init_nat(allocator, seed, node_count, drop_ppm, null);
    }

    /// `nat` makes one node advertise another UDP port than it sends from (port-translating
    /// NAT); the simulated network still delivers to it on either port.
    fn init_nat(
        allocator: std.mem.Allocator,
        seed: u64,
        node_count: u8,
        drop_ppm: u32,
        nat: ?struct { index: u8, port: u16 },
    ) !*Cluster {
        assert(node_count >= 2 and node_count <= node_count_max);
        const cluster = try allocator.create(Cluster);
        cluster.* = .{
            .allocator = allocator,
            .node_count = node_count,
            .network_prng = Prng.init(seed),
            .queue = .empty,
            .drop_ppm = drop_ppm,
        };
        if (nat) |value| {
            cluster.nat_index = value.index;
            cluster.nat_port = value.port;
        }
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
            const is_nat = if (nat) |value| value.index == index else false;
            const record = try enr.build(secret, .{
                .ip4 = .{ 10, 0, octet, 1 },
                .udp = if (is_nat) nat.?.port else 9000,
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
                .from_port = cluster.source_port(from, to, datagram.endpoint.port),
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
        cluster.run_at(0, duration_ns);
    }

    /// `run` starting at `start_ns` instead of zero, so time keeps moving across calls.
    fn run_at(cluster: *Cluster, start_ns: u64, duration_ns: u64) void {
        const step_ns = 10 * ns_per_ms;
        var now_ns: u64 = start_ns;
        while (now_ns < start_ns + duration_ns) : (now_ns += step_ns) {
            while (cluster.queue.peek()) |flight| {
                if (flight.deliver_ns > now_ns) break;
                const due = cluster.queue.pop().?;
                const service = &cluster.services[due.to];
                const source = endpoint_port(due.from, due.from_port);
                service.on_packet(source, due.bytes[0..due.length], due.deliver_ns);
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

test "disc service: a NAT-translated handshake record is verified by a ping, then added" {
    const cluster = try Cluster.init_nat(std.testing.allocator, 0x4a7, 3, 0, .{
        .index = 1,
        .port = 9100,
    });
    defer cluster.deinit();
    cluster.boot_all_from(0);
    cluster.run(3000 * ns_per_ms);
    const boot = &cluster.services[0];
    // Node 1's handshakes come from :9000 but its record says :9100.
    try std.testing.expect(boot.stats.unverifiable_enr >= 1);
    try std.testing.expect(boot.stats.unverifiable_enr_verified >= 1);
    const entry = boot.table.get(cluster.services[1].local_id).?;
    try std.testing.expectEqual(@as(u16, 9100), entry.endpoint.port);
    // It was forwarded for dialing either way.
    try std.testing.expect(cluster.discovered[0][1]);
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

// ------------------------------------------------------- hostile in-session messages
//
// Node 0 completes a real handshake with node 1, then uses its session keys to send node 1
// hostile messages that pass AES-GCM: junk plaintext, PINGs with huge sequence numbers,
// PONGs with spoofed endpoints, FINDNODE with junk distances, NODES answering node 1's real
// pending FINDNODE with bogus totals and junk, truncated, or foreign records, and TALK*.
// Node 1 must not crash, must not let invented nodes into its table, and must keep its
// honest peer (node 2) and keep discovering with it.

const attacker = 0;
const victim = 1;
const honest = 2;

/// The victim's live request to the attacker of `kind`, if any (a real request id to
/// answer, which reaches the response handlers instead of being dropped as unsolicited).
fn pending_to_attacker(cluster: *Cluster, kind: anytype) ?messages.RequestId {
    const attacker_id = cluster.services[attacker].local_id;
    for (cluster.services[victim].pending) |*pending| {
        if (!pending.used or pending.kind != kind) continue;
        if (!std.mem.eql(u8, &pending.node_id, &attacker_id)) continue;
        return pending.request_id;
    }
    return null;
}

fn random_request_id(random: std.Random) messages.RequestId {
    var id: messages.RequestId = .{ .length = random.uintAtMost(u8, 8) };
    random.bytes(id.bytes[0..id.length]);
    return id;
}

/// A NODES message with a bogus total and up to 20 junk, truncated, or valid foreign
/// records; `storage` backs the record bytes.
fn hostile_nodes(cluster: *Cluster, random: std.Random, storage: []u8) !messages.Message {
    const pending = pending_to_attacker(cluster, .findnode);
    // Answering a real request: mostly a valid total, so the records get examined.
    const bogus_total = random.uintLessThan(u8, if (pending != null) 8 else 2) == 0;
    var nodes: messages.Nodes = .{
        .request_id = pending orelse random_request_id(random),
        .total = if (!bogus_total)
            1 + random.uintAtMost(u64, 5)
        else if (random.boolean()) 0 else random.int(u64),
    };
    var used: usize = 0;
    const count = 1 + random.uintAtMost(u8, if (random.boolean()) 2 else messages.records_max - 1);
    for (0..count) |_| {
        var record_bytes: []const u8 = undefined;
        if (random.uintLessThan(u8, 3) == 0) {
            var secret: secp256k1.SecretKey = undefined;
            random.bytes(&secret);
            secp256k1.validate_secret_key(secret) catch continue;
            const record = try enr.build(secret, .{
                .ip4 = .{ 10, 9, random.int(u8), 1 },
                .udp = 9000,
                .opstack = .{ .chain_id = if (random.boolean()) chain_id else 10 },
            });
            const encoded = storage[used..][0..record.raw().len];
            @memcpy(encoded, record.raw());
            const truncate = random.boolean();
            const keep = if (truncate) random.uintAtMost(usize, encoded.len) else encoded.len;
            record_bytes = encoded[0..keep];
        } else {
            const length = random.uintAtMost(usize, 60);
            random.bytes(storage[used..][0..length]);
            record_bytes = storage[used..][0..length];
        }
        if (used + 400 > storage.len) break;
        used += record_bytes.len;
        nodes.records[nodes.records_count] = record_bytes;
        nodes.records_count += 1;
    }
    return .{ .nodes = nodes };
}

fn hostile_message(cluster: *Cluster, random: std.Random, storage: []u8) !messages.Message {
    if (pending_to_attacker(cluster, .findnode) != null and random.boolean()) {
        return hostile_nodes(cluster, random, storage);
    }
    return switch (random.uintLessThan(u8, 6)) {
        0 => .{ .ping = .{ .request_id = random_request_id(random), .enr_seq = random.int(u64) } },
        1 => .{ .pong = .{
            .request_id = pending_to_attacker(cluster, .ping) orelse random_request_id(random),
            .enr_seq = random.int(u64),
            .address = .{ .ip4 = .{ random.int(u8), 0, 0, 1 } },
            .port = random.int(u16),
        } },
        2 => blk: {
            var findnode: messages.Findnode = .{ .request_id = random_request_id(random) };
            findnode.distances_count = random.uintAtMost(u8, messages.distances_max);
            for (findnode.distances[0..findnode.distances_count]) |*distance| {
                distance.* = if (random.boolean()) random.uintAtMost(u16, 256) else random.int(u16);
            }
            break :blk .{ .findnode = findnode };
        },
        3, 4 => try hostile_nodes(cluster, random, storage),
        else => .{ .talkreq = .{
            .request_id = random_request_id(random),
            .protocol = storage[0..random.uintAtMost(usize, 32)],
            .request = storage[32..][0..random.uintAtMost(usize, 300)],
        } },
    };
}

/// Hostile plaintext: an encoded hostile message, or raw junk with a random type byte.
fn hostile_plaintext(cluster: *Cluster, random: std.Random, output: []u8) ![]const u8 {
    var storage: [8192]u8 = undefined;
    random.bytes(storage[0..512]);
    if (random.uintLessThan(u8, 5) == 0) {
        const length = random.uintAtMost(usize, 300) + 1;
        random.bytes(output[0..length]);
        output[0] = random.uintAtMost(u8, 8);
        return output[0..length];
    }
    const message = try hostile_message(cluster, random, &storage);
    return messages.encode(output, &message) catch |err| switch (err) {
        error.TooLarge => output[0..1], // Too many records for one packet: send a stub.
        else => return err,
    };
}

/// Seals `plaintext` with the attacker's real session to the victim and delivers it.
fn inject(cluster: *Cluster, random: std.Random, plaintext: []const u8, now_ns: u64) bool {
    const victim_service = &cluster.services[victim];
    const attacker_service = &cluster.services[attacker];
    const session = attacker_service.sessions.get(
        victim_service.local_id,
        Cluster.endpoint(victim),
    ) orelse return false;
    const nonce = session_module.next_nonce(session, random, now_ns) orelse return false;
    var outgoing: packet.Outgoing = .{
        .dest_id = victim_service.local_id,
        .masking_iv = undefined,
        .nonce = nonce,
        .authdata = .{ .message = attacker_service.local_id },
        .plaintext = plaintext,
        .key = session.write_key,
    };
    random.bytes(&outgoing.masking_iv);
    var buffer: [packet.size_max]u8 = undefined;
    const bytes = packet.encode(&buffer, &outgoing) catch return false; // Over the cap.
    victim_service.on_packet(Cluster.endpoint(attacker), bytes, now_ns);
    cluster.collect(victim, now_ns);
    return true;
}

test "disc service: hostile messages inside an established session" {
    const cluster = try Cluster.init(std.testing.allocator, 0x686f_7374, 3, 0);
    defer cluster.deinit();
    cluster.boot_all_from(victim);
    cluster.run_at(0, 3000 * ns_per_ms);
    const victim_service = &cluster.services[victim];
    const honest_id = cluster.services[honest].local_id;
    try std.testing.expect(victim_service.table.get(honest_id) != null);
    var prng = Prng.init(0x6469_7363);
    const random = prng.random();
    var now_ns: u64 = 3000 * ns_per_ms;
    var injected: u32 = 0;
    var plaintext: [packet.size_max]u8 = undefined;
    for (0..512) |round| {
        const bytes = try hostile_plaintext(cluster, random, &plaintext);
        if (inject(cluster, random, bytes, now_ns)) injected += 1;
        if (round % 16 == 15) {
            // Let replies, timeouts, and lookups (new pending requests to answer) run.
            cluster.run_at(now_ns, 250 * ns_per_ms);
            now_ns += 250 * ns_per_ms;
        }
    }
    cluster.run_at(now_ns, 5000 * ns_per_ms);
    // Most messages rode the authenticated session (it may be re-established midway).
    try std.testing.expect(injected > 256);
    // Junk records were counted and rejected; none of the invented nodes got in.
    try std.testing.expect(victim_service.stats.records_rejected > 0);
    try std.testing.expect(victim_service.table.live_count() <= 2);
    // The honest peer survived the attack and the two still talk.
    try std.testing.expect(victim_service.table.get(honest_id) != null);
    try std.testing.expect(cluster.services[honest].table.get(victim_service.local_id) != null);
}

const SessionFixture = struct {
    cluster: *Cluster,
    prng: Prng,
    now_ns: u64,
};

fn fuzz_session_plaintext(fixture: *SessionFixture, input: []const u8) anyerror!void {
    if (input.len == 0) return;
    const random = fixture.prng.random();
    fixture.now_ns += ns_per_ms;
    _ = inject(fixture.cluster, random, input[0..@min(input.len, 1100)], fixture.now_ns);
    const victim_service = &fixture.cluster.services[victim];
    // Invented nodes may be learned (sigp discv5 does too) but never become live.
    try std.testing.expect(victim_service.table.live_count() <= 2);
}

test "disc service: fuzz plaintext sealed into an established session" {
    const cluster = try Cluster.init(std.testing.allocator, 0x7365_7373, 3, 0);
    defer cluster.deinit();
    cluster.boot_all_from(victim);
    cluster.run_at(0, 3000 * ns_per_ms);
    var fixture: SessionFixture = .{
        .cluster = cluster,
        .prng = Prng.init(0x7365),
        .now_ns = 3000 * ns_per_ms,
    };
    try fuzz.run_bytes(&fixture, fuzz_session_plaintext, .{
        .input_size_max = 1100,
        .corpus = &.{ "\x01\xc6\x84\x00\x00\x00\x01\x01", "\x04\xc5\x80\x05\xc2\x80\x80" },
    });
    // The honest node is still known after every input.
    const honest_id = cluster.services[honest].local_id;
    try std.testing.expect(cluster.services[victim].table.get(honest_id) != null);
}

//! p2p.Service tests: a seeded in-memory network of services. Datagrams are delivered
//! instantly, dial commands become simulated libp2p connections, and gossip frames move
//! between connection slots. Checks discovery -> dial -> mesh -> block delivery, and the
//! score-based ban path.

const std = @import("std");
const assert = std.debug.assert;
const service_module = @import("service.zig");
const disc = @import("disc/root.zig");
const enr = @import("peers/enr.zig");
const multiaddr = @import("peers/multiaddr.zig");
const peer_id = @import("peers/peer_id.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const rpc = @import("gossip/rpc.zig");
const ssz = @import("gossip/ssz_payload.zig");
const validity = @import("gossip/validity.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus_types = @import("../../common/consensus/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Service = service_module.Service;
const Slot = service_module.Slot;
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;
const chain_id = 8453;
const nodes = 4;
const start_s: u64 = 2_000_000;

const Link = struct { a: usize, slot_a: Slot, b: usize, slot_b: Slot };

const Net = struct {
    rollup: rollup_config.RollupConfig,
    sequencer_secret: [32]u8,
    services: [nodes]*Service,
    prngs: [nodes]Prng,
    records: [nodes]enr.Record,
    links: [64]Link = undefined,
    links_count: usize = 0,
    buffer: []u8,
    now_ns: u64 = start_s * ns_per_s,
    tx_storage: [512]u8 = undefined,

    fn init(net: *Net) !void {
        const allocator = std.testing.allocator;
        net.links_count = 0;
        net.now_ns = start_s * ns_per_s;
        net.rollup = .{ .l2_chain_id = chain_id };
        net.rollup.upgrades.set(.ecotone, 0);
        net.sequencer_secret = @splat(0);
        net.sequencer_secret[31] = 5;
        const signer: primitives.Address = .{
            .bytes = try common_secp256k1.address(net.sequencer_secret),
        };
        net.buffer = try allocator.alloc(u8, 1 << 20);
        var key_prng = Prng.init(0x7365_7276);
        for (0..nodes) |index| {
            var secret: secp256k1.SecretKey = undefined;
            while (true) {
                key_prng.fill(&secret);
                secp256k1.validate_secret_key(secret) catch continue;
                break;
            }
            net.records[index] = try enr.build(secret, .{
                .ip4 = .{ 10, 0, @intCast(index), 1 },
                .udp = 9000,
                .tcp = 9222,
                .opstack = .{ .chain_id = chain_id },
            });
            net.prngs[index] = Prng.init(index + 11);
            net.services[index] = try Service.create(allocator, .{
                .rollup = &net.rollup,
                .unsafe_block_signer = signer,
                .disc = .{
                    .chain_id = chain_id,
                    .lookup_interval_ns = 1000 * ns_per_ms,
                    .table = .{ .subnet_bucket_max = 0, .subnet_table_max = 0 },
                },
                .mcache = .{ .entries_max = 64, .arena_bytes = 1 << 20 },
                .accepted_bytes = 1 << 20,
                .ban_enabled = true,
            }, secret, net.records[index], net.prngs[index].random());
        }
        for (1..nodes) |index| net.services[index].add_boot_record(&net.records[0], net.now_ns);
    }

    fn deinit(net: *Net) void {
        for (net.services) |service| service.destroy(std.testing.allocator);
        std.testing.allocator.free(net.buffer);
    }

    fn node_of_address(net: *const Net, address: [4]u8) ?usize {
        for (&net.records, 0..) |*record, index| {
            if (std.mem.eql(u8, &record.ip4().?, &address)) return index;
        }
        return null;
    }

    fn deliver_datagrams(net: *Net) void {
        for (0..nodes) |from| {
            while (net.services[from].pop_datagram()) |datagram| {
                const to = net.node_of_address(datagram.endpoint.address.ip4) orelse continue;
                const source: disc.table.Endpoint = .{
                    .address = .{ .ip4 = net.records[from].ip4().? },
                    .port = 9000,
                };
                net.services[to].on_datagram(source, datagram.slice(), net.now_ns);
            }
        }
    }

    fn execute_commands(net: *Net) !void {
        for (0..nodes) |from| {
            while (net.services[from].pop_command()) |command| switch (command) {
                .dial => |address| try net.connect(from, &address),
                .disconnect => |slot| net.disconnect(from, slot),
            };
        }
    }

    fn connect(net: *Net, from: usize, address: *const multiaddr.Multiaddr) !void {
        const remote_peer = address.peer().?;
        const to = for (&net.records, 0..) |*record, index| {
            const peer = peer_id.from_public_key(record.public_key);
            if (peer.eql(&remote_peer)) break index;
        } else unreachable;
        const local_peer = peer_id.from_public_key(net.records[from].public_key);
        const from_ip: @import("peers/ip.zig").Address = .{ .ip4 = net.records[from].ip4().? };
        if (!net.services[to].reserve_inbound(from_ip)) {
            net.services[from].on_dial_failed(address);
            return;
        }
        const listener = net.services[to];
        const slot_b = listener.on_connected(local_peer, .inbound, from_ip, net.now_ns) catch {
            net.services[from].on_dial_failed(address);
            return;
        };
        const to_ip: @import("peers/ip.zig").Address = .{ .ip4 = net.records[to].ip4().? };
        const dialer = net.services[from];
        const slot_a = try dialer.on_connected(remote_peer, .outbound, to_ip, net.now_ns);
        net.links[net.links_count] = .{ .a = from, .slot_a = slot_a, .b = to, .slot_b = slot_b };
        net.links_count += 1;
    }

    fn disconnect(net: *Net, node: usize, slot: Slot) void {
        for (net.links[0..net.links_count], 0..) |link, index| {
            const match = (link.a == node and link.slot_a == slot) or
                (link.b == node and link.slot_b == slot);
            if (!match) continue;
            net.services[link.a].on_disconnected(link.slot_a, net.now_ns);
            net.services[link.b].on_disconnected(link.slot_b, net.now_ns);
            net.links_count -= 1;
            net.links[index] = net.links[net.links_count];
            return;
        }
    }

    fn pump_gossip(net: *Net) void {
        var rounds: u32 = 0;
        while (rounds < 32) : (rounds += 1) {
            var moved = false;
            for (net.links[0..net.links_count]) |link| {
                moved = net.move(link.a, link.slot_a, link.b, link.slot_b) or moved;
                moved = net.move(link.b, link.slot_b, link.a, link.slot_a) or moved;
            }
            if (!moved) return;
        }
    }

    fn move(net: *Net, from: usize, from_slot: Slot, to: usize, to_slot: Slot) bool {
        const frame = net.services[from].drain_gossip(from_slot, net.buffer) orelse return false;
        const header = (rpc.frame_decode(frame, rpc.frame_size_max_default) catch unreachable).?;
        net.services[to].on_gossip_frame(to_slot, header.payload, net.now_ns);
        return true;
    }

    fn step(net: *Net, duration_ns: u64) !void {
        net.now_ns += duration_ns;
        for (net.services) |service| service.tick(net.now_ns);
        var rounds: u32 = 0;
        while (rounds < 8) : (rounds += 1) {
            net.deliver_datagrams();
            try net.execute_commands();
        }
        net.pump_gossip();
    }

    fn payload(net: *Net, number: u64) !ssz.ExecutionPayload {
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
        const encoded = deposit.encode_to(net.tx_storage[256..]);
        var result: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = number,
            .timestamp = net.now_ns / ns_per_s,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = ssz.Transactions.encode(net.tx_storage[0..256], &.{encoded}),
        };
        result.block_hash = try validity.block_hash(&net.rollup, &result, beacon_root);
        return result;
    }
};

const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };

test "p2p service: discovery, dialing, and block gossip end to end" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..12) |_| try net.step(500 * ns_per_ms);
    for (net.services) |service| try std.testing.expect(service.connected_count() >= 2);
    const value = try net.payload(42);
    _ = try net.services[1].publish_block(net.sequencer_secret, beacon_root, value, net.now_ns);
    net.pump_gossip();
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (net.services, 0..) |service, index| {
        if (index == 1) continue;
        const envelope = service.pop_block(scratch) orelse return error.BlockNotDelivered;
        try std.testing.expectEqual(@as(u64, 42), envelope.payload.block_number);
        // Validation decoded the bytes the message-id hash had already decompressed.
        try std.testing.expect(service.gossip.stats.decompress_reused >= 1);
    }
}

test "p2p service: republishing a block or many blocks at one height does not crash" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..12) |_| try net.step(500 * ns_per_ms);
    const sequencer = net.services[1];
    const value = try net.payload(42);
    // The same block again and again (a retrying sequencer).
    for (0..8) |_| {
        _ = sequencer.publish_block(net.sequencer_secret, beacon_root, value, net.now_ns) catch {};
        net.pump_gossip();
    }
    // Distinct blocks at one height, more than the seen table keeps per height.
    for (0..8) |index| {
        var other = value;
        other.gas_limit += index + 1;
        other.block_hash = try validity.block_hash(&net.rollup, &other, beacon_root);
        _ = sequencer.publish_block(net.sequencer_secret, beacon_root, other, net.now_ns) catch {};
        net.pump_gossip();
    }
    // The original block still reached every other node.
    const scratch = try std.testing.allocator.alloc(u8, 10 << 20);
    defer std.testing.allocator.free(scratch);
    for (net.services, 0..) |service, index| {
        if (index == 1) continue;
        const envelope = service.pop_block(scratch) orelse return error.BlockNotDelivered;
        try std.testing.expect(envelope.payload.block_hash.eql(value.block_hash));
    }
}

test "p2p service: peers under the ban threshold are disconnected and banned" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..12) |_| try net.step(500 * ns_per_ms);
    const service = net.services[0];
    const link = for (net.links[0..net.links_count]) |link| {
        if (link.a == 0 or link.b == 0) break link;
    } else return error.NoLink;
    const slot = if (link.a == 0) link.slot_a else link.slot_b;
    const other = if (link.a == 0) link.b else link.a;
    service.gossip.router.peer(slot).counters.behaviour_penalty = 1000;
    const before = service.connected_count();
    try net.step(16 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 1), service.stats.banned);
    try std.testing.expect(service.connected_count() < before);
    const banned_id = net.records[other].node_id();
    try std.testing.expect(service.discovery.is_banned(banned_id, net.now_ns));
}

test "p2p service: protected peers are never score-banned" {
    const net = try std.testing.allocator.create(Net);
    defer std.testing.allocator.destroy(net);
    try net.init();
    defer net.deinit();
    for (0..12) |_| try net.step(500 * ns_per_ms);
    const service = net.services[0];
    const link = for (net.links[0..net.links_count]) |link| {
        if (link.a == 0 or link.b == 0) break link;
    } else return error.NoLink;
    const slot = if (link.a == 0) link.slot_a else link.slot_b;
    try std.testing.expect(service.gater.protect_peer(service.connected[slot].peer));
    service.gossip.router.peer(slot).counters.behaviour_penalty = 1000;
    const before = service.connected_count();
    try net.step(16 * ns_per_s);
    try std.testing.expectEqual(@as(u64, 0), service.stats.banned);
    try std.testing.expectEqual(before, service.connected_count());
}

test "p2p service: a protected peer connects past the established limit" {
    var fixture: @import("rpc_test.zig").Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const service = fixture.service;
    service.limits.limits.established_max = 2; // Two peers are already connected.
    var secret: [32]u8 = @splat(0);
    secret[31] = 50;
    const extra = peer_id.from_public_key(try secp256k1.public_key(secret));
    try std.testing.expect(service.reserve_inbound(null));
    const refused = service.on_connected(extra, .inbound, null, 0);
    try std.testing.expectError(error.EstablishedLimit, refused);
    try std.testing.expect(service.gater.protect_peer(extra));
    try std.testing.expect(service.reserve_inbound(null));
    _ = try service.on_connected(extra, .inbound, null, 0);
    try std.testing.expectEqual(@as(u32, 3), service.connected_count());
}

fn count_of(service: *const Service, reason: service_module.DialError) u64 {
    return service.stats.dial_errors[@backingInt(reason)];
}

test "p2p service: dial and inbound refusals are counted by base/base reason" {
    var fixture: @import("rpc_test.zig").Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const service = fixture.service;
    var secret: [32]u8 = @splat(0);
    secret[31] = 60;
    const record = try enr.build(secret, .{
        .ip4 = .{ 10, 9, 0, 1 },
        .tcp = 9222,
        .opstack = .{ .chain_id = chain_id },
    });
    const address = multiaddr.from_enr(&record).?;
    const peer = address.peer().?;
    // Without a peer id the gater cannot key the dial.
    service.dial(&try multiaddr.parse("/ip4/10.9.0.1/tcp/9222"), 0);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .invalid_multiaddr));
    // A dial already in flight, then a failed dial.
    service.dial(&address, 0);
    try std.testing.expectEqual(@as(u64, 1), service.stats.dials);
    service.dial(&address, 0);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .already_dialing));
    service.on_dial_failed(&address);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .connection_error));
    // Blocked subnet, then blocked peer (checked first).
    const subnet = try @import("rpc.zig").parse_subnet("10.9.0.0/16");
    try std.testing.expect(service.gater.block_subnet(subnet));
    service.dial(&address, 0);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .blocked_subnet));
    try std.testing.expect(service.gater.block_peer(peer));
    service.dial(&address, 0);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .blocked_peer));
    // Already connected: fixture peer 1 (secret 21) is connected.
    var connected_secret: [32]u8 = @splat(0);
    connected_secret[31] = 21;
    const connected_record = try enr.build(connected_secret, .{
        .ip4 = .{ 10, 8, 0, 1 },
        .tcp = 9222,
        .opstack = .{ .chain_id = chain_id },
    });
    service.dial(&multiaddr.from_enr(&connected_record).?, 0);
    try std.testing.expectEqual(@as(u64, 1), count_of(service, .already_connected));
    // Inbound: a blocked address is refused before the handshake and counted.
    const blocked: @import("peers/ip.zig").Address = .{ .ip4 = .{ 10, 7, 0, 1 } };
    try std.testing.expect(service.gater.block_address(blocked));
    try std.testing.expect(!service.reserve_inbound(blocked));
    const inbound = service.stats.inbound_errors;
    const reason = service_module.InboundError.blocked_address;
    try std.testing.expectEqual(@as(u64, 1), inbound[@backingInt(reason)]);
    try std.testing.expectEqual(@as(u64, 1), service.stats.inbound_refused);
}

fn dials_to(service: *Service, peer: peer_id.PeerId) u32 {
    var count: u32 = 0;
    while (service.pop_command()) |command| switch (command) {
        .dial => |address| count += @intFromBool(address.peer().?.eql(&peer)),
        .disconnect => {},
    };
    return count;
}

test "p2p service: known unconnected nodes are redialed only when enabled" {
    var fixture: @import("rpc_test.zig").Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const service = fixture.service;
    // On this chain and unconnected, on another chain, and already connected (secret 21).
    const secrets = [_]u8{ 61, 62, 21 };
    const chains = [_]u64{ chain_id, 10, chain_id };
    var peers: [3]peer_id.PeerId = undefined;
    var addresses: [3]multiaddr.Multiaddr = undefined;
    for (secrets, chains, &peers, &addresses, 0..) |byte, chain, *peer, *address, index| {
        var secret: [32]u8 = @splat(0);
        secret[31] = byte;
        const record = try enr.build(secret, .{
            .ip4 = .{ 10, 6, @intCast(index), 1 },
            .tcp = 9222,
            .udp = 9223,
            .opstack = .{ .chain_id = chain },
        });
        const endpoint = disc.service.Service.endpoint_of(&record).?;
        _ = service.discovery.table.insert(&record, endpoint, 0);
        peer.* = peer_id.from_public_key(record.public_key);
        address.* = multiaddr.from_enr(&record).?;
    }
    // Off (base/base): nodes already in the table are never dialed again.
    service.tick(1 * ns_per_s);
    service.tick(30 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 0), dials_to(service, peers[0]));
    service.config.redial_known_interval_ns = 10 * ns_per_s;
    service.tick(31 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), dials_to(service, peers[0]));
    try std.testing.expectEqual(@as(u64, 1), service.stats.redials);
    // A busy peer refused us; the next attempt waits for the interval.
    service.on_dial_failed(&addresses[0]);
    service.tick(35 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 0), dials_to(service, peers[0]));
    service.tick(41 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), dials_to(service, peers[0]));
    // The other chain's node and the connected peer were never dialed.
    try std.testing.expectEqual(@as(u64, 2), service.stats.redials);
    try std.testing.expectEqual(@as(u64, 0), count_of(service, .already_connected));
}

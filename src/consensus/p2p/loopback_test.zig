//! Real-socket interop: two full p2p `Network`s on the OS IO backend (kqueue on macOS,
//! io_uring on Linux) over 127.0.0.1. Each node knows only the other's ENR (never the
//! chain's default bootnodes, so no traffic leaves the host); they must find each other
//! through discv5 over real UDP (`recvfrom`/`sendto` completions), connect over libp2p on
//! real TCP, and both must gossip a signed block. Ports are picked by binding ephemeral
//! sockets first, so the test never collides with a running devnet or a parallel suite.
//! Stopping must drain every UDP completion (`Network.busy`) before `deinit`.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const network_module = @import("network.zig");
const options_module = @import("options.zig");
const enr = @import("peers/enr.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const ssz = @import("gossip/ssz_payload.zig");
const validity = @import("gossip/validity.zig");
const primitives = @import("../../common/primitives/root.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const testing = std.testing;
const IO = io_module.IO;
const Network = network_module.Network(IO);
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;
const chain_id = 8453;
const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };
/// Wall-clock budget for discovery plus connection; SimIo needs ~2 s of virtual time.
const connect_deadline_ns = 20 * ns_per_s;

const Ports = struct { tcp: u16, udp: u16 };
const Family = io_module.Address.Family;
const ip6_loopback: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

fn loopback(family: Family, port: u16) io_module.Address {
    return switch (family) {
        .ip4 => io_module.Address.loopback(port),
        .ip6 => io_module.Address.ip6(ip6_loopback, port),
    };
}

/// Ephemeral TCP and UDP ports the kernel just handed out (then released).
fn free_ports(io: *IO, family: Family) !Ports {
    const tcp_fd = try io.open_socket_tcp(family);
    defer io.close_now(tcp_fd);
    const tcp = try io.listen(tcp_fd, loopback(family, 0), 1);
    const udp_fd = try io.open_socket_udp(family);
    defer io.close_now(udp_fd);
    const udp = try io.bind_udp(udp_fd, loopback(family, 0));
    assert(tcp.port != 0 and udp.port != 0);
    return .{ .tcp = tcp.port, .udp = udp.port };
}

const Pair = struct {
    io: IO,
    family: Family,
    networks: [2]Network,
    prngs: [2]Prng,
    secrets: [2]secp256k1.SecretKey,
    ports: [2]Ports,
    rollup: rollup_config.RollupConfig,
    sequencer_key: [32]u8,
    signer: primitives.Address,
    /// `Options` borrows its argument strings, so they live as long as the networks.
    flags: [2][3][64]u8,
    boot_flags: [2][enr.text_length_max + 16]u8,

    fn init(pair: *Pair, family: Family) !void {
        pair.family = family;
        pair.io = try io_module.init_for_test();
        errdefer pair.io.deinit();
        pair.rollup = .{ .l2_chain_id = chain_id, .block_time = 2 };
        pair.rollup.upgrades.set(.ecotone, 0);
        pair.sequencer_key = @splat(0);
        pair.sequencer_key[31] = 5;
        pair.signer = .{ .bytes = try common_secp256k1.address(pair.sequencer_key) };
        pair.secrets = .{ @splat(0), @splat(0) };
        pair.secrets[0][31] = 3;
        pair.secrets[1][31] = 4;
        pair.prngs = .{ Prng.init(1), Prng.init(2) };
        for (&pair.ports) |*ports| ports.* = try free_ports(&pair.io, family);
        try pair.init_network(0);
        errdefer pair.networks[0].deinit(testing.allocator);
        try pair.init_network(1);
        errdefer pair.networks[1].deinit(testing.allocator);
        for (&pair.networks) |*network| _ = try network.start();
    }

    fn init_network(pair: *Pair, index: usize) !void {
        const ports = pair.ports[index];
        var arguments: [4][]const u8 = undefined;
        arguments[0] = switch (pair.family) {
            .ip4 => "--p2p.listen.ip=127.0.0.1",
            .ip6 => "--p2p.listen.ip=::1",
        };
        arguments[1] = try std.fmt.bufPrint(&pair.flags[index][0], "--p2p.listen.tcp={d}", .{
            ports.tcp,
        });
        arguments[2] = try std.fmt.bufPrint(&pair.flags[index][1], "--p2p.listen.udp={d}", .{
            ports.udp,
        });
        const other = 1 - index;
        var fields: enr.Fields = .{
            .tcp = pair.ports[other].tcp,
            .udp = pair.ports[other].udp,
            .opstack = .{ .chain_id = chain_id },
        };
        switch (pair.family) {
            .ip4 => fields.ip4 = .{ 127, 0, 0, 1 },
            .ip6 => fields.ip6 = ip6_loopback,
        }
        const boot = try enr.build(pair.secrets[other], fields);
        var text: [enr.text_length_max]u8 = undefined;
        arguments[3] = try std.fmt.bufPrint(&pair.boot_flags[index], "--p2p.bootnodes={s}", .{
            enr.encode_text(&text, &boot),
        });
        const options = try options_module.parse(&arguments);
        try pair.networks[index].init(
            testing.allocator,
            &pair.io,
            &pair.rollup,
            options,
            pair.secrets[index],
            pair.signer,
            pair.prngs[index].random(),
            index,
        );
    }

    fn deinit(pair: *Pair) void {
        for (&pair.networks) |*network| network.stop();
        var rounds: u32 = 0;
        while (pair.networks[0].busy() or pair.networks[1].busy()) : (rounds += 1) {
            assert(rounds < 2000); // Canceled UDP completions return promptly.
            pair.io.run_for_ns(ns_per_ms) catch break;
        }
        for (&pair.networks) |*network| network.deinit(testing.allocator);
        pair.io.deinit();
    }

    /// Runs the real event loop for up to `duration_ns` of wall-clock time.
    fn run(pair: *Pair, duration_ns: u64) !void {
        const start = pair.io.now_realtime_ns();
        while (pair.io.now_realtime_ns() - start < duration_ns) {
            try pair.io.run_for_ns(5 * ns_per_ms);
            for (&pair.networks) |*network| network.transport.execute_commands();
        }
    }

    /// Connected over libp2p and a discv5 handshake completed on each side (a UDP round
    /// trip both ways: boot ENRs are also dialed over TCP, so a connection alone does not
    /// prove discovery works).
    fn connected(pair: *const Pair) bool {
        for (&pair.networks) |*network| {
            if (network.peer_count() != 1) return false;
            if (network.service.discovery.stats.handshakes_completed == 0) return false;
        }
        return true;
    }

    fn payload(pair: *Pair, number: u64, variant: u64) !ssz.ExecutionPayload {
        var result: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = number,
            .timestamp = pair.io.now_realtime_ns() / ns_per_s,
            .gas_limit = 30_000_000 + variant,
            .base_fee_per_gas = 1,
            .extra_data = "base",
        };
        result.block_hash = try validity.block_hash(&pair.rollup, &result, beacon_root);
        return result;
    }

    /// Publishes from `from` until the other node pops a block at `number` (up to 10
    /// tries, 0.5 s apart). Each try is a distinct block: a republished one is a gossip
    /// duplicate, so it would never be sent again if the mesh was still forming.
    fn deliver(pair: *Pair, from: usize, number: u64, scratch: []u8) !void {
        for (0..10) |variant| {
            const sent = try pair.payload(number, variant);
            const network = &pair.networks[from];
            _ = try network.publish_block(pair.sequencer_key, beacon_root, sent);
            try pair.run(500 * ns_per_ms);
            while (pair.networks[1 - from].pop_block(scratch)) |envelope| {
                if (envelope.payload.block_number == number) return;
            }
        }
        return error.BlockNotDelivered;
    }
};

test "p2p loopback: real UDP discovery, TCP libp2p, and gossip on the OS IO backend" {
    try expect_loopback(.ip4);
}

test "p2p loopback: the same over IPv6 (::1)" {
    try expect_loopback(.ip6);
}

fn expect_loopback(family: Family) !void {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    try pair.init(family);
    defer pair.deinit();
    const start = pair.io.now_realtime_ns();
    while (!pair.connected()) {
        if (pair.io.now_realtime_ns() - start > connect_deadline_ns) {
            return error.NotConnected;
        }
        try pair.run(100 * ns_per_ms);
    }
    for (&pair.networks) |*network| {
        // Discovery ran over real datagrams in both directions.
        try testing.expect(network.transport.stats.datagrams_received > 0);
        try testing.expect(network.transport.stats.datagrams_sent > 0);
        try testing.expectEqual(@as(u64, 0), network.transport.stats.datagram_receive_errors);
    }
    const scratch = try testing.allocator.alloc(u8, 10 << 20);
    defer testing.allocator.free(scratch);
    try pair.deliver(0, 7, scratch);
    try pair.deliver(1, 8, scratch);
}

//! `base el-peers`: finds execution-layer peers of a Base chain over discv4
//! (`execution.p2p.discv4`), with no RPC. It bonds (Ping/Pong) with the chain's bootnodes,
//! walks the table with FindNode, asks every node it bonds with for its ENR, and prints the
//! nodes whose fork id carries the wanted fork hash, as enodes for `base el-fetch`. Base nodes
//! advertise their fork id under the `opel` ENR key (EIP-868) and discovery reads it before
//! `eth`; so does this.
//!
//!     base el-peers [--chain base-sepolia|base-mainnet] [--duration <s>]
//!                   [--fork-hash <8 hex digits>] [--port <udp port>] [--seed <enode>]...
//!                   [--peers <file>]
//!
//! `--peers` seeds the crawl with the file's enodes (walked as hard as the bootnodes: a
//! chain's nodes know more of it) and appends every newly found node to the file, which
//! `el-run --peers` re-reads every minute.
//! The discv4 table is shared by every Ethereum-family network, so most nodes found are
//! other chains; the fork hash filter keeps the chain's own. Without `--fork-hash` every
//! node with an `eth` entry is printed with its fork hash. A printed node is only a
//! candidate: `el-fetch` checks its network id and genesis in Status.

const std = @import("std");
const base = @import("base");

const discv4 = base.execution.p2p.discv4;
const enode = base.consensus.p2p.peers.enode;
const enr = base.consensus.p2p.peers.enr;
const curve = base.common.crypto.secp256k1;
const Io = std.Io;
const assert = std.debug.assert;

const usage =
    \\usage: base el-peers [--chain base-sepolia|base-mainnet] [--duration <s>]
    \\                     [--fork-hash <8 hex digits>] [--port <udp port>] [--seed <enode>]...
    \\                     [--peers <file>]
    \\
;

const nodes_max = 1 << 17;
/// Largest peer file read or written.
const peers_file_bytes_max = 64 * 1024;
/// Distinct fork hashes counted for the summary.
const forks_max = 64;
/// New pings per loop pass: keeps the send rate near 50 packets per 100 ms.
const pings_per_pass = 16;
/// FindNode rounds per bonded node, each for a fresh random target. The chain's bootnodes
/// get many more: every node of the chain bonds with them, so their tables hold it.
const lookups_per_node = 3;
const lookups_per_bootnode = 64;

const Flags = struct {
    chain: *const base.common.chains.ChainConfig = &base.common.chains.sepolia,
    duration_s: u64 = 120,
    fork_hash: ?[4]u8 = null,
    port: u16 = 0,
    /// Known peers to seed from; every newly found one is appended.
    peers: ?[]const u8 = null,
    /// Extra starting nodes, ahead of the bootnodes (for example a known peer list).
    seeds: [seeds_max][]const u8 = undefined,
    seeds_count: usize = 0,
};

const seeds_max = 16;

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 2) {
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--duration")) {
            flags.duration_s = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--port")) {
            flags.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, name, "--fork-hash")) {
            var hash: [4]u8 = undefined;
            if (value.len != 8) return error.InvalidArguments;
            _ = try std.fmt.hexToBytes(&hash, value);
            flags.fork_hash = hash;
        } else if (std.mem.eql(u8, name, "--peers")) {
            flags.peers = value;
        } else if (std.mem.eql(u8, name, "--seed")) {
            if (flags.seeds_count == seeds_max) return error.InvalidArguments;
            flags.seeds[flags.seeds_count] = value;
            flags.seeds_count += 1;
        } else if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = if (std.mem.eql(u8, value, "base-mainnet"))
                &base.common.chains.mainnet
            else
                &base.common.chains.sepolia;
        } else return error.InvalidArguments;
    }
    if (index != args.len or flags.duration_s == 0) return error.InvalidArguments;
    return flags;
}

const Node = struct {
    id: discv4.PublicKey,
    address: Io.net.IpAddress,
    tcp: u16,
    pinged: bool = false,
    ponged: bool = false,
    pinged_us: bool = false,
    lookups: u8 = 0,
    lookups_max: u8 = lookups_per_node,
    enr_requests: u8 = 0,
    enr_received: bool = false,
    enr_hash: [32]u8 = @splat(0),
    printed: bool = false,
};

const Crawler = struct {
    io: Io,
    socket: Io.net.Socket,
    secret: [32]u8,
    flags: *const Flags,
    nodes: []Node,
    index: std.AutoHashMapUnmanaged(discv4.PublicKey, u32) = .empty,
    forks: [forks_max]struct { hash: [4]u8, count: u32 } = undefined,
    forks_count: usize = 0,
    count: usize = 0,
    next_ping: usize = 0,
    found: u32 = 0,
    enrs: u32 = 0,
    other_chain: u32 = 0,
    opel: u32 = 0,

    fn find(crawler: *Crawler, id: *const discv4.PublicKey) ?*Node {
        const slot = crawler.index.get(id.*) orelse return null;
        assert(slot < crawler.count);
        return &crawler.nodes[slot];
    }

    fn add(crawler: *Crawler, id: discv4.PublicKey, address: Io.net.IpAddress, tcp: u16) void {
        if (crawler.find(&id) != null or crawler.count == crawler.nodes.len) return;
        crawler.nodes[crawler.count] = .{ .id = id, .address = address, .tcp = tcp };
        // Capacity for every node was reserved at startup.
        crawler.index.putAssumeCapacity(id, @intCast(crawler.count));
        crawler.count += 1;
    }

    fn count_fork(crawler: *Crawler, hash: [4]u8) void {
        for (crawler.forks[0..crawler.forks_count]) |*fork| {
            if (std.mem.eql(u8, &fork.hash, &hash)) {
                fork.count += 1;
                return;
            }
        }
        if (crawler.forks_count == forks_max) return;
        crawler.forks[crawler.forks_count] = .{ .hash = hash, .count = 1 };
        crawler.forks_count += 1;
    }

    fn expiration(crawler: *const Crawler) u64 {
        const now = Io.Clock.real.now(crawler.io);
        return @as(u64, @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_s))) + 20;
    }

    fn send(crawler: *Crawler, node: *const Node, packet_type: discv4.Type, data: []const u8) void {
        var wire: [discv4.packet_size_max]u8 = undefined;
        const packet = discv4.encode(crawler.secret, packet_type, data, &wire) catch return;
        // A lost datagram is the protocol's normal case; the crawl moves on.
        crawler.socket.send(crawler.io, &node.address, packet) catch {};
    }

    fn ping(crawler: *Crawler, node: *Node) void {
        var data: [128]u8 = undefined;
        const from: discv4.Endpoint = .{ .ip = &.{ 0, 0, 0, 0 }, .udp = 0, .tcp = 0 };
        var ip_buffer: [16]u8 = undefined;
        const to = endpoint_of(&node.address, node.tcp, &ip_buffer);
        const message = discv4.encode_ping(&data, from, to, crawler.expiration()) catch return;
        crawler.send(node, .ping, message);
        node.pinged = true;
    }

    fn lookup(crawler: *Crawler, node: *Node) void {
        if (node.lookups >= node.lookups_max) return;
        var target: discv4.PublicKey = undefined;
        crawler.io.random(&target);
        var data: [96]u8 = undefined;
        const message = discv4.encode_find_node(&data, &target, crawler.expiration()) catch
            return;
        crawler.send(node, .find_node, message);
        node.lookups += 1;
    }

    fn request_enr(crawler: *Crawler, node: *Node) void {
        // Nodes answer only once they hold our Pong to their Ping (endpoint proof).
        if (node.enr_received or node.enr_requests >= 2) return;
        if (!node.ponged or !node.pinged_us) return;
        var data: [16]u8 = undefined;
        const message = discv4.encode_enr_request(&data, crawler.expiration()) catch return;
        var wire: [discv4.packet_size_max]u8 = undefined;
        const packet = discv4.encode(crawler.secret, .enr_request, message, &wire) catch return;
        node.enr_hash = packet[0..32].*;
        node.enr_requests += 1;
        crawler.socket.send(crawler.io, &node.address, packet) catch {};
    }
};

fn endpoint_of(address: *const Io.net.IpAddress, tcp: u16, ip: *[16]u8) discv4.Endpoint {
    return switch (address.*) {
        .ip4 => |value| blk: {
            ip[0..4].* = value.bytes;
            break :blk .{ .ip = ip[0..4], .udp = value.port, .tcp = tcp };
        },
        .ip6 => |value| blk: {
            ip.* = value.bytes;
            break :blk .{ .ip = ip[0..16], .udp = value.port, .tcp = tcp };
        },
    };
}

fn address_of(endpoint: discv4.Endpoint) ?Io.net.IpAddress {
    if (endpoint.udp == 0) return null;
    return switch (endpoint.ip.len) {
        4 => .{ .ip4 = .{ .bytes = endpoint.ip[0..4].*, .port = endpoint.udp } },
        16 => .{ .ip6 = .{ .bytes = endpoint.ip[0..16].*, .port = endpoint.udp } },
        else => null,
    };
}

/// Handles one received packet; drops anything malformed or unsolicited.
fn handle(crawler: *Crawler, from: Io.net.IpAddress, bytes: []const u8) void {
    const packet = discv4.decode(bytes) catch return;
    switch (packet.type) {
        .ping => {
            const ping = discv4.decode_ping(packet.data) catch return;
            crawler.add(packet.sender, from, ping.from.tcp);
            const node = crawler.find(&packet.sender) orelse return;
            var data: [128]u8 = undefined;
            var ip_buffer: [16]u8 = undefined;
            const to = endpoint_of(&from, 0, &ip_buffer);
            const expiration = crawler.expiration();
            const pong = discv4.encode_pong(&data, to, packet.hash, expiration) catch return;
            crawler.send(node, .pong, pong);
            node.pinged_us = true;
            // We are bonded once the node has our Pong: now it answers FindNode.
            if (node.ponged) {
                crawler.lookup(node);
                crawler.request_enr(node);
            }
        },
        .pong => {
            const node = crawler.find(&packet.sender) orelse return;
            node.ponged = true;
            if (node.pinged_us) crawler.lookup(node);
            crawler.request_enr(node);
        },
        .neighbors => {
            var neighbors = discv4.decode_neighbors(packet.data) catch return;
            while (neighbors.next() catch null) |neighbor| {
                const address = address_of(neighbor.endpoint) orelse continue;
                crawler.add(neighbor.id, address, neighbor.endpoint.tcp);
            }
        },
        .enr_response => handle_enr(crawler, &packet),
        else => {},
    }
}

fn handle_enr(crawler: *Crawler, packet: *const discv4.Packet) void {
    const node = crawler.find(&packet.sender) orelse return;
    const response = discv4.decode_enr_response(packet.data) catch return;
    if (!std.mem.eql(u8, &response.request_hash, &node.enr_hash)) return;
    if (node.enr_received) return;
    const record = enr.decode(response.record) catch return;
    node.enr_received = true;
    crawler.enrs += 1;
    // Base nodes advertise their fork id under `opel` and read it before `eth`.
    const opel = record.get("opel");
    if (opel != null) crawler.opel += 1;
    const value = opel orelse record.get("eth") orelse return;
    const fork = discv4.decode_eth_entry(value) catch return;
    crawler.count_fork(fork.hash);
    if (crawler.flags.fork_hash) |wanted| {
        if (!std.mem.eql(u8, &wanted, &fork.hash)) {
            crawler.other_chain += 1;
            return;
        }
    }
    if (node.printed or node.tcp == 0) return;
    node.printed = true;
    // A node of the chain knows others of the chain: walk its table harder.
    node.lookups_max = lookups_per_bootnode;
    crawler.found += 1;
    var text: [enode.text_length_max]u8 = undefined;
    const line = format_enode(&text, node) catch return;
    std.debug.print("el-peers: fork {x} next {d} {s}\n", .{ &fork.hash, fork.next, line });
    if (crawler.flags.peers) |path| append_peer(crawler.io, path, line) catch |err| {
        std.debug.print("el-peers: cannot update {s}: {t}\n", .{ path, err });
    };
}

/// Adds `line` to the peer file at `path` unless a line with the same node id is there.
fn append_peer(io: Io, path: []const u8, line: []const u8) !void {
    var buffer: [peers_file_bytes_max]u8 = undefined;
    const existing = Io.Dir.cwd().readFile(io, path, buffer[0 .. buffer.len - 512]) catch |err|
        switch (err) {
            error.FileNotFound => buffer[0..0],
            else => return err,
        };
    const id_end = std.mem.indexOfScalar(u8, line, '@') orelse return error.InvalidEnode;
    if (std.mem.indexOf(u8, existing, line[0..id_end]) != null) return;
    if (line.len + 1 > buffer.len - existing.len) return error.FileTooLarge;
    var length = existing.len;
    if (length > 0 and buffer[length - 1] != '\n') {
        buffer[length] = '\n';
        length += 1;
    }
    @memcpy(buffer[length..][0..line.len], line);
    length += line.len;
    buffer[length] = '\n';
    length += 1;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buffer[0..length] });
}

fn format_enode(output: []u8, node: *const Node) ![]u8 {
    var writer: Io.Writer = .fixed(output);
    try writer.print("enode://{x}@", .{&node.id});
    switch (node.address) {
        .ip4 => |value| try writer.print("{d}.{d}.{d}.{d}", .{
            value.bytes[0], value.bytes[1], value.bytes[2], value.bytes[3],
        }),
        .ip6 => |value| try writer.print("[{f}]", .{Io.net.Ip6Address{
            .bytes = value.bytes,
            .port = 0,
        }}),
    }
    try writer.print(":{d}", .{node.tcp});
    if (node.address.getPort() != node.tcp) try writer.print("?discport={d}", .{
        node.address.getPort(),
    });
    return writer.buffered();
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const io = init.io;
    const bind: Io.net.IpAddress = .{ .ip4 = .{ .bytes = @splat(0), .port = flags.port } };
    const socket = try bind.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    const nodes = try init.gpa.alloc(Node, nodes_max);
    defer init.gpa.free(nodes);
    var crawler: Crawler = .{
        .io = io,
        .socket = socket,
        .secret = random_secret(io),
        .flags = &flags,
        .nodes = nodes,
    };
    try crawler.index.ensureTotalCapacity(init.gpa, nodes_max);
    defer crawler.index.deinit(init.gpa);
    for (flags.seeds[0..flags.seeds_count]) |text| add_enode(&crawler, text, lookups_per_node);
    // Known peers of the chain: their tables hold more of it, so walk them hard.
    var peers_buffer: [peers_file_bytes_max]u8 = undefined;
    if (flags.peers) |path| {
        const text = Io.Dir.cwd().readFile(io, path, &peers_buffer) catch "";
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        while (lines.next()) |line| add_enode(&crawler, line, lookups_per_bootnode);
    }
    for (flags.chain.bootnodes.execution) |text| add_enode(&crawler, text, lookups_per_bootnode);
    if (crawler.count == 0) return error.NoBootnodes;
    try crawl(&crawler);

    std.debug.print("el-peers: nodes {d} bonded {d} enrs {d} opel {d} other_chain {d}" ++
        " found {d}\n", .{
        crawler.count,       bonded_count(&crawler), crawler.enrs, crawler.opel,
        crawler.other_chain, crawler.found,
    });
    for (crawler.forks[0..crawler.forks_count]) |fork| {
        if (fork.count >= 5) std.debug.print("el-peers: fork {x} records {d}\n", .{
            &fork.hash, fork.count,
        });
    }
    return if (crawler.found > 0) 0 else 1;
}

fn add_enode(crawler: *Crawler, text: []const u8, lookups_max: u8) void {
    const record = enode.parse(text) catch return;
    const id = curve.decompress_public_key(&record.public_key) orelse return;
    const address: Io.net.IpAddress = switch (record.address) {
        .ip4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = record.udp_port } },
        .ip6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = record.udp_port } },
    };
    crawler.add(id, address, record.tcp_port);
    if (crawler.find(&id)) |node| node.lookups_max = lookups_max;
}

fn crawl(crawler: *Crawler) !void {
    const io = crawler.io;
    const duration: Io.Clock.Duration = .{
        .raw = .fromSeconds(@intCast(crawler.flags.duration_s)),
        .clock = .awake,
    };
    const deadline = Io.Clock.Timestamp.fromNow(io, duration);
    var buffer: [discv4.packet_size_max]u8 = undefined;
    var passes: u64 = 0;
    while (deadline.untilNow(io).raw.nanoseconds < 0) : (passes += 1) {
        var sent: u32 = 0;
        while (crawler.next_ping < crawler.count and sent < pings_per_pass) : (sent += 1) {
            crawler.ping(&crawler.nodes[crawler.next_ping]);
            crawler.next_ping += 1;
        }
        // Bonded nodes get their remaining lookups, one per pass each.
        if (passes % 10 == 0) {
            for (crawler.nodes[0..crawler.count]) |*node| {
                if (!node.ponged) continue;
                crawler.lookup(node);
                if (passes % 50 == 0) crawler.request_enr(node);
            }
        }
        const timeout: Io.Timeout = .{ .duration = .{
            .raw = .fromMilliseconds(100),
            .clock = .awake,
        } };
        for (0..64) |_| {
            const message = crawler.socket.receiveTimeout(io, &buffer, timeout) catch |err|
                switch (err) {
                    error.Timeout => break,
                    else => return err,
                };
            handle(crawler, message.from, message.data);
        }
        if (passes % 100 == 0) {
            std.debug.print("el-peers: nodes {d} pinged {d} bonded {d} enrs {d} found {d}\n", .{
                crawler.count, crawler.next_ping, bonded_count(crawler), crawler.enrs,
                crawler.found,
            });
        }
    }
    assert(crawler.count <= crawler.nodes.len);
}

fn bonded_count(crawler: *const Crawler) u32 {
    var count: u32 = 0;
    for (crawler.nodes[0..crawler.count]) |node| count += @intFromBool(node.ponged);
    return count;
}

fn random_secret(io: Io) [32]u8 {
    while (true) {
        var secret: [32]u8 = undefined;
        io.random(&secret);
        _ = curve.public_key(secret) catch continue;
        return secret;
    }
}

test "el-peers: flags" {
    const flags = try parse_flags(&.{ "--fork-hash", "c6757f44", "--duration", "5" });
    try std.testing.expectEqualSlices(u8, &.{ 0xc6, 0x75, 0x7f, 0x44 }, &flags.fork_hash.?);
    try std.testing.expectEqual(@as(u64, 5), flags.duration_s);
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{"--duration"}));
}

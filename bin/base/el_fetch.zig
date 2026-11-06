//! `base el-fetch`: fetches a block range from one execution-layer peer over devp2p
//! (RLPx + eth/68, `execution.p2p`), with no RPC, and checks it: every header hashes to the
//! next header's parent hash, and every body's transactions match its header's
//! `transactionsRoot`. This is the peer-based block source for snapshot-to-tip catch-up
//! (docs/UNSAFE_TIP.md).
//!
//!     base el-fetch --enode <enode://...> --from <block> [--count <n>] [--batch <n>]
//!                   [--chain base-sepolia|base-mainnet]
//!
//! Blocks are bound only to each other here. A consumer binds the range to a trusted
//! hash (the snapshot block, or a sequencer-signed gossip block).

const std = @import("std");
const base = @import("base");

const p2p = base.execution.p2p;
const rlpx = p2p.rlpx;
const eth = p2p.eth;
const snappy = base.consensus.p2p.gossip.snappy;
const enode = base.consensus.p2p.peers.enode;
const curve = base.common.crypto.secp256k1;
const keccak = base.common.crypto.keccak;
const Header = base.common.consensus.Header;
const Io = std.Io;
const assert = std.debug.assert;

const usage =
    \\usage: base el-fetch --enode <enode://...> --from <block> [--count <n>] [--batch <n>]
    \\                     [--chain base-sepolia|base-mainnet]
    \\
;

/// Largest message we accept: eth caps responses near 2 MiB; allow 16 MiB decoded.
const message_size_max = 16 << 20;
const transactions_max = 1 << 14;

const Flags = struct {
    enode: ?[]const u8 = null,
    from: ?u64 = null,
    count: u64 = 1000,
    batch: u32 = 128,
    chain: *const base.common.chains.ChainConfig = &base.common.chains.sepolia,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 2) {
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--enode")) {
            flags.enode = value;
        } else if (std.mem.eql(u8, name, "--from")) {
            flags.from = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--count")) {
            flags.count = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--batch")) {
            flags.batch = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = if (std.mem.eql(u8, value, "base-mainnet"))
                &base.common.chains.mainnet
            else
                &base.common.chains.sepolia;
        } else return error.InvalidArguments;
    }
    if (index != args.len or flags.enode == null or flags.from == null) {
        return error.InvalidArguments;
    }
    if (flags.batch == 0 or flags.batch > 1024 or flags.count == 0) return error.InvalidArguments;
    return flags;
}

/// One RLPx connection over a blocking stream.
const Peer = struct {
    io: Io,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    session: rlpx.Session = undefined,
    compressor: snappy.Compressor = .{},
    /// Frames in and out, and decompressed message data.
    wire: []u8,
    plain: []u8,
    message: []u8,
    request_id: u64 = 0,

    fn send(peer: *Peer, id: eth.Id, data: []const u8, compress: bool) !void {
        var length = eth.write_id(peer.plain, id);
        if (compress) {
            length += peer.compressor.compress(data, peer.plain[length..]).len;
        } else {
            @memcpy(peer.plain[length..][0..data.len], data);
            length += data.len;
        }
        const frame = try peer.session.seal(peer.plain[0..length], peer.wire);
        try peer.writer.interface.writeAll(frame);
        try peer.writer.interface.flush();
    }

    /// The next message; answers pings and skips unrelated messages up to `skips_max`.
    fn receive(peer: *Peer, compressed: bool) !struct { id: eth.Id, data: []const u8 } {
        for (0..256) |_| {
            const header = try peer.reader.interface.takeArray(rlpx.frame_header_length);
            const rest = try peer.session.open_header(header);
            if (rest > peer.wire.len) return error.FrameTooLarge;
            try peer.reader.interface.readSliceAll(peer.wire[0..rest]);
            const frame = try peer.session.open_body(peer.wire[0..rest]);
            const message = try eth.split(frame);
            const data = if (compressed and message.data.len > 0)
                try snappy.decompress(message.data, peer.message, message_size_max)
            else
                message.data;
            switch (message.id) {
                .ping => try peer.send(.pong, &.{0xc0}, compressed),
                .disconnect => {
                    std.debug.print("el-fetch: peer disconnected, reason {d}\n", .{
                        eth.decode_disconnect(data),
                    });
                    return error.Disconnected;
                },
                .hello, .status, .block_headers, .block_bodies => {
                    return .{ .id = message.id, .data = data };
                },
                else => {}, // Transaction announcements and the like.
            }
        }
        return error.NoResponse;
    }

    fn expect(peer: *Peer, id: eth.Id) ![]const u8 {
        const message = try peer.receive(id != .hello);
        if (message.id != id) return error.UnexpectedMessage;
        return message.data;
    }
};

fn handshake(peer: *Peer, secret: [32]u8, remote: curve.PublicKey) !void {
    var random: rlpx.Random = undefined;
    peer.io.random(&random.nonce);
    peer.io.random(&random.iv);
    random.ephemeral_secret = random_secret(peer.io);
    random.padding = 128;
    var initiator: rlpx.Initiator = .{
        .static_secret = secret,
        .remote = remote,
        .random = random,
    };
    try peer.writer.interface.writeAll(try initiator.start());
    try peer.writer.interface.flush();
    const prefix = try peer.reader.interface.takeArray(2);
    var ack: [rlpx.handshake_size_max + 2]u8 = undefined;
    const length = try rlpx.packet_length(prefix);
    ack[0..2].* = prefix.*;
    try peer.reader.interface.readSliceAll(ack[2..length]);
    peer.session = try initiator.finish(ack[0..length]);
}

fn random_secret(io: Io) [32]u8 {
    while (true) {
        var secret: [32]u8 = undefined;
        io.random(&secret);
        _ = curve.public_key(secret) catch continue;
        return secret;
    }
}

/// Hello both ways, then Status both ways (ours mirrors the peer's head and fork id).
fn greet(peer: *Peer, secret: [32]u8, chain: *const base.common.chains.ChainConfig) !void {
    const node_id = try curve.public_key(secret);
    var buffer: [512]u8 = undefined;
    try peer.send(.hello, try eth.encode_hello(&buffer, "needlefish", &node_id), false);
    const hello = try eth.decode_hello(try peer.expect(.hello));
    std.debug.print("el-fetch: hello from {s}\n", .{hello.client});
    if (!hello.eth_68) return error.NoSharedCapability;
    const status = try eth.decode_status(try peer.expect(.status));
    std.debug.print("el-fetch: status network {d} fork 0x{x} next {d}\n", .{
        status.network_id, &status.fork_id.hash, status.fork_id.next,
    });
    if (status.network_id != chain.chain_id) return error.WrongNetwork;
    if (!std.mem.eql(u8, &status.genesis, &chain.genesis_l2_hash.bytes)) return error.WrongGenesis;
    var ours = status;
    ours.version = eth.eth_version;
    ours.total_difficulty = 0;
    try peer.send(.status, try eth.encode_status(&buffer, &ours), true);
}

const Progress = struct {
    next: u64,
    parent: ?[32]u8 = null,
    blocks: u64 = 0,
    transactions: u64 = 0,
    bytes: u64 = 0,
};

/// Fetches and checks one batch of headers and bodies starting at `progress.next`.
fn fetch_batch(peer: *Peer, progress: *Progress, amount: u32) !void {
    var request: [64]u8 = undefined;
    peer.request_id += 1;
    const id = peer.request_id;
    const get_headers = try eth.encode_get_block_headers(&request, id, progress.next, amount);
    try peer.send(.get_block_headers, get_headers, true);
    const headers_data = try peer.expect(.block_headers);
    var response = try eth.decode_response(headers_data);
    if (response.request_id != id) return error.UnexpectedResponse;
    var hashes: [1024][32]u8 = undefined;
    var roots: [1024][32]u8 = undefined;
    var count: usize = 0;
    while (!response.items.is_empty()) : (count += 1) {
        if (count == amount) return error.TooManyHeaders;
        const raw = try response.items.raw();
        const header = try Header.decode(raw);
        if (header.number != progress.next + count) return error.HeaderOutOfOrder;
        const parent = if (count == 0) progress.parent else hashes[count - 1];
        if (parent) |hash| {
            if (!std.mem.eql(u8, &hash, &header.parent_hash.bytes)) return error.BrokenChain;
        }
        hashes[count] = keccak.keccak256(raw);
        roots[count] = header.transactions_root.bytes;
    }
    if (count == 0) return error.NoHeaders;
    progress.bytes += headers_data.len;
    try fetch_bodies(peer, progress, hashes[0..count], roots[0..count]);
    progress.parent = hashes[count - 1];
    progress.next += count;
    progress.blocks += count;
}

/// Bodies per request when pipelining: small requests let the peer answer them in parallel.
const bodies_per_request = 16;
const requests_in_flight_max = 64;

/// Requests bodies for `hashes` in chunks, all in flight at once, then checks each answer
/// against its header's transactions root. A partial answer re-requests the rest of its
/// chunk on its own.
fn fetch_bodies(
    peer: *Peer,
    progress: *Progress,
    hashes: []const [32]u8,
    roots: []const [32]u8,
) !void {
    assert(hashes.len == roots.len and hashes.len > 0);
    const chunks = std.math.divCeil(usize, hashes.len, bodies_per_request) catch unreachable;
    if (chunks > requests_in_flight_max) return error.TooManyRequests;
    var done: [requests_in_flight_max]usize = @splat(0);
    const first_id = peer.request_id + 1;
    var request: [bodies_per_request * 33 + 64]u8 = undefined;
    for (0..chunks) |chunk| {
        peer.request_id += 1;
        const range = chunk_range(hashes.len, chunk);
        const chunk_hashes = hashes[range[0]..range[1]];
        const message = try eth.encode_get_block_bodies(&request, peer.request_id, chunk_hashes);
        try peer.send(.get_block_bodies, message, true);
    }
    for (0..chunks) |_| {
        const data = try peer.expect(.block_bodies);
        var response = try eth.decode_response(data);
        if (response.request_id < first_id or response.request_id >= first_id + chunks) {
            return error.UnexpectedResponse;
        }
        const chunk: usize = @intCast(response.request_id - first_id);
        const range = chunk_range(hashes.len, chunk);
        done[chunk] = try check_bodies(progress, &response.items, roots, range);
        progress.bytes += data.len;
    }
    for (0..chunks) |chunk| {
        const range = chunk_range(hashes.len, chunk);
        while (range[0] + done[chunk] < range[1]) {
            peer.request_id += 1;
            const id = peer.request_id;
            const from = range[0] + done[chunk];
            const message = try eth.encode_get_block_bodies(&request, id, hashes[from..range[1]]);
            try peer.send(.get_block_bodies, message, true);
            const data = try peer.expect(.block_bodies);
            var response = try eth.decode_response(data);
            if (response.request_id != id) return error.UnexpectedResponse;
            const checked = try check_bodies(progress, &response.items, roots, .{ from, range[1] });
            if (checked == 0) return error.NoBodies;
            done[chunk] += checked;
        }
    }
}

fn chunk_range(length: usize, chunk: usize) [2]usize {
    const from = chunk * bodies_per_request;
    assert(from < length);
    return .{ from, @min(length, from + bodies_per_request) };
}

/// Checks the bodies in `items` against `roots[range]` in order; returns how many came.
fn check_bodies(
    progress: *Progress,
    items: *base.common.rlp.Decoder,
    roots: []const [32]u8,
    range: [2]usize,
) !usize {
    var transactions: [transactions_max][]const u8 = undefined;
    var index = range[0];
    while (!items.is_empty()) : (index += 1) {
        if (index == range[1]) return error.TooManyBodies;
        const body = try eth.body_transactions(try items.raw(), &transactions);
        const root = eth.transactions_root(transactions[0..body.count]);
        if (!std.mem.eql(u8, &root, &roots[index]) or !body.ommers_empty) {
            std.debug.print("el-fetch: body {d} does not match its header\n", .{
                progress.next + index,
            });
            return error.BodyMismatch;
        }
        progress.transactions += body.count;
    }
    return index - range[0];
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const node = enode.parse(flags.enode.?) catch {
        std.debug.print("el-fetch: invalid enode\n", .{});
        return 2;
    };
    const remote_compressed = node.public_key;
    const remote = curve.decompress_public_key(&remote_compressed) orelse return error.InvalidKey;
    const address: Io.net.IpAddress = switch (node.address) {
        .ip4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = node.tcp_port } },
        .ip6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = node.tcp_port } },
    };
    const io = init.io;
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const allocator = init.gpa;
    const wire = try allocator.alloc(u8, message_size_max + 64);
    defer allocator.free(wire);
    const plain = try allocator.alloc(u8, snappy.max_compressed_length(message_size_max) + 16);
    defer allocator.free(plain);
    const message = try allocator.alloc(u8, message_size_max);
    defer allocator.free(message);
    var read_buffer: [64 * 1024]u8 = undefined;
    var write_buffer: [64 * 1024]u8 = undefined;
    var peer: Peer = .{
        .io = io,
        .stream = stream,
        .reader = stream.reader(io, &read_buffer),
        .writer = stream.writer(io, &write_buffer),
        .wire = wire,
        .plain = plain,
        .message = message,
    };
    const secret = random_secret(io);
    try handshake(&peer, secret, remote);
    try greet(&peer, secret, flags.chain);
    return run(&peer, &flags);
}

fn run(peer: *Peer, flags: *const Flags) !u8 {
    var progress: Progress = .{ .next = flags.from.? };
    const end = flags.from.? + flags.count;
    const start = Io.Clock.awake.now(peer.io);
    while (progress.next < end) {
        const amount: u32 = @intCast(@min(flags.batch, end - progress.next));
        try fetch_batch(peer, &progress, amount);
        const elapsed = start.durationTo(Io.Clock.awake.now(peer.io));
        const elapsed_ms: u64 = @intCast(@max(1, elapsed.toMilliseconds()));
        std.debug.print("el-fetch: blocks {d}..{d} txs {d} bytes {d} blocks_per_s {d}\n", .{
            flags.from.?,                        progress.next - 1,
            progress.transactions,               progress.bytes,
            progress.blocks * 1000 / elapsed_ms,
        });
    }
    std.debug.print("el-fetch: ok, {d} linked blocks, last hash 0x{x}\n", .{
        progress.blocks, &progress.parent.?,
    });
    return 0;
}

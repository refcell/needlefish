//! A block source over one execution-layer peer (devp2p RLPx + eth/68, `execution.p2p`):
//! ascending blocks from a start number, each its header RLP, hash and EIP-2718
//! transactions. Every header's parent hash is the previous block's hash (the first one's
//! too, when the caller gives the parent), and every body's transactions hash to its
//! header's `transactionsRoot`. Past the peer's head, `next` returns false; ask again later.
//! A dropped or refused connection is retried with backoff, and the range resumes from the
//! last block handed out.
//!
//! Blocks are not signed: a consumer binds the range to a trusted hash (the snapshot block
//! as `parent`, or a sequencer-signed gossip block). Used by `base el-fetch`; it is the
//! devp2p implementation of the catch-up block source (docs/UNSAFE_TIP.md).

const std = @import("std");
const base = @import("base");

const p2p = base.execution.p2p;
const rlpx = p2p.rlpx;
const eth = p2p.eth;
const snappy = base.consensus.p2p.gossip.snappy;
const curve = base.common.crypto.secp256k1;
const keccak = base.common.crypto.keccak;
const Header = base.common.consensus.Header;
const Io = std.Io;
const assert = std.debug.assert;

/// Largest message we accept: eth caps responses near 2 MiB; allow 16 MiB decoded.
const message_size_max = 16 << 20;
pub const transactions_max = 1 << 14;
pub const batch_max = 1024;
/// Raw headers and bodies of one batch.
const headers_bytes_max = 2 << 20;
const bodies_bytes_max = 64 << 20;
const reconnects_max_default = 32;
/// Bodies per request when pipelining: small requests let the peer answer them in parallel.
const bodies_per_request = 16;
const requests_in_flight_max = batch_max / bodies_per_request;

pub const Block = struct {
    number: u64,
    hash: [32]u8,
    header_rlp: []const u8,
    /// Valid until the next call to `next`.
    transactions: []const []const u8,
};

/// Everything needed to (re)open the connection.
pub const Target = struct {
    address: Io.net.IpAddress,
    remote: curve.PublicKey,
    secret: [32]u8,
    chain: *const base.common.chains.ChainConfig,
};

const Span = struct { offset: u32, length: u32 };
const Entry = struct { header: Span, body: Span, hash: [32]u8, root: [32]u8 };

/// Up to `spans.len` consecutive blocks: raw headers and bodies in two arenas.
pub const Batch = struct {
    headers: []u8,
    bodies: []u8,
    spans: []Entry,
    first: u64 = 0,
    count: u32 = 0,
    /// The parent hash the first header names.
    parent: [32]u8 = @splat(0),
    headers_used: u32 = 0,
    bodies_used: u32 = 0,

    pub fn alloc(
        allocator: std.mem.Allocator,
        blocks_max: u32,
        headers_bytes: usize,
        bodies_bytes: usize,
    ) !Batch {
        assert(blocks_max > 0 and blocks_max <= batch_max);
        const headers = try allocator.alloc(u8, headers_bytes);
        errdefer allocator.free(headers);
        const bodies = try allocator.alloc(u8, bodies_bytes);
        errdefer allocator.free(bodies);
        const spans = try allocator.alloc(Entry, blocks_max);
        return .{ .headers = headers, .bodies = bodies, .spans = spans };
    }

    pub fn free(batch: *Batch, allocator: std.mem.Allocator) void {
        allocator.free(batch.headers);
        allocator.free(batch.bodies);
        allocator.free(batch.spans);
        batch.* = undefined;
    }

    fn reset(batch: *Batch, first: u64) void {
        batch.first = first;
        batch.count = 0;
        batch.headers_used = 0;
        batch.bodies_used = 0;
    }

    pub fn hash(batch: *const Batch, index: u32) [32]u8 {
        assert(index < batch.count);
        return batch.spans[index].hash;
    }

    /// Block `index`, its transactions decoded into `transactions`. Borrows the batch.
    pub fn block(
        batch: *const Batch,
        index: u32,
        transactions: [][]const u8,
    ) !Block {
        assert(index < batch.count);
        const span = &batch.spans[index];
        const body = batch.bodies[span.body.offset..][0..span.body.length];
        const result = try eth.body_transactions(body, transactions);
        return .{
            .number = batch.first + index,
            .hash = span.hash,
            .header_rlp = batch.headers[span.header.offset..][0..span.header.length],
            .transactions = transactions[0..result.count],
        };
    }
};

/// Fetches blocks `first`.. (at most `amount`, fewer past the peer's head) from `peer` into
/// `batch` and checks them: each header's number and parent hash (the first one's against
/// `parent` when given), and each body's transactions root and empty ommers. Headers come
/// in one request; bodies in chunks of `bodies_per_request`, all in flight at once.
/// Returns how many blocks came (zero past the peer's head).
pub fn fetch(
    peer: *Peer,
    batch: *Batch,
    first: u64,
    amount: u32,
    parent: ?[32]u8,
    scratch: [][]const u8,
) !u32 {
    assert(amount > 0 and amount <= batch.spans.len);
    batch.reset(first);
    const count = try fetch_headers(peer, batch, amount, parent);
    if (count == 0) return 0;
    try fetch_bodies(peer, batch, count, scratch);
    batch.count = count;
    assert(batch.count <= amount);
    return count;
}

fn fetch_headers(peer: *Peer, batch: *Batch, amount: u32, parent: ?[32]u8) !u32 {
    var request: [64]u8 = undefined;
    peer.request_id += 1;
    const id = peer.request_id;
    const origin: eth.Origin = .{ .number = batch.first };
    try peer.send(.get_block_headers, try eth.encode_get_block_headers(
        &request,
        id,
        origin,
        amount,
    ), true);
    const sent = peer.now();
    const data = try peer.expect(.block_headers);
    peer.trace_response("headers", batch.first, data.len, sent);
    var response = try eth.decode_response(data);
    if (response.request_id != id) return error.UnexpectedResponse;
    var count: u32 = 0;
    while (!response.items.is_empty()) : (count += 1) {
        if (count == amount) return error.TooManyHeaders;
        const raw = try response.items.raw();
        const header = try Header.decode(raw);
        if (header.number != batch.first + count) return error.HeaderOutOfOrder;
        if (count == 0) batch.parent = header.parent_hash.bytes;
        const expected = if (count == 0) parent else batch.spans[count - 1].hash;
        if (expected) |hash| {
            if (!std.mem.eql(u8, &hash, &header.parent_hash.bytes)) return error.BrokenChain;
        }
        batch.spans[count] = .{
            .header = try copy(batch.headers, &batch.headers_used, raw),
            .body = .{ .offset = 0, .length = 0 },
            .hash = keccak.keccak256(raw),
            .root = header.transactions_root.bytes,
        };
    }
    return count;
}

/// Requests bodies in chunks, all in flight at once, then checks each answer against
/// its header's transactions root. A partial answer re-requests the rest of its chunk.
fn fetch_bodies(peer: *Peer, batch: *Batch, count: u32, scratch: [][]const u8) !void {
    assert(count > 0);
    // The divisor is a nonzero constant, so divCeil cannot fail.
    const chunks = std.math.divCeil(u32, count, bodies_per_request) catch unreachable;
    assert(chunks <= requests_in_flight_max);
    var done: [requests_in_flight_max]u32 = @splat(0);
    const first_id = peer.request_id + 1;
    const sent = peer.now();
    for (0..chunks) |chunk| {
        peer.request_id += 1;
        try request_bodies(peer, batch, peer.request_id, chunk_range(count, @intCast(chunk)));
    }
    for (0..chunks) |_| {
        const data = try peer.expect(.block_bodies);
        peer.trace_response("bodies", batch.first, data.len, sent);
        var response = try eth.decode_response(data);
        if (response.request_id < first_id or response.request_id >= first_id + chunks) {
            return error.UnexpectedResponse;
        }
        const chunk: u32 = @intCast(response.request_id - first_id);
        const range = chunk_range(count, chunk);
        done[chunk] = try store_bodies(batch, &response.items, range, scratch);
    }
    for (0..chunks) |chunk_index| {
        const range = chunk_range(count, @intCast(chunk_index));
        while (range[0] + done[chunk_index] < range[1]) {
            peer.request_id += 1;
            const id = peer.request_id;
            const from = range[0] + done[chunk_index];
            try request_bodies(peer, batch, id, .{ from, range[1] });
            const data = try peer.expect(.block_bodies);
            var response = try eth.decode_response(data);
            if (response.request_id != id) return error.UnexpectedResponse;
            const stored = try store_bodies(batch, &response.items, .{ from, range[1] }, scratch);
            if (stored == 0) return error.NoBodies;
            done[chunk_index] += stored;
        }
    }
}

/// Asks for the bodies of batch entries `range`, at most one chunk.
fn request_bodies(peer: *Peer, batch: *const Batch, id: u64, range: [2]u32) !void {
    assert(range[0] < range[1] and range[1] - range[0] <= bodies_per_request);
    var hashes: [bodies_per_request][32]u8 = undefined;
    const length = range[1] - range[0];
    for (hashes[0..length], batch.spans[range[0]..range[1]]) |*hash, entry| {
        hash.* = entry.hash;
    }
    var request: [bodies_per_request * 33 + 64]u8 = undefined;
    const message = try eth.encode_get_block_bodies(&request, id, hashes[0..length]);
    try peer.send(.get_block_bodies, message, true);
}

/// Checks the bodies in `items` against `spans[range]` in order and stores them;
/// returns how many came.
fn store_bodies(
    batch: *Batch,
    items: *base.common.rlp.Decoder,
    range: [2]u32,
    scratch: [][]const u8,
) !u32 {
    var index = range[0];
    while (!items.is_empty()) : (index += 1) {
        if (index == range[1]) return error.TooManyBodies;
        const raw = try items.raw();
        const body = try eth.body_transactions(raw, scratch);
        const root = eth.transactions_root(scratch[0..body.count]);
        if (!std.mem.eql(u8, &root, &batch.spans[index].root) or !body.ommers_empty) {
            std.debug.print("el-source: body {d} does not match its header\n", .{
                batch.first + index,
            });
            return error.BodyMismatch;
        }
        batch.spans[index].body = try copy(batch.bodies, &batch.bodies_used, raw);
    }
    return index - range[0];
}

pub const Source = struct {
    peer: Peer,
    target: Target,
    /// The next block number to hand out, and the hash its header must name as parent.
    next_number: u64,
    parent: ?[32]u8,
    batch_amount: u32,
    batch: Batch,
    transactions: [][]const u8,
    index: u32 = 0,
    // Counters.
    blocks: u64 = 0,
    transactions_count: u64 = 0,
    reconnects: u32 = 0,
    reconnects_max: u32,

    pub const Options = struct {
        /// Null: start at the peer's head.
        from: ?u64,
        /// The hash block `from` must name as its parent, when known.
        parent: ?[32]u8 = null,
        batch: u32 = 128,
        /// Print each response's size and latency (diagnostics).
        trace: bool = false,
        /// Failed connects (with backoff) before giving up with `TooManyReconnects`.
        reconnects_max: u32 = reconnects_max_default,
    };

    /// Connects, handshakes and allocates every buffer. `source` must not move afterwards.
    pub fn init(
        source: *Source,
        allocator: std.mem.Allocator,
        io: Io,
        target: Target,
        options: Options,
    ) !void {
        try source.init_unconnected(allocator, io, target, options);
        errdefer source.deinit(allocator);
        const status = try source.reopen();
        source.next_number = options.from orelse try source.peer.head_number(status.head);
        assert(source.peer.connected);
    }

    /// Allocates every buffer without connecting: the caller swaps a connected `peer` in
    /// (and sets `target` to its peer), or calls `init` instead. `options.from` is required.
    pub fn init_unconnected(
        source: *Source,
        allocator: std.mem.Allocator,
        io: Io,
        target: Target,
        options: Options,
    ) !void {
        assert(options.batch > 0 and options.batch <= batch_max);
        var peer = try Peer.alloc(allocator, io);
        errdefer peer.free(allocator);
        peer.trace = options.trace;
        var batch = try Batch.alloc(allocator, batch_max, headers_bytes_max, bodies_bytes_max);
        errdefer batch.free(allocator);
        const transactions = try allocator.alloc([]const u8, transactions_max);
        errdefer allocator.free(transactions);
        source.* = .{
            .peer = peer,
            .target = target,
            .next_number = 0,
            .parent = options.parent,
            .batch_amount = options.batch,
            .batch = batch,
            .transactions = transactions,
            .reconnects_max = options.reconnects_max,
        };
        source.next_number = options.from orelse 0;
    }

    pub fn deinit(source: *Source, allocator: std.mem.Allocator) void {
        source.peer.close();
        source.peer.free(allocator);
        source.batch.free(allocator);
        allocator.free(source.transactions);
    }

    /// The next block, or false when the peer has none past the last one yet.
    pub fn next(source: *Source, block: *Block) !bool {
        if (!source.peer.connected) _ = try source.reopen();
        if (source.index == source.batch.count) {
            if (!try source.refill_reconnecting()) return false;
        }
        assert(source.index < source.batch.count);
        block.* = try source.batch.block(source.index, source.transactions);
        assert(block.number == source.next_number);
        source.index += 1;
        source.next_number += 1;
        source.parent = block.hash;
        source.blocks += 1;
        source.transactions_count += block.transactions.len;
        return true;
    }

    /// Block `number` (the next one) came from elsewhere with `hash`: hands out `number + 1`
    /// next. A fetched batch that holds `number` keeps its later blocks only when they
    /// continue `hash`.
    pub fn skip(source: *Source, number: u64, hash: [32]u8) void {
        assert(number == source.next_number);
        if (source.index < source.batch.count) {
            const same = std.mem.eql(u8, &source.batch.hash(source.index), &hash);
            source.index = if (same) source.index + 1 else source.batch.count;
        }
        assert(source.index <= source.batch.count);
        source.next_number = number + 1;
        source.parent = hash;
    }

    fn refill_reconnecting(source: *Source) !bool {
        while (true) {
            return source.refill() catch |err| switch (err) {
                error.Disconnected, error.EndOfStream, error.ReadFailed, error.WriteFailed => {
                    std.debug.print("el-source: reconnecting at {d} ({s})\n", .{
                        source.next_number, @errorName(err),
                    });
                    _ = try source.reopen();
                    continue;
                },
                else => return err,
            };
        }
    }

    /// (Re)connects, backing off 1 s, 2 s, ... up to 30 s between attempts: peers refuse
    /// quick reconnects from an address they just dropped.
    fn reopen(source: *Source) !eth.Status {
        source.peer.close();
        var backoff_s: u64 = 1;
        while (true) {
            const status = source.peer.open(&source.target) catch |err| {
                source.reconnects += 1;
                if (source.reconnects > source.reconnects_max) return error.TooManyReconnects;
                std.debug.print("el-source: connect failed ({s}), retry in {d} s\n", .{
                    @errorName(err), backoff_s,
                });
                try source.peer.io.sleep(.fromSeconds(@intCast(backoff_s)), .awake);
                backoff_s = @min(backoff_s * 2, 30);
                continue;
            };
            assert(source.peer.connected);
            return status;
        }
    }

    /// Fetches and checks the next batch; false when the peer has nothing new.
    fn refill(source: *Source) !bool {
        assert(source.index == source.batch.count);
        source.index = 0;
        const count = try fetch(
            &source.peer,
            &source.batch,
            source.next_number,
            source.batch_amount,
            source.parent,
            source.transactions,
        );
        return count > 0;
    }
};

fn chunk_range(count: u32, chunk: u32) [2]u32 {
    const from = chunk * bodies_per_request;
    assert(from < count);
    return .{ from, @min(count, from + bodies_per_request) };
}

fn copy(arena: []u8, used: *u32, bytes: []const u8) !Span {
    if (arena.len - used.* < bytes.len) return error.BatchTooLarge;
    const span: Span = .{ .offset = used.*, .length = @intCast(bytes.len) };
    @memcpy(arena[used.*..][0..bytes.len], bytes);
    used.* += span.length;
    return span;
}

/// One RLPx connection over a blocking stream.
pub const Peer = struct {
    io: Io,
    stream: Io.net.Stream = undefined,
    reader: Io.net.Stream.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,
    read_buffer: []u8,
    write_buffer: []u8,
    connected: bool = false,
    session: rlpx.Session = undefined,
    compressor: snappy.Compressor = .{},
    /// Frames in and out, and decompressed message data.
    wire: []u8,
    plain: []u8,
    message: []u8,
    request_id: u64 = 0,
    /// Decompressed message bytes received.
    bytes: u64 = 0,
    /// Print each response's size and latency (diagnostics).
    trace: bool = false,
    /// Do not print the handshake lines.
    quiet: bool = false,

    pub fn alloc(allocator: std.mem.Allocator, io: Io) !Peer {
        const read_buffer = try allocator.alloc(u8, 64 * 1024);
        errdefer allocator.free(read_buffer);
        const write_buffer = try allocator.alloc(u8, 64 * 1024);
        errdefer allocator.free(write_buffer);
        const wire = try allocator.alloc(u8, message_size_max + 64);
        errdefer allocator.free(wire);
        const plain = try allocator.alloc(u8, snappy.max_compressed_length(message_size_max) + 16);
        errdefer allocator.free(plain);
        const message = try allocator.alloc(u8, message_size_max);
        return .{
            .io = io,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .wire = wire,
            .plain = plain,
            .message = message,
        };
    }

    pub fn free(peer: *Peer, allocator: std.mem.Allocator) void {
        assert(!peer.connected);
        allocator.free(peer.read_buffer);
        allocator.free(peer.write_buffer);
        allocator.free(peer.wire);
        allocator.free(peer.plain);
        allocator.free(peer.message);
    }

    pub fn open(peer: *Peer, target: *const Target) !eth.Status {
        assert(!peer.connected);
        // Zig 0.17's threaded Io has no connect timeout yet (it panics on one).
        peer.stream = try target.address.connect(peer.io, .{ .mode = .stream });
        peer.connected = true;
        errdefer peer.close();
        peer.reader = peer.stream.reader(peer.io, peer.read_buffer);
        peer.writer = peer.stream.writer(peer.io, peer.write_buffer);
        peer.compressor = .{};
        try peer.handshake(target.secret, target.remote);
        return peer.greet(target.secret, target.chain);
    }

    pub fn close(peer: *Peer) void {
        if (!peer.connected) return;
        peer.stream.close(peer.io);
        peer.connected = false;
    }

    /// Unblocks a read in progress on another thread; `close` still follows.
    pub fn shutdown(peer: *Peer) void {
        if (!peer.connected) return;
        peer.stream.shutdown(peer.io, .both) catch {};
    }

    fn now(peer: *const Peer) Io.Timestamp {
        return Io.Clock.awake.now(peer.io);
    }

    fn trace_response(
        peer: *const Peer,
        kind: []const u8,
        number: u64,
        bytes: usize,
        sent: Io.Timestamp,
    ) void {
        if (!peer.trace) return;
        const elapsed_ms = sent.durationTo(peer.now()).toMilliseconds();
        std.debug.print("el-source: trace {s} at {d} bytes {d} after_ms {d}\n", .{
            kind, number, bytes, elapsed_ms,
        });
    }

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

    /// The next message we care about; answers pings and skips announcements.
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
            peer.bytes += data.len;
            switch (message.id) {
                .ping => try peer.send(.pong, &.{0xc0}, compressed),
                .disconnect => {
                    std.debug.print("el-source: peer disconnected, reason {d}\n", .{
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

    /// Hello both ways, then Status both ways (ours mirrors the peer's head and fork id).
    fn greet(
        peer: *Peer,
        secret: [32]u8,
        chain: *const base.common.chains.ChainConfig,
    ) !eth.Status {
        const node_id = try curve.public_key(secret);
        var buffer: [512]u8 = undefined;
        try peer.send(.hello, try eth.encode_hello(&buffer, "needlefish", &node_id), false);
        const hello = try eth.decode_hello(try peer.expect(.hello));
        if (!peer.quiet) std.debug.print("el-source: hello from {s}\n", .{hello.client});
        if (!hello.eth_68) return error.NoSharedCapability;
        const status = try eth.decode_status(try peer.expect(.status));
        if (!peer.quiet) std.debug.print("el-source: status network {d} fork 0x{x} next {d}\n", .{
            status.network_id, &status.fork_id.hash, status.fork_id.next,
        });
        if (status.network_id != chain.chain_id) return error.WrongNetwork;
        const genesis = &chain.genesis_l2_hash.bytes;
        if (!std.mem.eql(u8, &status.genesis, genesis)) return error.WrongGenesis;
        var ours = status;
        ours.version = eth.eth_version;
        ours.total_difficulty = 0;
        try peer.send(.status, try eth.encode_status(&buffer, &ours), true);
        return status;
    }

    /// Keeps an idle connection alive: one header request, during which `receive` answers
    /// any ping the peer sent meanwhile (a peer drops a connection whose pings go
    /// unanswered, disconnect reason 11).
    pub fn keepalive(peer: *Peer, number: u64) !void {
        assert(peer.connected);
        var request: [64]u8 = undefined;
        peer.request_id += 1;
        const id = peer.request_id;
        const message = try eth.encode_get_block_headers(&request, id, .{ .number = number }, 1);
        try peer.send(.get_block_headers, message, true);
        const response = try eth.decode_response(try peer.expect(.block_headers));
        if (response.request_id != id) return error.UnexpectedResponse;
    }

    /// The block number of the peer's head, from its Status head hash.
    pub fn head_number(peer: *Peer, head: [32]u8) !u64 {
        var request: [64]u8 = undefined;
        peer.request_id += 1;
        const id = peer.request_id;
        const message = try eth.encode_get_block_headers(&request, id, .{ .hash = head }, 1);
        try peer.send(.get_block_headers, message, true);
        var response = try eth.decode_response(try peer.expect(.block_headers));
        if (response.request_id != id or response.items.is_empty()) return error.NoHead;
        const header = try Header.decode(try response.items.raw());
        std.debug.print("el-source: peer head {d}\n", .{header.number});
        return header.number;
    }
};

pub fn random_secret(io: Io) [32]u8 {
    while (true) {
        var secret: [32]u8 = undefined;
        io.random(&secret);
        _ = curve.public_key(secret) catch continue;
        return secret;
    }
}

//! `base unsafe-watch`: joins a Base chain's consensus p2p network (discv5 + libp2p
//! gossipsub, docs/lanes/p2p.md) with no RPC at all and reports every unsafe block it
//! receives: signer, block hash, parent continuity, and tip lag. It is the p2p half of the
//! unsafe-tip demo (docs/UNSAFE_TIP.md): it proves reception and validity independently of
//! execution.
//!
//!     base unsafe-watch [--chain base-sepolia|base-mainnet] [--duration <seconds>]
//!                       [--quiet] [--archive <path>] [--p2p.* ...]
//!     base unsafe-watch --check-archive <path> [--chain ...]
//!
//! `--p2p.*` flags apply over the `low-latency` profile (`p2p.options.low_latency`): more
//! peers, faster discovery and re-dialing, a wider mesh. `--p2p.profile base` restores
//! base/base defaults.
//!
//! `--archive` appends every accepted block, as gossiped, to a gossip archive
//! (`p2p.gossip.archive`), so execution can replay a p2p-only block stream later.
//! `--check-archive` re-verifies such a file offline (signer, block hash, parent links).
//!
//! Every block the gossip handler accepts was already checked against the chain's unsafe
//! block signer and its recomputed block hash; this command recovers the signer again and
//! tracks the chain by parent hash, so a printed `ok` line is evidence a reader can redo.

const std = @import("std");
const base = @import("base");

const io = base.utilities.io;
const p2p = base.consensus.p2p;
const protocol = base.consensus.protocol;
const chains = base.common.chains;
const block = p2p.gossip.block;
const validity = p2p.gossip.validity;
const snappy = p2p.gossip.snappy;
const archive = p2p.gossip.archive;
const Io = std.Io;
const Network = p2p.network.Network(io.IO);
const assert = std.debug.assert;
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const usage =
    \\usage: base unsafe-watch [--chain base-sepolia|base-mainnet] [--duration <seconds>]
    \\                         [--quiet] [--archive <path>] [--p2p.* ...]
    \\       base unsafe-watch --check-archive <path> [--chain base-sepolia|base-mainnet]
    \\
;

const Flags = struct {
    chain: *const chains.ChainConfig = &chains.sepolia,
    duration_s: u64 = 0,
    quiet: bool = false,
    archive: ?[]const u8 = null,
    check_archive: ?[]const u8 = null,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.startsWith(u8, arg, "--p2p.")) {
            const has_value = std.mem.indexOfScalar(u8, arg, '=') != null or
                p2p.options.is_bool(arg["--p2p.".len..]);
            if (!has_value) index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--quiet")) {
            flags.quiet = true;
            continue;
        }
        if (index + 1 >= args.len) return error.InvalidArguments;
        const value = args[index + 1];
        index += 1;
        if (std.mem.eql(u8, arg, "--chain")) {
            flags.chain = if (std.mem.eql(u8, value, "base-sepolia"))
                &chains.sepolia
            else if (std.mem.eql(u8, value, "base-mainnet"))
                &chains.mainnet
            else
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--archive")) {
            flags.archive = value;
        } else if (std.mem.eql(u8, arg, "--check-archive")) {
            flags.check_archive = value;
        } else if (std.mem.eql(u8, arg, "--duration")) {
            flags.duration_s = std.fmt.parseInt(u64, value, 10) catch
                return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    return flags;
}

/// The rollup fields gossip validation reads, from the built-in public chain config.
pub fn rollup_for(chain: *const chains.ChainConfig) protocol.RollupConfig {
    var rollup: protocol.RollupConfig = .{
        .block_time = chain.block_time,
        .l1_chain_id = chain.l1_chain_id,
        .l2_chain_id = chain.chain_id,
        .l1_system_config_address = chain.system_config_address,
    };
    rollup.genesis.l2 = .{ .number = chain.genesis_l2_number, .hash = chain.genesis_l2_hash };
    rollup.genesis.l2_time = chain.genesis_l2_time;
    rollup.upgrades = protocol.rollup_config.UpgradeConfig.for_chain_id(chain.chain_id).?;
    assert(rollup.l2_chain_id != 0);
    assert(rollup.block_time > 0);
    return rollup;
}

/// Prints every gossip peer connect and disconnect with its identify agent and age.
const PeerLog = struct {
    const slots = p2p.gossip.router.peers_max;
    active: [slots]bool = @splat(false),
    connected_ns: [slots]u64 = @splat(0),

    fn poll(log: *PeerLog, service: *const p2p.service.Service, now_ns: u64) void {
        for (&service.connected, 0..) |*connection, slot| {
            if (connection.active == log.active[slot]) continue;
            log.active[slot] = connection.active;
            if (connection.active) {
                log.connected_ns[slot] = now_ns;
                std.debug.print("peer + {d} {s}\n", .{ slot, @tagName(connection.direction) });
            } else {
                const age_ms = (now_ns -| log.connected_ns[slot]) / ns_per_ms;
                std.debug.print("peer - {d} age_ms {d}\n", .{ slot, age_ms });
            }
        }
    }
};

const Watch = struct {
    rollup: *const protocol.RollupConfig,
    signer: base.common.primitives.Address,
    quiet: bool,
    head_number: u64 = 0,
    head_hash: base.common.primitives.B256 = .zero,
    received: u64 = 0,
    continuous: u64 = 0,
    gaps: u64 = 0,
    reorgs: u64 = 0,
    stale: u64 = 0,
    signer_mismatches: u64 = 0,
    lag_ms_sum: u64 = 0,
    lag_ms_max: u64 = 0,
    last_link: Link = .first,

    fn on_block(watch: *Watch, envelope: *const block.Envelope, now_ns: u64) void {
        const payload = &envelope.payload;
        watch.received += 1;
        const recovered = block.recover_signer(envelope, watch.rollup.l2_chain_id);
        const signer_ok = if (recovered) |address| address.eql(watch.signer) else false;
        if (!signer_ok) watch.signer_mismatches += 1;
        const expected_ms = watch.rollup.l2_block_timestamp_ms(payload.block_number);
        const now_ms = now_ns / ns_per_ms;
        const lag_ms = now_ms -| expected_ms;
        watch.lag_ms_sum += lag_ms;
        watch.lag_ms_max = @max(watch.lag_ms_max, lag_ms);
        const linked = watch.link(payload.block_number, payload.parent_hash);
        watch.last_link = linked;
        if (linked != .stale) {
            watch.head_number = payload.block_number;
            watch.head_hash = payload.block_hash;
        }
        if (watch.quiet) return;
        std.debug.print(
            "block {d} hash 0x{x} parent 0x{x} txs {d} gas {d} lag_ms {d} signer {s} {s}\n",
            .{
                payload.block_number,            payload.block_hash.bytes[0..8],
                payload.parent_hash.bytes[0..8], payload.transactions.count,
                payload.gas_used,                lag_ms,
                if (signer_ok) "ok" else "BAD",  @tagName(linked),
            },
        );
    }

    const Link = enum { first, ok, gap, reorg, stale };

    fn link(watch: *Watch, number: u64, parent_hash: base.common.primitives.B256) Link {
        if (watch.received == 1) return .first;
        if (number == watch.head_number + 1) {
            if (parent_hash.eql(watch.head_hash)) {
                watch.continuous += 1;
                return .ok;
            }
            watch.reorgs += 1;
            return .reorg;
        }
        if (number <= watch.head_number) {
            watch.stale += 1;
            return .stale;
        }
        watch.gaps += 1;
        return .gap;
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const rollup = rollup_for(flags.chain);
    // A watcher only receives, so it takes the low-latency preset unless told otherwise.
    var options = try p2p.options.parse_profile(args, .low_latency);
    const signer = options.unsafe_block_signer orelse flags.chain.unsafe_block_signer.?;
    if (flags.check_archive) |path| return check_archive(init, &rollup, signer, path);
    // Without inbound reachability (NAT), keep asking known peers for a slot.
    if (options.redial_known_interval_s == 0) options.redial_known_interval_s = 10;
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    var seed_bytes: [8]u8 = undefined;
    init.io.random(&seed_bytes);
    const seed = std.mem.readInt(u64, &seed_bytes, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const secret = try p2p.network.node_secret(&options, null, prng.random());
    const allocator = init.gpa;
    const network = try allocator.create(Network);
    defer allocator.destroy(network);
    try network.init(allocator, &os_io, &rollup, options, secret, signer, prng.random(), seed);
    const invalid = try network.start();
    std.debug.print("unsafe-watch: chain {s} signer 0x{x} bootnodes_invalid {d}\n", .{
        flags.chain.name, &signer.bytes, invalid,
    });
    var file: ?ArchiveFile = if (flags.archive) |path|
        try ArchiveFile.open(allocator, init.io, path)
    else
        null;
    defer if (file) |*value| value.close(allocator);
    var watch: Watch = .{ .rollup = &rollup, .signer = signer, .quiet = flags.quiet };
    try run(&os_io, network, &watch, if (file) |*value| value else null, &flags);
    network.stop();
    var drain: u32 = 0;
    while (network.busy() and drain < 1000) : (drain += 1) try os_io.run_for_ns(ns_per_ms);
    network.deinit(allocator);
    return if (watch.signer_mismatches == 0) 0 else 1;
}

fn run(
    os_io: *io.IO,
    network: *Network,
    watch: *Watch,
    file: ?*ArchiveFile,
    flags: *const Flags,
) !void {
    const scratch = try std.heap.page_allocator.alloc(u8, snappy.gossip_size_max);
    defer std.heap.page_allocator.free(scratch);
    var peer_log: PeerLog = .{};
    const start_ns = os_io.now_monotonic_ns();
    var report_ns = start_ns;
    while (true) {
        try os_io.run_for_ns(5 * ns_per_ms);
        const now_ns = os_io.now_realtime_ns();
        while (network.pop_block(scratch)) |envelope| {
            watch.on_block(&envelope, now_ns);
            if (file) |archive_file| try archive_file.append(&envelope, scratch, now_ns);
        }
        if (!flags.quiet) peer_log.poll(network.service, now_ns);
        const monotonic_ns = os_io.now_monotonic_ns();
        const elapsed_s = (monotonic_ns - start_ns) / ns_per_s;
        const done = flags.duration_s > 0 and elapsed_s >= flags.duration_s;
        if (done or monotonic_ns >= report_ns + 10 * ns_per_s) {
            report_ns = monotonic_ns;
            report(network, watch, elapsed_s);
            if (file) |archive_file| try archive_file.sync();
        }
        if (done) return;
    }
}

/// The `--archive` file: accepted blocks appended as gossiped, synced every report.
const ArchiveFile = struct {
    io: Io,
    file: Io.File,
    length: u64,
    compressor: snappy.Compressor = .{},
    output: []u8,
    records: u64 = 0,

    fn open(allocator: std.mem.Allocator, file_io: Io, path: []const u8) !ArchiveFile {
        const create: Io.Dir.CreateFileOptions = .{ .read = true, .truncate = false };
        const file = try Io.Dir.cwd().createFile(file_io, path, create);
        errdefer file.close(file_io);
        const output = try allocator.alloc(u8, archive.header_length + archive.data_length_max);
        errdefer allocator.free(output);
        // Cut a torn final record (a crash mid-write) before appending after it.
        const contents = try allocator.alloc(u8, @intCast(try file.length(file_io)));
        defer allocator.free(contents);
        const read = try file.readPositionalAll(file_io, contents, 0);
        if (read != contents.len) return error.ShortRead;
        var reader: archive.Reader = .{ .bytes = contents };
        var records: u64 = 0;
        while (reader.next() catch null) |_| records += 1;
        if (reader.position < contents.len) try file.setLength(file_io, reader.position);
        std.debug.print("archive: {s} has {d} records, appending at {d}\n", .{
            path, records, reader.position,
        });
        return .{ .io = file_io, .file = file, .length = reader.position, .output = output };
    }

    fn close(file: *ArchiveFile, allocator: std.mem.Allocator) void {
        file.file.sync(file.io) catch {};
        file.file.close(file.io);
        allocator.free(file.output);
    }

    /// Appends `envelope`, whose decompressed signed bytes are at the front of `scratch`.
    fn append(
        file: *ArchiveFile,
        envelope: *const block.Envelope,
        scratch: []const u8,
        now_ns: u64,
    ) !void {
        const length: usize = @intCast(block.signed_length(envelope.payload));
        assert(length <= scratch.len);
        const body = file.output[archive.header_length..];
        const data = file.compressor.compress(scratch[0..length], body);
        const record: archive.Record = .{
            .version = envelope.version,
            .received_ms = now_ns / ns_per_ms,
            .data = data,
        };
        archive.encode_header(file.output[0..archive.header_length], record);
        const bytes = file.output[0 .. archive.header_length + data.len];
        try file.file.writePositionalAll(file.io, bytes, file.length);
        file.length += bytes.len;
        file.records += 1;
    }

    fn sync(file: *ArchiveFile) !void {
        try file.file.sync(file.io);
    }
};

/// Re-verifies an archive offline: every record's signer and block hash, then the chain of
/// parent hashes. Exit 0 only when every record verifies and links to the one before it.
fn check_archive(
    init: std.process.Init,
    rollup: *const protocol.RollupConfig,
    signer: base.common.primitives.Address,
    path: []const u8,
) !u8 {
    const allocator = init.gpa;
    const contents = try Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 34));
    defer allocator.free(contents);
    const scratch = try allocator.alloc(u8, snappy.gossip_size_max);
    defer allocator.free(scratch);
    var watch: Watch = .{ .rollup = rollup, .signer = signer, .quiet = true };
    var reader: archive.Reader = .{ .bytes = contents };
    var invalid: u64 = 0;
    var first: u64 = 0;
    while (true) {
        const record = reader.next() catch |err| {
            const position = reader.position;
            std.debug.print("check-archive: {s} at offset {d}\n", .{ @errorName(err), position });
            invalid += 1;
            break;
        } orelse break;
        const envelope = archive.verify(rollup, signer, record, scratch) catch |err| {
            const position = reader.position;
            std.debug.print("check-archive: record at {d}: {s}\n", .{ position, @errorName(err) });
            invalid += 1;
            continue;
        };
        if (watch.received == 0) first = envelope.payload.block_number;
        watch.on_block(&envelope, record.received_ms * ns_per_ms);
        if (watch.last_link != .ok and watch.last_link != .first) {
            std.debug.print("check-archive: block {d} link {s}\n", .{
                envelope.payload.block_number, @tagName(watch.last_link),
            });
        }
    }
    const lag_ms_average = if (watch.received > 0) watch.lag_ms_sum / watch.received else 0;
    std.debug.print("check-archive: records {d} invalid {d} blocks {d}..{d} continuous {d} " ++
        "gaps {d} reorgs {d} stale {d} bad_signer {d} lag_ms_avg {d} lag_ms_max {d}\n", .{
        watch.received + invalid, invalid,        first,            watch.head_number,
        watch.continuous,         watch.gaps,     watch.reorgs,     watch.stale,
        watch.signer_mismatches,  lag_ms_average, watch.lag_ms_max,
    });
    const clean = invalid == 0 and watch.gaps == 0 and watch.reorgs == 0 and watch.stale == 0;
    return if (clean and watch.received > 0) 0 else 1;
}

fn report(network: *const Network, watch: *const Watch, elapsed_s: u64) void {
    const service = network.service;
    const gossip = &service.gossip.stats;
    const lag_ms_average = if (watch.received > 0) watch.lag_ms_sum / watch.received else 0;
    std.debug.print(
        "status t={d}s peers {d} blocks {d} continuous {d} gaps {d} reorgs {d} stale {d} " ++
            "bad_signer {d} head {d} lag_ms_avg {d} lag_ms_max {d} " ++
            "gossip_accepted {d} rejected {d} ignored {d} decode_failed {d}\n",
        .{
            elapsed_s,        network.peer_count(),    watch.received,
            watch.continuous, watch.gaps,              watch.reorgs,
            watch.stale,      watch.signer_mismatches, watch.head_number,
            lag_ms_average,   watch.lag_ms_max,        gossip.accepted,
            gossip.rejected,  gossip.ignored,          gossip.decode_failed,
        },
    );
    var text: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    print_counts(&writer, "failed", validity.Reason, &gossip.failed);
    const transport = &network.transport.stats;
    print_counts(&writer, "closed", p2p.libp2p.connection.CloseReason, &transport.close_reasons);
    writer.print("socket={d} ", .{transport.socket_closes}) catch {};
    print_counts(&writer, "dial", p2p.service.DialError, &service.stats.dial_errors);
    std.debug.print("  {s}\n", .{writer.buffered()});
    report_network(network);
}

fn print_counts(
    writer: *std.Io.Writer,
    label: []const u8,
    comptime Enum: type,
    counts: []const u64,
) void {
    const names = std.meta.fieldNames(Enum);
    assert(names.len == counts.len);
    writer.print("{s}: ", .{label}) catch return;
    for (names, counts) |name, count| {
        if (count > 0) writer.print("{s}={d} ", .{ name, count }) catch return;
    }
}

/// Discovery, transport, and gossipsub control counters, then one line per peer.
fn report_network(network: *const Network) void {
    const service = network.service;
    const disc = service.discovery.stats;
    const transport = &network.transport.stats;
    std.debug.print("  disc: live {d} lookups {d} packets {d} handshakes_out {d} " ++
        "timeouts {d} published {d} redials {d} | tcp: dialed {d} failed {d} accepted {d} " ++
        "bytes_in {d}\n", .{
        service.discovery.table.live_count(), disc.lookups,
        disc.packets_received,                disc.handshakes_initiated,
        disc.requests_timed_out,              disc.discovered,
        service.stats.redials,                transport.dialed,
        transport.dial_failures,              transport.accepted,
        transport.bytes_received,
    });
    const router = &service.gossip.router;
    const stats = router.stats;
    std.debug.print("  gossip: topics {d} rpcs {d} publish {d} graft {d} prune {d} " ++
        "ihave {d} iwant {d}\n", .{
        router.subscribed_count(), stats.rpcs_received,   stats.publishes_received,
        stats.grafts_received,     stats.prunes_received, stats.ihaves_received,
        stats.iwants_received,
    });
    for (&service.connected, 0..) |*connection, slot| {
        if (!connection.active) continue;
        const index: p2p.gossip.router.Slot = @intCast(slot);
        std.debug.print("  peer {d} agent {s} topics 0b{b:0>4} mesh 0b{b:0>4} first {d}\n", .{
            slot,                                connection.info.agent_version.slice(),
            router.peers[slot].topics,           mesh_topics(router, index),
            router.peers[slot].first_deliveries,
        });
        const info = &connection.info;
        for (info.protocols[0..info.protocols_count]) |*name| {
            std.debug.print("    protocol {s}\n", .{name.slice()});
        }
    }
}

/// Bit `t` set when peer `slot` is in our mesh for topic index `t`.
fn mesh_topics(router: *const p2p.gossip.router.Router, slot: p2p.gossip.router.Slot) u8 {
    var mesh: u8 = 0;
    for (router.mesh, 0..) |set, topic| {
        if (set & (@as(u64, 1) << @intCast(slot)) != 0) mesh |= @as(u8, 1) << @intCast(topic);
    }
    return mesh;
}

test "unsafe-watch: rollup config from the built-in chain" {
    const rollup = rollup_for(&chains.sepolia);
    try std.testing.expectEqual(@as(u64, 84532), rollup.l2_chain_id);
    try std.testing.expect(rollup.upgrades.get(.denim) != null);
    const flags = try parse_flags(&.{ "--p2p.peers.hi", "4", "--quiet" });
    try std.testing.expect(flags.quiet);
}

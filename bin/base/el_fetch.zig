//! `base el-fetch`: fetches a block range from one execution-layer peer over devp2p
//! (RLPx + eth/68, `el_source.zig`), with no RPC, and checks it: every header hashes to the
//! next header's parent hash, and every body's transactions match its header's
//! `transactionsRoot`. This is the peer-based block source for snapshot-to-tip catch-up
//! (docs/UNSAFE_TIP.md).
//!
//!     base el-fetch --enode <enode://...> --from <block|tip> [--count <n>] [--batch <n>]
//!                   [--parent <hash>] [--follow] [--duration <s>] [--verbose] [--trace]
//!                   [--chain base-sepolia|base-mainnet]
//!
//! `--from tip` starts at the peer's head. `--parent` binds the first block to a known hash
//! (the snapshot block's). `--follow` keeps going past `--count`: it polls for the next
//! block every 100 ms and prints each one with its tip lag (now minus the block's scheduled
//! time), for `--duration` seconds. A dropped connection is reopened and the range resumes
//! from the last linked block. `--verbose` prints every block's hash; `--trace` every
//! response's size and latency.
//!
//! `--peers <file>` (one enode per line) fetches through `el_feed.zig` instead: from every
//! peer at once (`el_pool.zig`) up to a few hundred blocks below the tip, then one peer
//! following the tip, from `--from <block>` for `--count` blocks or `--duration` seconds.
//! It reports the download rate and, once at the tip, the lag: blocks are checked and
//! linked, not executed. `--consume-us <n>` makes the consumer spend `n` microseconds per
//! block, standing in for execution, to see how the pool behaves behind a slower consumer.
//! `--gossip` (with any `--p2p.*` flags) checks each block against the sequencer-signed
//! gossip block at its height (`el_gossip.zig`).

const std = @import("std");
const base = @import("base");

const el_source = @import("el_source.zig");
const el_feed = @import("el_feed.zig");
const el_gossip = @import("el_gossip.zig");
const unsafe_watch = @import("unsafe_watch.zig");
const enode = base.consensus.p2p.peers.enode;
const curve = base.common.crypto.secp256k1;
const Io = std.Io;
const assert = std.debug.assert;

const usage =
    \\usage: base el-fetch --enode <enode://...> --from <block|tip> [--count <n>] [--batch <n>]
    \\                     [--parent <hash>] [--follow] [--duration <s>] [--verbose] [--trace]
    \\                     [--chain base-sepolia|base-mainnet]
    \\       base el-fetch --peers <file> --from <block> [--count <n>] [--duration <s>]
    \\                     [--parent <hash>] [--consume-us <n>] [--gossip [--p2p.* ...]]
    \\                     [--chain base-sepolia|base-mainnet]
    \\
;

const Flags = struct {
    enode: ?[]const u8 = null,
    peers: ?[]const u8 = null,
    from: ?u64 = null,
    from_tip: bool = false,
    parent: ?[32]u8 = null,
    follow: bool = false,
    gossip: bool = false,
    args: []const []const u8 = &.{},
    verbose: bool = false,
    trace: bool = false,
    duration_s: u64 = 0,
    consume_us: u64 = 0,
    count: u64 = 1000,
    batch: u32 = 128,
    chain: *const base.common.chains.ChainConfig = &base.common.chains.sepolia,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{ .args = args };
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const name = args[index];
        if (std.mem.eql(u8, name, "--follow")) {
            flags.follow = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--verbose")) {
            flags.verbose = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--trace")) {
            flags.trace = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--gossip")) {
            flags.gossip = true;
            continue;
        }
        if (std.mem.startsWith(u8, name, "--p2p.")) {
            const has_value = std.mem.indexOfScalar(u8, name, '=') != null or
                base.consensus.p2p.options.is_bool(name["--p2p.".len..]);
            if (!has_value) index += 1;
            continue;
        }
        index += 1;
        if (index == args.len) return error.InvalidArguments;
        const value = args[index];
        if (std.mem.eql(u8, name, "--enode")) {
            flags.enode = value;
        } else if (std.mem.eql(u8, name, "--peers")) {
            flags.peers = value;
        } else if (std.mem.eql(u8, name, "--consume-us")) {
            flags.consume_us = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--duration")) {
            flags.duration_s = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--from")) {
            if (std.mem.eql(u8, value, "tip")) {
                flags.from_tip = true;
            } else {
                flags.from = try std.fmt.parseInt(u64, value, 10);
            }
        } else if (std.mem.eql(u8, name, "--parent")) {
            const text = if (std.mem.startsWith(u8, value, "0x")) value[2..] else value;
            if (text.len != 64) return error.InvalidArguments;
            var hash: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&hash, text);
            flags.parent = hash;
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
    if ((flags.enode == null) == (flags.peers == null)) return error.InvalidArguments;
    if ((flags.from == null) == !flags.from_tip) return error.InvalidArguments;
    if (flags.peers != null and flags.from_tip) return error.InvalidArguments;
    if (flags.batch == 0 or flags.batch > el_source.batch_max) return error.InvalidArguments;
    if (flags.count == 0) return error.InvalidArguments;
    return flags;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    if (flags.peers) |path| return run_pool(init, &flags, path);
    const node = enode.parse(flags.enode.?) catch {
        std.debug.print("el-fetch: invalid enode\n", .{});
        return 2;
    };
    const remote_compressed = node.public_key;
    const target: el_source.Target = .{
        .address = switch (node.address) {
            .ip4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = node.tcp_port } },
            .ip6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = node.tcp_port } },
        },
        .remote = curve.decompress_public_key(&remote_compressed) orelse return error.InvalidKey,
        .secret = el_source.random_secret(init.io),
        .chain = flags.chain,
    };
    const source = try init.gpa.create(el_source.Source);
    defer init.gpa.destroy(source);
    try source.init(init.gpa, init.io, target, .{
        .from = flags.from,
        .parent = flags.parent,
        .batch = flags.batch,
        .trace = flags.trace,
    });
    defer source.deinit(init.gpa);
    return run(source, init.io, &flags);
}

const Lag = struct {
    count: u64 = 0,
    sum_ms: u64 = 0,
    max_ms: u64 = 0,
};

fn run(source: *el_source.Source, io: Io, flags: *const Flags) !u8 {
    const from = source.next_number;
    const end = if (flags.follow) std.math.maxInt(u64) else from + flags.count;
    const rollup = unsafe_watch.rollup_for(flags.chain);
    const start = Io.Clock.awake.now(io);
    var at_tip = false;
    var lag: Lag = .{};
    var last: el_source.Block = undefined;
    var reported: u64 = 0;
    while (source.next_number < end) {
        const elapsed = start.durationTo(Io.Clock.awake.now(io));
        const elapsed_ms: u64 = @intCast(@max(1, elapsed.toMilliseconds()));
        if (flags.duration_s > 0 and elapsed_ms >= flags.duration_s * 1000) break;
        if (!try source.next(&last)) {
            at_tip = true;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        }
        if (flags.verbose and !at_tip) {
            std.debug.print("el-fetch: block {d} hash 0x{x} txs {d}\n", .{
                last.number, &last.hash, last.transactions.len,
            });
        }
        if (at_tip) {
            const now = Io.Clock.real.now(io);
            const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
            const lag_ms = now_ms -| rollup.l2_block_timestamp_ms(last.number);
            lag.count += 1;
            lag.sum_ms += lag_ms;
            lag.max_ms = @max(lag.max_ms, lag_ms);
            std.debug.print("el-fetch: tip block {d} hash 0x{x} txs {d} lag_ms {d}\n", .{
                last.number, &last.hash, last.transactions.len, lag_ms,
            });
        } else if (source.blocks - reported >= flags.batch) {
            reported = source.blocks;
            std.debug.print("el-fetch: blocks {d}..{d} txs {d} bytes {d} blocks_per_s {d}\n", .{
                from,                              last.number,
                source.transactions_count,         source.peer.bytes,
                source.blocks * 1000 / elapsed_ms,
            });
        }
    }
    if (source.blocks == 0) return error.NoBlocks;
    std.debug.print("el-fetch: ok, {d} linked blocks {d}..{d}, last hash 0x{x}, " ++
        "reconnects {d}\n", .{
        source.blocks, from, source.next_number - 1, &source.parent.?, source.reconnects,
    });
    if (lag.count > 0) std.debug.print("el-fetch: tip blocks {d} lag_ms avg {d} max {d}\n", .{
        lag.count, lag.sum_ms / lag.count, lag.max_ms,
    });
    return 0;
}

/// Download only, through the multi-peer feed: rates, per-peer counters, and tip lag.
fn run_pool(init: std.process.Init, flags: *const Flags, path: []const u8) !u8 {
    const io = init.io;
    const feed = el_feed.Feed.create(init.gpa, io, .{
        .chain = flags.chain,
        .from = flags.from.?,
        .parent = flags.parent,
        .peers_path = path,
    }) catch |err| {
        std.debug.print("el-fetch: no usable peers in {s}: {t}\n", .{ path, err });
        return 2;
    };
    defer feed.destroy();
    const gossip = if (flags.gossip)
        try el_gossip.Gossip.start(init.gpa, io, flags.chain, null, flags.args)
    else
        null;
    defer if (gossip) |value| value.destroy();
    const rollup = unsafe_watch.rollup_for(flags.chain);
    const start = Io.Clock.awake.now(io);
    var last_report_ms: i64 = 0;
    var block: el_source.Block = undefined;
    var blocks: u64 = 0;
    var lag: Lag = .{};
    while (blocks < flags.count) {
        const elapsed_ms = start.durationTo(Io.Clock.awake.now(io)).toMilliseconds();
        const duration_ms: i64 = @intCast(flags.duration_s * 1000);
        if (flags.duration_s > 0 and elapsed_ms >= duration_ms) break;
        if (elapsed_ms - last_report_ms >= 5_000) {
            last_report_ms = elapsed_ms;
            report(feed, elapsed_ms, blocks, &lag);
            if (gossip) |value| value.summary();
        }
        if (!try feed.next(&block)) {
            if (!flags.follow and feed.mode == .follow) break;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        }
        blocks += 1;
        if (gossip) |value| _ = value.on_chain(block.number, block.hash);
        if (flags.consume_us > 0) {
            try io.sleep(.fromMicroseconds(@intCast(flags.consume_us)), .awake);
        }
        if (feed.at_tip) {
            const now = Io.Clock.real.now(io);
            const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
            const lag_ms = now_ms -| rollup.l2_block_timestamp_ms(block.number);
            lag.count += 1;
            lag.sum_ms += lag_ms;
            lag.max_ms = @max(lag.max_ms, lag_ms);
        }
    }
    const elapsed_ms = start.durationTo(Io.Clock.awake.now(io)).toMilliseconds();
    report(feed, elapsed_ms, blocks, &lag);
    if (gossip) |value| value.summary();
    feed.pool.print_peers();
    std.debug.print("el-fetch: ok, {d} linked blocks {d}..{d}, {d} duplicate segments\n", .{
        blocks, flags.from.?, feed.next_number -| 1, feed.pool.duplicates,
    });
    return 0;
}

fn report(feed: *el_feed.Feed, elapsed_ms: i64, blocks: u64, lag: *const Lag) void {
    const elapsed: u64 = @intCast(@max(elapsed_ms, 1));
    const last = feed.next_number -| 1;
    std.debug.print("el-fetch: at {d}, {d} blocks, {d} blocks/s, {t}, {d} behind the " ++
        "schedule, tip blocks {d} lag_ms avg {d} max {d}\n", .{
        last,
        blocks,
        blocks * 1000 / elapsed,
        feed.mode,
        feed.pool.tip_estimate() -| last,
        lag.count,
        if (lag.count == 0) 0 else lag.sum_ms / lag.count,
        lag.max_ms,
    });
}

test "el-fetch: flags take a number or the tip, and a valueless --follow anywhere" {
    const enode_text = "enode://00@127.0.0.1:1";
    const tip = try parse_flags(&.{ "--follow", "--enode", enode_text, "--from", "tip" });
    try std.testing.expect(tip.follow and tip.from_tip and tip.from == null);
    const number = try parse_flags(&.{ "--from", "7", "--enode", enode_text, "--follow" });
    try std.testing.expectEqual(@as(?u64, 7), number.from);
    try std.testing.expect(number.follow and !number.from_tip);
    const missing = parse_flags(&.{ "--enode", enode_text });
    try std.testing.expectError(error.InvalidArguments, missing);
    const no_value = parse_flags(&.{ "--enode", enode_text, "--from" });
    try std.testing.expectError(error.InvalidArguments, no_value);
    const parent = "0x" ++ ("abababababababababababababababab" ++
        "abababababababababababababababab");
    const bound = try parse_flags(&.{ "--enode", enode_text, "--from", "1", "--parent", parent });
    try std.testing.expectEqual(@as(u8, 0xab), bound.parent.?[31]);
}

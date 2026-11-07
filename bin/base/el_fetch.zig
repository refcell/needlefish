//! `base el-fetch`: fetches a block range from one execution-layer peer over devp2p
//! (RLPx + eth/68, `el_source.zig`), with no RPC, and checks it: every header hashes to the
//! next header's parent hash, and every body's transactions match its header's
//! `transactionsRoot`. This is the peer-based block source for snapshot-to-tip catch-up
//! (docs/UNSAFE_TIP.md).
//!
//!     base el-fetch --enode <enode://...> --from <block|tip> [--count <n>] [--batch <n>]
//!                   [--parent <hash>] [--follow] [--duration <s>] [--verbose]
//!                   [--chain base-sepolia|base-mainnet]
//!
//! `--from tip` starts at the peer's head. `--parent` binds the first block to a known hash
//! (the snapshot block's). `--follow` keeps going past `--count`: it polls for the next
//! block every 100 ms and prints each one with its tip lag (now minus the block's scheduled
//! time), for `--duration` seconds. A dropped connection is reopened and the range resumes
//! from the last linked block. `--verbose` prints every block's hash.

const std = @import("std");
const base = @import("base");

const el_source = @import("el_source.zig");
const unsafe_watch = @import("unsafe_watch.zig");
const enode = base.consensus.p2p.peers.enode;
const curve = base.common.crypto.secp256k1;
const Io = std.Io;
const assert = std.debug.assert;

const usage =
    \\usage: base el-fetch --enode <enode://...> --from <block|tip> [--count <n>] [--batch <n>]
    \\                     [--parent <hash>] [--follow] [--duration <s>] [--verbose]
    \\                     [--chain base-sepolia|base-mainnet]
    \\
;

const Flags = struct {
    enode: ?[]const u8 = null,
    from: ?u64 = null,
    from_tip: bool = false,
    parent: ?[32]u8 = null,
    follow: bool = false,
    verbose: bool = false,
    duration_s: u64 = 0,
    count: u64 = 1000,
    batch: u32 = 128,
    chain: *const base.common.chains.ChainConfig = &base.common.chains.sepolia,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
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
        index += 1;
        if (index == args.len) return error.InvalidArguments;
        const value = args[index];
        if (std.mem.eql(u8, name, "--enode")) {
            flags.enode = value;
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
    if (flags.enode == null or (flags.from == null) == !flags.from_tip) {
        return error.InvalidArguments;
    }
    if (flags.batch == 0 or flags.batch > el_source.batch_max) return error.InvalidArguments;
    if (flags.count == 0) return error.InvalidArguments;
    return flags;
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
                source.transactions_count,         source.bytes,
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

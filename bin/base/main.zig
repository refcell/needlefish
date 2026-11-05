//! `base`: the multi-tool CLI. Subcommands dispatch to the node, consensus,
//! batcher, and tooling entry points as they land.

const std = @import("std");
const base = @import("base");
const devnet = @import("devnet.zig");
const batcher = @import("batcher.zig");
const node = @import("node.zig");
const consensus = @import("consensus.zig");
const proof = @import("proof.zig");
const balance_monitor = @import("balance_monitor.zig");
const load_test = @import("load_test.zig");
const snapshotter = @import("snapshotter.zig");
const roxy = @import("roxy.zig");
const basectl = @import("basectl.zig");

const usage =
    \\usage: base <command> [args]
    \\
    \\commands:
    \\  version    print version
    \\  devnet     generate local devnet config (base devnet init)
    \\  batcher    submit L2 batches to L1
    \\  node       execution node (--dev-l1 for a standalone L1 dev chain)
    \\  consensus  consensus (rollup) node: derivation, engine driving, optimism_* RPC
    \\  proof      fault-proof tooling (replay a recorded preimage archive)
    \\  balance-monitor  poll an account balance, serve metrics and health
    \\  load-test  send a seeded transaction workload, report inclusion latency
    \\  snapshotter  create, restore, or verify node datadir snapshots
    \\  roxy       JSON-RPC reverse proxy: load balancing, retries, method allowlist
    \\  basectl    operator commands: sync-status, block, txpool, doctor, ...
    \\
;

test {
    _ = devnet;
    _ = batcher;
    _ = node;
    _ = consensus;
    _ = proof;
    _ = balance_monitor;
    _ = load_test;
    _ = snapshotter;
    _ = roxy;
    _ = basectl;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return;
    }
    const command = args[1];
    if (std.mem.eql(u8, command, "version")) {
        std.debug.print("base {s} ({s})\n", .{
            base.build_options.version,
            base.build_options.git_rev,
        });
        return;
    }
    if (std.mem.eql(u8, command, "devnet")) {
        std.process.exit(try devnet.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "node")) {
        std.process.exit(try node.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "consensus")) {
        std.process.exit(try consensus.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "batcher")) {
        std.process.exit(try batcher.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "proof")) {
        std.process.exit(try proof.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "balance-monitor")) {
        std.process.exit(try balance_monitor.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "snapshotter")) {
        std.process.exit(try snapshotter.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "load-test")) {
        std.process.exit(try load_test.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "roxy")) {
        std.process.exit(try roxy.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "basectl")) {
        std.process.exit(try basectl.main(init, args[2..]));
    }
    std.debug.print("unknown command: {s}\n{s}", .{ command, usage });
    std.process.exit(2);
}

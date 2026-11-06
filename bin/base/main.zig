//! `base`: the multi-tool CLI. Subcommands dispatch to the node, consensus,
//! batcher, and tooling entry points as they land.

const std = @import("std");
const base = @import("base");
const devnet = @import("devnet.zig");
const batcher = @import("batcher.zig");
const node = @import("node.zig");
const consensus = @import("consensus.zig");
const proof = @import("proof.zig");
const proposer = @import("proposer.zig");
const challenger = @import("challenger.zig");
const prover_service = @import("prover_service.zig");
const balance_monitor = @import("balance_monitor.zig");
const load_test = @import("load_test.zig");
const withdrawer = @import("withdrawer.zig");
const snapshotter = @import("snapshotter.zig");
const sidecrush = @import("sidecrush.zig");
const fee_jobs = @import("fee_jobs.zig");
const roxy = @import("roxy.zig");
const basectl = @import("basectl.zig");
const audit = @import("audit.zig");

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
    \\  proposer   propose output-root dispute games
    \\  challenger dispute invalid output-root games, claim bonds
    \\  prover-service  proof-request JSON-RPC service
    \\  prover-worker   claim and prove range jobs with the native host
    \\  balance-monitor  poll an account balance, serve metrics and health
    \\  load-test  send a seeded transaction workload, report inclusion latency
    \\  withdrawer  L2->L1 withdrawals: initiate, status, prove, finalize, run
    \\  snapshotter  create, restore, or verify node datadir snapshots
    \\  sidecrush  block-production health sidecar (metrics, readiness)
    \\  fee-jobs  one-shot fee jobs: disburse, process, sweep
    \\  roxy       JSON-RPC reverse proxy: load balancing, retries, method allowlist
    \\  basectl    operator commands: sync-status, block, txpool, doctor, ...
    \\  audit      transaction-event audit archiver: Vector ingest, JSON-RPC queries
    \\
;

test {
    _ = devnet;
    _ = batcher;
    _ = node;
    _ = consensus;
    _ = proof;
    _ = proposer;
    _ = challenger;
    _ = prover_service;
    _ = balance_monitor;
    _ = load_test;
    _ = withdrawer;
    _ = snapshotter;
    _ = sidecrush;
    _ = fee_jobs;
    _ = roxy;
    _ = basectl;
    _ = audit;
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
    if (std.mem.eql(u8, command, "prover-service")) {
        std.process.exit(try prover_service.service_main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "prover-worker")) {
        std.process.exit(try prover_service.worker_main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "challenger")) {
        std.process.exit(try challenger.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "proposer")) {
        std.process.exit(try proposer.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "proof")) {
        std.process.exit(try proof.main(init, args[2..]));
    }
    if (try infra_main(init, command, args[2..])) |status| std.process.exit(status);
    std.debug.print("unknown command: {s}\n{s}", .{ command, usage });
    std.process.exit(2);
}

/// Infra-lane tools (`src/infra`); null when `command` is not one of them.
fn infra_main(init: std.process.Init, command: []const u8, args: []const []const u8) !?u8 {
    std.debug.assert(command.len > 0);
    if (std.mem.eql(u8, command, "balance-monitor")) {
        return try balance_monitor.main(init, args);
    }
    if (std.mem.eql(u8, command, "fee-jobs")) {
        return try fee_jobs.main(init, args);
    }
    if (std.mem.eql(u8, command, "sidecrush")) {
        return try sidecrush.main(init, args);
    }
    if (std.mem.eql(u8, command, "snapshotter")) {
        return try snapshotter.main(init, args);
    }
    if (std.mem.eql(u8, command, "withdrawer")) {
        return try withdrawer.main(init, args);
    }
    if (std.mem.eql(u8, command, "load-test")) {
        return try load_test.main(init, args);
    }
    if (std.mem.eql(u8, command, "roxy")) {
        return try roxy.main(init, args);
    }
    if (std.mem.eql(u8, command, "basectl")) {
        return try basectl.main(init, args);
    }
    if (std.mem.eql(u8, command, "audit")) {
        return try audit.main(init, args);
    }
    return null;
}

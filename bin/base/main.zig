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
const registrar = @import("registrar.zig");
const prover_service = @import("prover_service.zig");
const nitro_enclave = @import("nitro_enclave.zig");
const balance_monitor = @import("balance_monitor.zig");
const load_test = @import("load_test.zig");
const withdrawer = @import("withdrawer.zig");
const snapshotter = @import("snapshotter.zig");
const sidecrush = @import("sidecrush.zig");
const fee_jobs = @import("fee_jobs.zig");
const roxy = @import("roxy.zig");
const basectl = @import("basectl.zig");
const audit = @import("audit.zig");
const replay = @import("replay.zig");
const follow = @import("follow.zig");
const snapshot_import = @import("snapshot_import.zig");
const import_run = @import("import_run.zig");
const unsafe_watch = @import("unsafe_watch.zig");
const el_fetch = @import("el_fetch.zig");
const el_peers = @import("el_peers.zig");
const el_run = @import("el_run.zig");
const state_check = @import("state_check.zig");
const derive_check = @import("derive_check.zig");
const https_bridge = @import("https_bridge.zig");

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
    \\  registrar  register TEE prover signers from Nitro attestations
    \\  prover-service  proof-request JSON-RPC service
    \\  prover-worker   claim and prove range jobs with the native host
    \\  nitro-enclave   TEE enclave server in local mode (TCP in place of vsock)
    \\  balance-monitor  poll an account balance, serve metrics and health
    \\  load-test  send a seeded transaction workload, report inclusion latency
    \\  withdrawer  L2->L1 withdrawals: initiate, status, prove, finalize, run
    \\  snapshotter  create, restore, or verify node datadir snapshots
    \\  sidecrush  block-production health sidecar (metrics, readiness)
    \\  fee-jobs  one-shot fee jobs: disburse, process, sweep
    \\  roxy       JSON-RPC reverse proxy: load balancing, retries, method allowlist
    \\  basectl    operator commands: sync-status, block, txpool, doctor, ...
    \\  audit      transaction-event audit archiver: Vector ingest, JSON-RPC queries
    \\  replay     replay real Base blocks offline and check every header field
    \\  follow     follow a live Base chain over RPC, re-executing and checking every block
    \\  snapshot-import  verify a reth snapshot database: state root against the block header
    \\  import-run  execute blocks N+1.. on an imported disk-mode database, checking headers
    \\  unsafe-watch  join a Base chain's p2p gossip (no RPC), check signer and continuity
    \\  el-fetch   fetch and check a block range from an execution peer (devp2p eth/68)
    \\  el-peers   find a Base chain's execution peers over discv4
    \\  el-run     execute blocks from an execution peer (devp2p) on an imported database
    \\  state-check  spot-check a database's accounts and slots against a reference node
    \\  derive-check  derive a Base chain's safe blocks from L1, compare with a reference node
    \\  https-bridge  forward plain HTTP on loopback to HTTPS upstreams (public L1 for consensus)
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
    _ = registrar;
    _ = prover_service;
    _ = nitro_enclave;
    _ = balance_monitor;
    _ = load_test;
    _ = withdrawer;
    _ = snapshotter;
    _ = sidecrush;
    _ = fee_jobs;
    _ = roxy;
    _ = basectl;
    _ = audit;
    _ = replay;
    _ = follow;
    _ = snapshot_import;
    _ = import_run;
    _ = unsafe_watch;
    _ = el_fetch;
    _ = el_peers;
    _ = el_run;
    _ = state_check;
    _ = derive_check;
    _ = https_bridge;
    _ = @import("derive_check_net.zig");
    _ = @import("el_source.zig");
    _ = @import("el_pool.zig");
    _ = @import("metrics_server.zig");
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
    if (std.mem.eql(u8, command, "nitro-enclave")) {
        std.process.exit(try nitro_enclave.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "prover-worker")) {
        std.process.exit(try prover_service.worker_main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "challenger")) {
        std.process.exit(try challenger.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "registrar")) {
        std.process.exit(try registrar.main(init, args[2..]));
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
    if (std.mem.eql(u8, command, "replay")) {
        return try replay.main(init, args);
    }
    if (std.mem.eql(u8, command, "follow")) {
        return try follow.main(init, args);
    }
    if (std.mem.eql(u8, command, "snapshot-import")) {
        return try snapshot_import.main(init, args);
    }
    if (std.mem.eql(u8, command, "import-run")) {
        return try import_run.main(init, args);
    }
    if (std.mem.eql(u8, command, "unsafe-watch")) {
        return try unsafe_watch.main(init, args);
    }
    if (std.mem.eql(u8, command, "el-fetch")) {
        return try el_fetch.main(init, args);
    }
    if (std.mem.eql(u8, command, "el-peers")) {
        return try el_peers.main(init, args);
    }
    if (std.mem.eql(u8, command, "el-run")) {
        return try el_run.main(init, args);
    }
    if (std.mem.eql(u8, command, "state-check")) {
        return try state_check.main(init, args);
    }
    if (std.mem.eql(u8, command, "derive-check")) {
        return try derive_check.main(init, args);
    }
    if (std.mem.eql(u8, command, "https-bridge")) {
        return try https_bridge.main(init, args);
    }
    return null;
}

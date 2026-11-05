//! `base challenger`: scans dispute games, disputes invalid output roots, keeps the anchor
//! moving and claims bonds (base/base `bin/challenger`, `crates/proof/challenge`).

const std = @import("std");
const base = @import("base");
const consensus_cli = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const proof = base.proof;
const challenger = proof.challenger;
const secp256k1 = base.common.crypto.secp256k1;

const RpcClient = proof.host.rpc_source.RpcSource(io.IO).Client;
const Endpoint = proof.rpc.Endpoint(io.IO);
const Chain = challenger.rpc_chain.RpcChain(Endpoint);
const Submitter = challenger.tx_submitter.TxSubmitter(Endpoint);
const ServiceClient = proof.prover_service.client.Client(io.IO);
const ChallengerProver = proof.prover_service.challenger_prover.ChallengerProver(io.IO);

const usage =
    \\usage: base challenger --l1-eth-rpc <url> --l2-eth-rpc <url>
    \\         --dispute-game-factory-addr <addr> --anchor-state-registry-addr <addr>
    \\         --game-type <n> --private-key <hex> [--zk-rpc-url <url>]
    \\         [--poll-interval 12s] [--max-proof-duration 4h] [--tee-submit-retry-limit 3]
    \\         [--bond-discovery-lookback-games 1000] [--bond-discovery-interval 300s]
    \\         [--bond-claim-addresses a,b] [--ticks-max n]
    \\
;

const http_options: http.client.Options = .{
    .recv_buffer_size = (16 << 20) + 64 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 16 << 20 },
    .request_timeout_ns = 60 * std.time.ns_per_s,
};

const Process = struct {
    os_io: io.IO,
    l1_client: RpcClient,
    l2_client: RpcClient,
    l1_view: Endpoint,
    l1_tx: Endpoint,
    l2: Endpoint,
    chain: Chain,
    submitter: Submitter,
    driver: challenger.Driver,
    prover_http: RpcClient,
    prover_endpoint: Endpoint,
    prover_client: ServiceClient,
    prover: ChallengerProver,

    fn step(context: *anyopaque) anyerror!void {
        const os_io: *io.IO = @ptrCast(@alignCast(context));
        try os_io.run_for_ns(std.time.ns_per_ms);
    }

    fn pump(process: *Process) proof.rpc.endpoint.Pump {
        return .{ .context = &process.os_io, .step = step };
    }
};

/// Without `--zk-rpc-url` every proof request is refused and the attempt retries, while
/// scanning, anchor updates and bond claims run.
const NoProver = struct {
    fn request(
        _: *anyopaque,
        _: challenger.chain.Address,
        _: u64,
        _: challenger.chain.ProofRequest,
    ) challenger.chain.ProverError!challenger.chain.SessionId {
        return error.ProverUnavailable;
    }

    fn poll(
        _: *anyopaque,
        _: challenger.chain.SessionId,
    ) challenger.chain.ProverError!challenger.chain.ProverStatus {
        return error.ProverUnavailable;
    }

    const vtable: challenger.chain.Prover.VTable = .{ .request = request, .poll = poll };
    var instance: u8 = 0;

    fn prover() challenger.chain.Prover {
        return .{ .context = &instance, .vtable = &vtable };
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = challenger.flags.parse(args) catch |err| {
        std.debug.print("challenger: {t}\n{s}", .{ err, usage });
        return 2;
    };
    const allocator = init.gpa;
    const process = try allocator.create(Process);
    defer allocator.destroy(process);
    connect(process, allocator, &flags) catch |err| {
        std.debug.print("challenger: cannot connect to the L1/L2 endpoints: {t}\n", .{err});
        return 1;
    };
    defer disconnect(process, allocator);
    const prover = if (flags.zk_rpc_url.len == 0) NoProver.prover() else prover: {
        open_prover(process, allocator, flags.zk_rpc_url) catch |err| {
            std.debug.print("challenger: cannot open the prover service: {t}\n", .{err});
            return 1;
        };
        break :prover process.prover.prover();
    };
    defer if (flags.zk_rpc_url.len > 0) close_prover(process, allocator);
    const sender = try secp256k1.address(flags.private_key.?);
    process.driver.init(flags.driver_config(sender), .{
        .chain = process.chain.view(),
        .prover = prover,
        .submitter = process.submitter.submitter(),
    });
    return tick_loop(process, &flags);
}

fn connect(
    process: *Process,
    allocator: std.mem.Allocator,
    flags: *const challenger.flags.Flags,
) !void {
    const builtin = @import("builtin");
    process.os_io = if (builtin.os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    errdefer process.os_io.deinit();
    const os_io = &process.os_io;
    const l1 = try consensus_cli.parse_url(flags.l1_eth_rpc);
    const l2 = try consensus_cli.parse_url(flags.l2_eth_rpc);
    process.l1_client = try .init(allocator, os_io, l1, http_options, 4096);
    errdefer process.l1_client.deinit();
    process.l2_client = try .init(allocator, os_io, l2, http_options, 4096);
    errdefer process.l2_client.deinit();
    const steps_max = 300_000;
    process.l1_view = .init(allocator, &process.l1_client, process.pump(), steps_max);
    errdefer process.l1_view.deinit();
    process.l1_tx = .init(allocator, &process.l1_client, process.pump(), steps_max);
    errdefer process.l1_tx.deinit();
    process.l2 = .init(allocator, &process.l2_client, process.pump(), steps_max);
    errdefer process.l2.deinit();
    process.chain = .init(&process.l1_view, &process.l2, .{
        .factory = flags.dispute_game_factory,
        .anchor_state_registry = flags.anchor_state_registry,
    });
    const chain_id = try proof.rpc.endpoint.parse_quantity(
        try process.l1_tx.call("eth_chainId", &.{}),
    );
    process.l1_tx.reset();
    const key = flags.private_key.?;
    process.submitter = try .init(allocator, &process.l1_tx, .{
        .chain_id = chain_id,
        .private_key = key,
        .from = try secp256k1.address(key),
    });
}

fn open_prover(process: *Process, allocator: std.mem.Allocator, url: []const u8) !void {
    const address = try consensus_cli.parse_url(url);
    process.prover_http = try .init(allocator, &process.os_io, address, http_options, 4096);
    errdefer process.prover_http.deinit();
    process.prover_endpoint = .init(allocator, &process.prover_http, process.pump(), 300_000);
    errdefer process.prover_endpoint.deinit();
    process.prover_client = try .init(allocator, &process.prover_endpoint, .{});
    process.prover = .{ .client = &process.prover_client };
}

fn close_prover(process: *Process, allocator: std.mem.Allocator) void {
    process.prover_client.deinit(allocator);
    process.prover_endpoint.deinit();
    process.prover_http.deinit();
}

fn disconnect(process: *Process, allocator: std.mem.Allocator) void {
    process.submitter.deinit(allocator);
    process.l2.deinit();
    process.l1_tx.deinit();
    process.l1_view.deinit();
    process.l2_client.deinit();
    process.l1_client.deinit();
    process.os_io.deinit();
}

fn tick_loop(process: *Process, flags: *const challenger.flags.Flags) !u8 {
    const interval_ns = flags.poll_interval_ms * std.time.ns_per_ms;
    const start_ns = process.os_io.now_monotonic_ns();
    var ticks: u64 = 0;
    while (flags.ticks_max == null or ticks < flags.ticks_max.?) : (ticks += 1) {
        process.driver.tick(process.os_io.now_monotonic_ns() - start_ns);
        const stats = process.driver.stats;
        std.debug.print(
            "challenger: step {d}: {d} games scanned, {d} invalid, {d} scan errors\n",
            .{ stats.steps, stats.games_scanned, stats.invalid_detected, stats.scan_errors },
        );
        try process.os_io.run_for_ns(interval_ns);
    }
    return 0;
}

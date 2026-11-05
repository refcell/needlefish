//! `base proposer`: proposes output-root dispute games (base/base `crates/proof/proposer`).
//! Flags and validation follow base/base (`proof.proposer.config`); `--prover-rpc native`
//! proves in-process over the L1/L2 endpoints, `--dry-run` sends nothing.

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const consensus_cli = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const proof = base.proof;
const proposer = proof.proposer;
const host = proof.host;
const kzg = base.common.crypto.kzg;
const secp256k1 = base.common.crypto.secp256k1;
const protocol = base.consensus.protocol;

const Source = host.rpc_source.RpcSource(io.IO);
const Endpoint = proof.rpc.Endpoint(io.IO);
const Chain = proposer.rpc_chain.RpcChain(Endpoint);
const Submitter = proposer.tx_submitter.TxSubmitter(Endpoint);

const usage =
    \\usage: base proposer --prover-rpc <url|native> --l1-eth-rpc <url> --l2-eth-rpc <url>
    \\         --rollup-rpc <url> --anchor-state-registry-addr <addr>
    \\         --dispute-game-factory-addr <addr> --game-type <n>
    \\         (--private-key <hex> | --dry-run) [--poll-interval 12s] [--rpc-timeout 30s]
    \\         [--rollup-config <file>] [--l1-genesis <file>] [--ticks-max <n>]
    \\
;

const response_bytes_max = 256 << 20;

const http_options: http.client.Options = .{
    .recv_buffer_size = response_bytes_max + 64 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = response_bytes_max },
    .request_timeout_ns = 120 * std.time.ns_per_s,
};

/// Every long-lived piece of the service, heap-allocated once at startup.
const Service = struct {
    os_io: io.IO,
    l1_client: Source.Client,
    l2_client: Source.Client,
    rollup_client: Source.Client,
    l1_chain: Endpoint,
    l1_tx: Endpoint,
    rollup: Endpoint,
    chain: Chain,
    pipeline: proposer.Pipeline,

    fn step(context: *anyopaque) anyerror!void {
        const os_io: *io.IO = @ptrCast(@alignCast(context));
        try os_io.run_for_ns(std.time.ns_per_ms);
    }

    fn pump(service: *Service) proof.rpc.endpoint.Pump {
        return .{ .context = &service.os_io, .step = step };
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const config = proposer.config.parse(args) catch |err| {
        std.debug.print("proposer: {t}\n{s}", .{ err, usage });
        return 2;
    };
    if (!config.native_prover()) {
        std.debug.print("proposer: only --prover-rpc native is supported so far\n", .{});
        return 2;
    }
    const allocator = init.gpa;
    const service = try allocator.create(Service);
    defer allocator.destroy(service);
    try connect(service, allocator, &config);
    defer disconnect(service);
    return run(init, service, &config);
}

fn connect(
    service: *Service,
    allocator: std.mem.Allocator,
    config: *const proposer.config.Config,
) !void {
    const builtin = @import("builtin");
    service.os_io = if (builtin.os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    errdefer service.os_io.deinit();
    const os_io = &service.os_io;
    const l1 = try consensus_cli.parse_url(config.l1_eth_rpc);
    const l2 = try consensus_cli.parse_url(config.l2_eth_rpc);
    const rollup = try consensus_cli.parse_url(config.rollup_rpc);
    service.l1_client = try .init(allocator, os_io, l1, http_options, 4096);
    errdefer service.l1_client.deinit();
    service.l2_client = try .init(allocator, os_io, l2, http_options, 4096);
    errdefer service.l2_client.deinit();
    service.rollup_client = try .init(allocator, os_io, rollup, http_options, 4096);
    errdefer service.rollup_client.deinit();
    const steps_max = 300_000;
    service.l1_chain = .init(allocator, &service.l1_client, service.pump(), steps_max);
    service.l1_tx = .init(allocator, &service.l1_client, service.pump(), steps_max);
    service.rollup = .init(allocator, &service.rollup_client, service.pump(), steps_max);
    service.chain = .init(&service.l1_chain, &service.rollup, .{
        .factory = config.dispute_game_factory,
        .anchor_state_registry = config.anchor_state_registry,
        .game_type = config.game_type.?,
    });
}

fn disconnect(service: *Service) void {
    service.rollup.deinit();
    service.l1_tx.deinit();
    service.l1_chain.deinit();
    service.rollup_client.deinit();
    service.l2_client.deinit();
    service.l1_client.deinit();
    service.os_io.deinit();
}

/// Builds the native prover and the submitter, then ticks the pipeline.
fn run(init: std.process.Init, service: *Service, config: *const proposer.config.Config) !u8 {
    const allocator = init.gpa;
    const rollup_json = try Io.Dir.cwd().readFileAlloc(
        init.io,
        config.rollup_config,
        allocator,
        .limited(proof.program.boot.rollup_config_bytes_max),
    );
    defer allocator.free(rollup_json);
    const l1_genesis = try read_optional(init, config.l1_genesis);
    defer allocator.free(l1_genesis);
    const l1_config = try base.utilities.json.find_path(l1_genesis, &.{"config"}) orelse "";
    const rollup = try protocol.rollup_json.parse(rollup_json);
    var source: Source = .init(allocator, &service.l1_client, &service.l2_client, service.pump(), .{
        .steps_max = 300_000,
    });
    defer source.deinit();
    const kzg_state = try KzgState.create(allocator);
    defer kzg_state.destroy(allocator);
    var native = try proposer.native_prover.NativeProver.init(allocator, source.as_source(), .{
        .rollup_config_json = rollup_json,
        .chain_id = rollup.l2_chain_id,
        .l1_config_json = l1_config,
        .options = kzg_state.options(),
        .roots_brp = kzg_state.roots,
    });
    defer native.deinit();
    var dry_run: proposer.dry_run.DryRun = .{};
    var submitter: ?Submitter = null;
    defer if (submitter) |*sender| sender.deinit(allocator);
    const zero: [20]u8 = @splat(0);
    const address = if (config.private_key) |key| try secp256k1.address(key) else zero;
    if (!config.dry_run) submitter = try open_submitter(allocator, service, config, address);
    const submit = if (submitter) |*sender| sender.submitter() else dry_run.submitter();
    proposer.Pipeline.init(&service.pipeline, .{
        .game_type = config.game_type.?,
        .proposer = address,
        .anchor_state_registry = config.anchor_state_registry,
        .poll_interval_ns = config.poll_interval_ms * std.time.ns_per_ms,
    }, service.chain.chain(), native.prover_interface(), submit);
    return tick_loop(service, config, &native, &dry_run);
}

fn open_submitter(
    allocator: std.mem.Allocator,
    service: *Service,
    config: *const proposer.config.Config,
    address: [20]u8,
) !Submitter {
    const raw = try service.l1_tx.call("eth_chainId", &.{});
    const chain_id = try proof.rpc.endpoint.parse_quantity(raw);
    service.l1_tx.reset();
    return Submitter.init(allocator, &service.l1_tx, .{
        .chain_id = chain_id,
        .private_key = config.private_key.?,
        .from = address,
        .factory = config.dispute_game_factory,
        .game_type = config.game_type.?,
        // The native prover's initData is a witness archive (hundreds of KiB).
        .calldata_bytes_max = 4 << 20,
    });
}

fn tick_loop(
    service: *Service,
    config: *const proposer.config.Config,
    native: *const proposer.native_prover.NativeProver,
    dry_run: *const proposer.dry_run.DryRun,
) !u8 {
    const interval_ns = config.poll_interval_ms * std.time.ns_per_ms;
    const start_ns = service.os_io.now_monotonic_ns();
    var ticks: u64 = 0;
    while (config.ticks_max == null or ticks < config.ticks_max.?) : (ticks += 1) {
        service.pipeline.tick(service.os_io.now_monotonic_ns() - start_ns);
        const stats = service.pipeline.stats;
        std.debug.print("proposer: tick {d}: {d} proofs, {d} dry-run sends, {d} restarts\n", .{
            stats.ticks,
            native.proofs_total,
            dry_run.sent,
            stats.restarts,
        });
        try service.os_io.run_for_ns(interval_ns);
    }
    return 0;
}

/// KZG settings and scratch for the native prover's blob reads.
const KzgState = struct {
    storage: kzg.blob.Settings.Storage,
    workspace: kzg.blob.Workspace,
    roots_value: [kzg.field_elements_per_blob][32]u8,
    settings: kzg.blob.Settings,
    roots: *const [kzg.field_elements_per_blob][32]u8,

    fn create(allocator: std.mem.Allocator) !*KzgState {
        const state = try allocator.create(KzgState);
        errdefer allocator.destroy(state);
        host.handler.fill_roots(&state.roots_value);
        state.roots = &state.roots_value;
        state.settings = try kzg.blob.Settings.init(&state.storage);
        return state;
    }

    fn destroy(state: *KzgState, allocator: std.mem.Allocator) void {
        allocator.destroy(state);
    }

    fn options(state: *KzgState) proof.client.client.Options {
        return .{
            .builder = proof.client.client.default_builder_config,
            .kzg_settings = &state.settings,
            .kzg_workspace = &state.workspace,
        };
    }
};

fn read_optional(init: std.process.Init, path: []const u8) ![]u8 {
    if (path.len == 0) return init.gpa.alloc(u8, 0);
    const limit: Io.Limit = .limited(256 << 20);
    return Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, limit);
}

//! `base registrar`: registers TEE prover signers on the `TEEProverRegistry` from Nitro
//! attestations and deregisters revoked and orphaned signers (base/base
//! `bin/prover-registrar`, `crates/proof/tee/registrar`).
//!
//! Provers come from the static `--prover-endpoints` list (no AWS discovery). CRL checks
//! need an HTTP fetcher for arbitrary CRL hosts, which needlefish lacks (no DNS, no TLS),
//! so `--crl-nitro-verifier-address` is refused instead of silently skipping CRL checks.

const std = @import("std");
const base = @import("base");
const consensus_cli = @import("consensus.zig");
const telemetry_servers = @import("telemetry.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const proof = base.proof;
const registrar = proof.tee.registrar;
const secp256k1 = base.common.crypto.secp256k1;
const accounts = base.batcher.devnet.accounts;

const RpcClient = proof.host.rpc_source.RpcSource(io.IO).Client;
const Endpoint = proof.rpc.Endpoint(io.IO);
const Chain = registrar.rpc_l1.RpcChain(Endpoint);
const Transactor = registrar.rpc_l1.RpcTransactor(Endpoint);
const ProverClient = registrar.prover.RpcClient(io.IO);
const Telemetry = telemetry_servers.Servers(registrar.metrics.Exporter);

const usage =
    \\usage: base registrar --l1-rpc-url <url> --tee-prover-registry-address <addr>
    \\         --prover-endpoints <url,url> [--private-key <hex> | --dev-key-index <n>]
    \\         (prefer BASE_REGISTRAR_PRIVATE_KEY=<hex> to keep the key out of argv)
    \\         [--max-attestation-age-secs 3300] [--poll-interval-secs 30]
    \\         [--prover-timeout-secs 30] [--instance-cache-ttl-cycles 5]
    \\         [--max-tx-retries 3] [--tx-retry-delay-secs 5] [--ticks-max n]
    \\         [--health.addr 0.0.0.0] [--health.port 8080 (0: off)]
    \\         [--metrics.enabled] [--metrics.addr 0.0.0.0] [--metrics.port 7300]
    \\
;

const l1_http_options: http.client.Options = .{
    .recv_buffer_size = (4 << 20) + 64 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 4 << 20 },
    .request_timeout_ns = 60 * std.time.ns_per_s,
};

const receipt_poll_interval_ms: u64 = 2_000;
const steps_max = 300_000;

const Prover = struct {
    client: RpcClient,
    endpoint: Endpoint,
};

const Process = struct {
    os_io: io.IO,
    l1_client: RpcClient,
    l1_view: Endpoint,
    l1_tx: Endpoint,
    chain: Chain,
    transactor: Transactor,
    static: registrar.StaticDiscovery,
    provers: []Prover,
    stats: registrar.metrics.Stats = .{},
    manager: registrar.SignerManager,
    driver: registrar.RegistrationDriver,

    fn step(context: *anyopaque) anyerror!void {
        const os_io: *io.IO = @ptrCast(@alignCast(context));
        try os_io.run_for_ns(std.time.ns_per_ms);
    }

    fn pump(process: *Process) proof.rpc.endpoint.Pump {
        return .{ .context = &process.os_io, .step = step };
    }

    fn of(context: *anyopaque) *Process {
        return @ptrCast(@alignCast(context));
    }

    /// Runs IO for `ms`, in slices so a cancel is noticed.
    fn sleep(context: *anyopaque, ms: u64, cancel: *const registrar.l1.Cancel) bool {
        const process = of(context);
        var left_ms = ms;
        while (left_ms > 0) {
            if (cancel.is_cancelled()) return false;
            const slice_ms: u64 = @min(left_ms, 100);
            process.os_io.run_for_ns(slice_ms * std.time.ns_per_ms) catch return false;
            left_ms -= slice_ms;
        }
        return !cancel.is_cancelled();
    }

    fn now_unix_ms(context: *anyopaque) u64 {
        return of(context).os_io.now_realtime_ns() / std.time.ns_per_ms;
    }

    fn wait(context: *anyopaque, ms: u64) void {
        of(context).os_io.run_for_ns(ms * std.time.ns_per_ms) catch {};
    }

    const clock_vtable: registrar.l1.Clock.VTable = .{
        .now_unix_ms = now_unix_ms,
        .sleep_ms = sleep,
    };

    /// The prover connection serving `url`, one per `--prover-endpoints` entry.
    fn prover_for(process: *Process, url: []const u8) *Endpoint {
        for (process.static.slice(), process.provers) |*instance, *prover| {
            if (std.mem.eql(u8, instance.endpoint.slice(), url)) return &prover.endpoint;
        }
        unreachable; // Discovery only returns the static list's endpoints.
    }

    fn readyz(context: *anyopaque, url: []const u8) registrar.prover.Error!void {
        return ProverClient.readyz(of(context).prover_for(url));
    }

    fn signer_public_keys(
        context: *anyopaque,
        url: []const u8,
    ) registrar.prover.Error!registrar.prover.ByteLists {
        return ProverClient.signer_public_keys(of(context).prover_for(url));
    }

    fn signer_attestations(
        context: *anyopaque,
        url: []const u8,
        nonces: []const []const u8,
    ) registrar.prover.Error!registrar.prover.ByteLists {
        return ProverClient.signer_attestations(of(context).prover_for(url), nonces);
    }

    const client_vtable: registrar.driver.EndpointClient.VTable = .{
        .readyz = readyz,
        .signer_public_keys = signer_public_keys,
        .signer_attestations = signer_attestations,
    };
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const env_key = init.environ_map.get("BASE_REGISTRAR_PRIVATE_KEY");
    const config = registrar.service.parse_with_env(args, env_key) catch |err| {
        std.debug.print("registrar: {t}\n{s}", .{ err, usage });
        return 2;
    };
    if (config.crl_nitro_verifier_address != null) {
        std.debug.print("registrar: CRL checks are not supported (no CRL fetcher)\n", .{});
        return 2;
    }
    const allocator = init.gpa;
    const process = try allocator.create(Process);
    defer allocator.destroy(process);
    process.* = undefined;
    process.stats = .{};
    connect(process, allocator, &config) catch |err| {
        std.debug.print("registrar: cannot connect to L1 or the provers: {t}\n", .{err});
        return 1;
    };
    defer disconnect(process, allocator);
    const servers = try allocator.create(Telemetry);
    defer allocator.destroy(servers);
    try servers.open(allocator, &process.os_io, &config, .{
        .version = "needlefish",
        .poll_interval_ns = config.poll_interval_s * std.time.ns_per_s,
    }, "registrar");
    defer servers.close(allocator, &process.os_io);
    return tick_loop(process, &config, &servers.exporter);
}

fn signer_key(config: *const registrar.RegistrarConfig) [32]u8 {
    if (config.private_key) |key| return key;
    return accounts.derive_dev(config.dev_key_index.?).private_key;
}

fn connect(
    process: *Process,
    allocator: std.mem.Allocator,
    config: *const registrar.RegistrarConfig,
) !void {
    const builtin = @import("builtin");
    process.os_io = if (builtin.os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    errdefer process.os_io.deinit();
    const os_io = &process.os_io;
    const l1 = try consensus_cli.parse_url(config.l1_rpc_url);
    process.l1_client = try .init(allocator, os_io, l1, l1_http_options, 4096);
    errdefer process.l1_client.deinit();
    process.l1_view = .init(allocator, &process.l1_client, process.pump(), steps_max);
    errdefer process.l1_view.deinit();
    process.l1_tx = .init(allocator, &process.l1_client, process.pump(), steps_max);
    errdefer process.l1_tx.deinit();
    const registry = config.tee_prover_registry_address;
    const cert_manager = try Chain.resolve_cert_manager(&process.l1_view, registry);
    process.chain = .init(&process.l1_view, registry, cert_manager);
    const chain_id = try proof.rpc.endpoint.parse_quantity(
        try process.l1_tx.call("eth_chainId", &.{}),
    );
    process.l1_tx.reset();
    const key = signer_key(config);
    process.transactor = try .init(allocator, &process.l1_tx, .{
        .chain_id = chain_id,
        .private_key = key,
        .from = try secp256k1.address(key),
        .calldata_bytes_max = registrar.signer_manager.calldata_size_max,
        .resubmit_polls = 12,
    }, .{ .context = process, .wait_ms = Process.wait }, receipt_poll_interval_ms);
    errdefer process.transactor.deinit(allocator);
    try open_provers(process, allocator, config);
    errdefer close_provers(process, allocator);
    try open_driver(process, allocator, config, cert_manager);
}

fn open_provers(
    process: *Process,
    allocator: std.mem.Allocator,
    config: *const registrar.RegistrarConfig,
) !void {
    process.static = try .parse(config.prover_endpoints);
    const instances = process.static.slice();
    process.provers = try allocator.alloc(Prover, instances.len);
    errdefer allocator.free(process.provers);
    var options = l1_http_options;
    options.request_timeout_ns = config.prover_timeout_s * std.time.ns_per_s;
    var opened: usize = 0;
    errdefer for (process.provers[0..opened]) |*prover| {
        prover.endpoint.deinit();
        prover.client.deinit();
    };
    for (instances, process.provers) |*instance, *prover| {
        const address = try consensus_cli.parse_url(instance.endpoint.slice());
        prover.client = try .init(allocator, &process.os_io, address, options, 4096);
        prover.endpoint = .init(allocator, &prover.client, process.pump(), steps_max);
        opened += 1;
    }
}

fn open_driver(
    process: *Process,
    allocator: std.mem.Allocator,
    config: *const registrar.RegistrarConfig,
    cert_manager: registrar.l1.Address,
) !void {
    process.manager = try .init(allocator, config.signer_manager_config(cert_manager), .{
        .chain = process.chain.chain(),
        .transactor = process.transactor.transactor(),
        .clock = .{ .context = process, .vtable = &Process.clock_vtable },
    }, &process.stats);
    errdefer process.manager.deinit(allocator);
    try process.driver.init(
        allocator,
        config.driver_config(),
        process.static.discovery(),
        .{ .context = process, .vtable = &Process.client_vtable },
        &process.manager,
    );
}

fn close_provers(process: *Process, allocator: std.mem.Allocator) void {
    for (process.provers) |*prover| {
        prover.endpoint.deinit();
        prover.client.deinit();
    }
    allocator.free(process.provers);
}

fn disconnect(process: *Process, allocator: std.mem.Allocator) void {
    process.driver.deinit(allocator);
    process.manager.deinit(allocator);
    close_provers(process, allocator);
    process.transactor.deinit(allocator);
    process.l1_tx.deinit();
    process.l1_view.deinit();
    process.l1_client.deinit();
    process.os_io.deinit();
}

fn tick_loop(
    process: *Process,
    config: *const registrar.RegistrarConfig,
    exporter: *registrar.metrics.Exporter,
) !u8 {
    const driver = &process.driver;
    const clock = process.manager.world.clock;
    const interval_ms = config.poll_interval_s * std.time.ms_per_s;
    while (config.ticks_max == null or driver.cycles < config.ticks_max.?) {
        driver.step();
        registrar.driver.observe(exporter, driver);
        const stats = &process.stats;
        std.debug.print(
            "registrar: cycle {d}: {d} registrations, {d} deregistrations, {d} errors\n",
            .{ driver.cycles, stats.registrations, stats.deregistrations, stats.processing_errors },
        );
        if (!clock.sleep_ms(interval_ms, &driver.cancel)) break;
    }
    return 0;
}

test "registrar binary: rejects bad flags" {
    const config = registrar.service.parse(&.{"--l1-rpc-url"});
    try std.testing.expectError(error.MissingValue, config);
}

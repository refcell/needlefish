//! `base prover-service` and `base prover-worker` (base/base `bin/prover-service`,
//! `crates/proof/worker`): the proof-request JSON-RPC service over HTTP, and a worker
//! that claims `compressed` range jobs from it and proves them with the native host, or
//! (`--backend tee`, base/base `nitro-host`) claims AWS Nitro TEE jobs and proves them
//! through a local-mode enclave in this process, optionally serving the enclave signer
//! JSON-RPC (`enclave_signerPublicKey`, `enclave_signerAttestation`) on `--signer-rpc`.

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const consensus_cli = @import("consensus.zig");
const beacon = @import("beacon.zig");
const telemetry_servers = @import("telemetry.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const proof = base.proof;
const service_module = proof.prover_service.service;
const kzg = base.common.crypto.kzg;
const protocol = base.consensus.protocol;

const Store = proof.prover_service.store.Store;
const Service = service_module.Service;
const Server = http.Server(io.IO, *Service, Service.handle_http);
const Client = proof.prover_service.client.Client(io.IO);
const Worker = proof.prover_service.worker.Worker(io.IO);
const Native = proof.prover_service.native_backend.Native(io.IO);
const tee_host = proof.tee.host;
const SignerServer = http.Server(io.IO, *tee_host.Server, tee_host.Server.handle_http);
const Endpoint = proof.rpc.Endpoint(io.IO);
const exporters = proof.prover_service.exporter;
const ServiceTelemetry = telemetry_servers.Servers(exporters.ServiceExporter);
const WorkerTelemetry = telemetry_servers.Servers(exporters.WorkerExporter);

pub const ServiceFlags = struct {
    listen: []const u8 = "http://127.0.0.1:7300",
    jobs_max: u32 = 64,
    proof_bytes_max: u32 = 1 << 20,
    telemetry: telemetry_servers.Flags = .{},
};

pub const Backend = enum { native, tee };

pub const WorkerFlags = struct {
    backend: Backend = .native,
    /// TEE: a file holding the local-mode enclave signer key (hex).
    enclave_key_file: ?[]const u8 = null,
    /// TEE: where to serve the enclave signer and health JSON-RPC.
    signer_rpc: ?[]const u8 = null,
    enclave_request_bytes_max: u32 = 64 << 20,
    /// TEE: route proofs only to enclaves whose signer `TEEProverRegistry` (read over `--l1`)
    /// finds valid; without it every local enclave is used.
    tee_prover_registry: ?[20]u8 = null,
    prover_rpc: ?[]const u8 = null,
    l1: ?[]const u8 = null,
    l2: ?[]const u8 = null,
    rollup_config: ?[]const u8 = null,
    l1_genesis: ?[]const u8 = null,
    l1_beacon: ?[]const u8 = null,
    worker_id: []const u8 = "native",
    poll_interval_ms: u64 = 1000,
    proof_bytes_max: u32 = 1 << 20,
    telemetry: telemetry_servers.Flags = .{},
};

fn parse_u32(value: []const u8) !u32 {
    const parsed = try std.fmt.parseUnsigned(u32, value, 10);
    if (parsed == 0) return error.InvalidArguments;
    return parsed;
}

pub fn parse_service(args: []const []const u8) !ServiceFlags {
    var flags: ServiceFlags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        while (index < args.len and try flags.telemetry.parse_one(args, &index)) {}
        if (index == args.len) break;
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--listen")) {
            flags.listen = value;
        } else if (std.mem.eql(u8, name, "--jobs-max")) {
            flags.jobs_max = try parse_u32(value);
        } else if (std.mem.eql(u8, name, "--proof-bytes-max")) {
            flags.proof_bytes_max = try parse_u32(value);
        } else return error.InvalidArguments;
    }
    _ = try consensus_cli.parse_url(flags.listen);
    return flags;
}

pub fn parse_worker(args: []const []const u8) !WorkerFlags {
    var flags: WorkerFlags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        while (index < args.len and try flags.telemetry.parse_one(args, &index)) {}
        if (index == args.len) break;
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        const value = args[index + 1];
        const fields = .{
            .{ "--prover-rpc", "prover_rpc" },             .{ "--l1", "l1" },
            .{ "--l2", "l2" },                             .{ "--rollup-config", "rollup_config" },
            .{ "--l1-genesis", "l1_genesis" },             .{ "--l1-beacon", "l1_beacon" },
            .{ "--enclave-key-file", "enclave_key_file" }, .{ "--signer-rpc", "signer_rpc" },
        };
        var matched = false;
        inline for (fields) |field| {
            if (std.mem.eql(u8, name, field[0])) {
                @field(flags, field[1]) = value;
                matched = true;
            }
        }
        if (matched) continue;
        if (std.mem.eql(u8, name, "--worker-id")) {
            if (value.len == 0 or value.len > protocol_worker_id_max) return error.InvalidArguments;
            flags.worker_id = value;
        } else if (std.mem.eql(u8, name, "--poll-interval-ms")) {
            flags.poll_interval_ms = try parse_u32(value);
        } else if (std.mem.eql(u8, name, "--proof-bytes-max")) {
            flags.proof_bytes_max = try parse_u32(value);
        } else if (std.mem.eql(u8, name, "--backend")) {
            flags.backend = std.meta.stringToEnum(Backend, value) orelse
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--enclave-request-bytes-max")) {
            flags.enclave_request_bytes_max = try parse_u32(value);
        } else if (std.mem.eql(u8, name, "--tee-prover-registry-address")) {
            const address = base.utilities.json.parse_fixed(20, value) catch
                return error.InvalidArguments;
            if (std.mem.allEqual(u8, &address, 0)) return error.InvalidArguments;
            flags.tee_prover_registry = address;
        } else return error.InvalidArguments;
    }
    if (flags.backend == .tee and flags.enclave_key_file == null) return error.MissingFlag;
    if (flags.backend != .tee and flags.tee_prover_registry != null) {
        return error.InvalidArguments;
    }
    if (flags.signer_rpc) |url| _ = try consensus_cli.parse_url(url);
    const required = [_]?[]const u8{ flags.prover_rpc, flags.l1, flags.l2, flags.rollup_config };
    for (required) |present| if (present == null) return error.MissingFlag;
    return flags;
}

const protocol_worker_id_max = proof.prover_service.protocol.worker_id_bytes_max;

fn open_io() !io.IO {
    const builtin = @import("builtin");
    return if (builtin.os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
}

pub fn service_main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_service(args) catch |err| {
        std.debug.print("prover-service: {t}\nusage: base prover-service " ++
            "[--listen http://127.0.0.1:7300] [--jobs-max 64] [--proof-bytes-max N]\n         " ++
            telemetry_servers.Flags.usage ++ "\n", .{err});
        return 2;
    };
    const allocator = init.gpa;
    var os_io = try open_io();
    defer os_io.deinit();
    var store: Store = try .init(allocator, .{
        .jobs_max = flags.jobs_max,
        .proof_bytes_max = flags.proof_bytes_max,
        .seed = os_io.now_realtime_ns(),
    });
    defer store.deinit(allocator);
    const clock = service_module.Clock.of(io.IO, &os_io);
    // A submitted proof travels as hex: twice its size, plus the envelope.
    const body_max = 2 * flags.proof_bytes_max + (64 << 10);
    var service: Service = try .init(allocator, &store, clock, .{
        .request_arena_bytes = body_max + (1 << 20),
    });
    defer service.deinit(allocator);
    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.init(allocator, &os_io, &service, .{
        .connections_max = 16,
        .recv_buffer_size = body_max + 8 * 1024,
        .send_buffer_size = body_max + 8 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = body_max },
    });
    defer server.deinit();
    const bound = try server.listen(try consensus_cli.parse_url(flags.listen));
    std.debug.print("prover-service: listening on {f}\n", .{bound});
    const servers = try allocator.create(ServiceTelemetry);
    defer allocator.destroy(servers);
    const loop_ns = 10 * std.time.ns_per_ms;
    try servers.open(allocator, &os_io, &flags.telemetry, .{
        .version = "needlefish",
        .poll_interval_ns = loop_ns,
        .stale_after_intervals = 100,
    }, "prover-service");
    defer servers.close(allocator, &os_io);
    var loops: u64 = 0;
    while (true) {
        loops += 1;
        exporters.observe_service(&servers.exporter, service.requests, store.stats, loops);
        try os_io.run_for_ns(loop_ns);
    }
}

const response_bytes_max = 256 << 20;

const http_options: http.client.Options = .{
    .recv_buffer_size = response_bytes_max + 64 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = response_bytes_max },
    .request_timeout_ns = 120 * std.time.ns_per_s,
};

/// The worker process: connections, the native backend and its KZG state.
const WorkerProcess = struct {
    os_io: io.IO,
    l1: Native.Source.Client,
    l2: Native.Source.Client,
    service_http: Native.Source.Client,
    service_endpoint: Endpoint,
    client: Client,
    source: Native.Source,
    kzg_storage: kzg.blob.Settings.Storage,
    kzg_workspace: kzg.blob.Workspace,
    roots: [kzg.field_elements_per_blob][32]u8,
    settings: kzg.blob.Settings,

    fn step(context: *anyopaque) anyerror!void {
        const os_io: *io.IO = @ptrCast(@alignCast(context));
        try os_io.run_for_ns(std.time.ns_per_ms);
    }

    fn pump(process: *WorkerProcess) proof.rpc.endpoint.Pump {
        return .{ .context = &process.os_io, .step = step };
    }
};

pub fn worker_main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_worker(args) catch |err| {
        std.debug.print("prover-worker: {t}\nusage: base prover-worker --prover-rpc <url> " ++
            "--l1 <url> --l2 <url> --rollup-config <file> [--l1-genesis <file>] " ++
            "[--l1-beacon <url>] [--worker-id native] [--poll-interval-ms 1000]\n         " ++
            "[--backend native|tee] [--enclave-key-file <file>] [--signer-rpc <url>]\n         " ++
            "[--tee-prover-registry-address <addr>]\n         " ++
            telemetry_servers.Flags.usage ++ "\n", .{err});
        return 2;
    };
    const allocator = init.gpa;
    const process = try allocator.create(WorkerProcess);
    defer allocator.destroy(process);
    try connect_worker(process, allocator, &flags);
    defer disconnect_worker(process, allocator);
    return run_worker(init, process, &flags);
}

fn connect_worker(
    process: *WorkerProcess,
    allocator: std.mem.Allocator,
    flags: *const WorkerFlags,
) !void {
    process.os_io = try open_io();
    errdefer process.os_io.deinit();
    const os_io = &process.os_io;
    const l1_address = try consensus_cli.parse_url(flags.l1.?);
    process.l1 = try .init(allocator, os_io, l1_address, http_options, 4096);
    errdefer process.l1.deinit();
    const l2_address = try consensus_cli.parse_url(flags.l2.?);
    process.l2 = try .init(allocator, os_io, l2_address, http_options, 4096);
    errdefer process.l2.deinit();
    const service_address = try consensus_cli.parse_url(flags.prover_rpc.?);
    process.service_http = try .init(allocator, os_io, service_address, http_options, 4096);
    errdefer process.service_http.deinit();
    process.service_endpoint = .init(allocator, &process.service_http, process.pump(), 300_000);
    errdefer process.service_endpoint.deinit();
    process.client = try .init(allocator, &process.service_endpoint, .{
        .request_bytes_max = 2 * flags.proof_bytes_max + (64 << 10),
    });
    errdefer process.client.deinit(allocator);
    process.source = .init(allocator, &process.l1, &process.l2, process.pump(), .{
        .steps_max = 300_000,
    });
    base.proof.host.handler.fill_roots(&process.roots);
    process.settings = try kzg.blob.Settings.init(&process.kzg_storage);
}

fn disconnect_worker(process: *WorkerProcess, allocator: std.mem.Allocator) void {
    process.source.deinit();
    process.client.deinit(allocator);
    process.service_endpoint.deinit();
    process.service_http.deinit();
    process.l2.deinit();
    process.l1.deinit();
    process.os_io.deinit();
}

fn run_worker(init: std.process.Init, process: *WorkerProcess, flags: *const WorkerFlags) !u8 {
    const allocator = init.gpa;
    const rollup_json = try Io.Dir.cwd().readFileAlloc(
        init.io,
        flags.rollup_config.?,
        allocator,
        .limited(proof.program.boot.rollup_config_bytes_max),
    );
    defer allocator.free(rollup_json);
    const l1_genesis = if (flags.l1_genesis) |path|
        try Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(256 << 20))
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(l1_genesis);
    const l1_config = try beacon.l1_chain_config(l1_genesis);
    const rollup = try protocol.rollup_json.parse(rollup_json);
    var blobs: ?*beacon.Blobs = null;
    defer if (blobs) |opened| opened.destroy(allocator);
    if (flags.l1_beacon) |url| {
        const os_io = &process.os_io;
        const settings = &process.settings;
        blobs = try .create(allocator, os_io, url, settings, http_options, process.pump());
        process.source.blobs = blobs.?.fetcher();
    }
    const inputs: WorkerInputs = .{
        .rollup_json = rollup_json,
        .l1_config = l1_config,
        .chain_id = rollup.l2_chain_id,
        .client_options = .{
            .builder = proof.client.client.default_builder_config,
            .kzg_settings = &process.settings,
            .kzg_workspace = &process.kzg_workspace,
        },
    };
    return switch (flags.backend) {
        .native => run_native(init, process, flags, &inputs),
        .tee => run_tee(init, process, flags, &inputs),
    };
}

/// What every backend needs from the rollup and the proof client.
const WorkerInputs = struct {
    rollup_json: []const u8,
    l1_config: []const u8,
    chain_id: u64,
    client_options: proof.client.client.Options,
};

fn run_native(
    init: std.process.Init,
    process: *WorkerProcess,
    flags: *const WorkerFlags,
    inputs: *const WorkerInputs,
) !u8 {
    var native: Native = try .init(init.gpa, &process.source, .{
        .rollup_config_json = inputs.rollup_json,
        .l1_config_json = inputs.l1_config,
        .chain_id = inputs.chain_id,
        .client_options = inputs.client_options,
        .roots_brp = &process.roots,
        .proof_bytes_max = flags.proof_bytes_max,
    });
    defer native.deinit();
    const clock = service_module.Clock.of(io.IO, &process.os_io);
    var worker: Worker = .init(&process.client, native.backend(), clock, .{
        .worker_id = .from(flags.worker_id),
        .proof_type = .compressed,
        .zk_vms = &.{.sp1},
        .zk_backends = &.{.cluster},
        .poll_interval_ns = flags.poll_interval_ms * std.time.ns_per_ms,
    });
    return run_loop(init, process, flags, &worker);
}

/// base/base `nitro-host` in local mode: one in-process enclave behind the TEE backend.
fn run_tee(
    init: std.process.Init,
    process: *WorkerProcess,
    flags: *const WorkerFlags,
    inputs: *const WorkerInputs,
) !u8 {
    const allocator = init.gpa;
    var key_buffer: [256]u8 = undefined;
    const key_text = try Io.Dir.cwd().readFile(init.io, flags.enclave_key_file.?, &key_buffer);
    const key_hex = std.mem.trim(u8, key_text, " \t\r\n");
    const signer = try proof.tee.enclave.Signer.from_hex(key_hex);
    const local = try tee_host.LocalEnclave.create(allocator, .init_local(signer), .{
        .request_bytes_max = flags.enclave_request_bytes_max,
        .client_options = inputs.client_options,
    });
    defer local.destroy();
    const signer_address = local.server.signer_address();
    std.debug.print("prover-worker: local-mode enclave signer 0x{x}\n", .{&signer_address});
    const links = [_]*tee_host.Link{&local.link};
    var pool: tee_host.Pool = try .init(&links);
    var l1_endpoint: Endpoint = .init(allocator, &process.l1, process.pump(), 300_000);
    defer l1_endpoint.deinit();
    var rpc_registry: tee_host.rpc_registry.RpcRegistry(Endpoint) = undefined;
    var checker: tee_host.Checker = undefined;
    if (flags.tee_prover_registry) |address| {
        rpc_registry = .init(&l1_endpoint, address);
        checker = try .init(&links, rpc_registry.registry());
        try pool.set_checker(&checker);
        std.debug.print("prover-worker: gating enclaves on registry 0x{x}\n", .{&address});
    }
    var generator: tee_host.Generator = try .init(allocator, process.source.as_source(), .{
        .rollup_config_json = inputs.rollup_json,
        .l1_config_json = inputs.l1_config,
        .chain_id = inputs.chain_id,
        .client_options = inputs.client_options,
        .roots_brp = &process.roots,
    }, &pool);
    defer generator.deinit();
    var signer_server: tee_host.Server = .init(&links, .{ .version = "needlefish" });
    const http_server = try allocator.create(SignerServer);
    defer allocator.destroy(http_server);
    if (flags.signer_rpc) |url| {
        try http_server.init(allocator, &process.os_io, &signer_server, signer_http_options);
        const bound = try http_server.listen(try consensus_cli.parse_url(url));
        std.debug.print("prover-worker: enclave signer rpc on {f}\n", .{bound});
    }
    defer if (flags.signer_rpc != null) http_server.deinit();
    const host_config: tee_host.config.Config = .{
        .prover_service_url = flags.prover_rpc.?,
        .worker_id = flags.worker_id,
        .poll_interval_ns = flags.poll_interval_ms * std.time.ns_per_ms,
    };
    try host_config.validate();
    const clock = service_module.Clock.of(io.IO, &process.os_io);
    const backend = generator.backend();
    var worker: Worker = .init(&process.client, backend, clock, host_config.worker_config());
    return run_loop(init, process, flags, &worker);
}

const signer_http_options: http.server.Options = .{
    .connections_max = 8,
    .recv_buffer_size = 64 * 1024,
    .send_buffer_size = 512 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 32 * 1024 },
};

fn run_loop(
    init: std.process.Init,
    process: *WorkerProcess,
    flags: *const WorkerFlags,
    worker: *Worker,
) !u8 {
    const allocator = init.gpa;
    const servers = try allocator.create(WorkerTelemetry);
    defer allocator.destroy(servers);
    const loop_ns = 100 * std.time.ns_per_ms;
    try servers.open(allocator, &process.os_io, &flags.telemetry, .{
        .version = "needlefish",
        .poll_interval_ns = loop_ns,
        // A tick blocks while it proves; allow long proofs before reporting unready.
        .stale_after_intervals = 36_000,
    }, "prover-worker");
    defer servers.close(allocator, &process.os_io);
    var ticks: u64 = 0;
    while (true) {
        worker.tick();
        ticks += 1;
        exporters.observe_worker(&servers.exporter, worker.stats, ticks);
        try process.os_io.run_for_ns(loop_ns);
    }
}

test "prover service: command flags" {
    const service = try parse_service(&.{ "--listen", "http://127.0.0.1:7301", "--jobs-max", "8" });
    try std.testing.expectEqual(@as(u32, 8), service.jobs_max);
    try std.testing.expectError(error.InvalidArguments, parse_service(&.{ "--jobs-max", "0" }));
    const worker = try parse_worker(&.{
        "--prover-rpc",    "http://127.0.0.1:7300", "--l1",        "http://127.0.0.1:8545",
        "--l2",            "http://127.0.0.1:9545", "--worker-id", "w1",
        "--rollup-config", "rollup.json",
    });
    try std.testing.expectEqualStrings("w1", worker.worker_id);
    try std.testing.expectEqual(@as(?[]const u8, null), worker.l1_beacon);
    try std.testing.expectError(error.MissingFlag, parse_worker(&.{ "--l1", "http://a:1" }));
    try std.testing.expectError(error.InvalidArguments, parse_worker(&.{"--bogus"}));
    const tee_args = [_][]const u8{
        "--prover-rpc",    "http://127.0.0.1:7300", "--l1",      "http://127.0.0.1:8545",
        "--l2",            "http://127.0.0.1:9545", "--backend", "tee",
        "--rollup-config", "rollup.json",
    };
    try std.testing.expectError(error.MissingFlag, parse_worker(&tee_args));
    const tee = try parse_worker(&(tee_args ++ [_][]const u8{ "--enclave-key-file", "key.hex" }));
    try std.testing.expectEqual(Backend.tee, tee.backend);
    try std.testing.expectEqualStrings("key.hex", tee.enclave_key_file.?);
    try std.testing.expectError(error.InvalidArguments, parse_worker(&.{ "--backend", "sp1" }));
    const registry = [_][]const u8{
        "--tee-prover-registry-address", "0x00000000000000000000000000000000000000a5",
    };
    const keyed = tee_args ++ [_][]const u8{ "--enclave-key-file", "key.hex" };
    const gated = try parse_worker(&(keyed ++ registry));
    try std.testing.expectEqual(@as(u8, 0xa5), gated.tee_prover_registry.?[19]);
    // Registry gating is TEE-only, and the zero address is refused.
    const native_registry = parse_worker(&(tee_args[0..6].* ++ [_][]const u8{
        "--rollup-config", "rollup.json",
    } ++ registry));
    try std.testing.expectError(error.InvalidArguments, native_registry);
    const zero = [_][]const u8{
        "--tee-prover-registry-address", "0x0000000000000000000000000000000000000000",
    };
    try std.testing.expectError(error.InvalidArguments, parse_worker(&(keyed ++ zero)));
    const served = try parse_service(&.{ "--metrics.enabled", "--jobs-max", "4" });
    try std.testing.expect(served.telemetry.metrics_enabled);
    try std.testing.expectEqual(@as(u32, 4), served.jobs_max);
    try std.testing.expectEqual(@as(u16, 0), served.telemetry.health_port);
}

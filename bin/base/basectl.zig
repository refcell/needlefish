//! `base basectl <command>`: plain-text operator commands over the node, consensus,
//! batcher, and conductor JSON-RPCs. See `src/infra/basectl`. Defaults point at the local
//! devnet (`docs/DEVNET.md`); an empty URL leaves that endpoint unconfigured.

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Io = std.Io;
const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const basectl = base.infra.basectl;
const types = basectl.types;

const assert = std.debug.assert;
const env_prefix = "BASE_BASECTL_";

pub const Command = enum {
    sync_status,
    block,
    txpool,
    batcher,
    p2p,
    sequencer,
    conductor,
    proofs,
    upgrade_readiness,
    doctor,
    denim,
    node_metrics,

    /// Parses the hyphenated command name (`sync-status`).
    pub fn parse(text: []const u8) ?Command {
        var buffer: [32]u8 = undefined;
        if (text.len > buffer.len) return null;
        for (text, buffer[0..text.len]) |byte, *out| out.* = if (byte == '-') '_' else byte;
        return std.meta.stringToEnum(Command, buffer[0..text.len]);
    }
};

pub const Spec = struct {
    network: []const u8 = "devnet",
    l1_rpc: []const u8 = "http://127.0.0.1:8545",
    l2_rpc: []const u8 = "http://127.0.0.1:9545",
    rollup_rpc: []const u8 = "http://127.0.0.1:7545",
    batcher_rpc: []const u8 = "",
    conductor_rpc: []const u8 = "",
    timeout_ms: u32 = 10_000,
    json: bool = false,
    block: []const u8 = "latest",
    sender: []const u8 = "",
    node_name: []const u8 = "local",
    factory: []const u8 = "",
    limit: u32 = 10,
    target_version: []const u8 = "",
    sample_interval_ms: u32 = 3_000,
    peer_warn_below: u32 = 5,
    peer_fail_below: u32 = 1,
    safe_lag_warn_blocks: u64 = 150,
    safe_lag_fail_blocks: u64 = 300,
    finalized_lag_warn_blocks: u64 = 2_000,
    finalized_lag_fail_blocks: u64 = 7_200,
    cadence_blocks: u32 = basectl.denim_fetch.cadence_blocks_default,

    pub const help = .{
        .network = "Network label printed in reports",
        .l1_rpc = "L1 execution JSON-RPC (proofs, doctor); empty disables",
        .l2_rpc = "L2 execution JSON-RPC; empty disables",
        .rollup_rpc = "Consensus (rollup) node JSON-RPC; empty disables",
        .batcher_rpc = "Batcher admin JSON-RPC (batcher, doctor); empty disables",
        .conductor_rpc = "HA conductor JSON-RPC (conductor, sequencer, doctor); empty disables",
        .timeout_ms = "Per-request timeout",
        .json = "Print JSON instead of text",
        .block = "block: latest|safe|finalized|pending|earliest, a number, or a hash",
        .sender = "txpool: only this sender's transactions (0x address)",
        .node_name = "conductor/sequencer/node-metrics: name shown for the node",
        .factory = "proofs: DisputeGameFactory address on L1",
        .limit = "proofs: newest games to list (1..32)",
        .target_version = "upgrade-readiness: announced version to check (major.minor.patch)",
        .sample_interval_ms = "doctor: pause between the two head samples",
        .peer_warn_below = "doctor: warn when fewer peers are connected",
        .peer_fail_below = "doctor: fail when fewer peers are connected (0 never fails)",
        .safe_lag_warn_blocks = "doctor: safe head lag that warns",
        .safe_lag_fail_blocks = "doctor: safe head lag that fails",
        .finalized_lag_warn_blocks = "doctor: finalized head lag that warns",
        .finalized_lag_fail_blocks = "doctor: finalized head lag that fails",
        .cadence_blocks = "denim: parent-child edges the 200 ms cadence walk checks (1..256)",
    };
};

const usage =
    \\usage: base basectl <command> [flags]
    \\
    \\commands:
    \\  sync-status        consensus sync status and execution sync progress
    \\  block              one L2 block (--block)
    \\  txpool             pending and queued transaction counts (--sender)
    \\  batcher            batcher runtime state (--batcher-rpc)
    \\  p2p                peer identity and counts on both layers
    \\  sequencer          sequencer activity, role, heads, peers
    \\  conductor          HA conductor state and raft membership (--conductor-rpc)
    \\  node-metrics       one node's shared metrics: leadership, heads, sync, peers
    \\  proofs             recent dispute games (--factory)
    \\  upgrade-readiness  support for scheduled L1 upgrades (exit 1 when not ready)
    \\  doctor             health checks with pass/warn/fail (exit 1 on any fail)
    \\  denim              Denim readiness at the hash-pinned latest L2 block (exit 1 on any fail)
    \\
;

fn print_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("{s}\n{s}", .{ usage, writer.buffered() });
}

/// One configured endpoint's transport and client; unused when the URL is empty.
const Connection = struct {
    http: HttpTransport,
    client: rpc.Client,
    active: bool,
};

fn valid_url(url: []const u8) bool {
    return url.len == 0 or std.mem.startsWith(u8, url, "http://") or
        std.mem.startsWith(u8, url, "https://");
}

fn connect(
    connection: *Connection,
    init: std.process.Init,
    url: []const u8,
    timeout_ms: u32,
) !types.Endpoint {
    assert(valid_url(url));
    connection.active = url.len > 0;
    if (!connection.active) return .{ .url = url };
    connection.http = HttpTransport.init(init.gpa, init.io, url);
    connection.http.timeout_ms = timeout_ms;
    errdefer connection.http.deinit();
    connection.client = try rpc.Client.init(init.gpa, connection.http.transport(), .{
        .request_bytes_max = 4 * 1024,
        .response_bytes_max = 2 * 1024 * 1024,
        .parse_bytes_max = 16 * 1024 * 1024,
    });
    return .{ .client = &connection.client, .url = url };
}

fn disconnect(connection: *Connection, allocator: std.mem.Allocator) void {
    if (!connection.active) return;
    connection.client.deinit(allocator);
    connection.http.deinit();
    connection.active = false;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        print_help();
        return 2;
    }
    const command = Command.parse(args[0]) orelse {
        if (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) {
            print_help();
            return 0;
        }
        std.debug.print("basectl: unknown command: {s}\n{s}", .{ args[0], usage });
        return 2;
    };
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args[1..], env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("basectl: {t}: {s}\n", .{ err, diagnostic.subject });
        return 2;
    };
    const urls = [_][]const u8{
        spec.l1_rpc, spec.l2_rpc, spec.rollup_rpc, spec.batcher_rpc, spec.conductor_rpc,
    };
    for (urls) |url| if (!valid_url(url)) {
        std.debug.print("basectl: rpc urls must start with http:// or https://: {s}\n", .{url});
        return 2;
    };
    var connections: [urls.len]Connection = undefined;
    var endpoints: [urls.len]types.Endpoint = undefined;
    var connected: usize = 0;
    defer for (connections[0..connected]) |*connection| disconnect(connection, init.gpa);
    for (urls, &connections, &endpoints) |url, *connection, *endpoint| {
        endpoint.* = try connect(connection, init, url, spec.timeout_ms);
        connected += 1;
    }
    const context: types.Context = .{
        .network = spec.network,
        .l1 = endpoints[0],
        .l2 = endpoints[1],
        .rollup = endpoints[2],
        .batcher = endpoints[3],
        .conductor = endpoints[4],
    };
    var buffer: [16 * 1024]u8 = undefined;
    var stdout = Io.File.stdout().writer(init.io, &buffer);
    const out = &stdout.interface;
    const code = try run(command, spec, &context, init.io, out);
    try out.flush();
    return code;
}

/// Runs `command` and returns its exit code: 0 success, 1 failure, 2 bad flags.
fn run(command: Command, spec: Spec, context: *const types.Context, io: Io, out: *Io.Writer) !u8 {
    assert(context.network.len > 0);
    return switch (command) {
        .sync_status => emit(basectl.sync_status, basectl.sync_status.fetch(context), spec, out),
        .block => {
            const selector = basectl.block.Selector.parse(spec.block) catch {
                std.debug.print("basectl: invalid --block: {s}\n", .{spec.block});
                return 2;
            };
            return emit(basectl.block, basectl.block.fetch(context, selector), spec, out);
        },
        .txpool => {
            const sender = parse_address(spec.sender, "--sender") catch return 2;
            return emit(basectl.txpool, basectl.txpool.fetch(context, sender), spec, out);
        },
        .batcher => emit(basectl.batcher, basectl.batcher.fetch(context), spec, out),
        .p2p => emit(basectl.p2p, basectl.p2p.fetch(context), spec, out),
        .sequencer => emit(
            basectl.sequencer,
            basectl.sequencer.fetch(context, spec.node_name),
            spec,
            out,
        ),
        .conductor => emit(
            basectl.conductor,
            basectl.conductor.fetch(context, spec.node_name),
            spec,
            out,
        ),
        .node_metrics => emit(
            basectl.node_metrics,
            basectl.node_metrics.fetch(context, spec.node_name),
            spec,
            out,
        ),
        .proofs => run_proofs(spec, context, out),
        .upgrade_readiness => run_upgrade_readiness(spec, context, out),
        .doctor => run_doctor(spec, context, io, out),
        .denim => run_denim(spec, context, out),
    };
}

fn emit(comptime module: type, fetched: anytype, spec: Spec, out: *Io.Writer) !u8 {
    switch (fetched) {
        .failed => |failed| {
            std.debug.print("basectl: {s}: {s}\n", .{ failed.what, failed.failure.text() });
            return 1;
        },
        .ok => |*report| {
            if (spec.json) try types.render_json(report.*, out) else try module.render(report, out);
            return 0;
        },
    }
}

fn parse_address(text: []const u8, flag: []const u8) !?types.Address {
    if (text.len == 0) return null;
    const digits = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    var address: types.Address = .{};
    if (digits.len != 40) {
        std.debug.print("basectl: invalid {s}: {s}\n", .{ flag, text });
        return error.InvalidAddress;
    }
    _ = std.fmt.hexToBytes(&address.bytes, digits) catch {
        std.debug.print("basectl: invalid {s}: {s}\n", .{ flag, text });
        return error.InvalidAddress;
    };
    return address;
}

fn run_proofs(spec: Spec, context: *const types.Context, out: *Io.Writer) !u8 {
    const factory = parse_address(spec.factory, "--factory") catch return 2;
    if (factory == null or spec.limit == 0 or spec.limit > basectl.proofs.games_max) {
        std.debug.print("basectl: proofs needs --factory ADDRESS and --limit 1..32\n", .{});
        return 2;
    }
    return emit(basectl.proofs, basectl.proofs.fetch(context, factory.?, spec.limit), spec, out);
}

fn run_upgrade_readiness(spec: Spec, context: *const types.Context, out: *Io.Writer) !u8 {
    const target: ?[]const u8 = if (spec.target_version.len == 0) null else spec.target_version;
    const fetched = basectl.upgrade_readiness.fetch(context, target);
    const code = try emit(basectl.upgrade_readiness, fetched, spec, out);
    if (code != 0) return code;
    // Not ready fails so a rollout can gate on the exit code (base/base).
    return if (fetched.ok.readiness.ready) 0 else 1;
}

fn run_denim(spec: Spec, context: *const types.Context, out: *Io.Writer) !u8 {
    const blocks_max = basectl.denim_fetch.cadence_blocks_max;
    if (spec.cadence_blocks == 0 or spec.cadence_blocks > blocks_max) {
        std.debug.print("basectl: denim needs --cadence-blocks 1..{d}\n", .{blocks_max});
        return 2;
    }
    const options: basectl.denim_fetch.Options = .{ .cadence_blocks = spec.cadence_blocks };
    const fetched = basectl.denim_fetch.fetch(context, options);
    const code = try emit(basectl.denim, fetched, spec, out);
    if (code != 0) return code;
    // Any failing check fails the command; indeterminate checks do not.
    return if (fetched.ok.has_failures()) 1 else 0;
}

fn sleep_ms(context: *anyopaque, duration_ms: u64) void {
    const io: *const Io = @ptrCast(@alignCast(context));
    io.sleep(.fromMilliseconds(@intCast(duration_ms)), .awake) catch {};
}

fn run_doctor(spec: Spec, context: *const types.Context, io: Io, out: *Io.Writer) !u8 {
    const thresholds: basectl.doctor.Thresholds = .{
        .peer_warn_below = spec.peer_warn_below,
        .peer_fail_below = spec.peer_fail_below,
        .safe_lag_warn_blocks = spec.safe_lag_warn_blocks,
        .safe_lag_fail_blocks = spec.safe_lag_fail_blocks,
        .finalized_lag_warn_blocks = spec.finalized_lag_warn_blocks,
        .finalized_lag_fail_blocks = spec.finalized_lag_fail_blocks,
    };
    const ordered = thresholds.safe_lag_warn_blocks <= thresholds.safe_lag_fail_blocks and
        thresholds.finalized_lag_warn_blocks <= thresholds.finalized_lag_fail_blocks;
    if (!ordered or spec.sample_interval_ms > 60_000) {
        std.debug.print("basectl: doctor needs warn <= fail lags and " ++
            "--sample-interval-ms <= 60000\n", .{});
        return 2;
    }
    var io_copy = io;
    const sleeper: basectl.doctor.Sleeper = .{ .context = &io_copy, .sleep_fn = sleep_ms };
    const facts = basectl.doctor.gather(context, spec.sample_interval_ms, sleeper);
    const report = basectl.doctor.evaluate(&facts, thresholds, context.network);
    if (spec.json) try types.render_json(report, out) else try basectl.doctor.render(&report, out);
    return if (report.has_failures()) 1 else 0;
}

test "basectl: command names and addresses" {
    try std.testing.expectEqual(Command.sync_status, Command.parse("sync-status").?);
    try std.testing.expectEqual(Command.upgrade_readiness, Command.parse("upgrade-readiness").?);
    try std.testing.expectEqual(@as(?Command, null), Command.parse("tui"));
    try std.testing.expectEqual(Command.denim, Command.parse("denim").?);
    try std.testing.expectEqual(Command.node_metrics, Command.parse("node-metrics").?);
    const address = (try parse_address("0x" ++ "00000000000000000000000000000000000000ff", "x")).?;
    try std.testing.expectEqual(@as(u8, 0xff), address.bytes[19]);
    try std.testing.expect(valid_url(""));
    try std.testing.expect(!valid_url("127.0.0.1:8545"));
}

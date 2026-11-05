//! `base load-test`: sends a seeded transaction workload from public dev accounts at a fixed
//! open-loop rate and prints an inclusion-latency report. See `src/infra/load_test`.
//! Senders are dev-mnemonic accounts (devnet use only); the defaults avoid the devnet's
//! deployer, user, sequencer, batcher, and proposer accounts.

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Io = std.Io;
const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const load_test = base.infra.load_test;

const env_prefix = "BASE_LOAD_TEST_";

pub const Spec = struct {
    rpc_url: []const u8,
    chain_id: u64,
    rate: u32 = 10,
    duration_s: u32 = 60,
    drain_s: u32 = 60,
    accounts: []const u8 = "2,3,4,8,9",
    in_flight: u32 = 16,
    seed: u64 = 1,
    mix: []const u8 = "transfer=100",
    calldata_bytes_max: u32 = 1024,
    confirmations: u64 = 1,

    pub const help = .{
        .rpc_url = "JSON-RPC endpoint (http://...)",
        .chain_id = "Chain id to sign for",
        .rate = "Offered load, transactions per second",
        .duration_s = "Submission window in seconds",
        .drain_s = "Seconds to wait for outstanding transactions afterwards",
        .accounts = "Dev mnemonic account indices to send from (0..9)",
        .in_flight = "Unconfirmed transactions per sender before it is skipped",
        .seed = "Workload seed (same seed, same payloads)",
        .mix = "Payload weights: transfer=N,calldata=N,erc20_transfer=N",
        .calldata_bytes_max = "Largest random calldata payload",
        .confirmations = "Blocks deep before a transaction counts as confirmed",
    };
};

const Parsed = struct {
    config: load_test.Config,
    indices: [load_test.runner.senders_max]u32,
};

/// Validates flags. `parsed.config.account_indices` points into `parsed.indices`.
pub fn parse_config(spec: Spec, parsed: *Parsed) !void {
    if (spec.calldata_bytes_max > load_test.runner.calldata_bytes_max) return error.InvalidValue;
    if (spec.rate == 0 or spec.duration_s == 0 or spec.confirmations == 0) {
        return error.InvalidValue;
    }
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, spec.accounts, ',');
    while (parts.next()) |part| : (count += 1) {
        if (count == parsed.indices.len) return error.TooManyAccounts;
        parsed.indices[count] = try std.fmt.parseInt(u32, part, 10);
    }
    parsed.config = .{
        .chain_id = spec.chain_id,
        .account_indices = parsed.indices[0..count],
        .rate_per_s = spec.rate,
        .duration_ms = @as(u64, spec.duration_s) * 1000,
        .drain_ms = @as(u64, spec.drain_s) * 1000,
        .in_flight_per_sender = spec.in_flight,
        .workload = .{
            .seed = spec.seed,
            .mix = try load_test.workload.Mix.parse(spec.mix),
            .calldata_bytes_max = spec.calldata_bytes_max,
        },
        .manager = .{
            .num_confirmations = spec.confirmations,
            .resubmission_timeout_ms = 12_000,
            .receipt_query_interval_ms = 1_000,
        },
    };
}

fn print_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base load-test --rpc-url URL --chain-id ID\n{s}", .{writer.buffered()});
}

fn now_ms(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).toMilliseconds());
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args, env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("load-test: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    var parsed: Parsed = undefined;
    parse_config(spec, &parsed) catch |err| {
        std.debug.print("load-test: invalid flags: {t}\n", .{err});
        return 2;
    };
    var http = HttpTransport.init(init.gpa, init.io, spec.rpc_url);
    http.timeout_ms = 10_000;
    defer http.deinit();
    var client = try rpc.Client.init(init.gpa, http.transport(), .{
        .request_bytes_max = 64 * 1024,
        .response_bytes_max = 256 * 1024,
        .parse_bytes_max = 2 * 1024 * 1024,
    });
    defer client.deinit(init.gpa);
    var clients: [load_test.runner.senders_max]*rpc.Client = @splat(&client);
    const runner = try init.gpa.create(load_test.Runner);
    defer init.gpa.destroy(runner);
    const sender_count = parsed.config.account_indices.len;
    try runner.init(init.gpa, parsed.config, clients[0..sender_count], now_ms(init.io));
    defer runner.deinit(init.gpa);
    try run(init.io, runner);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try runner.recorder.write_report(&writer);
    std.debug.print("{s}rpc errors     {d}\n", .{ writer.buffered(), runner.rpc_errors });
    return if (runner.recorder.confirmed > 0) 0 else 1;
}

fn run(io: Io, runner: *load_test.Runner) !void {
    var progress_at_ms = now_ms(io) + 5_000;
    while (true) {
        const now = now_ms(io);
        if (runner.done(now)) return;
        runner.step(now);
        if (now >= progress_at_ms) {
            progress_at_ms = now + 5_000;
            std.debug.print("load-test: submitted {d} confirmed {d} failed {d} pending {d}\n", .{
                runner.recorder.submitted,
                runner.recorder.confirmed,
                runner.recorder.failed,
                runner.outstanding(),
            });
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

test "load-test: flags to config" {
    var parsed: Parsed = undefined;
    try parse_config(.{
        .rpc_url = "http://127.0.0.1:8545",
        .chain_id = 901,
        .accounts = "2,3",
        .mix = "transfer=1,calldata=1",
    }, &parsed);
    try std.testing.expectEqual(@as(usize, 2), parsed.config.account_indices.len);
    try std.testing.expectEqual(@as(u32, 3), parsed.config.account_indices[1]);
    try std.testing.expectError(error.InvalidMix, parse_config(.{
        .rpc_url = "http://127.0.0.1:8545",
        .chain_id = 901,
        .mix = "swap=1",
    }, &parsed));
}

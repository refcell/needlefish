//! `base load-test`: sends a seeded transaction workload at a fixed open-loop rate and prints
//! an inclusion-latency report (`--json` for one machine-readable line). See
//! `src/infra/load_test`. Senders are dev-mnemonic accounts (devnet use only; the defaults
//! avoid the devnet's deployer, user, sequencer, batcher, and proposer accounts), or with
//! `--senders N`, N key-stream accounts that a funder dev account first funds. Mixes with
//! `erc20_transfer`, `storage`, or `looper` deploy the workload contracts first.

const std = @import("std");
const assert = std.debug.assert;
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
    receipt_poll_ms: u64 = 200,
    senders: u32 = 0,
    funder_index: u32 = 8,
    fund_wei: u128 = 100_000_000_000_000_000,
    storage_slots: u32 = 4,
    looper_iterations: u32 = 10_000,
    json: bool = false,

    pub const help = .{
        .rpc_url = "JSON-RPC endpoint (http://...)",
        .chain_id = "Chain id to sign for",
        .rate = "Offered load, transactions per second",
        .duration_s = "Submission window in seconds",
        .drain_s = "Seconds to wait for outstanding transactions afterwards",
        .accounts = "Dev mnemonic account indices to send from (0..9)",
        .in_flight = "Unconfirmed transactions per sender before it is skipped",
        .seed = "Workload seed (same seed, same payloads)",
        .mix = "Payload weights: transfer,calldata,erc20_transfer,storage,precompile,looper=N",
        .calldata_bytes_max = "Largest random calldata payload",
        .confirmations = "Blocks deep before a transaction counts as confirmed",
        .receipt_poll_ms = "Receipt poll interval (L2 blocks are 200 ms)",
        .senders = "Key-stream senders derived from --seed and funded first (0: --accounts)",
        .funder_index = "Dev mnemonic account that deploys contracts and funds senders",
        .fund_wei = "Wei sent to each key-stream sender",
        .storage_slots = "Fresh storage slots written per storage transaction",
        .looper_iterations = "Loop iterations per looper transaction (40 gas each)",
        .json = "Print the report as one JSON line on stdout",
    };
};

const Parsed = struct {
    config: load_test.Config,
    indices: [load_test.runner.senders_max]u32,
};

/// Validates flags. `parsed.config.account_indices` points into `parsed.indices`.
pub fn parse_config(spec: Spec, parsed: *Parsed) !void {
    if (spec.calldata_bytes_max > load_test.runner.calldata_bytes_max) return error.InvalidValue;
    if (spec.rate == 0 or spec.duration_s == 0 or spec.confirmations == 0 or
        spec.receipt_poll_ms == 0)
    {
        return error.InvalidValue;
    }
    if (spec.senders > load_test.runner.senders_max) return error.TooManyAccounts;
    if (spec.storage_slots > load_test.workload.storage_slots_per_tx_max) {
        return error.InvalidValue;
    }
    if (spec.looper_iterations > load_test.workload.looper_iterations_max) {
        return error.InvalidValue;
    }
    const count = try parse_indices(spec.accounts, &parsed.indices);
    const mix = try load_test.workload.Mix.parse(spec.mix);
    const prep: ?load_test.runner.Prep = if (spec.senders > 0 or mix.needs_contracts()) .{
        .funder_index = spec.funder_index,
        .fund_wei = if (spec.senders > 0) spec.fund_wei else 0,
    } else null;
    parsed.config = .{
        .chain_id = spec.chain_id,
        .account_indices = parsed.indices[0..count],
        .stream_senders = spec.senders,
        .key_seed = spec.seed,
        .prep = prep,
        .rate_per_s = spec.rate,
        .duration_ms = @as(u64, spec.duration_s) * 1000,
        .drain_ms = @as(u64, spec.drain_s) * 1000,
        .in_flight_per_sender = spec.in_flight,
        .workload = .{
            .seed = spec.seed,
            .mix = mix,
            .calldata_bytes_max = spec.calldata_bytes_max,
            .storage_slots_per_tx = spec.storage_slots,
            .looper_iterations = spec.looper_iterations,
        },
        .manager = .{
            .num_confirmations = spec.confirmations,
            .resubmission_timeout_ms = 12_000,
            .receipt_query_interval_ms = spec.receipt_poll_ms,
        },
    };
}

fn parse_indices(text: []const u8, indices: []u32) !usize {
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part| : (count += 1) {
        if (count == indices.len) return error.TooManyAccounts;
        indices[count] = std.fmt.parseInt(u32, part, 10) catch return error.InvalidValue;
    }
    assert(count <= indices.len);
    return count;
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
    var clients: [load_test.runner.senders_max + 1]*rpc.Client = @splat(&client);
    const runner = try init.gpa.create(load_test.Runner);
    defer init.gpa.destroy(runner);
    const config = parsed.config;
    const sender_count = if (config.stream_senders > 0)
        config.stream_senders
    else
        config.account_indices.len;
    const client_count = sender_count + @intFromBool(config.prep != null);
    runner.init(init.gpa, config, clients[0..client_count], now_ms(init.io)) catch |err| {
        std.debug.print("load-test: {t}\n", .{err});
        return 2;
    };
    defer runner.deinit(init.gpa);
    try run(init.io, runner);
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    if (spec.json) {
        try runner.write_json(&writer);
        var stdout_buffer: [256]u8 = undefined;
        var stdout = std.Io.File.stdout().writer(init.io, &stdout_buffer);
        try stdout.interface.writeAll(writer.buffered());
        try stdout.interface.flush();
    } else {
        try runner.write_report(&writer);
        std.debug.print("{s}", .{writer.buffered()});
    }
    if (runner.prep_failed()) return 1;
    return if (runner.recorder.confirmed > 0) 0 else 1;
}

fn run(io: Io, runner: *load_test.Runner) !void {
    var progress_at_ms = now_ms(io) + 5_000;
    while (true) {
        const now = now_ms(io);
        if (runner.done(now)) return;
        runner.step(now);
        if (now >= progress_at_ms and !runner.loading) {
            progress_at_ms = now + 5_000;
            const prep = &runner.prep.?;
            std.debug.print("load-test: prep {t} {d}/{d} confirmed\n", .{
                prep.phase, prep.confirmed, prep.items,
            });
        } else if (now >= progress_at_ms) {
            progress_at_ms = now + 5_000;
            std.debug.print("load-test: submitted {d} confirmed {d} failed {d} pending {d}\n", .{
                runner.recorder.submitted,
                runner.recorder.confirmed,
                runner.recorder.failed,
                runner.outstanding(),
            });
        }
        try io.sleep(.fromMilliseconds(50), .awake);
    }
}

const testing = std.testing;
const rpc_url = "http://127.0.0.1:8545";

test "load-test: flags to config" {
    var parsed: Parsed = undefined;
    try parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .accounts = "2,3",
        .mix = "transfer=1,calldata=1",
    }, &parsed);
    try testing.expectEqual(@as(usize, 2), parsed.config.account_indices.len);
    try testing.expectEqual(@as(u32, 3), parsed.config.account_indices[1]);
    try testing.expect(parsed.config.prep == null);
    try testing.expectError(error.InvalidMix, parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .mix = "swap=1",
    }, &parsed));
}

test "load-test: senders and contract mixes enable the prep phase" {
    var parsed: Parsed = undefined;
    try parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .senders = 50,
        .funder_index = 9,
        .fund_wei = 7,
        .seed = 3,
    }, &parsed);
    try testing.expectEqual(@as(u32, 50), parsed.config.stream_senders);
    try testing.expectEqual(@as(u64, 3), parsed.config.key_seed);
    try testing.expectEqual(@as(u32, 9), parsed.config.prep.?.funder_index);
    try testing.expectEqual(@as(u256, 7), parsed.config.prep.?.fund_wei);
    // Dev senders with a contract mix: deploy and mint, no ETH funding.
    try parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .mix = "erc20_transfer=1,storage=1,looper=1",
    }, &parsed);
    try testing.expectEqual(@as(u256, 0), parsed.config.prep.?.fund_wei);
    try testing.expectError(error.TooManyAccounts, parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .senders = load_test.runner.senders_max + 1,
    }, &parsed));
}

fn check_flags(accounts: []const u8, mix: []const u8, senders: u32) !void {
    var parsed: Parsed = undefined;
    parse_config(.{
        .rpc_url = rpc_url,
        .chain_id = 901,
        .accounts = accounts,
        .mix = mix,
        .senders = senders,
    }, &parsed) catch return;
    try testing.expect(parsed.config.account_indices.len <= load_test.runner.senders_max);
    try testing.expect(parsed.config.stream_senders <= load_test.runner.senders_max);
    const needs_prep = senders > 0 or parsed.config.workload.mix.needs_contracts();
    try testing.expectEqual(needs_prep, parsed.config.prep != null);
}

test "load-test: seeded fuzz flags" {
    var prng = base.testing.Prng.init(0xf1a6);
    const pieces = [_][]const u8{ "2", "3", "99999999999", ",", "x", "", "=", "1", "storage" };
    var accounts: [64]u8 = undefined;
    var mix: [64]u8 = undefined;
    for (0..2_000) |_| {
        const accounts_text = fill_random(&prng, &pieces, &accounts);
        const mix_text = fill_random(&prng, &pieces, &mix);
        try check_flags(accounts_text, mix_text, @intCast(prng.below(80)));
    }
}

fn fill_random(prng: *base.testing.Prng, pieces: []const []const u8, out: []u8) []const u8 {
    var writer: std.Io.Writer = .fixed(out);
    const count = prng.below(12);
    for (0..count) |_| writer.writeAll(pieces[@intCast(prng.below(pieces.len))]) catch break;
    return writer.buffered();
}

test "load-test: fuzz flags" {
    try testing.fuzz({}, fuzz_flags, .{});
}

fn fuzz_flags(_: void, smith: *testing.Smith) anyerror!void {
    var accounts: [64]u8 = undefined;
    var mix: [64]u8 = undefined;
    const accounts_text = accounts[0..smith.slice(&accounts)];
    const mix_text = mix[0..smith.slice(&mix)];
    try check_flags(accounts_text, mix_text, smith.value(u32) % 80);
}

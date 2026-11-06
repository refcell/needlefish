//! `base fee-jobs disburse|process|sweep|confirm`: one-shot fee collection jobs (see
//! `src/infra/fee_jobs`). disburse/process/sweep check the job's precondition, and when it
//! holds send one call through the tx manager and wait for `--confirmations`. Exit 0 on a
//! confirmed send or a skip (false precondition), 1 on a failed job, 2 on bad flags.
//!
//! `confirm` scans the L2 window for the FeeDisburser's `FeesDisbursed` events and proves or
//! finalizes its own ETH bridge withdrawals on L1 (fault proofs; `src/infra/fee_jobs/
//! confirm.zig`). Exit 1 when any receipt or withdrawal failed.
//!
//! The signing key comes from `BASE_FEE_JOBS_PRIVATE_KEY` (hex, `0x` optional; base/base
//! `JOB_RUNNER_KEY`) and is never accepted as a flag, so it stays out of process listings.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const base = @import("base");

const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const secp256k1 = base.common.crypto.secp256k1;
const fee_jobs = base.infra.fee_jobs;
const tx_manager = base.infra.tx_manager;
const HttpTransport = @import("http_transport.zig").HttpTransport;
const confirm = fee_jobs.confirm;
const withdrawer = base.infra.withdrawer;

const env_prefix = "BASE_FEE_JOBS_";
const key_variable = env_prefix ++ "PRIVATE_KEY";
const Driver = tx_manager.driver.Driver(.{ .sends_max = 1, .hashes_max = 16 });

pub const Spec = struct {
    rpc_url: []const u8,
    chain_id: u64,
    contract: []const u8,
    confirmations: u64 = 10,
    send_timeout_s: u32 = 600,
    resubmission_timeout_s: u32 = 48,
    receipt_poll_ms: u32 = 1_000,

    pub const help = .{
        .rpc_url = "JSON-RPC endpoint (L2 for disburse and sweep, L1 for process)",
        .chain_id = "Chain id of that endpoint",
        .contract = "FeeDisburser, BalanceTracker, or RegistrarController address",
        .confirmations = "Confirmation depth before the job succeeds",
        .send_timeout_s = "Give up on the send after this long",
        .resubmission_timeout_s = "Bump fees when not mined within this long",
        .receipt_poll_ms = "Receipt polling interval",
    };
};

/// `confirm` flags (base/base `ConfirmArgs`; durations in seconds or milliseconds).
pub const ConfirmSpec = struct {
    l1_rpc_url: []const u8,
    l2_rpc_url: []const u8,
    l1_chain_id: u64,
    portal: []const u8,
    contract: []const u8,
    lookback_s: u64 = 21 * 24 * 60 * 60,
    l2_block_time_ms: u64 = 2_000,
    num_blocks_per_query: u64 = 3_000,
    dry_run: bool = false,
    withdrawal_timeout_s: u64 = 600,
    confirmations: u64 = 10,
    resubmission_timeout_s: u32 = 48,
    receipt_poll_ms: u32 = 1_000,
    network_timeout_ms: u64 = 10_000,

    pub const help = .{
        .l1_rpc_url = "L1 JSON-RPC endpoint (http://...)",
        .l2_rpc_url = "L2 JSON-RPC endpoint (http://...)",
        .l1_chain_id = "L1 chain id to sign for",
        .portal = "OptimismPortal2 address on L1 (factory and registry are read from it)",
        .contract = "FeeDisburser address on L2",
        .lookback_s = "L2 lookback in seconds (covers the slowest finalization path)",
        .l2_block_time_ms = "L2 block time converting the lookback to blocks, rounded up",
        .num_blocks_per_query = "Blocks per eth_getLogs query",
        .dry_run = "Decide each withdrawal without sending",
        .withdrawal_timeout_s = "Deadline for each disbursal's proof or finalization",
        .confirmations = "Confirmation depth of the L1 sends",
        .resubmission_timeout_s = "Bump fees when not mined within this long",
        .receipt_poll_ms = "Receipt polling interval",
        .network_timeout_ms = "Per-request RPC timeout",
    };
};

fn print_confirm_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(ConfirmSpec, env_prefix, &writer) catch {};
    std.debug.print(
        "usage: base fee-jobs confirm --l1-rpc-url URL --l2-rpc-url URL --l1-chain-id ID " ++
            "--portal ADDR --contract ADDR\n  key: {s} (hex)\n{s}",
        .{ key_variable, writer.buffered() },
    );
}

fn print_help() void {
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print(
        "usage: base fee-jobs disburse|process|sweep --rpc-url URL --chain-id ID " ++
            "--contract ADDR\n       base fee-jobs confirm --help\n  key: {s} (hex)\n{s}",
        .{ key_variable, writer.buffered() },
    );
}

fn parse_hex(comptime size: usize, text: []const u8) ![size]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const digits = if (std.mem.startsWith(u8, trimmed, "0x")) trimmed[2..] else trimmed;
    if (digits.len != 2 * size) return error.InvalidHex;
    var out: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, digits) catch return error.InvalidHex;
    return out;
}

const Clock = struct {
    io: Io,

    pub fn now_ms(clock: *const Clock) u64 {
        return @intCast(Io.Clock.awake.now(clock.io).toMilliseconds());
    }

    pub fn sleep_ms(clock: *const Clock, duration_ms: u64) void {
        const duration: Io.Duration = .fromMilliseconds(@intCast(duration_ms));
        clock.io.sleep(duration, .awake) catch {};
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        print_help();
        return 2;
    }
    if (std.mem.eql(u8, args[0], "confirm")) return confirm_main(init, args[1..]);
    const kind = std.meta.stringToEnum(fee_jobs.Kind, args[0]) orelse {
        print_help();
        return if (std.mem.eql(u8, args[0], "--help")) 0 else 2;
    };
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args[1..], env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("fee-jobs: {t}: {s}\n", .{ err, diagnostic.subject });
        return 2;
    };
    const contract: fee_jobs.Address = .{ .bytes = parse_hex(20, spec.contract) catch {
        std.debug.print("fee-jobs: --contract is not a 20-byte hex address\n", .{});
        return 2;
    } };
    const signer = read_key(init) orelse return 2;
    return run(init, spec, kind, contract, signer.private_key, signer.from);
}

const Signer = struct { private_key: [32]u8, from: fee_jobs.Address };

/// The signer from `BASE_FEE_JOBS_PRIVATE_KEY`; prints why and returns null when unusable.
fn read_key(init: std.process.Init) ?Signer {
    const key_text = init.environ_map.get(key_variable) orelse {
        std.debug.print("fee-jobs: {s} is not set\n", .{key_variable});
        return null;
    };
    const private_key = parse_hex(32, key_text) catch {
        std.debug.print("fee-jobs: {s} is not a 32-byte hex key\n", .{key_variable});
        return null;
    };
    const from = secp256k1.address(private_key) catch {
        std.debug.print("fee-jobs: {s} is not a valid secp256k1 key\n", .{key_variable});
        return null;
    };
    return .{ .private_key = private_key, .from = .{ .bytes = from } };
}

pub const ConfirmParsed = struct { portal: [20]u8, contract: [20]u8, config: confirm.Config };

/// Validates `confirm` flags (base/base `ConfirmJob::config`).
pub fn parse_confirm(spec: ConfirmSpec) !ConfirmParsed {
    const portal = try parse_hex(20, spec.portal);
    const contract = try parse_hex(20, spec.contract);
    if (std.mem.allEqual(u8, &portal, 0) or std.mem.allEqual(u8, &contract, 0)) {
        return error.ZeroAddress;
    }
    if (spec.withdrawal_timeout_s == 0 or spec.confirmations == 0) return error.InvalidValue;
    const window: confirm.Window = .{
        .lookback_ms = std.math.mul(u64, spec.lookback_s, 1000) catch return error.InvalidValue,
        .block_time_ms = spec.l2_block_time_ms,
        .blocks_per_query = spec.num_blocks_per_query,
    };
    if (!window.valid()) return error.InvalidValue;
    const parsed: ConfirmParsed = .{ .portal = portal, .contract = contract, .config = .{
        .fee_disburser = contract,
        .window = window,
        .dry_run = spec.dry_run,
        .withdrawal_timeout_ms = spec.withdrawal_timeout_s * 1000,
        .poll_interval_ms = 2_000,
    } };
    assert(parsed.config.window.valid());
    return parsed;
}

fn confirm_main(init: std.process.Init, args: []const []const u8) !u8 {
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(ConfirmSpec, env_prefix, args, env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_confirm_help();
            return 0;
        }
        std.debug.print("fee-jobs confirm: {t}: {s}\n", .{ err, diagnostic.subject });
        return 2;
    };
    const parsed = parse_confirm(spec) catch |err| {
        std.debug.print("fee-jobs confirm: invalid flags: {t}\n", .{err});
        return 2;
    };
    const signer = read_key(init) orelse return 2;
    return run_confirm(init, spec, parsed, signer);
}

const ConfirmClients = struct {
    l1_http: HttpTransport,
    l2_http: HttpTransport,
    l1: rpc.Client,
    l2: rpc.Client,

    fn init(clients: *ConfirmClients, gpa: std.mem.Allocator, io: Io, spec: ConfirmSpec) !void {
        clients.l1_http = HttpTransport.init(gpa, io, spec.l1_rpc_url);
        clients.l2_http = HttpTransport.init(gpa, io, spec.l2_rpc_url);
        clients.l1_http.timeout_ms = spec.network_timeout_ms;
        clients.l2_http.timeout_ms = spec.network_timeout_ms;
        const limits: rpc.Limits = .{
            .request_bytes_max = 256 * 1024,
            .response_bytes_max = 2 * 1024 * 1024,
            .parse_bytes_max = 16 * 1024 * 1024,
        };
        clients.l1 = try rpc.Client.init(gpa, clients.l1_http.transport(), limits);
        errdefer clients.l1.deinit(gpa);
        clients.l2 = try rpc.Client.init(gpa, clients.l2_http.transport(), limits);
    }

    fn deinit(clients: *ConfirmClients, gpa: std.mem.Allocator) void {
        clients.l2.deinit(gpa);
        clients.l1.deinit(gpa);
        clients.l2_http.deinit();
        clients.l1_http.deinit();
    }
};

fn run_confirm(
    init: std.process.Init,
    spec: ConfirmSpec,
    parsed: ConfirmParsed,
    signer: Signer,
) !u8 {
    const gpa = init.gpa;
    var clients: ConfirmClients = undefined;
    try clients.init(gpa, init.io, spec);
    defer clients.deinit(gpa);
    var reader = try withdrawer.reader.Reader.init(
        gpa,
        &clients.l1,
        &clients.l2,
        parsed.portal,
        signer.from.bytes,
        .{},
    );
    defer reader.deinit(gpa);
    // base/base resolves the proof contracts (rejecting zero addresses) before scanning.
    _ = reader.resolve_contracts() catch |err| {
        std.debug.print("fee-jobs confirm: reading portal contracts: {t}\n", .{err});
        return 1;
    };
    const driver = try gpa.create(withdrawer.flow.SendDriver);
    defer gpa.destroy(driver);
    driver.* = try withdrawer.flow.SendDriver.init(gpa, .{
        .chain_id = spec.l1_chain_id,
        .private_key = signer.private_key,
        .from = signer.from,
        .data_bytes_max = 64 * 1024,
        .manager = .{
            .num_confirmations = spec.confirmations,
            .resubmission_timeout_ms = @as(u64, spec.resubmission_timeout_s) * 1000,
            .receipt_query_interval_ms = spec.receipt_poll_ms,
        },
    });
    defer driver.deinit(gpa);
    var printer: u8 = 0;
    var job: confirm.Job = .{
        .allocator = gpa,
        .config = parsed.config,
        .reader = &reader,
        .l1_driver = driver,
        .events = .{ .context = &printer, .emit = print_event },
    };
    const clock: Clock = .{ .io = init.io };
    const report = job.run(&clock) catch |err| {
        std.debug.print("fee-jobs confirm: failed: {t}\n", .{err});
        return 1;
    };
    std.debug.print("fee-jobs confirm: {d} disbursals, {d} withdrawals ({d} pending), " ++
        "{d} skipped, {d} failed\n", .{
        report.disbursals, report.withdrawals, report.pending, report.skipped, report.failures,
    });
    return if (report.failures == 0) 0 else 1;
}

fn print_event(context: *anyopaque, event: confirm.Event) void {
    assert(@as(*u8, @ptrCast(context)).* == 0);
    switch (event) {
        .range => |range| std.debug.print(
            "fee-jobs confirm: querying fee disbursals {d}..{d}\n",
            .{ range.from, range.to },
        ),
        .skipped => |skipped| std.debug.print(
            "fee-jobs confirm: skipping withdrawal 0x{x} not sent by the FeeDisburser " ++
                "(transaction 0x{x})\n",
            .{ &skipped.withdrawal, &skipped.transaction },
        ),
        .withdrawal => |withdrawal| {
            std.debug.print("fee-jobs confirm: withdrawal 0x{x} (transaction 0x{x}): {t}", .{
                &withdrawal.withdrawal, &withdrawal.transaction, withdrawal.outcome,
            });
            if (withdrawal.l1_transaction) |hash| std.debug.print(", l1 0x{x}", .{&hash});
            std.debug.print("\n", .{});
        },
        .failed => |failed| std.debug.print(
            "fee-jobs confirm: transaction 0x{x} failed: {t}\n",
            .{ &failed.transaction, failed.err },
        ),
    }
}

fn run(
    init: std.process.Init,
    spec: Spec,
    kind: fee_jobs.Kind,
    contract: fee_jobs.Address,
    private_key: [32]u8,
    from: fee_jobs.Address,
) !u8 {
    var http = HttpTransport.init(init.gpa, init.io, spec.rpc_url);
    http.timeout_ms = 10_000;
    defer http.deinit();
    var client = try rpc.Client.init(init.gpa, http.transport(), .{
        .request_bytes_max = 16 * 1024,
        .response_bytes_max = 64 * 1024,
        .parse_bytes_max = 512 * 1024,
    });
    defer client.deinit(init.gpa);
    var driver = try Driver.init(init.gpa, .{
        .chain_id = spec.chain_id,
        .private_key = private_key,
        .from = from,
        .data_bytes_max = 64,
        .manager = .{
            .num_confirmations = spec.confirmations,
            .resubmission_timeout_ms = @as(u64, spec.resubmission_timeout_s) * 1000,
            .receipt_query_interval_ms = spec.receipt_poll_ms,
            .tx_send_timeout_ms = @as(u64, spec.send_timeout_s) * 1000,
        },
    });
    defer driver.deinit(init.gpa);
    const clock: Clock = .{ .io = init.io };
    const step_ms = @max(50, spec.receipt_poll_ms / 2);
    const outcome = fee_jobs.run(&driver, &client, &clock, kind, contract, step_ms) catch |err| {
        std.debug.print("fee-jobs {t}: failed: {t}\n", .{ kind, err });
        return 1;
    };
    switch (outcome) {
        .skipped => |reading| switch (reading) {
            .window => |window| std.debug.print(
                "fee-jobs disburse: skipped, interval not elapsed (last {d} + interval {d} > " ++
                    "timestamp {d})\n",
                .{ window.last_s, window.interval_s, window.timestamp_s },
            ),
            .balance_wei => |balance| std.debug.print(
                "fee-jobs {t}: skipped, balance {d} wei below the minimum\n",
                .{ kind, balance },
            ),
        },
        .confirmed => |confirmed| std.debug.print(
            "fee-jobs {t}: confirmed 0x{x} in block {d}\n",
            .{ kind, &confirmed.hash, confirmed.block_number },
        ),
    }
    return 0;
}

const testing = std.testing;

test "fee-jobs confirm: flags mirror base/base defaults and validation" {
    var diagnostic: cli.Diagnostic = .{};
    const env: cli.Env = .{};
    const args = [_][]const u8{
        "--l1-rpc-url",  "http://127.0.0.1:8545",
        "--l2-rpc-url",  "http://127.0.0.1:9545",
        "--l1-chain-id", "900",
        "--portal",      "0x5050505050505050505050505050505050505050",
        "--contract",    "0x4444444444444444444444444444444444444444",
    };
    const spec = try cli.parse(ConfirmSpec, env_prefix, &args, env, &diagnostic);
    const parsed = try parse_confirm(spec);
    try testing.expectEqual(@as(u64, 21 * 24 * 60 * 60 * 1000), parsed.config.window.lookback_ms);
    try testing.expectEqual(@as(u64, 2_000), parsed.config.window.block_time_ms);
    try testing.expectEqual(@as(u64, 3_000), parsed.config.window.blocks_per_query);
    try testing.expectEqual(@as(u64, 600_000), parsed.config.withdrawal_timeout_ms);
    try testing.expect(!parsed.config.dry_run);
    try testing.expectEqual(@as(u8, 0x44), parsed.config.fee_disburser[19]);
    const dry_args = args ++ [_][]const u8{ "--dry-run", "--num-blocks-per-query", "25" };
    const dry_spec = try cli.parse(ConfirmSpec, env_prefix, &dry_args, env, &diagnostic);
    const dry = try parse_confirm(dry_spec);
    try testing.expect(dry.config.dry_run);
    try testing.expectEqual(@as(u64, 25), dry.config.window.blocks_per_query);
    var bad = spec;
    bad.num_blocks_per_query = 0;
    try testing.expectError(error.InvalidValue, parse_confirm(bad));
    bad = spec;
    bad.contract = "0x0000000000000000000000000000000000000000";
    try testing.expectError(error.ZeroAddress, parse_confirm(bad));
    bad = spec;
    bad.lookback_s = 0;
    try testing.expectError(error.InvalidValue, parse_confirm(bad));
    // The key is never a flag.
    const key_args = args ++ [_][]const u8{ "--private-key", "0x01" };
    const key_flag = cli.parse(ConfirmSpec, env_prefix, &key_args, env, &diagnostic);
    try testing.expectError(error.UnknownFlag, key_flag);
}

test "fee-jobs: hex parsing" {
    const address = try parse_hex(20, "0x" ++ "abababababababababababababababababababab");
    try testing.expectEqual(@as(u8, 0xab), address[19]);
    const key_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    _ = try parse_hex(32, key_hex);
    try testing.expectError(error.InvalidHex, parse_hex(20, "0x1234"));
    const bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    try testing.expectError(error.InvalidHex, parse_hex(20, bad));
}

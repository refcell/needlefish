//! `base fee-jobs disburse|process|sweep`: one-shot fee collection jobs (see
//! `src/infra/fee_jobs`). Checks the job's precondition, and when it holds sends one call
//! through the tx manager and waits for `--confirmations`. Exit 0 on a confirmed send or a
//! skip (false precondition), 1 on a failed job, 2 on bad flags.
//!
//! The signing key comes from `BASE_FEE_JOBS_PRIVATE_KEY` (hex, `0x` optional; base/base
//! `JOB_RUNNER_KEY`) and is never accepted as a flag, so it stays out of process listings.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const secp256k1 = base.common.crypto.secp256k1;
const fee_jobs = base.infra.fee_jobs;
const tx_manager = base.infra.tx_manager;
const HttpTransport = @import("http_transport.zig").HttpTransport;

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

fn print_help() void {
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print(
        "usage: base fee-jobs disburse|process|sweep --rpc-url URL --chain-id ID " ++
            "--contract ADDR\n  key: {s} (hex)\n{s}",
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
    const key_text = init.environ_map.get(key_variable) orelse {
        std.debug.print("fee-jobs: {s} is not set\n", .{key_variable});
        return 2;
    };
    const private_key = parse_hex(32, key_text) catch {
        std.debug.print("fee-jobs: {s} is not a 32-byte hex key\n", .{key_variable});
        return 2;
    };
    const from = secp256k1.address(private_key) catch {
        std.debug.print("fee-jobs: {s} is not a valid secp256k1 key\n", .{key_variable});
        return 2;
    };
    return run(init, spec, kind, contract, private_key, .{ .bytes = from });
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

test "fee-jobs: hex parsing" {
    const address = try parse_hex(20, "0x" ++ "abababababababababababababababababababab");
    try testing.expectEqual(@as(u8, 0xab), address[19]);
    const key_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    _ = try parse_hex(32, key_hex);
    try testing.expectError(error.InvalidHex, parse_hex(20, "0x1234"));
    const bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    try testing.expectError(error.InvalidHex, parse_hex(20, bad));
}

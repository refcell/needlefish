//! `base batcher`: submits L2 batches to L1 (see docs/DEVNET.md for the flags).

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const Servers = @import("batcher_servers.zig").Servers;

const Io = std.Io;
const batcher = base.batcher;

const usage =
    \\usage: base batcher --rollup-config FILE --l1 URL --l2 URL [--rollup-rpc URL]
    \\         [--key-index N | --private-key HEX] [--max-channel-duration L1_BLOCKS]
    \\         [--poll-interval-ms MS] [--metrics.port P] [--data-availability calldata|blobs]
    \\         [--compression brotli|zlib] [--no-throttle]
    \\         [--throttle-strategy off|step|linear|quadratic]
    \\         [--admin-port P [--admin-addr IP]] [--stopped] [--num-confirmations N]
    \\         [--min-tip-cap GWEI] [--min-basefee GWEI] [--max-pending-transactions N]
    \\         [--sub-safety-margin L1_BLOCKS] [--wait-node-sync [--check-recent-txs-depth N]
    \\         [--wait-node-sync-timeout SECONDS]]
    \\
;

const Flags = struct {
    rollup_config: ?[]const u8 = null,
    l1: ?[]const u8 = null,
    l2: ?[]const u8 = null,
    rollup_rpc: ?[]const u8 = null,
    key_index: u32 = @backingInt(batcher.devnet.accounts.Role.batcher),
    private_key: ?[32]u8 = null,
    max_channel_duration: u64 = 2,
    /// L1 blocks subtracted from `max_channel_duration` so channels close with room to land
    /// before they could time out (base/base `--sub-safety-margin`).
    sub_safety_margin: u64 = 0,
    poll_interval_ms: u64 = 1000,
    data_availability: batcher.txmgr.DataAvailability = .calldata,
    /// base/base batches with brotli (Fjord is active from genesis on the devnet).
    compression: batcher.comp.Algorithm = .brotli,
    /// Serve Prometheus metrics on this port (op-batcher `--metrics.port`).
    metrics_port: ?u16 = null,
    /// Admin JSON-RPC API (base/base `--admin-port`, `--admin-addr`, default loopback).
    admin_port: ?u16 = null,
    admin_address: base.utilities.io.Address = .loopback(0),
    /// Start with ingestion stopped until `admin_startBatcher` (base/base `--stopped`).
    stopped: bool = false,
    /// DA throttling of the sequencer (base/base default: quadratic).
    throttle_strategy: batcher.throttle.Strategy = .quadratic,
    /// base/base txmgr flags.
    confirmations: u64 = 1,
    min_tip_wei: u128 = 0,
    min_base_fee_wei: u128 = 0,
    /// In-flight tx slots (base/base `--max-pending-transactions`; ours defaults to 8).
    pending_max: u8 = 8,
    /// Wait for the rollup node to reach an L1 target before batching (base/base).
    wait_node_sync: bool = false,
    wait_node_sync_timeout_s: u64 = 600,
    /// Recent-tx window selecting the sync target; 0 = the L1 head.
    check_recent_txs_depth: u64 = 0,
};

/// Largest L1 transaction payload (op-batcher `MaxL1TxSize` default).
const tx_data_bytes_max: u32 = 120_000;

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var i: usize = 0;
    const eql = std.mem.eql;
    while (i < args.len) {
        const arg = args[i];
        if (parse_switch(&flags, arg)) {
            i += 1; // A switch takes no value.
            continue;
        }
        if (i + 1 == args.len) return error.MissingValue;
        const value = args[i + 1];
        if (eql(u8, arg, "--rollup-config")) {
            flags.rollup_config = value;
        } else if (eql(u8, arg, "--l1")) {
            flags.l1 = value;
        } else if (eql(u8, arg, "--l2")) {
            flags.l2 = value;
        } else if (eql(u8, arg, "--rollup-rpc")) {
            flags.rollup_rpc = value;
        } else if (eql(u8, arg, "--key-index")) {
            flags.key_index = try std.fmt.parseInt(u32, value, 10);
        } else if (eql(u8, arg, "--private-key")) {
            flags.private_key = try base.common.primitives.hex.decode_array(32, value);
        } else if (eql(u8, arg, "--max-channel-duration")) {
            flags.max_channel_duration = try std.fmt.parseInt(u64, value, 10);
        } else if (eql(u8, arg, "--poll-interval-ms")) {
            flags.poll_interval_ms = try std.fmt.parseInt(u64, value, 10);
        } else if (eql(u8, arg, "--metrics.port")) {
            flags.metrics_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--data-availability")) {
            flags.data_availability = std.meta.stringToEnum(
                batcher.txmgr.DataAvailability,
                value,
            ) orelse return error.UnknownDataAvailability;
        } else if (eql(u8, arg, "--check-recent-txs-depth")) {
            flags.check_recent_txs_depth = try std.fmt.parseInt(u64, value, 10);
        } else if (eql(u8, arg, "--wait-node-sync-timeout")) {
            flags.wait_node_sync_timeout_s = try std.fmt.parseInt(u64, value, 10);
        } else if (eql(u8, arg, "--sub-safety-margin")) {
            flags.sub_safety_margin = try std.fmt.parseInt(u64, value, 10);
        } else if (eql(u8, arg, "--num-confirmations")) {
            flags.confirmations = try std.fmt.parseInt(u64, value, 10);
            if (flags.confirmations == 0) return error.InvalidConfirmations;
        } else if (eql(u8, arg, "--min-tip-cap")) {
            flags.min_tip_wei = try parse_gwei(value);
        } else if (eql(u8, arg, "--min-basefee")) {
            flags.min_base_fee_wei = try parse_gwei(value);
        } else if (eql(u8, arg, "--max-pending-transactions")) {
            flags.pending_max = try std.fmt.parseInt(u8, value, 10);
            if (flags.pending_max == 0) return error.InvalidPendingMax;
        } else if (eql(u8, arg, "--admin-port")) {
            flags.admin_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--admin-addr")) {
            flags.admin_address = try base.utilities.io.Address.parse(value);
        } else if (eql(u8, arg, "--throttle-strategy")) {
            flags.throttle_strategy = std.meta.stringToEnum(batcher.throttle.Strategy, value) orelse
                return error.UnknownThrottleStrategy;
        } else if (eql(u8, arg, "--compression")) {
            flags.compression = std.meta.stringToEnum(batcher.comp.Algorithm, value) orelse
                return error.UnknownCompression;
        } else return error.UnknownFlag;
        i += 2;
    }
    if (i != args.len) return error.MissingValue;
    try validate_flags(flags);
    return flags;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch |err| {
        std.debug.print("batcher: {t}\n{s}", .{ err, usage });
        return 2;
    };
    const rollup_path = flags.rollup_config orelse return usage_error();
    const l1_url = flags.l1 orelse return usage_error();
    const l2_url = flags.l2 orelse return usage_error();
    const rollup_text = try Io.Dir.cwd().readFileAlloc(
        init.io,
        rollup_path,
        init.gpa,
        .limited(1 << 20),
    );
    defer init.gpa.free(rollup_text);
    const rollup = try batcher.service.RollupFields.parse(init.gpa, rollup_text);
    const accounts = batcher.devnet.accounts;
    const account = flags.private_key orelse accounts.derive_dev(flags.key_index).private_key;
    var seed: [16]u8 = undefined;
    init.io.random(&seed);
    // One frame per transaction payload: the payload is `version byte ++ frame`.
    const payload_max: u32 = switch (flags.data_availability) {
        .calldata => tx_data_bytes_max,
        .blobs => batcher.blobs.blob_data_length_max,
    };
    var service = try batcher.service.Service.init(init.gpa, .{
        .channels = .{
            .channel = .{
                .frame_size_max = payload_max - 1,
                .input_bytes_max = 4 << 20,
                .algorithm = flags.compression,
            },
            .max_channel_duration_l1_blocks = flags.max_channel_duration - flags.sub_safety_margin,
        },
        .txs = .{
            .chain_id = rollup.l1_chain_id,
            .private_key = account,
            .from = accounts.address_of(account),
            .to = rollup.batch_inbox_address,
            .tx_data_bytes_max = payload_max,
            .data_availability = flags.data_availability,
            // op-batcher's blob default: up to 6 frames (blobs) per transaction.
            .blobs_per_tx = if (flags.data_availability == .blobs) 6 else 1,
            .slots_max = flags.pending_max,
            .confirmations = flags.confirmations,
            .min_tip_wei = flags.min_tip_wei,
            .min_base_fee_wei = flags.min_base_fee_wei,
        },
        // 30 L1 blocks without safe-head progress: resubmit from the safe head.
        .stall_l1_blocks = 30,
        .throttle = .{ .strategy = flags.throttle_strategy },
        .stopped = flags.stopped,
    }, seed);
    defer service.deinit(init.gpa);
    return run(init, flags, &service, l1_url, l2_url);
}

fn run(
    init: std.process.Init,
    flags: Flags,
    service: *batcher.service.Service,
    l1_url: []const u8,
    l2_url: []const u8,
) !u8 {
    const limits: batcher.rpc.Limits = .{};
    var l1_http = HttpTransport.init(init.gpa, init.io, l1_url);
    defer l1_http.deinit();
    var l1 = try batcher.rpc.Client.init(init.gpa, l1_http.transport(), limits);
    defer l1.deinit(init.gpa);
    var l2_http = HttpTransport.init(init.gpa, init.io, l2_url);
    defer l2_http.deinit();
    var l2 = try batcher.rpc.Client.init(init.gpa, l2_http.transport(), limits);
    defer l2.deinit(init.gpa);
    var rollup_http = HttpTransport.init(init.gpa, init.io, flags.rollup_rpc orelse l2_url);
    defer rollup_http.deinit();
    var rollup = try batcher.rpc.Client.init(init.gpa, rollup_http.transport(), .{});
    defer rollup.deinit(init.gpa);
    const clients: batcher.service.Clients = .{
        .l1 = &l1,
        .l2 = &l2,
        .rollup = if (flags.rollup_rpc != null) &rollup else null,
    };
    std.debug.print("batcher: started on L1 chain {d}\n", .{service.txs.config.chain_id});
    if (flags.wait_node_sync) try wait_for_node_sync(init, flags, &l1, &rollup, service);
    var metrics: batcher.metrics.Metrics = .{};
    try metrics.register();
    var admin: batcher.admin.Admin = .{ .service = service };
    var servers: Servers = undefined;
    const serving = start_servers(&servers, init.gpa, flags, &metrics, &admin);
    var throttle_logged: batcher.throttle.Outcome = .idle;
    while (true) {
        const now_ms: u64 = @intCast(Io.Clock.awake.now(init.io).toMilliseconds());
        if (service.step(clients, now_ms)) |report| {
            log_report(report);
            metrics.record(report, service.txs.pending_count());
            log_throttle(report.throttle, &throttle_logged);
        } else |err| {
            metrics.step_failures.increment();
            std.debug.print("batcher: step failed: {t} {s}\n", .{ err, l1.last_error() });
        }
        if (serving) {
            try servers.serve_for(flags.poll_interval_ms);
        } else {
            try init.io.sleep(.fromMilliseconds(@intCast(flags.poll_interval_ms)), .awake);
        }
    }
}

/// Logs throttle outcomes when they change (pushes repeat every refresh).
fn log_throttle(outcome: batcher.throttle.Outcome, last: *batcher.throttle.Outcome) void {
    if (outcome == .idle or outcome == last.*) return;
    last.* = outcome;
    switch (outcome) {
        .idle => unreachable, // Returned above.
        .pushed => std.debug.print("batcher: DA limits applied by the block builder\n", .{}),
        .refused => std.debug.print("batcher: block builder refused the DA limits\n", .{}),
        .failed => std.debug.print("batcher: failed to push DA limits; retrying\n", .{}),
        .unsupported => std.debug.print(
            "batcher: block builder lacks miner_setMaxDASize; DA throttling disabled\n",
            .{},
        ),
    }
}

/// Valueless flags; returns false for flags that take a value.
fn parse_switch(flags: *Flags, arg: []const u8) bool {
    const eql = std.mem.eql;
    if (eql(u8, arg, "--stopped")) {
        flags.stopped = true;
    } else if (eql(u8, arg, "--wait-node-sync")) {
        flags.wait_node_sync = true;
    } else if (eql(u8, arg, "--no-throttle")) {
        flags.throttle_strategy = .off;
    } else return false;
    return true;
}

/// Cross-flag checks (base/base config validation).
fn validate_flags(flags: Flags) !void {
    // base/base rejects a margin that leaves no channel duration.
    if (flags.sub_safety_margin >= flags.max_channel_duration) return error.SubSafetyMarginTooLarge;
    const recent_depth_max = batcher.sync.recent_txs_depth_max;
    if (flags.check_recent_txs_depth > recent_depth_max) return error.RecentTxsDepthTooLarge;
    if (flags.check_recent_txs_depth > 0 and !flags.wait_node_sync)
        return error.RecentTxsDepthRequiresWaitNodeSync;
    // Node sync is read from the rollup node: required, not optional, with the flag.
    if (flags.wait_node_sync and flags.rollup_rpc == null)
        return error.WaitNodeSyncRequiresRollupRpc;
}

/// Waits until the rollup node's `current_l1` reaches the sync target, retrying RPC
/// failures, for at most `--wait-node-sync-timeout` (then exits, as base/base does).
fn wait_for_node_sync(
    init: std.process.Init,
    flags: Flags,
    l1: *batcher.rpc.Client,
    rollup: *batcher.rpc.Client,
    service: *const batcher.service.Service,
) !void {
    std.debug.assert(flags.wait_node_sync);
    const start_ms: u64 = @intCast(Io.Clock.awake.now(init.io).toMilliseconds());
    const deadline_ms = start_ms + flags.wait_node_sync_timeout_s * std.time.ms_per_s;
    var target: ?u64 = null;
    while (true) {
        const now_ms: u64 = @intCast(Io.Clock.awake.now(init.io).toMilliseconds());
        if (now_ms >= deadline_ms) return error.NodeSyncTimeout;
        if (target == null) target = sync_target(flags, l1, service) catch null;
        if (target) |target_l1| {
            if (batcher.sync.node_synced(rollup, target_l1)) |synced| {
                if (synced) {
                    std.debug.print("batcher: rollup node synced to L1 {d}\n", .{target_l1});
                    return;
                }
            } else |_| {}
        }
        try init.io.sleep(.fromMilliseconds(@intCast(flags.poll_interval_ms)), .awake);
    }
}

fn sync_target(
    flags: Flags,
    l1: *batcher.rpc.Client,
    service: *const batcher.service.Service,
) !u64 {
    if (flags.check_recent_txs_depth == 0) {
        return batcher.rpc.quantity(u64, try l1.call("eth_blockNumber", "[]"));
    }
    const from = service.txs.config.from;
    return batcher.sync.recent_tx_target(l1, from, flags.check_recent_txs_depth);
}

/// Parses a decimal gwei amount ("2", "0.25", up to 9 fraction digits) into wei.
fn parse_gwei(text: []const u8) !u128 {
    const dot = std.mem.indexOfScalar(u8, text, '.') orelse text.len;
    if (dot == 0) return error.InvalidGwei;
    const whole = try std.fmt.parseInt(u64, text[0..dot], 10);
    var fraction_wei: u128 = 0;
    if (dot < text.len) {
        const digits = text[dot + 1 ..];
        if (digits.len == 0 or digits.len > 9) return error.InvalidGwei;
        const fraction = try std.fmt.parseInt(u64, digits, 10);
        fraction_wei = fraction * std.math.pow(u128, 10, 9 - digits.len);
    }
    std.debug.assert(fraction_wei < 1_000_000_000);
    return @as(u128, whole) * 1_000_000_000 + fraction_wei;
}

/// Starts the optional HTTP endpoints. Each failure is logged and only disables that
/// endpoint: batching never depends on them. Returns false when none is serving.
fn start_servers(
    servers: *Servers,
    allocator: std.mem.Allocator,
    flags: Flags,
    metrics: *batcher.metrics.Metrics,
    admin: *batcher.admin.Admin,
) bool {
    if (flags.metrics_port == null and flags.admin_port == null) return false;
    servers.init() catch |err| {
        std.debug.print("batcher: HTTP endpoints disabled: {t}\n", .{err});
        return false;
    };
    if (flags.metrics_port) |port| _ = servers.serve_metrics(allocator, metrics, port);
    if (flags.admin_port) |port| {
        var address = flags.admin_address;
        address.port = port;
        _ = servers.serve_admin(allocator, admin, address);
    }
    return servers.active();
}

fn log_report(report: batcher.service.Report) void {
    const activity = report.blocks_loaded + report.txs_submitted + report.txs_confirmed;
    if (activity + report.resets == 0) return;
    std.debug.print("batcher: l1={d} safe={d} unsafe={d} ", .{
        report.heads.l1,
        report.heads.safe_l2,
        report.heads.unsafe_l2,
    });
    std.debug.print("loaded={d} sent={d} confirmed={d} resets={d}\n", .{
        report.blocks_loaded,
        report.txs_submitted,
        report.txs_confirmed,
        report.resets,
    });
}

fn usage_error() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

test "batcher: flags" {
    const args = [_][]const u8{ "--l1", "http://x", "--key-index", "3", "--metrics.port", "7300" };
    const flags = try parse_flags(&args);
    try std.testing.expectEqual(@as(u32, 3), flags.key_index);
    try std.testing.expectEqual(@as(?u16, 7300), flags.metrics_port);
    const bad_port = [_][]const u8{ "--metrics.port", "70000" };
    try std.testing.expectError(error.Overflow, parse_flags(&bad_port));
    const blobs = [_][]const u8{ "--data-availability", "blobs" };
    try std.testing.expectEqual(.blobs, (try parse_flags(&blobs)).data_availability);
    try std.testing.expectEqual(.brotli, (try parse_flags(&blobs)).compression);
    const zlib = [_][]const u8{ "--compression", "zlib" };
    try std.testing.expectEqual(.zlib, (try parse_flags(&zlib)).compression);
    try std.testing.expectEqual(.quadratic, (try parse_flags(&zlib)).throttle_strategy);
    const no_throttle = [_][]const u8{ "--no-throttle", "--compression", "zlib", "--no-throttle" };
    const switched = try parse_flags(&no_throttle);
    try std.testing.expectEqual(.off, switched.throttle_strategy);
    try std.testing.expectEqual(.zlib, switched.compression);
    const linear = [_][]const u8{ "--throttle-strategy", "linear" };
    try std.testing.expectEqual(.linear, (try parse_flags(&linear)).throttle_strategy);
    const admin = [_][]const u8{ "--stopped", "--admin-port", "7301", "--admin-addr", "0.0.0.0" };
    const admin_flags = try parse_flags(&admin);
    try std.testing.expect(admin_flags.stopped);
    try std.testing.expectEqual(@as(?u16, 7301), admin_flags.admin_port);
    try std.testing.expectEqual(@as(u8, 0), admin_flags.admin_address.bytes[0]);
    const bad_addr = [_][]const u8{ "--admin-addr", "localhost" };
    try std.testing.expectError(error.InvalidAddress, parse_flags(&bad_addr));
    const fees = [_][]const u8{
        "--min-tip-cap",       "0.01", "--min-basefee",              "2",
        "--num-confirmations", "3",    "--max-pending-transactions", "4",
    };
    const fee_flags = try parse_flags(&fees);
    try std.testing.expectEqual(@as(u128, 10_000_000), fee_flags.min_tip_wei);
    try std.testing.expectEqual(@as(u128, 2_000_000_000), fee_flags.min_base_fee_wei);
    try std.testing.expectEqual(@as(u64, 3), fee_flags.confirmations);
    try std.testing.expectEqual(@as(u8, 4), fee_flags.pending_max);
    try std.testing.expectError(error.InvalidGwei, parse_gwei("1.0000000001"));
    try std.testing.expectError(error.InvalidGwei, parse_gwei(".5"));
    try std.testing.expectEqual(@as(u128, 1_500_000_000), try parse_gwei("1.5"));
    const margin = [_][]const u8{ "--max-channel-duration", "10", "--sub-safety-margin", "4" };
    try std.testing.expectEqual(@as(u64, 4), (try parse_flags(&margin)).sub_safety_margin);
    const no_room = [_][]const u8{ "--max-channel-duration", "4", "--sub-safety-margin", "4" };
    try std.testing.expectError(error.SubSafetyMarginTooLarge, parse_flags(&no_room));
    const sync_ok = [_][]const u8{
        "--wait-node-sync", "--check-recent-txs-depth", "128",
        "--rollup-rpc",     "http://127.0.0.1:7545",    "--wait-node-sync-timeout",
        "5",
    };
    const sync_flags = try parse_flags(&sync_ok);
    try std.testing.expect(sync_flags.wait_node_sync);
    try std.testing.expectEqual(@as(u64, 128), sync_flags.check_recent_txs_depth);
    try std.testing.expectEqual(@as(u64, 5), sync_flags.wait_node_sync_timeout_s);
    const too_deep = [_][]const u8{ "--wait-node-sync", "--check-recent-txs-depth", "129" };
    try std.testing.expectError(error.RecentTxsDepthTooLarge, parse_flags(&too_deep));
    const no_wait = [_][]const u8{ "--check-recent-txs-depth", "3" };
    try std.testing.expectError(error.RecentTxsDepthRequiresWaitNodeSync, parse_flags(&no_wait));
    const no_rollup = [_][]const u8{"--wait-node-sync"};
    try std.testing.expectError(error.WaitNodeSyncRequiresRollupRpc, parse_flags(&no_rollup));
    const dangling = [_][]const u8{"--l1"};
    try std.testing.expectError(error.MissingValue, parse_flags(&dangling));
    const bad = [_][]const u8{ "--data-availability", "carrier-pigeon" };
    try std.testing.expectError(error.UnknownDataAvailability, parse_flags(&bad));
    try std.testing.expectError(error.MissingValue, parse_flags(&.{"--l1"}));
}

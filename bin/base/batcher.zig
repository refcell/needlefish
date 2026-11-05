//! `base batcher`: submits L2 batches to L1 (see docs/DEVNET.md for the flags).

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const MetricsServer = @import("batcher_metrics.zig").MetricsServer;

const Io = std.Io;
const batcher = base.batcher;

const usage =
    \\usage: base batcher --rollup-config FILE --l1 URL --l2 URL [--rollup-rpc URL]
    \\         [--key-index N | --private-key HEX] [--max-channel-duration L1_BLOCKS]
    \\         [--poll-interval-ms MS] [--metrics.port P] [--data-availability calldata|blobs]
    \\         [--compression brotli|zlib] [--no-throttle]
    \\         [--throttle-strategy off|step|linear|quadratic]
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
    poll_interval_ms: u64 = 1000,
    data_availability: batcher.txmgr.DataAvailability = .calldata,
    /// base/base batches with brotli (Fjord is active from genesis on the devnet).
    compression: batcher.comp.Algorithm = .brotli,
    /// Serve Prometheus metrics on this port (op-batcher `--metrics.port`).
    metrics_port: ?u16 = null,
    /// DA throttling of the sequencer (base/base default: quadratic).
    throttle_strategy: batcher.throttle.Strategy = .quadratic,
};

/// Largest L1 transaction payload (op-batcher `MaxL1TxSize` default).
const tx_data_bytes_max: u32 = 120_000;

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var i: usize = 0;
    const eql = std.mem.eql;
    while (i < args.len) {
        const arg = args[i];
        if (eql(u8, arg, "--no-throttle")) {
            flags.throttle_strategy = .off;
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
            .max_channel_duration_l1_blocks = flags.max_channel_duration,
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
        },
        // 30 L1 blocks without safe-head progress: resubmit from the safe head.
        .stall_l1_blocks = 30,
        .throttle = .{ .strategy = flags.throttle_strategy },
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
    var metrics: batcher.metrics.Metrics = .{};
    try metrics.register();
    var metrics_server: MetricsServer = undefined;
    const serving = if (flags.metrics_port) |port|
        start_metrics(&metrics_server, init.gpa, &metrics, port)
    else
        false;
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
            try metrics_server.serve_for(flags.poll_interval_ms);
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

/// Metrics are optional: a bind failure is logged and batching continues without them.
fn start_metrics(
    server: *MetricsServer,
    allocator: std.mem.Allocator,
    metrics: *batcher.metrics.Metrics,
    port: u16,
) bool {
    server.start(allocator, metrics, port) catch |err| {
        std.debug.print("batcher: metrics disabled, port {d}: {t}\n", .{ port, err });
        return false;
    };
    std.debug.print("batcher: metrics on :{d}/metrics\n", .{port});
    return true;
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
    const dangling = [_][]const u8{"--l1"};
    try std.testing.expectError(error.MissingValue, parse_flags(&dangling));
    const bad = [_][]const u8{ "--data-availability", "carrier-pigeon" };
    try std.testing.expectError(error.UnknownDataAvailability, parse_flags(&bad));
    try std.testing.expectError(error.MissingValue, parse_flags(&.{"--l1"}));
}

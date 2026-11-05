//! `base batcher`: submits L2 batches to L1 (see docs/DEVNET.md for the flags).

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Io = std.Io;
const batcher = base.batcher;

const usage =
    \\usage: base batcher --rollup-config FILE --l1 URL --l2 URL [--rollup-rpc URL]
    \\         [--key-index N | --private-key HEX] [--max-channel-duration L1_BLOCKS]
    \\         [--poll-interval-ms MS] [--metrics.port P] [--data-availability calldata]
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
};

/// Largest L1 transaction payload (op-batcher `MaxL1TxSize` default).
const tx_data_bytes_max: u32 = 120_000;

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 2) {
        const arg = args[i];
        const value = args[i + 1];
        const eql = std.mem.eql;
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
            // Metrics land with utilities/metrics; accepted for the process contract.
        } else if (eql(u8, arg, "--data-availability")) {
            flags.data_availability = std.meta.stringToEnum(
                batcher.txmgr.DataAvailability,
                value,
            ) orelse return error.UnknownDataAvailability;
        } else return error.UnknownFlag;
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
            .channel = .{ .frame_size_max = payload_max - 1, .input_bytes_max = 4 << 20 },
            .max_channel_duration_l1_blocks = flags.max_channel_duration,
        },
        .txs = .{
            .chain_id = rollup.l1_chain_id,
            .private_key = account,
            .from = accounts.address_of(account),
            .to = rollup.batch_inbox_address,
            .tx_data_bytes_max = payload_max,
            .data_availability = flags.data_availability,
        },
        // 30 L1 blocks without safe-head progress: resubmit from the safe head.
        .stall_l1_blocks = 30,
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
    while (true) {
        const now_ms: u64 = @intCast(Io.Clock.awake.now(init.io).toMilliseconds());
        if (service.step(clients, now_ms)) |report| {
            log_report(report);
        } else |err| {
            std.debug.print("batcher: step failed: {t} {s}\n", .{ err, l1.last_error() });
        }
        try init.io.sleep(.fromMilliseconds(@intCast(flags.poll_interval_ms)), .awake);
    }
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
    const blobs = [_][]const u8{ "--data-availability", "blobs" };
    try std.testing.expectEqual(.blobs, (try parse_flags(&blobs)).data_availability);
    const bad = [_][]const u8{ "--data-availability", "carrier-pigeon" };
    try std.testing.expectError(error.UnknownDataAvailability, parse_flags(&bad));
    try std.testing.expectError(error.MissingValue, parse_flags(&.{"--l1"}));
}

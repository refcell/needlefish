//! `base batcher`: submits L2 batches to L1 (see docs/DEVNET.md for the flags).

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const Servers = @import("batcher_servers.zig").Servers;
const sequencer_clients = @import("batcher_sequencers.zig");
const shadow_mode = @import("batcher_shadow.zig");

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
    \\         base/base names: --l1-rpc-url --poll-interval S --data-availability-type
    \\         --max-blobs-per-tx N --resubmission-timeout S --max-calldata-size-bytes N
    \\         --network-timeout S (0 disables) --compressed-size-target B
    \\         --brotli-quality 0-11 --publish-max-retries N --publish-retry-delay D
    \\         --throttle-{start,full}-threshold B --throttle-{block,tx}-size-{lower,upper}-limit B
    \\         [--no-force-blobs-when-throttling]
    \\         [--shadow.enabled --shadow.inbox ADDR --shadow.validator-rollup-rpc URL
    \\          --shadow.validator-l2-rpc URL (requires --no-throttle)]
    \\         [--sequencer-urls URL|L2_URL=ROLLUP_URL,... (instead of --l2/--rollup-rpc)]
    \\         [--sub-safety-margin L1_BLOCKS] [--wait-node-sync [--check-recent-txs-depth N]
    \\         [--wait-node-sync-timeout SECONDS]]
    \\
;

const Flags = struct {
    rollup_config: ?[]const u8 = null,
    l1: ?[]const u8 = null,
    l2: ?[]const u8 = null,
    rollup_rpc: ?[]const u8 = null,
    /// Comma-separated sequencer endpoints (`URL` or `L2_URL=ROLLUP_URL`); replaces
    /// `--l2`/`--rollup-rpc` (base/base `--sequencer-urls`).
    sequencer_urls: ?[]const u8 = null,
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
    /// DA throttling (base/base defaults); `--throttle-*` flags override fields.
    throttle: batcher.throttle.Config = .{},
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
    /// Frames (blobs) per blob transaction, 1..6 (base/base `--max-blobs-per-tx`).
    blobs_per_tx: u8 = 6,
    /// Same-nonce resubmission timeout (base/base `--resubmission-timeout`, seconds).
    resubmit_after_ms: u64 = 12_000,
    /// Calldata payload limit incl. the version byte (`--max-calldata-size-bytes`).
    calldata_bytes_max: u32 = tx_data_bytes_max,
    /// Calldata mode: send blobs while DA throttling is active (base/base default on;
    /// `--no-force-blobs-when-throttling` turns it off).
    force_blobs_when_throttling: bool = true,
    /// Per-request RPC timeout (base/base `--network-timeout`, seconds); 0 disables it.
    network_timeout_ms: u64 = 10 * std.time.ms_per_s,
    /// Compressed bytes a channel aims for before it closes; 0 = one full frame.
    compressed_size_target: u32 = 0,
    brotli_quality: u4 = batcher.comp.brotli.quality_default,
    shadow: shadow_mode.Settings = .{},
    publish_max_retries: u8 = 10,
    publish_retry_delay_ms: u64 = 1_000,
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
        if (try apply_alias(&flags, arg, value)) {
            i += 2;
            continue;
        }
        if (eql(u8, arg, "--rollup-config")) {
            flags.rollup_config = value;
        } else if (eql(u8, arg, "--l1")) {
            flags.l1 = value;
        } else if (eql(u8, arg, "--l2")) {
            flags.l2 = value;
        } else if (eql(u8, arg, "--rollup-rpc")) {
            flags.rollup_rpc = value;
        } else if (eql(u8, arg, "--sequencer-urls")) {
            flags.sequencer_urls = value;
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
        } else if (eql(u8, arg, "--admin-port")) {
            flags.admin_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--admin-addr")) {
            flags.admin_address = try base.utilities.io.Address.parse(value);
        } else if (eql(u8, arg, "--throttle-strategy")) {
            flags.throttle.strategy = std.meta.stringToEnum(batcher.throttle.Strategy, value) orelse
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
    var entries: [batcher.sequencers.sequencers_max]sequencer_clients.Entry = undefined;
    const entry_count = if (flags.sequencer_urls) |text|
        try sequencer_clients.parse_entries(text, &entries)
    else blk: {
        entries[0] = .{ .l2 = flags.l2 orelse return usage_error(), .rollup = flags.rollup_rpc };
        break :blk 1;
    };
    const rollup_text = try Io.Dir.cwd().readFileAlloc(
        init.io,
        rollup_path,
        init.gpa,
        .limited(1 << 20),
    );
    defer init.gpa.free(rollup_text);
    const rollup = try batcher.service.RollupFields.parse(init.gpa, rollup_text);
    try shadow_mode.check_inbox(flags.shadow, rollup.batch_inbox_address.bytes);
    const accounts = batcher.devnet.accounts;
    const account = flags.private_key orelse accounts.derive_dev(flags.key_index).private_key;
    var seed: [16]u8 = undefined;
    init.io.random(&seed);
    const config = service_config(flags, rollup, account);
    var service = try batcher.service.Service.init(init.gpa, config, seed);
    defer service.deinit(init.gpa);
    return run(init, flags, &service, l1_url, entries[0..entry_count]);
}

fn service_config(
    flags: Flags,
    rollup: batcher.service.RollupFields,
    account: [32]u8,
) batcher.service.Config {
    // One frame per transaction payload: the payload is `version byte ++ frame`.
    const payload_max: u32 = switch (flags.data_availability) {
        .calldata => flags.calldata_bytes_max,
        .blobs => batcher.blobs.blob_data_length_max,
    };
    // Forcing blobs needs the KZG prover in calldata mode; skip it when it cannot apply.
    const force_blobs = flags.force_blobs_when_throttling and
        flags.data_availability == .calldata and flags.throttle.strategy != .off;
    return .{
        .channels = .{
            .channel = .{
                .frame_size_max = payload_max - 1,
                .input_bytes_max = 4 << 20,
                .algorithm = flags.compression,
                .compressed_bytes_target = flags.compressed_size_target,
                .brotli_quality = flags.brotli_quality,
            },
            .max_channel_duration_l1_blocks = flags.max_channel_duration - flags.sub_safety_margin,
        },
        .txs = .{
            .chain_id = rollup.l1_chain_id,
            .private_key = account,
            .from = batcher.devnet.accounts.address_of(account),
            .to = rollup.batch_inbox_address,
            .tx_data_bytes_max = payload_max,
            .data_availability = flags.data_availability,
            // op-batcher's blob default: up to 6 frames (blobs) per transaction.
            .blobs_per_tx = if (flags.data_availability == .blobs) flags.blobs_per_tx else 1,
            .resubmit_after_ms = flags.resubmit_after_ms,
            .publish_max_retries = flags.publish_max_retries,
            .publish_retry_delay_ms = flags.publish_retry_delay_ms,
            .blob_override = force_blobs,
            .slots_max = flags.pending_max,
            .confirmations = flags.confirmations,
            .min_tip_wei = flags.min_tip_wei,
            .min_base_fee_wei = flags.min_base_fee_wei,
        },
        // 30 L1 blocks without safe-head progress: resubmit from the safe head.
        .stall_l1_blocks = 30,
        .throttle = flags.throttle,
        .stopped = flags.stopped,
        .force_blobs_when_throttling = force_blobs,
    };
}

fn run(
    init: std.process.Init,
    flags: Flags,
    service: *batcher.service.Service,
    l1_url: []const u8,
    entries: []const sequencer_clients.Entry,
) !u8 {
    const limits: batcher.rpc.Limits = .{};
    var l1_http = HttpTransport.init(init.gpa, init.io, l1_url);
    defer l1_http.deinit();
    l1_http.timeout_ms = flags.network_timeout_ms;
    var l1 = try batcher.rpc.Client.init(init.gpa, l1_http.transport(), limits);
    defer l1.deinit(init.gpa);
    const endpoints = try init.gpa.create(sequencer_clients.SequencerClients);
    defer init.gpa.destroy(endpoints);
    try endpoints.init(init.gpa, init.io, entries, flags.network_timeout_ms);
    defer endpoints.deinit(init.gpa);
    var leader = endpoints.tracker();
    var active_count: u8 = 1;
    const shadow = if (flags.shadow.enabled) try start_shadow(init, flags) else null;
    defer if (shadow) |validator| stop_shadow(init.gpa, validator);
    std.debug.print("batcher: started on L1 chain {d}\n", .{service.txs.config.chain_id});
    if (flags.wait_node_sync) {
        const rollup = if (shadow) |validator| &validator.rollup else leader.current().rollup;
        try wait_for_node_sync(init, flags, &l1, rollup, service);
    }
    var metrics: batcher.metrics.Metrics = .{};
    try metrics.register();
    var admin: batcher.admin.Admin = .{ .service = service };
    var servers: Servers = undefined;
    const serving = start_servers(&servers, init.gpa, flags, &metrics, &admin);
    var throttle_logged: batcher.throttle.Outcome = .idle;
    var blobs_forced_logged = false;
    while (true) {
        const now_ms: u64 = @intCast(Io.Clock.awake.now(init.io).toMilliseconds());
        var clients = follow_leader(&leader, &l1, endpoints.has_rollup, service, &active_count);
        // A shadow batcher follows the parity validator's derivation, not the leader's.
        if (shadow) |validator| {
            clients.rollup = &validator.rollup;
            clients.unsafe_from_l2 = true;
        }
        if (service.step(clients, now_ms)) |report| {
            log_report(report);
            metrics.record(report, service.txs.pending_count());
            metrics.poll_balance(&l1, service.txs.config.from.bytes, now_ms);
            log_throttle(report.throttle, &throttle_logged);
            if (report.blobs_forced != blobs_forced_logged) {
                blobs_forced_logged = report.blobs_forced;
                const state = if (report.blobs_forced) "on (DA throttling)" else "off";
                std.debug.print("batcher: forcing blob transactions {s}\n", .{state});
            }
        } else |err| {
            metrics.step_failures.increment();
            std.debug.print("batcher: step failed: {t} {s}\n", .{ err, l1.last_error() });
        }
        if (shadow) |validator| validator.check(clients.l2);
        if (serving) {
            try servers.serve_for(flags.poll_interval_ms);
        } else {
            try init.io.sleep(.fromMilliseconds(@intCast(flags.poll_interval_ms)), .awake);
        }
    }
}

fn start_shadow(init: std.process.Init, flags: Flags) !*shadow_mode.Shadow {
    const shadow = try init.gpa.create(shadow_mode.Shadow);
    errdefer init.gpa.destroy(shadow);
    try shadow.init(init.gpa, init.io, flags.shadow, flags.network_timeout_ms);
    const inbox = &flags.shadow.inbox.?;
    std.debug.print("batcher: SHADOW MODE: posting to shadow inbox 0x{x}\n", .{inbox});
    return shadow;
}

fn stop_shadow(allocator: std.mem.Allocator, shadow: *shadow_mode.Shadow) void {
    shadow.deinit(allocator);
    allocator.destroy(shadow);
}

/// Re-checks which sequencer is active and returns the clients for this step. A new
/// leader gets the DA limits pushed again; with no active sequencer the leader is kept.
fn follow_leader(
    leader: *batcher.sequencers.Sequencers,
    l1: *batcher.rpc.Client,
    has_rollup: bool,
    service: *batcher.service.Service,
    last_active_count: *u8,
) batcher.service.Clients {
    const refresh = leader.refresh();
    const active_changed = refresh.active_count != last_active_count.*;
    last_active_count.* = refresh.active_count;
    if (refresh.leader_changed) {
        std.debug.print("batcher: sequencer leader is now #{d}\n", .{leader.leader});
        service.throttle.pushed = null;
    }
    // Logged on change only: the refresh runs every step.
    if (!active_changed) {} else if (refresh.active_count == 0) {
        std.debug.print("batcher: no sequencer is active; keeping #{d}\n", .{leader.leader});
    } else if (refresh.active_count > 1) {
        std.debug.print("batcher: {d} sequencers are active\n", .{refresh.active_count});
    }
    const endpoint = leader.current();
    return .{ .l1 = l1, .l2 = endpoint.l2, .rollup = if (has_rollup) endpoint.rollup else null };
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

/// base/base `BatcherArgs` names (`base-batcher` flags) for the same settings, so its
/// command lines work unchanged. Returns false for flags it does not know.
fn apply_alias(flags: *Flags, arg: []const u8, value: []const u8) !bool {
    if (try apply_txmgr_flag(flags, arg, value)) return true;
    if (try shadow_mode.apply_flag(&flags.shadow, arg, value)) return true;
    if (try apply_throttle_flag(flags, arg, value)) return true;
    return apply_alias_settings(flags, arg, value);
}

/// base/base throttle thresholds and limits (bytes); checked together in `validate_flags`.
fn apply_throttle_flag(flags: *Flags, arg: []const u8, value: []const u8) !bool {
    const names = [_][]const u8{
        "--throttle-start-threshold",        "--throttle-full-threshold",
        "--throttle-block-size-lower-limit", "--throttle-block-size-upper-limit",
        "--throttle-tx-size-lower-limit",    "--throttle-tx-size-upper-limit",
    };
    const config = &flags.throttle;
    const fields = [_]*u64{
        &config.start_threshold_bytes,  &config.full_threshold_bytes,
        &config.block_size_lower_limit, &config.block_size_upper_limit,
        &config.tx_size_lower_limit,    &config.tx_size_upper_limit,
    };
    comptime std.debug.assert(names.len == fields.len);
    for (names, fields) |name, field| {
        if (std.mem.eql(u8, arg, name)) {
            field.* = try std.fmt.parseInt(u64, value, 10);
            return true;
        }
    }
    return false;
}

/// base/base tx manager flags.
fn apply_txmgr_flag(flags: *Flags, arg: []const u8, value: []const u8) !bool {
    const eql = std.mem.eql;
    if (eql(u8, arg, "--num-confirmations")) {
        flags.confirmations = try std.fmt.parseInt(u64, value, 10);
        if (flags.confirmations == 0) return error.InvalidConfirmations;
    } else if (eql(u8, arg, "--min-tip-cap")) {
        flags.min_tip_wei = try parse_gwei(value);
    } else if (eql(u8, arg, "--min-basefee")) {
        flags.min_base_fee_wei = try parse_gwei(value);
    } else if (eql(u8, arg, "--max-pending-transactions")) {
        flags.pending_max = try std.fmt.parseInt(u8, value, 10);
        if (flags.pending_max == 0) return error.InvalidPendingMax;
    } else return false;
    return true;
}

fn apply_alias_settings(flags: *Flags, arg: []const u8, value: []const u8) !bool {
    const eql = std.mem.eql;
    const parse = std.fmt.parseInt;
    if (eql(u8, arg, "--l1-rpc-url")) {
        flags.l1 = value;
    } else if (eql(u8, arg, "--poll-interval")) {
        const seconds = try parse(u64, value, 10);
        if (seconds == 0 or seconds > 3600) return error.InvalidPollInterval;
        flags.poll_interval_ms = seconds * std.time.ms_per_s;
    } else if (eql(u8, arg, "--network-timeout")) {
        const seconds = try parse(u64, value, 10);
        if (seconds > 3600) return error.InvalidNetworkTimeout;
        flags.network_timeout_ms = seconds * std.time.ms_per_s;
    } else if (eql(u8, arg, "--data-availability-type")) {
        const blobs = eql(u8, value, "blobs") or eql(u8, value, "blob");
        if (!blobs and !eql(u8, value, "calldata")) return error.UnknownDataAvailability;
        flags.data_availability = if (blobs) .blobs else .calldata;
    } else if (eql(u8, arg, "--max-blobs-per-tx")) {
        flags.blobs_per_tx = try parse(u8, value, 10);
        if (flags.blobs_per_tx == 0 or flags.blobs_per_tx > 6) return error.InvalidBlobsPerTx;
    } else if (eql(u8, arg, "--resubmission-timeout")) {
        const seconds = try parse(u64, value, 10);
        if (seconds == 0 or seconds > 3600) return error.InvalidResubmissionTimeout;
        flags.resubmit_after_ms = seconds * std.time.ms_per_s;
    } else if (eql(u8, arg, "--publish-max-retries")) {
        flags.publish_max_retries = try parse(u8, value, 10);
    } else if (eql(u8, arg, "--publish-retry-delay")) {
        flags.publish_retry_delay_ms = try parse_duration_ms(value);
    } else if (eql(u8, arg, "--brotli-quality")) {
        const quality = try parse(u8, value, 10);
        if (quality > batcher.comp.brotli.quality_max) return error.InvalidBrotliQuality;
        flags.brotli_quality = @intCast(quality);
    } else if (eql(u8, arg, "--compressed-size-target")) {
        flags.compressed_size_target = try parse(u32, value, 10);
        if (flags.compressed_size_target == 0) return error.InvalidCompressedSizeTarget;
    } else if (eql(u8, arg, "--max-calldata-size-bytes")) {
        flags.calldata_bytes_max = try parse(u32, value, 10);
        // Room for the version byte and a frame header plus data; at most the tx cap.
        const valid = flags.calldata_bytes_max >= 64 and
            flags.calldata_bytes_max <= tx_data_bytes_max;
        if (!valid) return error.InvalidCalldataSize;
    } else return false;
    return true;
}

/// Valueless flags; returns false for flags that take a value.
fn parse_switch(flags: *Flags, arg: []const u8) bool {
    const eql = std.mem.eql;
    if (eql(u8, arg, "--stopped")) {
        flags.stopped = true;
    } else if (eql(u8, arg, "--wait-node-sync")) {
        flags.wait_node_sync = true;
    } else if (eql(u8, arg, "--shadow.enabled")) {
        flags.shadow.enabled = true;
    } else if (eql(u8, arg, "--no-force-blobs-when-throttling")) {
        flags.force_blobs_when_throttling = false;
    } else if (eql(u8, arg, "--no-throttle")) {
        flags.throttle.strategy = .off;
    } else return false;
    return true;
}

/// Cross-flag checks (base/base config validation).
fn validate_flags(flags: Flags) !void {
    // base/base rejects a margin that leaves no channel duration.
    if (flags.sub_safety_margin >= flags.max_channel_duration) return error.SubSafetyMarginTooLarge;
    if (flags.throttle.problem() != null) return error.InvalidThrottleConfig;
    try shadow_mode.validate(flags.shadow, flags.throttle.strategy == .off);
    const recent_depth_max = batcher.sync.recent_txs_depth_max;
    if (flags.check_recent_txs_depth > recent_depth_max) return error.RecentTxsDepthTooLarge;
    if (flags.check_recent_txs_depth > 0 and !flags.wait_node_sync)
        return error.RecentTxsDepthRequiresWaitNodeSync;
    // Node sync is read from the rollup node: required, not optional, with the flag.
    if (flags.sequencer_urls != null and (flags.l2 != null or flags.rollup_rpc != null))
        return error.SequencerUrlsReplaceL2;
    if (flags.wait_node_sync and flags.rollup_rpc == null and flags.sequencer_urls == null)
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
    try std.testing.expectEqual(.quadratic, (try parse_flags(&zlib)).throttle.strategy);
    const no_throttle = [_][]const u8{ "--no-throttle", "--compression", "zlib", "--no-throttle" };
    const switched = try parse_flags(&no_throttle);
    try std.testing.expectEqual(.off, switched.throttle.strategy);
    try std.testing.expectEqual(.zlib, switched.compression);
    const linear = [_][]const u8{ "--throttle-strategy", "linear" };
    try std.testing.expectEqual(.linear, (try parse_flags(&linear)).throttle.strategy);
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
    const both = [_][]const u8{ "--l2", "http://a:1", "--sequencer-urls", "http://b:2" };
    try std.testing.expectError(error.SequencerUrlsReplaceL2, parse_flags(&both));
    const urls = [_][]const u8{ "--sequencer-urls", "http://b:2", "--wait-node-sync" };
    try std.testing.expect((try parse_flags(&urls)).wait_node_sync);
    const aliases = [_][]const u8{
        "--l1-rpc-url",             "http://l1:1", "--poll-interval",           "3",
        "--data-availability-type", "blob",        "--max-blobs-per-tx",        "2",
        "--resubmission-timeout",   "48",          "--max-calldata-size-bytes", "1000",
    };
    const alias_flags = try parse_flags(&aliases);
    try std.testing.expectEqualStrings("http://l1:1", alias_flags.l1.?);
    try std.testing.expectEqual(@as(u64, 3000), alias_flags.poll_interval_ms);
    try std.testing.expectEqual(.blobs, alias_flags.data_availability);
    try std.testing.expectEqual(@as(u8, 2), alias_flags.blobs_per_tx);
    try std.testing.expectEqual(@as(u64, 48_000), alias_flags.resubmit_after_ms);
    try std.testing.expectEqual(@as(u32, 1000), alias_flags.calldata_bytes_max);
    const bad_aliases = [_][2][]const u8{
        .{ "--poll-interval", "0" },          .{ "--max-blobs-per-tx", "7" },
        .{ "--data-availability-type", "x" }, .{ "--max-calldata-size-bytes", "10" },
        .{ "--resubmission-timeout", "0" },
    };
    for (bad_aliases) |pair| {
        try std.testing.expect(std.meta.isError(parse_flags(&pair)));
    }
    const throttle_args = [_][]const u8{
        "--throttle-start-threshold",     "1000", "--throttle-full-threshold",         "5000",
        "--throttle-tx-size-lower-limit", "100",  "--throttle-block-size-upper-limit", "90000",
    };
    const throttle_flags = try parse_flags(&throttle_args);
    try std.testing.expectEqual(@as(u64, 5000), throttle_flags.throttle.full_threshold_bytes);
    try std.testing.expectEqual(@as(u64, 100), throttle_flags.throttle.tx_size_lower_limit);
    try std.testing.expectEqual(@as(u64, 90000), throttle_flags.throttle.block_size_upper_limit);
    const inverted = [_][]const u8{ "--throttle-full-threshold", "1" };
    try std.testing.expectError(error.InvalidThrottleConfig, parse_flags(&inverted));
    try std.testing.expectEqual(@as(u64, 10_000), (try parse_flags(&.{})).network_timeout_ms);
    const size_target = [_][]const u8{ "--compressed-size-target", "4096" };
    const sized = try parse_flags(&size_target);
    try std.testing.expectEqual(@as(u32, 4096), sized.compressed_size_target);
    const retry = [_][]const u8{ "--publish-max-retries", "3", "--publish-retry-delay", "250ms" };
    const retry_flags = try parse_flags(&retry);
    try std.testing.expectEqual(@as(u8, 3), retry_flags.publish_max_retries);
    try std.testing.expectEqual(@as(u64, 250), retry_flags.publish_retry_delay_ms);
    const quality = [_][]const u8{ "--brotli-quality", "11" };
    try std.testing.expectEqual(@as(u4, 11), (try parse_flags(&quality)).brotli_quality);
    try std.testing.expectEqual(@as(u4, 9), (try parse_flags(&.{})).brotli_quality);
    const quality_big = [_][]const u8{ "--brotli-quality", "12" };
    try std.testing.expectError(error.InvalidBrotliQuality, parse_flags(&quality_big));
    const size_zero = [_][]const u8{ "--compressed-size-target", "0" };
    try std.testing.expectError(error.InvalidCompressedSizeTarget, parse_flags(&size_zero));
    const timeout_off = [_][]const u8{ "--network-timeout", "0" };
    try std.testing.expectEqual(@as(u64, 0), (try parse_flags(&timeout_off)).network_timeout_ms);
    const timeout_big = [_][]const u8{ "--network-timeout", "3601" };
    try std.testing.expectError(error.InvalidNetworkTimeout, parse_flags(&timeout_big));
    const no_force = [_][]const u8{"--no-force-blobs-when-throttling"};
    try std.testing.expect(!(try parse_flags(&no_force)).force_blobs_when_throttling);
    try std.testing.expect((try parse_flags(&.{})).force_blobs_when_throttling);
    const dangling = [_][]const u8{"--l1"};
    try std.testing.expectError(error.MissingValue, parse_flags(&dangling));
    const bad = [_][]const u8{ "--data-availability", "carrier-pigeon" };
    try std.testing.expectError(error.UnknownDataAvailability, parse_flags(&bad));
    try std.testing.expectError(error.MissingValue, parse_flags(&.{"--l1"}));
}

test {
    _ = sequencer_clients;
    _ = shadow_mode;
    _ = @import("http_transport.zig");
}

const fuzz_flag_names = [_][]const u8{
    "--poll-interval",
    "--max-blobs-per-tx",
    "--resubmission-timeout",
    "--max-calldata-size-bytes",
    "--data-availability-type",
    "--num-confirmations",
    "--max-pending-transactions",
    "--sub-safety-margin",
    "--max-channel-duration",
    "--check-recent-txs-depth",
    "--wait-node-sync",
    "--stopped",
    "--throttle-start-threshold",
    "--throttle-full-threshold",
    "--throttle-tx-size-lower-limit",
    "--no-force-blobs-when-throttling",
    "--network-timeout",
    "--compressed-size-target",
    "--brotli-quality",
    "--publish-max-retries",
    "--publish-retry-delay",
    "--shadow.enabled",
    "--shadow.inbox",
};
const fuzz_flag_values = [_][]const u8{ "0", "1", "6", "7", "64", "blobs", "calldata", "x", "" };

/// Parsed flags always satisfy the bounds the batcher relies on.
/// humantime-style duration for the forms base/base examples use: `500ms`, `2s`, `1m`,
/// or bare seconds. At most one hour.
fn parse_duration_ms(text: []const u8) !u64 {
    const units = [_]struct { suffix: []const u8, ms: u64 }{
        .{ .suffix = "ms", .ms = 1 },
        .{ .suffix = "s", .ms = std.time.ms_per_s },
        .{ .suffix = "m", .ms = std.time.ms_per_min },
    };
    var number = text;
    var unit_ms: u64 = std.time.ms_per_s;
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            number = text[0 .. text.len - unit.suffix.len];
            unit_ms = unit.ms;
            break;
        }
    }
    const value = std.fmt.parseInt(u64, number, 10) catch return error.InvalidDuration;
    const ms = std.math.mul(u64, value, unit_ms) catch return error.InvalidDuration;
    if (ms > std.time.ms_per_hour) return error.InvalidDuration;
    return ms;
}

test "batcher: parse_duration_ms forms and bounds" {
    try std.testing.expectEqual(@as(u64, 500), try parse_duration_ms("500ms"));
    try std.testing.expectEqual(@as(u64, 2000), try parse_duration_ms("2s"));
    try std.testing.expectEqual(@as(u64, 60_000), try parse_duration_ms("1m"));
    try std.testing.expectEqual(@as(u64, 3000), try parse_duration_ms("3"));
    for ([_][]const u8{ "", "s", "ms", "-1s", "2h", "61m", "1.5s", "99999999999999999999" }) |bad| {
        try std.testing.expectError(error.InvalidDuration, parse_duration_ms(bad));
    }
    var prng = base.testing.Prng.init(0xd0d0);
    var buffer: [12]u8 = undefined;
    const alphabet = "0123456789msh.";
    for (0..2000) |_| {
        const length = prng.range(0, buffer.len);
        for (buffer[0..length]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        const ms = parse_duration_ms(buffer[0..length]) catch continue;
        try std.testing.expect(ms <= std.time.ms_per_hour);
    }
}

test "batcher: fuzz parse_duration_ms" {
    try std.testing.fuzz({}, fuzz_duration, .{});
}

fn fuzz_duration(_: void, smith: *std.testing.Smith) anyerror!void {
    var buffer: [32]u8 = undefined;
    const ms = parse_duration_ms(buffer[0..smith.slice(&buffer)]) catch return;
    try std.testing.expect(ms <= std.time.ms_per_hour);
}

fn check_flag_invariants(flags: Flags) !void {
    try std.testing.expect(flags.blobs_per_tx >= 1 and flags.blobs_per_tx <= 6);
    try std.testing.expect(flags.poll_interval_ms > 0);
    try std.testing.expect(flags.brotli_quality <= batcher.comp.brotli.quality_max);
    try std.testing.expect(flags.network_timeout_ms <= 3600 * std.time.ms_per_s);
    try std.testing.expect(flags.resubmit_after_ms > 0);
    try std.testing.expect(flags.calldata_bytes_max >= 64);
    try std.testing.expect(flags.calldata_bytes_max <= tx_data_bytes_max);
    try std.testing.expect(flags.confirmations >= 1 and flags.pending_max >= 1);
    try std.testing.expect(flags.sub_safety_margin < flags.max_channel_duration);
    try std.testing.expect(flags.throttle.problem() == null);
}

fn fuzz_args(bytes: []const u8, args: *[16][]const u8) usize {
    var count: usize = 0;
    for (bytes) |byte| {
        if (count == args.len) break;
        args[count] = if (byte & 1 == 0)
            fuzz_flag_names[(byte >> 1) % fuzz_flag_names.len]
        else
            fuzz_flag_values[(byte >> 1) % fuzz_flag_values.len];
        count += 1;
    }
    return count;
}

test "batcher: seeded fuzz of flag parsing keeps invariants" {
    var prng = base.testing.Prng.init(0xf1a9);
    for (0..2000) |_| {
        var bytes: [16]u8 = undefined;
        prng.fill(&bytes);
        var args: [16][]const u8 = undefined;
        const count = fuzz_args(bytes[0..prng.range(0, 16)], &args);
        const flags = parse_flags(args[0..count]) catch continue;
        try check_flag_invariants(flags);
    }
}

test "batcher: fuzz flag parsing" {
    try std.testing.fuzz({}, fuzz_flags, .{});
}

fn fuzz_flags(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [16]u8 = undefined;
    const length = smith.slice(&bytes);
    var args: [16][]const u8 = undefined;
    const count = fuzz_args(bytes[0..length], &args);
    const flags = parse_flags(args[0..count]) catch return;
    try check_flag_invariants(flags);
}

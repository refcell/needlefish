//! `basectl doctor`: read-only health checks for one node (base/base `doctor.rs`), each
//! graded pass/warn/fail/info/skip; any fail makes the command exit non-zero.
//!
//! `gather` performs every read (two samples of the heads, `sample_interval_ms` apart, so a
//! stalled chain is caught) and `evaluate` grades the facts; it is pure, so every grading
//! path is unit tested without I/O. Checks cover endpoint reachability, chain ids against
//! the rollup config, heads advancing, safe/finalized lag, peer counts, and whether the
//! batcher and sequencer are active. base/base's public-tip, bootnode, reth.toml, and
//! external-reachability checks need config and services needlefish does not have.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");
const sync_status = @import("sync_status.zig");
const p2p = @import("p2p.zig");
const batcher = @import("batcher.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;
const Probe = types.Probe;
const probe = types.probe;
const decode_number = types.decode_number;
const decode_bool = types.decode_bool;
const SyncStatus = sync_status.SyncStatus;

pub const checks_max = 16;

/// Grading thresholds (base/base `DoctorThresholds` defaults where they exist).
pub const Thresholds = struct {
    peer_warn_below: u32 = 5,
    /// base/base fails at zero peers; a single-node devnet passes 0 here.
    peer_fail_below: u32 = 1,
    safe_lag_warn_blocks: u64 = 150,
    safe_lag_fail_blocks: u64 = 300,
    finalized_lag_warn_blocks: u64 = 2_000,
    finalized_lag_fail_blocks: u64 = 7_200,
};

pub const ChainIds = struct {
    l1_chain_id: u64,
    l2_chain_id: u64,
};

/// One reading of the heads.
pub const Sample = struct {
    l1_head: Probe(u64),
    l2_head: Probe(u64),
    sync: Probe(SyncStatus),
};

pub const Facts = struct {
    l1_chain_id: Probe(u64),
    l2_chain_id: Probe(u64),
    rollup_config: Probe(ChainIds),
    first: Sample,
    second: Sample,
    cl_peers: Probe(p2p.PeerStats),
    el_peers: Probe(u64),
    batcher: Probe(batcher.Status),
    sequencer_active: Probe(bool),
    is_leader: Probe(bool),
};

pub const Status = enum {
    pass,
    warn,
    fail,
    info,
    skip,

    pub fn label(status: Status) []const u8 {
        return switch (status) {
            .pass => "PASS",
            .warn => "WARN",
            .fail => "FAIL",
            .info => "INFO",
            .skip => "SKIP",
        };
    }
};

pub const Check = struct {
    name: []const u8,
    status: Status,
    message: types.Text(160),
};

pub const Summary = struct {
    pass: u32 = 0,
    warn: u32 = 0,
    fail: u32 = 0,
    info: u32 = 0,
    skip: u32 = 0,
};

pub const Report = struct {
    network: []const u8,
    summary: Summary = .{},
    checks: types.List(Check, checks_max) = .{},

    pub fn has_failures(report: *const Report) bool {
        return report.summary.fail > 0;
    }

    fn add(
        report: *Report,
        name: []const u8,
        status: Status,
        comptime format: []const u8,
        args: anytype,
    ) void {
        assert(name.len > 0);
        var check: Check = .{ .name = name, .status = status, .message = .{} };
        var writer: Writer = .fixed(&check.message.bytes);
        writer.print(format, args) catch {}; // A long message is truncated, not an error.
        check.message.length = @intCast(writer.buffered().len);
        // Proof: `evaluate` adds a fixed set of fewer than `checks_max` checks.
        assert(report.checks.push(check));
        switch (status) {
            inline else => |tag| @field(report.summary, @tagName(tag)) += 1,
        }
    }
};

/// Pauses between the two head samples (the binary sleeps; tests return at once).
pub const Sleeper = struct {
    context: *anyopaque,
    sleep_fn: *const fn (context: *anyopaque, duration_ms: u64) void,
};

pub fn decode_chain_ids(value: json.Value) DecodeError!ChainIds {
    const ids: ChainIds = .{
        .l1_chain_id = try rpc.number(try rpc.field(value, "l1_chain_id")),
        .l2_chain_id = try rpc.number(try rpc.field(value, "l2_chain_id")),
    };
    assert(value == .object);
    return ids;
}

fn take_sample(context: *const types.Context) Sample {
    const l1 = context.l1.client;
    const l2 = context.l2.client;
    const sample: Sample = .{
        .l1_head = types.probe(u64, l1, "eth_blockNumber", "[]", types.decode_number),
        .l2_head = types.probe(u64, l2, "eth_blockNumber", "[]", types.decode_number),
        .sync = types.probe(
            SyncStatus,
            context.rollup.client,
            "optimism_syncStatus",
            "[]",
            sync_status.decode_sync_status,
        ),
    };
    assert(sample.l1_head != .failed or sample.l1_head.failed != .not_configured or l1 == null);
    return sample;
}

pub fn gather(context: *const types.Context, sample_interval_ms: u64, sleeper: Sleeper) Facts {
    assert(sample_interval_ms <= 60_000);
    const rollup = context.rollup.client;
    const l1 = context.l1.client;
    const l2 = context.l2.client;
    const first = take_sample(context);
    const l1_chain_id = probe(u64, l1, "eth_chainId", "[]", decode_number);
    const l2_chain_id = probe(u64, l2, "eth_chainId", "[]", decode_number);
    const rollup_config = probe(ChainIds, rollup, "optimism_rollupConfig", "[]", decode_chain_ids);
    const cl_peers = probe(p2p.PeerStats, rollup, "opp2p_peerStats", "[]", p2p.decode_peer_stats);
    const el_peers = probe(u64, l2, "net_peerCount", "[]", decode_number);
    const batcher_status = probe(
        batcher.Status,
        context.batcher.client,
        "admin_getBatcherStatus",
        "[]",
        batcher.decode_status,
    );
    const sequencer_active = probe(bool, rollup, "admin_sequencerActive", "[]", decode_bool);
    const conductor = context.conductor.client;
    const is_leader = probe(bool, conductor, "conductor_leader", "[]", decode_bool);
    sleeper.sleep_fn(sleeper.context, sample_interval_ms);
    return .{
        .l1_chain_id = l1_chain_id,
        .l2_chain_id = l2_chain_id,
        .rollup_config = rollup_config,
        .first = first,
        .second = take_sample(context),
        .cl_peers = cl_peers,
        .el_peers = el_peers,
        .batcher = batcher_status,
        .sequencer_active = sequencer_active,
        .is_leader = is_leader,
    };
}

pub fn evaluate(facts: *const Facts, thresholds: Thresholds, network: []const u8) Report {
    assert(thresholds.safe_lag_warn_blocks <= thresholds.safe_lag_fail_blocks);
    assert(thresholds.finalized_lag_warn_blocks <= thresholds.finalized_lag_fail_blocks);
    var report: Report = .{ .network = network };
    check_reachable(&report, "l1_rpc", facts.l1_chain_id);
    check_reachable(&report, "l2_rpc", facts.l2_chain_id);
    check_reachable(&report, "rollup_rpc", facts.second.sync);
    check_chain_id(&report, "l1_chain_id", facts.l1_chain_id, facts.rollup_config, .l1);
    check_chain_id(&report, "l2_chain_id", facts.l2_chain_id, facts.rollup_config, .l2);
    check_advancing(&report, "l1_head_advancing", facts.first.l1_head, facts.second.l1_head, .warn);
    check_advancing(&report, "l2_head_advancing", facts.first.l2_head, facts.second.l2_head, .fail);
    const unsafe_first = unsafe_of(facts.first);
    const unsafe_second = unsafe_of(facts.second);
    check_advancing(&report, "unsafe_head_advancing", unsafe_first, unsafe_second, .fail);
    check_lag(&report, "safe_head_recency", facts.second.sync, .safe, thresholds);
    check_lag(&report, "finalized_head_recency", facts.second.sync, .finalized, thresholds);
    const cl_peers: Probe(u64) = switch (facts.cl_peers) {
        .ok => |stats| .{ .ok = stats.connected },
        .failed => |failure| .{ .failed = failure },
    };
    check_peers(&report, "cl_peer_count", cl_peers, thresholds);
    check_peers(&report, "el_peer_count", facts.el_peers, thresholds);
    check_batcher(&report, facts.batcher);
    check_sequencer(&report, facts.sequencer_active, facts.is_leader);
    assert(report.checks.count <= checks_max);
    return report;
}

fn unsafe_of(sample: Sample) Probe(u64) {
    return switch (sample.sync) {
        .ok => |status| .{ .ok = status.unsafe_l2.number },
        .failed => |failure| .{ .failed = failure },
    };
}

/// A read that failed only because the method is missing or no endpoint was given is
/// skipped; any other failure is graded with `status`.
fn skip_or(report: *Report, name: []const u8, failure: types.Failure, status: Status) void {
    const skipped = failure == .not_configured or failure == .unavailable;
    report.add(name, if (skipped) .skip else status, "{s}", .{failure.text()});
}

fn check_reachable(report: *Report, name: []const u8, probe_value: anytype) void {
    switch (probe_value) {
        .failed => |failure| {
            const status: Status = if (failure == .not_configured) .skip else .fail;
            report.add(name, status, "{s}", .{failure.text()});
        },
        .ok => report.add(name, .pass, "reachable", .{}),
    }
}

const Layer = enum { l1, l2 };

fn check_chain_id(
    report: *Report,
    name: []const u8,
    actual: Probe(u64),
    config: Probe(ChainIds),
    layer: Layer,
) void {
    const chain_id = switch (actual) {
        .ok => |id| id,
        // An unreachable endpoint already failed its reachability check.
        .failed => |failure| return report.add(name, .skip, "{s}", .{failure.text()}),
    };
    const ids = switch (config) {
        .ok => |ids| ids,
        .failed => |failure| return report.add(name, .skip, "rollup config {s} (chain id {d})", .{
            failure.text(),
            chain_id,
        }),
    };
    const expected = if (layer == .l1) ids.l1_chain_id else ids.l2_chain_id;
    if (expected == chain_id) {
        report.add(name, .pass, "chain id {d} matches the rollup config", .{chain_id});
    } else {
        report.add(name, .fail, "chain id {d}, rollup config expects {d}", .{ chain_id, expected });
    }
}

fn check_advancing(
    report: *Report,
    name: []const u8,
    first: Probe(u64),
    second: Probe(u64),
    stalled: Status,
) void {
    assert(stalled == .warn or stalled == .fail);
    const before = switch (first) {
        .ok => |head| head,
        .failed => |failure| return skip_or(report, name, failure, .skip),
    };
    const after = switch (second) {
        .ok => |head| head,
        .failed => |failure| return skip_or(report, name, failure, stalled),
    };
    if (after > before) {
        report.add(name, .pass, "advanced {d} -> {d}", .{ before, after });
    } else if (after == before) {
        report.add(name, stalled, "stalled at {d} between samples", .{before});
    } else {
        report.add(name, .warn, "went backwards {d} -> {d} (reorg?)", .{ before, after });
    }
}

const Head = enum { safe, finalized };

fn check_lag(
    report: *Report,
    name: []const u8,
    sync: Probe(SyncStatus),
    head: Head,
    thresholds: Thresholds,
) void {
    const status = switch (sync) {
        .ok => |status| status,
        .failed => |failure| return skip_or(report, name, failure, .skip),
    };
    const lag = if (head == .safe) status.safe_lag_blocks() else status.finalized_lag_blocks();
    const safe = head == .safe;
    const warn_at = if (safe)
        thresholds.safe_lag_warn_blocks
    else
        thresholds.finalized_lag_warn_blocks;
    const fail_at = if (safe)
        thresholds.safe_lag_fail_blocks
    else
        thresholds.finalized_lag_fail_blocks;
    assert(warn_at <= fail_at);
    const grade: Status = if (lag > fail_at) .fail else if (lag > warn_at) .warn else .pass;
    report.add(name, grade, "{d} blocks behind unsafe (warn > {d}, fail > {d})", .{
        lag,
        warn_at,
        fail_at,
    });
}

fn check_peers(report: *Report, name: []const u8, count: Probe(u64), thresholds: Thresholds) void {
    const peers = switch (count) {
        .ok => |peers| peers,
        .failed => |failure| return skip_or(report, name, failure, .warn),
    };
    const grade: Status = if (peers < thresholds.peer_fail_below)
        .fail
    else if (peers < thresholds.peer_warn_below)
        .warn
    else
        .pass;
    report.add(name, grade, "{d} connected (warn below {d})", .{
        peers,
        thresholds.peer_warn_below,
    });
}

fn check_batcher(report: *Report, probe_value: Probe(batcher.Status)) void {
    const status = switch (probe_value) {
        .ok => |status| status,
        .failed => |failure| return skip_or(report, "batcher_active", failure, .fail),
    };
    if (status.stopped) {
        return report.add("batcher_active", .fail, "batch submission is stopped", .{});
    }
    report.add("batcher_active", .pass, "running, {d} in flight, {d} backlog bytes", .{
        status.in_flight,
        status.da_backlog_bytes,
    });
}

fn check_sequencer(report: *Report, active: Probe(bool), is_leader: Probe(bool)) void {
    const sequencing = switch (active) {
        .ok => |sequencing| sequencing,
        .failed => |failure| return skip_or(report, "sequencer_active", failure, .warn),
    };
    const leader = is_leader.get();
    if (sequencing) {
        if (leader == false) {
            const message = "sequencing but not the conductor leader";
            return report.add("sequencer_active", .fail, message, .{});
        }
        return report.add("sequencer_active", .pass, "sequencing", .{});
    }
    if (leader == true) {
        return report.add("sequencer_active", .fail, "conductor leader but not sequencing", .{});
    }
    report.add("sequencer_active", .info, "not sequencing (verifier or follower)", .{});
}

pub fn render(report: *const Report, writer: *Writer) !void {
    const summary = report.summary;
    assert(summary.pass + summary.warn + summary.fail + summary.info + summary.skip ==
        report.checks.count);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "summary", "{d} pass, {d} warn, {d} fail, {d} info, {d} skip", .{
        summary.pass, summary.warn, summary.fail, summary.info, summary.skip,
    });
    for (report.checks.slice()) |*check| {
        try writer.print("\n{s} {s}\n  message: {s}\n", .{
            check.status.label(),
            check.name,
            check.message.slice(),
        });
    }
}

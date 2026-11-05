//! The proposer's health, readiness and metrics (base/base `crates/proof/proposer` health
//! server and metrics) over `proof.telemetry`: the pipeline and collector counters as
//! `base_proposer_*_total`, ready while ticks make progress (are not skipped).

const std = @import("std");
const assert = std.debug.assert;

const telemetry = @import("../telemetry/root.zig");
const pipeline_module = @import("pipeline.zig");
const collector_module = @import("collector.zig");

pub const Stats = struct {
    ticks: u64 = 0,
    ticks_skipped: u64 = 0,
    restarts: u64 = 0,
    proofs_ready: u64 = 0,
    proofs_failed: u64 = 0,
    root_mismatches: u64 = 0,
    games_created: u64 = 0,
    games_adopted: u64 = 0,
    submit_failures: u64 = 0,

    pub const descriptions = .{
        .ticks = "Pipeline ticks.",
        .ticks_skipped = "Ticks skipped (chain or prover unavailable).",
        .restarts = "Pipeline restarts from fresh on-chain state.",
        .proofs_ready = "Proofs the prover finished.",
        .proofs_failed = "Proofs the prover failed.",
        .root_mismatches = "Proofs whose root differed from the chain.",
        .games_created = "Dispute games this proposer created.",
        .games_adopted = "Games found already created by someone else.",
        .submit_failures = "Game creations that failed or were dropped.",
    };
};

pub const Exporter = telemetry.Exporter(Stats, "base_proposer");

/// Copies the pipeline's counters after a tick; ticks that were not skipped are progress.
pub fn observe(
    exporter: *Exporter,
    pipeline: pipeline_module.Pipeline.Stats,
    collector: collector_module.Collector.Stats,
) void {
    assert(pipeline.skipped <= pipeline.ticks);
    exporter.observe(.{
        .ticks = pipeline.ticks,
        .ticks_skipped = pipeline.skipped,
        .restarts = pipeline.restarts,
        .proofs_ready = collector.proofs_ready,
        .proofs_failed = collector.proofs_failed,
        .root_mismatches = collector.root_mismatches,
        .games_created = collector.games_created,
        .games_adopted = collector.games_adopted,
        .submit_failures = collector.submit_failures,
    }, pipeline.ticks - pipeline.skipped);
    assert(exporter.counter("ticks") == pipeline.ticks);
}

const testing = std.testing;

test "proposer exporter: pipeline counters and readiness" {
    var fake: telemetry.FakeClock = .{ .now_ns = 50 * std.time.ns_per_s };
    var exporter: Exporter = undefined;
    try exporter.init(fake.clock(), .{ .version = "v", .poll_interval_ns = std.time.ns_per_s });
    var buffer: [8192]u8 = undefined;
    // A skipped tick is not progress.
    observe(&exporter, .{ .ticks = 1, .skipped = 1 }, .{});
    try testing.expectEqual(@as(u16, 503), telemetry.get(&exporter, &buffer, "/readyz").status);
    observe(&exporter, .{ .ticks = 2, .skipped = 1 }, .{ .proofs_ready = 1, .games_created = 1 });
    try testing.expectEqual(@as(u16, 200), telemetry.get(&exporter, &buffer, "/readyz").status);
    var response = telemetry.get(&exporter, &buffer, "/metrics");
    try testing.expect(telemetry.contains(&response, "base_proposer_ticks_total 2"));
    try testing.expect(telemetry.contains(&response, "base_proposer_ticks_skipped_total 1"));
    try testing.expect(telemetry.contains(&response, "base_proposer_games_created_total 1"));
}

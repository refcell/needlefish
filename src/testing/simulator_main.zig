//! Deterministic simulator entry point (DST).
//!
//! Usage: zig build sim -- [seed]
//!
//! Runs the cluster (L1, sequencer, batcher, verifiers) on simulated time and network
//! with fault injection, driven by one seed. Same seed, same run. Exits non-zero on
//! any safety or liveness violation; the printed seed reproduces it exactly.

const std = @import("std");
const base = @import("base");
const sim = base.testing.sim;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const seed: u64 = if (args.len > 1)
        try std.fmt.parseInt(u64, args[1], 10)
    else
        @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(init.io, .real).nanoseconds)));

    var prng = base.testing.Prng.init(seed);
    const config = sim.cluster.Config.random(&prng);
    std.debug.print(
        "simulator: seed={d} verifiers={d} latency={d}..{d}ms drop={d}ppm dup={d}ppm " ++
            "crashes/min={d} partitions/min={d} disk_fault={d}ppm\n",
        .{
            seed,
            config.verifier_count,
            config.network.latency_ns_min / std.time.ns_per_ms,
            config.network.latency_ns_max / std.time.ns_per_ms,
            config.network.drop_ppm,
            config.network.duplicate_ppm,
            config.crashes_per_minute,
            config.partitions_per_minute,
            config.disk_fault_ppm,
        },
    );
    var cluster = try sim.Cluster.init(init.gpa, seed, config);
    defer cluster.deinit(init.gpa);
    const report = cluster.run() catch |err| {
        std.debug.print("simulator: FAIL seed={d} error={s}\n", .{ seed, @errorName(err) });
        std.process.exit(1);
    };
    std.debug.print(
        "simulator: ok seed={d} steps={d} l2_head={d} l1_head={d} crashes={d} " ++
            "partitions={d} disk_faults={d} sent={d} delivered={d} dropped={d}\n",
        .{
            seed,                     report.steps,
            report.sequencer_head,    report.l1_head,
            report.crashes,           report.partitions,
            report.disk_faults,       report.network.sent,
            report.network.delivered,
            report.network.dropped_random + report.network.dropped_partition +
                report.network.dropped_full,
        },
    );
}

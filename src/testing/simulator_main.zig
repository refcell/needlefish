//! Deterministic simulator entry point (DST).
//!
//! Usage:
//!   zig build sim -- [seed]              run one seed (random seed if omitted)
//!   zig build sim -- swarm FIRST COUNT   run seeds FIRST..FIRST+COUNT-1 in-process
//!   zig build sim -- minimize SEED       shrink a failing seed's config
//!   zig build sim -- regression SEED     print SEED's config as a regression entry
//!
//! Runs the cluster (L1, sequencer, batcher, verifiers) on simulated time and network
//! with fault injection, driven by one seed. Same seed, same run. Exits non-zero on
//! any safety or liveness violation; the printed seed reproduces it exactly.

const std = @import("std");
const base = @import("base");
const sim = base.testing.sim;
const Config = sim.cluster.Config;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len >= 4 and std.mem.eql(u8, args[1], "swarm")) {
        const first = try std.fmt.parseInt(u64, args[2], 10);
        const count = try std.fmt.parseInt(u64, args[3], 10);
        const result = try sim.swarm.run_range(init.gpa, first, count);
        std.debug.print("swarm: {d} passed, {d} failed\n", .{ result.passed, result.failed });
        if (result.failed > 0) std.process.exit(1);
        return;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "regression")) {
        const seed = try std.fmt.parseInt(u64, args[2], 10);
        sim.swarm.print_regression(seed, sim.swarm.config_for_seed(seed));
        return;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "minimize")) {
        const seed = try std.fmt.parseInt(u64, args[2], 10);
        const config = sim.swarm.config_for_seed(seed);
        if (try sim.swarm.run_config(init.gpa, seed, config) == .ok) {
            std.debug.print("minimize: seed={d} passes, nothing to minimize\n", .{seed});
            return;
        }
        const minimized = try sim.swarm.minimize(init.gpa, seed, config);
        std.debug.print("minimize: seed={d}\n", .{seed});
        print_config(minimized);
        std.debug.print("regression entry for src/testing/sim/swarm.zig:\n", .{});
        sim.swarm.print_regression(seed, minimized);
        return;
    }
    const seed: u64 = if (args.len > 1)
        try std.fmt.parseInt(u64, args[1], 10)
    else
        @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(init.io, .real).nanoseconds)));
    try run_one(init.gpa, seed);
}

fn run_one(allocator: std.mem.Allocator, seed: u64) !void {
    const config = sim.swarm.config_for_seed(seed);
    std.debug.print("simulator: seed={d}\n", .{seed});
    print_config(config);
    var cluster = try sim.Cluster.init(allocator, seed, config);
    defer cluster.deinit(allocator);
    const report = cluster.run() catch |err| {
        std.debug.print("simulator: FAIL seed={d} error={s}\n", .{ seed, @errorName(err) });
        std.process.exit(1);
    };
    const n = report.network;
    const dropped = n.dropped_random + n.dropped_partition + n.dropped_full;
    std.debug.print(
        "simulator: ok seed={d} steps={d} l2_head={d} l1_head={d}\n",
        .{ seed, report.steps, report.sequencer_head, report.l1_head },
    );
    std.debug.print(
        "  crashes={d} partitions={d} (one-way {d}) disk_faults={d} l1_reorgs={d} spam={d} " ++
            "sent={d} delivered={d} dropped={d}\n",
        .{
            report.crashes,     report.partitions, report.asymmetric_partitions,
            report.disk_faults, report.l1_reorgs,  report.spam,
            n.sent,             n.delivered,       dropped,
        },
    );
}

fn print_config(config: Config) void {
    const ms = std.time.ns_per_ms;
    std.debug.print(
        "  verifiers={d} latency={d}..{d}ms drop={d}ppm dup={d}ppm crashes/min={d} " ++
            "partitions/min={d} disk_fault={d}ppm downtime_max={d}ms fault_end={d}ms " ++
            "clock_skew_max={d}ms l1_reorgs/min={d} spam/min={d}\n",
        .{
            config.verifier_count,
            config.network.latency_ns_min / ms,
            config.network.latency_ns_max / ms,
            config.network.drop_ppm,
            config.network.duplicate_ppm,
            config.crashes_per_minute,
            config.partitions_per_minute,
            config.disk_fault_ppm,
            config.downtime_ns_max / ms,
            config.fault_end_ns / ms,
            config.clock_skew_ns_max / ms,
            config.l1_reorgs_per_minute,
            config.spam_per_minute,
        },
    );
}

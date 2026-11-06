//! `base replay bench <archive> [<warm runs>] [--recovery-threads <n>]`: replays an archive
//! once cold and then `warm runs` more times (default 5) in the same process, and prints one
//! line per block:
//!
//!     BENCH run=<r> block=<n> txs=<k> gas=<g> exec_ns=<e> total_ns=<t> pre_ns=<p>
//!         recover_ns=<s> post_ns=<w> receipts_ns=<c> commit_ns=<m> root_ns=<o> ok=<0|1>
//!
//! (one line). `exec_ns` covers the pre-block system calls and every transaction (sender
//! recovery included); `total_ns` is the whole block: execution, withdrawals, receipts root,
//! state commit, state root, transactions root and the resealed header hash. The phase fields
//! split it (`Executor.Phases`): `pre_ns` and `recover_ns` lie inside `exec_ns`; the rest of
//! `total_ns` after `root_ns` is the header check. Each run starts from a fresh replayer over
//! the same decoded archive, so every run executes the same blocks from the same pre-state;
//! loading and hashing the witness is outside the timed region. A block that does not
//! reproduce its canonical header stops the bench with exit code 1. The format matches the
//! base/base harness described in docs/BENCHMARKS.md. `--recovery-threads` sets the
//! sender-recovery workers (0: inline; default one per spare core, at most 7). `--evm-only`
//! runs the blocks over a flat in-memory pre-state instead (`replay_evm.zig`).

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const cli = @import("replay.zig");
const evm_only = @import("replay_evm.zig");

const replay = base.infra.replay;
const Archive = replay.Archive;
const Clock = base.execution.node.executor.Executor.Clock;
const assert = std.debug.assert;

const warm_runs_default: u32 = 5;
const warm_runs_max: u32 = 1000;

const usage = "usage: base replay bench <archive> [<warm runs>] [--recovery-threads <n>]\n" ++
    "                         [--evm-only [--prestate-out <file>]]\n";

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    var path: ?[]const u8 = null;
    var warm_runs: ?u32 = null;
    var recovery_threads = cli.recovery_threads_default();
    var evm = false;
    var prestate_out: ?[]const u8 = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--evm-only")) {
            evm = true;
        } else if (std.mem.eql(u8, args[index], "--prestate-out")) {
            if (index + 1 == args.len) return error.InvalidArguments;
            prestate_out = args[index + 1];
            index += 1;
        } else if (std.mem.eql(u8, args[index], "--recovery-threads")) {
            if (index + 1 == args.len) return error.InvalidArguments;
            recovery_threads = try cli.parse_recovery_threads(args[index + 1]);
            index += 1;
        } else if (path == null) {
            path = args[index];
        } else if (warm_runs == null) {
            warm_runs = try std.fmt.parseInt(u32, args[index], 10);
        } else {
            std.debug.print(usage, .{});
            return 2;
        }
    }
    const archive_path = path orelse {
        std.debug.print(usage, .{});
        return 2;
    };
    const runs = warm_runs orelse warm_runs_default;
    if (runs > warm_runs_max) return error.InvalidArguments;
    const gpa = init.gpa;
    const limit: Io.Limit = .limited(cli.file_bytes_max);
    const file = try Io.Dir.cwd().readFileAlloc(init.io, archive_path, gpa, limit);
    defer gpa.free(file);
    var archive: Archive = undefined;
    try cli.decode_archive(gpa, file, &archive);
    defer archive.deinit(gpa);
    var io = init.io;
    const clock: Clock = .{ .context = @ptrCast(&io), .now_ns = now_ns };
    var buffer: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(init.io, &buffer);
    if (evm) {
        const options: evm_only.Options = .{ .warm_runs = runs, .prestate_out = prestate_out };
        return evm_only.main(init, &archive, options, clock, &writer.interface);
    }
    var run: u32 = 0;
    while (run <= runs) : (run += 1) {
        const config = cli.replayer_config(&archive, recovery_threads);
        const passed = try bench_run(gpa, &archive, config, clock, run, &writer.interface);
        try writer.interface.flush();
        if (!passed) return 1;
    }
    assert(run == runs + 1);
    return 0;
}

/// One replay of the whole archive; false at the first block that does not reproduce.
fn bench_run(
    gpa: std.mem.Allocator,
    archive: *const Archive,
    config: replay.replayer.Config,
    clock: Clock,
    run: u32,
    out: *Io.Writer,
) !bool {
    assert(archive.block_count > 0);
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    const replayer = try gpa.create(replay.Replayer);
    defer gpa.destroy(replayer);
    try replayer.init(gpa, spec, archive, config);
    defer replayer.deinit(gpa);
    replayer.executor.phase_clock = clock;
    var blocks: u32 = 0;
    while (!replayer.done()) : (blocks += 1) {
        const start_ns = clock.read();
        const outcome = try replayer.replay_next();
        const total_ns = clock.read() -| start_ns;
        const phases = &replayer.executor.last_phases;
        try out.print("BENCH run={d} block={d} txs={d} gas={d} exec_ns={d} total_ns={d} " ++
            "pre_ns={d} recover_ns={d} post_ns={d} receipts_ns={d} commit_ns={d} " ++
            "root_ns={d} ok={d}\n", .{
            run,
            outcome.number,
            outcome.transactions,
            outcome.gas_used,
            replayer.executor.last_execution_ns,
            total_ns,
            phases.pre_block_ns,
            phases.recovery_ns,
            phases.post_block_ns,
            phases.receipts_root_ns,
            phases.commit_ns,
            phases.state_root_ns,
            @intFromBool(outcome.ok()),
        });
        if (!outcome.ok()) return false;
    }
    assert(blocks == archive.block_count);
    return true;
}

fn now_ns(context: *anyopaque) u64 {
    const io: *const Io = @ptrCast(@alignCast(context));
    const now = Io.Clock.awake.now(io.*);
    assert(now.nanoseconds >= 0);
    return @intCast(now.nanoseconds);
}

fn zero_ns(context: *anyopaque) u64 {
    _ = context;
    return 0;
}

test "replay bench: the report does not depend on the sender-recovery thread count" {
    const allocator = std.testing.allocator;
    const fixture = replay.mainnet_fixture;
    var archive = try Archive.init(allocator, fixture.fixture_config);
    defer archive.deinit(allocator);
    try replay.archive.decode(allocator, fixture.fixture, &archive);
    // A constant clock: the report is then everything but the timings.
    var context: u8 = 0;
    const clock: Clock = .{ .context = &context, .now_ns = zero_ns };
    var reports: [2]Io.Writer.Allocating = .{ .init(allocator), .init(allocator) };
    defer for (&reports) |*report| report.deinit();
    for ([_]u32{ 0, 7 }, &reports) |threads, *report| {
        const config = cli.replayer_config(&archive, threads);
        const passed = try bench_run(allocator, &archive, config, clock, 0, &report.writer);
        try std.testing.expect(passed);
    }
    try std.testing.expectEqualStrings(reports[0].written(), reports[1].written());
    const lines = std.mem.count(u8, reports[0].written(), "\n");
    try std.testing.expectEqual(@as(usize, 10), lines);
    try std.testing.expectEqual(lines, std.mem.count(u8, reports[0].written(), " ok=1\n"));
}

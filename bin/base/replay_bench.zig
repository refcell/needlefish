//! `base replay bench <archive> [<warm runs>]`: replays an archive once cold and then
//! `warm runs` more times (default 5) in the same process, and prints one line per block:
//!
//!     BENCH run=<r> block=<n> txs=<k> gas=<g> exec_ns=<e> total_ns=<t> ok=<0|1>
//!
//! `exec_ns` covers the pre-block system calls and every transaction (sender recovery
//! included); `total_ns` is the whole block: execution, withdrawals, receipts root, state
//! commit, state root, transactions root and the resealed header hash. Each run starts from
//! a fresh replayer over the same decoded archive, so every run executes the same blocks from
//! the same pre-state; loading and hashing the witness is outside the timed region. A block
//! that does not reproduce its canonical header stops the bench with exit code 1. The format
//! matches the base/base harness described in docs/BENCHMARKS.md.

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const cli = @import("replay.zig");

const replay = base.infra.replay;
const Archive = replay.Archive;
const Clock = base.execution.node.executor.Executor.Clock;
const assert = std.debug.assert;

const warm_runs_default: u32 = 5;
const warm_runs_max: u32 = 1000;

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0 or args.len > 2) {
        std.debug.print("usage: base replay bench <archive> [<warm runs>]\n", .{});
        return 2;
    }
    const warm_runs = if (args.len == 2)
        try std.fmt.parseInt(u32, args[1], 10)
    else
        warm_runs_default;
    if (warm_runs > warm_runs_max) return error.InvalidArguments;
    const gpa = init.gpa;
    const limit: Io.Limit = .limited(cli.file_bytes_max);
    const file = try Io.Dir.cwd().readFileAlloc(init.io, args[0], gpa, limit);
    defer gpa.free(file);
    var archive = try Archive.init(gpa, cli.archive_config);
    defer archive.deinit(gpa);
    try replay.archive.decode(gpa, file, &archive);
    var io = init.io;
    const clock: Clock = .{ .context = @ptrCast(&io), .now_ns = now_ns };
    var buffer: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(init.io, &buffer);
    var run: u32 = 0;
    while (run <= warm_runs) : (run += 1) {
        const passed = try bench_run(gpa, &archive, clock, run, &writer.interface);
        try writer.interface.flush();
        if (!passed) return 1;
    }
    assert(run == warm_runs + 1);
    return 0;
}

/// One replay of the whole archive; false at the first block that does not reproduce.
fn bench_run(
    gpa: std.mem.Allocator,
    archive: *const Archive,
    clock: Clock,
    run: u32,
    out: *Io.Writer,
) !bool {
    assert(archive.block_count > 0);
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    const replayer = try gpa.create(replay.Replayer);
    defer gpa.destroy(replayer);
    try replayer.init(gpa, spec, archive, cli.replayer_config(archive));
    defer replayer.deinit(gpa);
    replayer.executor.phase_clock = clock;
    var blocks: u32 = 0;
    while (!replayer.done()) : (blocks += 1) {
        const start_ns = clock.read();
        const outcome = try replayer.replay_next();
        const total_ns = clock.read() -| start_ns;
        const line = "BENCH run={d} block={d} txs={d} gas={d} exec_ns={d} total_ns={d} ok={d}\n";
        try out.print(line, .{
            run,
            outcome.number,
            outcome.transactions,
            outcome.gas_used,
            replayer.executor.last_execution_ns,
            total_ns,
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

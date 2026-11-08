//! `zig build statetest -- <file-or-dir>... [--fork Cancun] [--filter name] [--quiet]
//!     [--bench [--target-ms <ms>]] [--no-keccak-memo]`
//!
//! Runs ethereum/tests GeneralStateTests fixtures (fetch with `just vectors`) and prints
//! failures plus a pass-rate summary. Exits non-zero if any case fails. `--bench` times every
//! case instead and prints `BENCH` lines (`state_test_bench.zig`, `etc/bench/evm2.sh`).

const std = @import("std");
const base = @import("base");
const evm = base.execution.evm;
const state_test = evm.state_test;
const Io = std.Io;
const assert = std.debug.assert;
const bench = @import("state_test_bench.zig");

const memo_entries_default = (evm.env.Config{}).keccak_memo_entries;

const Context = struct {
    quiet: bool,
    verbose: bool = false,
    path: []const u8 = "",
    /// `--bench`: target time per case and phase, and where `BENCH` lines go.
    bench_target_ns: ?u64 = null,
    /// `--no-keccak-memo`: hash every KECCAK256 input (`evm.Config.keccak_memo_entries = 0`).
    keccak_memo: bool = true,
    out: ?*Io.Writer = null,
};

fn report(context_opaque: *anyopaque, failure: state_test.Failure) void {
    const context: *Context = @ptrCast(@alignCast(context_opaque));
    if (context.quiet) return;
    std.debug.print("FAIL {s} {s} [{t}] d{d}g{d}v{d}: {s}\n", .{
        context.path,
        failure.name,
        failure.fork,
        failure.index.data,
        failure.index.gas,
        failure.index.value,
        failure.reason,
    });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: statetest <file-or-dir>... [--fork F] [--filter S] [--quiet]" ++
            " [--bench [--target-ms <ms>]] [--no-keccak-memo]\n", .{});
        return 2;
    }
    var context = Context{ .quiet = false };
    const arguments = try parse_arguments(init.arena.allocator(), args[1..], &context) orelse
        return 2;
    var out_buffer: [4096]u8 = undefined;
    var out_writer = Io.File.stdout().writer(io, &out_buffer);
    context.out = &out_writer.interface;
    var database = evm.MemoryDatabase.init(gpa);
    defer database.deinit();
    // Pre-Osaka fixtures run up to 120M gas in one transaction: ~1.2M TSTOREs at 100 gas.
    var state = try evm.State.init(gpa, database.interface(), .{
        .transient_slots_max = 1 << 21,
        .journal_entries_max = 1 << 22,
    });
    defer state.deinit(gpa);
    // Some fixtures (1 MB calldata at depth 1024) need ~1 GB of frame memory; the
    // buffers are virtual until touched.
    var machine = try evm.Evm.init(gpa, .{
        .memory_bytes_max = 1536 << 20,
        .code_arena_bytes = 1536 << 20,
        .keccak_memo_entries = if (context.keccak_memo) memo_entries_default else 0,
    }, &state);
    defer machine.deinit(gpa);
    var runner = state_test.Runner{
        .state = &state,
        .evm = &machine,
        .on_failure = report,
        .context = &context,
    };
    var summary = state_test.Summary{};
    for (arguments.paths) |path| {
        summary.add(try run_path(io, gpa, &runner, &context, path, arguments.options));
    }
    if (context.bench_target_ns != null) return if (summary.failed == 0) 0 else 1;
    const total = summary.passed + summary.failed;
    std.debug.print("statetest: passed={d} total={d} failed={d} skipped_forks={d}\n", .{
        summary.passed, total, summary.failed, summary.skipped,
    });
    return if (summary.failed == 0) 0 else 1;
}

const Arguments = struct { paths: []const []const u8, options: state_test.Options };

/// Flags go to `context` and the returned options; null on a usage error.
fn parse_arguments(
    arena: std.mem.Allocator,
    args: []const []const u8,
    context: *Context,
) !?Arguments {
    const paths = try arena.alloc([]const u8, args.len);
    var paths_len: usize = 0;
    var options = state_test.Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--quiet")) {
            context.quiet = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            context.verbose = true;
        } else if (index + 1 < args.len and std.mem.eql(u8, arg, "--fork")) {
            index += 1;
            options.fork = evm.Fork.from_test_name(args[index]) orelse return null;
        } else if (index + 1 < args.len and std.mem.eql(u8, arg, "--filter")) {
            index += 1;
            options.name_filter = args[index];
        } else if (std.mem.eql(u8, arg, "--no-keccak-memo")) {
            context.keccak_memo = false;
        } else if (std.mem.eql(u8, arg, "--bench")) {
            context.bench_target_ns = context.bench_target_ns orelse 20 * std.time.ns_per_ms;
        } else if (index + 1 < args.len and std.mem.eql(u8, arg, "--target-ms")) {
            index += 1;
            const target_ms = try std.fmt.parseInt(u64, args[index], 10);
            if (target_ms == 0) return null;
            context.bench_target_ns = target_ms * std.time.ns_per_ms;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            std.debug.print("unknown option: {s}\n", .{arg});
            return null;
        } else {
            paths[paths_len] = arg;
            paths_len += 1;
        }
    }
    if (paths_len == 0) return null;
    assert(paths_len <= args.len);
    return .{ .paths = paths[0..paths_len], .options = options };
}

fn run_path(
    io: Io,
    gpa: std.mem.Allocator,
    runner: *state_test.Runner,
    context: *Context,
    path: []const u8,
    options: state_test.Options,
) !state_test.Summary {
    const cwd = Io.Dir.cwd();
    if (std.mem.endsWith(u8, path, ".json")) {
        return run_one(io, gpa, runner, context, cwd, path, options);
    }
    var dir = try cwd.openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    var summary = state_test.Summary{};
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".json")) continue;
        summary.add(try run_one(io, gpa, runner, context, dir, entry.path, options));
    }
    return summary;
}

fn run_one(
    io: Io,
    gpa: std.mem.Allocator,
    runner: *state_test.Runner,
    context: *Context,
    dir: Io.Dir,
    path: []const u8,
    options: state_test.Options,
) !state_test.Summary {
    const bytes = try dir.readFileAlloc(io, path, gpa, .limited(256 << 20));
    defer gpa.free(bytes);
    context.path = path;
    if (context.verbose) std.debug.print("RUN {s}\n", .{path});
    if (context.bench_target_ns) |target_ns| {
        bench.bench_file(io, context.out.?, gpa, runner, bytes, target_ns) catch |err| {
            std.debug.print("ERROR {s}: {t}\n", .{ path, err });
            return .{ .failed = 1 };
        };
        return .{};
    }
    return state_test.run_file(runner, gpa, bytes, options) catch |err| {
        std.debug.print("ERROR {s}: {t}\n", .{ path, err });
        return .{ .failed = 1 };
    };
}

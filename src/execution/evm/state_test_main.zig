//! `zig build statetest -- <file-or-dir> [--fork Cancun] [--filter name] [--quiet]`
//!
//! Runs ethereum/tests GeneralStateTests fixtures (fetch with `just vectors`) and prints
//! failures plus a pass-rate summary. Exits non-zero if any case fails.

const std = @import("std");
const base = @import("base");
const evm = base.execution.evm;
const state_test = evm.state_test;
const Io = std.Io;

const Context = struct { quiet: bool, verbose: bool = false, path: []const u8 = "" };

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
        std.debug.print("usage: statetest <file-or-dir> [--fork F] [--filter S] [--quiet]\n", .{});
        return 2;
    }
    var options = state_test.Options{};
    var context = Context{ .quiet = false };
    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--quiet")) {
            context.quiet = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            context.verbose = true;
        } else if (index + 1 < args.len and std.mem.eql(u8, arg, "--fork")) {
            index += 1;
            options.fork = evm.Fork.from_test_name(args[index]) orelse return 2;
        } else if (index + 1 < args.len and std.mem.eql(u8, arg, "--filter")) {
            index += 1;
            options.name_filter = args[index];
        }
    }
    var database = evm.MemoryDatabase.init(gpa);
    defer database.deinit();
    var state = try evm.State.init(gpa, database.interface(), .{});
    defer state.deinit(gpa);
    var machine = try evm.Evm.init(gpa, .{}, &state);
    defer machine.deinit(gpa);
    var runner = state_test.Runner{
        .state = &state,
        .evm = &machine,
        .on_failure = report,
        .context = &context,
    };
    const summary = try run_path(io, gpa, &runner, &context, args[1], options);
    const total = summary.passed + summary.failed;
    std.debug.print("statetest: {d}/{d} passed, {d} failed, {d} skipped forks\n", .{
        summary.passed, total, summary.failed, summary.skipped,
    });
    return if (summary.failed == 0) 0 else 1;
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
    return state_test.run_file(runner, gpa, bytes, options) catch |err| {
        std.debug.print("ERROR {s}: {t}\n", .{ path, err });
        return .{ .failed = 1 };
    };
}

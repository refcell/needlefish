//! Benchmark statistics for docs/BENCHMARKS.md: reads tagged `BENCH` lines on stdin and
//! prints Markdown tables with medians, tail percentiles, phase breakdowns and 95% bootstrap
//! confidence intervals. Standalone (std only), run with
//!
//!     zig run -OReleaseSafe etc/bench/stats.zig -- [--pair <a>/<b>]... < results.txt
//!
//! Every input line is one block of one pass, as printed by `base replay bench` or the
//! base/base harness, prefixed by `etc/bench/reproduce.sh` with the configuration, the
//! process mode and the process number:
//!
//!     BENCH cfg=<label> mode=<cold|warm> iter=<i> run=<r> block=<n> ... total_ns=<t> ok=1
//!
//! A process's first pass (`run=0`) belongs to its mode; later passes (`run>0`, the second
//! pass in the same process) are reported as mode `repeat`. A "window" is one pass over every
//! block of the archive; its time is the sum of its blocks' times. Per-block percentiles use
//! every (block, pass) sample, nearest rank. Confidence intervals resample whole passes with
//! replacement (10,000 resamples, fixed seed, so the output is deterministic).
//! `--pair a/b` adds the speedup of `a` over `b`: b's median window time over a's.

const std = @import("std");
const assert = std.debug.assert;

const configs_max = 64;
const passes_max = 4096;
const samples_max = 1 << 23;
const pairs_max = 32;
const resamples = 10_000;
const input_bytes_max = 1 << 31;

const Mode = enum(u8) { cold, warm, repeat };

/// Phase fields, in BENCH line order; absent fields read as null (the base/base harness
/// before phase timing, for example).
const phase_names = [_][]const u8{
    "pre_ns", "recover_ns", "post_ns", "receipts_ns", "commit_ns", "root_ns",
};
const Phase = enum(u8) { pre, recover, post, receipts, commit, root };

const Sample = struct {
    config: u16,
    mode: Mode,
    iteration: u32,
    run: u32,
    block: u64,
    gas: u64,
    exec_ns: u64,
    total_ns: u64,
    phases: [phase_names.len]?u64,
};

const Pass = struct { gas: u64 = 0, exec_ns: u64 = 0, total_ns: u64 = 0 };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var pairs: [pairs_max][2][]const u8 = undefined;
    var pairs_len: u32 = 0;
    var index: usize = 1;
    while (index < args.len) : (index += 2) {
        if (!std.mem.eql(u8, args[index], "--pair") or index + 1 == args.len) {
            return error.InvalidArguments;
        }
        const slash = std.mem.indexOfScalar(u8, args[index + 1], '/') orelse
            return error.InvalidArguments;
        if (pairs_len == pairs_max) return error.TooManyPairs;
        pairs[pairs_len] = .{ args[index + 1][0..slash], args[index + 1][slash + 1 ..] };
        pairs_len += 1;
    }
    var buffer: [1 << 16]u8 = undefined;
    var reader = std.Io.File.stdin().reader(init.io, &buffer);
    const input = try reader.interface.allocRemaining(gpa, .limited(input_bytes_max));
    var names: std.ArrayList([]const u8) = .empty;
    var samples: std.ArrayList(Sample) = .empty;
    try parse(gpa, input, &names, &samples);
    if (samples.items.len == 0) return error.NoSamples;
    var out_buffer: [1 << 14]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &out_buffer);
    const out = &writer.interface;
    try print_timings(gpa, out, names.items, samples.items);
    try print_phases(out, names.items, samples.items);
    try print_pairs(gpa, out, names.items, samples.items, pairs[0..pairs_len]);
    try out.flush();
}

fn parse(
    gpa: std.mem.Allocator,
    input: []const u8,
    names: *std.ArrayList([]const u8),
    samples: *std.ArrayList(Sample),
) !void {
    var lines = std.mem.tokenizeScalar(u8, input, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "BENCH ")) continue;
        var sample: Sample = .{
            .config = 0,
            .mode = .warm,
            .iteration = 0,
            .run = 0,
            .block = 0,
            .gas = 0,
            .exec_ns = 0,
            .total_ns = 0,
            .phases = @splat(null),
        };
        var config: ?[]const u8 = null;
        var ok = false;
        var fields = std.mem.tokenizeScalar(u8, line["BENCH ".len..], ' ');
        while (fields.next()) |field| {
            const equals = std.mem.indexOfScalar(u8, field, '=') orelse return error.BadLine;
            const key = field[0..equals];
            const value = field[equals + 1 ..];
            if (std.mem.eql(u8, key, "cfg")) {
                config = value;
            } else if (std.mem.eql(u8, key, "mode")) {
                sample.mode = std.meta.stringToEnum(Mode, value) orelse return error.BadMode;
            } else if (std.mem.eql(u8, key, "ok")) {
                ok = std.mem.eql(u8, value, "1");
            } else {
                try set_number(&sample, key, try std.fmt.parseInt(u64, value, 10));
            }
        }
        // A block that did not reproduce its canonical header invalidates the whole input.
        if (!ok) return error.BlockMismatch;
        sample.config = try intern(gpa, names, config orelse return error.MissingConfig);
        if (sample.run > 0) sample.mode = .repeat;
        if (samples.items.len == samples_max) return error.TooManySamples;
        try samples.append(gpa, sample);
    }
    assert(samples.items.len <= samples_max);
}

fn set_number(sample: *Sample, key: []const u8, value: u64) !void {
    if (std.mem.eql(u8, key, "iter")) {
        sample.iteration = @intCast(value);
    } else if (std.mem.eql(u8, key, "run")) {
        sample.run = @intCast(value);
    } else if (std.mem.eql(u8, key, "block")) {
        sample.block = value;
    } else if (std.mem.eql(u8, key, "gas")) {
        sample.gas = value;
    } else if (std.mem.eql(u8, key, "exec_ns")) {
        sample.exec_ns = value;
    } else if (std.mem.eql(u8, key, "total_ns")) {
        sample.total_ns = value;
    } else {
        for (phase_names, 0..) |name, phase| {
            if (std.mem.eql(u8, key, name)) sample.phases[phase] = value;
        }
    }
}

fn intern(gpa: std.mem.Allocator, names: *std.ArrayList([]const u8), name: []const u8) !u16 {
    for (names.items, 0..) |known, index| {
        if (std.mem.eql(u8, known, name)) return @intCast(index);
    }
    if (names.items.len == configs_max) return error.TooManyConfigs;
    try names.append(gpa, name);
    assert(names.items.len <= configs_max);
    return @intCast(names.items.len - 1);
}

/// Window passes of one (configuration, mode), one entry per (process, run).
fn collect_passes(
    gpa: std.mem.Allocator,
    samples: []const Sample,
    config: u16,
    mode: Mode,
) ![]Pass {
    var keys: std.ArrayList(u64) = .empty;
    var passes: std.ArrayList(Pass) = .empty;
    for (samples) |sample| {
        if (sample.config != config or sample.mode != mode) continue;
        const key = (@as(u64, sample.iteration) << 32) | sample.run;
        const index = for (keys.items, 0..) |known, index| {
            if (known == key) break index;
        } else blk: {
            if (keys.items.len == passes_max) return error.TooManyPasses;
            try keys.append(gpa, key);
            try passes.append(gpa, .{});
            break :blk keys.items.len - 1;
        };
        passes.items[index].gas += sample.gas;
        passes.items[index].exec_ns += sample.exec_ns;
        passes.items[index].total_ns += sample.total_ns;
    }
    assert(keys.items.len == passes.items.len);
    return passes.items;
}

fn print_timings(
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    names: []const []const u8,
    samples: []const Sample,
) !void {
    try out.print("| configuration | mode | phase | blocks | passes | ms/block median | p90 | " ++
        "p99 | window ms median (95% CI) | Mgas/s |\n", .{});
    try out.print("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n", .{});
    for (names, 0..) |name, config| {
        for (std.enums.values(Mode)) |mode| {
            const passes = try collect_passes(gpa, samples, @intCast(config), mode);
            if (passes.len == 0) continue;
            for ([_]bool{ false, true }) |total| {
                const row: Row = .{ .name = name, .config = @intCast(config), .mode = mode };
                try print_timing_row(gpa, out, row, total, samples, passes);
            }
        }
    }
    try out.print("\n", .{});
}

const Row = struct { name: []const u8, config: u16, mode: Mode };

fn print_timing_row(
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    row: Row,
    total: bool,
    samples: []const Sample,
    passes: []const Pass,
) !void {
    assert(passes.len > 0);
    var per_block: std.ArrayList(u64) = .empty;
    for (samples) |sample| {
        if (sample.config != row.config or sample.mode != row.mode) continue;
        try per_block.append(gpa, if (total) sample.total_ns else sample.exec_ns);
    }
    const windows = try gpa.alloc(u64, passes.len);
    for (passes, windows) |pass, *window| window.* = if (total) pass.total_ns else pass.exec_ns;
    const ci = try bootstrap_median(gpa, windows, null);
    const gas_per_pass = passes[0].gas;
    for (passes) |pass| assert(pass.gas == gas_per_pass); // Every pass replays the same blocks.
    std.mem.sort(u64, per_block.items, {}, std.sort.asc(u64));
    const blocks = per_block.items.len / passes.len;
    try out.print("| {s} | {t} | {s} | {d} | {d} | {d:.2} | {d:.2} | {d:.2} | " ++
        "{d:.1} ({d:.1}-{d:.1}) | {d:.0} |\n", .{
        row.name,
        row.mode,
        if (total) "execution + roots" else "execution",
        blocks,
        passes.len,
        ms(percentile(per_block.items, 50)),
        ms(percentile(per_block.items, 90)),
        ms(percentile(per_block.items, 99)),
        ms(ci.median),
        ms(ci.low),
        ms(ci.high),
        @as(f64, @floatFromInt(gas_per_pass)) * 1e3 / ci.median,
    });
}

fn ms(ns: f64) f64 {
    return ns / 1e6;
}

/// Nearest-rank percentile of sorted `values`.
fn percentile(values: []const u64, p: u32) f64 {
    assert(values.len > 0 and p <= 100);
    const rank = std.math.divCeil(usize, values.len * p, 100) catch unreachable;
    return @floatFromInt(values[@max(rank, 1) - 1]);
}

fn median_of(values: []u64) f64 {
    assert(values.len > 0);
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    const middle = values.len / 2;
    if (values.len % 2 == 1) return @floatFromInt(values[middle]);
    const sum: f64 = @floatFromInt(values[middle - 1] + values[middle]);
    return sum / 2;
}

const Interval = struct { median: f64, low: f64, high: f64 };

/// The median of `a`, or with `b` the ratio median(b) / median(a), and the 2.5% and 97.5%
/// quantiles of the same statistic over resamples (passes drawn with replacement).
fn bootstrap_median(gpa: std.mem.Allocator, a: []const u64, b: ?[]const u64) !Interval {
    assert(a.len > 0);
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();
    const scratch_a = try gpa.alloc(u64, a.len);
    const scratch_b = try gpa.alloc(u64, if (b) |values| values.len else 0);
    const statistics = try gpa.alloc(f64, resamples);
    @memcpy(scratch_a, a);
    if (b) |values| @memcpy(scratch_b, values);
    const point = statistic(scratch_a, if (b != null) scratch_b else null);
    for (statistics) |*value| {
        for (scratch_a) |*slot| slot.* = a[random.uintLessThan(usize, a.len)];
        if (b) |values| {
            for (scratch_b) |*slot| slot.* = values[random.uintLessThan(usize, values.len)];
        }
        value.* = statistic(scratch_a, if (b != null) scratch_b else null);
    }
    std.mem.sort(f64, statistics, {}, std.sort.asc(f64));
    const low = statistics[resamples * 25 / 1000];
    const high = statistics[resamples * 975 / 1000 - 1];
    assert(low <= high);
    return .{ .median = point, .low = low, .high = high };
}

fn statistic(a: []u64, b: ?[]u64) f64 {
    const median_a = median_of(a);
    const values = b orelse return median_a;
    assert(median_a > 0);
    return median_of(values) / median_a;
}

/// Mean ms per block of each phase, warm first passes (cold when there are none), and the
/// state root phase (commit + root) over the first and last tenth of the window.
fn print_phases(
    out: *std.Io.Writer,
    names: []const []const u8,
    samples: []const Sample,
) !void {
    try out.print("| configuration | mode | pre-block | sender recovery | transactions | " ++
        "post-block | receipts root | state commit | state root | header and other | " ++
        "commit + root, first tenth | commit + root, last tenth |\n", .{});
    try out.print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |" ++
        " ---: | ---: |\n", .{});
    for (names, 0..) |name, config| {
        const mode: Mode = for ([_]Mode{ .warm, .cold }) |mode| {
            if (has_samples(samples, @intCast(config), mode)) break mode;
        } else continue;
        const sums = phase_sums(samples, @intCast(config), mode);
        if (sums.count == 0) continue;
        const count: f64 = @floatFromInt(sums.count);
        try out.print("| {s} | {t} |", .{ name, mode });
        for (sums.columns) |column| try out.print(" {d:.3} |", .{ms(column) / count});
        try out.print(" {d:.3} | {d:.3} |\n", .{
            ms(sums.root_first) / @as(f64, @floatFromInt(@max(sums.first_count, 1))),
            ms(sums.root_last) / @as(f64, @floatFromInt(@max(sums.last_count, 1))),
        });
    }
    try out.print("\n", .{});
}

fn has_samples(samples: []const Sample, config: u16, mode: Mode) bool {
    for (samples) |sample| {
        if (sample.config == config and sample.mode == mode) return true;
    }
    return false;
}

const PhaseSums = struct {
    /// pre, recovery, transactions, post, receipts, commit, root, header and other.
    columns: [8]f64 = @splat(0),
    count: u64 = 0,
    root_first: f64 = 0,
    root_last: f64 = 0,
    first_count: u64 = 0,
    last_count: u64 = 0,
};

fn phase_sums(samples: []const Sample, config: u16, mode: Mode) PhaseSums {
    var first_block: u64 = std.math.maxInt(u64);
    var last_block: u64 = 0;
    for (samples) |sample| {
        if (sample.config != config or sample.mode != mode) continue;
        first_block = @min(first_block, sample.block);
        last_block = @max(last_block, sample.block);
    }
    const tenth = @max((last_block - first_block + 1) / 10, 1);
    var sums: PhaseSums = .{};
    for (samples) |sample| {
        if (sample.config != config or sample.mode != mode) continue;
        var phases: [phase_names.len]u64 = undefined;
        for (sample.phases, &phases) |value, *phase| phase.* = value orelse return .{};
        const p = struct {
            fn at(values: [phase_names.len]u64, phase: Phase) u64 {
                return values[@backingInt(phase)];
            }
        }.at;
        const transactions = sample.exec_ns -| (p(phases, .pre) + p(phases, .recover));
        const finish = p(phases, .post) + p(phases, .receipts) + p(phases, .commit) +
            p(phases, .root);
        const other = sample.total_ns -| (sample.exec_ns + finish);
        const columns = [8]u64{
            p(phases, .pre),      p(phases, .recover), transactions,     p(phases, .post),
            p(phases, .receipts), p(phases, .commit),  p(phases, .root), other,
        };
        for (columns, &sums.columns) |value, *sum| sum.* += @floatFromInt(value);
        sums.count += 1;
        const root: f64 = @floatFromInt(p(phases, .commit) + p(phases, .root));
        if (sample.block < first_block + tenth) {
            sums.root_first += root;
            sums.first_count += 1;
        }
        if (sample.block > last_block - tenth) {
            sums.root_last += root;
            sums.last_count += 1;
        }
    }
    return sums;
}

fn print_pairs(
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    names: []const []const u8,
    samples: []const Sample,
    pairs: []const [2][]const u8,
) !void {
    if (pairs.len == 0) return;
    try out.print("| faster | slower | mode | phase | speedup (95% CI) |\n", .{});
    try out.print("| --- | --- | --- | --- | ---: |\n", .{});
    for (pairs) |pair| {
        const a = index_of(names, pair[0]) orelse return error.UnknownConfig;
        const b = index_of(names, pair[1]) orelse return error.UnknownConfig;
        for (std.enums.values(Mode)) |mode| {
            const passes_a = try collect_passes(gpa, samples, a, mode);
            const passes_b = try collect_passes(gpa, samples, b, mode);
            if (passes_a.len == 0 or passes_b.len == 0) continue;
            for ([_]bool{ false, true }) |total| {
                const values_a = try window_times(gpa, passes_a, total);
                const values_b = try window_times(gpa, passes_b, total);
                const ci = try bootstrap_median(gpa, values_a, values_b);
                try out.print("| {s} | {s} | {t} | {s} | {d:.2}x ({d:.2}-{d:.2}) |\n", .{
                    pair[0],
                    pair[1],
                    mode,
                    if (total) "execution + roots" else "execution",
                    ci.median,
                    ci.low,
                    ci.high,
                });
            }
        }
    }
    try out.print("\n", .{});
}

fn index_of(names: []const []const u8, name: []const u8) ?u16 {
    for (names, 0..) |known, index| {
        if (std.mem.eql(u8, known, name)) return @intCast(index);
    }
    return null;
}

fn window_times(gpa: std.mem.Allocator, passes: []const Pass, total: bool) ![]u64 {
    const values = try gpa.alloc(u64, passes.len);
    for (passes, values) |pass, *value| value.* = if (total) pass.total_ns else pass.exec_ns;
    assert(values.len == passes.len);
    return values;
}

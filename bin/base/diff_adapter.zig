//! `base diff-adapter`: the differential execution adapter. Reads one JSON request per line
//! on stdin, writes exactly one JSON response line per request on stdout (flushed after
//! each), logs to stderr, and exits 0 when stdin closes. See `src/infra/diff_adapter`.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const diff = base.infra.diff_adapter;
const assert = std.debug.assert;

const usage =
    \\usage: base diff-adapter
    \\  Speaks the differential execution protocol on stdin/stdout (Base mainnet rules).
    \\  BASE_DIFF_COVERAGE=1 adds per-request coverage (needs a -Ddiff-coverage build).
    \\
;

/// Reader buffer; lines longer than this stream through it into the line buffer.
const read_buffer_bytes = 1 << 20;

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len != 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const gpa = init.gpa;
    const adapter = try gpa.create(diff.Adapter);
    defer gpa.destroy(adapter);
    try adapter.init(gpa);
    defer adapter.deinit();
    adapter.io = init.io;
    var coverage = try coverage_from_environment(init);
    defer if (coverage) |*features| features.deinit(gpa);
    const features: ?*const diff.Coverage = if (coverage) |*collected| collected else null;
    const read_buffer = try gpa.alloc(u8, read_buffer_bytes);
    defer gpa.free(read_buffer);
    var stdin = Io.File.stdin().reader(init.io, read_buffer);
    var write_buffer: [1 << 16]u8 = undefined;
    var stdout = Io.File.stdout().writer(init.io, &write_buffer);
    var line: Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var requests: u64 = 0;
    while (true) {
        line.clearRetainingCapacity();
        _ = stdin.interface.streamDelimiterEnding(&line.writer, '\n') catch |err| switch (err) {
            error.ReadFailed => return stdin.err orelse error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };
        const ended = stdin.interface.bufferedLen() == 0;
        if (!ended) stdin.interface.toss(1);
        const text = std.mem.trim(u8, line.written(), " \t\r");
        if (text.len > 0) {
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            try diff.handle_line(adapter, arena, text, &stdout.interface, features);
            try stdout.interface.writeAll("\n");
            try stdout.interface.flush();
            requests += 1;
        }
        if (ended) break;
    }
    std.log.info("diff-adapter: answered {d} requests", .{requests});
    return 0;
}

/// Coverage when `BASE_DIFF_COVERAGE` is set and not `0`; a build without
/// `-Ddiff-coverage` refuses instead of silently reporting nothing.
fn coverage_from_environment(init: std.process.Init) !?diff.Coverage {
    const setting = init.environ_map.get("BASE_DIFF_COVERAGE") orelse return null;
    if (setting.len == 0 or std.mem.eql(u8, setting, "0")) return null;
    if (!base.execution.evm.coverage.enabled) {
        std.log.err("BASE_DIFF_COVERAGE needs a binary built with -Ddiff-coverage", .{});
        return error.CoverageNotBuilt;
    }
    // The symbol table maps edge counters to functions; read once at startup.
    const executable = try Io.Dir.cwd().readFileAlloc(
        init.io,
        "/proc/self/exe",
        init.gpa,
        .limited(1 << 30),
    );
    defer init.gpa.free(executable);
    const coverage = try diff.Coverage.init(init.gpa, executable);
    std.log.info("diff-adapter: coverage on, of {d} edges {d} in the EVM and crypto, " ++
        "{d} in the trie, state database and storage engine (trie mode)", .{
        coverage.counters.len,
        coverage.edges.len,
        coverage.trie_edges.len,
    });
    return coverage;
}

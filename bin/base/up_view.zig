//! Terminal view of `base up`, in `base replay`'s style (`replay_tui.Style`): a bold header,
//! one line per phase with a green ✓ when done (a red ✗ and a `fix:` line when not), long
//! phases as a progress bar redrawn in place, and, once the node follows the tip, one aligned
//! row per block: number, transactions, gas, execution time, tip lag, the checks el-run made
//! (transactions root, gas, bloom, receipts root, state root, withdrawals root, block hash),
//! and the safe and finalized heads as consensus advances them.
//!
//! The children's own output goes to `logs/`, never here; rows come from el-run's per-block
//! log lines (`Line.parse`). Without a TTY (or with `--plain`) there is no color and no
//! redraw: progress prints at most every 30 s and marks read `ok` / `FAIL`.

const std = @import("std");
const replay_tui = @import("replay_tui.zig");

const Io = std.Io;
const Style = replay_tui.Style;
const assert = std.debug.assert;

const bar_width = 24;
const plain_progress_ms: i64 = 30_000;

pub const View = struct {
    file_writer: Io.File.Writer,
    style: Style,
    /// A redrawable line (progress or ticker) is on screen: the next line replaces it.
    live: bool = false,
    /// Nothing printed since the header (the table then needs no blank line above it).
    fresh: bool = false,
    last_plain_progress_ms: i64 = std.math.minInt(i64),
    /// The safe and finalized heads printed on the last row (to mark the ones that moved).
    last_safe: ?u64 = null,
    last_finalized: ?u64 = null,

    pub fn init(io: Io, buffer: []u8, plain: bool) View {
        const stdout = Io.File.stdout();
        const tty = stdout.isTty(io) catch false;
        return .{
            .file_writer = stdout.writerStreaming(io, buffer),
            .style = .{ .color = tty and !plain },
        };
    }

    fn out(view: *View) *Io.Writer {
        return &view.file_writer.interface;
    }

    /// Removes the live line so a permanent line can take its place.
    fn settle(view: *View) void {
        if (view.live and view.style.color) view.out().writeAll("\r\x1b[2K") catch {};
        view.live = false;
    }

    /// Starts a permanent line.
    fn begin_line(view: *View) void {
        view.settle();
        view.fresh = false;
    }

    fn done(view: *View) void {
        view.out().flush() catch {};
    }

    /// The one bold line naming the chain and the node, above everything else.
    pub fn header(view: *View, chain_name: []const u8, chain_id: u64, detail: []const u8) void {
        const s = view.style;
        view.settle();
        view.out().print("{s}needlefish{s}  {s}{s}{s} (chain {d})  {s}{s}{s}\n\n", .{
            s.bold(), s.reset(), s.bold(), chain_name, s.reset(),
            chain_id, s.dim(),   detail,   s.reset(),
        }) catch {};
        view.fresh = true;
        view.done();
    }

    /// A finished phase: `  ✓ phase      detail`.
    pub fn ok(view: *View, phase: []const u8, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        view.begin_line();
        const mark = if (s.color) "✓" else "ok";
        view.out().print("  {s}{s}{s} {s}{s:<10}{s} ", .{
            s.green(), mark, s.reset(), s.bold(), phase, s.reset(),
        }) catch {};
        view.out().print(format ++ "\n", args) catch {};
        view.done();
    }

    /// A failed check or phase: `  ✗ phase      what is wrong`, then `fix` lines.
    pub fn fail(view: *View, phase: []const u8, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        view.begin_line();
        const mark = if (s.color) "✗" else "FAIL";
        view.out().print("  {s}{s}{s} {s}{s:<10}{s} ", .{
            s.red(), mark, s.reset(), s.bold(), phase, s.reset(),
        }) catch {};
        view.out().print(format ++ "\n", args) catch {};
        view.done();
    }

    /// The fix for the failure above it.
    pub fn fix(view: *View, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        view.begin_line();
        view.out().print(
            "    {s}fix:{s} " ++ format ++ "\n",
            .{ s.bold(), s.reset() } ++ args,
        ) catch {};
        view.done();
    }

    /// A warning that does not stop the node.
    pub fn warn(view: *View, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        view.begin_line();
        view.out().print("  {s}!{s} " ++ format ++ "\n", .{ s.bold(), s.reset() } ++ args) catch {};
        view.done();
    }

    /// A detail under the phase above it (dim).
    pub fn note(view: *View, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        view.begin_line();
        view.out().print(
            "    {s}" ++ format ++ "{s}\n",
            .{s.dim()} ++ args ++ .{s.reset()},
        ) catch {};
        view.done();
    }

    /// A long phase's bar, redrawn in place (TTY); plain output prints it every 30 s.
    pub fn progress(
        view: *View,
        now_ms: i64,
        phase: []const u8,
        fraction: f64,
        comptime format: []const u8,
        args: anytype,
    ) void {
        const s = view.style;
        if (!s.color) {
            if (now_ms - view.last_plain_progress_ms < plain_progress_ms) return;
            view.last_plain_progress_ms = now_ms;
        }
        view.settle();
        const clamped = std.math.clamp(fraction, 0, 1);
        const filled: usize = @intFromFloat(clamped * bar_width);
        const w = view.out();
        w.print(
            "  {s}›{s} {s}{s:<10}{s} ",
            .{ s.cyan(), s.reset(), s.bold(), phase, s.reset() },
        ) catch {};
        if (s.color) {
            for (0..bar_width) |index| w.writeAll(if (index < filled) "█" else "░") catch {};
            w.writeAll(" ") catch {};
        }
        w.print("{d:>3.0}%  " ++ format, .{clamped * 100} ++ args) catch {};
        if (s.color) view.live = true else {
            w.writeAll("\n") catch {};
            view.fresh = false;
        }
        view.done();
    }

    /// The block table's column headings.
    pub fn table(view: *View) void {
        const s = view.style;
        const gap = if (view.fresh) "" else "\n";
        view.begin_line();
        const format = "{s}{s}  {s:<10} {s:>4} {s:>8} {s:>7} {s:>6}   {s}  {s:>10} {s:>10}{s}\n";
        view.out().print(format, .{
            gap,   s.dim(),       "block", "txs",       "gas",     "exec",
            "lag", check_heading, "safe",  "finalized", s.reset(),
        }) catch {};
        view.done();
    }

    /// One executed block (every check passed: el-run commits nothing else).
    pub fn row(view: *View, line: *const Line, safe: ?u64, finalized: ?u64) void {
        assert(line.kind == .block);
        const s = view.style;
        view.begin_line();
        const w = view.out();
        w.print("  {s}{d:<10}{s} {d:>4} {d:>7.2}M {d:>5}ms {d:>4}ms   ", .{
            s.cyan(),                                line.number,
            s.reset(),                               line.transactions,
            @as(f64, @floatFromInt(line.gas)) / 1e6, line.exec_ms,
            line.lag_ms,
        }) catch {};
        const mark = if (s.color) "✓" else "ok";
        const shown: usize = if (s.color) 1 else 2;
        for (check_widths) |width| {
            w.print("{s}{s}{s}", .{ s.green(), mark, s.reset() }) catch {};
            w.splatByteAll(' ', width - shown) catch {};
        }
        view.head_cell(safe, view.last_safe);
        view.head_cell(finalized, view.last_finalized);
        w.writeAll("\n") catch {};
        view.last_safe = safe;
        view.last_finalized = finalized;
        view.done();
    }

    /// A safe or finalized head: bright when it moved since the last row, dim when not.
    fn head_cell(view: *View, value: ?u64, last: ?u64) void {
        const s = view.style;
        const w = view.out();
        const number = value orelse {
            w.print(" {s}{s:>10}{s}", .{ s.dim(), "-", s.reset() }) catch {};
            return;
        };
        const moved = last == null or last.? != number;
        w.print(
            " {s}{d:>10}{s}",
            .{ if (moved) s.green() else s.dim(), number, s.reset() },
        ) catch {};
    }

    /// A block el-run refused: printed in red with the reason.
    pub fn refused(view: *View, number: u64, reason: []const u8) void {
        const s = view.style;
        view.begin_line();
        view.out().print("  {s}{d:<10} did not reproduce: {s}{s}\n", .{
            s.red(), number, reason, s.reset(),
        }) catch {};
        view.done();
    }

    /// The live line under the rows (TTY only).
    pub fn ticker(view: *View, comptime format: []const u8, args: anytype) void {
        const s = view.style;
        if (!s.color) return;
        view.settle();
        view.out().print("  {s}" ++ format ++ "{s}", .{s.dim()} ++ args ++ .{s.reset()}) catch {};
        view.live = true;
        view.done();
    }

    /// Leaves the live line on screen and ends it, before exiting.
    pub fn finish(view: *View) void {
        if (view.live) view.out().writeAll("\n") catch {};
        view.live = false;
        view.done();
    }
};

const check_heading = "tx gas bloom rcpt state wdr hash";
/// Each check column's width (heading word plus its space).
const check_widths = [_]usize{ 3, 4, 6, 5, 6, 4, 5 };

comptime {
    var total: usize = 0;
    for (check_widths) |width| total += width;
    assert(total == check_heading.len + 1);
}

/// A line of el-run's output that the view shows.
pub const Line = struct {
    kind: enum { block, at_tip, executing, mismatch, summary },
    number: u64 = 0,
    transactions: u64 = 0,
    gas: u64 = 0,
    exec_ms: u64 = 0,
    lag_ms: u64 = 0,
    /// `summary`: blocks behind the peers' head.
    behind: u64 = 0,

    /// `block N hash 0x.. T txs G gas E ms lag_ms L checks ok`, `el-run: at the tip, block N`,
    /// `el-run: executing <chain> from block N ...`, `MISMATCH block N ...`, and the summary's
    /// `head N (M behind)`; null for every other line.
    pub fn parse(text: []const u8) ?Line {
        var words = std.mem.tokenizeScalar(u8, text, ' ');
        const first = words.next() orelse return null;
        if (std.mem.eql(u8, first, "block")) return parse_block(text);
        if (std.mem.eql(u8, first, "MISMATCH")) {
            return .{
                .kind = .mismatch,
                .number = number_after(text, "MISMATCH block ") orelse return null,
            };
        }
        if (std.mem.startsWith(u8, text, "el-run: at the tip, block ")) {
            return .{
                .kind = .at_tip,
                .number = number_after(text, "at the tip, block ") orelse return null,
            };
        }
        if (std.mem.startsWith(u8, text, "el-run: executing ")) {
            return .{
                .kind = .executing,
                .number = number_after(text, " from block ") orelse return null,
            };
        }
        if (std.mem.startsWith(u8, text, "summary: ")) {
            const at = std.mem.indexOf(u8, text, ", head ") orelse return null;
            const number = number_after(text[at..], ", head ") orelse return null;
            const behind = number_after(text[at..], " (") orelse return null;
            return .{ .kind = .summary, .number = number, .behind = behind };
        }
        return null;
    }

    fn parse_block(text: []const u8) ?Line {
        if (!std.mem.endsWith(u8, std.mem.trimEnd(u8, text, "\r"), " checks ok")) return null;
        var fields: [14][]const u8 = undefined;
        var count: usize = 0;
        var words = std.mem.tokenizeScalar(u8, text, ' ');
        while (words.next()) |word| {
            if (count == fields.len) return null;
            fields[count] = word;
            count += 1;
        }
        // block N hash H T txs G gas E ms lag_ms L checks ok
        if (count != fields.len or !std.mem.eql(u8, fields[5], "txs")) return null;
        if (!std.mem.eql(u8, fields[10], "lag_ms")) return null;
        const parse_int = std.fmt.parseInt;
        return .{
            .kind = .block,
            .number = parse_int(u64, fields[1], 10) catch return null,
            .transactions = parse_int(u64, fields[4], 10) catch return null,
            .gas = parse_int(u64, fields[6], 10) catch return null,
            .exec_ms = parse_int(u64, fields[8], 10) catch return null,
            .lag_ms = parse_int(u64, fields[11], 10) catch return null,
        };
    }
};

fn number_after(text: []const u8, key: []const u8) ?u64 {
    const at = std.mem.indexOf(u8, text, key) orelse return null;
    const rest = text[at + key.len ..];
    const end = std.mem.indexOfNone(u8, rest, "0123456789") orelse rest.len;
    if (end == 0) return null;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
}

/// New complete lines of a growing log file, from where the last read stopped.
pub const Tail = struct {
    path: []const u8,
    offset: u64,
    /// The incomplete last line so far, then the bytes read after it.
    buffer: [buffer_size]u8 = undefined,
    pending: usize = 0,
    /// The complete lines of the last `read`.
    lines: [buffer_size]u8 = undefined,

    const buffer_size = 64 * 1024;

    /// Starts at the file's end (`from_end`) or its beginning.
    pub fn init(io: Io, path: []const u8, from_end: bool) Tail {
        var tail: Tail = .{ .path = path, .offset = 0 };
        if (from_end) tail.offset = file_length(io, path);
        return tail;
    }

    fn file_length(io: Io, path: []const u8) u64 {
        const stat = Io.Dir.cwd().statFile(io, path, .{}) catch return 0;
        return stat.size;
    }

    /// The complete lines appended since the last call (valid until the next one).
    pub fn read(tail: *Tail, io: Io) []const u8 {
        assert(tail.pending < buffer_size);
        if (file_length(io, tail.path) < tail.offset) {
            tail.offset = 0; // Truncated or replaced: start over.
            tail.pending = 0;
        }
        const file = Io.Dir.cwd().openFile(io, tail.path, .{}) catch return "";
        defer file.close(io);
        const got = file.readPositionalAll(
            io,
            tail.buffer[tail.pending..],
            tail.offset,
        ) catch return "";
        tail.offset += got;
        const filled = tail.pending + got;
        const newline = std.mem.lastIndexOfScalar(u8, tail.buffer[0..filled], '\n') orelse {
            // No line end in a full buffer: one line longer than the buffer, dropped.
            tail.pending = if (filled == buffer_size) 0 else filled;
            return "";
        };
        const end = newline + 1;
        @memcpy(tail.lines[0..end], tail.buffer[0..end]);
        tail.pending = filled - end;
        std.mem.copyForwards(u8, tail.buffer[0..tail.pending], tail.buffer[end..filled]);
        return tail.lines[0..end];
    }
};

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;

test "up view: el-run lines" {
    const block = Line.parse("block 56300123 hash 0xab12 21 txs 12450000 gas 24 ms lag_ms 210 " ++
        "checks ok").?;
    try testing.expectEqual(@as(u64, 56_300_123), block.number);
    try testing.expectEqual(@as(u64, 21), block.transactions);
    try testing.expectEqual(@as(u64, 12_450_000), block.gas);
    try testing.expectEqual(@as(u64, 24), block.exec_ms);
    try testing.expectEqual(@as(u64, 210), block.lag_ms);
    try testing.expectEqual(
        @as(u64, 55_577_860),
        Line.parse("el-run: at the tip, block 55577860").?.number,
    );
    const start = Line.parse("el-run: executing base-mainnet from block 56001552 (parent 0x..)").?;
    try testing.expectEqual(@as(u64, 56_001_552), start.number);
    const summary = Line.parse("summary: 640 blocks (14.8/s), 9000 txs, 103.0 Mgas/s executing, " ++
        "head 55000000 (577860 behind), catching_up, tip blocks 0").?;
    try testing.expectEqual(@as(u64, 577_860), summary.behind);
    try testing.expectEqual(@as(u64, 55_000_000), summary.number);
    try testing.expectEqual(@as(u64, 7), Line.parse("MISMATCH block 7 hash 0x.. (3 txs)").?.number);
    // Other lines, and damaged block lines, are not shown.
    try testing.expect(Line.parse("el-source: hello from reth") == null);
    try testing.expect(Line.parse("block 5 hash 0xab 1 txs 2 gas 3 ms lag_ms 4 checks") == null);
    try testing.expect(Line.parse("block x hash 0xab 1 txs 2 gas 3 ms lag_ms 4 checks ok") == null);
    try testing.expect(Line.parse("") == null);
}

test "up view: a tail yields whole lines as the file grows" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "el.log", .data = "old line\n" });
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = path_buffer[0..try tmp.dir.realPathFile(io, "el.log", &path_buffer)];
    var tail: Tail = .init(io, path, true);
    try testing.expectEqualStrings("", tail.read(io));
    const file = try tmp.dir.openFile(io, "el.log", .{ .mode = .write_only });
    defer file.close(io);
    try file.writePositionalAll(io, "first\nsec", 9);
    try testing.expectEqualStrings("first\n", tail.read(io));
    try file.writePositionalAll(io, "ond\nthird\n", 18);
    try testing.expectEqualStrings("second\nthird\n", tail.read(io));
    try testing.expectEqualStrings("", tail.read(io));
}

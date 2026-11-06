//! Terminal view of `base replay run`: one row per block (number, transactions, gas,
//! execution time, state root, the header checks), a progress bar redrawn in place, and a
//! summary. Zero dependencies: plain ANSI escapes. Without a TTY (or with `--plain`) it
//! prints the same rows without color or redraws, so logs and CI stay readable.

const std = @import("std");
const base = @import("base");

const replay = base.infra.replay;
const Outcome = replay.replayer.Outcome;
const Check = replay.replayer.Check;
const assert = std.debug.assert;

const bar_width = 32;

pub const Style = struct {
    color: bool,

    fn code(style: Style, comptime sequence: []const u8) []const u8 {
        return if (style.color) "\x1b[" ++ sequence ++ "m" else "";
    }

    fn reset(style: Style) []const u8 {
        return style.code("0");
    }
    fn dim(style: Style) []const u8 {
        return style.code("2");
    }
    fn bold(style: Style) []const u8 {
        return style.code("1");
    }
    fn green(style: Style) []const u8 {
        return style.code("32");
    }
    fn red(style: Style) []const u8 {
        return style.code("31");
    }
    fn cyan(style: Style) []const u8 {
        return style.code("36");
    }
};

/// What the summary line totals.
pub const Totals = struct {
    blocks: u32 = 0,
    passed: u32 = 0,
    transactions: u64 = 0,
    gas: u64 = 0,
    exec_ns: u64 = 0,
};

pub const View = struct {
    out: *std.Io.Writer,
    style: Style,
    block_count: u32,
    totals: Totals = .{},

    pub fn header(view: *View, first: u64, archive_bytes: u64) !void {
        const s = view.style;
        assert(view.block_count > 0);
        try view.out.print("{s}needlefish replay{s}  Base mainnet (chain 8453)  " ++
            "{d} blocks {d}..{d}  archive {d:.1} MB, offline\n\n", .{
            s.bold(),
            s.reset(),
            view.block_count,
            first,
            first + view.block_count - 1,
            @as(f64, @floatFromInt(archive_bytes)) / 1e6,
        });
        try view.out.print("{s}  {s:<10} {s:>4} {s:>9} {s:>8}  {s:<19} {s}{s}\n", .{
            s.dim(),
            "block",
            "txs",
            "gas",
            "exec",
            "state root",
            "tx  gas bloom blob rcpt state wdr hash",
            s.reset(),
        });
        try view.out.flush();
    }

    /// Prints one block's row, replacing the progress bar.
    pub fn row(view: *View, outcome: *const Outcome, exec_ns: u64) !void {
        const s = view.style;
        if (s.color) try view.out.writeAll("\r\x1b[2K");
        view.totals.blocks += 1;
        view.totals.transactions += outcome.transactions;
        view.totals.gas += outcome.gas_used;
        view.totals.exec_ns += exec_ns;
        if (outcome.ok()) view.totals.passed += 1;
        const root = &outcome.computed_state_root;
        try view.out.print("  {s}{d:<10}{s} {d:>4} {d:>7.2}M {d:>6.1}ms  {s}{x}..{x}{s}      ", .{
            s.cyan(),
            outcome.number,
            s.reset(),
            outcome.transactions,
            @as(f64, @floatFromInt(outcome.gas_used)) / 1e6,
            @as(f64, @floatFromInt(exec_ns)) / 1e6,
            s.dim(),
            root[0..4],
            root[30..32],
            s.reset(),
        });
        try view.checks(outcome);
        try view.out.writeAll("\n");
        try view.progress();
    }

    fn checks(view: *View, outcome: *const Outcome) !void {
        const s = view.style;
        const widths = [_]u8{ 4, 4, 6, 5, 5, 6, 4, 4 };
        comptime assert(widths.len == replay.replayer.check_count);
        inline for (@typeInfo(Check).@"enum".field_names, 0..) |name, index| {
            const ok = outcome.failure == null and outcome.check(@field(Check, name));
            const mark = if (!s.color) (if (ok) "ok" else "XX") else if (ok) "✓" else "✗";
            const shown: usize = if (s.color) 1 else 2;
            try view.out.print("{s}{s}{s}", .{ if (ok) s.green() else s.red(), mark, s.reset() });
            try view.out.splatByteAll(' ', widths[index] - shown);
        }
    }

    /// The progress bar under the rows (TTY only; redrawn by the next row).
    pub fn progress(view: *View) !void {
        const s = view.style;
        if (!s.color) return view.out.flush();
        const done = view.totals.blocks;
        const filled: u32 = @intCast(@as(u64, done) * bar_width / view.block_count);
        try view.out.writeAll("  ");
        for (0..bar_width) |index| {
            try view.out.writeAll(if (index < filled) "█" else "░");
        }
        try view.out.print(" {d}/{d}", .{ done, view.block_count });
        try view.out.flush();
    }

    pub fn summary(view: *View) !void {
        const s = view.style;
        const t = view.totals;
        if (s.color) try view.out.writeAll("\r\x1b[2K");
        const seconds = @as(f64, @floatFromInt(@max(t.exec_ns, 1))) / 1e9;
        const megagas = @as(f64, @floatFromInt(t.gas)) / 1e6;
        const all = t.passed == view.block_count;
        try view.out.print("\n  {s}{s}{d}/{d} blocks reproduced{s}  {d} txs  {d:.1} Mgas  " ++
            "{d:.0} ms  {d:.0} Mgas/s\n", .{
            s.bold(),
            if (all) s.green() else s.red(),
            t.passed,
            view.block_count,
            s.reset(),
            t.transactions,
            megagas,
            seconds * 1e3,
            megagas / seconds,
        });
        if (all) {
            try view.out.print("  {s}every state root, receipts root, gas used and block hash " ++
                "matches the canonical chain{s}\n", .{ s.dim(), s.reset() });
        }
        try view.out.flush();
    }
};

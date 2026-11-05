//! `zig build txtest -- <file-or-dir> [--fork F]`: ethereum/tests TransactionTests
//! (from `just vectors`) through the strict EIP-2718 decoder (`tx_vectors.zig`).

const std = @import("std");
const base = @import("base");
const tx_vectors = base.common.consensus.tx_vectors;
const Io = std.Io;

var current_path: []const u8 = "";

fn report(name: []const u8, outcome: tx_vectors.Outcome) void {
    std.debug.print("FAIL {s} {s}: {t}\n", .{ current_path, name, outcome });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: txtest <file-or-dir> [--fork F]\n", .{});
        return 2;
    }
    var fork: []const u8 = "Prague";
    if (args.len >= 4 and std.mem.eql(u8, args[2], "--fork")) fork = args[3];
    var summary: tx_vectors.Summary = .{};
    const cwd = Io.Dir.cwd();
    if (std.mem.endsWith(u8, args[1], ".json")) {
        try run_one(io, gpa, cwd, args[1], fork, &summary);
    } else {
        var dir = try cwd.openDir(io, args[1], .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".json")) continue;
            try run_one(io, gpa, dir, entry.path, fork, &summary);
        }
    }
    std.debug.print(
        "txtest {s}: valid_ok={d} valid_mismatch={d} invalid_rejected={d} " ++
            "invalid_accepted={d} wider_than_u128={d} skipped={d}\n",
        .{
            fork,
            summary.get(.valid_ok),
            summary.get(.valid_mismatch),
            summary.get(.invalid_rejected),
            summary.get(.invalid_accepted),
            summary.get(.valid_wider_than_u128),
            summary.get(.skipped),
        },
    );
    return if (summary.failed() == 0) 0 else 1;
}

fn run_one(
    io: Io,
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    path: []const u8,
    fork: []const u8,
    summary: *tx_vectors.Summary,
) !void {
    const bytes = try dir.readFileAlloc(io, path, gpa, .limited(64 << 20));
    defer gpa.free(bytes);
    current_path = path;
    const file_summary = tx_vectors.run_file(gpa, bytes, fork, report) catch |err| {
        std.debug.print("ERROR {s}: {t}\n", .{ path, err });
        summary.add(.valid_mismatch);
        return;
    };
    for (&summary.counts, file_summary.counts) |*sum, count| sum.* += count;
}

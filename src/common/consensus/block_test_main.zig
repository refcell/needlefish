//! `zig build blockrlp -- <file-or-dir>`: ethereum/tests BlockchainTests (from
//! `just vectors`) through the strict block decoder (`block_vectors.zig`).

const std = @import("std");
const base = @import("base");
const block_vectors = base.common.consensus.block_vectors;
const Io = std.Io;

var current_path: []const u8 = "";

fn report(name: []const u8, index: usize, outcome: block_vectors.Outcome) void {
    std.debug.print("FAIL {s} {s} block {d}: {t}\n", .{ current_path, name, index, outcome });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: blockrlp <file-or-dir>\n", .{});
        return 2;
    }
    var summary: block_vectors.Summary = .{};
    const cwd = Io.Dir.cwd();
    if (std.mem.endsWith(u8, args[1], ".json")) {
        try run_one(io, gpa, cwd, args[1], &summary);
    } else {
        var dir = try cwd.openDir(io, args[1], .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".json")) continue;
            try run_one(io, gpa, dir, entry.path, &summary);
        }
    }
    std.debug.print("blockrlp:", .{});
    for (std.enums.values(block_vectors.Outcome)) |outcome| {
        std.debug.print(" {t}={d}", .{ outcome, summary.get(outcome) });
    }
    std.debug.print("\n", .{});
    return if (summary.failed() == 0) 0 else 1;
}

fn run_one(
    io: Io,
    gpa: std.mem.Allocator,
    dir: Io.Dir,
    path: []const u8,
    summary: *block_vectors.Summary,
) !void {
    const bytes = try dir.readFileAlloc(io, path, gpa, .limited(256 << 20));
    defer gpa.free(bytes);
    current_path = path;
    const file_summary = block_vectors.run_file(gpa, bytes, report) catch |err| {
        std.debug.print("ERROR {s}: {t}\n", .{ path, err });
        summary.add(.decode_failed);
        return;
    };
    summary.merge(file_summary);
}

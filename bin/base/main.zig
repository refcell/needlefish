//! `base`: the multi-tool CLI. Subcommands dispatch to the node, consensus,
//! batcher, and tooling entry points as they land.

const std = @import("std");
const base = @import("base");

const usage =
    \\usage: base <command> [args]
    \\
    \\commands:
    \\  version    print version
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return;
    }
    const command = args[1];
    if (std.mem.eql(u8, command, "version")) {
        std.debug.print("base {s} ({s})\n", .{
            base.build_options.version,
            base.build_options.git_rev,
        });
        return;
    }
    std.debug.print("unknown command: {s}\n{s}", .{ command, usage });
    std.process.exit(2);
}

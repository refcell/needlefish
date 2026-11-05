//! `base`: the multi-tool CLI. Subcommands dispatch to the node, consensus,
//! batcher, and tooling entry points as they land.

const std = @import("std");
const base = @import("base");
const devnet = @import("devnet.zig");
const batcher = @import("batcher.zig");
const node = @import("node.zig");

const usage =
    \\usage: base <command> [args]
    \\
    \\commands:
    \\  version    print version
    \\  devnet     generate local devnet config (base devnet init)
    \\  batcher    submit L2 batches to L1
    \\  node       execution node (--dev-l1 for a standalone L1 dev chain)
    \\
;

test {
    _ = devnet;
    _ = batcher;
    _ = node;
}

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
    if (std.mem.eql(u8, command, "devnet")) {
        std.process.exit(try devnet.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "node")) {
        std.process.exit(try node.main(init, args[2..]));
    }
    if (std.mem.eql(u8, command, "batcher")) {
        std.process.exit(try batcher.main(init, args[2..]));
    }
    std.debug.print("unknown command: {s}\n{s}", .{ command, usage });
    std.process.exit(2);
}

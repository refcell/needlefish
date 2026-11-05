//! Micro benchmark entry point.
//!
//! Usage: zig build bench -Doptimize=ReleaseFast -- [filter]
//! Lanes register benchmarks here as they land hot paths.

const std = @import("std");
const base = @import("base");

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const filter: ?[]const u8 = args.next();
    base.common.crypto.bench.run(init.io, filter);
}

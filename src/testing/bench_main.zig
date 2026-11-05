//! Micro benchmark entry point.
//!
//! Usage: zig build bench -Doptimize=ReleaseFast -- [filter]
//! Lanes register benchmarks here as they land hot paths.

const std = @import("std");
const base = @import("base");

pub fn main(init: std.process.Init) !void {
    _ = init;
    _ = base;
    std.debug.print("bench: no benchmarks registered yet\n", .{});
}

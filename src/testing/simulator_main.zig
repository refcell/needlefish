//! Deterministic simulator entry point (DST).
//!
//! Usage: zig build sim -- [seed]
//!
//! Runs the whole Base stack (L1, sequencer, batcher, verifier) on simulated
//! time, network, and disk driven by one seed. Same seed, same run. The
//! devnet-dst lane grows this into the full cluster simulator.

const std = @import("std");
const base = @import("base");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const seed: u64 = if (args.len > 1)
        try std.fmt.parseInt(u64, args[1], 10)
    else
        @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(init.io, .real).nanoseconds)));

    var prng = base.testing.Prng.init(seed);
    std.debug.print("simulator: seed={d} first={x}\n", .{ seed, prng.int(u64) });
}

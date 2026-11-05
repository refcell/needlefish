//! Micro benchmark entry point.
//!
//! Usage: zig build bench -Doptimize=ReleaseFast -- [filter]
//!
//! Lanes keep case tables next to their code; list each table in `suites` below.
//! Record notable results in docs/PERF.md (machine, date, commit).

const std = @import("std");
const base = @import("base");
const bench = base.testing.bench;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const filter: ?[]const u8 = args.next();
    bench.run_cases(init.io, base.common.crypto.bench.cases, filter);
    bench.run_cases(init.io, base.common.consensus.bench.cases, filter);
    bench.run_cases(init.io, bench.cases, filter);
    bench.run_cases(init.io, base.execution.trie.bench.cases, filter);
    bench.run_cases(init.io, base.execution.evm.bench.cases, filter);
    bench.run_cases(init.io, base.consensus.p2p.bench.cases, filter);
}

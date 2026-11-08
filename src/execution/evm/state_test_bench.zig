//! `statetest --bench`: times every case of state-test fixtures, one transaction each, for
//! the evm2 comparison (`etc/bench/evm2.sh`, docs/BENCHMARKS.md). The evm2 and revm side is
//! the `nf` runner from `etc/bench/evm2-harness.patch`, which uses the same loop:
//!
//! - One `Evm` and `State` per case live across iterations, as in a node. Each iteration
//!   resets the state to the case's pre-state (`State.reset`, untimed; allocations and the
//!   code-analysis cache are kept) and times one `transact`.
//! - A warm-up runs for the target time, then iterations run until the timed total reaches
//!   it (at least two); the line reports the mean.
//! - Before timing, the case runs once through the conformance check (post-state root and
//!   logs hash); `ok=0` when it fails.
//!
//! Cases run in name order. One line per case (the first post state of the first fork):
//!
//!     BENCH case=<name> iterations=<n> gas=<gas used> exec_ns=<mean> total_ns=<mean> ok=<0|1>

const std = @import("std");
const base = @import("base");
const evm = base.execution.evm;
const state_test = evm.state_test;
const Io = std.Io;
const Value = std.json.Value;
const assert = std.debug.assert;

/// Times every case of one fixture file and prints a `BENCH` line per case.
pub fn bench_file(
    io: Io,
    out: *Io.Writer,
    gpa: std.mem.Allocator,
    runner: *state_test.Runner,
    json: []const u8,
    target_ns: u64,
) !void {
    assert(target_ns > 0);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try std.json.parseFromSliceLeaky(Value, arena, json, .{});
    if (root != .object) return error.InvalidFixture;
    const names = try arena.dupe([]const u8, root.object.keys());
    std.mem.sort([]const u8, names, {}, less_than);
    for (names) |name| {
        const case = state_test.Case{ .name = name, .fixture = root.object.get(name).? };
        try bench_case(io, out, .{ .gpa = gpa, .arena = arena }, runner, case, target_ns);
    }
}

fn less_than(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

const Allocators = struct { gpa: std.mem.Allocator, arena: std.mem.Allocator };

fn bench_case(
    io: Io,
    out: *Io.Writer,
    allocators: Allocators,
    runner: *state_test.Runner,
    case: state_test.Case,
    target_ns: u64,
) !void {
    const post = state_test.field(case.fixture, "post") orelse return error.InvalidFixture;
    if (post != .object or post.object.count() == 0) return error.InvalidFixture;
    const fork = evm.Fork.from_test_name(post.object.keys()[0]) orelse
        return error.InvalidFixture;
    const posts = post.object.values()[0];
    if (posts != .array or posts.array.items.len == 0) return error.InvalidFixture;
    const expected = posts.array.items[0];
    const gpa = allocators.gpa;
    const arena = allocators.arena;
    const failure = try state_test.run_case(runner, arena, case, fork, expected);

    var database = evm.MemoryDatabase.init(arena);
    const pre = state_test.field(case.fixture, "pre") orelse return error.InvalidFixture;
    try state_test.load_pre(&database, arena, pre);
    const tx = try state_test.tx_env(arena, case.fixture, try state_test.parse_index(expected));
    // Tables sized from the gas as the node sizes them from the block gas limit. Larger
    // tables would be cleared (and pulled through the cache) by every untimed reset.
    const limits = evm.state.Limits.for_block_gas(tx.gas_limit);
    var state = try evm.State.init(gpa, database.interface(), limits);
    defer state.deinit(gpa);
    // Same memo setting as the conformance run (`statetest --no-keccak-memo`).
    const memo_entries = runner.evm.config.keccak_memo_entries;
    var machine = try evm.Evm.init(gpa, .{ .keccak_memo_entries = memo_entries }, &state);
    defer machine.deinit(gpa);
    machine.block = try state_test.block_env(fork, case.fixture);
    const timing = Timing{ .state = &state, .machine = &machine, .database = &database };
    const result = try timing.measure(io, fork, &tx, target_ns);
    assert(result.iterations >= 2);
    try out.print("BENCH case={s} iterations={d} gas={d} exec_ns={d} total_ns={d} ok={d}\n", .{
        case.name,
        result.iterations,
        result.gas,
        result.mean_ns,
        result.mean_ns,
        @intFromBool(failure == null),
    });
    try out.flush();
}

const Timing = struct {
    state: *evm.State,
    machine: *evm.Evm,
    database: *evm.MemoryDatabase,

    const Result = struct { iterations: u64, gas: u64, mean_ns: u64 };

    /// Warm up for `target_ns`, then run until the timed total reaches `target_ns`.
    fn measure(
        timing: Timing,
        io: Io,
        fork: evm.Fork,
        tx: *const evm.transaction.TxEnv,
        target_ns: u64,
    ) !Result {
        var gas: u64 = 0;
        const warm_up_start = now(io);
        while (now(io) - warm_up_start < target_ns) {
            _ = try timing.iteration(io, fork, tx, &gas);
        }
        var timed_ns: u64 = 0;
        var iterations: u64 = 0;
        while (timed_ns < target_ns or iterations < 2) : (iterations += 1) {
            timed_ns += try timing.iteration(io, fork, tx, &gas);
        }
        assert(iterations >= 2);
        return .{ .iterations = iterations, .gas = gas, .mean_ns = timed_ns / iterations };
    }

    /// Reset to the pre-state (untimed) and time one transaction.
    fn iteration(
        timing: Timing,
        io: Io,
        fork: evm.Fork,
        tx: *const evm.transaction.TxEnv,
        gas: *u64,
    ) !u64 {
        timing.state.reset(timing.database.interface());
        timing.machine.state = timing.state;
        const start = now(io);
        const result = try evm.transaction.transact(timing.machine, fork, tx);
        const elapsed = now(io) - start;
        switch (result) {
            .invalid => return error.InvalidTransaction,
            .executed => |executed| gas.* = executed.gas_used,
        }
        assert(gas.* <= tx.gas_limit);
        return elapsed;
    }
};

fn now(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

//! History store memory per retained block, run by `run` from `src/testing/bench_main.zig`
//! (through `bench.history`).
//!
//! State: the db bench state (`bench.shape_bench`: 100k accounts, 1k contracts x 64 slots).
//! Blocks are `bench.write_block` blocks (distinct existing accounts bump nonce and balance,
//! distinct existing slots increment): the storage-heavy block (1k accounts + 4k slots) and a
//! typical block (~200 transactions: 1k accounts + 1k slots). For each, a `history.Store`
//! with a `window_blocks` window is reset at the filled state, then `2 * window_blocks`
//! blocks are committed so the window is full and pruning is in steady state. Reported:
//! - state bytes: `bytes_used` right after `reset` (every node of the state once);
//! - bytes per block: (steady `bytes_used` - state bytes) / window, averaged over the last
//!   window of commits; also as wall-clock cost at 5 blocks/s (200 ms blocks);
//! - versions per block (`head_block_versions`) and `commit_block` time (p50, max);
//! - with `bytes_max` at the state plus half the steady window: the effective window.
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const history = @import("history.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Shape = bench.Shape;

pub const window_blocks_bench = 64;
/// L2 blocks per second at Base's native 200 ms block time.
pub const blocks_per_second = 5;

pub const shape_typical: Shape = blk: {
    var shape = bench.shape_bench;
    shape.block_slots = 1_000;
    break :blk shape;
};

const Case = struct { name: []const u8, shape: Shape };

pub const cases = [_]Case{
    .{ .name = "db/history typical 1k acct+1k slot", .shape = shape_typical },
    .{ .name = "db/history heavy 1k acct+4k slot", .shape = bench.shape_bench },
};

pub const Result = struct {
    window_blocks: u32,
    state_nodes: u32,
    state_bytes: u64,
    steady_bytes: u64,
    /// Paths after `reset` and at the end of the steady window (new paths per block).
    state_paths: u32,
    steady_paths: u32,
    bytes_per_block: u64,
    versions_per_block: u64,
    commit_ns_p50: u64,
    commit_ns_max: u64,
    /// Under `budget_bytes`: the shortest window seen and the blocks shrunk.
    budget_bytes: u64,
    budget_window_min: u64,
    budget_shrinks: u64,
};

const Fixture = struct {
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    store: history.Store,
    prng: Prng,
    shape: Shape,

    /// Fills the state, then starts the store at it. `self` must not move afterwards.
    fn init(self: *Fixture, allocator: std.mem.Allocator, shape: Shape, window: u32) !void {
        shape.check();
        self.shape = shape;
        self.prng = Prng.init(3);
        self.state = try State.init(allocator, bench.state_config(shape));
        errdefer self.state.deinit(allocator);
        self.overlay = try Overlay.init(allocator, &self.state, bench.overlay_config(shape));
        errdefer self.overlay.deinit(allocator);
        self.changeset = try Changeset.init(allocator, bench.changeset_config(shape));
        errdefer self.changeset.deinit(allocator);
        for (0..shape.fill_blocks()) |fill_index| {
            try bench.write_fill(&self.overlay, shape, @intCast(fill_index));
            _ = try self.overlay.commit(&self.changeset);
        }
        try self.state.state_trie.track_changes(allocator);
        self.store = try history.Store.init(allocator, store_config(&self.state, shape, window));
        errdefer self.store.deinit(allocator);
        try self.store.reset(&self.state.state_trie, 0);
        assert(self.store.window().?.head == 0);
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.store.deinit(allocator);
        self.changeset.deinit(allocator);
        self.overlay.deinit(allocator);
        self.state.deinit(allocator);
        self.* = undefined;
    }

    /// One block: overlay writes and state root (untimed), then the timed history commit.
    fn commit(self: *Fixture, io: std.Io, number: u64) !u64 {
        try bench.write_block(&self.overlay, self.shape, &self.prng);
        _ = try self.overlay.commit(&self.changeset);
        const start = bench.now_ns(io);
        try self.store.commit_block(&self.state.state_trie, number);
        const end = bench.now_ns(io);
        assert(end >= start);
        return end - start;
    }
};

/// Capacities sized like the store's "Sizing" rule with a generous per-block bound (the
/// arrays are lazily committed, so unused capacity costs address space only).
fn store_config(state: *const State, shape: Shape, window: u32) history.Config {
    const tries = &state.state_trie;
    const nodes: u64 = tries.accounts.node_count() + tries.storage.node_count();
    const per_block: u64 = 8 * (@as(u64, shape.block_accounts) + shape.block_slots);
    const total = nodes + window * per_block;
    assert(total < std.math.maxInt(u32) / 2);
    return .{
        .window_blocks = window,
        .paths_max = @intCast(total),
        .small_versions_max = @intCast(total),
        .large_versions_max = @intCast(total / 2),
        .prune_per_commit = @intCast(per_block),
    };
}

pub fn measure(io: std.Io, allocator: std.mem.Allocator, shape: Shape, window: u32) !Result {
    assert(window > 1);
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    try fixture.init(allocator, shape, window);
    defer fixture.deinit(allocator);
    const commit_ns = try allocator.alloc(u64, window);
    defer allocator.free(commit_ns);
    const state_bytes = fixture.store.bytes_used();
    const state_paths = fixture.store.usage().paths;
    var number: u64 = 0;
    // Fill the window, then one more window in steady state (measured).
    for (0..window) |_| {
        number += 1;
        _ = try fixture.commit(io, number);
    }
    var bytes_sum: u64 = 0;
    var versions_sum: u64 = 0;
    for (commit_ns) |*sample| {
        number += 1;
        sample.* = try fixture.commit(io, number);
        bytes_sum += fixture.store.bytes_used();
        versions_sum += fixture.store.head_block_versions();
    }
    const window_now = fixture.store.window().?;
    assert(window_now.head - window_now.oldest + 1 == window);
    const steady_bytes = bytes_sum / window;
    assert(steady_bytes > state_bytes);
    std.mem.sort(u64, commit_ns, {}, std.sort.asc(u64));
    var result: Result = .{
        .window_blocks = window,
        .state_nodes = fixture.store.base_node_count(),
        .state_bytes = state_bytes,
        .steady_bytes = steady_bytes,
        .state_paths = state_paths,
        .steady_paths = fixture.store.usage().paths,
        .bytes_per_block = (steady_bytes - state_bytes) / window,
        .versions_per_block = versions_sum / window,
        .commit_ns_p50 = commit_ns[window / 2],
        .commit_ns_max = commit_ns[window - 1],
        .budget_bytes = state_bytes + (steady_bytes - state_bytes) / 2,
        .budget_window_min = window,
        .budget_shrinks = 0,
    };
    try measure_budget(io, fixture, &result, number);
    return result;
}

/// Commits one more window under `result.budget_bytes`; records the shortest window.
fn measure_budget(io: std.Io, fixture: *Fixture, result: *Result, head: u64) !void {
    fixture.store.config.bytes_max = result.budget_bytes;
    var number = head;
    for (0..result.window_blocks) |_| {
        number += 1;
        _ = try fixture.commit(io, number);
        const window = fixture.store.window().?;
        assert(window.head == number);
        assert(fixture.store.bytes_used() <= result.budget_bytes);
        result.budget_window_min = @min(result.budget_window_min, window.head - window.oldest + 1);
    }
    result.budget_shrinks = fixture.store.window_shrinks;
    assert(result.budget_window_min < result.window_blocks);
}

/// Runs the history benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    for (cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        const allocator = std.heap.page_allocator;
        const result = measure(io, allocator, case.shape, window_blocks_bench) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
            continue;
        };
        print(case.name, &result);
    }
}

fn print(name: []const u8, result: *const Result) void {
    const mib = 1024.0 * 1024.0;
    const per_block: f64 = @floatFromInt(result.bytes_per_block);
    std.debug.print(
        "{s:<44} window {d}: state {d} nodes {d:.1} MiB, steady {d:.1} MiB, " ++
            "{d:.2} MiB/block ({d} versions), {d:.1} MiB/s at 200 ms, " ++
            "commit p50 {d:.2} ms max {d:.2} ms\n",
        .{
            name,
            result.window_blocks,
            result.state_nodes,
            @as(f64, @floatFromInt(result.state_bytes)) / mib,
            @as(f64, @floatFromInt(result.steady_bytes)) / mib,
            per_block / mib,
            result.versions_per_block,
            per_block * blocks_per_second / mib,
            @as(f64, @floatFromInt(result.commit_ns_p50)) / 1e6,
            @as(f64, @floatFromInt(result.commit_ns_max)) / 1e6,
        },
    );
    std.debug.print(
        "{s:<44} paths {d} -> {d}; budget {d:.1} MiB: window {d} blocks, {d} shrinks\n",
        .{
            name,
            result.state_paths,
            result.steady_paths,
            @as(f64, @floatFromInt(result.budget_bytes)) / mib,
            result.budget_window_min,
            result.budget_shrinks,
        },
    );
}

test "history bench: steady state and budget (small shape)" {
    const window = 8;
    const result = try measure(std.testing.io, std.testing.allocator, bench.shape_test, window);
    try std.testing.expect(result.bytes_per_block > 0);
    try std.testing.expect(result.versions_per_block > 0);
    try std.testing.expect(result.state_nodes > 0);
    try std.testing.expect(result.budget_window_min < window);
    try std.testing.expect(result.budget_shrinks > 0);
    for (cases) |case| try std.testing.expect(bench.matches(case.name, "db/history"));
}

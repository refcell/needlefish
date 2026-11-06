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
const StateTrie = @import("../trie/root.zig").StateTrie;

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
    run_proofs(io, filter);
}

/// `eth_getProof(contract, [k1..kn], older block)` from history: 1 account + n keys of one
/// contract (its 64 slots, the rest absent) at the block after the window's oldest.
const ProofCase = struct { name: []const u8, keys: u32 };

pub const proof_cases = [_]ProofCase{
    .{ .name = "db/history proof 1 acct+64 keys", .keys = 64 },
    .{ .name = "db/history proof 1 acct+256 keys", .keys = 256 },
};

/// Window of the proof benchmarks (heavy blocks; shorter than the memory benchmark's).
pub const proof_window_blocks = 16;
const proof_iterations = 64;

pub const ProofResult = struct {
    keys: u32,
    /// Old RPC path: an account proof, then `get_proof` per key (account + storage walk).
    per_key_ns_p50: u64,
    /// `get_proof` with every key at once (one account walk, one storage walk per key).
    per_slot_ns_p50: u64,
    /// `get_proofs` (one account walk, one sorted storage walk) plus `fill` of every key.
    multi_ns_p50: u64,
};

/// Proof buffers of the proof benchmarks (heap: proofs are large).
const ProofBuffers = struct {
    account: StateTrie.AccountProof = .{},
    storage: [256]StateTrie.StorageProof = undefined,
    values: [256]u256 = undefined,
    slots: [256]u256 = undefined,
};

pub fn measure_proofs(
    io: std.Io,
    allocator: std.mem.Allocator,
    shape: Shape,
    window: u32,
    keys: u32,
) !ProofResult {
    assert(keys > 0 and keys <= 256 and window > 1);
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    try fixture.init(allocator, shape, window);
    defer fixture.deinit(allocator);
    var number: u64 = 0;
    while (number < 2 * window) {
        number += 1;
        _ = try fixture.commit(io, number);
    }
    const buffers = try allocator.create(ProofBuffers);
    defer allocator.destroy(buffers);
    buffers.* = .{};
    for (buffers.slots[0..keys], 0..) |*slot, index| slot.* = index;
    var set = try history.ProofSet.init(allocator, keys);
    defer set.deinit(allocator);
    const samples = try allocator.alloc(u64, 3 * proof_iterations);
    defer allocator.free(samples);
    const at = fixture.store.window().?.oldest + 1;
    const proof_run: ProofRun = .{ .store = &fixture.store, .number = at, .keys = keys };
    for (0..proof_iterations) |index| {
        samples[index] = try proof_run.per_key(io, buffers);
        samples[proof_iterations + index] = try proof_run.per_slot(io, buffers);
        samples[2 * proof_iterations + index] = try proof_run.multi(io, buffers, &set);
    }
    return .{
        .keys = keys,
        .per_key_ns_p50 = median(samples[0..proof_iterations]),
        .per_slot_ns_p50 = median(samples[proof_iterations .. 2 * proof_iterations]),
        .multi_ns_p50 = median(samples[2 * proof_iterations ..]),
    };
}

fn median(samples: []u64) u64 {
    assert(samples.len > 0);
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[samples.len / 2];
}

/// One timed `eth_getProof` of the proof benchmarks, three ways.
const ProofRun = struct {
    store: *const history.Store,
    number: u64,
    keys: u32,

    const address = bench.address_of(0);

    fn per_key(self: ProofRun, io: std.Io, buffers: *ProofBuffers) !u64 {
        const start = bench.now_ns(io);
        _ = try self.store.get_proof(self.number, address, &.{}, &buffers.account, &.{}, &.{});
        for (buffers.slots[0..self.keys]) |slot| {
            const proofs = buffers.storage[0..1];
            const values = buffers.values[0..1];
            const slots = [1]u256{slot};
            const account = &buffers.account;
            _ = try self.store.get_proof(self.number, address, &slots, account, proofs, values);
        }
        const end = bench.now_ns(io);
        assert(buffers.account.count > 0);
        return end - start;
    }

    fn per_slot(self: ProofRun, io: std.Io, buffers: *ProofBuffers) !u64 {
        const slots = buffers.slots[0..self.keys];
        const proofs = buffers.storage[0..self.keys];
        const values = buffers.values[0..self.keys];
        const start = bench.now_ns(io);
        _ = try self.store.get_proof(self.number, address, slots, &buffers.account, proofs, values);
        const end = bench.now_ns(io);
        assert(buffers.storage[0].count > 0);
        return end - start;
    }

    fn multi(self: ProofRun, io: std.Io, buffers: *ProofBuffers, set: *history.ProofSet) !u64 {
        const slots = buffers.slots[0..self.keys];
        const start = bench.now_ns(io);
        _ = try self.store.get_proofs(self.number, address, slots, &buffers.account, set);
        for (0..self.keys) |index| {
            set.fill(@intCast(index), &buffers.storage[0]);
            buffers.values[0] = set.value(@intCast(index));
        }
        const end = bench.now_ns(io);
        assert(buffers.storage[0].count > 0);
        return end - start;
    }
};

fn run_proofs(io: std.Io, filter: ?[]const u8) void {
    for (proof_cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        const allocator = std.heap.page_allocator;
        const shape = bench.shape_bench;
        const window = proof_window_blocks;
        const result = measure_proofs(io, allocator, shape, window, case.keys) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
            continue;
        };
        std.debug.print(
            "{s:<44} at oldest+1: per-key {d:.1} us, per-slot {d:.1} us, " ++
                "multi {d:.1} us ({d:.1}x vs per-key)\n",
            .{
                case.name,
                @as(f64, @floatFromInt(result.per_key_ns_p50)) / 1e3,
                @as(f64, @floatFromInt(result.per_slot_ns_p50)) / 1e3,
                @as(f64, @floatFromInt(result.multi_ns_p50)) / 1e3,
                @as(f64, @floatFromInt(result.per_key_ns_p50)) /
                    @as(f64, @floatFromInt(@max(result.multi_ns_p50, 1))),
            },
        );
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

test "history bench: multi-key proofs (small shape)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const result = try measure_proofs(io, allocator, bench.shape_test, 4, 32);
    try std.testing.expectEqual(@as(u32, 32), result.keys);
    for (proof_cases) |case| try std.testing.expect(bench.matches(case.name, "db/history"));
}

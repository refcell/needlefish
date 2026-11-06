//! `debug_executionWitness` end to end for the head block and head - 1, run by `run` from
//! `src/testing/bench_main.zig` (through `bench.witness_rpc`).
//!
//! State: the db bench state (`bench.shape_bench`: 100k accounts, 1k contracts x 64 slots)
//! with a `history.Store` (window `window_blocks`) started at it; `blocks_count` blocks of
//! `bench.write_block` writes are committed to the state and history, so the head block
//! and head - 1 both have their parent in the window and witness from history (no state
//! disturbance, the node's path for every block a prover asks for). Two block shapes: the
//! typical block (1k accounts + 1k slots) and the heavy block (1k accounts + 4k slots).
//!
//! The executor replays the block's committed changeset through an evm `State` over the
//! generator's recorded database (load + write of every changed account and slot): the
//! read and write set of real execution without the interpreter, so "execute" here is a
//! lower bound of a real block's re-execution (the evm cost of `db/witness` "evm block").
//!
//! Steps per sample (medians of `samples_count`, ReleaseFast):
//! - `Generator.generate_history` total, split into execute (the callback, timed inside),
//!   `Builder.build_from` (timed again on its own over the same inputs), and the rest
//!   (`commit_evm` + history changeset + headers: total - execute - build);
//! - JSON: `witness_json.length` and the `{state, codes, keys, headers}` hex object written
//!   into a response-sized `std.Io.Writer` through `json.Writer` (what `rpc/debug.zig`
//!   does), with the per-byte reference writer (`write_json_reference`) and the current one.
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const history = @import("history.zig");
const history_bench = @import("history_bench.zig");
const witness = @import("witness.zig");
const witness_block = @import("witness_block.zig");
const witness_json = @import("witness_json.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const evm = @import("../evm/root.zig");
const json = @import("../../utilities/json/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Generator = witness_block.Generator;
const Hash = state_module.Hash;
const Shape = bench.Shape;

pub const samples_count = 11;
const window_blocks = 4;
/// Committed blocks; the head and head - 1 are witnessed.
const blocks_count = 4;
/// A mainnet-sized RLP header (the builder copies headers, it does not parse them).
const header_bytes = 600;

comptime {
    assert(blocks_count >= 3 and blocks_count <= window_blocks);
}

const Case = struct { name: []const u8, shape: Shape };

pub const cases = [_]Case{
    .{ .name = "db/witness rpc typical 1k acct+1k slot", .shape = history_bench.shape_typical },
    .{ .name = "db/witness rpc heavy 1k acct+4k slot", .shape = bench.shape_bench },
};

const Metric = enum(u8) {
    total,
    execute,
    build,
    /// total - execute - build: `commit_evm`, the history changeset, headers.
    rest,
    length,
    json_reference,
    json,
    /// total + length + json: the handler's work for one call.
    end_to_end,
};
const metrics_count = std.enums.values(Metric).len;

const Report = struct {
    times_ns: [metrics_count][samples_count]u64 = @splat(@splat(0)),
    nodes: u32 = 0,
    keys: u32 = 0,
    json_bytes: u64 = 0,

    fn set(report: *Report, metric: Metric, sample: u32, duration_ns: u64) void {
        assert(sample < samples_count);
        report.times_ns[@backingInt(metric)][sample] = duration_ns;
    }

    fn median_us(report: *Report, metric: Metric) f64 {
        const samples = &report.times_ns[@backingInt(metric)];
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        const median = samples[samples_count / 2];
        return @as(f64, @floatFromInt(median)) / 1000.0;
    }

    /// The fastest sample: the least disturbed by other load on the machine.
    fn min_us(report: *Report, metric: Metric) f64 {
        const samples = &report.times_ns[@backingInt(metric)];
        return @as(f64, @floatFromInt(std.mem.min(u64, samples))) / 1000.0;
    }
};

pub const Fixture = struct {
    shape: Shape,
    prng: Prng,
    state: State,
    overlay: Overlay,
    /// Committed changesets by block number modulo `blocks_count`.
    changesets: [blocks_count]Changeset,
    store: history.Store,
    generator: Generator,
    evm_state: evm.State,
    head: u64 = 0,
    /// The block the executor replays, and the time of its last run.
    executing: u64 = 0,
    execute_ns: u64 = 0,
    io: std.Io,
    header: [header_bytes]u8 = @splat(0xab),
    response: []u8,

    /// Fills the state, starts history at it, and commits `blocks_count` blocks. `self`
    /// must not move afterwards.
    pub fn init(
        self: *Fixture,
        allocator: std.mem.Allocator,
        io: std.Io,
        shape: Shape,
        seed: u64,
    ) !void {
        shape.check();
        self.* = .{
            .shape = shape,
            .prng = Prng.init(seed),
            .state = try State.init(allocator, bench.state_config(shape)),
            .overlay = undefined,
            .changesets = undefined,
            .store = undefined,
            .generator = undefined,
            .evm_state = undefined,
            .io = io,
            .response = undefined,
        };
        self.overlay = try Overlay.init(allocator, &self.state, bench.overlay_config(shape));
        for (&self.changesets) |*changeset| {
            changeset.* = try Changeset.init(allocator, bench.changeset_config(shape));
        }
        for (0..shape.fill_blocks()) |fill_index| {
            try bench.write_fill(&self.overlay, shape, @intCast(fill_index));
            _ = try self.overlay.commit(&self.changesets[0]);
        }
        try self.state.state_trie.track_changes(allocator);
        self.store = try history.Store.init(allocator, store_config(&self.state, shape));
        try self.store.reset(&self.state.state_trie, 0);
        self.generator = try Generator.init(allocator, &self.state, generator_config(shape));
        const database = evm_backend.database(&self.state);
        self.evm_state = try evm.State.init(allocator, database, evm_limits(shape));
        self.response = try allocator.alloc(u8, response_bytes(shape));
        for (0..blocks_count) |_| try self.commit();
        assert(self.head == blocks_count);
    }

    pub fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.free(self.response);
        self.evm_state.deinit(allocator);
        self.generator.deinit(allocator);
        self.store.deinit(allocator);
        for (&self.changesets) |*changeset| changeset.deinit(allocator);
        self.overlay.deinit(allocator);
        self.state.deinit(allocator);
        self.* = undefined;
    }

    /// One `bench.write_block` block, committed to the state and history.
    pub fn commit(self: *Fixture) !void {
        self.head += 1;
        try bench.write_block(&self.overlay, self.shape, &self.prng);
        const changeset = &self.changesets[self.head % blocks_count];
        _ = try self.overlay.commit(changeset);
        try self.store.commit_block(&self.state.state_trie, self.head);
        assert(self.store.window().?.head == self.head);
    }

    /// The witness of block `number` from history; returns the post-state root.
    pub fn generate(self: *Fixture, number: u64) !Hash {
        assert(number + blocks_count > self.head and number <= self.head);
        self.executing = number;
        const execute: witness_block.Execute = .{ .context = self, .run = run_block };
        const blocks_view = self.blocks();
        const generator = &self.generator;
        const root = try generator.generate_history(&self.store, number, blocks_view, execute);
        assert(self.generator.source.? == .history);
        return root;
    }

    fn blocks(self: *const Fixture) witness_block.Blocks {
        return .{ .context = self, .hash = block_hash, .header = block_header };
    }

    fn block_hash(context: *const anyopaque, number: u64) ?Hash {
        var hash: Hash = @splat(0);
        std.mem.writeInt(u64, hash[0..8], number, .big);
        _ = context;
        return hash;
    }

    fn block_header(context: *const anyopaque, number: u64) ?[]const u8 {
        const self: *const Fixture = @ptrCast(@alignCast(context));
        assert(number < self.head);
        return &self.header;
    }

    /// The executor: loads and rewrites every account and slot the block changed.
    fn run_block(
        context: *anyopaque,
        database: evm.state.Database,
    ) witness_block.ExecuteError!*const evm.State {
        const self: *Fixture = @ptrCast(@alignCast(context));
        const start = bench.now_ns(self.io);
        defer self.execute_ns = bench.now_ns(self.io) - start;
        const changeset = &self.changesets[self.executing % blocks_count];
        const state = &self.evm_state;
        state.reset(database);
        state.begin_transaction();
        replay_writes(state, changeset) catch return error.ExecutionFailed;
        assert(state.accounts.count() >= changeset.account_changes().len);
        return state;
    }
};

fn replay_writes(state: *evm.State, changeset: *const Changeset) evm.state.Error!void {
    for (changeset.account_changes()) |*change| {
        const account = try state.load(change.address);
        const new = change.new.?;
        try state.set_nonce(account, new.nonce);
        try state.set_balance(account, new.balance);
    }
    for (changeset.storage_changes()) |*change| {
        const account = try state.load(change.address);
        const access = try state.storage_access(account, change.slot);
        try state.storage_write(account, access.slot, change.new);
    }
}

fn store_config(state: *const State, shape: Shape) history.Config {
    const tries = &state.state_trie;
    const nodes: u64 = tries.accounts.node_count() + tries.storage.node_count();
    const per_block: u64 = 8 * (@as(u64, shape.block_accounts) + shape.block_slots);
    const total = nodes + window_blocks * per_block;
    assert(total < std.math.maxInt(u32) / 2);
    return .{
        .window_blocks = window_blocks,
        .paths_max = @intCast(total),
        .small_versions_max = @intCast(total),
        .large_versions_max = @intCast(total / 2),
        .prune_per_commit = @intCast(per_block),
    };
}

fn generator_config(shape: Shape) witness_block.Config {
    // Written slots touch their contracts too.
    const accounts = shape.block_accounts + shape.contracts + 16;
    const slots = shape.block_slots + 16;
    // ~1-3 distinct proof nodes per touched key (`db/witness` bench); 3 per key + slack.
    const nodes = 3 * (accounts + slots) + 1024;
    const node_bytes = nodes * 600;
    return .{
        .builder = .{
            .sparse = .{
                .nodes_max = nodes,
                .node_bytes_max = node_bytes,
                .codes_max = 4,
                .code_bytes_max = 4 * 1024,
                .headers_max = 4,
                .trie_nodes_max = 5 * nodes,
                .storage_tries_max = shape.contracts + 16,
            },
            .keys = .{
                .accounts_max = accounts,
                .slots_max = slots,
                .codes_max = 16,
                .block_numbers_max = 16,
            },
        },
        .witness = .{
            .state_nodes_max = nodes,
            .state_bytes_max = node_bytes,
            .codes_max = 4,
            .code_bytes_max = 4 * 1024,
            .keys_max = accounts + slots,
            .headers_max = 4,
            .header_bytes_max = 4 * header_bytes,
        },
        .overlay = bench.overlay_config(shape),
        .changeset = bench.changeset_config(shape),
        .depth_max = blocks_count,
    };
}

fn evm_limits(shape: Shape) evm.state.Limits {
    const accounts = shape.block_accounts + shape.contracts + 64;
    const slots = shape.block_slots + 64;
    return .{
        .accounts_max = accounts,
        .slots_max = slots,
        .transient_slots_max = 16,
        .journal_entries_max = 2 * accounts + 2 * slots,
        .logs_max = 16,
        .log_data_bytes_max = 1024,
        .code_bytes_max = 4096,
    };
}

/// Room for the largest JSON witness of `shape` (2 hex chars per witness byte + framing).
fn response_bytes(shape: Shape) usize {
    const config = generator_config(shape).witness;
    const items: usize = config.state_nodes_max + config.codes_max + config.keys_max +
        config.headers_max;
    const bytes: usize = config.state_bytes_max + config.code_bytes_max +
        32 * @as(usize, config.keys_max) + config.header_bytes_max;
    return 2 * bytes + 5 * items + 256;
}

/// The result object as `rpc/debug.zig` writes it, through `json.Writer` into `out`.
pub fn write_json(built: *const witness.Witness, out: []u8) ![]const u8 {
    var buffer: std.Io.Writer = .fixed(out);
    var w: json.Writer = .init(&buffer);
    try w.begin_object();
    for (lists_of(built)) |entry| {
        const name, const list = entry;
        try w.key(name);
        try w.begin_array();
        var index: u32 = 0;
        while (index < list.count) : (index += 1) try w.data(list.get(index));
        try w.end_array();
    }
    try w.end_object();
    assert(buffer.end == witness_json.length(built));
    return buffer.buffered();
}

/// The same object with the `json.Writer.data` this bench started from: one `writeByte`
/// per hex digit. The reference for the byte-identical check and the before/after numbers.
pub fn write_json_reference(built: *const witness.Witness, out: []u8) ![]const u8 {
    const hex_digits = "0123456789abcdef";
    var w: std.Io.Writer = .fixed(out);
    try w.writeByte('{');
    for (lists_of(built), 0..) |entry, list_index| {
        const name, const list = entry;
        if (list_index > 0) try w.writeByte(',');
        try w.print("\"{s}\":[", .{name});
        var index: u32 = 0;
        while (index < list.count) : (index += 1) {
            if (index > 0) try w.writeByte(',');
            try w.writeAll("\"0x");
            for (list.get(index)) |byte| {
                try w.writeByte(hex_digits[byte >> 4]);
                try w.writeByte(hex_digits[byte & 0xf]);
            }
            try w.writeByte('"');
        }
        try w.writeByte(']');
    }
    try w.writeByte('}');
    assert(w.end == witness_json.length(built));
    return w.buffered();
}

const List = struct { []const u8, *const witness.ByteList };

fn lists_of(built: *const witness.Witness) [4]List {
    return .{
        .{ "state", &built.state },
        .{ "codes", &built.codes },
        .{ "keys", &built.keys },
        .{ "headers", &built.headers },
    };
}

fn lap(io: std.Io, report: *Report, metric: Metric, sample: u32, start: u64) u64 {
    const now = bench.now_ns(io);
    assert(now >= start);
    report.set(metric, sample, now - start);
    return now;
}

/// One sample of every metric for block `number`; checks the JSON is byte-identical.
fn measure_sample(fixture: *Fixture, number: u64, report: *Report, sample: u32) !void {
    const io = fixture.io;
    const generator = &fixture.generator;
    var clock = bench.now_ns(io);
    const root = try fixture.generate(number);
    clock = lap(io, report, .total, sample, clock);
    report.set(.execute, sample, fixture.execute_ns);
    const source: witness.HistorySource = .{
        .store = &fixture.store,
        .number = number - 1,
        .codes = &fixture.state,
    };
    const headers = generator.headers[0..generator.witness.headers.count];
    clock = bench.now_ns(io);
    const rebuilt = try generator.builder.build_from(
        source,
        &generator.recorder.keys,
        &generator.changeset_built,
        headers,
        &generator.witness,
    );
    clock = lap(io, report, .build, sample, clock);
    if (!std.mem.eql(u8, &rebuilt, &root)) return error.RootMismatch;
    const length = witness_json.length(&generator.witness);
    clock = lap(io, report, .length, sample, clock);
    const half = fixture.response.len / 2;
    const reference = try write_json_reference(&generator.witness, fixture.response[0..half]);
    clock = lap(io, report, .json_reference, sample, clock);
    const current = try write_json(&generator.witness, fixture.response[half..]);
    clock = lap(io, report, .json, sample, clock);
    if (!std.mem.eql(u8, reference, current)) return error.JsonMismatch;
    derive(report, sample);
    assert(current.len == length);
    report.nodes = generator.witness.state.count;
    report.keys = generator.witness.keys.count;
    report.json_bytes = length;
}

fn derive(report: *Report, sample: u32) void {
    const times = &report.times_ns;
    const total = times[@backingInt(Metric.total)][sample];
    const parts = times[@backingInt(Metric.execute)][sample] +
        times[@backingInt(Metric.build)][sample];
    report.set(.rest, sample, total -| parts);
    const handler = total + times[@backingInt(Metric.length)][sample] +
        times[@backingInt(Metric.json)][sample];
    report.set(.end_to_end, sample, handler);
}

fn measure_block(fixture: *Fixture, number: u64, report: *Report) !void {
    try measure_sample(fixture, number, report, 0); // Warm up.
    for (0..samples_count) |sample| try measure_sample(fixture, number, report, @intCast(sample));
    assert(report.nodes > 0 and report.json_bytes > 0);
}

const rows = [_]struct { Metric, []const u8 }{
    .{ .total, "generate_history total" },
    .{ .execute, "  execute (recorded history reads)" },
    .{ .build, "  Builder.build_from (timed alone)" },
    .{ .rest, "  commit_evm + history changeset + headers" },
    .{ .length, "witness_json length" },
    .{ .json_reference, "JSON write, reference per-byte writer" },
    .{ .json, "JSON write, json.Writer.data" },
    .{ .end_to_end, "end to end (generate + length + JSON)" },
};

fn print_report(name: []const u8, label: []const u8, report: *Report) void {
    std.debug.print("{s} {s}: nodes {d}  keys {d}  json {d} bytes (median / min us)\n", .{
        name, label, report.nodes, report.keys, report.json_bytes,
    });
    for (rows) |row| {
        const metric, const title = row;
        std.debug.print("  {s:<44} {d:>10.1} / {d:>10.1}\n", .{
            title, report.median_us(metric), report.min_us(metric),
        });
    }
}

/// Runs the witness rpc benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    for (cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        run_case(io, std.heap.page_allocator, case, true) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
        };
    }
}

fn run_case(io: std.Io, allocator: std.mem.Allocator, case: Case, print: bool) !void {
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    try fixture.init(allocator, io, case.shape, 9);
    defer fixture.deinit(allocator);
    const report = try allocator.create(Report);
    defer allocator.destroy(report);
    const labels = [_][]const u8{ "head", "head-1" };
    for (labels, 0..) |label, back| {
        report.* = .{};
        try measure_block(fixture, fixture.head - back, report);
        if (print) print_report(case.name, label, report);
    }
}

test "witness rpc bench: head and head-1 from history, JSON identical (small shape)" {
    const case: Case = .{ .name = cases[0].name, .shape = bench.shape_test };
    try run_case(std.testing.io, std.testing.allocator, case, false);
    try std.testing.expect(bench.matches(cases[1].name, "db/witness"));
}

/// The witness JSON of block `number` into `out` (current writer), checked against the
/// per-byte reference written into `scratch`.
fn checked_json(fixture: *Fixture, number: u64, out: []u8, scratch: []u8) ![]const u8 {
    _ = try fixture.generate(number);
    const built = &fixture.generator.witness;
    const current = try write_json(built, out);
    try std.testing.expectEqualStrings(try write_json_reference(built, scratch), current);
    return current;
}

test "witness rpc bench: seeded blocks: JSON equals the reference, stable across commits" {
    const allocator = std.testing.allocator;
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    for ([_]u64{ 0x11, 0x22, 0x33 }) |seed| {
        try fixture.init(allocator, std.testing.io, bench.shape_test, seed);
        defer fixture.deinit(allocator);
        const size = fixture.response.len / 3;
        const before = fixture.response[0..size];
        const after = fixture.response[size .. 2 * size];
        const scratch = fixture.response[2 * size ..];
        for (0..3) |_| {
            // Head - 1 again after one more commit: history moved (the verified-node cache
            // and the memo start over), the witness must not.
            const number = fixture.head;
            const first = try checked_json(fixture, number, before, scratch);
            try fixture.commit();
            const second = try checked_json(fixture, number, after, scratch);
            try std.testing.expectEqualStrings(first, second);
            _ = try checked_json(fixture, fixture.head, after, scratch);
        }
    }
}

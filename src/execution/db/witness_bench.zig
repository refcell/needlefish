//! Execution witness benchmarks: size and build time per block, run by `run` from
//! `src/testing/bench_main.zig` (through `bench.witness`).
//!
//! State: the db bench state (`bench.shape_bench`: 100k accounts, 1k contracts x 64 slots),
//! with every contract running `witness_evm_test.code_storage` (`old = SLOAD(cd[0]);
//! SSTORE(cd[0], cd[32]); LOG1`). Blocks, each built once and then measured `samples_count`
//! times without being committed (the pre-state never changes):
//! - 1k account writes, and 1k account writes + 4k slot writes (`bench.write_block`);
//!   their "execution" reads every written key once (old value), as the evm would.
//! - 200 calls from distinct senders to distinct contracts through the real evm.
//! Per block it reports the witness shape (state nodes, canonical encoded bytes, codes,
//! keys) and medians of: reads/execution over the plain backend vs through
//! `witness.Recorder` (the recorder's overhead), `Builder.build` (root verified) and
//! `Builder.build_with` with `verify_root = false` (same witness), codec encode/decode,
//! `SparseState` load + `witness.replay`, and (evm block) stateless re-execution.
//!
//! Benchmark scaffolding: fixtures come from the page allocator, sized from the shape.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const witness = @import("witness.zig");
const witness_codec = @import("witness_codec.zig");
const witness_evm_test = @import("witness_evm_test.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const evm = @import("../evm/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Hash = state_module.Hash;
const TxEnv = evm.transaction.TxEnv;
const Shape = bench.Shape;

pub const samples_count = 11;
const calls_max = 200;
const call_gas_limit: u64 = 100_000;
const calldata_bytes = 64;
const coinbase: state_module.Address = @splat(0xc0);

const Kind = enum { writes, calls };

const Spec = struct {
    name: []const u8,
    kind: Kind,
    block_accounts: u32 = 0,
    block_slots: u32 = 0,
};

pub const specs = [_]Spec{
    .{ .name = "db/witness 1k acct", .kind = .writes, .block_accounts = 1_000 },
    .{
        .name = "db/witness 1k acct+4k slot",
        .kind = .writes,
        .block_accounts = 1_000,
        .block_slots = 4_000,
    },
    .{ .name = "db/witness 200 evm SLOAD+SSTORE calls", .kind = .calls },
};

const Metric = enum(u8) {
    reads_plain,
    reads_recorded,
    build,
    build_unverified,
    builder_reset,
    reset,
    encode,
    decode,
    load,
    replay,
    stateless,
};
const metrics_count = std.enums.values(Metric).len;

/// Bench witnesses carry no headers (no BLOCKHASH), so the bound parent is never linked.
const no_headers_parent: witness.SparseState.Parent = .{ .number = 0, .hash = @splat(0) };

/// One block's witness shape and per-sample durations.
const Report = struct {
    nodes: u32 = 0,
    codes: u32 = 0,
    keys: u32 = 0,
    encoded_bytes: u32 = 0,
    /// Sparse trie pool nodes in use after the builder's replay and the verifier's replay.
    builder_trie_used: u32 = 0,
    trie_used: u32 = 0,
    trie_capacity: u32 = 0,
    times_ns: [metrics_count][samples_count]u64 = @splat(@splat(0)),

    fn set(report: *Report, metric: Metric, sample: u32, duration_ns: u64) void {
        assert(sample < samples_count);
        report.times_ns[@backingInt(metric)][sample] = duration_ns;
    }

    /// Median in microseconds (sorts that metric's samples).
    fn median_us(report: *Report, metric: Metric) f64 {
        const samples = &report.times_ns[@backingInt(metric)];
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        assert(samples[0] <= samples[samples_count - 1]);
        return @as(f64, @floatFromInt(samples[samples_count / 2])) / 1e3;
    }
};

/// Witness capacities for the largest block of `shape` (the storage-heavy block touches
/// every contract; the evm block touches `calls` senders and contracts).
const Limits = struct {
    keys: witness.KeySet.Config,
    sparse: witness.SparseState.Config,
    witness: witness.Witness.Config,
    encoded_bytes_max: u32,

    fn of(shape: Shape) Limits {
        const accounts = shape.block_accounts + shape.contracts + 2 * calls_max + 16;
        const slots = shape.block_slots + calls_max + 16;
        // Measured: ~1-3 distinct proof nodes per touched key at these sizes (nodes near
        // the roots are shared); 3 per key plus slack.
        const nodes = 3 * (accounts + slots) + 1024;
        const node_bytes = nodes * 600;
        const witness_config: witness.Witness.Config = .{
            .state_nodes_max = nodes,
            .state_bytes_max = node_bytes,
            .codes_max = 4,
            .code_bytes_max = 4 * 1024,
            .keys_max = accounts + slots,
            .headers_max = 1,
            .header_bytes_max = 64,
        };
        const encoded = witness_codec.prefix_bytes +
            witness_codec.sections_count * witness_codec.section_prefix_bytes +
            witness_codec.item_prefix_bytes * (nodes + 4 + accounts + slots + 1) +
            node_bytes + 4 * 1024 + 32 * (accounts + slots) + 64;
        return .{
            .keys = .{
                .accounts_max = accounts,
                .slots_max = slots,
                .codes_max = 16,
                .block_numbers_max = 16,
            },
            .sparse = .{
                .nodes_max = nodes,
                .node_bytes_max = node_bytes,
                .codes_max = 4,
                .code_bytes_max = 4 * 1024,
                .headers_max = 1,
                // A decoded branch holds up to 16 unresolved children; measured use is
                // ~3.5 pool nodes per witness node (`trie_used` in the report).
                .trie_nodes_max = 5 * nodes,
                .storage_tries_max = shape.contracts + calls_max + 16,
            },
            .witness = witness_config,
            .encoded_bytes_max = encoded,
        };
    }
};

fn evm_limits(calls: u32) evm.state.Limits {
    return .{
        .accounts_max = 4 * calls + 64,
        .slots_max = 2 * calls + 64,
        .transient_slots_max = 16,
        .journal_entries_max = 64 * calls + 1024,
        .logs_max = 2 * calls + 16,
        .log_data_bytes_max = 32 * (2 * calls + 16),
        .code_bytes_max = 4096,
    };
}

const Fixture = struct {
    shape: Shape,
    calls: u32,
    prng: Prng,
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    plain: evm.state.Database,
    recorder: witness.Recorder,
    builder: witness.Builder,
    built: witness.Witness,
    decoded: witness.Witness,
    encoder: witness_codec.Encoder,
    encoded: []u8,
    sparse: witness.SparseState,
    sparse_changeset: Changeset,
    evm_state: evm.State,
    machine: evm.Evm,
    txs: []TxEnv,
    calldata: [][calldata_bytes]u8,
    pre_root: Hash,

    /// In place: the overlay, recorder, and evm point into the fixture.
    fn init(fixture: *Fixture, allocator: std.mem.Allocator, shape: Shape) !void {
        shape.check();
        const limits = Limits.of(shape);
        const calls: u32 = @min(calls_max, shape.contracts);
        // Senders are the plain accounts right after the contracts.
        assert(shape.contracts + calls <= shape.accounts);
        fixture.shape = shape;
        fixture.calls = calls;
        fixture.prng = Prng.init(5);
        fixture.state = try State.init(allocator, bench.state_config(shape));
        const overlay_config = bench.overlay_config(shape);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, overlay_config);
        fixture.changeset = try Changeset.init(allocator, bench.changeset_config(shape));
        fixture.plain = evm_backend.database(&fixture.state);
        fixture.recorder = try witness.Recorder.init(allocator, fixture.plain, limits.keys);
        fixture.builder = try witness.Builder.init(allocator, .{
            .sparse = limits.sparse,
            .keys = limits.keys,
        });
        fixture.built = try witness.Witness.init(allocator, limits.witness);
        fixture.decoded = try witness.Witness.init(allocator, limits.witness);
        fixture.encoder = try witness_codec.Encoder.init(allocator, limits.witness);
        fixture.encoded = try allocator.alloc(u8, limits.encoded_bytes_max);
        fixture.sparse = try witness.SparseState.init(allocator, limits.sparse);
        const sparse_changeset = bench.changeset_config(shape);
        fixture.sparse_changeset = try Changeset.init(allocator, sparse_changeset);
        fixture.evm_state = try evm.State.init(allocator, fixture.plain, evm_limits(calls));
        const evm_config = witness_evm_test.evm_config;
        fixture.machine = try evm.Evm.init(allocator, evm_config, &fixture.evm_state);
        fixture.txs = try allocator.alloc(TxEnv, calls);
        fixture.calldata = try allocator.alloc([calldata_bytes]u8, calls);
        try fixture.fill();
        fixture.pre_root = try fixture.state.state_root();
    }

    fn deinit(fixture: *Fixture, allocator: std.mem.Allocator) void {
        allocator.free(fixture.calldata);
        allocator.free(fixture.txs);
        fixture.machine.deinit(allocator);
        fixture.evm_state.deinit(allocator);
        fixture.sparse_changeset.deinit(allocator);
        fixture.sparse.deinit(allocator);
        allocator.free(fixture.encoded);
        fixture.encoder.deinit(allocator);
        fixture.decoded.deinit(allocator);
        fixture.built.deinit(allocator);
        fixture.builder.deinit(allocator);
        fixture.recorder.deinit(allocator);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
        fixture.* = undefined;
    }

    /// The db bench setup blocks, then one block giving every contract the storage code.
    fn fill(fixture: *Fixture) !void {
        const shape = fixture.shape;
        for (0..shape.fill_blocks()) |fill_index| {
            try bench.write_fill(&fixture.overlay, shape, @intCast(fill_index));
            _ = try fixture.overlay.commit(&fixture.changeset);
        }
        const code_hash = try fixture.overlay.insert_code(&witness_evm_test.code_storage);
        for (0..shape.contracts) |contract| {
            const address = bench.address_of(contract);
            var info = fixture.overlay.basic(address).?;
            info.code_hash = code_hash;
            try fixture.overlay.set_account(address, info);
        }
        _ = try fixture.overlay.commit(&fixture.changeset);
        assert(fixture.state.account_table.count() == shape.accounts);
        assert(fixture.state.storage_table.count() == shape.slots());
    }

    /// Builds the block's changeset; the overlay is discarded (nothing is committed).
    fn prepare(fixture: *Fixture, spec: *const Spec) !void {
        switch (spec.kind) {
            .writes => {
                var shape = fixture.shape;
                // Small shapes (tests) cap the block at the overlay's capacity.
                const accounts_max = @max(shape.block_accounts, shape.fill_accounts);
                const slots_max = @max(shape.block_slots, shape.fill_slots());
                shape.block_accounts = @min(spec.block_accounts, accounts_max);
                shape.block_slots = @min(spec.block_slots, slots_max);
                try bench.write_block(&fixture.overlay, shape, &fixture.prng);
            },
            .calls => {
                fixture.generate_calls();
                try fixture.execute(fixture.plain);
                try evm_backend.commit_evm(&fixture.evm_state, &fixture.overlay);
            },
        }
        try fixture.overlay.build_changeset(&fixture.changeset);
        fixture.overlay.discard();
        assert(fixture.changeset.account_changes().len > 0);
    }

    /// Call `i`: sender `contracts + i` (nonce 1, free gas) calls contract
    /// `i * contracts / calls` to overwrite one random existing slot.
    fn generate_calls(fixture: *Fixture) void {
        const shape = fixture.shape;
        for (fixture.txs, fixture.calldata, 0..) |*tx, *calldata, index| {
            const contract = index * shape.contracts / fixture.calls;
            const slot = fixture.prng.below(shape.slots_per_contract);
            std.mem.writeInt(u256, calldata[0..32], slot, .big);
            const value = fixture.prng.range(1 << 32, 1 << 40);
            std.mem.writeInt(u256, calldata[32..64], value, .big);
            tx.* = .{
                .caller = bench.address_of(shape.contracts + index),
                .gas_limit = call_gas_limit,
                .gas_price = 0,
                .to = bench.address_of(contract),
                .data = calldata,
                .nonce = 1,
            };
        }
    }

    /// Runs the block's calls over `database`; every call must succeed.
    fn execute(fixture: *Fixture, database: evm.state.Database) !void {
        fixture.evm_state.reset(database);
        fixture.machine.block = .{ .number = 1, .timestamp = 2, .coinbase = coinbase };
        for (fixture.txs) |*tx| {
            const result = try evm.transaction.transact(
                &fixture.machine,
                witness_evm_test.fork,
                tx,
            );
            switch (result) {
                .invalid => return error.InvalidTransaction,
                .executed => |executed| {
                    if (executed.status != .success) return error.CallFailed;
                },
            }
        }
    }

    /// The writes block's "execution": reads every written key's old value once.
    fn read_keys(fixture: *Fixture, database: evm.state.Database) !u64 {
        var accumulator: u64 = 0;
        for (fixture.changeset.account_changes()) |*change| {
            const info = try database.basic(change.address) orelse continue;
            accumulator +%= info.nonce;
        }
        for (fixture.changeset.storage_changes()) |*change| {
            accumulator +%= @truncate(try database.storage(change.address, change.slot));
        }
        assert(fixture.changeset.account_changes().len > 0);
        return accumulator;
    }

    fn run_reads(fixture: *Fixture, kind: Kind, database: evm.state.Database) !void {
        switch (kind) {
            .writes => std.mem.doNotOptimizeAway(try fixture.read_keys(database)),
            .calls => try fixture.execute(database),
        }
    }
};

/// One sample of every metric; checks the witness-only roots against the builder's.
fn measure_sample(
    io: std.Io,
    fixture: *Fixture,
    kind: Kind,
    report: *Report,
    sample: u32,
) !void {
    // Warm caches first, so neither timed pass pays for the other's evictions.
    try fixture.run_reads(kind, fixture.plain);
    var clock: u64 = bench.now_ns(io);
    try fixture.run_reads(kind, fixture.plain);
    clock = lap(io, report, .reads_plain, sample, clock);
    fixture.recorder.keys.clear();
    try fixture.run_reads(kind, fixture.recorder.database());
    clock = lap(io, report, .reads_recorded, sample, clock);
    const keys = &fixture.recorder.keys;
    const post_root = try fixture.builder.build(
        &fixture.state,
        keys,
        &fixture.changeset,
        &.{},
        &fixture.built,
    );
    clock = lap(io, report, .build, sample, clock);
    report.builder_trie_used = trie_used(&fixture.builder.scratch);
    try measure_unverified(io, fixture, report, sample);
    clock = bench.now_ns(io);
    // `build` starts with this reset; timed alone to show its share (O(pool capacity)).
    fixture.builder.scratch.reset(fixture.pre_root, no_headers_parent);
    clock = lap(io, report, .builder_reset, sample, clock);
    const size = try fixture.encoder.encode(&fixture.built, fixture.encoded);
    clock = lap(io, report, .encode, sample, clock);
    try witness_codec.decode(fixture.encoded[0..size], &fixture.decoded);
    clock = lap(io, report, .decode, sample, clock);
    fixture.sparse.reset(fixture.pre_root, no_headers_parent);
    clock = lap(io, report, .reset, sample, clock);
    try fixture.sparse.load(&fixture.decoded);
    clock = lap(io, report, .load, sample, clock);
    try witness.replay(&fixture.sparse, keys, &fixture.changeset);
    clock = lap(io, report, .replay, sample, clock);
    report.trie_used = trie_used(&fixture.sparse);
    report.trie_capacity = @intCast(fixture.sparse.trie.nodes.len);
    if (!std.mem.eql(u8, &fixture.sparse.state_root(), &post_root)) return error.RootMismatch;
    if (kind == .calls) {
        fixture.sparse.reset(fixture.pre_root, no_headers_parent);
        try fixture.sparse.load(&fixture.decoded);
        clock = bench.now_ns(io);
        try fixture.execute(fixture.sparse.database());
        try fixture.sparse.apply_evm(&fixture.evm_state, &fixture.sparse_changeset);
        clock = lap(io, report, .stateless, sample, clock);
        assert(!fixture.sparse.incomplete);
        const root = fixture.sparse.state_root();
        if (!std.mem.eql(u8, &root, &post_root)) return error.RootMismatch;
    }
    report.nodes = fixture.built.state.count;
    report.codes = fixture.built.codes.count;
    report.keys = fixture.built.keys.count;
    report.encoded_bytes = @intCast(size);
}

/// `Builder.build_with` without root verification; must give the witness `build` gave.
fn measure_unverified(io: std.Io, fixture: *Fixture, report: *Report, sample: u32) !void {
    const nodes = fixture.built.state.count;
    const source = fixture.builder.state_source(&fixture.state);
    const options: witness.BuildOptions = .{ .verify_root = false };
    const clock = bench.now_ns(io);
    const unverified = try fixture.builder.build_with(
        source,
        &fixture.recorder.keys,
        &fixture.changeset,
        &.{},
        &fixture.built,
        options,
    );
    _ = lap(io, report, .build_unverified, sample, clock);
    assert(unverified == null);
    if (fixture.built.state.count != nodes) return error.WitnessMismatch;
}

fn trie_used(sparse: *const witness.SparseState) u32 {
    const capacity: u32 = @intCast(sparse.trie.nodes.len);
    assert(sparse.trie.free_count <= capacity);
    return capacity - sparse.trie.free_count;
}

/// Records the time since `start` and returns the new start.
fn lap(io: std.Io, report: *Report, metric: Metric, sample: u32, start: u64) u64 {
    const now = bench.now_ns(io);
    assert(now >= start);
    report.set(metric, sample, now - start);
    return now;
}

/// Builds the block, warms up once, then takes `samples_count` samples.
fn measure_block(io: std.Io, fixture: *Fixture, spec: *const Spec, report: *Report) !void {
    try fixture.prepare(spec);
    try measure_sample(io, fixture, spec.kind, report, 0);
    for (0..samples_count) |sample| {
        try measure_sample(io, fixture, spec.kind, report, @intCast(sample));
    }
    assert(report.nodes > 0 and report.encoded_bytes > 0);
    assert(report.keys > 0);
}

fn megabytes_per_s(bytes: u32, duration_us: f64) f64 {
    assert(duration_us >= 0);
    return @as(f64, @floatFromInt(bytes)) / @max(duration_us, 1e-3);
}

fn print_report(name: []const u8, report: *Report) void {
    std.debug.print("{s:<40} nodes {d}  bytes {d}  codes {d}  keys {d}\n", .{
        name, report.nodes, report.encoded_bytes, report.codes, report.keys,
    });
    const plain = report.median_us(.reads_plain);
    const recorded = report.median_us(.reads_recorded);
    const build = report.median_us(.build);
    std.debug.print("  {s:<38} {d:>10.1} us / {d:.1} us (recorder overhead {d:.1} us)\n", .{
        "reads plain / via Recorder", plain, recorded, recorded - plain,
    });
    std.debug.print("  {s:<38} {d:>10.1} us (+ recorder {d:.1} us, scratch reset {d:.1} us)\n", .{
        "Builder.build", build, recorded - plain, report.median_us(.builder_reset),
    });
    std.debug.print("  {s:<38} {d:>10.1} us\n", .{
        "Builder.build_with verify_root=false", report.median_us(.build_unverified),
    });
    std.debug.print("  {s:<38} {d:>10.1} us / {d:.1} us / {d:.1} us\n", .{
        "SparseState reset / load / replay",
        report.median_us(.reset),
        report.median_us(.load),
        report.median_us(.replay),
    });
    std.debug.print("  {s:<38} builder {d}, verifier {d}, capacity {d}\n", .{
        "sparse trie nodes used",
        report.builder_trie_used,
        report.trie_used,
        report.trie_capacity,
    });
    const encode = report.median_us(.encode);
    const decode = report.median_us(.decode);
    std.debug.print("  {s:<38} {d:>10.1} us / {d:.1} us ({d:.0} / {d:.0} MB/s)\n", .{
        "codec encode / decode",
        encode,
        decode,
        megabytes_per_s(report.encoded_bytes, encode),
        megabytes_per_s(report.encoded_bytes, decode),
    });
    if (report.times_ns[@backingInt(Metric.stateless)][0] != 0) {
        std.debug.print("  {s:<38} {d:>10.1} us\n", .{
            "stateless evm run + apply_evm", report.median_us(.stateless),
        });
    }
}

/// Runs the witness benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    var any = false;
    for (specs) |spec| any = any or bench.matches(spec.name, filter);
    if (!any) return;
    const allocator = std.heap.page_allocator;
    run_shape(io, allocator, bench.shape_bench, filter, true) catch |err| {
        std.debug.print("db/witness: failed: {s}\n", .{@errorName(err)});
    };
}

fn run_shape(
    io: std.Io,
    allocator: std.mem.Allocator,
    shape: Shape,
    filter: ?[]const u8,
    print: bool,
) !void {
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    try fixture.init(allocator, shape);
    defer fixture.deinit(allocator);
    const report = try allocator.create(Report);
    defer allocator.destroy(report);
    for (&specs) |*spec| {
        if (!bench.matches(spec.name, filter)) continue;
        report.* = .{};
        measure_block(io, fixture, spec, report) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ spec.name, @errorName(err) });
            return err;
        };
        if (print) print_report(spec.name, report);
    }
}

test "witness bench: every block builds, round-trips, and replays (small shape)" {
    try run_shape(std.testing.io, std.testing.allocator, bench.shape_test, null, false);
    try std.testing.expect(bench.matches(specs[0].name, "db/"));
    try std.testing.expect(bench.matches(specs[2].name, "db/witness"));
}

//! Node restart time: `Database.open` end to end, run by `bench.run_commit` ("restart").
//!
//! A database is built with the node's shape of work: the bench state (`bench.Shape`) is
//! filled, then `window_blocks` typical blocks (1k account writes + 1k slot writes, ~200
//! transactions) are committed, a checkpoint is taken, and `replay_blocks` more blocks are
//! committed so `open` replays a journal tail. With history on (the node's byte budget,
//! `node.service.history_config` reproduced here) `open` also rebuilds the window from the
//! retained changesets. The database is then dropped and reopened `samples` times per load
//! variant; `Database.open_trace` reports each step's end and the bench reads the clock:
//! checkpoint read (superblock, stream, verify), snapshot decode into the flat tables, trie
//! build, root, retained blocks, journal replay, history unwind, history reset (every node
//! into the path index), and history re-apply. Medians per step are printed.
//!
//! Variants: the reference `incremental` load (key-by-key inserts), and the `bulk` load
//! with 0 and 4 storage-rehash workers (`rehash_threads`; a node on 5+ cores runs 4).
//! The sim cases use a zero-latency `SimStorage` (CPU only); the os cases a scratch file
//! under `.zig-cache/tmp` (deleted afterwards; reads come from the page cache, a warm
//! restart). Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const overlay_module = @import("overlay.zig");
const database = @import("database.zig");
const history = @import("history.zig");
const journal_module = @import("storage/journal.zig");
const checkpoint_module = @import("storage/checkpoint.zig");
const storage_module = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const IoStorageType = @import("storage/io_storage.zig").IoStorageType;
const io_root = @import("../../utilities/io/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Overlay = overlay_module.Overlay;
const Hash = database.Hash;
const Shape = bench.Shape;
const OpenStep = database.OpenStep;

const step_count = @typeInfo(OpenStep).@"enum".field_names.len;

/// 100k accounts, 1k contracts x 64 slots; typical blocks.
pub const shape_100k: Shape = .{
    .accounts = 100_000,
    .contracts = 1_000,
    .slots_per_contract = 64,
    .block_accounts = 1_000,
    .block_slots = 1_000,
    .fill_accounts = 4_000,
    .rounds = 1,
    .round_blocks = 1,
};

/// 1M accounts, 10k contracts x 64 slots; typical blocks.
pub const shape_1m: Shape = .{
    .accounts = 1_000_000,
    .contracts = 10_000,
    .slots_per_contract = 64,
    .block_accounts = 1_000,
    .block_slots = 1_000,
    .fill_accounts = 20_000,
    .rounds = 1,
    .round_blocks = 1,
};

pub const shape_test: Shape = .{
    .accounts = 400,
    .contracts = 8,
    .slots_per_contract = 16,
    .block_accounts = 20,
    .block_slots = 40,
    .fill_accounts = 100,
    .rounds = 1,
    .round_blocks = 1,
};

/// One restart case: state shape, history, and storage.
pub const Case = struct {
    name: []const u8,
    shape: Shape,
    history: bool,
    storage: enum { sim, os },
    /// Blocks after the fill: the history window (300 at 200 ms, the node default).
    window_blocks: u32 = 300,
    /// Blocks committed after the checkpoint: the journal tail `open` replays.
    replay_blocks: u32 = 16,
    samples: u32 = 3,
    journal_size_bytes: u64 = 64 << 20,
};

pub const cases = [_]Case{
    .{ .name = "db/restart 100k sim", .shape = shape_100k, .history = false, .storage = .sim },
    .{
        .name = "db/restart 100k sim history",
        .shape = shape_100k,
        .history = true,
        .storage = .sim,
    },
    .{ .name = "db/restart 100k os", .shape = shape_100k, .history = false, .storage = .os },
    .{ .name = "db/restart 100k os history", .shape = shape_100k, .history = true, .storage = .os },
    .{
        .name = "db/restart 1m sim",
        .shape = shape_1m,
        .history = false,
        .storage = .sim,
        .journal_size_bytes = 256 << 20,
    },
    .{
        .name = "db/restart 1m sim history",
        .shape = shape_1m,
        .history = true,
        .storage = .sim,
        .journal_size_bytes = 256 << 20,
    },
    .{
        .name = "db/restart 1m os history",
        .shape = shape_1m,
        .history = true,
        .storage = .os,
        .journal_size_bytes = 256 << 20,
    },
};

/// Load variants measured on every case.
pub const Variant = struct {
    name: []const u8,
    load_mode: database.LoadMode,
    rehash_threads: u32,
};

pub const variants = [_]Variant{
    .{ .name = "incremental", .load_mode = .incremental, .rehash_threads = 0 },
    .{ .name = "bulk", .load_mode = .bulk, .rehash_threads = 0 },
    .{ .name = "bulk 4 threads", .load_mode = .bulk, .rehash_threads = 4 },
};

const header_size = 64;
const account_change_bytes = 20 + 1 + 2 * (8 + 32 + 32);
const storage_change_bytes = 20 + 3 * 32;
const changeset_header_bytes = 4 + 2 + 4 + 4 + 4;
const ticks_max: u64 = 1 << 40;
const busy_retries_max: u64 = 1 << 24;

fn changeset_bytes(accounts: u64, slots: u64) u64 {
    return changeset_header_bytes + accounts * account_change_bytes +
        slots * storage_change_bytes;
}

fn body_size_max(shape: Shape) u32 {
    const accounts: u64 = @max(shape.block_accounts, shape.fill_accounts);
    const slots: u64 = @max(shape.block_slots, shape.fill_slots());
    const size = database.block_entry_fixed_size + header_size + changeset_bytes(accounts, slots);
    return @intCast(storage_module.sector_ceil(size));
}

/// `node.service.history_config` with the default limits (1 GiB budget, 1k versions per
/// block) over this state's trie bounds.
fn history_config(shape: Shape, window: u32) history.Config {
    const state = bench.state_config(shape);
    const nodes: u64 = @as(u64, state.account_nodes_max) + state.storage_nodes_max;
    const per_block: u64 = 1 << 10;
    const total = nodes + @as(u64, window) * per_block;
    const budget: u64 = 1 << 30;
    const small = budget / history.small_version_bytes + per_block;
    const large = budget / history.large_version_bytes + per_block;
    const paths = @min(total, budget / (history.path_bytes + history.small_version_bytes) +
        per_block);
    assert(small < 1 << 31 and large < 1 << 31);
    return .{
        .window_blocks = window,
        .paths_max = @intCast(paths),
        .small_versions_max = @intCast(small),
        .large_versions_max = @intCast(large),
        .prune_per_commit = @intCast(per_block),
        .bytes_max = budget,
    };
}

pub fn database_config(case: Case, rehash_threads: u32) database.Config {
    const shape = case.shape;
    const body_max = body_size_max(shape);
    var state = bench.state_config(shape);
    state.rehash_threads = rehash_threads;
    const blocks_max = case.window_blocks + case.replay_blocks + 8;
    const block_record = header_size + changeset_bytes(shape.block_accounts, shape.block_slots);
    const bytes_max: u64 = @max(@as(u64, blocks_max) * block_record, 2 * @as(u64, body_max));
    const snapshot_bytes = 64 + @as(u64, state.accounts_max) * (20 + 8 + 32 + 32) +
        @as(u64, state.storage_slots_max) * (20 + 32 + 32) + 256 * 40;
    const blocks_bytes = bytes_max + @as(u64, blocks_max) * (4 + database.block_entry_fixed_size);
    const staging = database.checkpoint_header_size + snapshot_bytes + blocks_bytes;
    const block_size: u32 = 64 * 1024;
    const payload = checkpoint_module.payload_capacity(block_size);
    const zone_blocks = std.math.divCeil(u64, staging, payload) catch unreachable; // payload > 0.
    assert(case.journal_size_bytes >= 8 * journal_module.entry_size_bytes(body_max));
    return .{
        .engine = .{
            .journal_size_bytes = case.journal_size_bytes,
            .checkpoint_zone_size_bytes = (zone_blocks + 1) * block_size,
            .entry_body_size_max = body_max,
            .checkpoint_block_size = block_size,
        },
        .state = state,
        .chain = .{
            .blocks_max = blocks_max,
            .bytes_max = @intCast(bytes_max),
            .transactions_max = 1 << 16,
            .canonical_max = 1 << 16,
        },
        .changeset = bench.changeset_config(shape),
        .queue_entries_max = 4,
        .checkpoint_staging_bytes = @intCast(staging),
        .history = if (case.history) history_config(shape, case.window_blocks) else null,
    };
}

fn hash_of(number: u64) Hash {
    var hash: Hash = @splat(0xdd);
    std.mem.writeInt(u64, hash[0..8], number + 1, .big);
    return hash;
}

/// What a reopen must reproduce.
pub const Expected = struct {
    head: database.HeadInfo,
    window_oldest: ?u64,
};

/// One reopen: nanoseconds per step (0 for steps that did not run), init, and total.
pub const Sample = struct {
    steps_ns: [step_count]u64 = @splat(0),
    /// The opening thread's CPU time per step (steadier than wall time on a loaded
    /// machine; excludes rehash workers).
    steps_cpu_ns: [step_count]u64 = @splat(0),
    init_ns: u64 = 0,
    open_ns: u64 = 0,
    window_oldest: ?u64 = null,
};

pub fn RunType(comptime Storage: type) type {
    return struct {
        const Self = @This();
        const Database = database.DatabaseType(Storage);

        storage: *Storage,
        case: Case,
        io: std.Io,
        prng: Prng = Prng.init(11),
        header: [header_size]u8 = @splat(0x52),
        sample: Sample = .{},
        last_ns: u64 = 0,
        last_cpu_ns: u64 = 0,

        fn tick_while_phase(self: *Self, db: *Database, phase: database.Phase) !void {
            var ticks: u64 = 0;
            while (db.phase == phase) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.storage.tick();
            }
            assert(db.phase != phase);
        }

        fn tick_until_durable(self: *Self, db: *Database, sequence: u64) !void {
            var ticks: u64 = 0;
            while (db.durable_sequence < sequence) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.storage.tick();
            }
        }

        fn tick_until_idle(self: *Self, db: *Database) !void {
            var ticks: u64 = 0;
            while (!db.idle()) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                db.checkpoint_flush();
                self.storage.tick();
            }
        }

        fn commit_block(self: *Self, db: *Database, overlay: *Overlay) !void {
            const number: u64 = if (db.head_info.present) db.head_info.number + 1 else 0;
            std.mem.writeInt(u64, self.header[0..8], number, .little);
            const input: database.BlockInput = .{
                .hash = hash_of(number),
                .parent_hash = if (number == 0) @splat(0) else db.head_info.hash,
                .number = number,
                .timestamp = number,
                .header = &self.header,
                .body = "",
                .receipts = "",
                .transaction_hashes = &.{},
                .changeset = "",
            };
            var retries: u64 = 0;
            while (retries < busy_retries_max) : (retries += 1) {
                const commit = db.execute_and_commit(overlay, &input) catch |err| {
                    if (err != error.Busy) return err;
                    if (db.checkpoint_error) |checkpoint_err| return checkpoint_err;
                    self.storage.tick();
                    continue;
                };
                try self.tick_until_durable(db, commit.sequence);
                return;
            }
            return error.Timeout;
        }

        /// Formats and fills the database, commits the window, checkpoints, commits the
        /// replayed tail. Returns what a reopen must reproduce.
        pub fn build(self: *Self, allocator: std.mem.Allocator) !Expected {
            const shape = self.case.shape;
            shape.check();
            const db = try allocator.create(Database);
            defer allocator.destroy(db);
            db.* = try Database.init(allocator, self.storage, database_config(self.case, 0));
            defer db.deinit(allocator);
            var overlay = try Overlay.init(allocator, &db.state, bench.overlay_config(shape));
            defer overlay.deinit(allocator);
            db.format(0x7265_7374_6172_74);
            try self.tick_while_phase(db, .formatting);
            db.open();
            try self.tick_while_phase(db, .opening);
            if (db.open_error) |err| return err;
            for (0..shape.fill_blocks()) |fill_index| {
                try bench.write_fill(&overlay, shape, @intCast(fill_index));
                try self.commit_block(db, &overlay);
            }
            for (0..self.case.window_blocks) |_| {
                try bench.write_block(&overlay, shape, &self.prng);
                try self.commit_block(db, &overlay);
            }
            try self.tick_until_idle(db);
            const completed = db.checkpoints_completed;
            db.request_checkpoint();
            try self.tick_until_idle(db);
            if (db.checkpoint_error) |err| return err;
            assert(db.checkpoints_completed == completed + 1);
            for (0..self.case.replay_blocks) |_| {
                try bench.write_block(&overlay, shape, &self.prng);
                try self.commit_block(db, &overlay);
            }
            try self.tick_until_idle(db);
            assert(db.state.account_table.count() == shape.accounts);
            const window = if (db.history) |*store| store.window() else null;
            return .{
                .head = db.head_info,
                .window_oldest = if (window) |w| w.oldest else null,
            };
        }

        fn on_step(context: *anyopaque, step: OpenStep) void {
            const self: *Self = @ptrCast(@alignCast(context));
            const now = bench.now_ns(self.io);
            assert(now >= self.last_ns);
            self.sample.steps_ns[@backingInt(step)] += now - self.last_ns;
            self.last_ns = now;
            const cpu = cpu_ns(self.io);
            self.sample.steps_cpu_ns[@backingInt(step)] += cpu -| self.last_cpu_ns;
            self.last_cpu_ns = cpu;
        }

        /// Opens the built database once with `variant` and times every step.
        pub fn reopen(
            self: *Self,
            allocator: std.mem.Allocator,
            variant: Variant,
            expected: *const Expected,
        ) !Sample {
            self.sample = .{};
            const db = try allocator.create(Database);
            defer allocator.destroy(db);
            const config = database_config(self.case, variant.rehash_threads);
            const init_start = bench.now_ns(self.io);
            db.* = try Database.init(allocator, self.storage, config);
            defer db.deinit(allocator);
            const start = bench.now_ns(self.io);
            self.sample.init_ns = start - init_start;
            db.load_mode = variant.load_mode;
            db.open_trace = .{ .context = self, .step = on_step };
            self.last_ns = start;
            self.last_cpu_ns = cpu_ns(self.io);
            db.open();
            try self.tick_while_phase(db, .opening);
            self.sample.open_ns = bench.now_ns(self.io) - start;
            if (db.open_error) |err| return err;
            assert(db.phase == .ready);
            if (!db.head_info.eql(expected.head)) return error.HeadMismatch;
            const window = if (db.history) |*store| store.window() else null;
            self.sample.window_oldest = if (window) |w| w.oldest else null;
            return self.sample;
        }
    };
}

fn cpu_ns(io: std.Io) u64 {
    const nanoseconds = std.Io.Clock.cpu_thread.now(io).nanoseconds;
    assert(nanoseconds >= 0);
    return @intCast(nanoseconds);
}

fn median(values: []u64) u64 {
    assert(values.len > 0);
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

const samples_max = 8;

fn report(case: Case, variant: Variant, samples: []const Sample) void {
    assert(samples.len > 0 and samples.len <= samples_max);
    var scratch: [samples_max]u64 = undefined;
    for (samples, 0..) |sample, index| scratch[index] = sample.open_ns;
    const open_ns = median(scratch[0..samples.len]);
    for (samples, 0..) |sample, index| scratch[index] = sample.init_ns;
    const init_ns = median(scratch[0..samples.len]);
    std.debug.print("{s:<30} {s:<16} open {d:>9.1} ms  (init {d:.1} ms, window from {?d})\n", .{
        case.name,
        variant.name,
        @as(f64, @floatFromInt(open_ns)) / 1e6,
        @as(f64, @floatFromInt(init_ns)) / 1e6,
        samples[0].window_oldest,
    });
    inline for (@typeInfo(OpenStep).@"enum".field_names, 0..) |field_name, step| {
        for (samples, 0..) |sample, index| scratch[index] = sample.steps_ns[step];
        const step_ns = median(scratch[0..samples.len]);
        for (samples, 0..) |sample, index| scratch[index] = sample.steps_cpu_ns[step];
        const step_cpu_ns = median(scratch[0..samples.len]);
        if (step_ns > 0) {
            std.debug.print("    {s:<18} {d:>9.1} ms  cpu {d:>9.1} ms\n", .{
                field_name,
                @as(f64, @floatFromInt(step_ns)) / 1e6,
                @as(f64, @floatFromInt(step_cpu_ns)) / 1e6,
            });
        }
    }
}

fn measure(
    comptime Storage: type,
    io: std.Io,
    allocator: std.mem.Allocator,
    storage: *Storage,
    case: Case,
) !void {
    assert(case.samples > 0 and case.samples <= samples_max);
    const Run = RunType(Storage);
    var run_state: Run = .{ .storage = storage, .case = case, .io = io };
    const build_start = bench.now_ns(io);
    const expected = try run_state.build(allocator);
    std.debug.print("{s}: built head {d} in {d:.1} s\n", .{
        case.name,
        expected.head.number,
        @as(f64, @floatFromInt(bench.now_ns(io) - build_start)) / 1e9,
    });
    for (variants) |variant| {
        var samples: [samples_max]Sample = undefined;
        for (samples[0..case.samples]) |*sample| {
            sample.* = try run_state.reopen(allocator, variant, &expected);
            if (sample.window_oldest != expected.window_oldest) {
                std.debug.print("  window from {?d}, before restart {?d}\n", .{
                    sample.window_oldest, expected.window_oldest,
                });
            }
        }
        report(case, variant, samples[0..case.samples]);
    }
}

/// `State.rebuild_trie` + root over a filled in-memory state: the bulk trie build alone
/// (no storage, no checkpoint), fastest of `rounds`.
pub const TrieCase = struct { name: []const u8, shape: Shape, rehash_threads: u32 };

pub const trie_cases = [_]TrieCase{
    .{ .name = "db/restart trie 100k", .shape = shape_100k, .rehash_threads = 0 },
    .{ .name = "db/restart trie 1m", .shape = shape_1m, .rehash_threads = 0 },
    .{ .name = "db/restart trie 1m 4 threads", .shape = shape_1m, .rehash_threads = 4 },
};

fn run_trie(io: std.Io, allocator: std.mem.Allocator, case: TrieCase) !void {
    const state_module = @import("state.zig");
    const changeset_module = @import("changeset.zig");
    var config = bench.state_config(case.shape);
    config.rehash_threads = case.rehash_threads;
    const state = try allocator.create(state_module.State);
    defer allocator.destroy(state);
    state.* = try state_module.State.init(allocator, config);
    defer state.deinit(allocator);
    var overlay = try Overlay.init(allocator, state, bench.overlay_config(case.shape));
    defer overlay.deinit(allocator);
    var changeset = try changeset_module.Changeset.init(
        allocator,
        bench.changeset_config(case.shape),
    );
    defer changeset.deinit(allocator);
    for (0..case.shape.fill_blocks()) |fill_index| {
        try bench.write_fill(&overlay, case.shape, @intCast(fill_index));
        _ = try overlay.commit(&changeset);
    }
    const root = try state.state_root();
    const scratch = try allocator.alloc(u8, @intCast(state.build_trie_scratch_bytes()));
    defer allocator.free(scratch);
    const rounds = 5;
    // Wall time: with rehash workers the caller's CPU time misses their share.
    var build_ns: u64 = std.math.maxInt(u64);
    var root_ns: u64 = std.math.maxInt(u64);
    for (0..rounds) |_| {
        const start = bench.now_ns(io);
        try state.rebuild_trie(scratch);
        const built = bench.now_ns(io);
        const rebuilt = try state.state_root();
        const end = bench.now_ns(io);
        if (!std.mem.eql(u8, &root, &rebuilt)) return error.RootMismatch;
        build_ns = @min(build_ns, built - start);
        root_ns = @min(root_ns, end - built);
    }
    std.debug.print("{s:<30} build {d:>8.1} ms  root {d:>8.1} ms  (fastest of {d})\n", .{
        case.name,
        @as(f64, @floatFromInt(build_ns)) / 1e6,
        @as(f64, @floatFromInt(root_ns)) / 1e6,
        rounds,
    });
}

/// Runs the restart cases whose names match `filter`; only when it names "restart".
pub fn run(io: std.Io, filter: ?[]const u8) void {
    const pattern = filter orelse return;
    if (std.mem.indexOf(u8, pattern, "restart") == null) return;
    for (trie_cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        run_trie(io, std.heap.page_allocator, case) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
        };
    }
    for (cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        const allocator = std.heap.page_allocator;
        const result = switch (case.storage) {
            .sim => run_sim(io, allocator, case),
            .os => run_os(io, allocator, case),
        };
        result catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
        };
    }
}

pub fn run_sim(io: std.Io, allocator: std.mem.Allocator, case: Case) !void {
    const config = database_config(case, 0);
    var storage = try SimStorage.init(allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 9,
        .latency_ticks_min = 1,
        .latency_ticks_max = 1,
    });
    defer storage.deinit(allocator);
    try measure(SimStorage, io, allocator, &storage, case);
}

const scratch_directory = ".zig-cache/tmp/needlefish-db-restart-bench";
const scratch_path = scratch_directory ++ "/data.db";

fn run_os(io: std.Io, allocator: std.mem.Allocator, case: Case) !void {
    const IO = io_root.IO;
    var backend = (if (builtin.os.tag == .linux) IO.init(.{}) else IO.init()) catch |err| {
        std.debug.print("{s}: skipped, no IO backend: {s}\n", .{ case.name, @errorName(err) });
        return;
    };
    defer backend.deinit();
    const directory = std.Io.Dir.cwd();
    try directory.createDirPath(io, scratch_directory);
    defer directory.deleteDir(io, scratch_directory) catch |err| {
        std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            case.name, scratch_directory, @errorName(err),
        });
    };
    delete_scratch(io, case.name);
    defer delete_scratch(io, case.name);
    const fd = try backend.open_file(scratch_path, .create);
    defer backend.close_now(fd);
    const config = database_config(case, 0);
    assert(config.engine.size_bytes() < 2 << 30);
    const Storage = IoStorageType(IO);
    var storage = try Storage.init(allocator, &backend, fd, .{
        .size_bytes = config.engine.size_bytes(),
    });
    defer storage.deinit(allocator);
    try measure(Storage, io, allocator, &storage, case);
}

fn delete_scratch(io: std.Io, name: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, scratch_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name, scratch_path, @errorName(err),
        }),
    };
}

test "restart bench: every variant reopens to the same head (small shape)" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |history_on| {
        const case: Case = .{
            .name = "test",
            .shape = shape_test,
            .history = history_on,
            .storage = .sim,
            .window_blocks = 12,
            .replay_blocks = 3,
            .samples = 1,
            .journal_size_bytes = 1 << 20,
        };
        const config = database_config(case, 0);
        var storage = try SimStorage.init(allocator, .{
            .size_bytes = config.engine.size_bytes(),
            .seed = 9,
        });
        defer storage.deinit(allocator);
        const Run = RunType(SimStorage);
        var run_state: Run = .{ .storage = &storage, .case = case, .io = std.testing.io };
        const expected = try run_state.build(allocator);
        for (variants) |variant| {
            if (variant.rehash_threads > 0) continue; // Tests stay single-threaded.
            const sample = try run_state.reopen(allocator, variant, &expected);
            try std.testing.expectEqual(expected.window_oldest, sample.window_oldest);
            try std.testing.expect(sample.steps_ns[@backingInt(OpenStep.snapshot_root)] > 0 or
                sample.open_ns > 0);
        }
    }
}

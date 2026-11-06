//! Steady-state commit latency with automatic checkpoints, run by `bench.run_commit`.
//!
//! A node at Base's native 200 ms block cadence commits one block per slot, and the
//! database checkpoints on its own whenever the journal passes half full. This bench runs
//! thousands of typical blocks (1k account writes + 1k storage writes, about 200
//! transactions, over 100k accounts with 1k contracts x 64 slots) through
//! `Database.execute_and_commit` with the node's durable layout (64 MiB journal, 16 MiB of
//! retained blocks). The os case paces blocks at 200 ms slots: after a block is durable the
//! storage ticks every 2 ms (the node's storage timer) until the slot ends, so checkpoints
//! progress in idle time as on a node; the longest idle tick is an event-loop stall. The sim
//! case runs blocks back to back with 8 idle ticks (CPU only). Each commit's wall latency,
//! from `execute_and_commit` until its entry is durable,
//! is classified by what the checkpoint did during it:
//! - `start`: a checkpoint started (the state snapshot and retained blocks are serialized
//!   into the staging buffer inside the commit's tick),
//! - `advance`: a checkpoint was writing before and after,
//! - `finish`: a checkpoint completed (its sync and superblock),
//! - `none`: no checkpoint was running.
//! A journal without room returns `error.Busy`; the commit ticks and retries, and the wait
//! counts in its latency.
//!
//! The os case uses a scratch file under `.zig-cache/tmp` (deleted afterwards); the sim
//! case uses a zero-latency `SimStorage` (CPU only), with a few idle ticks between blocks.
//! Fixtures come from the page allocator: benchmark scaffolding, not library code.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const overlay_module = @import("overlay.zig");
const database = @import("database.zig");
const engine_module = @import("storage/engine.zig");
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

/// One steady-state case: a storage and a layout.
const Case = struct {
    name: []const u8,
    storage: enum { sim, os },
    layout: Layout,
};

pub const cases = [_]Case{
    .{ .name = "db/commit steady sim unpaced", .storage = .sim, .layout = layout_node },
    .{ .name = "db/commit steady sim paced", .storage = .sim, .layout = layout_node_paced },
    .{ .name = "db/commit steady os unpaced", .storage = .os, .layout = layout_node },
    .{ .name = "db/commit steady os paced", .storage = .os, .layout = layout_node_paced },
};

/// Typical block over the `bench.shape_bench` state: 1k accounts + 1k slots.
pub const shape_steady: Shape = .{
    .accounts = 100_000,
    .contracts = 1_000,
    .slots_per_contract = 64,
    .block_accounts = 1_000,
    .block_slots = 1_000,
    .fill_accounts = 4_000,
    .rounds = 1,
    .round_blocks = 3_000,
};

/// The os case paces blocks at 200 ms: 2k blocks take about 7 minutes.
pub const shape_steady_os: Shape = blk: {
    var shape = shape_steady;
    shape.round_blocks = 2_000;
    break :blk shape;
};

/// Small shape for the unit test: checkpoints every few blocks.
pub const shape_steady_test: Shape = .{
    .accounts = 400,
    .contracts = 8,
    .slots_per_contract = 16,
    .block_accounts = 20,
    .block_slots = 40,
    .fill_accounts = 100,
    .rounds = 1,
    .round_blocks = 64,
};

const header_size = 64;
const account_change_bytes = 20 + 1 + 2 * (8 + 32 + 32);
const storage_change_bytes = 20 + 3 * 32;
const changeset_header_bytes = 4 + 2 + 4 + 4 + 4;

/// Layout knobs: the node's durable layout, or a scaled-down one for tests.
pub const Layout = struct {
    journal_size_bytes: u64,
    retained_bytes_max: u32,
    retained_blocks_max: u32,
    /// Checkpoint bytes written per commit (`Config.checkpoint_bytes_per_commit`).
    checkpoint_bytes_per_commit: u32 = 0,
};

pub const layout_node: Layout = .{
    .journal_size_bytes = 64 << 20,
    .retained_bytes_max = 16 << 20,
    .retained_blocks_max = 1024,
};

/// `layout_node` with incremental checkpoints: 4 MiB of checkpoint per commit.
pub const layout_node_paced: Layout = blk: {
    var layout = layout_node;
    layout.checkpoint_bytes_per_commit = 4 << 20;
    break :blk layout;
};

fn body_size_max(shape: Shape) u32 {
    const accounts: u64 = @max(shape.block_accounts, shape.fill_accounts);
    const slots: u64 = @max(shape.block_slots, shape.fill_slots());
    const changeset = changeset_header_bytes + accounts * account_change_bytes +
        slots * storage_change_bytes;
    const size = database.block_entry_fixed_size + header_size + changeset;
    return @intCast(storage_module.sector_ceil(size));
}

pub fn database_config(shape: Shape, layout: Layout) database.Config {
    const body_max = body_size_max(shape);
    const state = bench.state_config(shape);
    const snapshot_bytes = 64 + @as(u64, state.accounts_max) * (20 + 8 + 32 + 32) +
        @as(u64, state.storage_slots_max) * (20 + 32 + 32) + 256 * 40;
    const blocks_bytes = layout.retained_bytes_max +
        @as(u64, layout.retained_blocks_max) * (4 + database.block_entry_fixed_size);
    const staging = database.checkpoint_header_size + snapshot_bytes + blocks_bytes;
    const block_size: u32 = 64 * 1024;
    const payload = checkpoint_module.payload_capacity(block_size);
    const zone_blocks = std.math.divCeil(u64, staging, payload) catch unreachable; // payload > 0.
    assert(layout.journal_size_bytes >= 8 * journal_module.entry_size_bytes(body_max));
    return .{
        .engine = .{
            .journal_size_bytes = layout.journal_size_bytes,
            .checkpoint_zone_size_bytes = (zone_blocks + 1) * block_size,
            .entry_body_size_max = body_max,
            .checkpoint_block_size = block_size,
        },
        .state = state,
        .chain = .{
            .blocks_max = layout.retained_blocks_max,
            .bytes_max = layout.retained_bytes_max,
            .transactions_max = 1 << 16,
            .canonical_max = 1 << 16,
        },
        .changeset = bench.changeset_config(shape),
        .queue_entries_max = 4,
        .checkpoint_staging_bytes = @intCast(staging),
        .checkpoint_bytes_per_commit = layout.checkpoint_bytes_per_commit,
    };
}

fn hash_of(number: u64) Hash {
    var hash: Hash = @splat(0xcc);
    std.mem.writeInt(u64, hash[0..8], number + 1, .big);
    return hash;
}

/// What the checkpoint did during one commit.
pub const Kind = enum(u8) { none, start, advance, finish };
const kind_count = 4;
const kinds = [kind_count]Kind{ .none, .start, .advance, .finish };

comptime {
    for (kinds, 0..) |kind, index| assert(@backingInt(kind) == index);
}

/// Per-kind latency samples (nanoseconds) of one run; `overlap` holds every commit that
/// overlapped a checkpoint (any kind but `none`).
pub const Samples = struct {
    all: []u64,
    overlap: []u64,
    by_kind: [kind_count][]u64,
    counts: [kind_count]u32 = @splat(0),
    count: u32 = 0,
    overlap_count: u32 = 0,

    fn init(allocator: std.mem.Allocator, capacity: u32) !Samples {
        assert(capacity > 0);
        var samples: Samples = .{
            .all = try allocator.alloc(u64, capacity),
            .overlap = try allocator.alloc(u64, capacity),
            .by_kind = undefined,
        };
        for (&samples.by_kind) |*slice| slice.* = try allocator.alloc(u64, capacity);
        return samples;
    }

    fn deinit(samples: *Samples, allocator: std.mem.Allocator) void {
        for (samples.by_kind) |slice| allocator.free(slice);
        allocator.free(samples.overlap);
        allocator.free(samples.all);
        samples.* = undefined;
    }

    fn add(samples: *Samples, kind: Kind, latency_ns: u64) void {
        const index = @backingInt(kind);
        assert(samples.count < samples.all.len);
        samples.all[samples.count] = latency_ns;
        samples.count += 1;
        samples.by_kind[index][samples.counts[index]] = latency_ns;
        samples.counts[index] += 1;
        if (kind != .none) {
            samples.overlap[samples.overlap_count] = latency_ns;
            samples.overlap_count += 1;
        }
        assert(samples.counts[index] <= samples.count);
        assert(samples.overlap_count + samples.counts[0] == samples.count);
    }

    /// Largest sample over every kind.
    pub fn max(samples: *const Samples) u64 {
        var result: u64 = 0;
        for (samples.all[0..samples.count]) |sample| result = @max(result, sample);
        return result;
    }
};

/// Upper bound on storage ticks while waiting for one operation (spinning on real IO).
const ticks_max: u64 = 1 << 40;
const serialize_samples = 3;
/// A quarter of the 200 ms slot.
const budget_ns: u64 = 50 * std.time.ns_per_ms;

/// Upper bound on `error.Busy` retries of one commit.
const busy_retries_max: u64 = 1 << 40;

pub fn RunType(comptime Storage: type) type {
    return struct {
        const Self = @This();
        const Database = database.DatabaseType(Storage);

        db: Database,
        overlay: Overlay,
        storage: *Storage,
        shape: Shape,
        prng: Prng,
        idle_ticks: u32,
        /// Os pacing: each block owns a slot of `slot_ns`; after it is durable the storage
        /// ticks every `tick_interval_ns` (the node's storage timer) until the slot ends.
        /// Zero runs blocks back to back.
        slot_ns: u64 = 0,
        tick_interval_ns: u64 = 2 * std.time.ns_per_ms,
        /// Longest single idle-time tick: a stall of the node's event loop.
        idle_tick_ns_max: u64 = 0,
        /// Slots whose commit overran the slot.
        slots_overrun: u64 = 0,
        header: [header_size]u8 = @splat(0x48),
        samples: Samples,
        busy_retries: u64 = 0,
        /// `request_checkpoint` on an idle database: serializing the staging buffer.
        serialize_ns: [serialize_samples]u64 = @splat(0),
        syncs: u64 = 0,

        /// `self` must not move after this (the engine and overlay point into it).
        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            storage: *Storage,
            shape: Shape,
            layout: Layout,
            idle_ticks: u32,
        ) !void {
            shape.check();
            const config = database_config(shape, layout);
            assert(config.engine.size_bytes() <= storage.size_bytes());
            self.* = .{
                .db = try Database.init(allocator, storage, config),
                .overlay = undefined,
                .storage = storage,
                .shape = shape,
                .prng = Prng.init(5),
                .idle_ticks = idle_ticks,
                .samples = try Samples.init(allocator, shape.round_blocks),
            };
            self.overlay = try Overlay.init(allocator, &self.db.state, bench.overlay_config(shape));
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.samples.deinit(allocator);
            self.overlay.deinit(allocator);
            self.db.deinit(allocator);
            self.* = undefined;
        }

        fn tick_until_durable(self: *Self, sequence: u64) !void {
            var ticks: u64 = 0;
            while (self.db.durable_sequence < sequence) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.storage.tick();
            }
            assert(self.db.durable_sequence >= sequence);
        }

        fn tick_while_phase(self: *Self, phase: database.Phase) !void {
            var ticks: u64 = 0;
            while (self.db.phase == phase) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.storage.tick();
            }
            assert(self.db.phase != phase);
        }

        fn format_open(self: *Self) !void {
            self.db.format(0x7374_6561_6479);
            try self.tick_while_phase(.formatting);
            self.db.open();
            try self.tick_while_phase(.opening);
            if (self.db.open_error) |err| return err;
            assert(self.db.phase == .ready);
            assert(!self.db.head_info.present);
        }

        /// Commits the overlay as the next block; on `error.Busy` ticks and retries.
        fn commit_block(self: *Self) !database.Commit {
            const number: u64 = if (self.db.head_info.present) self.db.head_info.number + 1 else 0;
            std.mem.writeInt(u64, self.header[0..8], number, .little);
            const input: database.BlockInput = .{
                .hash = hash_of(number),
                .parent_hash = if (number == 0) @splat(0) else self.db.head_info.hash,
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
                const commit = self.db.execute_and_commit(&self.overlay, &input) catch |err| {
                    if (err != error.Busy) return err;
                    if (self.db.checkpoint_error) |checkpoint_err| return checkpoint_err;
                    self.busy_retries += 1;
                    self.storage.tick();
                    continue;
                };
                assert(self.db.head_info.number == number);
                return commit;
            }
            return error.Timeout;
        }

        fn fill(self: *Self) !void {
            for (0..self.shape.fill_blocks()) |fill_index| {
                try bench.write_fill(&self.overlay, self.shape, @intCast(fill_index));
                const commit = try self.commit_block();
                try self.tick_until_durable(commit.sequence);
            }
            assert(self.db.state.account_table.count() == self.shape.accounts);
            assert(self.db.state.storage_table.count() == self.shape.slots());
        }

        fn classify(running_before: bool, running_after: bool, finished: bool) Kind {
            if (finished) return if (running_before) .finish else .start;
            if (!running_before) return if (running_after) .start else .none;
            assert(running_after);
            return .advance;
        }

        fn checkpoint_running(self: *const Self) bool {
            return self.db.engine.checkpoint_phase != .idle;
        }

        /// Overlay writes are untimed (execution's job); the clock covers the commit.
        fn measure_block(self: *Self, io: std.Io) !void {
            try bench.write_block(&self.overlay, self.shape, &self.prng);
            const running_before = self.checkpoint_running();
            const completed_before = self.db.checkpoints_completed;
            const syncs_before = self.storage.stats.syncs;
            const start = bench.now_ns(io);
            const commit = try self.commit_block();
            try self.tick_until_durable(commit.sequence);
            const durable = bench.now_ns(io);
            assert(durable >= start);
            if (self.db.checkpoint_error) |err| return err;
            const finished = self.db.checkpoints_completed != completed_before;
            const kind = classify(running_before, self.checkpoint_running(), finished);
            self.samples.add(kind, durable - start);
            self.syncs += self.storage.stats.syncs - syncs_before;
            for (0..self.idle_ticks) |_| self.storage.tick();
            if (self.slot_ns > 0) self.idle_until(io, start + self.slot_ns);
        }

        /// Ticks every `tick_interval_ns` until `deadline_ns`, recording the longest tick.
        fn idle_until(self: *Self, io: std.Io, deadline_ns: u64) void {
            assert(self.slot_ns > 0 and self.tick_interval_ns > 0);
            var now = bench.now_ns(io);
            if (now >= deadline_ns) self.slots_overrun += 1;
            var tick_next = now;
            var spins: u64 = 0;
            while (now < deadline_ns) : (spins += 1) {
                assert(spins < ticks_max);
                if (now >= tick_next) {
                    self.storage.tick();
                    const after = bench.now_ns(io);
                    self.idle_tick_ns_max = @max(self.idle_tick_ns_max, after - now);
                    tick_next = now + self.tick_interval_ns;
                    now = after;
                } else now = bench.now_ns(io);
            }
            assert(now >= deadline_ns);
        }

        pub fn run(self: *Self, io: std.Io) !void {
            try self.format_open();
            try self.fill();
            for (0..self.shape.round_blocks) |_| try self.measure_block(io);
            assert(self.samples.count == self.shape.round_blocks);
            for (&self.serialize_ns) |*sample| sample.* = try self.measure_serialize(io);
            assert(self.db.checkpoint_error == null);
        }

        fn tick_until_idle(self: *Self) !void {
            var ticks: u64 = 0;
            while (!self.db.idle()) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.db.checkpoint_flush();
                self.storage.tick();
            }
            assert(self.db.idle());
        }

        /// Times `request_checkpoint` on an idle database (the synchronous serialization),
        /// then lets that checkpoint finish unpaced.
        fn measure_serialize(self: *Self, io: std.Io) !u64 {
            try self.tick_until_idle();
            const completed = self.db.checkpoints_completed;
            const start = bench.now_ns(io);
            self.db.request_checkpoint();
            const elapsed = bench.now_ns(io) - start;
            try self.tick_until_idle();
            if (self.db.checkpoint_error) |err| return err;
            assert(self.db.checkpoints_completed == completed + 1);
            return elapsed;
        }

        pub fn report(self: *Self, name: []const u8) void {
            const blocks = self.samples.count;
            std.debug.print(
                "{s:<48} {d} blocks, {d:.2} syncs/block, {d} checkpoints of {d:.1} MB, " ++
                    "{d} busy retries\n",
                .{
                    name,
                    blocks,
                    @as(f64, @floatFromInt(self.syncs)) / @as(f64, @floatFromInt(blocks)),
                    self.db.checkpoints_completed,
                    @as(f64, @floatFromInt(self.db.staging_len)) / 1e6,
                    self.busy_retries,
                },
            );
            if (self.slot_ns > 0) {
                std.debug.print("  slot {d} ms: {d} overruns, longest idle tick {d:.2} ms\n", .{
                    self.slot_ns / std.time.ns_per_ms,
                    self.slots_overrun,
                    @as(f64, @floatFromInt(self.idle_tick_ns_max)) / 1e6,
                });
            }
            std.debug.print("  serialize (request_checkpoint) {d:.2} / {d:.2} / {d:.2} ms\n", .{
                @as(f64, @floatFromInt(self.serialize_ns[0])) / 1e6,
                @as(f64, @floatFromInt(self.serialize_ns[1])) / 1e6,
                @as(f64, @floatFromInt(self.serialize_ns[2])) / 1e6,
            });
            print_percentiles("  all commits", self.samples.all[0..blocks]);
            const overlap_count = self.samples.overlap_count;
            if (overlap_count > 0) {
                print_percentiles("  overlap", self.samples.overlap[0..overlap_count]);
            }
            for (kinds) |kind| {
                const index = @backingInt(kind);
                const count = self.samples.counts[index];
                if (count > 0) {
                    print_percentiles(@tagName(kind), self.samples.by_kind[index][0..count]);
                }
            }
        }
    };
}

/// Sorts `samples` and prints count, p50, p90, p99, max (milliseconds), and how many
/// exceed the 50 ms budget.
fn print_percentiles(label: []const u8, samples: []u64) void {
    assert(samples.len > 0);
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const p50 = samples[samples.len / 2];
    const p99 = samples[(samples.len * 99) / 100];
    const max = samples[samples.len - 1];
    assert(p50 <= p99 and p99 <= max);
    var over: u32 = 0;
    for (samples) |sample| over += @intFromBool(sample > budget_ns);
    const format = "{s:<16} n {d:>5}  p50 {d:>7.2} ms  p90 {d:>7.2} ms  p99 {d:>7.2} ms  " ++
        "max {d:>7.2} ms  >50ms {d}\n";
    std.debug.print(format, .{
        label,
        samples.len,
        @as(f64, @floatFromInt(p50)) / 1e6,
        @as(f64, @floatFromInt(samples[(samples.len * 9) / 10])) / 1e6,
        @as(f64, @floatFromInt(p99)) / 1e6,
        @as(f64, @floatFromInt(max)) / 1e6,
        over,
    });
}

/// Runs the steady-state cases whose names match `filter`. They take minutes (the os cases
/// pace 2k blocks at 200 ms), so they run only when the filter names them ("steady").
pub fn run(io: std.Io, filter: ?[]const u8) void {
    const pattern = filter orelse return;
    if (std.mem.indexOf(u8, pattern, "steady") == null) return;
    for (cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        const allocator = std.heap.page_allocator;
        switch (case.storage) {
            .sim => {
                const shape = shape_steady;
                _ = run_sim(io, allocator, shape, case.layout, case.name) catch |err| {
                    std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
                };
            },
            .os => run_os(io, allocator, case.layout, case.name) catch |err| {
                std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
            },
        }
    }
}

pub fn run_sim(
    io: std.Io,
    allocator: std.mem.Allocator,
    shape: Shape,
    layout: Layout,
    name: ?[]const u8,
) !u64 {
    const config = database_config(shape, layout);
    var storage = try SimStorage.init(allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 7,
        .latency_ticks_min = 1,
        .latency_ticks_max = 1,
    });
    defer storage.deinit(allocator);
    const Run = RunType(SimStorage);
    const run_state = try allocator.create(Run);
    defer allocator.destroy(run_state);
    try run_state.init(allocator, &storage, shape, layout, 8);
    defer run_state.deinit(allocator);
    try run_state.run(io);
    if (name) |label| run_state.report(label);
    return run_state.db.checkpoints_completed;
}

const scratch_directory = ".zig-cache/tmp/needlefish-db-steady-bench";
const scratch_path = scratch_directory ++ "/data.db";

fn run_os(io: std.Io, allocator: std.mem.Allocator, layout: Layout, name: []const u8) !void {
    const IO = io_root.IO;
    var backend = (if (builtin.os.tag == .linux) IO.init(.{}) else IO.init()) catch |err| {
        std.debug.print("{s}: skipped, no IO backend: {s}\n", .{ name, @errorName(err) });
        return;
    };
    defer backend.deinit();
    const directory = std.Io.Dir.cwd();
    try directory.createDirPath(io, scratch_directory);
    defer directory.deleteDir(io, scratch_directory) catch |err| {
        std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name, scratch_directory, @errorName(err),
        });
    };
    delete_scratch(io, name);
    defer delete_scratch(io, name);
    const fd = try backend.open_file(scratch_path, .create);
    defer backend.close_now(fd);
    const config = database_config(shape_steady_os, layout);
    assert(config.engine.size_bytes() < 2 << 30);
    const Storage = IoStorageType(IO);
    var storage = try Storage.init(allocator, &backend, fd, .{
        .size_bytes = config.engine.size_bytes(),
    });
    defer storage.deinit(allocator);
    const Run = RunType(Storage);
    const run_state = try allocator.create(Run);
    defer allocator.destroy(run_state);
    try run_state.init(allocator, &storage, shape_steady_os, layout, 0);
    defer run_state.deinit(allocator);
    run_state.slot_ns = 200 * std.time.ns_per_ms;
    try run_state.run(io);
    run_state.report(name);
}

fn delete_scratch(io: std.Io, name: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, scratch_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name, scratch_path, @errorName(err),
        }),
    };
}

test "steady bench: commit loop with automatic checkpoints (small shape)" {
    var layout: Layout = .{
        .journal_size_bytes = 256 * 1024,
        .retained_bytes_max = 256 * 1024,
        .retained_blocks_max = 8,
    };
    const allocator = std.testing.allocator;
    const unpaced = try run_sim(std.testing.io, allocator, shape_steady_test, layout, null);
    try std.testing.expect(unpaced >= 4);
    layout.checkpoint_bytes_per_commit = 64 * 1024;
    const paced = try run_sim(std.testing.io, allocator, shape_steady_test, layout, null);
    try std.testing.expect(paced >= 4);
}

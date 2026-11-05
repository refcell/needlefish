//! Database benchmarks, listed in `src/testing/bench_main.zig`.
//!
//! Every case works on one block shape (`shape_bench`): 1k account writes plus 4k storage
//! writes over a state of 100k accounts, 1k of them contracts with 64 slots each.
//! - `cases` (run by the shared harness, fastest of 5 samples): overlay -> changeset ->
//!   `State.apply` -> state root, in memory; changeset encode and decode throughput.
//! - `run_commit` (its own runner, per-block percentiles): `Database.execute_and_commit`
//!   until the head entry is durable, over `IoStorage` on the OS backend (a scratch file
//!   under `.zig-cache/tmp`, deleted afterwards) and over a zero-latency `SimStorage`, plus
//!   the duration of each checkpoint of the full state.
//!
//! Fixtures come from the page allocator and the scratch file is opened here: this is
//! benchmark scaffolding, not library code. Measured blocks touch distinct, existing accounts
//! and slots (a stride walk coprime with the table sizes), so every block has exactly the
//! same changeset size and the state never grows.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const database = @import("database.zig");
const journal_module = @import("storage/journal.zig");
const checkpoint_module = @import("storage/checkpoint.zig");
const storage_module = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const IoStorageType = @import("storage/io_storage.zig").IoStorageType;
const io_root = @import("../../utilities/io/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const Hash = database.Hash;
const sector_size = storage_module.sector_size;

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
    bytes_per_op: u64 = 0,
};

pub const cases = [_]Case{
    .{
        .name = "db/block 1k acct+4k slot apply+root",
        .iterations = 100,
        .run = bench_block,
    },
    .{
        .name = "db/changeset encode 1k acct+4k slot",
        .iterations = 1_000,
        .run = bench_encode,
        .bytes_per_op = changeset_bytes(shape_bench),
    },
    .{
        .name = "db/changeset decode 1k acct+4k slot",
        .iterations = 1_000,
        .run = bench_decode,
        .bytes_per_op = changeset_bytes(shape_bench),
    },
};

/// The sizes of one benchmark state and its blocks.
pub const Shape = struct {
    accounts: u32,
    contracts: u32,
    slots_per_contract: u32,
    /// Writes of one measured block.
    block_accounts: u32,
    block_slots: u32,
    /// New accounts per setup block; setup blocks also create the contracts' slots.
    fill_accounts: u32,
    /// Measured blocks: `rounds` rounds of `round_blocks`, a checkpoint after each round.
    rounds: u32,
    round_blocks: u32,

    fn slots(shape: Shape) u32 {
        return shape.contracts * shape.slots_per_contract;
    }

    fn fill_blocks(shape: Shape) u32 {
        return shape.accounts / shape.fill_accounts;
    }

    fn fill_slots(shape: Shape) u32 {
        return shape.slots() / shape.fill_blocks();
    }

    fn changed_accounts_max(shape: Shape) u32 {
        return @max(shape.block_accounts, shape.fill_accounts);
    }

    fn changed_slots_max(shape: Shape) u32 {
        return @max(shape.block_slots, shape.fill_slots());
    }

    fn blocks(shape: Shape) u32 {
        return shape.rounds * shape.round_blocks;
    }

    fn check(shape: Shape) void {
        assert(shape.accounts % shape.fill_accounts == 0);
        assert(shape.contracts % shape.fill_blocks() == 0);
        assert(shape.slots() % shape.fill_blocks() == 0);
        // Every contract exists after the first setup block.
        assert(shape.contracts <= shape.fill_accounts);
        assert(shape.block_accounts <= shape.accounts);
        assert(shape.block_slots <= shape.slots());
        assert(std.math.gcd(stride, shape.accounts) == 1);
        assert(std.math.gcd(stride, shape.slots()) == 1);
        assert(shape.rounds > 0 and shape.round_blocks > 0);
    }
};

pub const shape_bench: Shape = .{
    .accounts = 100_000,
    .contracts = 1_000,
    .slots_per_contract = 64,
    .block_accounts = 1_000,
    .block_slots = 4_000,
    .fill_accounts = 4_000,
    .rounds = 4,
    .round_blocks = 32,
};

const shape_test: Shape = .{
    .accounts = 400,
    .contracts = 8,
    .slots_per_contract = 16,
    .block_accounts = 20,
    .block_slots = 40,
    .fill_accounts = 100,
    .rounds = 2,
    .round_blocks = 4,
};

/// Walk step for distinct accounts and slots; coprime with the table sizes.
const stride = 97;
const header_size = 64;
const account_change_bytes = 20 + 1 + 2 * (8 + 32 + 32);
const storage_change_bytes = 20 + 3 * 32;
const changeset_header_bytes = 4 + 2 + 4 + 4 + 4;

/// Encoded size of one measured block's changeset (both sides of every account present).
fn changeset_bytes(shape: Shape) u64 {
    return changeset_header_bytes + @as(u64, shape.block_accounts) * account_change_bytes +
        @as(u64, shape.block_slots) * storage_change_bytes;
}

comptime {
    assert(changeset_bytes(shape_bench) == 629_018);
}

fn address_of(index: u64) Address {
    assert(index <= std.math.maxInt(u32));
    var address: Address = @splat(0x5a);
    std.mem.writeInt(u32, address[0..4], @intCast(index), .big);
    return address;
}

fn hash_of(number: u64) Hash {
    var hash: Hash = @splat(0xbb);
    std.mem.writeInt(u64, hash[0..8], number + 1, .big);
    return hash;
}

/// Setup block `fill_index`: creates its accounts and every slot of its contracts.
fn write_fill(overlay: *Overlay, shape: Shape, fill_index: u32) !void {
    assert(fill_index < shape.fill_blocks());
    const first: u64 = @as(u64, fill_index) * shape.fill_accounts;
    for (0..shape.fill_accounts) |offset| {
        const index = first + offset;
        try overlay.set_account(address_of(index), .{ .nonce = 1, .balance = index + 1 });
    }
    const contracts_per_fill = shape.contracts / shape.fill_blocks();
    const contract_first: u64 = @as(u64, fill_index) * contracts_per_fill;
    for (0..contracts_per_fill) |contract| {
        const address = address_of(contract_first + contract);
        for (0..shape.slots_per_contract) |slot| {
            try overlay.set_storage(address, slot, slot + 1);
        }
    }
    assert(overlay.accounts.count() == shape.fill_accounts);
    assert(overlay.slots.count() == shape.fill_slots());
}

/// One measured block: distinct accounts bump nonce and balance, distinct existing slots
/// increment (never to zero), so the changeset has exactly the block's write counts.
fn write_block(overlay: *Overlay, shape: Shape, prng: *Prng) !void {
    var account = prng.below(shape.accounts);
    for (0..shape.block_accounts) |_| {
        const address = address_of(account);
        var info = overlay.basic(address).?;
        info.nonce += 1;
        info.balance += 1;
        try overlay.set_account(address, info);
        account = (account + stride) % shape.accounts;
    }
    var slot_index = prng.below(shape.slots());
    for (0..shape.block_slots) |_| {
        const address = address_of(slot_index / shape.slots_per_contract);
        const slot = slot_index % shape.slots_per_contract;
        try overlay.set_storage(address, slot, overlay.storage(address, slot) + 1);
        slot_index = (slot_index + stride) % shape.slots();
    }
    assert(overlay.accounts.count() == shape.block_accounts);
    assert(overlay.slots.count() == shape.block_slots);
}

fn state_config(shape: Shape) state_module.Config {
    const accounts = shape.accounts + shape.changed_accounts_max();
    const slots = shape.slots() + shape.changed_slots_max();
    return .{
        .accounts_max = accounts,
        .storage_slots_max = slots,
        .codes_max = 1,
        .code_bytes_max = 64,
        // `State.apply` wants 3 free nodes per change on top of the live trie.
        .account_nodes_max = 3 * accounts + 1024,
        .storage_nodes_max = 3 * slots + 1024,
    };
}

fn changeset_config(shape: Shape) changeset_module.Config {
    return .{
        .accounts_max = shape.changed_accounts_max(),
        .storage_max = shape.changed_slots_max(),
        .codes_max = 1,
        .code_bytes_max = 64,
    };
}

fn overlay_config(shape: Shape) overlay_module.Config {
    return .{
        .accounts_max = shape.changed_accounts_max(),
        .slots_max = shape.changed_slots_max(),
        .codes_max = 1,
    };
}

/// Largest block entry: header plus a changeset of the largest block (setup or measured).
fn body_size_max(shape: Shape) u32 {
    const changeset_max = changeset_header_bytes +
        @as(u64, shape.changed_accounts_max()) * account_change_bytes +
        @as(u64, shape.changed_slots_max()) * storage_change_bytes;
    const size = database.block_entry_fixed_size + header_size + changeset_max;
    return @intCast(storage_module.sector_ceil(size));
}

fn database_config(shape: Shape) database.Config {
    const body_max = body_size_max(shape);
    const state = state_config(shape);
    const blocks_retained = 4;
    // A round (or the setup) stays under half the journal: no automatic checkpoints.
    const blocks_per_lap = @max(shape.round_blocks, shape.fill_blocks()) + 2;
    const entry_bytes = journal_module.entry_size_bytes(body_max) + sector_size;
    const snapshot_bytes = 64 + @as(u64, state.accounts_max) * (20 + 8 + 32 + 32) +
        @as(u64, state.storage_slots_max) * (20 + 32 + 32) + state_module.block_hashes_max * 40;
    const staging = database.checkpoint_header_size + snapshot_bytes +
        blocks_retained * (4 + @as(u64, body_max));
    const block_size: u32 = 64 * 1024;
    const payload = checkpoint_module.payload_capacity(block_size);
    const zone_blocks = std.math.divCeil(u64, staging, payload) catch unreachable; // payload > 0.
    return .{
        .engine = .{
            .journal_size_bytes = 2 * blocks_per_lap * entry_bytes,
            .checkpoint_zone_size_bytes = (zone_blocks + 1) * block_size,
            .entry_body_size_max = body_max,
            .checkpoint_block_size = block_size,
        },
        .state = state,
        .chain = .{
            .blocks_max = blocks_retained,
            .bytes_max = blocks_retained * body_max,
            .transactions_max = 64,
            .canonical_max = 64,
        },
        .changeset = changeset_config(shape),
        .queue_entries_max = 4,
        .checkpoint_staging_bytes = @intCast(staging),
    };
}

// In-memory cases.

const Memory = struct {
    shape: Shape,
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    decoded: Changeset,
    encoded: []u8,
    encoded_len: u32 = 0,
    prng: Prng,

    /// Builds the state with setup blocks, then commits one measured block and encodes it.
    /// `memory` must not move afterwards (the overlay points at its state).
    fn init(memory: *Memory, allocator: std.mem.Allocator, shape: Shape) !void {
        shape.check();
        memory.shape = shape;
        memory.prng = Prng.init(1);
        memory.state = try State.init(allocator, state_config(shape));
        memory.overlay = try Overlay.init(allocator, &memory.state, overlay_config(shape));
        memory.changeset = try Changeset.init(allocator, changeset_config(shape));
        memory.decoded = try Changeset.init(allocator, changeset_config(shape));
        memory.encoded = try allocator.alloc(u8, body_size_max(shape));
        for (0..shape.fill_blocks()) |fill_index| {
            try write_fill(&memory.overlay, shape, @intCast(fill_index));
            _ = try memory.overlay.commit(&memory.changeset);
        }
        assert(memory.state.account_table.count() == shape.accounts);
        assert(memory.state.storage_table.count() == shape.slots());
        _ = try memory.block();
        const encoded = memory.changeset.encode(memory.encoded);
        assert(encoded.len == changeset_bytes(shape));
        memory.encoded_len = @intCast(encoded.len);
    }

    fn deinit(memory: *Memory, allocator: std.mem.Allocator) void {
        allocator.free(memory.encoded);
        memory.decoded.deinit(allocator);
        memory.changeset.deinit(allocator);
        memory.overlay.deinit(allocator);
        memory.state.deinit(allocator);
        memory.* = undefined;
    }

    /// Overlay writes, changeset build, `State.apply`, state root.
    fn block(memory: *Memory) !Hash {
        try write_block(&memory.overlay, memory.shape, &memory.prng);
        const root = try memory.overlay.commit(&memory.changeset);
        assert(memory.changeset.accounts_len == memory.shape.block_accounts);
        assert(memory.changeset.storage_len == memory.shape.block_slots);
        return root;
    }
};

var memory_fixture: ?*Memory = null;

fn get_memory() *Memory {
    if (memory_fixture == null) {
        const allocator = std.heap.page_allocator;
        const memory = allocator.create(Memory) catch @panic("bench fixture: out of memory");
        memory.init(allocator, shape_bench) catch @panic("bench fixture: setup failed");
        memory_fixture = memory;
    }
    return memory_fixture.?;
}

fn bench_block(iterations: u32) u64 {
    const memory = get_memory();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const root = memory.block() catch @panic("bench: block failed");
        accumulator +%= root[0];
    }
    return accumulator;
}

fn bench_encode(iterations: u32) u64 {
    const memory = get_memory();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const encoded = memory.changeset.encode(memory.encoded);
        assert(encoded.len == memory.encoded_len);
        accumulator +%= encoded[encoded.len - 1];
    }
    return accumulator;
}

fn bench_decode(iterations: u32) u64 {
    const memory = get_memory();
    const encoded = memory.encoded[0..memory.encoded_len];
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        memory.decoded.decode(encoded) catch @panic("bench: decode failed");
        accumulator +%= memory.decoded.storage_len;
    }
    return accumulator;
}

// Commit latency.

fn now_ns(io: std.Io) u64 {
    const nanoseconds = std.Io.Clock.awake.now(io).nanoseconds;
    assert(nanoseconds >= 0);
    return @intCast(nanoseconds);
}

/// Upper bound on storage ticks while waiting for one operation (spinning on real IO).
const ticks_max: u64 = 1 << 40;

fn CommitRunType(comptime Storage: type) type {
    return struct {
        const Self = @This();
        const Database = database.DatabaseType(Storage);

        db: Database,
        overlay: Overlay,
        storage: *Storage,
        shape: Shape,
        prng: Prng,
        header: [header_size]u8 = @splat(0x48),
        /// Per measured block: `execute_and_commit` alone, and until the head is durable.
        cpu_ns: []u64,
        durable_ns: []u64,
        /// One checkpoint after setup and one after each round.
        checkpoint_ns: []u64,
        syncs: u64 = 0,

        /// `self` must not move after this (the engine and overlay point into it).
        fn init(self: *Self, allocator: std.mem.Allocator, storage: *Storage, shape: Shape) !void {
            shape.check();
            const config = database_config(shape);
            assert(config.engine.size_bytes() <= storage.size_bytes());
            self.* = .{
                .db = try Database.init(allocator, storage, config),
                .overlay = undefined,
                .storage = storage,
                .shape = shape,
                .prng = Prng.init(2),
                .cpu_ns = try allocator.alloc(u64, shape.blocks()),
                .durable_ns = try allocator.alloc(u64, shape.blocks()),
                .checkpoint_ns = try allocator.alloc(u64, shape.rounds + 1),
            };
            self.overlay = try Overlay.init(allocator, &self.db.state, overlay_config(shape));
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.checkpoint_ns);
            allocator.free(self.durable_ns);
            allocator.free(self.cpu_ns);
            self.overlay.deinit(allocator);
            self.db.deinit(allocator);
            self.* = undefined;
        }

        /// Ticks the storage while `pending(self, argument)` holds.
        fn tick_while(
            self: *Self,
            comptime pending: fn (*const Self, u64) bool,
            argument: u64,
        ) !void {
            var ticks: u64 = 0;
            while (pending(self, argument)) : (ticks += 1) {
                if (ticks == ticks_max) return error.Timeout;
                self.storage.tick();
            }
            assert(!pending(self, argument));
        }

        fn in_phase(self: *const Self, phase: u64) bool {
            return @backingInt(self.db.phase) == phase;
        }

        fn not_durable(self: *const Self, sequence: u64) bool {
            return self.db.durable_sequence < sequence;
        }

        fn checkpoint_pending(self: *const Self, completed: u64) bool {
            return self.db.checkpoints_completed == completed or !self.db.idle();
        }

        fn format_open(self: *Self) !void {
            self.db.format(0x6e65_6564_6c65);
            try self.tick_while(in_phase, @backingInt(database.Phase.formatting));
            self.db.open();
            try self.tick_while(in_phase, @backingInt(database.Phase.opening));
            if (self.db.open_error) |err| return err;
            assert(self.db.phase == .ready);
            assert(!self.db.head_info.present);
        }

        /// Commits the overlay as the next block and waits until its head entry is durable.
        fn commit_block(self: *Self) !database.Commit {
            const number: u64 = if (self.db.head_info.present) self.db.head_info.number + 1 else 0;
            std.mem.writeInt(u64, self.header[0..8], number, .little);
            const input: database.BlockInput = .{
                .hash = hash_of(number),
                .parent_hash = if (number == 0) @splat(0) else self.db.head_info.hash,
                .number = number,
                .timestamp = number * 2,
                .header = &self.header,
                .body = "",
                .receipts = "",
                .transaction_hashes = &.{},
                .changeset = "",
            };
            const commit = try self.db.execute_and_commit(&self.overlay, &input);
            assert(self.db.head_info.number == number);
            return commit;
        }

        fn fill(self: *Self) !void {
            for (0..self.shape.fill_blocks()) |fill_index| {
                try write_fill(&self.overlay, self.shape, @intCast(fill_index));
                const commit = try self.commit_block();
                try self.tick_while(not_durable, commit.head_sequence);
            }
            assert(self.db.state.account_table.count() == self.shape.accounts);
            assert(self.db.state.storage_table.count() == self.shape.slots());
        }

        /// Overlay writes are untimed (execution's job); the clock covers the commit.
        fn measure_block(self: *Self, io: std.Io, sample: u32) !void {
            try write_block(&self.overlay, self.shape, &self.prng);
            const syncs_before = self.storage.stats.syncs;
            const start = now_ns(io);
            const commit = try self.commit_block();
            const returned = now_ns(io);
            try self.tick_while(not_durable, commit.head_sequence);
            const durable = now_ns(io);
            assert(durable >= returned and returned >= start);
            self.cpu_ns[sample] = returned - start;
            self.durable_ns[sample] = durable - start;
            self.syncs += self.storage.stats.syncs - syncs_before;
        }

        /// From the request until the checkpoint is written and the engine is idle again.
        fn measure_checkpoint(self: *Self, io: std.Io, sample: u32) !void {
            assert(self.db.idle());
            const completed = self.db.checkpoints_completed;
            const start = now_ns(io);
            self.db.request_checkpoint();
            try self.tick_while(checkpoint_pending, completed);
            self.checkpoint_ns[sample] = now_ns(io) - start;
            if (self.db.checkpoint_error) |err| return err;
            assert(self.db.checkpoints_completed == completed + 1);
        }

        fn run(self: *Self, io: std.Io) !void {
            try self.format_open();
            try self.fill();
            try self.measure_checkpoint(io, 0);
            for (0..self.shape.rounds) |round| {
                for (0..self.shape.round_blocks) |offset| {
                    const sample = round * self.shape.round_blocks + offset;
                    try self.measure_block(io, @intCast(sample));
                }
                try self.measure_checkpoint(io, @intCast(round + 1));
            }
            assert(self.db.idle());
            assert(self.db.checkpoints_completed == self.shape.rounds + 1);
        }

        fn report(self: *Self, name: []const u8) void {
            const blocks = self.shape.blocks();
            std.debug.print("{s:<40} {d} blocks, {d:.1} syncs/block, checkpoint {d:.1} MB\n", .{
                name,
                blocks,
                @as(f64, @floatFromInt(self.syncs)) / @as(f64, @floatFromInt(blocks)),
                @as(f64, @floatFromInt(self.db.staging_len)) / 1e6,
            });
            print_percentiles("  execute_and_commit (cpu)", self.cpu_ns);
            print_percentiles("  commit until durable", self.durable_ns);
            print_percentiles("  checkpoint", self.checkpoint_ns);
        }
    };
}

/// Sorts `samples` and prints p50, p99, and max in microseconds.
fn print_percentiles(label: []const u8, samples: []u64) void {
    assert(samples.len > 0);
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const p50 = samples[samples.len / 2];
    const p99 = samples[(samples.len * 99) / 100];
    const max = samples[samples.len - 1];
    assert(p50 <= p99 and p99 <= max);
    std.debug.print("{s:<40} p50 {d:>10.1} us  p99 {d:>10.1} us  max {d:>10.1} us\n", .{
        label,
        @as(f64, @floatFromInt(p50)) / 1e3,
        @as(f64, @floatFromInt(p99)) / 1e3,
        @as(f64, @floatFromInt(max)) / 1e3,
    });
}

fn matches(name: []const u8, filter: ?[]const u8) bool {
    const pattern = filter orelse return true;
    return std.mem.indexOf(u8, name, pattern) != null;
}

const name_sim = "db/commit sim (zero latency)";
const name_os = "db/commit os (fsync)";

/// Runs the commit-latency benchmarks whose names match `filter`.
pub fn run_commit(io: std.Io, filter: ?[]const u8) void {
    if (matches(name_sim, filter)) {
        run_commit_sim(io, std.heap.page_allocator, shape_bench, name_sim) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ name_sim, @errorName(err) });
        };
    }
    if (matches(name_os, filter)) {
        run_commit_os(io, std.heap.page_allocator) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ name_os, @errorName(err) });
        };
    }
}

fn run_commit_sim(
    io: std.Io,
    allocator: std.mem.Allocator,
    shape: Shape,
    name: ?[]const u8,
) !void {
    const config = database_config(shape);
    var storage = try SimStorage.init(allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 3,
        .latency_ticks_min = 1,
        .latency_ticks_max = 1,
    });
    defer storage.deinit(allocator);
    const Run = CommitRunType(SimStorage);
    const run = try allocator.create(Run);
    defer allocator.destroy(run);
    try run.init(allocator, &storage, shape);
    defer run.deinit(allocator);
    try run.run(io);
    if (name) |label| run.report(label);
}

const scratch_directory = ".zig-cache/tmp/needlefish-db-bench";
const scratch_path = scratch_directory ++ "/data.db";

fn run_commit_os(io: std.Io, allocator: std.mem.Allocator) !void {
    const IO = io_root.IO;
    var backend = (if (builtin.os.tag == .linux) IO.init(.{}) else IO.init()) catch |err| {
        std.debug.print("{s}: skipped, no IO backend: {s}\n", .{ name_os, @errorName(err) });
        return;
    };
    defer backend.deinit();
    const directory = std.Io.Dir.cwd();
    try directory.createDirPath(io, scratch_directory);
    defer directory.deleteDir(io, scratch_directory) catch |err| {
        std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name_os, scratch_directory, @errorName(err),
        });
    };
    // A file left by an interrupted run could be longer than the layout: start empty.
    delete_scratch(io);
    defer delete_scratch(io);
    const fd = try backend.open_file(scratch_path, .create);
    defer backend.close_now(fd);
    const config = database_config(shape_bench);
    const Storage = IoStorageType(IO);
    var storage = try Storage.init(allocator, &backend, fd, .{
        .size_bytes = config.engine.size_bytes(),
    });
    defer storage.deinit(allocator);
    const Run = CommitRunType(Storage);
    const run = try allocator.create(Run);
    defer allocator.destroy(run);
    try run.init(allocator, &storage, shape_bench);
    defer run.deinit(allocator);
    try run.run(io);
    run.report(name_os);
}

fn delete_scratch(io: std.Io) void {
    std.Io.Dir.cwd().deleteFile(io, scratch_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name_os, scratch_path, @errorName(err),
        }),
    };
}

test "bench: cases are well formed" {
    for (cases) |case| {
        assert(case.name.len > 0);
        assert(case.iterations > 0);
    }
    assert(cases.len == 3);
    shape_bench.check();
    shape_test.check();
    try std.testing.expect(matches(name_os, "db/commit"));
    try std.testing.expect(!matches(name_os, "trie"));
}

test "bench: in-memory block and changeset round trip (small shape)" {
    const allocator = std.testing.allocator;
    const memory = try allocator.create(Memory);
    defer allocator.destroy(memory);
    try memory.init(allocator, shape_test);
    defer memory.deinit(allocator);
    const root_before = try memory.state.state_root();
    const root_after = try memory.block();
    try std.testing.expect(!std.mem.eql(u8, &root_before, &root_after));
    const encoded = memory.changeset.encode(memory.encoded);
    try memory.decoded.decode(encoded);
    try std.testing.expectEqual(memory.changeset.storage_len, memory.decoded.storage_len);
    try std.testing.expectEqual(changeset_bytes(shape_test), encoded.len);
}

test "bench: commit loop over SimStorage (small shape)" {
    try run_commit_sim(std.testing.io, std.testing.allocator, shape_test, null);
}

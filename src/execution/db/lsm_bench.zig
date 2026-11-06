//! LSM tree costs for flat state (disk state phase 2), run by `bench.run_commit` (filter
//! "db/lsm"): put throughput, compaction IO per commit and write amplification over a run of
//! mainnet-sized 200 ms blocks, and point lookups (warm hit, cold hit, absent key).
//!
//! Two trees share one grid and free set, as the database will use them: accounts (32-byte
//! hashed key, 80-byte value: nonce, balance, code hash, slot count) and storage (64-byte key:
//! account hash ++ slot hash, 32-byte value). Each block writes 1k accounts and 4k slots with
//! uniformly random keys over a fixed universe (hashed keys are uniform; repeats model hot
//! keys), then grants each tree its compaction budget. Every 50 blocks (10 s) a checkpoint is
//! simulated on the free set (snapshot, then durable), so compacted blocks are reused on the
//! same schedule as with the engine.
//!
//! Storage is `SimStorage` with one tick of latency: IO costs only its CPU side (copy,
//! checksum, verify), not device time. Write amplification counts whole grid blocks written
//! (block size each) over the logical bytes put (key + value per put).
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const storage_module = @import("storage/root.zig");
const lsm = storage_module.lsm;
const SimStorage = storage_module.SimStorage;
const FreeSet = storage_module.free_set.FreeSet;
const BlockCache = storage_module.table.BlockCache;
const Prng = @import("../../testing/prng.zig").Prng;

const AccountTree = lsm.TreeType(SimStorage, 32, 80);
const StorageTree = lsm.TreeType(SimStorage, 64, 32);
const Grid = AccountTree.Grid;

const block_size: u32 = 64 * 1024;
const grid_blocks: u64 = 24 * 1024; // 1.5 GiB.
const blocks_run: u32 = 1000;
const accounts_per_block: u32 = 1000;
const slots_per_block: u32 = 4000;
const account_universe: u64 = 1_000_000;
const slot_universe: u64 = 4_000_000;
const checkpoint_interval_blocks: u32 = 50;
const budget_blocks: u64 = 256;
const lookups: u32 = 20_000;

fn tree_config(memtable_entries_max: u32) lsm.Config {
    return .{
        .block_size = block_size,
        .block_count = grid_blocks,
        .memtable_entries_max = memtable_entries_max,
        .flush_entries_min = memtable_entries_max / 2,
        .replay_entries_max = memtable_entries_max / 4,
        .table_records_max = 64 * 1024,
        .level0_tables_max = 4,
        .levels_count = 7,
        .growth_factor = 8,
    };
}

fn key_of(comptime size: u32, id: u64) [size]u8 {
    var key: [size]u8 = undefined;
    for (0..size / 8) |chunk| {
        // Storage keys: the first half is the owner account's hash (64 slots per account).
        const source = if (size == 64 and chunk < 4) id / 64 else id;
        const word = std.hash.Wyhash.hash(chunk, std.mem.asBytes(&source));
        std.mem.writeInt(u64, key[chunk * 8 ..][0..8], word, .little);
    }
    return key;
}

const Fixture = struct {
    sim: SimStorage,
    grid: Grid,
    free_set: FreeSet,
    free_set_image: []u8,
    cache: BlockCache,
    accounts: AccountTree,
    storage: StorageTree,
    lookup_done: bool = false,

    fn on_account_lookup(tree: *AccountTree) void {
        const self: *Fixture = @alignCast(@fieldParentPtr("accounts", tree));
        self.lookup_done = true;
    }

    fn on_storage_lookup(tree: *StorageTree) void {
        const self: *Fixture = @alignCast(@fieldParentPtr("storage", tree));
        self.lookup_done = true;
    }

    fn io_pending(self: *const Fixture) bool {
        return self.accounts.compaction.io_pending or self.storage.compaction.io_pending;
    }

    fn settle(self: *Fixture) void {
        var ticks: u64 = 0;
        while (self.io_pending()) : (ticks += 1) {
            assert(ticks < 1_000_000);
            self.sim.tick();
        }
    }

    fn checkpoint(self: *Fixture) void {
        self.free_set.checkpoint_begin(self.free_set_image);
        self.free_set.checkpoint_durable();
    }
};

fn fixture_create(allocator: std.mem.Allocator) !*Fixture {
    const fixture = try allocator.create(Fixture);
    fixture.sim = try SimStorage.init(allocator, .{
        .size_bytes = grid_blocks * block_size,
        .seed = 1,
        .latency_ticks_max = 1,
    });
    fixture.grid = Grid.init(&fixture.sim, .{
        .zone_offset = 0,
        .block_size = block_size,
        .block_count = grid_blocks,
    });
    fixture.free_set = try FreeSet.init(allocator, grid_blocks);
    fixture.free_set_image = try allocator.alloc(u8, @intCast(fixture.free_set.encoded_size()));
    fixture.cache = try BlockCache.init(allocator, block_size, 1024);
    fixture.lookup_done = false;
    const grid = &fixture.grid;
    const cache = &fixture.cache;
    fixture.accounts = try AccountTree.init(allocator, grid, cache, tree_config(32 * 1024));
    fixture.storage = try StorageTree.init(allocator, grid, cache, tree_config(64 * 1024));
    fixture.accounts.bind(grid, &fixture.free_set);
    fixture.storage.bind(grid, &fixture.free_set);
    return fixture;
}

const RunResult = struct {
    put_ns: u64 = 0,
    compaction_ns: u64 = 0,
    puts: u64 = 0,
    busy: u64 = 0,
    /// Per commit: block reads + writes of both trees.
    io_max: u64 = 0,
    io_total: u64 = 0,
};

fn put_block(fixture: *Fixture, prng: *Prng, result: *RunResult) void {
    var value_account: [80]u8 = undefined;
    var value_slot: [32]u8 = undefined;
    for (0..accounts_per_block) |_| {
        const key = key_of(32, prng.below(account_universe));
        prng.fill(&value_account);
        fixture.accounts.put(&key, &value_account) catch {
            result.busy += 1;
        };
    }
    for (0..slots_per_block) |_| {
        const key = key_of(64, prng.below(slot_universe));
        prng.fill(&value_slot);
        fixture.storage.put(&key, &value_slot) catch {
            result.busy += 1;
        };
    }
    result.puts += accounts_per_block + slots_per_block;
}

fn io_count(fixture: *const Fixture) u64 {
    const accounts = fixture.accounts.stats;
    const storage = fixture.storage.stats;
    return accounts.blocks_read + accounts.blocks_written + storage.blocks_read +
        storage.blocks_written;
}

fn run_blocks(io: std.Io, fixture: *Fixture) RunResult {
    var result: RunResult = .{};
    var prng = Prng.init(42);
    for (0..blocks_run) |block| {
        const start = bench.now_ns(io);
        put_block(fixture, &prng, &result);
        const put_end = bench.now_ns(io);
        const io_before = io_count(fixture);
        fixture.accounts.compact(budget_blocks);
        fixture.storage.compact(budget_blocks);
        fixture.settle();
        result.compaction_ns += bench.now_ns(io) - put_end;
        result.put_ns += put_end - start;
        const used = io_count(fixture) - io_before;
        result.io_max = @max(result.io_max, used);
        result.io_total += used;
        if ((block + 1) % checkpoint_interval_blocks == 0) fixture.checkpoint();
    }
    return result;
}

fn lookup_ns(
    io: std.Io,
    fixture: *Fixture,
    keys_hot: u64,
    absent: bool,
) !struct { f64, u32 } {
    var prng = Prng.init(7);
    var found: u32 = 0;
    // Warm-up pass over the hot set fills the cache when it is large enough.
    for (0..@min(keys_hot, lookups)) |index| _ = try lookup_one(fixture, index);
    const start = bench.now_ns(io);
    for (0..lookups) |_| {
        var id = prng.below(keys_hot);
        if (absent) id += slot_universe;
        if (try lookup_one(fixture, id)) found += 1;
    }
    const elapsed = bench.now_ns(io) - start;
    return .{ @as(f64, @floatFromInt(elapsed)) / lookups, found };
}

fn lookup_one(fixture: *Fixture, id: u64) !bool {
    const key = key_of(64, id);
    if (fixture.storage.lookup(&key, Fixture.on_storage_lookup) == .pending) {
        var ticks: u32 = 0;
        while (!fixture.lookup_done) : (ticks += 1) {
            if (ticks > 10_000) return error.Timeout;
            fixture.sim.tick();
        }
        fixture.lookup_done = false;
    }
    return try fixture.storage.lookup_result;
}

fn print_levels(name: []const u8, tree: anytype) void {
    std.debug.print("  {s} levels (tables/records):", .{name});
    for (0..tree.config.levels_count) |level| {
        const records = tree.level_records[level];
        std.debug.print(" L{d} {d}/{d}", .{ level, tree.level_count[level], records });
    }
    std.debug.print("\n", .{});
}

fn run_case(io: std.Io) !void {
    const allocator = std.heap.page_allocator;
    const fixture = try fixture_create(allocator);
    const result = run_blocks(io, fixture);
    const accounts = fixture.accounts.stats;
    const storage = fixture.storage.stats;
    const logical = accounts.puts * (32 + 80) + storage.puts * (64 + 32);
    const written = (accounts.blocks_written + storage.blocks_written) * block_size;
    const amplification = @as(f64, @floatFromInt(written)) / @as(f64, @floatFromInt(logical));
    const account_bytes = accounts.puts * (32 + 80);
    const account_amp = @as(f64, @floatFromInt(accounts.blocks_written * block_size)) /
        @as(f64, @floatFromInt(account_bytes));
    const storage_amp = @as(f64, @floatFromInt(storage.blocks_written * block_size)) /
        @as(f64, @floatFromInt(storage.puts * (64 + 32)));
    std.debug.print(
        "db/lsm flat state: {d} blocks of {d} accounts + {d} slots, 64 KiB grid blocks\n",
        .{ blocks_run, accounts_per_block, slots_per_block },
    );
    std.debug.print("  put {d:.0} ns/put (memtable insert), busy {d}\n", .{
        @as(f64, @floatFromInt(result.put_ns)) / @as(f64, @floatFromInt(result.puts)),
        result.busy,
    });
    std.debug.print(
        "  compaction cpu {d:.2} ms/block, io {d:.1} blocks/block (max {d}, budget {d}/tree)\n",
        .{
            @as(f64, @floatFromInt(result.compaction_ns)) / 1e6 / blocks_run,
            @as(f64, @floatFromInt(result.io_total)) / blocks_run,
            result.io_max,
            budget_blocks,
        },
    );
    std.debug.print(
        "  write amplification {d:.2} (accounts {d:.2}, storage {d:.2}); stalls {d}\n",
        .{ amplification, account_amp, storage_amp, accounts.stalls + storage.stalls },
    );
    print_levels("accounts", &fixture.accounts);
    print_levels("storage", &fixture.storage);
    try run_lookups(io, fixture);
}

fn run_lookups(io: std.Io, fixture: *Fixture) !void {
    const allocator = std.heap.page_allocator;
    // Warm: a 10k-key hot set and a cache that holds its blocks.
    fixture.cache.deinit(allocator);
    fixture.cache = try BlockCache.init(allocator, block_size, 16 * 1024);
    const warm, _ = try lookup_ns(io, fixture, 10_000, false);
    // Cold: a 16-block cache, keys over the whole universe.
    fixture.cache.deinit(allocator);
    fixture.cache = try BlockCache.init(allocator, block_size, 16);
    const cold, const found = try lookup_ns(io, fixture, slot_universe, false);
    const absent, const found_absent = try lookup_ns(io, fixture, slot_universe, true);
    assert(found_absent == 0);
    const stats = fixture.storage.stats;
    std.debug.print(
        "  storage lookup: warm hit {d:.0} ns, cold {d:.0} ns ({d}/{d} present), " ++
            "absent {d:.0} ns\n",
        .{ warm, cold, found, lookups, absent },
    );
    std.debug.print("  filter skips {d}, table probes {d}\n", .{
        stats.filter_negatives,
        stats.table_probes,
    });
}

/// Runs the LSM benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches("db/lsm flat state", filter)) return;
    run_case(io) catch |err| std.debug.print("db/lsm: failed: {s}\n", .{@errorName(err)});
}

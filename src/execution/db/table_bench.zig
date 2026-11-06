//! Sorted-table costs on the grid, run by `bench.run_commit` (filter "db/table"):
//! build throughput, point lookup with the block cache warm (hit) and cold (one verified
//! block read per lookup), and absent keys. Records are code-shaped: a 32-byte hash key and
//! a 100..8000-byte value, the first user planned for tables (contract code).
//!
//! Storage is `SimStorage` with one tick of latency, so a miss measures the CPU side of a
//! read (copy, block checksum verify, structural check, cache insert), not device latency.
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const storage_module = @import("storage/root.zig");
const table_module = storage_module.table;
const SimStorage = storage_module.SimStorage;
const FreeSet = storage_module.free_set.FreeSet;
const Prng = @import("../../testing/prng.zig").Prng;

const Table = table_module.TableType(SimStorage, 32);
const Key = Table.Key;
const BlockCache = table_module.BlockCache;

const block_size: u32 = 64 * 1024;
const record_count: u32 = 10_000;
const lookups: u32 = 20_000;

const Records = struct {
    keys: []Key,
    starts: []u32,
    values: []u8,
    cursor: u32 = 0,

    fn next(context: *anyopaque) ?Table.Record {
        const self: *Records = @ptrCast(@alignCast(context));
        if (self.cursor == self.keys.len) return null;
        const index = self.cursor;
        self.cursor += 1;
        const value = self.values[self.starts[index]..self.starts[index + 1]];
        return .{ .key = &self.keys[index], .value = value };
    }

    fn less(_: void, a: Key, b: Key) bool {
        return std.mem.order(u8, &a, &b) == .lt;
    }
};

const Fixture = struct {
    sim: SimStorage,
    grid: Table.Grid,
    free_set: FreeSet,
    builder: Table.Builder,
    done: bool = false,

    fn on_built(builder: *Table.Builder) void {
        const self: *Fixture = @alignCast(@fieldParentPtr("builder", builder));
        self.done = true;
    }
};

const Lookup = struct {
    reader: Table.Reader,
    done: bool = false,

    fn on_read(reader: *Table.Reader) void {
        const self: *Lookup = @alignCast(@fieldParentPtr("reader", reader));
        self.done = true;
    }

    fn run(self: *Lookup, sim: *SimStorage, info: *const Table.Info, key: *const Key) !bool {
        self.done = false;
        if (self.reader.lookup(info, key, on_read) == .pending) {
            var ticks: u32 = 0;
            while (!self.done) : (ticks += 1) {
                if (ticks > 1000) return error.Timeout;
                sim.tick();
            }
        }
        try self.reader.result;
        return self.reader.value != null;
    }
};

fn generate(allocator: std.mem.Allocator, prng: *Prng) !Records {
    const keys = try allocator.alloc(Key, record_count);
    const starts = try allocator.alloc(u32, record_count + 1);
    for (keys) |*key| prng.fill(key);
    std.mem.sortUnstable(Key, keys, {}, Records.less);
    var total: u32 = 0;
    for (starts[0..record_count]) |*start| {
        start.* = total;
        total += @intCast(prng.range(100, 8000));
    }
    starts[record_count] = total;
    const values = try allocator.alloc(u8, total);
    prng.fill(values);
    return .{ .keys = keys, .starts = starts, .values = values };
}

fn measure_lookups(
    io: std.Io,
    fixture: *Fixture,
    info: *const Table.Info,
    records: *const Records,
    cache_blocks: u32,
    present: bool,
) !f64 {
    const allocator = std.heap.page_allocator;
    var cache = try BlockCache.init(allocator, block_size, cache_blocks);
    defer cache.deinit(allocator);
    var lookup: Lookup = .{ .reader = try Table.Reader.init(allocator, &fixture.grid, &cache) };
    defer lookup.reader.deinit(allocator);
    var prng = Prng.init(77);
    // Warm: one pass over the keys fills a large cache with every block.
    for (records.keys) |*key| _ = try lookup.run(&fixture.sim, info, key);
    var found: u32 = 0;
    const start = bench.now_ns(io);
    for (0..lookups) |_| {
        var key: Key = records.keys[prng.below(record_count)];
        if (!present) prng.fill(&key);
        if (try lookup.run(&fixture.sim, info, &key)) found += 1;
    }
    const elapsed = bench.now_ns(io) - start;
    assert(found == if (present) lookups else 0);
    return @as(f64, @floatFromInt(elapsed)) / lookups;
}

fn run_case(io: std.Io) !void {
    const allocator = std.heap.page_allocator;
    var prng = Prng.init(5);
    var records = try generate(allocator, &prng);
    const bytes_total = records.starts[record_count] + @as(u64, record_count) * 32;
    const blocks = Table.blocks_max(block_size, record_count, bytes_total);
    const fixture = try allocator.create(Fixture);
    fixture.sim = try SimStorage.init(allocator, .{
        .size_bytes = (blocks + 1) * block_size,
        .seed = 1,
        .latency_ticks_max = 1,
    });
    fixture.grid = Table.Grid.init(&fixture.sim, .{
        .zone_offset = 0,
        .block_size = block_size,
        .block_count = blocks + 1,
    });
    fixture.free_set = try FreeSet.init(allocator, blocks + 1);
    fixture.builder = try Table.Builder.init(allocator, &fixture.grid);
    fixture.done = false;
    var reservation = try fixture.free_set.reserve(blocks);
    const start = bench.now_ns(io);
    const source: Table.Source = .{ .context = &records, .next = Records.next };
    fixture.builder.build(source, &fixture.free_set, &reservation, Fixture.on_built);
    while (!fixture.done) fixture.sim.tick();
    const build_ns = bench.now_ns(io) - start;
    fixture.free_set.forfeit(&reservation);
    const info = try fixture.builder.result;

    const cache_all = 2 * info.data_block_count + 32;
    const hit = try measure_lookups(io, fixture, &info, &records, cache_all, true);
    const miss = try measure_lookups(io, fixture, &info, &records, 16, true);
    const absent = try measure_lookups(io, fixture, &info, &records, 16, false);
    const megabytes = @as(f64, @floatFromInt(bytes_total)) / (1024 * 1024);
    const build_ms = @as(f64, @floatFromInt(build_ns)) / 1e6;
    std.debug.print(
        "db/table code-sized: {d} records, {d:.1} MiB, {d} data blocks of 64 KiB\n",
        .{ record_count, megabytes, info.data_block_count },
    );
    const build_rate = megabytes / build_ms * 1e3;
    std.debug.print("  build {d:.1} ms ({d:.0} MiB/s)\n", .{ build_ms, build_rate });
    std.debug.print(
        "  lookup hit (warm cache) {d:.0} ns, miss (1 block read) {d:.0} ns, " ++
            "absent {d:.0} ns\n",
        .{ hit, miss, absent },
    );
}

/// Runs the table benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches("db/table code-sized", filter)) return;
    run_case(io) catch |err| std.debug.print("db/table: failed: {s}\n", .{@errorName(err)});
}

//! Table tests: build/lookup/scan differential against a sorted reference, seeded over block
//! sizes, record counts, and value sizes; corruption is reported, never served; decoder fuzz.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const grid_module = @import("grid.zig");
const table_module = @import("table.zig");
const free_set_module = @import("free_set.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

const sector_size = storage.sector_size;
const Table = table_module.TableType(SimStorage, 32);
const Key = Table.Key;
const FreeSet = free_set_module.FreeSet;
const BlockCache = table_module.BlockCache;

const records_max = 3000;

/// The reference: sorted unique keys with their values in one byte arena.
const Reference = struct {
    keys: [records_max]Key = undefined,
    value_starts: [records_max + 1]u32 = undefined,
    values: [records_max * 300]u8 = undefined,
    count: u32 = 0,
    cursor: u32 = 0,

    fn value(self: *const Reference, index: u32) []const u8 {
        return self.values[self.value_starts[index]..self.value_starts[index + 1]];
    }

    fn generate(self: *Reference, prng: *Prng, count: u32, value_max: u32) void {
        assert(count <= records_max);
        for (self.keys[0..count]) |*key| prng.fill(key);
        std.mem.sortUnstable(Key, self.keys[0..count], {}, less);
        // Drop duplicates (vanishingly rare with random 32-byte keys, but keep it exact).
        var unique: u32 = 0;
        for (self.keys[0..count], 0..) |key, index| {
            if (index > 0 and std.mem.eql(u8, &key, &self.keys[unique - 1])) continue;
            self.keys[unique] = key;
            unique += 1;
        }
        self.count = unique;
        var position: u32 = 0;
        for (0..unique) |index| {
            self.value_starts[index] = position;
            const length: u32 = @intCast(prng.below(@min(value_max, 300) + 1));
            prng.fill(self.values[position..][0..length]);
            position += length;
        }
        self.value_starts[unique] = position;
        self.cursor = 0;
    }

    fn less(_: void, a: Key, b: Key) bool {
        return std.mem.order(u8, &a, &b) == .lt;
    }

    fn bytes_total(self: *const Reference) u64 {
        return @as(u64, self.count) * 32 + self.value_starts[self.count];
    }

    fn next(context: *anyopaque) ?Table.Record {
        const self: *Reference = @ptrCast(@alignCast(context));
        if (self.cursor == self.count) return null;
        const index = self.cursor;
        self.cursor += 1;
        return .{ .key = &self.keys[index], .value = self.value(index) };
    }

    /// Index of `key`, or of the first key above it.
    fn lower_bound(self: *const Reference, key: *const Key) u32 {
        var low: u32 = 0;
        var high: u32 = self.count;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (std.mem.order(u8, &self.keys[middle], key) == .lt) low = middle + 1 else {
                high = middle;
            }
        }
        return low;
    }
};

const Harness = struct {
    sim: SimStorage,
    grid: Table.Grid,
    free_set: FreeSet,
    cache: BlockCache,
    builder: Table.Builder,
    reader: Table.Reader,
    built: bool = false,
    read_done: bool = false,

    fn init(harness: *Harness, block_size: u32, block_count: u64, cache_blocks: u32) !void {
        harness.sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = block_count * block_size,
            .seed = block_size,
        });
        errdefer harness.sim.deinit(testing.allocator);
        harness.grid = Table.Grid.init(&harness.sim, .{
            .zone_offset = 0,
            .block_size = block_size,
            .block_count = block_count,
        });
        harness.grid.format_id = 5;
        harness.free_set = try FreeSet.init(testing.allocator, block_count);
        errdefer harness.free_set.deinit(testing.allocator);
        harness.cache = try BlockCache.init(testing.allocator, block_size, cache_blocks);
        errdefer harness.cache.deinit(testing.allocator);
        harness.builder = try Table.Builder.init(testing.allocator, &harness.grid);
        errdefer harness.builder.deinit(testing.allocator);
        harness.reader = try Table.Reader.init(testing.allocator, &harness.grid, &harness.cache);
    }

    fn deinit(harness: *Harness) void {
        harness.reader.deinit(testing.allocator);
        harness.builder.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.free_set.deinit(testing.allocator);
        harness.sim.deinit(testing.allocator);
    }

    fn on_built(builder: *Table.Builder) void {
        const harness: *Harness = @alignCast(@fieldParentPtr("builder", builder));
        harness.built = true;
    }

    fn on_read(reader: *Table.Reader) void {
        const harness: *Harness = @alignCast(@fieldParentPtr("reader", reader));
        harness.read_done = true;
    }

    fn build(harness: *Harness, reference: *Reference) !Table.Info {
        const block_size = harness.grid.config.block_size;
        const blocks = Table.blocks_max(block_size, reference.count, reference.bytes_total());
        return harness.build_reserving(reference, blocks);
    }

    /// Reserves every free block, so only the index capacity limits the table.
    fn build_unbounded(harness: *Harness, reference: *Reference) !Table.Info {
        return harness.build_reserving(reference, harness.free_set.count_free());
    }

    fn build_reserving(harness: *Harness, reference: *Reference, blocks: u64) !Table.Info {
        var reservation = try harness.free_set.reserve(blocks);
        defer harness.free_set.forfeit(&reservation);
        harness.built = false;
        reference.cursor = 0;
        harness.builder.build(
            .{ .context = reference, .next = Reference.next },
            &harness.free_set,
            &reservation,
            on_built,
        );
        var ticks: u32 = 0;
        while (!harness.built) : (ticks += 1) {
            if (ticks > 1_000_000) return error.Timeout;
            harness.sim.tick();
        }
        return harness.builder.result;
    }

    fn wait(harness: *Harness, status: table_module.Status) !void {
        if (status == .done) return;
        var ticks: u32 = 0;
        while (!harness.read_done) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            harness.sim.tick();
        }
    }

    fn lookup(harness: *Harness, info: *const Table.Info, key: *const Key) !?[]const u8 {
        harness.read_done = false;
        try harness.wait(harness.reader.lookup(info, key, on_read));
        try harness.reader.result;
        return harness.reader.value;
    }
};

const ScanCheck = struct {
    reference: *const Reference,
    position: u32,
    end: u32,
    stop_after: u32,
    visited: u32 = 0,
    mismatch: bool = false,

    fn visit(context: *anyopaque, key: *const Key, value: []const u8) bool {
        const self: *ScanCheck = @ptrCast(@alignCast(context));
        const ok = self.position < self.end and
            std.mem.eql(u8, key, &self.reference.keys[self.position]) and
            std.mem.eql(u8, value, self.reference.value(self.position));
        if (!ok) self.mismatch = true;
        self.position += 1;
        self.visited += 1;
        return self.visited < self.stop_after;
    }
};

fn check_scan(
    harness: *Harness,
    info: *const Table.Info,
    reference: *const Reference,
    prng: *Prng,
) !void {
    var first: Key = undefined;
    var last: Key = undefined;
    prng.fill(&first);
    prng.fill(&last);
    if (prng.chance(1, 2)) first = reference.keys[prng.below(reference.count)];
    if (std.mem.order(u8, &first, &last) == .gt) std.mem.swap(Key, &first, &last);
    const start = reference.lower_bound(&first);
    var end = reference.lower_bound(&last);
    if (end < reference.count and std.mem.eql(u8, &reference.keys[end], &last)) end += 1;
    const stop_after: u32 = if (prng.chance(1, 4)) @intCast(prng.range(1, 10)) else records_max + 1;
    var check: ScanCheck = .{
        .reference = reference,
        .position = start,
        .end = end,
        .stop_after = stop_after,
    };
    harness.read_done = false;
    const status = harness.reader.scan(info, &first, &last, .{
        .context = &check,
        .visit = ScanCheck.visit,
    }, Harness.on_read);
    try harness.wait(status);
    try harness.reader.result;
    try testing.expect(!check.mismatch);
    try testing.expectEqual(@min(end - start, stop_after), check.visited);
}

fn differential(seed: u64, prng: *Prng) !void {
    const block_size: u32 = sector_size * @as(u32, @intCast(prng.range(1, 6)));
    const value_wanted: u32 = @intCast(prng.range(0, 300));
    const value_max: u32 = @min(Table.value_size_max(block_size), value_wanted);
    // Stay within one index block: half full data blocks at worst.
    const per_block = (block_size - 256) / (32 + 4 + value_max) / 2 + 1;
    const fit: u64 = @min(records_max, per_block * (Table.index_capacity(block_size) - 1));
    const count: u32 = @intCast(prng.range(1, fit));
    const reference = try testing.allocator.create(Reference);
    defer testing.allocator.destroy(reference);
    reference.generate(prng, count, value_max);
    var harness: Harness = undefined;
    try harness.init(block_size, 1024, 16 * @as(u32, @intCast(prng.range(1, 3))));
    defer harness.deinit();
    _ = seed;
    const info = try harness.build(reference);
    try testing.expectEqual(@as(u64, reference.count), info.record_count);
    try testing.expectEqualSlices(u8, &reference.keys[0], &info.key_min);
    try testing.expectEqualSlices(u8, &reference.keys[reference.count - 1], &info.key_max);
    for (0..200) |_| {
        var key: Key = undefined;
        prng.fill(&key);
        const present = prng.chance(1, 2);
        const index: u32 = @intCast(prng.below(reference.count));
        if (present) key = reference.keys[index];
        const found = try harness.lookup(&info, &key);
        if (present) {
            try testing.expectEqualSlices(u8, reference.value(index), found.?);
        } else {
            const at = reference.lower_bound(&key);
            const exists = at < reference.count and std.mem.eql(u8, &reference.keys[at], &key);
            try testing.expectEqual(exists, found != null);
        }
    }
    for (0..20) |_| try check_scan(&harness, &info, reference, prng);
    try testing.expect(harness.cache.stats.hits > 0);
    try testing.expect(harness.cache.stats.misses > 0);
}

test "table: build, lookup, and scan match a sorted reference (seeded)" {
    var prng = Prng.init(0x7ab1e);
    for (0..24) |seed| try differential(seed, &prng);
}

test "table: one-record table, empty source, and a table too large for its index" {
    const reference = try testing.allocator.create(Reference);
    defer testing.allocator.destroy(reference);
    var prng = Prng.init(3);
    var harness: Harness = undefined;
    try harness.init(sector_size, 64, 16);
    defer harness.deinit();
    reference.generate(&prng, 1, 10);
    const info = try harness.build(reference);
    try testing.expectEqual(@as(u32, 1), info.data_block_count);
    const found = try harness.lookup(&info, &reference.keys[0]);
    try testing.expectEqualSlices(u8, reference.value(0), found.?);
    reference.count = 0;
    reference.value_starts[0] = 0;
    var reservation = try harness.free_set.reserve(1);
    harness.built = false;
    reference.cursor = 0;
    const source: Table.Source = .{ .context = reference, .next = Reference.next };
    harness.builder.build(source, &harness.free_set, &reservation, Harness.on_built);
    try testing.expect(harness.built); // No IO: finished inside `build`.
    try testing.expectError(error.Empty, harness.builder.result);
    harness.free_set.forfeit(&reservation);
    // 4 KiB blocks name at most 62 data blocks; 3000 records of 200 bytes need ~150.
    reference.generate(&prng, records_max, 200);
    try testing.expectError(error.TableTooLarge, harness.build_unbounded(reference));
}

test "table: a rotten data block fails the lookup, never serves wrong bytes" {
    const reference = try testing.allocator.create(Reference);
    defer testing.allocator.destroy(reference);
    var prng = Prng.init(4);
    var harness: Harness = undefined;
    try harness.init(2 * sector_size, 256, 16);
    defer harness.deinit();
    reference.generate(&prng, 500, 100);
    const info = try harness.build(reference);
    // Rot every data block's first record bytes (a cold cache forces reads).
    harness.cache.deinit(testing.allocator);
    harness.cache = try BlockCache.init(testing.allocator, 2 * sector_size, 16);
    for (1..info.data_block_count + 1) |address| {
        const block_offset = harness.grid.offset_of(address);
        const offset: usize = @intCast(block_offset + grid_module.block_header_size + 40);
        harness.sim.durable[offset] ^= 1;
        harness.sim.memory[offset] ^= 1;
    }
    for (0..50) |_| {
        const index: u32 = @intCast(prng.below(reference.count));
        try testing.expectError(error.Corrupt, harness.lookup(&info, &reference.keys[index]));
    }
}

fn fuzz_data_block(_: void, input: []const u8) anyerror!void {
    if (!Table.data_valid(input)) return;
    // Accepted payloads decode to strictly ascending keys and in-range records.
    const count = Table.data_count(input);
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const record = Table.data_record(input, index);
        try testing.expect(record.len >= 32);
        const found = Table.data_search(input, Table.record_key(record)).?;
        try testing.expectEqualSlices(u8, record[32..], found);
    }
}

fn fuzz_index_block(_: void, input: []const u8) anyerror!void {
    if (!Table.index_valid(input, 1 << 20)) return;
    const count = Table.index_count(input);
    var ordinal: u32 = 0;
    while (ordinal < count) : (ordinal += 1) {
        const key = Table.index_key(input, ordinal);
        try testing.expectEqual(ordinal, Table.index_find(input, key).?);
    }
}

test "table: fuzz the block decoders" {
    try fuzz.run_bytes({}, fuzz_data_block, .{ .iterations = 512, .input_size_max = 1024 });
    try fuzz.run_bytes({}, fuzz_index_block, .{ .iterations = 512, .input_size_max = 1024 });
}

test "table: seeded mutations of a valid data block are rejected or stay consistent" {
    const reference = try testing.allocator.create(Reference);
    defer testing.allocator.destroy(reference);
    var prng = Prng.init(8);
    var harness: Harness = undefined;
    try harness.init(sector_size, 64, 16);
    defer harness.deinit();
    reference.generate(&prng, 20, 40);
    const info = try harness.build(reference);
    _ = try harness.lookup(&info, &reference.keys[0]);
    const index_block = harness.cache.get(info.index).?;
    const index_payload = index_block[grid_module.block_header_size..];
    const data_reference = Table.index_reference(index_payload, 0);
    const data_block = harness.cache.get(data_reference).?;
    const header_bytes = data_block[0..grid_module.block_header_size];
    const header: *const grid_module.BlockHeader = @ptrCast(@alignCast(header_bytes));
    var payload: [sector_size]u8 = undefined;
    const size = header.payload_size;
    for (0..2000) |_| {
        @memcpy(payload[0..size], data_block[grid_module.block_header_size..][0..size]);
        const flips = prng.range(1, 3);
        for (0..flips) |_| payload[prng.below(size)] ^= @as(u8, 1) << @intCast(prng.below(8));
        try fuzz_data_block({}, payload[0..size]);
    }
}

test "table: a paced build pauses after each granted block and equals an unpaced build" {
    var prng = Prng.init(0x9ace);
    const block_size: u32 = 2 * sector_size;
    const reference = try testing.allocator.create(Reference);
    defer testing.allocator.destroy(reference);
    reference.generate(&prng, 400, 300);
    var unpaced: Harness = undefined;
    try unpaced.init(block_size, 256, 16);
    defer unpaced.deinit();
    const expected = try unpaced.build(reference);
    try testing.expect(expected.data_block_count > 2);

    var paced: Harness = undefined;
    try paced.init(block_size, 256, 16);
    defer paced.deinit();
    const blocks = Table.blocks_max(block_size, reference.count, reference.bytes_total());
    var reservation = try paced.free_set.reserve(blocks);
    defer paced.free_set.forfeit(&reservation);
    reference.cursor = 0;
    paced.built = false;
    const source: Table.Source = .{ .context = reference, .next = Reference.next };
    paced.builder.build_paced(source, &paced.free_set, &reservation, 1, Harness.on_built);
    var pauses: u32 = 0;
    var ticks: u32 = 0;
    while (!paced.built) : (ticks += 1) {
        if (ticks > 1_000_000) return error.Timeout;
        if (paced.builder.paused) {
            try testing.expectEqual(@as(u64, 0), paced.builder.blocks_allowed);
            // No write goes out while paused.
            const writes = paced.grid.stats.writes;
            for (0..5) |_| paced.sim.tick();
            try testing.expectEqual(writes, paced.grid.stats.writes);
            pauses += 1;
            paced.builder.grant(1);
        }
        paced.sim.tick();
    }
    const info = try paced.builder.result;
    // One pause after every block but the last (data blocks + index - 1).
    try testing.expectEqual(expected.data_block_count, pauses);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&expected), std.mem.asBytes(&info));
}

test "table: a claimed cache slot is empty until filled, and drops the address's old entry" {
    var cache = try BlockCache.init(testing.allocator, sector_size, BlockCache.ways);
    defer cache.deinit(testing.allocator);
    const old: grid_module.Reference = .{ .address = 7, .checksum = 1 };
    const new: grid_module.Reference = .{ .address = 7, .checksum = 2 };
    var block: [64]u8 = @splat(0xaa);
    _ = cache.put(old, &block);
    try testing.expect(cache.get(old) != null);
    // Claiming the address (a reused block) drops the old entry before the read lands.
    const claimed = cache.claim(new);
    try testing.expectEqual(@as(usize, sector_size), claimed.buffer.len);
    try testing.expect(cache.get(old) == null);
    try testing.expect(cache.get(new) == null);
    // A read that fails leaves the slot empty; a later claim reuses it.
    const again = cache.claim(new);
    @memset(again.buffer[0..64], 0xbb);
    const filled = cache.fill(again, new, 64);
    block = @splat(0xbb);
    try testing.expectEqualSlices(u8, &block, filled);
    try testing.expectEqualSlices(u8, &block, cache.get(new).?[0..64]);
    try testing.expect(cache.get(old) == null);
}

fn check_bytes_compare(comptime size: u32, a: *const [size]u8, b: *const [size]u8) !void {
    const expected = std.mem.order(u8, a, b);
    try testing.expectEqual(expected, table_module.bytes_order(size, a, b));
    try testing.expectEqual(expected.invert(), table_module.bytes_order(size, b, a));
    try testing.expectEqual(expected == .eq, table_module.bytes_equal(size, a, b));
    try testing.expectEqual(std.mem.eql(u8, a, b), table_module.bytes_equal(size, b, a));
}

fn check_bytes_compare_size(comptime size: u32, prng: *Prng) !void {
    var a: [size]u8 = undefined;
    var b: [size]u8 = undefined;
    var round: u32 = 0;
    while (round < 2000) : (round += 1) {
        prng.fill(&a);
        // Random, shared 32-byte owner prefix, or one byte apart (every position, both
        // directions, including the sign bit and the last byte).
        switch (prng.below(4)) {
            0 => prng.fill(&b),
            1 => {
                prng.fill(&b);
                @memcpy(b[0..@min(size, 32)], a[0..@min(size, 32)]);
            },
            2 => {
                b = a;
                const position = prng.below(size);
                b[position] = @as(u8, 1) << @intCast(prng.below(8)) ^ a[position];
            },
            else => {
                b = a;
                b[size - 1] = a[size - 1] +% @as(u8, @intCast(prng.range(1, 255)));
            },
        }
        try check_bytes_compare(size, &a, &b);
        try check_bytes_compare(size, &a, &a);
    }
    // Extremes: 0x00.. vs 0xff.. differing in the last byte only.
    @memset(&a, 0xff);
    b = a;
    b[size - 1] = 0;
    try check_bytes_compare(size, &a, &b);
    @memset(&a, 0);
    b = a;
    b[0] = 0x80;
    try check_bytes_compare(size, &a, &b);
}

test "table: bytes_order and bytes_equal match std.mem for every key size" {
    var prng = Prng.init(0x6b65_795f_6f72_6472);
    inline for (.{ 1, 7, 8, 9, 32, 33, 64, 65, 72 }) |size| {
        try check_bytes_compare_size(size, &prng);
    }
}

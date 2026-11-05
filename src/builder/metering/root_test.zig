//! Metering store tests: the base/base `store.rs` cases, then an LRU/TTL model fuzz.

const std = @import("std");
const testing = std.testing;
const metering = @import("root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = metering.B256;
const MeteringStore = metering.MeteringStore;
const s = std.time.ns_per_s;

fn hash_of(byte: u8) B256 {
    return .{ .bytes = @splat(byte) };
}

fn meter(gas: u64) metering.Metering {
    return .{ .total_gas_used = gas, .total_execution_time_us = 533, .state_block_number = 4 };
}

fn store_init(enabled: bool, capacity: u32) !MeteringStore {
    return MeteringStore.init(testing.allocator, enabled, capacity, 30 * s);
}

test "metering: insert, replace, get, and the enabled switch" {
    var store = try store_init(true, 100);
    defer store.deinit(testing.allocator);
    store.insert(hash_of(1), meter(21_000), 0);
    try testing.expectEqual(@as(u64, 21_000), store.get(hash_of(1), 1).?.total_gas_used);
    store.insert(hash_of(1), meter(50_000), 2);
    try testing.expectEqual(@as(u64, 50_000), store.get(hash_of(1), 3).?.total_gas_used);
    store.set_enabled(false);
    try testing.expect(!store.is_enabled());
    try testing.expectEqual(@as(?metering.Metering, null), store.get(hash_of(1), 3));
    store.set_enabled(true);
    try testing.expect(store.get(hash_of(1), 3) != null);
    store.clear();
    try testing.expectEqual(@as(u32, 0), store.len());
}

test "metering: late arrivals are counted, not cached; skip and cached data clear the mark" {
    var store = try store_init(true, 100);
    defer store.deinit(testing.allocator);
    // A plain miss does not mark the hash.
    try testing.expect(store.get(hash_of(2), 0) == null);
    store.insert(hash_of(2), meter(1), 1);
    try testing.expect(store.get(hash_of(2), 1) != null);
    // Included without metering, then metering arrives: late, not cached.
    store.mark_included_without_metering(hash_of(3), 10 * std.time.ns_per_ms);
    store.insert(hash_of(3), meter(1), 60 * std.time.ns_per_ms);
    try testing.expect(store.get(hash_of(3), 61 * std.time.ns_per_ms) == null);
    try testing.expectEqual(@as(u64, 1), store.metrics.late_arrivals.get());
    // Skip clears the mark: the next insert is cached.
    store.mark_included_without_metering(hash_of(4), 0);
    store.skip(hash_of(4), 1);
    store.insert(hash_of(4), meter(1), 2);
    try testing.expect(store.get(hash_of(4), 2) != null);
    // Cached data present: no mark.
    store.mark_included_without_metering(hash_of(4), 3);
    try testing.expect(!store.needed_at.contains(hash_of(4), 3));
    // Clear resets marks; disabled stores do not mark.
    store.mark_included_without_metering(hash_of(5), 0);
    store.clear();
    try testing.expect(!store.needed_at.contains(hash_of(5), 0));
    store.set_enabled(false);
    store.mark_included_without_metering(hash_of(6), 0);
    try testing.expect(!store.needed_at.contains(hash_of(6), 0));
}

test "metering: lru eviction keeps recently read entries; ttl expires" {
    var store = try store_init(true, 3);
    defer store.deinit(testing.allocator);
    store.insert(hash_of(1), meter(1), 0);
    store.insert(hash_of(2), meter(2), 0);
    store.insert(hash_of(3), meter(3), 0);
    _ = store.get(hash_of(1), 1); // 2 is now least recently used.
    store.insert(hash_of(4), meter(4), 2); // Always admitted.
    try testing.expectEqual(@as(u32, 3), store.len());
    try testing.expect(store.get(hash_of(2), 2) == null);
    try testing.expect(store.get(hash_of(1), 2) != null);
    try testing.expectEqual(@as(u64, 1), store.metrics.lru_evictions.get());
    try testing.expect(store.get(hash_of(4), 30 * s + 1) != null); // Inserted at 2.
    try testing.expect(store.get(hash_of(1), 30 * s) == null); // Reads do not extend.
    store.expire(30 * s + 2);
    try testing.expectEqual(@as(u32, 0), store.len());
    try testing.expectEqual(@as(u64, 3), store.metrics.ttl_expirations.get());
}

test "metering: execution metering mode" {
    const Mode = metering.ExecutionMeteringMode;
    try testing.expect(!Mode.off.is_enabled());
    try testing.expect(Mode.dry_run.is_enabled() and Mode.dry_run.is_dry_run());
    try testing.expect(Mode.enforce.is_enabled() and !Mode.enforce.is_dry_run());
    try testing.expectEqual(@as(?Mode, .dry_run), Mode.parse("dry-run"));
    try testing.expectEqual(@as(?Mode, null), Mode.parse("dry_run"));
}

const Lru = metering.LruTtl(u32);

/// Model: arrays of (key, value, inserted, last_used). Eviction picks the least recently
/// used live-or-dead entry; reads of expired entries do nothing.
fn run_model(seed: u64) !void {
    var prng = Prng.init(seed);
    const capacity: u32 = @intCast(prng.range(1, 10));
    const ttl_ns = prng.range(5, 60);
    var table = try Lru.init(testing.allocator, capacity, ttl_ns);
    defer table.deinit(testing.allocator);
    var keys: [16]u8 = undefined;
    var values: [16]u32 = undefined;
    var inserted: [16]u64 = undefined;
    var used: [16]u64 = undefined;
    var count: usize = 0;
    var now_ns: u64 = 0;
    var clock: u64 = 0; // Recency order, strictly increasing.
    for (0..400) |step| {
        now_ns += prng.below(4);
        clock += 1;
        const key: u8 = @intCast(prng.below(14));
        const found = std.mem.indexOfScalar(u8, keys[0..count], key);
        const live = if (found) |i| now_ns - inserted[i] < ttl_ns else false;
        switch (prng.below(4)) {
            0, 1 => {
                const value: u32 = @intCast(step);
                _ = table.insert(hash_of(key), value, now_ns);
                if (found) |i| {
                    values[i] = value;
                    inserted[i] = now_ns;
                    used[i] = clock;
                } else {
                    if (count == capacity) {
                        const victim = std.mem.indexOfMin(u64, used[0..count]);
                        keys[victim] = keys[count - 1];
                        values[victim] = values[count - 1];
                        inserted[victim] = inserted[count - 1];
                        used[victim] = used[count - 1];
                        count -= 1;
                    }
                    keys[count] = key;
                    values[count] = value;
                    inserted[count] = now_ns;
                    used[count] = clock;
                    count += 1;
                }
            },
            2 => {
                const expected: ?u32 = if (live) values[found.?] else null;
                try testing.expectEqual(expected, table.get(hash_of(key), now_ns));
                if (live) used[found.?] = clock;
            },
            else => {
                const expected: ?u32 = if (live) values[found.?] else null;
                try testing.expectEqual(expected, table.remove(hash_of(key), now_ns));
                if (found) |i| {
                    keys[i] = keys[count - 1];
                    values[i] = values[count - 1];
                    inserted[i] = inserted[count - 1];
                    used[i] = used[count - 1];
                    count -= 1;
                }
            },
        }
        try testing.expectEqual(@as(u32, @intCast(count)), table.count());
    }
}

test "metering: seeded fuzz lru ttl against a model" {
    var prng = Prng.init(0x3e7e_12);
    for (0..300) |_| try run_model(prng.int(u64));
}

test "metering: fuzz lru ttl" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try run_model(smith.value(u64));
        }
    }.run, .{});
}

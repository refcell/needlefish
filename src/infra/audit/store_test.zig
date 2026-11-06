//! Store tests: indexes, queries, ordering, capacity and arena eviction, retention.

const std = @import("std");
const testing = std.testing;

const store_module = @import("store.zig");
const event_module = @import("event.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Store = store_module.Store;
const Record = store_module.Record;
const s = std.time.ns_per_s;
const day_ns = 86_400 * s;
const now_ns = 1_000 * day_ns;

const Spec = struct {
    id: []const u8,
    time_ns: u64 = now_ns,
    ingested_ns: u64 = now_ns,
    tx: ?u8 = null,
    block: ?u64 = null,
    block_hash: ?u8 = null,
    bundle_id: ?[]const u8 = null,
    bundle_hash: ?[]const u8 = null,
    event_type: event_module.EventType = .builder_accepted,
    data: []const u8 = "{}",
};

fn record_of(spec: Spec) Record {
    return .{ .ingested_at_ns = spec.ingested_ns, .event = .{
        .event_id = spec.id,
        .event_time_ns = spec.time_ns,
        .producer = .base_builder,
        .event_type = spec.event_type,
        .network = "base-mainnet",
        .tx_hash = if (spec.tx) |byte| @splat(byte) else null,
        .block_hash = if (spec.block_hash) |byte| @splat(byte) else null,
        .block_number = spec.block,
        .data = spec.data,
        .bundle_id = spec.bundle_id,
        .bundle_hash = spec.bundle_hash,
    } };
}

fn init_store(events_max: u32, arena_bytes: u32) !Store {
    return Store.init(testing.allocator, .{
        .events_max = events_max,
        .arena_bytes = arena_bytes,
        .retention_ns = .initFill(30 * day_ns),
    });
}

fn add(store: *Store, spec: Spec) u32 {
    const record = record_of(spec);
    return store.insert(&record);
}

fn expect_ids(store: *const Store, slots: []const u32, ids: []const []const u8) !void {
    try testing.expectEqual(ids.len, slots.len);
    for (slots, ids) |slot, id| {
        try testing.expectEqualStrings(id, store.get(slot).event.event_id);
    }
}

test "store: round trip and event id lookup" {
    var store = try init_store(8, 1024);
    defer store.deinit(testing.allocator);
    const slot = add(&store, .{
        .id = "a",
        .tx = 1,
        .block = 5,
        .bundle_id = "b",
        .data = "{\"x\":1}",
    });
    try testing.expectEqual(slot, store.find_event_id("a").?);
    try testing.expect(store.find_event_id("b") == null);
    const record = store.get(slot);
    try testing.expectEqualStrings("base-mainnet", record.event.network.?);
    try testing.expectEqualStrings("{\"x\":1}", record.event.data);
    try testing.expectEqual(@as(u64, 5), record.event.block_number.?);
    try testing.expect(record.event.block_hash == null and record.event.payload_id == null);
    try testing.expectEqualStrings("b", record.event.bundle_id.?);
}

test "store: queries by tx hash, block, block hash, and bundle, oldest first" {
    var store = try init_store(16, 4096);
    defer store.deinit(testing.allocator);
    _ = add(&store, .{ .id = "c", .time_ns = now_ns - 1, .tx = 1, .block = 9 });
    _ = add(&store, .{ .id = "b", .time_ns = now_ns - 2, .tx = 1, .block_hash = 7 });
    _ = add(&store, .{ .id = "a", .time_ns = now_ns - 1, .tx = 1, .bundle_id = "u-1" });
    _ = add(&store, .{ .id = "d", .time_ns = now_ns - 1, .ingested_ns = now_ns - 5, .tx = 1 });
    _ = add(&store, .{ .id = "e", .tx = 2, .block = 9, .bundle_hash = "u-1" });
    _ = add(&store, .{ .id = "f", .bundle_id = "u-1", .bundle_hash = "u-1" });
    const by_tx = store.query(.{ .tx_hash = @splat(1) }, 500, now_ns);
    try expect_ids(&store, by_tx, &.{ "b", "d", "a", "c" });
    try expect_ids(&store, store.query(.{ .tx_hash = @splat(1) }, 2, now_ns), &.{ "b", "d" });
    try expect_ids(&store, store.query(.{ .tx_hash = @splat(1) }, 0, now_ns), &.{"b"});
    try expect_ids(&store, store.query(.{ .block_number = 9 }, 500, now_ns), &.{ "c", "e" });
    try expect_ids(&store, store.query(.{ .block_hash = @splat(7) }, 500, now_ns), &.{"b"});
    // A bundle key matches bundle_id or bundle_hash, each event once.
    try expect_ids(&store, store.query(.{ .bundle = "u-1" }, 500, now_ns), &.{ "a", "e", "f" });
    try expect_ids(&store, store.query(.{ .bundle = "u-2" }, 500, now_ns), &.{});
    try expect_ids(&store, store.query(.{ .tx_hash = @splat(3) }, 500, now_ns), &.{});
}

test "store: rejected events, newest first, with block and time filters" {
    var store = try init_store(16, 4096);
    defer store.deinit(testing.allocator);
    const rejected = .builder_rejected;
    _ = add(&store, .{ .id = "r1", .time_ns = now_ns - 30, .block = 10, .event_type = rejected });
    const failed = .simulation_failed;
    _ = add(&store, .{ .id = "r2", .time_ns = now_ns - 20, .block = 20, .event_type = failed });
    _ = add(&store, .{ .id = "r3", .time_ns = now_ns - 10, .event_type = .builder_expired });
    _ = add(&store, .{ .id = "ok", .time_ns = now_ns - 5, .block = 15 });
    try expect_ids(&store, store.query_rejected(.{}, now_ns), &.{ "r3", "r2", "r1" });
    try expect_ids(&store, store.query_rejected(.{ .from_block = 15 }, now_ns), &.{"r2"});
    try expect_ids(&store, store.query_rejected(.{ .to_block = 15 }, now_ns), &.{"r1"});
    const window: store_module.RejectedQuery = .{
        .from_time_ns = now_ns - 20,
        .to_time_ns = now_ns - 10,
    };
    try expect_ids(&store, store.query_rejected(window, now_ns), &.{"r2"});
    try expect_ids(&store, store.query_rejected(.{ .limit = 1 }, now_ns), &.{"r3"});
}

test "store: capacity eviction drops the oldest and its index entries" {
    var store = try init_store(3, 4096);
    defer store.deinit(testing.allocator);
    _ = add(&store, .{ .id = "a", .tx = 1 });
    _ = add(&store, .{ .id = "b", .tx = 1 });
    _ = add(&store, .{ .id = "c", .tx = 1 });
    _ = add(&store, .{ .id = "d", .tx = 1 });
    try testing.expectEqual(@as(u32, 3), store.count);
    try testing.expect(store.find_event_id("a") == null);
    try testing.expectEqual(@as(u64, 1), store.stats.evicted_capacity);
    const by_tx = store.query(.{ .tx_hash = @splat(1) }, 500, now_ns);
    try expect_ids(&store, by_tx, &.{ "b", "c", "d" });
}

test "store: arena eviction wraps the byte ring" {
    // Each record: id (1) + network (12) + data (20) = 33 bytes; 100 bytes hold 3.
    var store = try init_store(16, 100);
    defer store.deinit(testing.allocator);
    const data = "{\"pad\":\"xxxxxxxxxx\"}";
    for ([_][]const u8{ "a", "b", "c", "d", "e" }) |id| {
        _ = add(&store, .{ .id = id, .data = data });
    }
    try testing.expectEqual(@as(u32, 3), store.count);
    try testing.expect(store.find_event_id("b") == null);
    try testing.expectEqualStrings(data, store.get(store.find_event_id("e").?).event.data);
    try testing.expectEqual(@as(u64, 99), store.arena_used);
}

test "store: retention hides and prunes expired events" {
    var store = try init_store(8, 4096);
    defer store.deinit(testing.allocator);
    _ = add(&store, .{ .id = "old", .time_ns = now_ns - 31 * day_ns, .tx = 1 });
    _ = add(&store, .{ .id = "new", .time_ns = now_ns, .tx = 1 });
    _ = add(&store, .{ .id = "older", .time_ns = now_ns - 40 * day_ns, .tx = 1 });
    try expect_ids(&store, store.query(.{ .tx_hash = @splat(1) }, 500, now_ns), &.{"new"});
    // Only the head is pruned: "older" waits behind "new" but is never served.
    try testing.expectEqual(@as(u32, 1), store.prune(now_ns));
    try testing.expectEqual(@as(u32, 2), store.count);
    try testing.expectEqual(@as(u64, 1), store.stats.evicted_retention);
    try testing.expectEqual(@as(u32, 2), store.prune(now_ns + 31 * day_ns));
    try testing.expectEqual(@as(u32, 0), store.count);
}

test "store: pop_tail rolls back the newest insert" {
    var store = try init_store(4, 4096);
    defer store.deinit(testing.allocator);
    _ = add(&store, .{ .id = "a", .tx = 1 });
    _ = add(&store, .{ .id = "b", .tx = 1 });
    store.pop_tail();
    try testing.expect(store.find_event_id("b") == null);
    _ = add(&store, .{ .id = "c", .tx = 1 });
    try expect_ids(&store, store.query(.{ .tx_hash = @splat(1) }, 500, now_ns), &.{ "a", "c" });
    try testing.expectEqual(@as(u64, 1), store.sequence_of(store.find_event_id("c").?));
}

test "store: seeded fuzz keeps indexes consistent with the live window" {
    var prng = Prng.init(0x570e);
    var store = try init_store(32, 2048);
    defer store.deinit(testing.allocator);
    var ids: [512][8]u8 = undefined;
    var inserted: u32 = 0;
    for (0..2000) |round| {
        const id = std.fmt.bufPrint(&ids[inserted % ids.len], "e{d}", .{round}) catch unreachable;
        var data_buffer: [96]u8 = undefined;
        const pad = prng.below(64);
        const filler: [64]u8 = @splat('p');
        const data = std.fmt.bufPrint(&data_buffer, "{{\"p\":\"{s}\"}}", .{filler[0..pad]}) catch
            unreachable;
        if (store.find_event_id(id) == null) {
            _ = add(&store, .{
                .id = id,
                .tx = @truncate(prng.below(4)),
                .block = prng.below(4),
                .time_ns = now_ns - prng.below(40) * day_ns,
                .data = data,
            });
            inserted += 1;
        }
        if (prng.chance(1, 50)) _ = store.prune(now_ns);
        if (prng.chance(1, 40) and store.count > 0) store.pop_tail();
        try check_consistent(&store);
    }
}

fn check_consistent(store: *Store) !void {
    var total: u32 = 0;
    for (0..4) |tx| {
        total += @intCast(store.query(.{ .tx_hash = @splat(@intCast(tx)) }, 2000, 0).len);
    }
    try testing.expectEqual(store.count, total);
    var arena_used: u64 = 0;
    for (0..store.count) |position| {
        const slot = store.slot_at(@intCast(position));
        const record = store.get(slot);
        try testing.expectEqual(slot, store.find_event_id(record.event.event_id).?);
        arena_used += Store.record_size(&record);
    }
    try testing.expectEqual(store.arena_used, arena_used);
    try testing.expect(store.arena_used <= store.arena.len);
}

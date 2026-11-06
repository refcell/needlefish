//! Segment encoding, replay (torn tails, corruption, duplicates), and fuzzing.

const std = @import("std");
const testing = std.testing;

const segment = @import("segment.zig");
const store_module = @import("store.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Record = store_module.Record;
const payload_max = segment.payload_size_max(4096);

fn sample(id: []const u8, block: ?u64) Record {
    return .{ .ingested_at_ns = 77, .event = .{
        .event_id = id,
        .event_time_ns = 1_700_000_000 * std.time.ns_per_s,
        .producer = .base_reth_node,
        .event_type = .txpool_dropped,
        .network = "base-sepolia",
        .tx_hash = @splat(0xab),
        .block_number = block,
        .request_id = "req",
        .data = "{\"reason\":\"x\"}",
        .bundle_hash = "0xbundle",
    } };
}

fn init_store() !store_module.Store {
    return store_module.Store.init(testing.allocator, .{
        .events_max = 16,
        .arena_bytes = 4096,
        .retention_ns = .initFill(std.math.maxInt(u64)),
    });
}

test "segment: encode and decode round trip" {
    var buffer: [1024]u8 = undefined;
    const record = sample("id-1", 42);
    const bytes = segment.encode(&record, &buffer);
    const decoded = segment.decode(bytes, payload_max).record;
    try testing.expectEqual(@as(u32, @intCast(bytes.len)), decoded.size);
    const value = decoded.record.event;
    try testing.expectEqualStrings("id-1", value.event_id);
    try testing.expectEqual(@as(u64, 77), decoded.record.ingested_at_ns);
    try testing.expectEqual(@as(u64, 42), value.block_number.?);
    try testing.expectEqualStrings("base-sepolia", value.network.?);
    try testing.expectEqualStrings("req", value.request_id.?);
    try testing.expect(value.payload_id == null and value.block_hash == null);
    try testing.expect(value.bundle_id == null);
    try testing.expectEqualStrings("0xbundle", value.bundle_hash.?);
    try testing.expectEqual(record.event.event_type, value.event_type);
    try testing.expectEqual(record.event.producer, value.producer);
}

test "segment: truncated and corrupted records" {
    var buffer: [1024]u8 = undefined;
    const record = sample("id-1", null);
    const bytes = segment.encode(&record, &buffer);
    try testing.expect(segment.decode(bytes[0..0], payload_max) == .incomplete);
    try testing.expect(segment.decode(bytes[0..3], payload_max) == .incomplete);
    try testing.expect(segment.decode(bytes[0 .. bytes.len - 1], payload_max) == .incomplete);
    try testing.expect(segment.decode("XEV1", payload_max) == .corrupt);
    var copy: [1024]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    copy[bytes.len - 2] ^= 1;
    try testing.expect(segment.decode(copy[0..bytes.len], payload_max) == .corrupt);
    try testing.expect(segment.decode(bytes, 100) == .corrupt);
}

test "segment: replay restores the store, skips duplicates, stops at a torn tail" {
    var file: [4096]u8 = undefined;
    var length: usize = 0;
    for ([_][]const u8{ "a", "b", "a", "c" }, 0..) |id, block| {
        const record = sample(id, block);
        length += segment.encode(&record, file[length..]).len;
    }
    const full = length;
    const torn = sample("d", null);
    length += segment.encode(&torn, file[length..]).len - 5;
    var store = try init_store();
    defer store.deinit(testing.allocator);
    const result = segment.replay(&store, file[0..length], payload_max, 0);
    try testing.expectEqual(segment.ReplayStop.incomplete, result.stop);
    try testing.expectEqual(@as(u64, full), result.consumed);
    try testing.expectEqual(@as(u32, 3), result.inserted);
    try testing.expectEqual(@as(u32, 1), result.duplicates);
    try testing.expectEqual(@as(u32, 3), store.count);
    const slot = store.find_event_id("c").?;
    try testing.expectEqual(@as(u64, 3), store.get(slot).event.block_number.?);
    const by_tx = store.query(.{ .tx_hash = @splat(0xab) }, 10, 0);
    try testing.expectEqual(@as(usize, 3), by_tx.len);
}

test "segment: replay stops at a corrupt record" {
    var file: [4096]u8 = undefined;
    var length: usize = 0;
    const first = sample("a", null);
    length += segment.encode(&first, file[length..]).len;
    const boundary = length;
    const second = sample("b", null);
    length += segment.encode(&second, file[length..]).len;
    file[boundary + 20] ^= 0xff;
    var store = try init_store();
    defer store.deinit(testing.allocator);
    const result = segment.replay(&store, file[0..length], payload_max, 0);
    try testing.expectEqual(segment.ReplayStop.corrupt, result.stop);
    try testing.expectEqual(@as(u64, boundary), result.consumed);
    try testing.expectEqual(@as(u32, 1), store.count);
}

test "segment: encode_live compacts the live store in chunks" {
    var store = try init_store();
    defer store.deinit(testing.allocator);
    for ([_][]const u8{ "a", "b", "c" }) |id| {
        const record = sample(id, null);
        _ = store.insert(&record);
    }
    var chunk: [400]u8 = undefined;
    var file: [2048]u8 = undefined;
    var length: usize = 0;
    var position: u32 = 0;
    var chunks: u32 = 0;
    while (position < store.count) : (chunks += 1) {
        const bytes = segment.encode_live(&store, &position, &chunk, 0);
        try testing.expect(bytes.len > 0);
        @memcpy(file[length..][0..bytes.len], bytes);
        length += bytes.len;
    }
    try testing.expect(chunks > 1);
    var restored = try init_store();
    defer restored.deinit(testing.allocator);
    const result = segment.replay(&restored, file[0..length], payload_max, 0);
    try testing.expectEqual(@as(u32, 3), result.inserted);
    try testing.expectEqualStrings("c", restored.get(restored.slot_at(2)).event.event_id);
}

fn check_arbitrary(bytes: []const u8) !void {
    var store = try init_store();
    defer store.deinit(testing.allocator);
    const result = segment.replay(&store, bytes, payload_max, 0);
    try testing.expect(result.consumed <= bytes.len);
    try testing.expectEqual(store.count, result.inserted);
    // Every decoded record re-encodes byte-identically.
    var offset: usize = 0;
    var buffer: [8192]u8 = undefined;
    var records: u32 = 0;
    while (offset < result.consumed) : (records += 1) {
        const decoded = segment.decode(bytes[offset..], payload_max).record;
        const again = segment.encode(&decoded.record, &buffer);
        try testing.expectEqualSlices(u8, bytes[offset..][0..decoded.size], again);
        offset += decoded.size;
    }
    try testing.expectEqual(result.consumed, offset);
    try testing.expect(records >= result.inserted);
}

test "segment: seeded fuzz of mutated segments" {
    var prng = Prng.init(0x5e6);
    var file: [2048]u8 = undefined;
    for (0..2000) |_| {
        var length: usize = 0;
        const count = prng.below(4);
        for (0..count) |index| {
            const ids = [_][]const u8{ "a", "b", "c" };
            const record = sample(ids[prng.below(ids.len)], if (prng.chance(1, 2)) index else null);
            length += segment.encode(&record, file[length..]).len;
        }
        const flips = prng.below(3);
        for (0..flips) |_| {
            if (length == 0) break;
            file[prng.below(length)] = @truncate(prng.int(u8));
        }
        if (length > 0 and prng.chance(1, 3)) length = prng.below(length);
        try check_arbitrary(file[0..length]);
    }
}

fn fuzz_replay(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [2048]u8 = undefined;
    const size = smith.slice(&input);
    try check_arbitrary(input[0..size]);
}

test "segment: fuzz replay" {
    var buffer: [1024]u8 = undefined;
    const record = sample("seed", 1);
    const seed = segment.encode(&record, &buffer);
    try testing.fuzz({}, fuzz_replay, .{ .corpus = &.{seed} });
}

//! Replay ring tests: fixed cases and a model-checked seeded fuzz.

const std = @import("std");
const testing = std.testing;
const ring_module = @import("ring.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Ring = ring_module.Ring;
const Position = ring_module.Position;

fn at(block_number: u64, flashblock_index: u64) Position {
    return .{ .block_number = block_number, .flashblock_index = flashblock_index };
}

test "publish ring: eviction by count and bytes, lookups" {
    var ring = try Ring.init(testing.allocator, 3, 10);
    defer ring.deinit(testing.allocator);
    try testing.expectEqual(@as(?Position, null), ring.oldest_position());
    try testing.expectEqual(@as(u32, 0), ring.push(at(1, 0), "aaaa"));
    try testing.expectEqual(@as(u32, 0), ring.push(at(1, 1), "bbbb"));
    // Two bytes fit at the tail: no eviction.
    try testing.expectEqual(@as(u32, 0), ring.push(at(1, 2), "cc"));
    try testing.expectEqual(@as(u32, 3), ring.len());
    try testing.expectEqual(@as(u32, 1), ring.first_after(at(1, 0)));
    try testing.expectEqual(@as(u32, 0), ring.first_after(at(0, 99)));
    try testing.expectEqual(@as(u32, 3), ring.first_after(at(1, 2)));
    // Four bytes wrap to offset 0 once "aaaa" (count bound) is evicted.
    try testing.expectEqual(@as(u32, 1), ring.push(at(1, 3), "dddd"));
    try testing.expectEqualStrings("bbbb", ring.get(0).payload);
    try testing.expectEqualStrings("dddd", ring.get(2).payload);
    // Wrapped: only [4, 4) is free, so "e" evicts "bbbb".
    try testing.expectEqual(@as(u32, 1), ring.push(at(1, 4), "e"));
    try testing.expectEqualStrings("cc", ring.get(0).payload);
    // An older position restarts history.
    try testing.expectEqual(@as(u32, 3), ring.push(at(1, 0), "z"));
    try testing.expectEqual(@as(u32, 1), ring.len());
    // A full-arena payload evicts everything else.
    try testing.expectEqual(@as(u32, 1), ring.push(at(2, 0), "0123456789"));
    try testing.expectEqualStrings("0123456789", ring.get(0).payload);
    try testing.expectEqual(at(2, 0), ring.newest_position().?);
    // Count bound.
    _ = ring.push(at(2, 1), "");
    _ = ring.push(at(2, 2), "");
    _ = ring.push(at(2, 3), "");
    try testing.expectEqual(@as(u32, 3), ring.len());
    try testing.expectEqual(at(2, 1), ring.oldest_position().?);
}

const payload_length_max = 24;

const ModelEntry = struct { position: Position, payload: [payload_length_max]u8, length: u8 };

/// Pushes random entries and checks the ring holds exactly a suffix of history since the
/// last restart, within its bounds, and evicts only for space (fragmentation can cost at
/// most a few payloads' worth of bytes).
fn run_model(seed: u64, steps: u32) !void {
    var prng = Prng.init(seed);
    const entries_max: u32 = @intCast(prng.range(1, 12));
    const bytes_max: u32 = @intCast(prng.range(payload_length_max, 8 * payload_length_max));
    var ring = try Ring.init(testing.allocator, entries_max, bytes_max);
    defer ring.deinit(testing.allocator);
    var history: [512]ModelEntry = undefined;
    var history_start: usize = 0;
    var history_count: usize = 0;
    var position = at(prng.below(4), 0);
    for (0..steps) |_| {
        if (history_count == history.len) break;
        if (prng.chance(1, 20)) {
            const restarted = at(position.block_number -| 1, 0); // A new payload job.
            if (restarted.less_than(position)) history_start = history_count;
            position = restarted;
        } else if (prng.chance(1, 4)) {
            position = at(position.block_number + 1, 0);
        } else {
            position.flashblock_index += prng.below(2);
        }
        var entry: ModelEntry = .{ .position = position, .payload = undefined, .length = 0 };
        entry.length = @intCast(prng.below(payload_length_max + 1));
        prng.fill(entry.payload[0..entry.length]);
        _ = ring.push(position, entry.payload[0..entry.length]);
        history[history_count] = entry;
        history_count += 1;
        try check_suffix(&ring, history[history_start..history_count], entries_max, bytes_max);
    }
}

fn check_suffix(
    ring: *const Ring,
    live: []const ModelEntry,
    entries_max: u32,
    bytes_max: u32,
) !void {
    const count = ring.len();
    try testing.expect(count >= 1 and count <= entries_max and count <= live.len);
    const suffix = live[live.len - count ..];
    var bytes: u64 = 0;
    for (suffix, 0..) |expected, index| {
        const entry = ring.get(@intCast(index));
        try testing.expectEqual(expected.position, entry.position);
        try testing.expectEqualSlices(u8, expected.payload[0..expected.length], entry.payload);
        bytes += expected.length;
    }
    try testing.expect(bytes <= bytes_max);
    if (count < entries_max and count < live.len) {
        // Evicted for space: the next older entry did not fit, up to fragmentation slack.
        const older = live[live.len - count - 1].length;
        try testing.expect(bytes + older + 2 * payload_length_max > bytes_max);
    }
    for (0..count) |index| {
        const cutoff = suffix[index].position;
        const first = ring.first_after(cutoff);
        try testing.expect(first > index);
        if (first < count) try testing.expect(cutoff.less_than(suffix[first].position));
    }
}

test "publish ring: seeded fuzz against a model" {
    var prng = Prng.init(0x7e9a_1a);
    for (0..200) |_| try run_model(prng.int(u64), 400);
}

test "publish ring: fuzz" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try run_model(smith.value(u64), 200);
        }
    }.run, .{});
}

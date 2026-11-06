//! Journal tests: round trips, wrapping, fullness, corruption detection, crashes, and fuzzed
//! header decoding.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const storage = @import("storage.zig");
const journal_module = @import("journal.zig");
const SimStorage = @import("sim_storage.zig").SimStorage;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

const sector_size = storage.sector_size;
const Journal = journal_module.JournalType(SimStorage);
const metadata_size = journal_module.metadata_size;

const body_size_max = 3 * sector_size;
const entries_max = 64;
const format_id: u128 = 0x1234_5678;

const Harness = struct {
    journal: Journal,
    done: bool = false,
    recovered: [entries_max][body_size_max]u8 = undefined,
    recovered_size: [entries_max]u32 = undefined,
    recovered_sequence: [entries_max]u64 = undefined,
    recovered_count: u32 = 0,

    fn on_done(journal: *Journal) void {
        const self: *Harness = @alignCast(@fieldParentPtr("journal", journal));
        assert(!self.done);
        self.done = true;
    }

    fn on_entry(context: *anyopaque, entry: journal_module.Entry) void {
        const self: *Harness = @ptrCast(@alignCast(context));
        assert(self.recovered_count < entries_max);
        assert(entry.metadata[0] == @as(u8, @truncate(entry.sequence)));
        @memcpy(self.recovered[self.recovered_count][0..entry.body.len], entry.body);
        self.recovered_size[self.recovered_count] = @intCast(entry.body.len);
        self.recovered_sequence[self.recovered_count] = entry.sequence;
        self.recovered_count += 1;
    }

    fn wait(self: *Harness, sim: *SimStorage) !void {
        var ticks: u32 = 0;
        while (!self.done) : (ticks += 1) {
            if (ticks > 100_000) return error.Timeout;
            sim.tick();
        }
        self.done = false;
    }

    fn append(self: *Harness, sim: *SimStorage, body: []const u8) !u64 {
        var metadata: [metadata_size]u8 = @splat(0);
        metadata[0] = @truncate(self.journal.sequence_next);
        const sequence = try self.journal.append(body, &metadata, on_done);
        try self.wait(sim);
        return sequence;
    }

    fn recover(self: *Harness, sim: *SimStorage, start: storage_start) !void {
        self.journal.reset(format_id, start);
        self.recovered_count = 0;
        self.journal.recover(.{ .context = self, .on_entry = on_entry }, on_done);
        try self.wait(sim);
    }
};

const storage_start = @import("superblock.zig").JournalStart;

fn setup(sim: *SimStorage, zone_size: u64) !*Harness {
    const harness = try testing.allocator.create(Harness);
    harness.* = .{ .journal = try .init(testing.allocator, sim, .{
        .zone_offset = sector_size,
        .zone_size_bytes = zone_size,
        .body_size_max = body_size_max,
    }) };
    harness.journal.reset(format_id, .{ .previous_checksum = 7, .offset = 0, .sequence = 1 });
    return harness;
}

fn teardown(harness: *Harness) void {
    harness.journal.deinit(testing.allocator);
    testing.allocator.destroy(harness);
}

const Bodies = struct {
    bytes: [entries_max][body_size_max]u8 = undefined,
    size: [entries_max]u32 = undefined,

    fn make(bodies: *Bodies, prng: *Prng, index: u32) []const u8 {
        const size: u32 = @intCast(switch (prng.below(4)) {
            0 => 0,
            1 => prng.below(64),
            else => prng.below(body_size_max + 1),
        });
        prng.fill(bodies.bytes[index][0..size]);
        bodies.size[index] = size;
        return bodies.bytes[index][0..size];
    }

    fn get(bodies: *const Bodies, index: u32) []const u8 {
        return bodies.bytes[index][0..bodies.size[index]];
    }
};

fn expect_recovered(harness: *const Harness, bodies: *const Bodies, first: u32) !void {
    for (0..harness.recovered_count) |index| {
        const recovered = harness.recovered[index][0..harness.recovered_size[index]];
        try testing.expectEqualSlices(u8, bodies.get(first + @as(u32, @intCast(index))), recovered);
        try testing.expectEqual(@as(u64, first + index + 1), harness.recovered_sequence[index]);
    }
}

test "journal: append then recover round trip" {
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 1 << 20, .seed = 1 });
    defer sim.deinit(testing.allocator);
    const harness = try setup(&sim, 512 * 1024);
    defer teardown(harness);
    var prng = Prng.init(1);
    var bodies: Bodies = .{};
    for (0..20) |index| {
        const sequence = try harness.append(&sim, bodies.make(&prng, @intCast(index)));
        try testing.expectEqual(@as(u64, index + 1), sequence);
    }
    const head = harness.journal.head;
    try harness.recover(&sim, .{ .previous_checksum = 7, .offset = 0, .sequence = 1 });
    try testing.expectEqual(@as(u32, 20), harness.recovered_count);
    try testing.expectEqual(journal_module.StopReason.clean, harness.journal.recover_result.stop);
    try testing.expectEqual(head, harness.journal.head);
    try testing.expectEqual(@as(u64, 21), harness.journal.sequence_next);
    try expect_recovered(harness, &bodies, 0);

    // A wrong chain anchor accepts nothing.
    try harness.recover(&sim, .{ .previous_checksum = 8, .offset = 0, .sequence = 1 });
    try testing.expectEqual(@as(u32, 0), harness.recovered_count);
}

test "journal: full ring, release, wrap, recover across the wrap" {
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 1 << 20, .seed = 2 });
    defer sim.deinit(testing.allocator);
    const zone_size = 8 * 4 * sector_size;
    const harness = try setup(&sim, zone_size);
    defer teardown(harness);
    var prng = Prng.init(2);
    var bodies: Bodies = .{};
    var count: u32 = 0;
    var start = harness.journal.start_point();
    var start_index: u32 = 0;
    var wraps: u32 = 0;
    var round: u32 = 0;
    while (round < 6) : (round += 1) {
        // Fill until full, then "checkpoint": everything so far is released.
        while (count < entries_max) {
            const body = bodies.make(&prng, count);
            _ = harness.append(&sim, body) catch |err| switch (err) {
                error.JournalFull => break,
                else => return err,
            };
            count += 1;
        }
        try testing.expect(harness.journal.head - harness.journal.tail <= zone_size);
        const head = harness.journal.head;
        try harness.recover(&sim, start);
        try testing.expectEqual(count - start_index, harness.recovered_count);
        try testing.expectEqual(head, harness.journal.head);
        try expect_recovered(harness, &bodies, start_index);
        // Nothing crashed, so the scan must end clean, wherever the end falls after a wrap.
        const stop = harness.journal.recover_result.stop;
        try testing.expectEqual(journal_module.StopReason.clean, stop);
        wraps = @intCast(head / zone_size);
        start = harness.journal.start_point();
        start_index = count;
        harness.journal.reset(format_id, start);
        if (count >= entries_max - 8) break;
    }
    try testing.expect(wraps >= 1);
}

// The newest entry ends inside an older lap's body: those bytes look like a damaged header
// unless the writer zeroed the sector after the entry, so a clean restart reported corruption.
test "journal: a clean end inside an older lap's body is reported clean" {
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 1 << 20, .seed = 3 });
    defer sim.deinit(testing.allocator);
    const zone_size = 8 * 4 * sector_size;
    const harness = try setup(&sim, zone_size);
    defer teardown(harness);
    var body: [body_size_max]u8 = undefined;
    @memset(&body, 0x5a);
    // Eight 4-sector entries fill the ring exactly; release them all.
    for (0..8) |_| _ = try harness.append(&sim, &body);
    const metadata: [metadata_size]u8 = @splat(0);
    const full = harness.journal.append(&body, &metadata, Harness.on_done);
    try testing.expectError(error.JournalFull, full);
    harness.journal.reset(format_id, harness.journal.start_point());
    const start = harness.journal.start_point();
    // A 2-sector entry at the zone start ends on sector 2: the middle of the old first body.
    _ = try harness.append(&sim, body[0..100]);
    try testing.expectEqual(@as(u64, 2 * sector_size), harness.journal.head % zone_size);
    try harness.recover(&sim, start);
    try testing.expectEqual(@as(u32, 1), harness.recovered_count);
    const stop = harness.journal.recover_result.stop;
    try testing.expectEqual(journal_module.StopReason.clean, stop);
    // A stray non-zero sector at the end is still corruption (the scan did not go lax).
    // The zone starts one sector into the disk.
    sim.corrupt_sector(1 + @as(u32, @intCast(harness.journal.head % zone_size / sector_size)));
    try harness.recover(&sim, start);
    try testing.expectEqual(@as(u32, 1), harness.recovered_count);
    try testing.expect(harness.journal.recover_result.stop != .clean);
}

test "journal: corrupt body and header are detected, never delivered" {
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 1 << 20, .seed = 3 });
    defer sim.deinit(testing.allocator);
    const harness = try setup(&sim, 512 * 1024);
    defer teardown(harness);
    var prng = Prng.init(3);
    var bodies: Bodies = .{};
    var positions: [6]u64 = undefined;
    for (0..6) |index| {
        positions[index] = harness.journal.head;
        // Full sectors, so bit rot anywhere in a body sector hits checksummed bytes.
        bodies.size[index] = body_size_max;
        prng.fill(&bodies.bytes[index]);
        _ = try harness.append(&sim, bodies.get(@intCast(index)));
    }
    const start: storage_start = .{ .previous_checksum = 7, .offset = 0, .sequence = 1 };
    const zone_sector: u32 = 1;
    sim.corrupt_sector(zone_sector + @as(u32, @intCast(positions[3] / sector_size)) + 1);
    try harness.recover(&sim, start);
    try testing.expectEqual(@as(u32, 3), harness.recovered_count);
    try testing.expectEqual(
        journal_module.StopReason.body_corrupt,
        harness.journal.recover_result.stop,
    );
    try expect_recovered(harness, &bodies, 0);

    sim.corrupt_sector(zone_sector + @as(u32, @intCast(positions[1] / sector_size)));
    try harness.recover(&sim, start);
    try testing.expectEqual(@as(u32, 1), harness.recovered_count);
    try testing.expectEqual(
        journal_module.StopReason.header_corrupt,
        harness.journal.recover_result.stop,
    );
}

test "journal: crash at a random tick keeps every committed entry and a valid prefix" {
    var prng = Prng.init(4);
    for (0..48) |seed| {
        var sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = 256 * 1024,
            .seed = seed,
            .read_fault_numerator = 1,
            .read_fault_denominator = 50,
        });
        defer sim.deinit(testing.allocator);
        const harness = try setup(&sim, 32 * sector_size);
        defer teardown(harness);
        var bodies: Bodies = .{};
        var committed: u32 = 0;
        var submitted: u32 = 0;
        const crash_tick = prng.range(1, 200);
        var tick: u64 = 0;
        while (tick < crash_tick) : (tick += 1) {
            if (harness.journal.idle()) {
                if (harness.done) committed = submitted;
                harness.done = false;
                var metadata: [metadata_size]u8 = @splat(0);
                metadata[0] = @truncate(harness.journal.sequence_next);
                const body = bodies.make(&prng, submitted);
                if (harness.journal.append(body, &metadata, Harness.on_done)) |_| {
                    submitted += 1;
                } else |_| break;
            }
            sim.tick();
        }
        if (harness.done) committed = submitted;
        sim.crash();
        harness.journal.state = .idle;
        harness.journal.callback = null;
        harness.done = false;
        try harness.recover(&sim, .{ .previous_checksum = 7, .offset = 0, .sequence = 1 });
        try testing.expect(harness.recovered_count >= committed);
        try testing.expect(harness.recovered_count <= submitted);
        try expect_recovered(harness, &bodies, 0);
    }
}

fn fuzz_header(_: void, input: []const u8) anyerror!void {
    var sector: [sector_size]u8 = @splat(0);
    const length = @min(input.len, sector_size);
    @memcpy(sector[0..length], input[0..length]);
    var header: journal_module.Header = undefined;
    const expect: journal_module.Expect = .{
        .format_id = 0,
        .sequence = 1,
        .previous_checksum = 0,
        .body_size_max = body_size_max,
    };
    try testing.expect(journal_module.classify_header(&sector, expect, &header) != .valid);
}

test "journal: fuzz arbitrary header bytes are never valid" {
    try fuzz.run_bytes({}, fuzz_header, .{ .iterations = 128, .input_size_max = sector_size });
}

test "journal: seeded mutations of a valid header are rejected" {
    var prng = Prng.init(5);
    var header = std.mem.zeroes(journal_module.Header);
    header.magic = journal_module.magic;
    header.sequence = 9;
    header.previous_checksum = 3;
    header.format_id = format_id;
    header.body_size = 10;
    header.checksum = header.compute_checksum();
    const expect: journal_module.Expect = .{
        .format_id = format_id,
        .sequence = 9,
        .previous_checksum = 3,
        .body_size_max = body_size_max,
    };
    var scratch: journal_module.Header = undefined;
    const original = std.mem.toBytes(header);
    try testing.expectEqual(journal_module.Verdict.valid, journal_module.classify_header(
        &original,
        expect,
        &scratch,
    ));
    for (0..512) |_| {
        var bytes = original;
        const bit = prng.below(sector_size * 8);
        bytes[@intCast(bit / 8)] ^= @as(u8, 1) << @intCast(bit % 8);
        const verdict = journal_module.classify_header(&bytes, expect, &scratch);
        try testing.expectEqual(journal_module.Verdict.corrupt, verdict);
    }
}

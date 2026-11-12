//! Archive tests against a model: every block's changes are generated up front and the
//! model keeps the full key state after each block, so any answer the archive gives
//! (`value_after`, `find`, `block_at`) is checked against state derived independently.
//! Covers seals, evictions (byte ring and lap skips), reopen after a flush, a crash with
//! unsynced blocks, rebase truncation into a sealed segment, and corrupt sectors.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const archive_module = @import("root.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const Prng = @import("../../testing/prng.zig").Prng;

const Archive = archive_module.ArchiveType(SimStorage);
const Kind = archive_module.Kind;
const Hash = archive_module.Hash;

const config: archive_module.Config = .{
    .segment_blocks = 8,
    .segment_entries_max = 1024,
    .segments_max = 16,
    .unit_bytes_max = 16 * 1024,
    .filter_bytes = 1024,
    .sync_blocks = 4,
};
const superblock_bytes = 4096;
const ring_bytes = 640 * 1024;

const first_block: u64 = 1000;
const blocks_max = 600;
const keys_count = 48;
const changes_max = 6;
const record_bytes_max = 9000;

const ChangeSpec = struct { key: u8, new: ?u64 };

/// The chain: per block its changes and record length, and the state after each block
/// (`states[0]` before `first_block`).
const Model = struct {
    states: [blocks_max + 1][keys_count]?u64,
    changes: [blocks_max][changes_max]ChangeSpec,
    counts: [blocks_max]u32,
    record_lengths: [blocks_max]u32,

    fn generate(model: *Model, seed: u64) void {
        var prng = Prng.init(seed);
        for (&model.states[0], 0..) |*value, key| {
            value.* = if (key % 3 == 0) null else prng.int(u64);
        }
        for (0..blocks_max) |index| {
            model.states[index + 1] = model.states[index];
            const count: u32 = @intCast(prng.below(changes_max + 1));
            const start = prng.below(keys_count);
            for (0..count) |j| {
                // 7 is coprime with 48: distinct keys.
                const key: u8 = @intCast((start + 7 * j) % keys_count);
                const new: ?u64 = if (prng.chance(1, 5)) null else prng.int(u64);
                model.changes[index][j] = .{ .key = key, .new = new };
                model.states[index + 1][key] = new;
            }
            model.counts[index] = count;
            model.record_lengths[index] = @intCast(prng.range(1, record_bytes_max));
        }
    }

    /// The state index after block `number`.
    fn after(number: u64) usize {
        assert(number + 1 >= first_block);
        return @intCast(number + 1 - first_block);
    }
};

fn hash_of(number: u64) Hash {
    var hash: Hash = @splat(0);
    std.mem.writeInt(u64, hash[0..8], number, .little);
    hash[8] = 0xb1;
    return hash;
}

fn transaction_hash(number: u64, index: u32) Hash {
    var hash: Hash = @splat(0);
    std.mem.writeInt(u64, hash[0..8], number, .little);
    hash[8] = 0x7a;
    hash[9] = @intCast(index);
    return hash;
}

fn kind_of(key: usize) Kind {
    return if (key % 2 == 0) .account else .slot;
}

fn key_of(key: usize, buffer: *[64]u8) []const u8 {
    @memset(buffer, 0xac);
    buffer[0] = @intCast(key);
    return if (key % 2 == 0) buffer[0..32] else buffer[0..64];
}

fn record_byte(number: u64, position: usize) u8 {
    return @truncate(number *% 31 +% position);
}

/// Appends block `number` of the model.
fn append(archive: *Archive, model: *const Model, number: u64) !void {
    const index: usize = @intCast(number - first_block);
    var keys: [changes_max][64]u8 = undefined;
    var olds: [changes_max][8]u8 = undefined;
    var changes: [changes_max]archive_module.Change = undefined;
    for (model.changes[index][0..model.counts[index]], 0..) |spec, j| {
        const old = model.states[index][spec.key];
        if (old) |value| std.mem.writeInt(u64, &olds[j], value, .little);
        changes[j] = .{
            .kind = kind_of(spec.key),
            .key = key_of(spec.key, &keys[j]),
            .old = if (old != null) &olds[j] else null,
        };
    }
    var record: [record_bytes_max]u8 = undefined;
    const length = model.record_lengths[index];
    for (record[0..length], 0..) |*byte, position| byte.* = record_byte(number, position);
    const hashes = [_]Hash{ transaction_hash(number, 0), transaction_hash(number, 1) };
    try archive.append(&.{
        .number = number,
        .hash = hash_of(number),
        .parent_hash = hash_of(number - 1),
        .record = record[0..length],
        .transaction_hashes = &hashes,
        .changes = changes[0..model.counts[index]],
    });
    try archive.tick();
}

/// Checks the archive's window against the model at `samples` random blocks, plus its
/// first and last.
fn check(archive: *Archive, model: *const Model, prng: *Prng, samples: u32) !void {
    const head = archive.head orelse return;
    const oldest = archive.oldest().?;
    try testing.expect(oldest >= first_block);
    try testing.expectEqualSlices(u8, &hash_of(head), &archive.head_hash);
    for (0..samples + 2) |sample| {
        const number = switch (sample) {
            0 => oldest - 1,
            1 => head,
            else => prng.range(oldest - 1, head),
        };
        try check_values(archive, model, number);
        if (number < oldest) continue;
        try check_block(archive, model, number);
    }
    if (oldest > first_block) {
        const pruned = hash_of(oldest - 1);
        try testing.expectEqual(null, try archive.find(.block, &pruned));
    }
    const above = hash_of(head + 1);
    try testing.expectEqual(null, try archive.find(.block, &above));
}

fn check_values(archive: *Archive, model: *const Model, number: u64) !void {
    const head = archive.head.?;
    for (0..keys_count) |key| {
        var buffer: [64]u8 = undefined;
        const found = try archive.value_after(kind_of(key), key_of(key, &buffer), number);
        const actual: ?u64 = if (found) |value| blk: {
            try testing.expect(value.number > number and value.number <= head);
            const old = value.old orelse break :blk null;
            try testing.expectEqual(8, old.len);
            break :blk std.mem.readInt(u64, old[0..8], .little);
        } else model.states[Model.after(head)][key];
        try testing.expectEqual(model.states[Model.after(number)][key], actual);
    }
}

fn check_block(archive: *Archive, model: *const Model, number: u64) !void {
    const location = (try archive.find(.block, &hash_of(number))).?;
    try testing.expectEqual(number, location.number);
    const transaction = (try archive.find(.transaction, &transaction_hash(number, 1))).?;
    try testing.expectEqual(number, transaction.number);
    try testing.expectEqual(1, transaction.aux);
    const unit = (try archive.block_at(number)).?;
    try testing.expectEqualSlices(u8, &hash_of(number - 1), &unit.parent_hash);
    try testing.expectEqual(2, unit.transaction_hashes.len);
    const record = unit.record.?;
    try testing.expectEqual(model.record_lengths[@intCast(number - first_block)], record.len);
    for (record, 0..) |byte, position| {
        try testing.expectEqual(record_byte(number, position), byte);
    }
}

const Harness = struct {
    storage: SimStorage,
    model: *Model,
    prng: Prng,

    fn init(harness: *Harness, seed: u64) !void {
        harness.storage = try SimStorage.init(testing.allocator, .{
            .size_bytes = 2 * superblock_bytes + ring_bytes,
            .seed = seed,
        });
        errdefer harness.storage.deinit(testing.allocator);
        harness.model = try testing.allocator.create(Model);
        harness.model.generate(seed);
        harness.prng = Prng.init(seed ^ 0x5eed);
    }

    fn deinit(harness: *Harness) void {
        testing.allocator.destroy(harness.model);
        harness.storage.deinit(testing.allocator);
    }

    fn open(harness: *Harness) !Archive {
        var archive = try Archive.init(testing.allocator, &harness.storage, config);
        errdefer archive.deinit(testing.allocator);
        try archive.load();
        return archive;
    }
};

test "archive: answers match a model across seals, evictions, and lap skips" {
    var harness: Harness = undefined;
    try harness.init(1);
    defer harness.deinit();
    var archive = try harness.open();
    defer archive.deinit(testing.allocator);
    try testing.expectEqual(null, archive.head);
    var number = first_block;
    while (number < first_block + blocks_max) : (number += 1) {
        try append(&archive, harness.model, number);
        if ((number - first_block) % 50 == 49) {
            try check(&archive, harness.model, &harness.prng, 8);
        }
    }
    try testing.expect(archive.stats.seals > 30);
    try testing.expect(archive.stats.evictions > 10);
    // The byte ring bounds the window well below the directory's 16 segments.
    try testing.expect(archive.oldest().? > first_block + blocks_max - 16 * 8);
    try testing.expect(archive.bytes_used() <= ring_bytes);
    try archive.flush();
}

test "archive: reopens after a flush and after a crash" {
    var harness: Harness = undefined;
    try harness.init(2);
    defer harness.deinit();
    const flushed_head = first_block + 199;
    {
        var archive = try harness.open();
        defer archive.deinit(testing.allocator);
        var number = first_block;
        while (number <= flushed_head) : (number += 1) {
            try append(&archive, harness.model, number);
        }
        try archive.flush();
    }
    var archive = try harness.open();
    defer archive.deinit(testing.allocator);
    try testing.expectEqual(flushed_head, archive.head.?);
    try check(&archive, harness.model, &harness.prng, 16);
    var number = flushed_head + 1;
    while (number <= flushed_head + 30) : (number += 1) {
        try append(&archive, harness.model, number);
    }
    // Power loss with unsynced blocks: the reopened archive keeps a prefix of the chain.
    harness.storage.crash();
    var reopened = try harness.open();
    defer reopened.deinit(testing.allocator);
    const head = reopened.head.?;
    try testing.expect(head >= flushed_head and head <= flushed_head + 30);
    try check(&reopened, harness.model, &harness.prng, 16);
    number = head + 1;
    while (number < first_block + 300) : (number += 1) {
        try append(&reopened, harness.model, number);
    }
    try check(&reopened, harness.model, &harness.prng, 16);
    try reopened.flush();
}

test "archive: rebase truncates into a sealed segment, or resets" {
    var harness: Harness = undefined;
    try harness.init(3);
    defer harness.deinit();
    var archive = try harness.open();
    defer archive.deinit(testing.allocator);
    var number = first_block;
    while (number < first_block + 100) : (number += 1) {
        try append(&archive, harness.model, number);
    }
    const target = first_block + 77;
    try testing.expectEqual(.aligned, try archive.rebase(target, hash_of(target)));
    try testing.expectEqual(target, archive.head.?);
    try check(&archive, harness.model, &harness.prng, 8);
    try testing.expectEqual(null, try archive.find(.block, &hash_of(target + 1)));
    // Re-appending after a truncation gives the same answers.
    number = target + 1;
    while (number < first_block + 120) : (number += 1) {
        try append(&archive, harness.model, number);
    }
    try check(&archive, harness.model, &harness.prng, 8);
    const ahead = first_block + 150;
    try testing.expectEqual(.behind, try archive.rebase(ahead, hash_of(ahead)));
    // A different block at the head: the archive cannot serve that chain.
    var other = hash_of(first_block + 119);
    other[31] = 1;
    try testing.expectEqual(.empty, try archive.rebase(first_block + 119, other));
    try testing.expectEqual(null, archive.head);
    try testing.expectEqual(null, try archive.find(.block, &hash_of(first_block + 110)));
    try archive.flush();
    var reopened = try harness.open();
    defer reopened.deinit(testing.allocator);
    try testing.expectEqual(null, reopened.head);
}

test "archive: a corrupt sector is an error, never a wrong answer" {
    var harness: Harness = undefined;
    try harness.init(4);
    defer harness.deinit();
    var archive = try harness.open();
    defer archive.deinit(testing.allocator);
    var number = first_block;
    while (number < first_block + 120) : (number += 1) {
        try append(&archive, harness.model, number);
    }
    try archive.flush();
    const ring_sectors: u32 = ring_bytes / 4096;
    for (0..64) |_| {
        const sector: u32 = @intCast(2 + harness.prng.below(ring_sectors));
        harness.storage.corrupt_sector(sector);
    }
    archive.read_cached = null;
    var errors: u32 = 0;
    for (0..40) |_| {
        const oldest = archive.oldest().?;
        const at = harness.prng.range(oldest - 1, archive.head.?);
        check_values(&archive, harness.model, at) catch |err| switch (err) {
            error.Corrupt => errors += 1,
            else => return err,
        };
    }
    try testing.expect(errors > 0);
}

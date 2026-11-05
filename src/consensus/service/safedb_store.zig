//! Durable L1 -> safe head mapping (base/base `--safedb.path`), so
//! `optimism_safeHeadAtL1Block` answers across restarts.
//!
//! base/base keeps the entries in redb. Here the file is one image
//! `magic | count u32 | count * 80-byte safedb records | crc32 (over everything before it)`,
//! written through `p2p.peers.store_file` (io layer, fsync after each write; shorter images
//! are padded with spaces, which the decoder ignores). A torn or foreign image fails the
//! checksum and loads as an empty database, like a missing file.
//!
//! The owner gates derivation until `loaded` (the database must not change before the old
//! image is read), then calls `update` every tick: a changed database schedules a write.

const std = @import("std");
const assert = std.debug.assert;

const safedb = @import("../safedb/root.zig");
const store_file = @import("../p2p/peers/store_file.zig");

const SafeDB = safedb.SafeDB;
const record_size_bytes = safedb.record_size_bytes;

pub const magic = "nfsafe01".*;
const header_length = magic.len + 4;
/// Re-writes the image this often even without changes.
pub const save_interval_ns = 60 * std.time.ns_per_s;

pub fn image_length_max(capacity: u32) usize {
    assert(capacity > 0);
    return header_length + @as(usize, capacity) * record_size_bytes + 4;
}

/// Writes `db` as an image into `out` and returns the used prefix.
pub fn encode_image(db: *const SafeDB, out: []u8) []const u8 {
    const length = header_length + @as(usize, db.count) * record_size_bytes + 4;
    assert(out.len >= length);
    out[0..magic.len].* = magic;
    std.mem.writeInt(u32, out[magic.len..][0..4], db.count, .big);
    for (db.entries[0..db.count], 0..) |entry, index| {
        const start = header_length + index * record_size_bytes;
        out[start..][0..record_size_bytes].* = safedb.encode_record(entry);
    }
    const crc = std.hash.Crc32.hash(out[0 .. length - 4]);
    std.mem.writeInt(u32, out[length - 4 ..][0..4], crc, .big);
    return out[0..length];
}

pub const DecodeError = error{ Truncated, BadMagic, BadChecksum, TooManyEntries, Unsorted };

/// Replaces `db`'s entries with the image's. On error `db` is left empty.
pub fn decode_image(db: *SafeDB, contents: []const u8) DecodeError!void {
    db.count = 0;
    if (contents.len < header_length + 4) return error.Truncated;
    if (!std.mem.eql(u8, contents[0..magic.len], &magic)) return error.BadMagic;
    const count = std.mem.readInt(u32, contents[magic.len..][0..4], .big);
    if (count > db.entries.len) return error.TooManyEntries;
    const length = header_length + @as(usize, count) * record_size_bytes + 4;
    if (contents.len < length) return error.Truncated;
    for (contents[length..]) |byte| if (byte != ' ') return error.BadChecksum;
    const crc = std.mem.readInt(u32, contents[length - 4 ..][0..4], .big);
    if (crc != std.hash.Crc32.hash(contents[0 .. length - 4])) return error.BadChecksum;
    var previous: ?u64 = null;
    for (0..count) |index| {
        const start = header_length + index * record_size_bytes;
        const entry = safedb.decode_record(contents[start..][0..record_size_bytes]);
        if (previous) |number| if (entry.l1_block.number <= number) {
            db.count = 0;
            return error.Unsorted;
        };
        previous = entry.l1_block.number;
        db.entries[index] = entry;
        db.count = @intCast(index + 1);
    }
    assert(db.count == count);
}

pub fn SafeDbStore(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const File = store_file.StoreFile(IO, Self, .{
            .loaded = on_loaded,
            .produce = produce,
        });

        file: File,
        db: *SafeDB,
        loaded: bool = false,
        /// `db.version` of the last image handed to the file.
        saved_version: u64 = 0,
        invalid_images: u64 = 0,

        /// `store` must not move afterwards.
        pub fn init(
            store: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            db: *SafeDB,
            path: []const u8,
        ) !void {
            store.* = .{ .file = undefined, .db = db };
            const length = image_length_max(@intCast(db.entries.len));
            try store.file.init(allocator, io, store, path, length, save_interval_ns);
            assert(!store.loaded);
            assert(store.file.buffer.len == length);
        }

        pub fn deinit(store: *Self, allocator: std.mem.Allocator) void {
            assert(!store.file.busy());
            store.file.deinit(allocator);
            store.* = undefined;
        }

        pub fn start(store: *Self) void {
            assert(!store.loaded);
            store.file.start();
        }

        pub fn stop(store: *Self) void {
            store.file.stop();
        }

        pub fn busy(store: *const Self) bool {
            return store.file.busy();
        }

        /// Schedules a write when the database changed since the last one.
        pub fn update(store: *Self) void {
            if (!store.loaded) return; // Never overwrite before the old image is read.
            if (store.db.version == store.saved_version) return;
            store.file.save();
        }

        fn on_loaded(store: *Self, contents: []const u8) void {
            assert(!store.loaded);
            if (contents.len > 0) {
                decode_image(store.db, contents) catch {
                    store.invalid_images += 1;
                };
            }
            store.db.version += 1;
            store.saved_version = store.db.version; // What is on disk (or nothing to keep).
            store.loaded = true;
        }

        fn produce(store: *Self, buffer: []u8) []const u8 {
            assert(store.loaded);
            store.saved_version = store.db.version;
            return encode_image(store.db, buffer);
        }
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const io_module = @import("../../utilities/io/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn random_db(prng: *Prng, db: *SafeDB, entries: u32) void {
    var number: u64 = prng.below(1000);
    for (0..entries) |_| {
        number += 1 + prng.below(50);
        var entry: safedb.Entry = .{
            .l1_block = .{ .number = number },
            .safe_head = .{ .number = prng.int(u64) },
        };
        prng.fill(&entry.l1_block.hash.bytes);
        prng.fill(&entry.safe_head.hash.bytes);
        db.insert(entry);
    }
}

test "safedb store: image roundtrip, padding, and corruption" {
    var prng = Prng.init(0x5afe);
    var db = try SafeDB.init(testing.allocator, 16);
    defer db.deinit(testing.allocator);
    random_db(&prng, &db, 12);
    var buffer: [image_length_max(16) + 8]u8 = undefined;
    const image = encode_image(&db, &buffer);
    try testing.expectEqual(header_length + 12 * record_size_bytes + 4, image.len);
    var copy = try SafeDB.init(testing.allocator, 16);
    defer copy.deinit(testing.allocator);
    @memset(buffer[image.len..], ' '); // StoreFile pads shorter images with spaces.
    try decode_image(&copy, &buffer);
    try testing.expectEqualSlices(safedb.Entry, db.entries[0..db.count], copy.entries[0..12]);
    buffer[20] ^= 1;
    try testing.expectError(error.BadChecksum, decode_image(&copy, &buffer));
    try testing.expectEqual(@as(u32, 0), copy.count);
    var small = try SafeDB.init(testing.allocator, 4);
    defer small.deinit(testing.allocator);
    buffer[20] ^= 1;
    try testing.expectError(error.TooManyEntries, decode_image(&small, &buffer));
    try testing.expectError(error.Truncated, decode_image(&copy, buffer[0 .. image.len - 1]));
    const foreign = "nfsafe02".* ++ @as([8]u8, @splat(0));
    try testing.expectError(error.BadMagic, decode_image(&copy, &foreign));
}

test "safedb store: seeded roundtrip of random databases" {
    var prng = Prng.init(0xdb5);
    var db = try SafeDB.init(testing.allocator, 64);
    defer db.deinit(testing.allocator);
    var copy = try SafeDB.init(testing.allocator, 64);
    defer copy.deinit(testing.allocator);
    var buffer: [image_length_max(64)]u8 = undefined;
    for (0..64) |_| {
        db.count = 0;
        random_db(&prng, &db, @intCast(prng.below(65)));
        const image = encode_image(&db, &buffer);
        try decode_image(&copy, image);
        const decoded = copy.entries[0..copy.count];
        try testing.expectEqualSlices(safedb.Entry, db.entries[0..db.count], decoded);
    }
}

fn fuzz_image(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [image_length_max(4) + 8]u8 = undefined;
    const length = smith.slice(&bytes);
    var entries: [4]safedb.Entry = undefined;
    var db: SafeDB = .{ .entries = &entries };
    decode_image(&db, bytes[0..length]) catch {
        try testing.expectEqual(@as(u32, 0), db.count);
        return;
    };
    var out: [image_length_max(4)]u8 = undefined;
    const image = encode_image(&db, &out);
    try testing.expectEqualSlices(u8, image, bytes[0..image.len]);
}

test "safedb store: fuzz" {
    try std.testing.fuzz({}, fuzz_image, .{});
}

test "safedb store: persists across a restart through the sim io" {
    const allocator = testing.allocator;
    var world = try io_module.SimWorld.init(allocator, .{ .seed = 0x5d });
    defer world.deinit();
    var sim: io_module.SimIo = undefined;
    try io_module.SimIo.init(&sim, allocator, &world, .{
        .host = io_module.Address.ip4(.{ 10, 0, 0, 1 }, 0),
        .disk = .{ .files_max = 1, .file_size_max = 4096 },
    });
    defer sim.deinit();
    var prng = Prng.init(0x77);
    var db = try SafeDB.init(allocator, 32);
    defer db.deinit(allocator);
    const Store = SafeDbStore(io_module.SimIo);
    var store: Store = undefined;
    try store.init(allocator, &sim, &db, "safedb.bin");
    store.start();
    world.run_for_ns(10 * std.time.ns_per_ms);
    try testing.expect(store.loaded);
    try testing.expectEqual(@as(u32, 0), db.count); // No file yet.
    random_db(&prng, &db, 20);
    store.update();
    world.run_for_ns(10 * std.time.ns_per_ms);
    store.stop();
    world.run_for_ns(10 * std.time.ns_per_ms);
    store.deinit(allocator);
    var restored = try SafeDB.init(allocator, 32);
    defer restored.deinit(allocator);
    try store.init(allocator, &sim, &restored, "safedb.bin");
    store.start();
    world.run_for_ns(10 * std.time.ns_per_ms);
    try testing.expect(store.loaded);
    try testing.expectEqualSlices(safedb.Entry, db.entries[0..db.count], restored.entries[0..20]);
    store.stop();
    world.run_for_ns(10 * std.time.ns_per_ms);
    store.deinit(allocator);
}

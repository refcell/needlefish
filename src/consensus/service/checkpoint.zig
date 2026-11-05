//! Durable forkchoice checkpoints: the last safe and finalized L2 heads, so a restart can
//! recover them when the execution client has pruned those blocks' bodies (base/base
//! `crates/consensus/service/src/actors/checkpoint`, `--checkpoint.path`).
//!
//! Each head is stored in base/base's 128-byte record layout (hash, number, parent hash,
//! timestamp, L1 origin number, L1 origin hash, sequence number; integers big-endian).
//! base/base keeps the records in redb; here the file is one fixed-size image
//! `magic | present mask | safe record | finalized record | crc32` written through
//! `p2p.peers.store_file` (io layer, fsync after each write). A torn or foreign image fails
//! the checksum and loads as "no checkpoints", like a missing file.
//!
//! The owner calls `update` with the engine's heads; a change schedules a write right away
//! (skipped and retried at the next change or interval while one is in flight).

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const store_file = @import("../p2p/peers/store_file.zig");

const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;

pub const record_length = 128;
pub const magic = "nfckpt01".*;
pub const image_length = magic.len + 1 + 2 * record_length + 4;
/// Re-writes the image this often even without changes.
pub const save_interval_ns = 60 * std.time.ns_per_s;

pub const Label = enum(u1) { safe = 0, finalized = 1 };

pub const Checkpoints = struct {
    safe: ?L2BlockInfo = null,
    finalized: ?L2BlockInfo = null,

    pub fn get(checkpoints: Checkpoints, label: Label) ?L2BlockInfo {
        return switch (label) {
            .safe => checkpoints.safe,
            .finalized => checkpoints.finalized,
        };
    }
};

const hash_offset = 0;
const number_offset = hash_offset + 32;
const parent_hash_offset = number_offset + 8;
const timestamp_offset = parent_hash_offset + 32;
const origin_number_offset = timestamp_offset + 8;
const origin_hash_offset = origin_number_offset + 8;
const sequence_number_offset = origin_hash_offset + 32;
const payload_end = sequence_number_offset + 8;

comptime {
    assert(payload_end == record_length);
    assert(image_length == 269);
}

pub fn encode_record(block: L2BlockInfo) [record_length]u8 {
    var bytes: [record_length]u8 = undefined;
    bytes[hash_offset..][0..32].* = block.block_info.hash.bytes;
    std.mem.writeInt(u64, bytes[number_offset..][0..8], block.block_info.number, .big);
    bytes[parent_hash_offset..][0..32].* = block.block_info.parent_hash.bytes;
    std.mem.writeInt(u64, bytes[timestamp_offset..][0..8], block.block_info.timestamp, .big);
    std.mem.writeInt(u64, bytes[origin_number_offset..][0..8], block.l1_origin.number, .big);
    bytes[origin_hash_offset..][0..32].* = block.l1_origin.hash.bytes;
    std.mem.writeInt(u64, bytes[sequence_number_offset..][0..8], block.sequence_number, .big);
    assert(std.mem.eql(u8, bytes[0..32], &block.block_info.hash.bytes));
    return bytes;
}

pub fn decode_record(bytes: *const [record_length]u8) L2BlockInfo {
    const block: L2BlockInfo = .{
        .block_info = .{
            .hash = .{ .bytes = bytes[hash_offset..][0..32].* },
            .number = std.mem.readInt(u64, bytes[number_offset..][0..8], .big),
            .parent_hash = .{ .bytes = bytes[parent_hash_offset..][0..32].* },
            .timestamp = std.mem.readInt(u64, bytes[timestamp_offset..][0..8], .big),
        },
        .l1_origin = .{
            .number = std.mem.readInt(u64, bytes[origin_number_offset..][0..8], .big),
            .hash = .{ .bytes = bytes[origin_hash_offset..][0..32].* },
        },
        .sequence_number = std.mem.readInt(u64, bytes[sequence_number_offset..][0..8], .big),
    };
    assert(std.mem.eql(u8, &block.block_info.hash.bytes, bytes[0..32]));
    return block;
}

pub fn encode_image(checkpoints: Checkpoints, out: *[image_length]u8) void {
    @memset(out, 0);
    out[0..magic.len].* = magic;
    var mask: u8 = 0;
    inline for (.{ Label.safe, Label.finalized }) |label| {
        if (checkpoints.get(label)) |block| {
            mask |= @as(u8, 1) << @backingInt(label);
            const start = magic.len + 1 + @as(usize, @backingInt(label)) * record_length;
            out[start..][0..record_length].* = encode_record(block);
        }
    }
    out[magic.len] = mask;
    const crc = std.hash.Crc32.hash(out[0 .. image_length - 4]);
    std.mem.writeInt(u32, out[image_length - 4 ..][0..4], crc, .little);
    assert(out[magic.len] <= 3);
}

pub const DecodeError = error{InvalidImage};

/// Empty contents (no file yet) decode to no checkpoints.
pub fn decode_image(contents: []const u8) DecodeError!Checkpoints {
    if (contents.len == 0) return .{};
    if (contents.len != image_length) return error.InvalidImage;
    if (!std.mem.eql(u8, contents[0..magic.len], &magic)) return error.InvalidImage;
    const stored = std.mem.readInt(u32, contents[image_length - 4 ..][0..4], .little);
    if (stored != std.hash.Crc32.hash(contents[0 .. image_length - 4])) {
        return error.InvalidImage;
    }
    const mask = contents[magic.len];
    if (mask > 3) return error.InvalidImage;
    var checkpoints: Checkpoints = .{};
    const safe_start = magic.len + 1;
    const finalized_start = safe_start + record_length;
    // Canonical images zero the slots of absent records.
    const safe_slot = contents[safe_start..][0..record_length];
    const finalized_slot = contents[finalized_start..][0..record_length];
    if (mask & 1 == 0 and !std.mem.allEqual(u8, safe_slot, 0)) return error.InvalidImage;
    if (mask & 2 == 0 and !std.mem.allEqual(u8, finalized_slot, 0)) return error.InvalidImage;
    if (mask & 1 != 0) checkpoints.safe = decode_record(contents[safe_start..][0..record_length]);
    if (mask & 2 != 0) {
        checkpoints.finalized = decode_record(contents[finalized_start..][0..record_length]);
    }
    assert((checkpoints.safe != null) == (mask & 1 != 0));
    return checkpoints;
}

fn same_block(a: ?L2BlockInfo, b: L2BlockInfo) bool {
    const left = a orelse return false;
    return std.meta.eql(left, b);
}

pub fn CheckpointStore(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const File = store_file.StoreFile(IO, Self, .{
            .loaded = on_loaded,
            .produce = produce,
        });

        file: File,
        checkpoints: Checkpoints = .{},
        /// The checkpoints read at start (null until the read finished).
        loaded: ?Checkpoints = null,
        invalid_images: u64 = 0,

        /// `store` must not move afterwards.
        pub fn init(
            store: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            path: []const u8,
        ) !void {
            store.* = .{ .file = undefined };
            try store.file.init(allocator, io, store, path, image_length, save_interval_ns);
            assert(store.loaded == null);
            assert(store.file.buffer.len == image_length);
        }

        pub fn deinit(store: *Self, allocator: std.mem.Allocator) void {
            assert(!store.file.busy());
            store.file.deinit(allocator);
            store.* = undefined;
        }

        pub fn start(store: *Self) void {
            assert(store.loaded == null);
            store.file.start();
        }

        pub fn stop(store: *Self) void {
            store.file.stop();
        }

        pub fn busy(store: *const Self) bool {
            return store.file.busy();
        }

        /// Records the engine's safe and finalized heads (genesis-default heads are skipped).
        pub fn update(store: *Self, safe: L2BlockInfo, finalized: L2BlockInfo) void {
            if (store.loaded == null) return; // Never overwrite before the old image is read.
            var changed = false;
            const empty: L2BlockInfo = .{};
            if (!std.meta.eql(safe, empty) and !same_block(store.checkpoints.safe, safe)) {
                store.checkpoints.safe = safe;
                changed = true;
            }
            if (!std.meta.eql(finalized, empty) and
                !same_block(store.checkpoints.finalized, finalized))
            {
                store.checkpoints.finalized = finalized;
                changed = true;
            }
            if (changed) store.file.save();
            assert(!changed or store.checkpoints.safe != null or
                store.checkpoints.finalized != null);
        }

        fn on_loaded(store: *Self, contents: []const u8) void {
            const checkpoints = decode_image(contents) catch blk: {
                store.invalid_images += 1;
                break :blk Checkpoints{};
            };
            store.loaded = checkpoints;
            store.checkpoints = checkpoints;
            assert(store.loaded != null);
        }

        fn produce(store: *Self, buffer: []u8) []const u8 {
            assert(buffer.len >= image_length);
            encode_image(store.checkpoints, buffer[0..image_length]);
            return buffer[0..image_length];
        }
    };
}

const testing = std.testing;
const io_module = @import("../../utilities/io/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const ns_per_ms = std.time.ns_per_ms;

fn random_block(prng: *Prng) L2BlockInfo {
    var block: L2BlockInfo = .{
        .block_info = .{ .number = prng.int(u64), .timestamp = prng.int(u64) },
        .l1_origin = .{ .number = prng.int(u64) },
        .sequence_number = prng.int(u64),
    };
    prng.fill(&block.block_info.hash.bytes);
    prng.fill(&block.block_info.parent_hash.bytes);
    prng.fill(&block.l1_origin.hash.bytes);
    return block;
}

test "checkpoint: record layout matches base/base" {
    var block: L2BlockInfo = .{
        .block_info = .{ .number = 0x0102, .timestamp = 7 },
        .l1_origin = .{ .number = 9 },
        .sequence_number = 3,
    };
    block.block_info.hash.bytes = @splat(0xaa);
    block.block_info.parent_hash.bytes = @splat(0xbb);
    block.l1_origin.hash.bytes = @splat(0xcc);
    const bytes = encode_record(block);
    try testing.expectEqual(@as(u8, 0xaa), bytes[0]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 1, 2 }, bytes[32..40]);
    try testing.expectEqual(@as(u8, 0xbb), bytes[40]);
    try testing.expectEqual(@as(u8, 7), bytes[79]);
    try testing.expectEqual(@as(u8, 9), bytes[87]);
    try testing.expectEqual(@as(u8, 0xcc), bytes[88]);
    try testing.expectEqual(@as(u8, 3), bytes[127]);
    try testing.expect(std.meta.eql(block, decode_record(&bytes)));
}

test "checkpoint: image round trip and corruption detection" {
    var prng = Prng.init(0xc4);
    var image: [image_length]u8 = undefined;
    for (0..128) |_| {
        const checkpoints: Checkpoints = .{
            .safe = if (prng.chance(1, 2)) random_block(&prng) else null,
            .finalized = if (prng.chance(1, 2)) random_block(&prng) else null,
        };
        encode_image(checkpoints, &image);
        const decoded = try decode_image(&image);
        try testing.expect(std.meta.eql(checkpoints, decoded));
        // Any single flipped bit fails the checksum (or the magic).
        const index = prng.below(image_length);
        image[index] ^= @as(u8, 1) << @intCast(prng.below(8));
        try testing.expectError(error.InvalidImage, decode_image(&image));
    }
    try testing.expect(std.meta.eql(Checkpoints{}, try decode_image("")));
    try testing.expectError(error.InvalidImage, decode_image("short"));
}

fn fuzz_image(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [image_length + 8]u8 = undefined;
    const length = smith.slice(&bytes);
    if (length == 0) return; // No file: no checkpoints, nothing to compare.
    const checkpoints = decode_image(bytes[0..length]) catch return;
    var image: [image_length]u8 = undefined;
    encode_image(checkpoints, &image);
    try testing.expectEqualSlices(u8, bytes[0..length], &image);
}

test "checkpoint: fuzz images" {
    try testing.fuzz({}, fuzz_image, .{});
}

const Store = CheckpointStore(io_module.SimIo);

const Harness = struct {
    world: io_module.SimWorld,
    io: io_module.SimIo,

    fn init(harness: *Harness, seed: u64) !void {
        harness.world = try io_module.SimWorld.init(testing.allocator, .{ .seed = seed });
        errdefer harness.world.deinit();
        try harness.io.init(testing.allocator, &harness.world, .{
            .host = io_module.Address.ip4(.{ 10, 0, 0, 1 }, 0),
            .disk = .{ .files_max = 1, .file_size_max = 512 },
        });
    }

    fn deinit(harness: *Harness) void {
        harness.io.deinit();
        harness.world.deinit();
    }

    fn open(harness: *Harness, store: *Store) !void {
        try store.init(testing.allocator, &harness.io, "checkpoint.bin");
        store.start();
        var rounds: u32 = 0;
        while (store.loaded == null) : (rounds += 1) {
            if (rounds == 1000) return error.ReadStuck;
            harness.world.run_for_ns(ns_per_ms);
        }
    }

    fn close(harness: *Harness, store: *Store) void {
        store.stop();
        while (store.busy()) harness.world.run_for_ns(ns_per_ms);
        store.deinit(testing.allocator);
    }
};

test "checkpoint: store persists heads across restarts and survives a crash" {
    var harness: Harness = undefined;
    try harness.init(0xc5);
    defer harness.deinit();
    var prng = Prng.init(0xc6);
    var store: Store = undefined;
    try harness.open(&store);
    try testing.expect(std.meta.eql(Checkpoints{}, store.loaded.?));
    const safe = random_block(&prng);
    const finalized = random_block(&prng);
    store.update(safe, .{});
    try testing.expect(store.checkpoints.finalized == null);
    while (store.file.phase != .idle) harness.world.run_for_ns(ns_per_ms);
    store.update(safe, finalized);
    harness.close(&store);
    try harness.open(&store);
    try testing.expect(std.meta.eql(safe, store.loaded.?.safe.?));
    try testing.expect(std.meta.eql(finalized, store.loaded.?.finalized.?));
    try testing.expectEqual(@as(u64, 0), store.invalid_images);
    // A write lost in a crash keeps the previous durable image.
    store.update(random_block(&prng), finalized);
    harness.io.crash();
    testing.allocator.free(store.file.buffer);
    try harness.open(&store);
    try testing.expect(std.meta.eql(safe, store.loaded.?.safe.?));
    harness.close(&store);
}

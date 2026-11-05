//! Real L1 data path for the simulator. The batcher model encodes L2 blocks with the
//! batcher lane's channel manager (singular batches, zlib, frame tx data); L1 carries
//! opaque tx data; verifiers decode it with the consensus protocol codecs (frames,
//! channel assembly, decompression, batch reader, singular batch decoding).
//!
//! Every submission is one channel in one frame, so decoding is stateless per L1
//! transaction and L1 reorg handling stays in the follower. Multi-frame channels across
//! L1 blocks need a channel bank; the simulator adopts the derive lane's once it lands.
//!
//! Model block encoding: block `n` is a singular batch with `timestamp = n * 2`,
//! `parent_hash` / hash carrying the model's 64-bit hashes, and one 8-byte transaction
//! holding the payload.

const std = @import("std");
const assert = std.debug.assert;
const manager_module = @import("../../batcher/channel/manager.zig");
const source = @import("../../batcher/source/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const B256 = primitives.B256;
const SingleBatch = protocol.batch.SingleBatch;
const batch_reader = protocol.batch_reader;

pub const blocks_max = 8;
/// Largest tx data: version byte plus one frame.
pub const tx_data_max = 2048;
pub const l2_block_time_s = 2;
const frame_size_max = tx_data_max - 1;
const input_bytes_max = 4096;
const decompressed_bytes_max = 16 * 1024;
/// Decompression allocates a full zlib window (64 KiB) plus the output.
const scratch_bytes = 256 * 1024;

/// A contiguous run of L2 blocks recovered from one L1 transaction.
pub const Blocks = struct {
    number_first: u64,
    count: u8,
    payloads: [blocks_max]u64,
};

fn word_hash(word: u64) B256 {
    var hash: B256 = .zero;
    std.mem.writeInt(u64, hash.bytes[24..32], word, .big);
    return hash;
}

/// Append-only store of submitted tx data. L1 blocks reference entries by index, as
/// real blocks carry transactions; entries are never rewritten, so a stale message
/// about an orphaned L1 block still names the same bytes.
pub const TxPool = struct {
    bytes: []u8,
    lengths: []u16,
    count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, entries_max: u32) !TxPool {
        assert(entries_max > 0);
        const bytes = try allocator.alloc(u8, @as(usize, entries_max) * tx_data_max);
        errdefer allocator.free(bytes);
        const lengths = try allocator.alloc(u16, entries_max);
        return .{ .bytes = bytes, .lengths = lengths };
    }

    pub fn deinit(pool: *TxPool, allocator: std.mem.Allocator) void {
        allocator.free(pool.bytes);
        allocator.free(pool.lengths);
        pool.* = undefined;
    }

    /// Stores `data`; returns its index, or null when the pool is full.
    pub fn append(pool: *TxPool, data: []const u8) ?u32 {
        assert(data.len > 0 and data.len <= tx_data_max);
        if (pool.count == pool.lengths.len) return null;
        const index = pool.count;
        @memcpy(pool.bytes[@as(usize, index) * tx_data_max ..][0..data.len], data);
        pool.lengths[index] = @intCast(data.len);
        pool.count += 1;
        return index;
    }

    pub fn get(pool: *const TxPool, index: u32) []const u8 {
        assert(index < pool.count);
        return pool.bytes[@as(usize, index) * tx_data_max ..][0..pool.lengths[index]];
    }

    /// Mutable view for byzantine tests that corrupt data already on L1.
    pub fn get_mutable(pool: *TxPool, index: u32) []u8 {
        assert(index < pool.count);
        return pool.bytes[@as(usize, index) * tx_data_max ..][0..pool.lengths[index]];
    }
};

pub const Encoder = struct {
    manager: manager_module.Manager,

    pub fn init(allocator: std.mem.Allocator, seed: u64) !Encoder {
        var channel_id_seed: [16]u8 = @splat(0);
        std.mem.writeInt(u64, channel_id_seed[0..8], seed, .big);
        const manager = try manager_module.Manager.init(allocator, .{
            .channel = .{ .frame_size_max = frame_size_max, .input_bytes_max = input_bytes_max },
            .batch_bytes_max = 512,
        }, channel_id_seed);
        return .{ .manager = manager };
    }

    pub fn deinit(encoder: *Encoder, allocator: std.mem.Allocator) void {
        encoder.manager.deinit(allocator);
        encoder.* = undefined;
    }

    /// Encodes blocks `first .. first + count` of a chain as one single-frame channel.
    /// The result borrows the encoder and is valid until the next call.
    pub fn encode(
        encoder: *Encoder,
        hashes: []const u64,
        payloads: []const u64,
        first: u64,
        count: u8,
    ) []const u8 {
        assert(first > 0 and count > 0 and count <= blocks_max);
        assert(first + count <= hashes.len and hashes.len == payloads.len);
        const manager = &encoder.manager;
        manager.reset();
        var number = first;
        while (number < first + count) : (number += 1) {
            var transaction: [8]u8 = undefined;
            std.mem.writeInt(u64, &transaction, payloads[number], .big);
            const transactions = [_][]const u8{&transaction};
            const block: source.L2Block = .{
                .number = number,
                .hash = word_hash(hashes[number]),
                .parent_hash = word_hash(hashes[number - 1]),
                .timestamp = number * l2_block_time_s,
                .l1_origin = .{},
                .sequence_number = 0,
                .transactions = &transactions,
            };
            // Proof: the channel input target (~3 KiB) exceeds blocks_max batches (~90 B).
            manager.add_block(&block, 0) catch unreachable;
        }
        manager.close_open();
        const data = manager.next_tx_data() orelse unreachable; // Closed with batches.
        assert(!manager.has_pending_frames()); // One frame per channel.
        assert(data.len <= tx_data_max);
        return data;
    }
};

pub const Decoder = struct {
    scratch: []u8,

    pub fn init(allocator: std.mem.Allocator) !Decoder {
        return .{ .scratch = try allocator.alloc(u8, scratch_bytes) };
    }

    pub fn deinit(decoder: *Decoder, allocator: std.mem.Allocator) void {
        allocator.free(decoder.scratch);
        decoder.* = undefined;
    }

    /// Decodes one L1 transaction, or null when it is not a valid single-frame channel
    /// of contiguous model blocks (derivation then ignores it).
    pub fn decode(decoder: *Decoder, tx_data: []const u8) ?Blocks {
        var fixed = std.heap.FixedBufferAllocator.init(decoder.scratch);
        const allocator = fixed.allocator();
        var frames_buffer: [4]protocol.Frame = undefined;
        const frames = protocol.frame.parse_frames(tx_data, &frames_buffer) catch return null;
        assert(frames.len > 0);
        var channel = protocol.Channel.init(frames[0].id, .{});
        for (frames) |frame| channel.add_frame(allocator, frame, .{}) catch return null;
        if (!channel.is_ready()) return null;
        const data = channel.frame_data_alloc(allocator) catch return null;
        const decompressed = batch_reader.decompress_channel(
            allocator,
            data,
            decompressed_bytes_max,
            false,
        ) catch return null;
        return decode_batches(allocator, decompressed);
    }
};

fn decode_batches(allocator: std.mem.Allocator, decompressed: []const u8) ?Blocks {
    var reader = batch_reader.BatchReader.init(decompressed);
    var blocks: Blocks = .{ .number_first = 0, .count = 0, .payloads = undefined };
    for (0..blocks_max + 1) |_| {
        const raw = (reader.next() catch return null) orelse break;
        if (raw.batch_type != .single) return null;
        if (blocks.count == blocks_max) return null;
        const batch = SingleBatch.decode(allocator, raw.payload) catch return null;
        if (batch.transactions.len != 1 or batch.transactions[0].len != 8) return null;
        if (batch.timestamp == 0 or batch.timestamp % l2_block_time_s != 0) return null;
        const number = batch.timestamp / l2_block_time_s;
        if (blocks.count == 0) {
            blocks.number_first = number;
        } else if (number != blocks.number_first + blocks.count) {
            return null;
        }
        blocks.payloads[blocks.count] = std.mem.readInt(u64, batch.transactions[0][0..8], .big);
        blocks.count += 1;
    } else return null; // More than blocks_max batches.
    if (blocks.count == 0) return null;
    assert(blocks.number_first > 0);
    return blocks;
}

const testing = std.testing;
const fuzz = @import("../fuzz.zig");

const Fixture = struct {
    hashes: [blocks_max + 2]u64,
    payloads: [blocks_max + 2]u64,
    encoder: Encoder,
    decoder: Decoder,

    fn init(fixture: *Fixture, seed: u64) !void {
        var prng = @import("../prng.zig").Prng.init(seed);
        for (&fixture.hashes, &fixture.payloads) |*hash, *payload| {
            hash.* = prng.int(u64);
            payload.* = prng.int(u64);
        }
        fixture.encoder = try Encoder.init(testing.allocator, seed);
        errdefer fixture.encoder.deinit(testing.allocator);
        fixture.decoder = try Decoder.init(testing.allocator);
    }

    fn deinit(fixture: *Fixture) void {
        fixture.encoder.deinit(testing.allocator);
        fixture.decoder.deinit(testing.allocator);
    }
};

test "codec: encode then decode round trips every batch size" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    var count: u8 = 1;
    while (count <= blocks_max) : (count += 1) {
        const data = fixture.encoder.encode(&fixture.hashes, &fixture.payloads, 1, count);
        const blocks = fixture.decoder.decode(data) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(@as(u64, 1), blocks.number_first);
        try testing.expectEqual(count, blocks.count);
        const expected = fixture.payloads[1..][0..count];
        try testing.expectEqualSlices(u64, expected, blocks.payloads[0..count]);
    }
}

fn fuzz_tamper(fixture: *Fixture, smith: *std.testing.Smith) anyerror!void {
    const count: u8 = smith.valueRangeAtMost(u8, 1, blocks_max);
    const first: u64 = smith.valueRangeAtMost(u8, 1, blocks_max + 1 - count);
    const encoded = fixture.encoder.encode(&fixture.hashes, &fixture.payloads, first, count);
    var data: [tx_data_max]u8 = undefined;
    @memcpy(data[0..encoded.len], encoded);
    var length: u32 = @intCast(encoded.len);
    if (smith.value(bool)) length = smith.valueRangeAtMost(u32, 1, length);
    const flips = smith.valueRangeAtMost(u8, 0, 3);
    for (0..flips) |_| data[smith.index(length)] ^= smith.value(u8) | 1;
    // Tampered tx data either fails to decode or decodes to a well-formed run.
    // (zlib's Adler-32 makes a silently different payload astronomically unlikely, but
    // the derivation model must not rely on it: it only needs a contiguous run.)
    const blocks = fixture.decoder.decode(data[0..length]) orelse return;
    try testing.expect(blocks.count >= 1 and blocks.count <= blocks_max);
    try testing.expect(blocks.number_first > 0);
    if (flips == 0 and length == encoded.len) {
        try testing.expectEqual(first, blocks.number_first);
        const expected = fixture.payloads[first..][0..count];
        try testing.expectEqualSlices(u64, expected, blocks.payloads[0..count]);
    }
}

test "codec: tampered tx data never decodes to a malformed run" {
    var fixture: Fixture = undefined;
    try fixture.init(2);
    defer fixture.deinit();
    try fuzz.run(&fixture, fuzz_tamper, .{ .iterations = 256 });
}

test "codec: pool keeps entries stable and reports full" {
    var pool = try TxPool.init(testing.allocator, 2);
    defer pool.deinit(testing.allocator);
    try testing.expectEqual(@as(?u32, 0), pool.append("ab"));
    try testing.expectEqual(@as(?u32, 1), pool.append("cde"));
    try testing.expectEqual(@as(?u32, null), pool.append("f"));
    try testing.expectEqualStrings("ab", pool.get(0));
    try testing.expectEqualStrings("cde", pool.get(1));
}

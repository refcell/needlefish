//! Channel reader: decompresses one channel at a time and decodes its batches.
//! Mirrors base/base `crates/consensus/derive/src/stages/channel/channel_reader.rs` and
//! `crates/consensus/protocol/src/batch/core.rs` (`Batch::decode`).
//!
//! Each decoded batch owns an arena holding a copy of its bytes and every decoded
//! structure, so it outlives the channel and is freed with `OwnedBatch.deinit`.
//!
//! The upstream channel stage exposes `next_data(prev) Error!?[]u8` (owned data) and the
//! stage below it (`prev`) exposes `origin() ?BlockInfo`. `Upstream` binds the reader to
//! both so the batch stages can treat it as a stage with `next_batch`, `flush`, `origin`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");

const batch_reader = protocol.batch_reader;
const SingleBatch = protocol.batch.SingleBatch;
const SpanBatch = protocol.span_batch.SpanBatch;
const RawSpanBatch = protocol.span_batch.RawSpanBatch;
const BlockInfo = protocol.block.BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Error = errors.Error;

pub const Batch = union(enum) {
    single: SingleBatch,
    span: SpanBatch,

    pub fn timestamp(batch: *const Batch) u64 {
        return switch (batch.*) {
            .single => |single| single.timestamp,
            .span => |span| span.starting_timestamp(),
        };
    }
};

/// A batch together with the arena that owns all of its memory.
pub const OwnedBatch = struct {
    arena: std.heap.ArenaAllocator,
    batch: Batch,

    pub fn deinit(owned: *OwnedBatch) void {
        owned.arena.deinit();
        owned.* = undefined;
    }

    /// Deep-copies a singular batch (including transaction bytes) into a new arena.
    pub fn from_single(
        allocator: Allocator,
        single: *const SingleBatch,
    ) Allocator.Error!OwnedBatch {
        var owned: OwnedBatch = .{ .arena = .init(allocator), .batch = undefined };
        errdefer owned.arena.deinit();
        const arena = owned.arena.allocator();
        const transactions = try arena.alloc([]const u8, single.transactions.len);
        for (transactions, single.transactions) |*copy, tx| copy.* = try arena.dupe(u8, tx);
        var copy = single.*;
        copy.transactions = transactions;
        owned.batch = .{ .single = copy };
        assert(transactions.len == single.transactions.len);
        return owned;
    }
};

/// Decodes one typed batch (`batch_type ++ payload`) into an owned batch. Returns null when
/// the batch is malformed; the caller drops the rest of the channel, as base/base does.
pub fn decode_batch(
    allocator: Allocator,
    rollup: *const RollupConfig,
    raw: batch_reader.RawBatch,
) Allocator.Error!?OwnedBatch {
    var owned: OwnedBatch = .{ .arena = .init(allocator), .batch = undefined };
    errdefer owned.arena.deinit();
    const arena = owned.arena.allocator();
    const payload = try arena.dupe(u8, raw.payload);
    switch (raw.batch_type) {
        .single => {
            const single = SingleBatch.decode(arena, payload) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                owned.arena.deinit();
                return null;
            };
            owned.batch = .{ .single = single };
        },
        .span => {
            const span = decode_span(arena, rollup, payload) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                owned.arena.deinit();
                return null;
            };
            assert(span.batches.len > 0);
            owned.batch = .{ .span = span };
        },
    }
    return owned;
}

fn decode_span(
    arena: Allocator,
    rollup: *const RollupConfig,
    payload: []const u8,
) protocol.span_batch.Error!SpanBatch {
    var input = payload;
    const raw = try RawSpanBatch.decode(arena, &input);
    assert(input.len <= payload.len);
    return raw.derive(arena, rollup.block_time, rollup.genesis.l2_time, rollup.l2_chain_id);
}

pub const ChannelReader = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    /// The current channel's decompressed batch stream, owned.
    decompressed: ?[]u8 = null,
    reader: batch_reader.BatchReader = .init(&.{}),

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) ChannelReader {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(channel_reader: *ChannelReader) void {
        channel_reader.next_channel();
        channel_reader.* = undefined;
    }

    /// Drops the current channel (reset, activation, flush, or after a decode failure).
    pub fn next_channel(channel_reader: *ChannelReader) void {
        if (channel_reader.decompressed) |data| channel_reader.allocator.free(data);
        channel_reader.decompressed = null;
        channel_reader.reader = .init(&.{});
        assert(channel_reader.reader.decompressed.len == 0);
    }

    /// Called by the batch stream when a span batch is invalid (post-Holocene only).
    pub fn flush(channel_reader: *ChannelReader) void {
        channel_reader.next_channel();
    }

    /// Loads and decompresses the next channel. Returns false when the channel failed to
    /// decompress and was dropped.
    fn load(channel_reader: *ChannelReader, channels: anytype, prev: anytype) Error!bool {
        assert(channel_reader.decompressed == null);
        const channel = try channels.next_data(prev) orelse return error.ChannelReaderEmpty;
        defer channel_reader.allocator.free(channel);
        const origin = prev.origin() orelse return error.MissingOrigin;
        const rollup = channel_reader.rollup;
        const limit = rollup.max_rlp_bytes_per_channel(origin.timestamp);
        const brotli = rollup.is_feature_active(.brotli_compression, origin.timestamp);
        const decompressed = batch_reader.decompress_channel(
            channel_reader.allocator,
            channel,
            limit,
            brotli,
        ) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return false;
        };
        assert(decompressed.len <= limit);
        channel_reader.decompressed = decompressed;
        channel_reader.reader = .init(decompressed);
        return true;
    }

    /// Returns the next batch, owned by the caller. `error.NotEnoughData` means the
    /// channel ended or was dropped; `error.ChannelReaderEmpty` means no channel was ready.
    pub fn next_batch(
        channel_reader: *ChannelReader,
        channels: anytype,
        prev: anytype,
    ) Error!OwnedBatch {
        if (channel_reader.decompressed == null) {
            const loaded = channel_reader.load(channels, prev) catch |err| {
                channel_reader.next_channel();
                return err;
            };
            if (!loaded) return error.NotEnoughData;
        }
        assert(channel_reader.decompressed != null);
        const raw = channel_reader.reader.next() catch null orelse {
            channel_reader.next_channel();
            return error.NotEnoughData;
        };
        const owned = try decode_batch(channel_reader.allocator, channel_reader.rollup, raw);
        return owned orelse {
            channel_reader.next_channel();
            return error.NotEnoughData;
        };
    }

    /// Binds the reader to its upstream stages.
    pub fn upstream(
        channel_reader: *ChannelReader,
        channels: anytype,
        prev: anytype,
    ) Upstream(@TypeOf(channels), @TypeOf(prev)) {
        return .{ .reader = channel_reader, .channels = channels, .prev = prev };
    }
};

/// The channel reader seen as a stage by the batch stream.
pub fn Upstream(comptime Channels: type, comptime Prev: type) type {
    return struct {
        reader: *ChannelReader,
        channels: Channels,
        prev: Prev,

        const Self = @This();

        pub fn next_batch(self: Self) Error!OwnedBatch {
            return self.reader.next_batch(self.channels, self.prev);
        }

        pub fn flush(self: Self) void {
            self.reader.flush();
        }

        pub fn origin(self: Self) ?BlockInfo {
            return self.prev.origin();
        }
    };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const rlp = @import("../../common/rlp/root.zig");
const flate = std.compress.flate;

fn compress_zlib(allocator: Allocator, input: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, 64);
    defer output.deinit();
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);
    var compress = try flate.Compress.init(&output.writer, window, .zlib, .default);
    try compress.writer.writeAll(input);
    try compress.finish();
    return output.toOwnedSlice();
}

/// Builds a decompressed batch stream: each entry is RLP-string-wrapped.
const StreamBuilder = struct {
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(builder: *StreamBuilder) void {
        builder.bytes.deinit(testing.allocator);
    }

    fn add_typed(builder: *StreamBuilder, typed: []const u8) !void {
        const length = rlp.bytes_length(typed);
        const out = try builder.bytes.addManyAsSlice(testing.allocator, length);
        var encoder = rlp.Encoder.init(out);
        encoder.bytes(typed);
        assert(encoder.written().len == length);
    }

    fn add_single(builder: *StreamBuilder, single: SingleBatch) !void {
        var buffer: [1024]u8 = undefined;
        buffer[0] = @backingInt(protocol.batch.BatchType.single);
        const encoded = single.encode(buffer[1..]);
        try builder.add_typed(buffer[0 .. encoded.len + 1]);
    }

    fn add_span(builder: *StreamBuilder, singles: []const SingleBatch, rollup: RollupConfig) !void {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const span = try SpanBatch.from_singular_batches(
            arena,
            singles,
            0,
            rollup.genesis.l2_time,
            rollup.l2_chain_id,
        );
        const encoded = try span.encode_alloc(arena);
        const typed = try arena.alloc(u8, encoded.len + 1);
        typed[0] = @backingInt(protocol.batch.BatchType.span);
        @memcpy(typed[1..], encoded);
        try builder.add_typed(typed);
    }

    fn compressed(builder: *const StreamBuilder) ![]u8 {
        return compress_zlib(testing.allocator, builder.bytes.items);
    }
};

/// Channel stage stub: hands out copies of `channels`, then null.
const TestChannels = struct {
    channels: []const []const u8,
    index: usize = 0,
    fail: ?Error = null,

    fn next_data(stub: *TestChannels, prev: anytype) Error!?[]u8 {
        _ = prev;
        if (stub.fail) |err| return err;
        if (stub.index == stub.channels.len) return null;
        defer stub.index += 1;
        return try testing.allocator.dupe(u8, stub.channels[stub.index]);
    }
};

const TestOrigin = struct {
    block: ?BlockInfo = .{},

    fn origin(stub: *const TestOrigin) ?BlockInfo {
        return stub.block;
    }
};

fn test_single(timestamp: u64, transactions: []const []const u8) SingleBatch {
    return .{
        .parent_hash = .init(@splat(0x11)),
        .epoch_num = 3,
        .epoch_hash = .init(@splat(0x22)),
        .timestamp = timestamp,
        .transactions = transactions,
    };
}

test "channel reader: single and span batches from one channel" {
    const rollup: RollupConfig = .{ .block_time = 2, .l2_chain_id = 10 };
    var builder: StreamBuilder = .{};
    defer builder.deinit();
    const txs = [_][]const u8{ &.{ 0x02, 0xaa }, &.{0x01} };
    try builder.add_single(test_single(100, &txs));
    const singles = [_]SingleBatch{ test_single(102, &.{}), test_single(104, &.{}) };
    try builder.add_span(&singles, rollup);
    const channel = try builder.compressed();
    defer testing.allocator.free(channel);

    var reader = ChannelReader.init(testing.allocator, &rollup);
    defer reader.deinit();
    var channels: TestChannels = .{ .channels = &.{channel} };
    var origin: TestOrigin = .{};
    const stage = reader.upstream(&channels, &origin);

    var first = try stage.next_batch();
    defer first.deinit();
    try testing.expectEqual(@as(u64, 100), first.batch.timestamp());
    try testing.expectEqual(@as(usize, 2), first.batch.single.transactions.len);
    try testing.expectEqualSlices(u8, txs[0], first.batch.single.transactions[0]);
    var second = try stage.next_batch();
    defer second.deinit();
    try testing.expectEqual(@as(usize, 2), second.batch.span.batches.len);
    try testing.expectEqual(@as(u64, 104), second.batch.span.final_timestamp());
    try testing.expect(reader.decompressed != null);
    try testing.expectError(error.NotEnoughData, stage.next_batch());
    try testing.expect(reader.decompressed == null);
    try testing.expectError(error.ChannelReaderEmpty, stage.next_batch());
    try testing.expect(stage.origin() != null);
}

test "channel reader: malformed batch drops the rest of the channel" {
    const rollup: RollupConfig = .{ .block_time = 2 };
    var builder: StreamBuilder = .{};
    defer builder.deinit();
    try builder.add_single(test_single(100, &.{}));
    try builder.add_typed(&.{ 0x00, 0xc1, 0x05 });
    try builder.add_single(test_single(102, &.{}));
    const first_channel = try builder.compressed();
    defer testing.allocator.free(first_channel);
    var next_builder: StreamBuilder = .{};
    defer next_builder.deinit();
    try next_builder.add_single(test_single(200, &.{}));
    const second_channel = try next_builder.compressed();
    defer testing.allocator.free(second_channel);

    var reader = ChannelReader.init(testing.allocator, &rollup);
    defer reader.deinit();
    var channels: TestChannels = .{ .channels = &.{ first_channel, second_channel } };
    var origin: TestOrigin = .{};
    var first = try reader.next_batch(&channels, &origin);
    first.deinit();
    try testing.expectError(error.NotEnoughData, reader.next_batch(&channels, &origin));
    try testing.expect(reader.decompressed == null);
    // The batch after the malformed one is gone: the next channel is read instead.
    var next = try reader.next_batch(&channels, &origin);
    defer next.deinit();
    try testing.expectEqual(@as(u64, 200), next.batch.timestamp());
}

test "channel reader: decompression failure drops the channel" {
    const rollup: RollupConfig = .{};
    var reader = ChannelReader.init(testing.allocator, &rollup);
    defer reader.deinit();
    const bad_zlib = [_]u8{ 0x78, 0x00, 0x00 };
    const unknown = [_]u8{0x02};
    var channels: TestChannels = .{ .channels = &.{ &bad_zlib, &unknown } };
    var origin: TestOrigin = .{};
    try testing.expectError(error.NotEnoughData, reader.next_batch(&channels, &origin));
    try testing.expect(reader.decompressed == null);
    try testing.expectError(error.NotEnoughData, reader.next_batch(&channels, &origin));
    try testing.expectError(error.ChannelReaderEmpty, reader.next_batch(&channels, &origin));
}

test "channel reader: upstream errors, missing origin, and flush" {
    const rollup: RollupConfig = .{};
    var builder: StreamBuilder = .{};
    defer builder.deinit();
    try builder.add_single(test_single(100, &.{}));
    try builder.add_single(test_single(102, &.{}));
    const channel = try builder.compressed();
    defer testing.allocator.free(channel);

    var reader = ChannelReader.init(testing.allocator, &rollup);
    defer reader.deinit();
    var channels: TestChannels = .{ .channels = &.{ channel, channel }, .fail = error.Eof };
    var origin: TestOrigin = .{};
    try testing.expectError(error.Eof, reader.next_batch(&channels, &origin));
    channels.fail = null;
    origin.block = null;
    try testing.expectError(error.MissingOrigin, reader.next_batch(&channels, &origin));
    try testing.expect(reader.decompressed == null);
    origin.block = .{};
    var first = try reader.next_batch(&channels, &origin);
    first.deinit();
    reader.flush();
    try testing.expect(reader.decompressed == null);
    try testing.expectError(error.ChannelReaderEmpty, reader.next_batch(&channels, &origin));
}

test "channel reader: owned single copy outlives its source" {
    const txs = [_][]const u8{&.{ 0x02, 0x03 }};
    var owned = try OwnedBatch.from_single(testing.allocator, &test_single(9, &txs));
    defer owned.deinit();
    try testing.expect(owned.batch.single.transactions[0].ptr != txs[0].ptr);
    try testing.expectEqualSlices(u8, txs[0], owned.batch.single.transactions[0]);
}

fn random_single(prng: *Prng, storage: *[4][32]u8, txs: *[4][]const u8) SingleBatch {
    const count = prng.below(txs.len + 1);
    for (0..count) |i| {
        const length = prng.range(1, storage[i].len);
        prng.fill(storage[i][0..length]);
        txs[i] = storage[i][0..length];
    }
    var single = test_single(prng.int(u32), txs[0..count]);
    single.epoch_num = prng.int(u32);
    return single;
}

test "channel reader: seeded fuzz batch streams" {
    var prng = Prng.init(0x43524452);
    const rollup: RollupConfig = .{ .block_time = 2 };
    var storage: [4][32]u8 = undefined;
    var txs: [4][]const u8 = undefined;
    for (0..60) |_| {
        var builder: StreamBuilder = .{};
        defer builder.deinit();
        const count = prng.below(6);
        for (0..count) |_| {
            if (prng.chance(1, 6)) {
                var junk: [8]u8 = undefined;
                prng.fill(&junk);
                junk[0] = @intCast(prng.below(3));
                try builder.add_typed(&junk);
            } else {
                try builder.add_single(random_single(&prng, &storage, &txs));
            }
        }
        const channel = try builder.compressed();
        defer testing.allocator.free(channel);
        if (channel.len > 4 and prng.chance(1, 3)) channel[prng.range(2, channel.len - 1)] ^= 0x5a;
        var reader = ChannelReader.init(testing.allocator, &rollup);
        defer reader.deinit();
        var channels: TestChannels = .{ .channels = &.{channel} };
        var origin: TestOrigin = .{};
        var produced: u64 = 0;
        for (0..count + 2) |_| {
            var owned = reader.next_batch(&channels, &origin) catch |err| switch (err) {
                error.NotEnoughData, error.ChannelReaderEmpty => continue,
                else => return err,
            };
            owned.deinit();
            produced += 1;
        }
        try testing.expect(produced <= count);
        try testing.expect(reader.decompressed == null);
    }
}

fn check_decode(input: []const u8) !void {
    if (input.len == 0) return;
    const rollup: RollupConfig = .{ .block_time = 2 };
    const batch_type = std.enums.fromInt(protocol.batch.BatchType, input[0] & 1).?;
    const raw: batch_reader.RawBatch = .{ .batch_type = batch_type, .payload = input[1..] };
    var owned = try decode_batch(testing.allocator, &rollup, raw) orelse return;
    defer owned.deinit();
    switch (owned.batch) {
        .single => |single| try testing.expect(single.transactions.len <= input.len),
        .span => |span| try testing.expect(span.batches.len > 0),
    }
}

test "channel reader: seeded fuzz decode_batch" {
    var prng = Prng.init(0x44454342);
    var input: [256]u8 = undefined;
    var storage: [4][32]u8 = undefined;
    var txs: [4][]const u8 = undefined;
    for (0..1_000) |_| {
        var length = prng.range(1, input.len);
        if (prng.chance(1, 2)) {
            input[0] = 0;
            const encoded = random_single(&prng, &storage, &txs).encode(input[1..]);
            length = encoded.len + 1;
            if (prng.chance(1, 2)) input[prng.below(length)] = prng.int(u8);
        } else {
            prng.fill(input[0..length]);
        }
        try check_decode(input[0..length]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "channel reader: fuzz decode_batch" {
    try testing.fuzz({}, fuzz_decode, .{});
}

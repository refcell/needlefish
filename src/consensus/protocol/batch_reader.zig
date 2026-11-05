//! Reads batches out of a ready channel: decompresses the channel data, then yields each
//! RLP-string-wrapped batch as `batch_type ++ payload`.
//!
//! Compression is detected from the first byte: a zlib header (CM = 8 or 15 in the low
//! nibble) or the Fjord brotli version byte 0x01. Matching base/base, output is truncated at
//! `max_rlp_bytes_per_channel`, and a stream that fails midway keeps the bytes decoded so
//! far (only an error with no output at all fails the channel).
//! Mirrors base/base `crates/consensus/protocol/src/batch/reader.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;

const rlp = @import("../../common/rlp/root.zig");
const BatchType = @import("batch.zig").BatchType;

pub const zlib_deflate_method: u8 = 8;
pub const zlib_reserved_method: u8 = 15;
pub const channel_version_brotli: u8 = 1;

pub const DecompressError = error{
    EmptyData,
    UnsupportedCompression,
    ZlibFailed,
    BrotliFailed,
} || Allocator.Error;

pub const ReadError = rlp.Error || error{ EmptyBatch, InvalidBatchType };

/// Decompresses zlib `input`, keeping at most `limit` bytes. Caller owns the result.
pub fn decompress_zlib(allocator: Allocator, input: []const u8, limit: u64) DecompressError![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var reader: std.Io.Reader = .fixed(input);
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);
    var decompress: flate.Decompress = .init(&reader, .zlib, window);

    var failed = false;
    // Each successful iteration writes at least one byte, bounded by `limit`.
    while (output.written().len < limit) {
        const remaining: usize = @intCast(limit - output.written().len);
        _ = decompress.reader.stream(&output.writer, .limited(remaining)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.WriteFailed => return error.OutOfMemory,
            error.ReadFailed => {
                failed = true;
                break;
            },
        };
    }
    if (failed) {
        // Deliver bytes the decoder produced before the error.
        const pending = decompress.reader.buffered();
        const room: usize = @intCast(limit - output.written().len);
        const take = pending[0..@min(pending.len, room)];
        output.writer.writeAll(take) catch return error.OutOfMemory;
        if (output.written().len == 0) return error.ZlibFailed;
    }
    assert(output.written().len <= limit);
    return output.toOwnedSlice();
}

/// Channel data → decompressed RLP batch stream. Caller owns the result.
pub fn decompress_channel(
    allocator: Allocator,
    data: []const u8,
    limit: u64,
    brotli_supported: bool,
) DecompressError![]u8 {
    if (data.len == 0) return error.EmptyData;
    const method = data[0] & 0x0f;
    if (method == zlib_deflate_method or method == zlib_reserved_method) {
        return decompress_zlib(allocator, data, limit);
    }
    if (data[0] == channel_version_brotli and brotli_supported) {
        // Brotli decoding lands with `brotli.zig`; until then a brotli channel is dropped.
        return error.BrotliFailed;
    }
    return error.UnsupportedCompression;
}

pub const RawBatch = struct {
    batch_type: BatchType,
    /// The batch payload after the type byte, borrowed from the reader.
    payload: []const u8,
};

/// Iterates batches in a decompressed channel stream.
pub const BatchReader = struct {
    decompressed: []const u8,
    cursor: usize = 0,

    pub fn init(decompressed: []const u8) BatchReader {
        return .{ .decompressed = decompressed };
    }

    /// Returns the next raw batch, or null at the end of the stream. Any error ends the
    /// channel: the caller drops the remaining data.
    pub fn next(reader: *BatchReader) ReadError!?RawBatch {
        assert(reader.cursor <= reader.decompressed.len);
        if (reader.cursor == reader.decompressed.len) return null;
        var decoder = rlp.Decoder.init(reader.decompressed[reader.cursor..]);
        const data = try decoder.bytes();
        reader.cursor += decoder.position;
        if (data.len == 0) return error.EmptyBatch;
        const batch_type = std.enums.fromInt(BatchType, data[0]) orelse {
            return error.InvalidBatchType;
        };
        return .{ .batch_type = batch_type, .payload = data[1..] };
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

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

test "batch reader: zlib roundtrip, truncation, and batch iteration" {
    // Two batches: a singular-typed payload and a span-typed payload.
    const stream = [_]u8{ 0x83, 0x00, 0xaa, 0xbb, 0x82, 0x01, 0xcc };
    const compressed = try compress_zlib(testing.allocator, &stream);
    defer testing.allocator.free(compressed);

    const full = try decompress_channel(testing.allocator, compressed, 1000, false);
    defer testing.allocator.free(full);
    try testing.expectEqualSlices(u8, &stream, full);
    var reader = BatchReader.init(full);
    const first = (try reader.next()).?;
    try testing.expectEqual(BatchType.single, first.batch_type);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, first.payload);
    const second = (try reader.next()).?;
    try testing.expectEqual(BatchType.span, second.batch_type);
    try testing.expect((try reader.next()) == null);

    const truncated = try decompress_channel(testing.allocator, compressed, 5, false);
    defer testing.allocator.free(truncated);
    try testing.expectEqualSlices(u8, stream[0..5], truncated);
    var short_reader = BatchReader.init(truncated);
    _ = (try short_reader.next()).?;
    try testing.expectError(error.UnexpectedEnd, short_reader.next());
}

fn channel(data: []const u8, brotli_supported: bool) DecompressError![]u8 {
    return decompress_channel(testing.allocator, data, 1 << 20, brotli_supported);
}

test "batch reader: compression type detection" {
    try testing.expectError(error.EmptyData, decompress_channel(testing.allocator, "", 10, true));
    const brotli = [_]u8{ channel_version_brotli, 0xff };
    try testing.expectError(error.UnsupportedCompression, channel(&brotli, false));
    try testing.expectError(error.UnsupportedCompression, channel(&.{0x02}, true));
    try testing.expectError(error.ZlibFailed, channel(&.{ 0x78, 0x00, 0x00 }, false));
}

test "batch reader: corrupt tail keeps decoded prefix" {
    var prng = Prng.init(0x52454144);
    var plain: [4096]u8 = undefined;
    for (&plain, 0..) |*byte, i| byte.* = @truncate(i % 251);
    const compressed = try compress_zlib(testing.allocator, &plain);
    defer testing.allocator.free(compressed);
    for (0..200) |_| {
        const cut = prng.range(3, compressed.len - 1);
        const output = channel(compressed[0..cut], false) catch |err| {
            try testing.expect(err == error.ZlibFailed);
            continue;
        };
        defer testing.allocator.free(output);
        try testing.expectEqualSlices(u8, plain[0..output.len], output);
    }
}

fn check_channel(input: []const u8) !void {
    const output = decompress_channel(testing.allocator, input, 1 << 16, true) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    defer testing.allocator.free(output);
    try testing.expect(output.len <= 1 << 16);
    var reader = BatchReader.init(output);
    for (0..output.len + 1) |_| {
        const batch = reader.next() catch break orelse break;
        try testing.expect(batch.payload.len < output.len);
    }
}

test "batch reader: seeded fuzz" {
    var prng = Prng.init(0x46555a5a);
    var input: [512]u8 = undefined;
    for (0..1_000) |_| {
        const length = prng.range(1, input.len);
        prng.fill(input[0..length]);
        if (prng.chance(1, 2)) input[0] = 0x78;
        try check_channel(input[0..length]);
    }
}

fn fuzz_channel(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.slice(&input);
    try check_channel(input[0..length]);
}

test "batch reader: fuzz decompress" {
    try testing.fuzz({}, fuzz_channel, .{});
}

//! EIP-4844 blob codec used for batcher data availability.
//!
//! A blob holds 4096 field elements of 32 bytes. The top two bits of every field
//! element must be zero (so the value stays below the BLS modulus), which leaves 254
//! usable bits. The OP Stack/Base codec packs data in rounds of 4 field elements:
//! each element carries 31 whole bytes after its high byte, and the low 6 bits of the
//! four high bytes reassemble three more bytes. That is 127 data bytes per 128 blob
//! bytes. The first 4 bytes of the packed stream are a header: encoding version (0)
//! and a 24-bit big-endian payload length.

const std = @import("std");
pub const kzg = @import("kzg.zig");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const bytes_per_blob = 131_072;
pub const field_elements_per_blob = 4096;
pub const encoding_rounds = 1024;
pub const encoding_version: u8 = 0;

/// Packed stream bytes: 127 data bytes per round.
const stream_length = 127 * encoding_rounds;
const header_length = 4;

/// Maximum payload bytes in one blob: 130044.
pub const blob_data_length_max = stream_length - header_length;

comptime {
    assert(field_elements_per_blob * 32 == bytes_per_blob);
    assert(encoding_rounds * 4 == field_elements_per_blob);
    assert(blob_data_length_max == (4 * 31 + 3) * 1024 - 4);
    assert(blob_data_length_max < 1 << 24);
}

pub const Blob = [bytes_per_blob]u8;

pub const EncodeError = error{BlobDataTooLarge};

/// Encodes `data` into `blob`. Unused space is zeroed.
pub fn encode(data: []const u8, blob: *Blob) EncodeError!void {
    if (data.len > blob_data_length_max) return error.BlobDataTooLarge;
    blob.* = @splat(0);
    var header: [header_length]u8 = undefined;
    header[0] = encoding_version;
    std.mem.writeInt(u24, header[1..4], @intCast(data.len), .big);

    const used_rounds = std.math.divCeil(usize, header_length + data.len, 127) catch
        unreachable; // Divisor is a non-zero constant.
    assert(used_rounds >= 1 and used_rounds <= encoding_rounds);
    for (0..used_rounds) |round| {
        var chunk: [127]u8 = undefined;
        stream_chunk(&header, data, round, &chunk);
        encode_round(&chunk, blob[round * 128 ..][0..128]);
    }
}

/// Copies round `round` of the virtual stream `header ++ data ++ zeros` into `chunk`.
fn stream_chunk(
    header: *const [header_length]u8,
    data: []const u8,
    round: usize,
    chunk: *[127]u8,
) void {
    const start = round * 127;
    for (chunk, 0..) |*byte, i| {
        const position = start + i;
        byte.* = if (position < header_length)
            header[position]
        else if (position - header_length < data.len)
            data[position - header_length]
        else
            0;
    }
}

fn encode_round(chunk: *const [127]u8, out: *[128]u8) void {
    for (0..4) |element| {
        @memcpy(out[element * 32 + 1 ..][0..31], chunk[element * 32 ..][0..31]);
    }
    const x = chunk[31];
    const y = chunk[63];
    const z = chunk[95];
    out[0] = x & 0x3f;
    out[32] = ((x >> 6) << 4) | (y & 0x0f);
    out[64] = z & 0x3f;
    out[96] = (y >> 4) | ((z >> 6) << 4);
    for (0..4) |element| assert(out[element * 32] & 0xc0 == 0);
}

pub const DecodeError = error{
    BlobInvalidFieldElement,
    BlobInvalidEncodingVersion,
    BlobInvalidLength,
    BlobNonZeroPadding,
};

/// Decodes `blob` into `out` and returns the payload slice of `out`.
pub fn decode(blob: *const Blob, out: []u8) DecodeError![]u8 {
    assert(out.len >= blob_data_length_max);
    var chunk: [127]u8 = undefined;
    try decode_round(blob[0..128], &chunk);
    if (chunk[0] != encoding_version) return error.BlobInvalidEncodingVersion;
    const length: usize = std.mem.readInt(u24, chunk[1..4], .big);
    if (length > blob_data_length_max) return error.BlobInvalidLength;

    // Decode every round so padding validation covers the whole blob.
    var written: usize = 0;
    for (0..encoding_rounds) |round| {
        if (round > 0) try decode_round(blob[round * 128 ..][0..128], &chunk);
        const payload = if (round == 0) chunk[header_length..] else chunk[0..];
        for (payload) |byte| {
            if (written < length) {
                out[written] = byte;
            } else if (byte != 0) {
                return error.BlobNonZeroPadding;
            }
            written += 1;
        }
    }
    assert(written == blob_data_length_max);
    return out[0..length];
}

fn decode_round(in: *const [128]u8, chunk: *[127]u8) DecodeError!void {
    for (0..4) |element| {
        if (in[element * 32] & 0xc0 != 0) return error.BlobInvalidFieldElement;
        @memcpy(chunk[element * 32 ..][0..31], in[element * 32 + 1 ..][0..31]);
    }
    const e0 = in[0];
    const e1 = in[32];
    const e2 = in[64];
    const e3 = in[96];
    chunk[31] = e0 | ((e1 & 0x30) << 2);
    chunk[63] = (e1 & 0x0f) | ((e3 & 0x0f) << 4);
    chunk[95] = e2 | ((e3 & 0x30) << 2);
}

const testing = std.testing;

fn expect_roundtrip(data: []const u8) !void {
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    const out = try testing.allocator.alloc(u8, blob_data_length_max);
    defer testing.allocator.free(out);
    try encode(data, blob);
    try testing.expectEqualSlices(u8, data, try decode(blob, out));
}

test "blobs: round trip edge sizes" {
    const data = try testing.allocator.alloc(u8, blob_data_length_max);
    defer testing.allocator.free(data);
    for (data, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 7);
    const sizes = [_]usize{ 0, 1, 5, 27, 28, 123, 124, 127, 128, 4096, blob_data_length_max };
    for (sizes) |size| try expect_roundtrip(data[0..size]);
    @memset(data, 0xff);
    try expect_roundtrip(data);
}

test "blobs: header layout and errors" {
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    const out = try testing.allocator.alloc(u8, blob_data_length_max + 1);
    defer testing.allocator.free(out);
    try encode("hello world", blob);
    try testing.expectEqual(@as(u8, 0), blob[1]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 11 }, blob[2..5]);
    try testing.expectError(error.BlobDataTooLarge, encode(out, blob));

    blob[1] = 1;
    try testing.expectError(error.BlobInvalidEncodingVersion, decode(blob, out));
    blob[1] = 0;
    blob[32 * 7] = 0x40;
    try testing.expectError(error.BlobInvalidFieldElement, decode(blob, out));
    blob[32 * 7] = 0;
    blob[bytes_per_blob - 1] = 1;
    try testing.expectError(error.BlobNonZeroPadding, decode(blob, out));
    blob[bytes_per_blob - 1] = 0;
    blob[2] = 0xff;
    try testing.expectError(error.BlobInvalidLength, decode(blob, out));
}

test "blobs: seeded fuzz round trip and mutation" {
    var prng = Prng.init(0x626c6f62);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    const data = try testing.allocator.alloc(u8, 4096);
    defer testing.allocator.free(data);
    const out = try testing.allocator.alloc(u8, blob_data_length_max);
    defer testing.allocator.free(out);
    for (0..64) |_| {
        const size = prng.below(data.len + 1);
        prng.fill(data[0..size]);
        try encode(data[0..size], blob);
        try testing.expectEqualSlices(u8, data[0..size], try decode(blob, out));
        // A single mutated byte either fails to decode or decodes to something;
        // it must never crash.
        blob[prng.below(bytes_per_blob)] ^= @as(u8, 1) << @intCast(prng.below(8));
        _ = decode(blob, out) catch {};
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var blob: Blob = @splat(0);
    _ = smith.slice(blob[0..4096]);
    var out: [blob_data_length_max]u8 = undefined;
    const payload = decode(&blob, &out) catch return;
    var again: Blob = undefined;
    try encode(payload, &again);
    try testing.expectEqualSlices(u8, &blob, &again);
}

test "blobs: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_decode, .{});
}

test {
    std.testing.refAllDecls(@This());
}

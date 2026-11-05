//! EIP-4844 blob data encoding used by the OP Stack batcher.
//!
//! A blob is 4096 field elements of 32 bytes. Each element carries 31 full bytes plus 6
//! bits in its high byte (the top two bits stay zero so it is a valid BLS12-381 scalar).
//! Four elements pack 4 * 31 + 3 = 127 data bytes. The first element starts with the
//! encoding version (0) and a 24-bit big-endian data length.
//! Mirrors base/base `crates/consensus/derive/src/sources/blob_data.rs` (decode) and the
//! public op-node `Blob.FromData` algorithm (encode).

const std = @import("std");
const assert = std.debug.assert;

pub const bytes_per_blob: u32 = 131_072;
pub const encoding_version: u8 = 0;
pub const encoding_rounds: u32 = 1024;
/// Largest payload a blob can carry: 1024 rounds of 127 bytes, minus the 4-byte header.
pub const max_data_size: u32 = (4 * 31 + 3) * 1024 - 4;

pub const Blob = [bytes_per_blob]u8;

pub const DecodeError = error{ InvalidEncodingVersion, InvalidLength, InvalidFieldElement };

const Decoder = struct {
    blob: *const Blob,
    output: []u8,
    input_position: u32 = 32,
    output_position: u32 = 28,

    /// Copies 31 bytes of the next field element and returns its high byte.
    fn field_element(decoder: *Decoder) DecodeError!u8 {
        const input = decoder.input_position;
        const high = decoder.blob[input];
        if (high & 0b1100_0000 != 0) return error.InvalidFieldElement;
        const output = decoder.output_position;
        @memcpy(decoder.output[output..][0..31], decoder.blob[input + 1 ..][0..31]);
        decoder.output_position += 32;
        decoder.input_position += 32;
        return high;
    }

    /// Rebuilds the three bytes spread across the high bits of four field elements.
    fn reassemble(decoder: *Decoder, encoded: [4]u8) void {
        decoder.output_position -= 1;
        const position = decoder.output_position;
        const x = (encoded[0] & 0b0011_1111) | ((encoded[1] & 0b0011_0000) << 2);
        const y = (encoded[1] & 0b0000_1111) | ((encoded[3] & 0b0000_1111) << 4);
        const z = (encoded[2] & 0b0011_1111) | ((encoded[3] & 0b0011_0000) << 2);
        decoder.output[position - 32] = z;
        decoder.output[position - 64] = y;
        decoder.output[position - 96] = x;
    }
};

/// Decodes `blob` into the `output` scratch buffer, returning the payload slice.
pub fn decode(blob: *const Blob, output: *[max_data_size]u8) DecodeError![]u8 {
    if (blob[1] != encoding_version) return error.InvalidEncodingVersion;
    const length = std.mem.readInt(u24, blob[2..5], .big);
    if (length > max_data_size) return error.InvalidLength;
    @memset(output, 0);
    @memcpy(output[0..27], blob[5..32]);

    var decoder: Decoder = .{ .blob = blob, .output = output };
    var encoded: [4]u8 = .{ blob[0], 0, 0, 0 };
    for (encoded[1..]) |*byte| byte.* = try decoder.field_element();
    decoder.reassemble(encoded);
    var round: u32 = 1;
    while (round < encoding_rounds and decoder.output_position < length) : (round += 1) {
        for (&encoded) |*byte| byte.* = try decoder.field_element();
        decoder.reassemble(encoded);
    }
    for (output[length..]) |byte| if (byte != 0) return error.InvalidFieldElement;
    for (blob[decoder.input_position..]) |byte| if (byte != 0) return error.InvalidFieldElement;
    assert(decoder.input_position <= bytes_per_blob);
    return output[0..length];
}

const Encoder = struct {
    data: []const u8,
    blob: *Blob,
    read_offset: u32 = 0,
    write_offset: u32 = 0,
    buffer: [31]u8 = @splat(0),

    fn read1(encoder: *Encoder) u8 {
        if (encoder.read_offset >= encoder.data.len) return 0;
        defer encoder.read_offset += 1;
        return encoder.data[encoder.read_offset];
    }

    fn read31(encoder: *Encoder) void {
        @memset(&encoder.buffer, 0);
        if (encoder.read_offset >= encoder.data.len) return;
        const available = encoder.data[encoder.read_offset..];
        const count = @min(available.len, 31);
        @memcpy(encoder.buffer[0..count], available[0..count]);
        encoder.read_offset += @intCast(count);
    }

    fn write_element(encoder: *Encoder, high: u8) void {
        assert(high & 0b1100_0000 == 0);
        encoder.blob[encoder.write_offset] = high;
        @memcpy(encoder.blob[encoder.write_offset + 1 ..][0..31], &encoder.buffer);
        encoder.write_offset += 32;
    }
};

/// Encodes `data` (at most `max_data_size` bytes) into `blob`.
pub fn encode(data: []const u8, blob: *Blob) error{DataTooLarge}!void {
    if (data.len > max_data_size) return error.DataTooLarge;
    @memset(blob, 0);
    var encoder: Encoder = .{ .data = data, .blob = blob };
    var round: u32 = 0;
    while (round < encoding_rounds and encoder.read_offset < data.len) : (round += 1) {
        if (round == 0) {
            encoder.buffer = @splat(0);
            encoder.buffer[0] = encoding_version;
            std.mem.writeInt(u24, encoder.buffer[1..4], @intCast(data.len), .big);
            const count = @min(data.len, 27);
            @memcpy(encoder.buffer[4..][0..count], data[0..count]);
            encoder.read_offset = @intCast(count);
        } else {
            encoder.read31();
        }
        const x = encoder.read1();
        encoder.write_element(x & 0b0011_1111);
        encoder.read31();
        const y = encoder.read1();
        encoder.write_element((y & 0b0000_1111) | ((x & 0b1100_0000) >> 2));
        encoder.read31();
        const z = encoder.read1();
        encoder.write_element(z & 0b0011_1111);
        encoder.read31();
        encoder.write_element(((z & 0b1100_0000) >> 2) | ((y & 0b1111_0000) >> 4));
    }
    assert(encoder.read_offset >= data.len);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

var test_blob: Blob = undefined;
var test_output: [max_data_size]u8 = undefined;

fn roundtrip(data: []const u8) !void {
    try encode(data, &test_blob);
    const decoded = try decode(&test_blob, &test_output);
    try testing.expectEqualSlices(u8, data, decoded);
}

test "blob: roundtrip boundaries" {
    var data: [max_data_size]u8 = undefined;
    var prng = Prng.init(0x424c4f42);
    prng.fill(&data);
    try roundtrip("");
    try roundtrip("this is a test of blob encoding/decoding");
    for ([_]u32{ 1, 26, 27, 28, 126, 127, 128, 130_044, max_data_size - 1, max_data_size }) |n| {
        try roundtrip(data[0..n]);
    }
    try testing.expectError(error.DataTooLarge, encode(&(data ++ [_]u8{0}), &test_blob));
}

test "blob: decode rejects malformed blobs" {
    try encode("hello", &test_blob);
    test_blob[1] = 1;
    try testing.expectError(error.InvalidEncodingVersion, decode(&test_blob, &test_output));
    try encode("hello", &test_blob);
    test_blob[32] = 0b1000_0000;
    try testing.expectError(error.InvalidFieldElement, decode(&test_blob, &test_output));
    try encode("hello", &test_blob);
    test_blob[bytes_per_blob - 1] = 1; // Trailing data past the payload.
    try testing.expectError(error.InvalidFieldElement, decode(&test_blob, &test_output));
    try encode("hello", &test_blob);
    std.mem.writeInt(u24, test_blob[2..5], max_data_size + 1, .big);
    try testing.expectError(error.InvalidLength, decode(&test_blob, &test_output));
    try encode("hello", &test_blob);
    test_blob[10] = 0xff; // Payload byte beyond the declared length.
    try testing.expectError(error.InvalidFieldElement, decode(&test_blob, &test_output));
}

test "blob: seeded fuzz roundtrip and mutation" {
    var prng = Prng.init(0x46555a42);
    var data: [4096]u8 = undefined;
    for (0..200) |_| {
        const length = prng.below(data.len);
        prng.fill(data[0..length]);
        try roundtrip(data[0..length]);
        // Mutations either fail cleanly or decode to some bounded payload.
        test_blob[prng.below(4096)] = prng.int(u8);
        const decoded = decode(&test_blob, &test_output) catch continue;
        try testing.expect(decoded.len <= max_data_size);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    @memset(&test_blob, 0);
    _ = smith.slice(test_blob[0..8192]);
    const decoded = decode(&test_blob, &test_output) catch return;
    try testing.expect(decoded.len <= max_data_size);
}

test "blob: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

//! Snappy block format (no framing), as used by OP Stack gossip payloads and libp2p
//! req/resp. Written from the public format description:
//!
//!   preamble: uncompressed length as a little-endian base-128 varint (at most 32 bits)
//!   elements: a tag byte whose low two bits select the element type
//!     00 literal: length-1 in the upper six bits; 60..63 mean 1..4 extra length bytes
//!     01 copy, 1-byte offset: length 4..11 in bits 2..4, offset bits 8..10 in bits 5..7
//!     10 copy, 2-byte offset: length 1..64 in the upper six bits, offset u16 LE
//!     11 copy, 4-byte offset: length 1..64 in the upper six bits, offset u32 LE
//!
//! The decoder writes into a caller buffer and never trusts the preamble beyond the
//! caller's `decoded_size_max` (OP Stack caps gossip at 10 MiB). Copies with offset
//! zero or reaching before the start of the output are corrupt, and the decoded size
//! must match the preamble exactly.
//!
//! The compressor follows the reference design: 64 KiB blocks, a fixed hash table of
//! u16 positions owned by `Compressor` (reset per block, so no allocation), greedy
//! matching with a skip heuristic for incompressible input.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The input ended inside the preamble or an element.
    Truncated,
    /// The preamble varint does not fit in 32 bits.
    HeaderOverflow,
    /// The preamble declares more than the caller's `decoded_size_max`.
    TooLarge,
    /// The preamble declares more than the output buffer holds.
    OutputTooSmall,
    /// A copy element has offset zero.
    OffsetZero,
    /// A copy element reaches before the start of the output.
    OffsetOutOfRange,
    /// An element would write past the declared decoded length.
    LengthOverflow,
    /// The input ended before the declared decoded length was produced.
    LengthMismatch,
};

/// OP Stack gossip cap on decoded payloads (base/base `MAX_GOSSIP_SIZE`).
pub const gossip_size_max: u32 = 10 * (1 << 20);

/// Longest preamble: a 32-bit varint.
pub const header_length_max = 5;

/// Compression block size: copies never cross a block, so offsets fit in u16.
pub const block_size: u32 = 1 << 16;

const table_bits = 14;
const table_size: u32 = 1 << table_bits;

/// Blocks shorter than this are emitted as a single literal.
const block_size_min_compressible: u32 = 17;

pub const Header = struct {
    /// Declared decoded length in bytes.
    decoded_length: u32,
    /// Preamble size in bytes, `1..header_length_max`.
    header_length: u8,
};

/// Upper bound on `compress` output for `n` input bytes (matches the reference bound).
pub fn max_compressed_length(n: u64) u64 {
    const bound = 32 + n + n / 6;
    assert(bound > n);
    assert(bound >= 32);
    return bound;
}

/// Reads the preamble. Accepts non-minimal varints like the reference decoders.
pub fn decode_header(input: []const u8) Error!Header {
    var value: u64 = 0;
    var index: usize = 0;
    while (index < header_length_max) : (index += 1) {
        if (index >= input.len) return error.Truncated;
        const byte = input[index];
        value |= @as(u64, byte & 0x7f) << @intCast(7 * index);
        if (byte & 0x80 == 0) {
            if (value > std.math.maxInt(u32)) return error.HeaderOverflow;
            assert(index < header_length_max);
            return .{ .decoded_length = @intCast(value), .header_length = @intCast(index + 1) };
        }
    }
    assert(index == header_length_max);
    return error.HeaderOverflow;
}

/// Decodes `input` into the front of `output`, returning the decoded prefix.
pub fn decompress(input: []const u8, output: []u8, decoded_size_max: u32) Error![]u8 {
    const header = try decode_header(input);
    if (header.decoded_length > decoded_size_max) return error.TooLarge;
    if (header.decoded_length > output.len) return error.OutputTooSmall;
    const target = output[0..header.decoded_length];

    var position: usize = header.header_length;
    var written: usize = 0;
    // Every element consumes at least one input byte.
    var iterations: usize = 0;
    while (position < input.len) : (iterations += 1) {
        assert(iterations < input.len);
        const tag = input[position];
        position += 1;
        if (tag & 0x03 == 0) {
            position = try decode_literal(input, position, tag, target, &written);
        } else {
            position = try decode_copy(input, position, tag, target, &written);
        }
        assert(position <= input.len);
        assert(written <= target.len);
    }
    if (written != target.len) return error.LengthMismatch;
    return target;
}

fn decode_literal(
    input: []const u8,
    position_start: usize,
    tag: u8,
    target: []u8,
    written: *usize,
) Error!usize {
    assert(tag & 0x03 == 0);
    assert(position_start <= input.len);
    var position = position_start;
    var length: u64 = tag >> 2;
    if (length >= 60) {
        const extra: usize = @intCast(length - 59);
        if (input.len - position < extra) return error.Truncated;
        length = 0;
        for (0..extra) |index| length |= @as(u64, input[position + index]) << @intCast(8 * index);
        position += extra;
    }
    length += 1;
    if (input.len - position < length) return error.Truncated;
    if (target.len - written.* < length) return error.LengthOverflow;
    const count: usize = @intCast(length);
    @memcpy(target[written.*..][0..count], input[position..][0..count]);
    written.* += count;
    return position + count;
}

fn decode_copy(
    input: []const u8,
    position_start: usize,
    tag: u8,
    target: []u8,
    written: *usize,
) Error!usize {
    assert(tag & 0x03 != 0);
    assert(position_start <= input.len);
    var position = position_start;
    var length: usize = undefined;
    var offset: usize = undefined;
    switch (tag & 0x03) {
        1 => {
            if (input.len - position < 1) return error.Truncated;
            length = 4 + ((tag >> 2) & 0x07);
            offset = (@as(usize, tag >> 5) << 8) | input[position];
            position += 1;
        },
        2 => {
            if (input.len - position < 2) return error.Truncated;
            length = 1 + @as(usize, tag >> 2);
            offset = std.mem.readInt(u16, input[position..][0..2], .little);
            position += 2;
        },
        3 => {
            if (input.len - position < 4) return error.Truncated;
            length = 1 + @as(usize, tag >> 2);
            offset = std.mem.readInt(u32, input[position..][0..4], .little);
            position += 4;
        },
        else => unreachable, // Literal tags are handled by `decode_literal`.
    }
    if (offset == 0) return error.OffsetZero;
    if (offset > written.*) return error.OffsetOutOfRange;
    if (target.len - written.* < length) return error.LengthOverflow;
    // Forward byte copy: overlapping copies (offset < length) repeat the pattern.
    const source = written.* - offset;
    for (0..length) |index| target[written.* + index] = target[source + index];
    written.* += length;
    return position;
}

/// Snappy compressor. Owns its hash table so compression never allocates; keep one
/// per thread (the table is 32 KiB).
pub const Compressor = struct {
    table: [table_size]u16 = undefined,

    /// Compresses `input` into the front of `output`, returning the written prefix.
    /// `output.len` must be at least `max_compressed_length(input.len)`.
    pub fn compress(compressor: *Compressor, input: []const u8, output: []u8) []u8 {
        assert(input.len <= std.math.maxInt(u32));
        assert(output.len >= max_compressed_length(input.len));
        var written: usize = encode_header(output, @intCast(input.len));
        var position: usize = 0;
        while (position < input.len) {
            const end = @min(input.len, position + block_size);
            written += compressor.compress_block(input[position..end], output[written..]);
            position = end;
        }
        assert(position == input.len);
        assert(written <= max_compressed_length(input.len));
        return output[0..written];
    }

    fn compress_block(compressor: *Compressor, block: []const u8, output: []u8) usize {
        assert(block.len > 0);
        assert(block.len <= block_size);
        if (block.len < block_size_min_compressible) return emit_literal(output, block);
        @memset(&compressor.table, 0);

        var written: usize = 0;
        var emit_next: usize = 0;
        var position: usize = 1;
        const position_limit = block.len - 4;
        while (position <= position_limit) {
            const value = load32(block, position);
            const slot = hash(value);
            const candidate: usize = compressor.table[slot];
            compressor.table[slot] = @intCast(position);
            if (candidate >= position or load32(block, candidate) != value) {
                position += 1 + ((position - emit_next) >> 5);
                continue;
            }
            if (emit_next < position) {
                written += emit_literal(output[written..], block[emit_next..position]);
            }
            var length: usize = 4;
            while (position + length < block.len and
                block[candidate + length] == block[position + length]) length += 1;
            written += emit_copy(output[written..], position - candidate, length);
            position += length;
            emit_next = position;
        }
        if (emit_next < block.len) written += emit_literal(output[written..], block[emit_next..]);
        assert(written <= max_compressed_length(block.len));
        return written;
    }
};

fn load32(bytes: []const u8, position: usize) u32 {
    assert(position + 4 <= bytes.len);
    return std.mem.readInt(u32, bytes[position..][0..4], .little);
}

fn hash(value: u32) u32 {
    const slot = (value *% 0x1e35a7bd) >> (32 - table_bits);
    assert(slot < table_size);
    return slot;
}

fn encode_header(output: []u8, length: u32) usize {
    var remaining = length;
    var index: usize = 0;
    while (remaining >= 0x80) : (index += 1) {
        output[index] = @as(u8, @truncate(remaining)) | 0x80;
        remaining >>= 7;
    }
    output[index] = @intCast(remaining);
    assert(index < header_length_max);
    return index + 1;
}

/// Emits `literal` (non-empty), returning bytes written.
fn emit_literal(output: []u8, literal: []const u8) usize {
    assert(literal.len > 0);
    assert(literal.len <= std.math.maxInt(u32));
    const n: u32 = @intCast(literal.len - 1);
    var header: usize = 1;
    if (n < 60) {
        output[0] = @intCast(n << 2);
    } else {
        const extra: u8 = if (n < 1 << 8) 1 else if (n < 1 << 16) 2 else if (n < 1 << 24) 3 else 4;
        output[0] = (59 + extra) << 2;
        for (0..extra) |index| output[1 + index] = @truncate(n >> @intCast(8 * index));
        header += extra;
    }
    @memcpy(output[header..][0..literal.len], literal);
    return header + literal.len;
}

/// Emits a copy of `length` (at least 4) bytes at `offset` (within a block).
fn emit_copy(output: []u8, offset: usize, length_total: usize) usize {
    assert(offset > 0 and offset < block_size);
    assert(length_total >= 4);
    var length = length_total;
    var written: usize = 0;
    // Each 2-byte-offset copy carries at most 64 bytes; leave at least 4 for the tail.
    while (length >= 68) : (length -= 64) written += emit_copy2(output[written..], offset, 64);
    if (length > 64) {
        written += emit_copy2(output[written..], offset, 60);
        length -= 60;
    }
    assert(length >= 4 and length <= 64);
    if (length >= 12 or offset >= 2048) {
        return written + emit_copy2(output[written..], offset, length);
    }
    output[written] = @intCast(((offset >> 8) << 5) | ((length - 4) << 2) | 0x01);
    output[written + 1] = @truncate(offset);
    return written + 2;
}

fn emit_copy2(output: []u8, offset: usize, length: usize) usize {
    assert(length >= 1 and length <= 64);
    assert(offset > 0 and offset <= std.math.maxInt(u16));
    output[0] = @intCast(((length - 1) << 2) | 0x02);
    std.mem.writeInt(u16, output[1..3], @intCast(offset), .little);
    return 3;
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

fn expect_decode(expected: []const u8, input: []const u8) !void {
    var buffer: [256]u8 = undefined;
    const decoded = try decompress(input, &buffer, buffer.len);
    try std.testing.expectEqualSlices(u8, expected, decoded);
}

test "snappy: golden decode vectors" {
    try expect_decode("", "\x00");
    try expect_decode("\xff\xff\xff", "\x03\x08\xff\xff\xff");
    try expect_decode("hello", "\x05\x10hello");
    // Literal with a one-byte extended length (60 => length-1 in the next byte).
    const run: [61]u8 = @splat('a');
    try expect_decode(&run, "\x3d\xf0\x3c" ++ run);
    // Copy-1: "ab" then copy length 8 at offset 2.
    try expect_decode("ababababab", "\x0a\x04ab\x11\x02");
    // Copy-2: "abcd" then copy length 4 at offset 4.
    try expect_decode("abcdabcd", "\x08\x0cabcd\x0e\x04\x00");
    // Copy-4: "abcd" then copy length 4 at offset 4.
    try expect_decode("abcdabcd", "\x08\x0cabcd\x0f\x04\x00\x00\x00");
    // Overlapping copy-1 with offset 1 repeats a single byte.
    try expect_decode("zzzzzzzzzzzz", "\x0c\x00z\x1d\x01");
    // Non-minimal preamble is accepted (reference decoders use a plain uvarint).
    try expect_decode("x", "\x81\x00\x00x");
}

test "snappy: rejects corrupt input" {
    var buffer: [64]u8 = undefined;
    const t = std.testing;
    try t.expectError(error.Truncated, decompress("", &buffer, 64));
    try t.expectError(error.Truncated, decompress("\x80", &buffer, 64));
    try t.expectError(error.HeaderOverflow, decompress("\xff\xff\xff\xff\x10", &buffer, 64));
    try t.expectError(error.HeaderOverflow, decompress("\x80\x80\x80\x80\x80\x00", &buffer, 64));
    try t.expectError(error.TooLarge, decompress("\x41", &buffer, 64));
    try t.expectError(error.OutputTooSmall, decompress("\x30", buffer[0..32], 64));
    try t.expectError(error.OffsetZero, decompress("\x06\x0cabcd\x15\x00", &buffer, 64));
    try t.expectError(error.OffsetOutOfRange, decompress("\x06\x0cabcd\x15\x05", &buffer, 64));
    try t.expectError(error.LengthOverflow, decompress("\x03\x0cabcd", &buffer, 64));
    try t.expectError(error.LengthMismatch, decompress("\x05\x0cabcd", &buffer, 64));
    try t.expectError(error.Truncated, decompress("\x05\x10hell", &buffer, 64));
    try t.expectError(error.Truncated, decompress("\x08\x0cabcd\x0e\x04", &buffer, 64));
    try t.expectError(error.Truncated, decompress("\x08\x0cabcd\x0f\x04\x00", &buffer, 64));
    try t.expectError(error.Truncated, decompress("\x08\xf4\x07", &buffer, 64));
    try t.expectError(error.LengthOverflow, decompress("\x04\x04ab\x11\x02", &buffer, 64));
}

test "snappy: golden compress of short input is a literal" {
    var compressor: Compressor = .{};
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "\x00", compressor.compress("", &buffer));
    try std.testing.expectEqualSlices(u8, "\x05\x10hello", compressor.compress("hello", &buffer));
}

test "snappy: compress shrinks repetitive input" {
    var compressor: Compressor = .{};
    const input: [100_000]u8 = @splat('a');
    var compressed: [max_compressed_length(input.len)]u8 = undefined;
    var decoded: [input.len]u8 = undefined;
    const encoded = compressor.compress(&input, &compressed);
    try std.testing.expect(encoded.len < 5000);
    const output = try decompress(encoded, &decoded, gossip_size_max);
    try std.testing.expectEqualSlices(u8, &input, output);
}

fn round_trip(compressor: *Compressor, input: []const u8, scratch: []u8, out: []u8) !void {
    const encoded = compressor.compress(input, scratch);
    try std.testing.expectEqual(input.len, (try decode_header(encoded)).decoded_length);
    const decoded = try decompress(encoded, out, gossip_size_max);
    try std.testing.expectEqualSlices(u8, input, decoded);
}

test "snappy: seeded round trip of random and repetitive data" {
    var prng = Prng.init(0x736e_6170);
    var compressor: Compressor = .{};
    const size_max = 3 * block_size + 77;
    const input = try std.testing.allocator.alloc(u8, size_max);
    defer std.testing.allocator.free(input);
    const scratch = try std.testing.allocator.alloc(u8, max_compressed_length(size_max));
    defer std.testing.allocator.free(scratch);
    const out = try std.testing.allocator.alloc(u8, size_max);
    defer std.testing.allocator.free(out);
    for (0..48) |iteration| {
        const length: usize = @intCast(prng.range(0, size_max));
        const data = input[0..length];
        switch (iteration % 3) {
            0 => prng.fill(data),
            1 => for (data) |*byte| {
                byte.* = @intCast(prng.below(4));
            },
            else => {
                // Repeated random phrases with occasional noise.
                const phrase_length: usize = @intCast(prng.range(1, 300));
                var phrase: [300]u8 = undefined;
                prng.fill(phrase[0..phrase_length]);
                for (data, 0..) |*byte, index| byte.* = phrase[index % phrase_length];
                if (length > 0) data[@intCast(prng.below(length))] ^= 0x5a;
            },
        }
        try round_trip(&compressor, data, scratch, out);
    }
}

fn fuzz_decompress(_: void, input: []const u8) anyerror!void {
    var first: [fuzz.input_size_limit * 2]u8 = undefined;
    var second: [fuzz.input_size_limit * 2]u8 = undefined;
    const size_max: u32 = fuzz.input_size_limit * 2;
    const result = decompress(input, &first, size_max);
    const again = decompress(input, &second, size_max);
    const decoded = result catch |err| {
        try std.testing.expectError(err, again);
        return;
    };
    try std.testing.expectEqualSlices(u8, decoded, try again);
    try std.testing.expectEqual(decoded.len, (try decode_header(input)).decoded_length);
    // Anything accepted must also survive our own compressor.
    var compressor: Compressor = .{};
    var scratch: [max_compressed_length(fuzz.input_size_limit * 2)]u8 = undefined;
    try round_trip(&compressor, decoded, &scratch, &second);
}

test "snappy: fuzz decompress" {
    try fuzz.run_bytes({}, fuzz_decompress, .{
        .corpus = &.{
            "\x0a\x04ab\x11\x02",
            "\x0c\x00z\x1d\x01",
            "\x08\x0cabcd\x0f\x04\x00\x00\x00",
        },
    });
}

fn fuzz_round_trip(_: void, input: []const u8) anyerror!void {
    var compressor: Compressor = .{};
    var scratch: [max_compressed_length(fuzz.input_size_limit)]u8 = undefined;
    var out: [fuzz.input_size_limit]u8 = undefined;
    try round_trip(&compressor, input, &scratch, &out);
}

test "snappy: fuzz compress round trip" {
    try fuzz.run_bytes({}, fuzz_round_trip, .{ .input_size_max = fuzz.input_size_limit });
}

//! Channel compression for the batcher.
//!
//! A channel is the concatenation of RLP-encoded batches, compressed. Derivation picks
//! the decompressor from the first byte (OP Stack spec, Fjord):
//!   - low nibble 8 (0x78, 0x08, ...): zlib (RFC 1950)
//!   - 0x01: brotli (RFC 7932); the version byte is followed by the brotli stream
//!
//! zlib uses `std.compress.flate`. The brotli encoder is our own and currently emits
//! uncompressed meta-blocks only: a valid stream that every decoder accepts, used to
//! exercise the brotli path end to end until the real compressor lands.

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const Prng = @import("../../testing/prng.zig").Prng;

pub const Algorithm = enum { zlib, brotli };

/// Channel version byte that selects brotli.
pub const brotli_channel_version: u8 = 0x01;

pub const Error = error{OutputTooSmall};

/// Zlib compressor with its history window held inline so callers can allocate it
/// once at startup. The struct is ~64 KiB: keep it off the stack in long-lived code.
pub const Zlib = struct {
    window: [flate.max_window_len]u8 = undefined,
    level: flate.Compress.Options = .default,

    /// Compresses `input` as one complete zlib stream into `out`.
    pub fn compress(zlib: *Zlib, input: []const u8, out: []u8) Error![]u8 {
        assert(out.len > 8);
        var writer: std.Io.Writer = .fixed(out);
        var compressor = flate.Compress.init(&writer, &zlib.window, .zlib, zlib.level) catch
            return error.OutputTooSmall;
        compressor.writer.writeAll(input) catch return error.OutputTooSmall;
        compressor.finish() catch return error.OutputTooSmall;
        const written = writer.buffered();
        // CMF byte: deflate method (8) in the low nibble, as derivation expects.
        assert(written.len >= 6 and written[0] & 0x0f == 8);
        return written;
    }
};

/// Worst-case compressed size for `input_length` bytes (stored blocks plus framing).
pub fn zlib_bound(input_length: u64) u64 {
    // Stored deflate blocks carry at most 65535 bytes with 5 bytes of header each;
    // add the zlib header/footer and slack for the final empty block.
    return input_length + (input_length / 16_383 + 1) * 5 + 6 + 16;
}

pub const DecompressError = error{ Corrupt, OutputTooSmall };

/// Decompresses one zlib stream. `window` must be `flate.max_window_len` bytes.
/// Used by tests and tooling; derivation has its own bounded reader.
pub fn zlib_decompress(input: []const u8, window: []u8, out: []u8) DecompressError![]u8 {
    assert(window.len >= flate.max_window_len);
    var reader: std.Io.Reader = .fixed(input);
    var decompressor = flate.Decompress.init(&reader, .zlib, window);
    var writer: std.Io.Writer = .fixed(out);
    _ = decompressor.reader.streamRemaining(&writer) catch |err| switch (err) {
        error.WriteFailed => return error.OutputTooSmall,
        error.ReadFailed => return error.Corrupt,
    };
    return writer.buffered();
}

/// Little-endian bit writer over a fixed buffer, as brotli requires.
const BitWriter = struct {
    out: []u8,
    position_bits: u64 = 0,

    fn write(bits: *BitWriter, value: u32, count: u5) Error!void {
        assert(count == 0 or value >> count == 0);
        for (0..count) |i| {
            const byte_index = bits.position_bits / 8;
            if (byte_index >= bits.out.len) return error.OutputTooSmall;
            const bit_index: u3 = @intCast(bits.position_bits % 8);
            if (bit_index == 0) bits.out[byte_index] = 0;
            const bit: u8 = @intCast((value >> @intCast(i)) & 1);
            bits.out[byte_index] |= bit << bit_index;
            bits.position_bits += 1;
        }
    }

    fn align_byte(bits: *BitWriter) void {
        bits.position_bits = std.mem.alignForward(u64, bits.position_bits, 8);
    }

    fn byte_length(bits: *const BitWriter) u64 {
        return std.math.divCeil(u64, bits.position_bits, 8) catch unreachable; // 8 > 0.
    }
};

/// Largest uncompressed meta-block we emit: 4 nibbles of MLEN-1.
const brotli_meta_block_length_max = 1 << 16;

/// Worst-case brotli channel size (version byte + stored meta-blocks).
pub fn brotli_bound(input_length: u64) u64 {
    const blocks = input_length / brotli_meta_block_length_max + 1;
    return 1 + 1 + blocks * 4 + input_length + 1;
}

/// Encodes `input` as a brotli channel: version byte, then a brotli stream with
/// window bits 16 and uncompressed meta-blocks.
pub fn brotli_compress_stored(input: []const u8, out: []u8) Error![]u8 {
    if (out.len < 2) return error.OutputTooSmall;
    out[0] = brotli_channel_version;
    var bits: BitWriter = .{ .out = out[1..] };
    try bits.write(0, 1); // WBITS = 16.
    var offset: usize = 0;
    // Each iteration consumes up to brotli_meta_block_length_max bytes.
    while (offset < input.len) {
        const length = @min(input.len - offset, brotli_meta_block_length_max);
        assert(length > 0);
        try bits.write(0, 1); // ISLAST = 0.
        try bits.write(0, 2); // MNIBBLES = 4.
        try bits.write(@intCast(length - 1), 16); // MLEN - 1.
        try bits.write(1, 1); // ISUNCOMPRESSED = 1.
        bits.align_byte();
        const start = bits.position_bits / 8;
        if (start + length > bits.out.len) return error.OutputTooSmall;
        @memcpy(bits.out[start..][0..length], input[offset..][0..length]);
        bits.position_bits += @as(u64, length) * 8;
        offset += length;
    }
    try bits.write(1, 1); // ISLAST = 1.
    try bits.write(1, 1); // ISLASTEMPTY = 1.
    const total = 1 + bits.byte_length();
    assert(total <= brotli_bound(input.len));
    return out[0..total];
}

const testing = std.testing;

test "comp: zlib round trip" {
    const zlib = try testing.allocator.create(Zlib);
    defer testing.allocator.destroy(zlib);
    zlib.* = .{};
    const window = try testing.allocator.alloc(u8, flate.max_window_len);
    defer testing.allocator.free(window);
    var input: [10_000]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i % 251);
    var compressed: [12_000]u8 = undefined;
    const encoded = try zlib.compress(&input, &compressed);
    try testing.expect(encoded.len < input.len / 4);
    var decoded: [10_000]u8 = undefined;
    try testing.expectEqualSlices(u8, &input, try zlib_decompress(encoded, window, &decoded));
    try testing.expectError(error.OutputTooSmall, zlib.compress(&input, compressed[0..16]));
}

test "comp: brotli stored framing" {
    var out: [64]u8 = undefined;
    const empty = try brotli_compress_stored("", &out);
    // Version, then bits: WBITS 0, ISLAST 1, ISLASTEMPTY 1 -> 0b110.
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x06 }, empty);
    const hello = try brotli_compress_stored("hello", &out);
    try testing.expectEqual(@as(usize, 1 + 3 + 5 + 1), hello.len);
    try testing.expectEqualStrings("hello", hello[4..9]);
    try testing.expectError(error.OutputTooSmall, brotli_compress_stored("hello", out[0..6]));
}

/// Minimal reader for the stored-only streams we emit, used to check framing.
fn brotli_stored_decode(channel: []const u8, out: []u8) ![]u8 {
    if (channel.len < 2 or channel[0] != brotli_channel_version) return error.Corrupt;
    const stream = channel[1..];
    var position_bits: u64 = 1;
    var written: usize = 0;
    while (true) {
        const read = struct {
            fn bits(s: []const u8, pos: *u64, count: u5) !u32 {
                var value: u32 = 0;
                for (0..count) |i| {
                    if (pos.* / 8 >= s.len) return error.Corrupt;
                    const bit = (s[pos.* / 8] >> @intCast(pos.* % 8)) & 1;
                    value |= @as(u32, bit) << @intCast(i);
                    pos.* += 1;
                }
                return value;
            }
        };
        if (try read.bits(stream, &position_bits, 1) == 1) {
            if (try read.bits(stream, &position_bits, 1) != 1) return error.Corrupt;
            return out[0..written];
        }
        if (try read.bits(stream, &position_bits, 2) != 0) return error.Corrupt;
        const length = try read.bits(stream, &position_bits, 16) + 1;
        if (try read.bits(stream, &position_bits, 1) != 1) return error.Corrupt;
        position_bits = std.mem.alignForward(u64, position_bits, 8);
        const start = position_bits / 8;
        if (start + length > stream.len) return error.Corrupt;
        @memcpy(out[written..][0..length], stream[start..][0..length]);
        written += length;
        position_bits += @as(u64, length) * 8;
    }
}

test "comp: seeded fuzz brotli stored and zlib" {
    var prng = Prng.init(0x636f6d70);
    const zlib = try testing.allocator.create(Zlib);
    defer testing.allocator.destroy(zlib);
    zlib.* = .{ .level = .fastest };
    const window = try testing.allocator.alloc(u8, flate.max_window_len);
    defer testing.allocator.free(window);
    const size_max = 3 * brotli_meta_block_length_max;
    const input = try testing.allocator.alloc(u8, size_max);
    defer testing.allocator.free(input);
    const compressed = try testing.allocator.alloc(u8, zlib_bound(size_max));
    defer testing.allocator.free(compressed);
    const decoded = try testing.allocator.alloc(u8, size_max);
    defer testing.allocator.free(decoded);
    for (0..24) |_| {
        const size = prng.below(size_max + 1);
        // Mix compressible runs and noise.
        for (input[0..size]) |*byte| byte.* = if (prng.chance(1, 2)) 'a' else prng.int(u8);
        const b = try brotli_compress_stored(input[0..size], compressed);
        try testing.expect(b.len <= brotli_bound(size));
        try testing.expectEqualSlices(u8, input[0..size], try brotli_stored_decode(b, decoded));
        const z = try zlib.compress(input[0..size], compressed);
        try testing.expect(z.len <= zlib_bound(size));
        try testing.expectEqualSlices(u8, input[0..size], try zlib_decompress(z, window, decoded));
    }
}

fn fuzz_zlib(_: void, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const n = smith.slice(&input);
    var window: [flate.max_window_len]u8 = undefined;
    var out: [4096]u8 = undefined;
    // Arbitrary input must never crash the decompressor.
    _ = zlib_decompress(input[0..n], &window, &out) catch {};
    var zlib: Zlib = .{ .level = .fastest };
    var compressed: [4096]u8 = undefined;
    const z = try zlib.compress(input[0..n], &compressed);
    try testing.expectEqualSlices(u8, input[0..n], try zlib_decompress(z, &window, &out));
}

test "comp: fuzz zlib" {
    try testing.fuzz({}, fuzz_zlib, .{});
}

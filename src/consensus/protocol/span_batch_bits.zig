//! Span batch primitives: the error set, element limits, big-endian bitlists, and
//! unsigned varints, plus a length-counting byte writer shared by every encoder.
//! Mirrors base/base `crates/consensus/protocol/src/batch/{bits,errors,element}.rs`
//! and the `unsigned-varint` crate semantics used by base/base.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Maximum number of blocks, transactions in total, or transactions per block, and
/// the maximum byte size of one transaction's data in a span batch.
pub const max_span_batch_elements: u64 = 10_000_000;

/// Fail-fast bound on one EIP-8130 auth proof (base/base `Channel::MAX_RLP_BYTES`).
pub const max_auth_proof_bytes: u64 = 10_000_000;

/// base/base `SpanBatchError` with `SpanDecodingError` flattened in, plus
/// allocation failure and the needlefish-only limits documented on each tag.
pub const Error = error{
    TooBigSpanBatchSize,
    BitfieldTooLong,
    EmptySpanBatch,
    L1OriginBeforeSafeHead,
    MissingL1Origin,
    RelativeTimestamp,
    L1OriginNumber,
    ParentCheck,
    L1OriginCheck,
    BlockCount,
    BlockTxCounts,
    TxNonces,
    TypeSignatureLenMismatch,
    InvalidTransactionType,
    InvalidTransactionData,
    InvalidAuthData,
    InvalidTransactionSignature,
    /// EIP-8130 transactions decode and re-encode as raw columns, but rebuilding the
    /// signed transaction (or splitting one into columns) is not implemented yet.
    Eip8130Unsupported,
    /// A derived timestamp or epoch number left the u64 range (base/base wraps).
    ArithmeticOverflow,
} || Allocator.Error;

/// Bytes needed for `bit_length` bits, rounded up.
pub fn bits_buffer_length(bit_length: u64) usize {
    const length = bit_length / 8 + @intFromBool(bit_length % 8 != 0);
    assert(length * 8 >= bit_length);
    assert(length * 8 < bit_length + 8);
    return @intCast(length);
}

/// A standard span-batch bitlist: a big-endian integer, bit `i` is the `i`-th least
/// significant bit. The bytes either borrow the decoded input or live in an arena.
pub const Bits = struct {
    bytes: []const u8 = &.{},

    pub const empty: Bits = .{};

    /// Decodes a bitlist of at most `bit_length` bits from the front of `r`.
    /// Like base/base, input shorter than the bitlist is consumed entirely and
    /// zero-padded on the right; only the final bit-length check can fail.
    pub fn decode(arena: Allocator, r: *[]const u8, bit_length: u64) Error!Bits {
        const length = bits_buffer_length(bit_length);
        var bytes: []const u8 = undefined;
        if (r.len < length) {
            const padded = try arena.alloc(u8, length);
            @memset(padded, 0);
            @memcpy(padded[0..r.len], r.*);
            bytes = padded;
            r.* = r.*[r.len..];
        } else {
            bytes = r.*[0..length];
            r.* = r.*[length..];
        }
        const bits: Bits = .{ .bytes = bytes };
        assert(bits.bytes.len == length);
        if (bits.bit_len() > bit_length) return error.BitfieldTooLong;
        return bits;
    }

    /// Writes the bitlist left-padded to exactly `bits_buffer_length(bit_length)`.
    pub fn encode(bits: Bits, writer: *Writer, bit_length: u64) Error!void {
        if (bits.bit_len() > bit_length) return error.BitfieldTooLong;
        const length = bits_buffer_length(bit_length);
        const significant = bits.bytes[bits.bytes.len - bits_buffer_length(bits.bit_len()) ..];
        assert(significant.len <= length);
        writer.put_zeros(length - significant.len);
        writer.put(significant);
    }

    pub fn get_bit(bits: Bits, index: u64) ?u1 {
        const byte_index = index / 8;
        if (byte_index >= bits.bytes.len) return null;
        const byte = bits.bytes[bits.bytes.len - 1 - @as(usize, @intCast(byte_index))];
        const bit: u3 = @intCast(index % 8);
        return @intCast((byte >> bit) & 1);
    }

    /// Position of the most significant set bit plus one; zero when no bit is set.
    pub fn bit_len(bits: Bits) u64 {
        for (bits.bytes, 0..) |byte, i| {
            if (byte == 0) continue;
            const msb: u64 = 7 - @as(u64, @clz(byte));
            const lower_bytes: u64 = bits.bytes.len - i - 1;
            return msb + 1 + lower_bytes * 8;
        }
        return 0;
    }

    pub fn count_ones(bits: Bits) u64 {
        var total: u64 = 0;
        for (bits.bytes) |byte| total += @popCount(byte);
        assert(total <= bits.bytes.len * 8);
        return total;
    }

    /// Sets bit `index` of a mutable bitlist buffer that is already large enough.
    pub fn set_bit(bytes: []u8, index: u64, value: bool) void {
        const byte_index: usize = @intCast(index / 8);
        assert(byte_index < bytes.len);
        const bit: u3 = @intCast(index % 8);
        const byte = &bytes[bytes.len - 1 - byte_index];
        if (value) byte.* |= @as(u8, 1) << bit else byte.* &= ~(@as(u8, 1) << bit);
        assert(((byte.* >> bit) & 1 == 1) == value);
    }
};

/// Maximum encoded length of a u64 unsigned varint.
pub const uvarint_length_max = 10;

/// Decodes a u64 unsigned varint, exactly like `unsigned_varint::decode::u64`:
/// at most 10 bytes, a multi-byte varint may not end in a zero byte, and high bits of
/// the tenth byte are silently discarded. Null on insufficient, overflowing, or
/// non-minimal input.
pub fn read_uvarint(r: *[]const u8) ?u64 {
    var value: u64 = 0;
    const length = @min(r.len, uvarint_length_max);
    for (r.*[0..length], 0..) |byte, i| {
        const shift: u6 = @intCast(i * 7);
        value |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) {
            if (byte == 0 and i > 0) return null;
            r.* = r.*[i + 1 ..];
            return value;
        }
    }
    assert(length <= uvarint_length_max);
    return null;
}

pub fn uvarint_length(value: u64) usize {
    var length: usize = 1;
    var rest = value >> 7;
    while (rest != 0) : (rest >>= 7) length += 1;
    assert(length <= uvarint_length_max);
    return length;
}

/// Appends bytes to a fixed buffer, or only counts them when `buffer` is null, so a
/// single encode routine also computes the exact encoded length.
pub const Writer = struct {
    buffer: ?[]u8,
    position: usize = 0,

    pub fn counting() Writer {
        return .{ .buffer = null };
    }

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    pub fn put(writer: *Writer, data: []const u8) void {
        if (writer.buffer) |buffer| {
            assert(writer.position + data.len <= buffer.len);
            @memcpy(buffer[writer.position..][0..data.len], data);
        }
        writer.position += data.len;
    }

    pub fn put_zeros(writer: *Writer, count: usize) void {
        if (writer.buffer) |buffer| {
            assert(writer.position + count <= buffer.len);
            @memset(buffer[writer.position..][0..count], 0);
        }
        writer.position += count;
    }

    pub fn put_uvarint(writer: *Writer, value: u64) void {
        var scratch: [uvarint_length_max]u8 = undefined;
        var length: usize = 0;
        var rest = value;
        while (rest >= 0x80) : (rest >>= 7) {
            scratch[length] = @as(u8, @truncate(rest)) | 0x80;
            length += 1;
        }
        scratch[length] = @intCast(rest);
        length += 1;
        assert(length == uvarint_length(value));
        writer.put(scratch[0..length]);
    }

    pub fn written(writer: *const Writer) []u8 {
        const buffer = writer.buffer.?;
        assert(writer.position <= buffer.len);
        return buffer[0..writer.position];
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn bits_of(buffer: []u8, indices: []const u64) Bits {
    @memset(buffer, 0);
    for (indices) |index| Bits.set_bit(buffer, index, true);
    return .{ .bytes = buffer };
}

test "span bits: big endian zero extended" {
    var buffer: [2]u8 = undefined;
    const bits = bits_of(&buffer, &.{ 1, 6, 8, 15 });
    try testing.expectEqual(@as(u8, 0b1000_0001), buffer[0]);
    try testing.expectEqual(@as(u8, 0b0100_0010), buffer[1]);
    try testing.expectEqual(@as(u64, 16), bits.bit_len());
    try testing.expectEqual(@as(u64, 4), bits.count_ones());
}

test "span bits: static set and get" {
    var buffer: [3]u8 = undefined;
    const bits = bits_of(&buffer, &.{ 0, 1, 2, 4, 7, 17 });
    try testing.expectEqual(@as(?u1, 1), bits.get_bit(0));
    try testing.expectEqual(@as(?u1, 1), bits.get_bit(2));
    try testing.expectEqual(@as(?u1, 0), bits.get_bit(3));
    try testing.expectEqual(@as(?u1, 1), bits.get_bit(4));
    try testing.expectEqual(@as(?u1, 1), bits.get_bit(17));
    try testing.expectEqual(@as(?u1, null), bits.get_bit(32));
    Bits.set_bit(&buffer, 17, false);
    try testing.expectEqual(@as(u64, 8), bits.bit_len());
}

test "span bits: decode checks length and pads short input" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var input: []const u8 = &.{ 0x02, 0x02, 0xff };
    const bits = try Bits.decode(arena, &input, 10);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x02 }, bits.bytes);
    try testing.expectEqual(@as(usize, 1), input.len);
    var too_long: []const u8 = &.{ 0x04, 0x00 };
    try testing.expectError(error.BitfieldTooLong, Bits.decode(arena, &too_long, 10));
    var short: []const u8 = &.{0x01};
    const padded = try Bits.decode(arena, &short, 16);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, padded.bytes);
    try testing.expectEqual(@as(usize, 0), short.len);
}

test "span bits: seeded encode/decode roundtrip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var prng = Prng.init(0x42495453);
    var raw: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    for (0..2_000) |_| {
        const length = prng.below(raw.len + 1);
        prng.fill(raw[0..length]);
        var input: []const u8 = raw[0..length];
        const bits = try Bits.decode(arena_state.allocator(), &input, length * 8);
        var writer = Writer.init(&out);
        try bits.encode(&writer, length * 8);
        try testing.expectEqualSlices(u8, raw[0..length], writer.written());
        const extra = prng.below(16);
        var wide = Writer.counting();
        try bits.encode(&wide, length * 8 + extra);
        try testing.expectEqual(bits_buffer_length(length * 8 + extra), wide.position);
    }
}

test "span uvarint: unsigned-varint semantics" {
    var buffer: [uvarint_length_max]u8 = undefined;
    for ([_]u64{ 0, 1, 127, 128, 300, std.math.maxInt(u32), std.math.maxInt(u64) }) |value| {
        var writer = Writer.init(&buffer);
        writer.put_uvarint(value);
        var input: []const u8 = writer.written();
        try testing.expectEqual(@as(?u64, value), read_uvarint(&input));
        try testing.expectEqual(@as(usize, 0), input.len);
    }
    var non_minimal: []const u8 = &.{ 0x80, 0x00 };
    try testing.expectEqual(@as(?u64, null), read_uvarint(&non_minimal));
    var insufficient: []const u8 = &.{ 0xff, 0xff };
    try testing.expectEqual(@as(?u64, null), read_uvarint(&insufficient));
    var overflow: []const u8 = &(@as([10]u8, @splat(0xff)) ++ [_]u8{0x01});
    try testing.expectEqual(@as(?u64, null), read_uvarint(&overflow));
    // The tenth byte's high bits are dropped, as in the Rust crate.
    var truncated: []const u8 = &(@as([9]u8, @splat(0x80)) ++ [_]u8{0x03});
    try testing.expectEqual(@as(?u64, 1 << 63), read_uvarint(&truncated));
}

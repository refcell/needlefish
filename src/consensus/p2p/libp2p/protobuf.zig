//! Minimal protobuf wire-format reader and writer for the small libp2p messages
//! (`PublicKey`, `NoiseHandshakePayload`). Supports wire types varint (0), 64-bit (1),
//! length-delimited (2) and 32-bit (5); group wire types are rejected. Readers never copy:
//! length-delimited values are slices of the input.

const std = @import("std");
const assert = std.debug.assert;
const varint = @import("../peers/varint.zig");

pub const Error = error{InvalidProtobuf};

pub const WireType = enum(u3) {
    varint = 0,
    fixed64 = 1,
    bytes = 2,
    fixed32 = 5,
};

pub const Field = struct {
    number: u32,
    wire_type: WireType,
    /// Varint or fixed value; zero for `bytes`.
    value: u64,
    /// Payload for `bytes`; empty otherwise.
    bytes: []const u8,
};

pub const Reader = struct {
    input: []const u8,
    offset: usize = 0,

    pub fn init(input: []const u8) Reader {
        return .{ .input = input };
    }

    /// Next field, or null at the end of the input. Every call consumes >= 2 bytes.
    pub fn next(reader: *Reader) Error!?Field {
        assert(reader.offset <= reader.input.len);
        if (reader.offset == reader.input.len) return null;
        const key = try reader.read_varint();
        const number = key >> 3;
        if (number == 0 or number > std.math.maxInt(u29)) return error.InvalidProtobuf;
        const wire_type: WireType = switch (@as(u3, @truncate(key))) {
            0 => .varint,
            1 => .fixed64,
            2 => .bytes,
            5 => .fixed32,
            else => return error.InvalidProtobuf,
        };
        var field: Field = .{
            .number = @intCast(number),
            .wire_type = wire_type,
            .value = 0,
            .bytes = &.{},
        };
        switch (wire_type) {
            .varint => field.value = try reader.read_varint(),
            .fixed64 => field.value = std.mem.readInt(u64, try reader.take(8), .little),
            .fixed32 => field.value = std.mem.readInt(u32, try reader.take(4), .little),
            .bytes => {
                const length = try reader.read_varint();
                if (length > reader.input.len - reader.offset) return error.InvalidProtobuf;
                field.bytes = reader.input[reader.offset..][0..@intCast(length)];
                reader.offset += @intCast(length);
            },
        }
        assert(reader.offset <= reader.input.len);
        return field;
    }

    fn read_varint(reader: *Reader) Error!u64 {
        const decoded = varint.decode(reader.input[reader.offset..]) catch {
            return error.InvalidProtobuf;
        };
        reader.offset += decoded.length;
        assert(reader.offset <= reader.input.len);
        return decoded.value;
    }

    fn take(reader: *Reader, comptime length: usize) Error!*const [length]u8 {
        if (reader.input.len - reader.offset < length) return error.InvalidProtobuf;
        const result = reader.input[reader.offset..][0..length];
        reader.offset += length;
        return result;
    }
};

/// Appends fields to a caller-provided buffer.
pub const Writer = struct {
    output: []u8,
    length: usize = 0,

    pub fn init(output: []u8) Writer {
        return .{ .output = output };
    }

    pub fn write_varint_field(writer: *Writer, number: u32, value: u64) void {
        assert(number > 0);
        writer.write_varint((@as(u64, number) << 3) | @backingInt(WireType.varint));
        writer.write_varint(value);
    }

    pub fn write_bytes_field(writer: *Writer, number: u32, bytes: []const u8) void {
        assert(number > 0);
        writer.write_varint((@as(u64, number) << 3) | @backingInt(WireType.bytes));
        writer.write_varint(bytes.len);
        assert(writer.output.len - writer.length >= bytes.len);
        @memcpy(writer.output[writer.length..][0..bytes.len], bytes);
        writer.length += bytes.len;
    }

    pub fn written(writer: *const Writer) []const u8 {
        assert(writer.length <= writer.output.len);
        return writer.output[0..writer.length];
    }

    fn write_varint(writer: *Writer, value: u64) void {
        assert(writer.output.len - writer.length >= varint.encoded_length(value));
        const encoded = varint.encode(writer.output[writer.length..], value);
        writer.length += encoded.len;
    }
};

const fuzz = @import("../../../testing/fuzz.zig");

test "protobuf: write then read" {
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    writer.write_varint_field(1, 2);
    writer.write_bytes_field(2, "abc");
    writer.write_varint_field(300, 1 << 40);
    const expected = [_]u8{ 0x08, 0x02, 0x12, 0x03, 'a', 'b', 'c' };
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..7]);
    var reader = Reader.init(writer.written());
    const a = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 1), a.number);
    try std.testing.expectEqual(@as(u64, 2), a.value);
    const b = (try reader.next()).?;
    try std.testing.expectEqualStrings("abc", b.bytes);
    const c = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 300), c.number);
    try std.testing.expectEqual(@as(u64, 1 << 40), c.value);
    try std.testing.expectEqual(@as(?Field, null), try reader.next());
}

test "protobuf: rejects malformed" {
    var reader = Reader.init(&.{ 0x12, 0x05, 'a' });
    try std.testing.expectError(error.InvalidProtobuf, reader.next());
    reader = Reader.init(&.{ 0x0b, 0x00 });
    try std.testing.expectError(error.InvalidProtobuf, reader.next());
    reader = Reader.init(&.{ 0x00, 0x00 });
    try std.testing.expectError(error.InvalidProtobuf, reader.next());
    reader = Reader.init(&.{ 0x09, 0x00 });
    try std.testing.expectError(error.InvalidProtobuf, reader.next());
}

fn fuzz_reader(_: void, input: []const u8) anyerror!void {
    var reader = Reader.init(input);
    var fields: usize = 0;
    while (reader.next() catch return) |field| {
        fields += 1;
        try std.testing.expect(field.number > 0);
        try std.testing.expect(fields <= input.len);
    }
}

test "protobuf: fuzz reader" {
    try fuzz.run_bytes({}, fuzz_reader, .{ .input_size_max = 256 });
}

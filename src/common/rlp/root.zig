//! Recursive Length Prefix (RLP) serialization, the Ethereum wire and storage format.
//! Mirrors alloy-rlp as used by base/base.
//!
//! - `Encoder`: zero-allocation writer into a caller buffer; size it with the
//!   `*_length` functions or `codec.length`.
//! - `Decoder`: strict canonical zero-copy reader over a slice.
//! - `codec`: comptime-generic encode/decode driven by Zig types.

const std = @import("std");
const assert = std.debug.assert;

pub const encode_module = @import("encode.zig");
pub const decode_module = @import("decode.zig");
pub const codec = @import("codec.zig");

pub const Encoder = encode_module.Encoder;
pub const Decoder = decode_module.Decoder;
pub const Header = decode_module.Header;
pub const Error = decode_module.Error;
pub const decode_header = decode_module.decode_header;
pub const validate = decode_module.validate;
pub const byte_length = encode_module.byte_length;
pub const header_length = encode_module.header_length;
pub const bytes_length = encode_module.bytes_length;
pub const int_length = encode_module.int_length;
pub const list_length = encode_module.list_length;
pub const length = codec.length;
pub const encode = codec.encode;
pub const encode_to = codec.encode_to;
pub const decode = codec.decode;
pub const decode_exact = codec.decode_exact;

/// Maximum list nesting accepted by `reencode` and the structural validators.
pub const depth_max = 64;

/// Strictly decodes exactly one item from `input` and re-encodes it into `output`.
/// Because the decoder only accepts canonical encodings, the result must equal the
/// input byte for byte; tests use this as a canonicality oracle.
pub fn reencode(output: []u8, input: []const u8) (Error || error{TooDeep})![]u8 {
    assert(output.len >= input.len);
    const header = try decode_header(input);
    if (header.total_length() != input.len) return error.TrailingBytes;
    _ = try validate(input, depth_max);
    // Structure is valid, so every item copies through unchanged: list headers are
    // re-derived from payload lengths, strings via `Encoder.bytes`.
    var stack: [depth_max]Decoder = undefined;
    stack[0] = Decoder.init(input);
    var depth: usize = 1;
    var encoder = Encoder.init(output);
    var iterations: usize = 0;
    while (depth > 0) : (iterations += 1) {
        assert(iterations <= 2 * input.len + 1);
        const top = &stack[depth - 1];
        if (top.is_empty()) {
            depth -= 1;
            continue;
        }
        const item = try top.peek_header();
        if (item.list) {
            encoder.list_header(item.payload_length);
            assert(depth < depth_max);
            stack[depth] = try top.list();
            depth += 1;
        } else {
            encoder.bytes(try top.bytes());
        }
    }
    return encoder.written();
}

/// Builds nested RLP when list payload sizes are not known in advance. Items are
/// written in order; `end_list` shifts the payload right to make room for the header.
/// O(n * depth) copying: for tests and tools, not hot paths.
pub const TreeWriter = struct {
    buffer: []u8,
    position: usize = 0,
    starts: [depth_max]usize = undefined,
    depth: usize = 0,

    pub fn begin_list(writer: *TreeWriter) void {
        assert(writer.depth < depth_max);
        writer.starts[writer.depth] = writer.position;
        writer.depth += 1;
    }

    pub fn end_list(writer: *TreeWriter) void {
        assert(writer.depth > 0);
        writer.depth -= 1;
        const start = writer.starts[writer.depth];
        const payload_length = writer.position - start;
        const size = header_length(payload_length);
        assert(writer.position + size <= writer.buffer.len);
        const payload = writer.buffer[start..writer.position];
        std.mem.copyBackwards(u8, writer.buffer[start + size ..][0..payload_length], payload);
        var encoder = Encoder.init(writer.buffer[start..][0..size]);
        encoder.list_header(payload_length);
        writer.position += size;
    }

    pub fn bytes(writer: *TreeWriter, value: []const u8) void {
        var encoder = Encoder.init(writer.buffer[writer.position..]);
        encoder.bytes(value);
        writer.position += encoder.position;
    }

    pub fn written(writer: *const TreeWriter) []u8 {
        assert(writer.depth == 0);
        return writer.buffer[0..writer.position];
    }
};

const testing = std.testing;
const hex = @import("../primitives/hex.zig");
const Prng = @import("../../testing/prng.zig").Prng;

/// Writes a JSON test-vector value with an explicit stack (no recursion).
fn write_json(writer: *TreeWriter, root: std.json.Value) !void {
    const Frame = struct { items: []std.json.Value, index: usize };
    var stack: [depth_max]Frame = undefined;
    var depth: usize = 0;
    var pending: ?std.json.Value = root;
    while (true) {
        if (pending) |value| {
            pending = null;
            switch (value) {
                .array => |array| {
                    writer.begin_list();
                    stack[depth] = .{ .items = array.items, .index = 0 };
                    depth += 1;
                },
                .integer => |integer| try write_integer(writer, @intCast(integer)),
                .string => |string| if (string.len > 0 and string[0] == '#') {
                    try write_integer(writer, try std.fmt.parseInt(u512, string[1..], 10));
                } else writer.bytes(string),
                else => return error.UnsupportedVector,
            }
        }
        if (depth == 0) return;
        const frame = &stack[depth - 1];
        if (frame.index == frame.items.len) {
            writer.end_list();
            depth -= 1;
            if (depth == 0) return;
        } else {
            pending = frame.items[frame.index];
            frame.index += 1;
        }
    }
}

fn write_integer(writer: *TreeWriter, value: u512) !void {
    var scratch: [64]u8 = undefined;
    std.mem.writeInt(u512, &scratch, value, .big);
    writer.bytes(scratch[64 - byte_length(value) ..]);
}

test "rlp: ethereum valid vectors" {
    const text = @embedFile("testdata/rlptest.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var iterator = parsed.value.object.iterator();
    var count: usize = 0;
    while (iterator.next()) |entry| : (count += 1) {
        const vector = entry.value_ptr.object;
        var expected_buffer: [2048]u8 = undefined;
        const expected = try hex.decode_into(&expected_buffer, vector.get("out").?.string);
        var buffer: [2048]u8 = undefined;
        var writer: TreeWriter = .{ .buffer = &buffer };
        try write_json(&writer, vector.get("in").?);
        try testing.expectEqualSlices(u8, expected, writer.written());
        var again: [2048]u8 = undefined;
        try testing.expectEqualSlices(u8, expected, try reencode(&again, expected));
    }
    try testing.expect(count >= 28);
}

test "rlp: ethereum invalid vectors" {
    const text = @embedFile("testdata/invalidRLPTest.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var iterator = parsed.value.object.iterator();
    var count: usize = 0;
    while (iterator.next()) |entry| : (count += 1) {
        var input_buffer: [256]u8 = undefined;
        const out_text = entry.value_ptr.object.get("out").?.string;
        const input = try hex.decode_into(&input_buffer, out_text);
        var output: [256]u8 = undefined;
        if (reencode(&output, input)) |_| {
            std.debug.print("accepted invalid vector {s}\n", .{entry.key_ptr.*});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try testing.expect(count >= 26);
}

test "rlp: ethereum random vectors" {
    // RLPTests/RandomRLPTests: `"in": "VALID"` means `out` is well-formed RLP, so the
    // strict structural walk must accept it and re-encode it byte-identical.
    const text = @embedFile("testdata/randomRLPTest.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var iterator = parsed.value.object.iterator();
    var count: usize = 0;
    while (iterator.next()) |entry| : (count += 1) {
        try testing.expectEqualStrings("VALID", entry.value_ptr.object.get("in").?.string);
        var input_buffer: [256]u8 = undefined;
        const out_text = entry.value_ptr.object.get("out").?.string;
        const input = try hex.decode_into(&input_buffer, out_text);
        var output: [256]u8 = undefined;
        try testing.expectEqualSlices(u8, input, try reencode(&output, input));
    }
    try testing.expect(count >= 1);
}

/// Writes a random tree of at most `item_max` items into `writer`.
fn write_random_tree(prng: *Prng, writer: *TreeWriter, item_max: usize) void {
    writer.begin_list();
    var items: usize = 0;
    while (items < item_max) : (items += 1) {
        const roll = prng.below(10);
        if (roll < 2 and writer.depth < 8) {
            writer.begin_list();
        } else if (roll < 4 and writer.depth > 1) {
            writer.end_list();
        } else {
            var data: [80]u8 = undefined;
            const len = prng.below(data.len + 1);
            prng.fill(data[0..len]);
            writer.bytes(data[0..len]);
        }
    }
    while (writer.depth > 0) writer.end_list();
}

test "rlp: seeded fuzz random trees round trip" {
    var prng = Prng.init(0x2b1d);
    var buffer: [16384]u8 = undefined;
    var output: [16384]u8 = undefined;
    for (0..300) |_| {
        var writer: TreeWriter = .{ .buffer = &buffer };
        write_random_tree(&prng, &writer, prng.below(64));
        const encoded = writer.written();
        try testing.expectEqualSlices(u8, encoded, try reencode(&output, encoded));
        // Any single-byte corruption must either be rejected or still be canonical.
        var corrupted: [16384]u8 = undefined;
        @memcpy(corrupted[0..encoded.len], encoded);
        corrupted[prng.below(encoded.len)] = prng.int(u8);
        if (reencode(&output, corrupted[0..encoded.len])) |again| {
            try testing.expectEqualSlices(u8, corrupted[0..encoded.len], again);
        } else |_| {}
    }
}

test "rlp: seeded fuzz integers" {
    var prng = Prng.init(0x1e7);
    var buffer: [40]u8 = undefined;
    for (0..2000) |_| {
        const value = prng.int(u256) >> @intCast(prng.below(257) % 256);
        const encoded = encode_to(&buffer, value);
        try testing.expectEqual(int_length(value), encoded.len);
        try testing.expectEqual(value, try decode_exact(u256, encoded));
    }
}

fn fuzz_reencode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1024]u8 = undefined;
    const again = reencode(&output, input[0..len]) catch return;
    try testing.expectEqualSlices(u8, input[0..len], again);
}

test "rlp: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_reencode, .{});
}

test {
    std.testing.refAllDecls(@This());
}

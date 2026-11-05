//! Calldata decoding for native precompiles with alloy's validating decoder semantics
//! (`abi_decode_validate`, non-strict): trailing bytes are allowed, offsets need not be
//! canonical, a short buffer is an overrun, an offset or length word above 64 bits is an
//! "offset (usize)" type-check failure, and invalid values (dirty address bits, a bool above
//! 1, an out-of-range enum) fail the whole parameter tuple's type check after decoding.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");

pub const Kind = enum {
    address,
    uint64,
    bool,
    /// A Solidity enum (uint8) with values up to the caller's `enumeration_max`.
    enumeration,
    address_array,
    uint64_array,
    bytes32,
    uint256,
    uint8,
    /// `bytes4`: left-aligned, the low 28 bytes must be zero.
    bytes4,
    /// UTF-8 `string`; invalid UTF-8 fails the tuple type check.
    string,
    bytes,
    /// `uint8[]` of enum values up to `enumeration_max`.
    enumeration_array,
    uint256_array,
    /// `bytes[]`: element offsets are relative to the word after the length.
    bytes_array,

    fn is_array(kind: Kind) bool {
        return switch (kind) {
            .address_array, .uint64_array, .enumeration_array, .uint256_array => true,
            else => false,
        };
    }
};

pub const arguments_max = 8;

/// A decoded dynamic array of one-word elements (`address[]`, `uint64[]`).
pub const Array = struct {
    words: []const u8,

    pub fn count(array: Array) u32 {
        assert(array.words.len % 32 == 0);
        return @intCast(array.words.len / 32);
    }

    pub fn word(array: Array, index: u32) *const [32]u8 {
        assert(index < array.count());
        return array.words[@as(usize, index) * 32 ..][0..32];
    }

    pub fn uint64(array: Array, index: u32) u64 {
        return std.mem.readInt(u64, array.word(index)[24..32], .big);
    }
};

pub const Arguments = struct {
    words: [arguments_max]*const [32]u8 = undefined,
    /// The first dynamic array argument.
    array: Array = .{ .words = &.{} },
    /// Dynamic payload per argument: array words or string bytes.
    dynamic: [arguments_max][]const u8 = @splat(&.{}),
    /// Element counts of `bytes[]` arguments.
    counts: [arguments_max]u32 = @splat(0),

    /// Element `item` of a decoded `bytes[]` argument (validated during decoding).
    pub fn bytes_item(arguments: *const Arguments, index: usize, item: u32) []const u8 {
        return bytes_element(arguments.dynamic[index], item).?;
    }

    pub fn bytes_count(arguments: *const Arguments, index: usize) u32 {
        return arguments.counts[index];
    }

    pub fn bytes(arguments: *const Arguments, index: usize) []const u8 {
        return arguments.dynamic[index];
    }

    pub fn list(arguments: *const Arguments, index: usize) Array {
        return .{ .words = arguments.dynamic[index] };
    }

    pub fn uint256(arguments: *const Arguments, index: usize) u256 {
        return std.mem.readInt(u256, arguments.words[index], .big);
    }

    pub fn address(arguments: *const Arguments, index: usize) native.Address {
        return arguments.words[index][12..32].*;
    }

    pub fn uint64(arguments: *const Arguments, index: usize) u64 {
        return std.mem.readInt(u64, arguments.words[index][24..32], .big);
    }

    pub fn flag(arguments: *const Arguments, index: usize) bool {
        return arguments.words[index][31] != 0;
    }

    pub fn small(arguments: *const Arguments, index: usize) u8 {
        return arguments.words[index][31];
    }
};

/// Decode `kinds` from `data` (calldata after the selector), or report the failure.
pub fn decode_arguments(
    data: []const u8,
    kinds: []const Kind,
    enumeration_max: u8,
    failure: *native.DecodeFailure,
) ?Arguments {
    assert(kinds.len <= arguments_max);
    var arguments = Arguments{};
    var array_count: u32 = 0;
    for (kinds, 0..) |kind, index| {
        const head = head_word(data, index) orelse {
            failure.* = .overrun;
            return null;
        };
        arguments.words[index] = head;
        if (kind == .bytes_array) {
            const area = decode_bytes_array(data, head, &arguments.counts[index], failure) orelse
                return null;
            arguments.dynamic[index] = area;
            continue;
        }
        if (kind == .string or kind == .bytes) {
            arguments.dynamic[index] = decode_dynamic(data, head, 1, failure) orelse return null;
            continue;
        }
        if (!kind.is_array()) continue;
        const words = decode_dynamic(data, head, 32, failure) orelse return null;
        arguments.dynamic[index] = words;
        if (array_count == 0) arguments.array = .{ .words = words };
        array_count += 1;
    }
    for (kinds, 0..) |kind, index| {
        const payload = arguments.list(index);
        if (!valid(kind, arguments.words[index], payload, enumeration_max)) {
            failure.* = .type_check;
            return null;
        }
    }
    return arguments;
}

fn head_word(data: []const u8, index: usize) ?*const [32]u8 {
    if (data.len < 32 * (index + 1)) return null;
    return data[32 * index ..][0..32];
}

fn as_offset(word: *const [32]u8) ?u64 {
    for (word[0..24]) |byte| {
        if (byte != 0) return null;
    }
    return std.mem.readInt(u64, word[24..32], .big);
}

/// `bytes[]`: returns the element area (after the length word) once every element decodes.
fn decode_bytes_array(
    data: []const u8,
    head: *const [32]u8,
    count: *u32,
    failure: *native.DecodeFailure,
) ?[]const u8 {
    const offset = as_offset(head) orelse {
        failure.* = .{ .offset = head.* };
        return null;
    };
    if (offset > data.len or data.len - offset < 32) {
        failure.* = .overrun;
        return null;
    }
    const length_word = data[@intCast(offset)..][0..32];
    const length = as_offset(length_word) orelse {
        failure.* = .{ .offset = length_word.* };
        return null;
    };
    const area = data[@intCast(offset + 32)..];
    if (length > area.len / 32) {
        failure.* = .overrun;
        return null;
    }
    var item: u32 = 0;
    while (item < length) : (item += 1) {
        const head_item = area[32 * @as(usize, item) ..][0..32];
        _ = decode_dynamic(area, head_item, 1, failure) orelse return null;
    }
    count.* = @intCast(length);
    return area;
}

fn bytes_element(area: []const u8, item: u32) ?[]const u8 {
    var failure: native.DecodeFailure = .overrun;
    const head = area[32 * @as(usize, item) ..][0..32];
    return decode_dynamic(area, head, 1, &failure);
}

/// Follow an offset to a length-prefixed payload of `length * element_size` bytes.
fn decode_dynamic(
    data: []const u8,
    head: *const [32]u8,
    comptime element_size: u8,
    failure: *native.DecodeFailure,
) ?[]const u8 {
    const offset = as_offset(head) orelse {
        failure.* = .{ .offset = head.* };
        return null;
    };
    if (offset > data.len or data.len - offset < 32) {
        failure.* = .overrun;
        return null;
    }
    const length_word = data[@intCast(offset)..][0..32];
    const length = as_offset(length_word) orelse {
        failure.* = .{ .offset = length_word.* };
        return null;
    };
    const elements = data[@intCast(offset + 32)..];
    if (length > elements.len / element_size) {
        failure.* = .overrun;
        return null;
    }
    return elements[0..@intCast(length * element_size)];
}

fn zero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn valid(kind: Kind, word: *const [32]u8, elements: Array, enumeration_max: u8) bool {
    return switch (kind) {
        .address => zero(word[0..12]),
        .uint64 => zero(word[0..24]),
        .bool => zero(word[0..31]) and word[31] <= 1,
        .enumeration => zero(word[0..31]) and word[31] <= enumeration_max,
        .bytes32, .uint256 => true,
        .uint8 => zero(word[0..31]),
        .bytes4 => zero(word[4..32]),
        .address_array => for (0..elements.count()) |index| {
            if (!zero(elements.word(@intCast(index))[0..12])) break false;
        } else true,
        .uint64_array => for (0..elements.count()) |index| {
            if (!zero(elements.word(@intCast(index))[0..24])) break false;
        } else true,
        .enumeration_array => for (0..elements.count()) |index| {
            const element = elements.word(@intCast(index));
            if (!zero(element[0..31]) or element[31] > enumeration_max) break false;
        } else true,
        .uint256_array, .bytes_array, .bytes => true,
        .string => std.unicode.utf8ValidateSlice(elements.words),
    };
}

const testing = std.testing;

test "native abi: dynamic address arrays follow alloy's decoder" {
    const kinds = [_]Kind{ .uint64, .bool, .address_array };
    var data: [6 * 32]u8 = @splat(0);
    data[31] = 7;
    data[63] = 1;
    data[95] = 0x60; // Offset of the array.
    data[127] = 2; // Length.
    data[159] = 0xaa;
    data[191] = 0xbb;
    var failure: native.DecodeFailure = .overrun;
    const arguments = decode_arguments(&data, &kinds, 1, &failure).?;
    try testing.expectEqual(@as(u64, 7), arguments.uint64(0));
    try testing.expectEqual(@as(u32, 2), arguments.array.count());
    try testing.expectEqual(@as(u8, 0xbb), arguments.array.word(1)[31]);

    data[127] = 3; // Length beyond the buffer.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 1, &failure));
    try testing.expectEqual(native.DecodeFailure.overrun, failure);
    data[127] = 2;
    data[64] = 1; // Dirty offset.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 1, &failure));
    try testing.expect(failure == .offset);
    data[64] = 0;
    data[160] = 1; // Dirty address element: a tuple type-check failure.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 1, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
    data[160] = 0;
    data[63] = 2; // Bool above 1.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 1, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
}

test "native abi: strings are unpadded slices validated as UTF-8" {
    const kinds = [_]Kind{ .string, .enumeration_array };
    var data: [6 * 32]u8 = @splat(0);
    data[31] = 0x40; // String offset.
    data[63] = 0x80; // Array offset.
    data[95] = 3; // String length.
    data[96..99].* = "abc".*;
    data[159] = 1; // Array length.
    data[191] = 2; // Enum element.
    var failure: native.DecodeFailure = .overrun;
    const arguments = decode_arguments(&data, &kinds, 2, &failure).?;
    try testing.expectEqualStrings("abc", arguments.bytes(0));
    try testing.expectEqual(@as(u32, 1), arguments.list(1).count());
    try testing.expectEqual(null, decode_arguments(data[0..191], &kinds, 2, &failure));
    try testing.expectEqual(native.DecodeFailure.overrun, failure);
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 1, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
    data[96] = 0xff; // Invalid UTF-8.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 2, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
    data[96] = 'a';
    data[95] = 100; // String longer than the buffer.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, 2, &failure));
    try testing.expectEqual(native.DecodeFailure.overrun, failure);
}

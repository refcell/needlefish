//! Calldata decoding for native precompiles with alloy's validating decoder semantics
//! (`abi_decode_validate`, non-strict): trailing bytes are allowed, offsets need not be
//! canonical, a short buffer is an overrun, an offset or length word above 64 bits is an
//! "offset (usize)" type-check failure, and invalid values (dirty address bits, a bool above
//! 1, an out-of-range enum) fail the whole parameter tuple's type check after decoding.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");

pub const Kind = enum { address, uint64, bool, policy_type, address_array, bytes32, uint256 };

pub const arguments_max = 4;

/// A decoded `address[]`: `count` validated-later 32-byte words.
pub const AddressArray = struct {
    words: []const u8,

    pub fn count(array: AddressArray) u32 {
        assert(array.words.len % 32 == 0);
        return @intCast(array.words.len / 32);
    }

    pub fn word(array: AddressArray, index: u32) *const [32]u8 {
        assert(index < array.count());
        return array.words[@as(usize, index) * 32 ..][0..32];
    }
};

pub const Arguments = struct {
    words: [arguments_max]*const [32]u8 = undefined,
    array: AddressArray = .{ .words = &.{} },

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
        if (kind != .address_array) continue;
        assert(array_count == 0);
        array_count += 1;
        arguments.array = address_array(data, head, failure) orelse return null;
    }
    for (kinds, 0..) |kind, index| {
        if (!valid(kind, arguments.words[index], arguments.array)) {
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

fn address_array(
    data: []const u8,
    head: *const [32]u8,
    failure: *native.DecodeFailure,
) ?AddressArray {
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
    if (length > elements.len / 32) {
        failure.* = .overrun;
        return null;
    }
    return .{ .words = elements[0..@intCast(length * 32)] };
}

fn zero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn valid(kind: Kind, word: *const [32]u8, array: AddressArray) bool {
    return switch (kind) {
        .address => zero(word[0..12]),
        .uint64 => zero(word[0..24]),
        .bool => zero(word[0..31]) and word[31] <= 1,
        .policy_type => zero(word[0..31]) and word[31] <= 1,
        .bytes32, .uint256 => true,
        .address_array => for (0..array.count()) |index| {
            if (!zero(array.word(@intCast(index))[0..12])) break false;
        } else true,
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
    const arguments = decode_arguments(&data, &kinds, &failure).?;
    try testing.expectEqual(@as(u64, 7), arguments.uint64(0));
    try testing.expectEqual(@as(u32, 2), arguments.array.count());
    try testing.expectEqual(@as(u8, 0xbb), arguments.array.word(1)[31]);

    data[127] = 3; // Length beyond the buffer.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, &failure));
    try testing.expectEqual(native.DecodeFailure.overrun, failure);
    data[127] = 2;
    data[64] = 1; // Dirty offset.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, &failure));
    try testing.expect(failure == .offset);
    data[64] = 0;
    data[160] = 1; // Dirty address element: a tuple type-check failure.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
    data[160] = 0;
    data[63] = 2; // Bool above 1.
    try testing.expectEqual(null, decode_arguments(&data, &kinds, &failure));
    try testing.expectEqual(native.DecodeFailure.type_check, failure);
}

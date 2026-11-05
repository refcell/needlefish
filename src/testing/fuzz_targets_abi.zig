//! Model-based fuzz target for native precompile calldata decoding
//! (`execution/evm/native_abi.zig`). Native precompiles decode attacker-chosen calldata
//! inside block execution, so a panic there halts the chain and a wrong accept or reject
//! forks it from the Rust node (alloy's validating, non-strict decoder).
//!
//! Random parameter tuples (every `Kind`) with random values are ABI-encoded by a
//! reference encoder here. Properties:
//!   - the canonical encoding decodes, and every accessor returns the encoded value;
//!   - trailing bytes change nothing (non-strict decoding);
//!   - one invalid value (dirty high bits, bool above 1, enum above the maximum, dirty
//!     array element, invalid UTF-8) fails with `type_check`;
//!   - any truncation fails with `overrun`, or decodes to the same values (only padding
//!     of the last payload was cut);
//!   - arbitrary calldata never crashes, and every decoded slice lies inside the calldata.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const abi = @import("../execution/evm/native_abi.zig");
const native = @import("../execution/evm/native.zig");

const Kind = abi.Kind;
const kinds_all = std.enums.values(Kind);
const elements_max = 4;
const payload_bytes_max = 40;
const items_max = 3;
const data_bytes_max = 4096;

/// One argument value. Static kinds use `word`; arrays use `words[0..count]`; `string`
/// and `bytes` use `bytes[0..length]`; `bytes[]` uses `items`.
const Value = struct {
    word: [32]u8 = @splat(0),
    words: [elements_max][32]u8 = @splat(@splat(0)),
    count: u32 = 0,
    bytes: [payload_bytes_max]u8 = undefined,
    length: u32 = 0,
    items: [items_max][payload_bytes_max]u8 = undefined,
    item_lengths: [items_max]u32 = @splat(0),
};

const Tuple = struct {
    kinds: [abi.arguments_max]Kind = undefined,
    values: [abi.arguments_max]Value = @splat(.{}),
    len: usize = 0,
    enumeration_max: u8 = 0,
};

fn random_word(prng: *Prng, kind: Kind, enumeration_max: u8) [32]u8 {
    var word: [32]u8 = @splat(0);
    switch (kind) {
        .address, .address_array => prng.fill(word[12..]),
        .uint64, .uint64_array => prng.fill(word[24..]),
        .bool => word[31] = @intFromBool(prng.chance(1, 2)),
        .enumeration, .enumeration_array => {
            word[31] = @intCast(prng.below(@as(u64, enumeration_max) + 1));
        },
        .uint8 => word[31] = @truncate(prng.int(u64)),
        .bytes4 => prng.fill(word[0..4]),
        .uint48 => prng.fill(word[26..]),
        .uint16 => prng.fill(word[30..]),
        .bytes32, .uint256, .uint256_array => prng.fill(&word),
        .string, .bytes, .bytes_array => unreachable, // Proof: dynamic payloads.
    }
    return word;
}

fn random_payload(prng: *Prng, out: []u8, text: bool) u32 {
    const length: u32 = @intCast(prng.below(out.len + 1));
    for (out[0..length]) |*byte| {
        byte.* = if (text) @intCast(prng.range('a', 'z')) else @truncate(prng.int(u64));
    }
    return length;
}

fn random_tuple(prng: *Prng) Tuple {
    var tuple: Tuple = .{ .enumeration_max = @intCast(prng.below(8)) };
    tuple.len = @intCast(prng.below(abi.arguments_max + 1));
    for (tuple.kinds[0..tuple.len], tuple.values[0..tuple.len]) |*kind, *value| {
        kind.* = kinds_all[@intCast(prng.below(kinds_all.len))];
        switch (kind.*) {
            .string, .bytes => value.length = random_payload(prng, &value.bytes, kind.* == .string),
            .bytes_array => {
                value.count = @intCast(prng.below(items_max + 1));
                for (0..value.count) |item| {
                    value.item_lengths[item] = random_payload(prng, &value.items[item], false);
                }
            },
            .address_array, .uint64_array, .enumeration_array, .uint256_array => {
                value.count = @intCast(prng.below(elements_max + 1));
                for (value.words[0..value.count]) |*word| {
                    word.* = random_word(prng, kind.*, tuple.enumeration_max);
                }
            },
            else => value.word = random_word(prng, kind.*, tuple.enumeration_max),
        }
    }
    return tuple;
}

const Encoder = struct {
    data: [data_bytes_max]u8 = undefined,
    len: usize = 0,

    fn word(encoder: *Encoder, at: usize, number: u64) void {
        @memset(encoder.data[at..][0..32], 0);
        std.mem.writeInt(u64, encoder.data[at + 24 ..][0..8], number, .big);
    }

    /// Appends a length word and the payload padded to a word boundary.
    fn payload(encoder: *Encoder, bytes: []const u8) void {
        encoder.word(encoder.len, bytes.len);
        encoder.len += 32;
        const padded = std.mem.alignForward(usize, bytes.len, 32);
        @memset(encoder.data[encoder.len..][0..padded], 0);
        @memcpy(encoder.data[encoder.len..][0..bytes.len], bytes);
        encoder.len += padded;
    }

    fn encode(encoder: *Encoder, tuple: *const Tuple) []const u8 {
        encoder.len = 32 * tuple.len;
        for (tuple.kinds[0..tuple.len], tuple.values[0..tuple.len], 0..) |kind, *value, index| {
            const head = 32 * index;
            switch (kind) {
                .string, .bytes => {
                    encoder.word(head, encoder.len);
                    encoder.payload(value.bytes[0..value.length]);
                },
                .bytes_array => {
                    encoder.word(head, encoder.len);
                    encoder.bytes_array(value);
                },
                .address_array, .uint64_array, .enumeration_array, .uint256_array => {
                    encoder.word(head, encoder.len);
                    encoder.word(encoder.len, value.count);
                    encoder.len += 32;
                    for (value.words[0..value.count]) |*element| {
                        encoder.data[encoder.len..][0..32].* = element.*;
                        encoder.len += 32;
                    }
                },
                else => encoder.data[head..][0..32].* = value.word,
            }
        }
        assert(encoder.len <= data_bytes_max);
        return encoder.data[0..encoder.len];
    }

    /// `bytes[]`: length, item offsets relative to the word after the length, items.
    fn bytes_array(encoder: *Encoder, value: *const Value) void {
        encoder.word(encoder.len, value.count);
        encoder.len += 32;
        const area = encoder.len;
        encoder.len += 32 * value.count;
        for (0..value.count) |item| {
            encoder.word(area + 32 * item, encoder.len - area);
            encoder.payload(value.items[item][0..value.item_lengths[item]]);
        }
    }
};

fn expect_values(tuple: *const Tuple, arguments: *const abi.Arguments) !void {
    const testing = std.testing;
    for (tuple.kinds[0..tuple.len], tuple.values[0..tuple.len], 0..) |kind, *value, index| {
        switch (kind) {
            .string, .bytes => {
                const expected = value.bytes[0..value.length];
                try testing.expectEqualSlices(u8, expected, arguments.bytes(index));
            },
            .bytes_array => {
                try testing.expectEqual(value.count, arguments.bytes_count(index));
                for (0..value.count) |item| {
                    const expected = value.items[item][0..value.item_lengths[item]];
                    const actual = arguments.bytes_item(index, @intCast(item));
                    try testing.expectEqualSlices(u8, expected, actual);
                }
            },
            .address_array, .uint64_array, .enumeration_array, .uint256_array => {
                const list = arguments.list(index);
                try testing.expectEqual(value.count, list.count());
                for (value.words[0..value.count], 0..) |*element, item| {
                    try testing.expectEqualSlices(u8, element, list.word(@intCast(item)));
                }
            },
            else => try testing.expectEqualSlices(u8, &value.word, arguments.words[index]),
        }
    }
}

/// Makes one value invalid for its kind. Returns false when the tuple has no kind with
/// invalid values (e.g. only `uint256` and `bytes`).
fn corrupt(prng: *Prng, tuple: *Tuple) bool {
    const start: usize = @intCast(prng.below(@max(tuple.len, 1)));
    for (0..tuple.len) |offset| {
        const index = (start + offset) % tuple.len;
        if (corrupt_value(prng, tuple.kinds[index], &tuple.values[index], tuple.enumeration_max)) {
            return true;
        }
    }
    return false;
}

fn corrupt_value(prng: *Prng, kind: Kind, value: *Value, enumeration_max: u8) bool {
    const element: ?*[32]u8 = if (value.count > 0)
        &value.words[@intCast(prng.below(value.count))]
    else
        null;
    switch (kind) {
        .address => value.word[@intCast(prng.below(12))] |= 1,
        .uint64 => value.word[@intCast(prng.below(24))] |= 0x80,
        .bool => value.word[31] = @intCast(prng.range(2, 255)),
        .enumeration => value.word[31] = enumeration_max + 1,
        .uint8 => value.word[@intCast(prng.below(31))] |= 1,
        .bytes4 => value.word[@intCast(prng.range(4, 31))] |= 1,
        .uint48 => value.word[@intCast(prng.below(26))] |= 1,
        .uint16 => value.word[@intCast(prng.below(30))] |= 1,
        .address_array => (element orelse return false)[@intCast(prng.below(12))] |= 1,
        .uint64_array => (element orelse return false)[@intCast(prng.below(24))] |= 1,
        .enumeration_array => (element orelse return false)[31] = enumeration_max + 1,
        .string => {
            if (value.length == 0) return false;
            value.bytes[@intCast(prng.below(value.length))] = 0xff;
        },
        .bytes32, .uint256, .uint256_array, .bytes, .bytes_array => return false,
    }
    return true;
}

fn fuzz_round_trip(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var tuple = random_tuple(&prng);
    var encoder: Encoder = .{};
    const data = encoder.encode(&tuple);
    const kinds = tuple.kinds[0..tuple.len];
    var failure: native.DecodeFailure = .overrun;
    const decoded = abi.decode_arguments(data, kinds, tuple.enumeration_max, &failure) orelse
        return error.TestUnexpectedResult;
    try expect_values(&tuple, &decoded);

    // Trailing bytes are ignored.
    const extra: usize = @intCast(prng.below(64));
    prng.fill(encoder.data[encoder.len..][0..extra]);
    const longer = encoder.data[0 .. encoder.len + extra];
    const trailing = abi.decode_arguments(longer, kinds, tuple.enumeration_max, &failure) orelse
        return error.TestUnexpectedResult;
    try expect_values(&tuple, &trailing);

    // Truncation: an overrun, or the same values when only padding was cut.
    if (data.len > 0) {
        const cut = data[0..@intCast(prng.below(data.len))];
        if (abi.decode_arguments(cut, kinds, tuple.enumeration_max, &failure)) |short| {
            try expect_values(&tuple, &short);
        } else try std.testing.expect(failure == .overrun);
    }

    // One invalid value fails the tuple type check.
    if (corrupt(&prng, &tuple)) {
        const bad = encoder.encode(&tuple);
        const result = abi.decode_arguments(bad, kinds, tuple.enumeration_max, &failure);
        try std.testing.expect(result == null);
        try std.testing.expect(failure == .type_check);
    }
}

fn inside(data: []const u8, slice: []const u8) bool {
    if (slice.len == 0) return true;
    const start = @intFromPtr(data.ptr);
    const begin = @intFromPtr(slice.ptr);
    return begin >= start and begin + slice.len <= start + data.len;
}

fn fuzz_arbitrary(_: void, smith: *Smith) anyerror!void {
    var kinds: [abi.arguments_max]Kind = undefined;
    const count = smith.valueRangeAtMost(u8, 0, abi.arguments_max);
    for (kinds[0..count]) |*kind| kind.* = kinds_all[smith.value(u8) % kinds_all.len];
    const enumeration_max = smith.value(u8);
    var buffer: [512]u8 = undefined;
    const length = smith.slice(&buffer);
    const data = buffer[0..length];
    var failure: native.DecodeFailure = .overrun;
    const arguments = abi.decode_arguments(data, kinds[0..count], enumeration_max, &failure) orelse
        return;
    for (kinds[0..count], 0..) |kind, index| {
        try std.testing.expect(inside(data, arguments.words[index]));
        try std.testing.expect(inside(data, arguments.dynamic[index]));
        if (kind != .bytes_array) continue;
        for (0..arguments.bytes_count(index)) |item| {
            try std.testing.expect(inside(data, arguments.bytes_item(index, @intCast(item))));
        }
    }
}

test "fuzz_targets_abi: native calldata round trips and rejects invalid values" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 2048 });
}

test "fuzz_targets_abi: arbitrary native calldata stays in bounds" {
    try fuzz.run({}, fuzz_arbitrary, .{ .iterations = 2048 });
}

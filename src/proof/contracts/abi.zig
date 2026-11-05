//! A minimal Solidity ABI codec for the proof contracts' calls: static words (uint,
//! address, bytes32, bool) and dynamic `bytes`, encoded into caller buffers and decoded
//! strictly (dirty high bits, out-of-range offsets and short data are errors), as alloy's
//! validating decoder does for these types.

const std = @import("std");
const assert = std.debug.assert;

pub const word_bytes = 32;
pub const Address = [20]u8;

pub const DecodeError = error{ Overrun, TypeCheck, SelectorMismatch };
pub const EncodeError = error{NoSpaceLeft};

/// The 4-byte function selector of a canonical signature.
pub fn selector(comptime signature: []const u8) [4]u8 {
    @setEvalBranchQuota(100_000);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(signature, &digest, .{});
    return digest[0..4].*;
}

fn padded(length: usize) usize {
    return (length + word_bytes - 1) / word_bytes * word_bytes;
}

/// One argument of a call.
pub const Value = union(enum) {
    uint: u256,
    address: Address,
    word: [32]u8,
    boolean: bool,
    bytes: []const u8,
};

/// Encodes `selector ++ abi.encode(values...)` into `out`.
pub fn encode_call(out: []u8, function: [4]u8, values: []const Value) EncodeError![]u8 {
    var size: usize = 4 + values.len * word_bytes;
    for (values) |value| {
        if (value == .bytes) size += word_bytes + padded(value.bytes.len);
    }
    if (size > out.len) return error.NoSpaceLeft;
    const result = out[0..size];
    @memset(result, 0);
    result[0..4].* = function;
    var tail: usize = values.len * word_bytes;
    for (values, 0..) |value, index| {
        const head = result[4 + index * word_bytes ..][0..word_bytes];
        switch (value) {
            .uint => |number| std.mem.writeInt(u256, head, number, .big),
            .address => |address| head[12..].* = address,
            .word => |word| head.* = word,
            .boolean => |flag| head[31] = @intFromBool(flag),
            .bytes => |bytes| {
                std.mem.writeInt(u256, head, tail, .big);
                const body = result[4 + tail ..];
                std.mem.writeInt(u256, body[0..word_bytes], bytes.len, .big);
                @memcpy(body[word_bytes..][0..bytes.len], bytes);
                tail += word_bytes + padded(bytes.len);
            },
        }
    }
    assert(4 + tail == size);
    return result;
}

/// Reads the words of an ABI-encoded tuple (return data, or calldata after the selector).
pub const Decoder = struct {
    data: []const u8,

    /// Calldata: checks the selector and decodes the arguments after it.
    pub fn call(data: []const u8, function: [4]u8) DecodeError!Decoder {
        if (data.len < 4) return error.Overrun;
        if (!std.mem.eql(u8, data[0..4], &function)) return error.SelectorMismatch;
        return .{ .data = data[4..] };
    }

    pub fn word(decoder: Decoder, index: usize) DecodeError!*const [32]u8 {
        const start = std.math.mul(usize, index, word_bytes) catch return error.Overrun;
        if (start + word_bytes > decoder.data.len) return error.Overrun;
        return decoder.data[start..][0..word_bytes];
    }

    pub fn uint(decoder: Decoder, comptime T: type, index: usize) DecodeError!T {
        const value = std.mem.readInt(u256, try decoder.word(index), .big);
        return std.math.cast(T, value) orelse error.TypeCheck;
    }

    pub fn address(decoder: Decoder, index: usize) DecodeError!Address {
        const raw = try decoder.word(index);
        if (!std.mem.allEqual(u8, raw[0..12], 0)) return error.TypeCheck;
        return raw[12..].*;
    }

    pub fn boolean(decoder: Decoder, index: usize) DecodeError!bool {
        const value = try decoder.uint(u8, index);
        if (value > 1) return error.TypeCheck;
        return value == 1;
    }

    /// A dynamic `bytes` argument: the head holds the offset of its length word.
    pub fn bytes(decoder: Decoder, index: usize) DecodeError![]const u8 {
        const offset = try decoder.uint(u32, index);
        if (offset % word_bytes != 0) return error.TypeCheck;
        const length_index = offset / word_bytes;
        const length = try decoder.uint(u32, length_index);
        const start = @as(usize, offset) + word_bytes;
        if (length > decoder.data.len -| start) return error.Overrun;
        const result = decoder.data[start..][0..length];
        const pad_end = @min(start + padded(length), decoder.data.len);
        if (!std.mem.allEqual(u8, decoder.data[start + length .. pad_end], 0)) {
            return error.TypeCheck;
        }
        return result;
    }
};

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "abi: well-known selectors" {
    const transfer = selector("transfer(address,uint256)");
    try testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &transfer);
    const balance_of = selector("balanceOf(address)");
    try testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &balance_of);
}

test "abi: a call with static and dynamic arguments round trips" {
    var buffer: [512]u8 = undefined;
    const function = selector("f(uint32,bytes32,bytes,bytes)");
    const extra: [36]u8 = @splat(0xab);
    const encoded = try encode_call(&buffer, function, &.{
        .{ .uint = 7 },
        .{ .word = @splat(0x11) },
        .{ .bytes = &extra },
        .{ .bytes = "" },
    });
    try testing.expectEqual(@as(usize, 4 + 4 * 32 + 32 + 64 + 32), encoded.len);
    const decoder = try Decoder.call(encoded, function);
    try testing.expectEqual(@as(u32, 7), try decoder.uint(u32, 0));
    try testing.expectEqualSlices(u8, &extra, try decoder.bytes(2));
    try testing.expectEqual(@as(usize, 0), (try decoder.bytes(3)).len);
    try testing.expectError(error.SelectorMismatch, Decoder.call(encoded, selector("g()")));
    const short = try Decoder.call(encoded[0..40], function);
    try testing.expectError(error.Overrun, short.bytes(2));
    var dirty = buffer;
    dirty[4] = 1; // High bits of the uint32.
    const dirty_decoder = try Decoder.call(dirty[0..encoded.len], function);
    try testing.expectError(error.TypeCheck, dirty_decoder.uint(u32, 0));
    try testing.expectError(error.NoSpaceLeft, encode_call(buffer[0..100], function, &.{
        .{ .uint = 7 }, .{ .word = @splat(0) }, .{ .bytes = &extra }, .{ .bytes = "" },
    }));
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var data: [256]u8 = undefined;
    const length = smith.slice(&data);
    const decoder: Decoder = .{ .data = data[0..length] };
    // Arbitrary data decodes or fails cleanly; decoded bytes lie inside the input.
    for (0..4) |index| {
        _ = decoder.address(index) catch {};
        _ = decoder.boolean(index) catch {};
        const bytes = decoder.bytes(index) catch continue;
        const base = @intFromPtr(decoder.data.ptr);
        try testing.expect(@intFromPtr(bytes.ptr) >= base);
        try testing.expect(@intFromPtr(bytes.ptr) + bytes.len <= base + length);
    }
}

test "abi: fuzz decode" {
    try fuzz.run({}, fuzz_decode, .{ .iterations = 2048 });
}

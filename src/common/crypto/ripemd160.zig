//! RIPEMD-160, the EVM precompile at address 0x03 (the 20-byte digest is returned
//! left-padded with 12 zero bytes). std has no RIPEMD-160, so correctness rests on the
//! official vectors from the RIPEMD-160 paper plus a deliberately naive reference
//! implementation (runtime loops, no unrolling) used as a differential oracle in tests.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const digest_length = 20;
pub const block_length = 64;
pub const Digest = [digest_length]u8;
pub const precompile_output_length = 32;

comptime {
    assert(block_length == 64);
    assert(precompile_output_length - digest_length == 12);
}

const initial_state = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

/// Message word index per step, left line then right line (5 rounds of 16 steps).
const word_left = [80]u8{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};
const word_right = [80]u8{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};

/// Left-rotation amount per step.
const rotate_left = [80]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};
const rotate_right = [80]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

const constant_left = [5]u32{ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
const constant_right = [5]u32{ 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

comptime {
    // Each line reads every message word exactly once per round of 16 steps.
    for ([2][80]u8{ word_left, word_right }) |table| {
        for (0..5) |round_index| {
            var seen: u16 = 0;
            for (table[round_index * 16 ..][0..16]) |word| seen |= @as(u16, 1) << @intCast(word);
            assert(seen == 0xffff);
        }
    }
}

/// Boolean function of round `round_index` (0..4).
inline fn mix(comptime round_index: u3, x: u32, y: u32, z: u32) u32 {
    return switch (round_index) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        4 => x ^ (y | ~z),
        else => unreachable,
    };
}

inline fn rotl(value: u32, amount: u5) u32 {
    return std.math.rotl(u32, value, amount);
}

/// Runs the 80 steps of one line (left or right) over the working registers.
inline fn line(
    comptime right: bool,
    state: *const [5]u32,
    words: *const [16]u32,
) [5]u32 {
    var a, var b, var c, var d, var e = state.*;
    inline for (0..80) |step| {
        const round_index = step / 16;
        const f_round: u3 = if (right) 4 - round_index else round_index;
        const word = words[if (right) word_right[step] else word_left[step]];
        const constant = if (right) constant_right[round_index] else constant_left[round_index];
        const amount = if (right) rotate_right[step] else rotate_left[step];
        const t = rotl(a +% mix(f_round, b, c, d) +% word +% constant, amount) +% e;
        a = e;
        e = d;
        d = rotl(c, 10);
        c = b;
        b = t;
    }
    return .{ a, b, c, d, e };
}

fn compress(state: *[5]u32, blocks: []const u8) void {
    assert(blocks.len % block_length == 0);
    var offset: usize = 0;
    while (offset < blocks.len) : (offset += block_length) {
        var words: [16]u32 = undefined;
        for (&words, 0..) |*word, index| {
            word.* = std.mem.readInt(u32, blocks[offset + index * 4 ..][0..4], .little);
        }
        const left = line(false, state, &words);
        const right = line(true, state, &words);
        combine(state, left, right);
    }
}

/// Feed-forward: cross-adds the two lines into the chaining value.
inline fn combine(state: *[5]u32, left: [5]u32, right: [5]u32) void {
    const next = [5]u32{
        state[1] +% left[2] +% right[3],
        state[2] +% left[3] +% right[4],
        state[3] +% left[4] +% right[0],
        state[4] +% left[0] +% right[1],
        state[0] +% left[1] +% right[2],
    };
    state.* = next;
}

fn write_digest(state: *const [5]u32) Digest {
    var out: Digest = undefined;
    for (state, 0..) |word, index| std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .little);
    return out;
}

/// Zero-pads `tail_buffer` after `used` bytes, appends 0x80 and the little-endian bit
/// length; returns the number of valid blocks (1 or 2).
fn pad(tail_buffer: *[2 * block_length]u8, used: usize, total_bytes: u64) usize {
    assert(used < block_length);
    @memset(tail_buffer[used..], 0);
    tail_buffer[used] = 0x80;
    const blocks: usize = if (used + 1 + 8 <= block_length) 1 else 2;
    const end = blocks * block_length;
    std.mem.writeInt(u64, tail_buffer[end - 8 ..][0..8], total_bytes *% 8, .little);
    assert(blocks == 1 or blocks == 2);
    return blocks;
}

/// One-shot RIPEMD-160.
pub fn ripemd160(data: []const u8) Digest {
    var state = initial_state;
    const whole = data.len - data.len % block_length;
    compress(&state, data[0..whole]);
    var tail: [2 * block_length]u8 = undefined;
    const used = data.len - whole;
    @memcpy(tail[0..used], data[whole..]);
    const blocks = pad(&tail, used, data.len);
    compress(&state, tail[0 .. blocks * block_length]);
    return write_digest(&state);
}

/// Precompile 0x03: the 20-byte digest left-padded with zeros to 32 bytes.
pub fn precompile_ripemd160(input: []const u8) [precompile_output_length]u8 {
    var out: [precompile_output_length]u8 = @splat(0);
    out[12..].* = ripemd160(input);
    assert(std.mem.allEqual(u8, out[0..12], 0));
    return out;
}

/// Streaming RIPEMD-160. No allocation; state lives inline.
pub const Hasher = struct {
    state: [5]u32 = initial_state,
    buffer: [block_length]u8 = undefined,
    buffer_len: u8 = 0,
    total_bytes: u64 = 0,

    pub fn init() Hasher {
        return .{};
    }

    pub fn update(hasher: *Hasher, data: []const u8) void {
        assert(hasher.buffer_len < block_length);
        hasher.total_bytes += data.len;
        var remaining = data;
        if (hasher.buffer_len > 0) {
            const take = @min(remaining.len, block_length - hasher.buffer_len);
            @memcpy(hasher.buffer[hasher.buffer_len..][0..take], remaining[0..take]);
            hasher.buffer_len += @intCast(take);
            remaining = remaining[take..];
            if (hasher.buffer_len < block_length) return;
            compress(&hasher.state, &hasher.buffer);
            hasher.buffer_len = 0;
        }
        const whole = remaining.len - remaining.len % block_length;
        compress(&hasher.state, remaining[0..whole]);
        remaining = remaining[whole..];
        @memcpy(hasher.buffer[0..remaining.len], remaining);
        hasher.buffer_len = @intCast(remaining.len);
        assert(hasher.buffer_len < block_length);
    }

    pub fn final(hasher: *Hasher) Digest {
        assert(hasher.buffer_len < block_length);
        var tail: [2 * block_length]u8 = undefined;
        @memcpy(tail[0..hasher.buffer_len], hasher.buffer[0..hasher.buffer_len]);
        const blocks = pad(&tail, hasher.buffer_len, hasher.total_bytes);
        compress(&hasher.state, tail[0 .. blocks * block_length]);
        hasher.buffer_len = 0;
        return write_digest(&hasher.state);
    }
};

const testing = std.testing;

fn hex_to_digest(comptime hex: *const [40]u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime literal, checked here.
    return out;
}

/// Naive reference straight from the paper: runtime loops, one function per round.
fn reference(data: []const u8) Digest {
    var message: [2 * block_length + 128]u8 = undefined;
    var state = initial_state;
    var remaining = data;
    while (remaining.len >= block_length) {
        reference_block(&state, remaining[0..block_length]);
        remaining = remaining[block_length..];
    }
    @memset(&message, 0);
    @memcpy(message[0..remaining.len], remaining);
    message[remaining.len] = 0x80;
    const padded: usize = if (remaining.len < 56) 64 else 128;
    std.mem.writeInt(u64, message[padded - 8 ..][0..8], @as(u64, data.len) * 8, .little);
    var offset: usize = 0;
    while (offset < padded) : (offset += block_length) {
        reference_block(&state, message[offset..][0..block_length]);
    }
    return write_digest(&state);
}

fn reference_f(round_index: usize, x: u32, y: u32, z: u32) u32 {
    return switch (round_index) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        else => x ^ (y | ~z),
    };
}

fn reference_block(state: *[5]u32, block: *const [block_length]u8) void {
    var x: [16]u32 = undefined;
    for (&x, 0..) |*word, index| word.* = std.mem.readInt(u32, block[index * 4 ..][0..4], .little);
    var left = state.*;
    var right = state.*;
    for (0..80) |step| {
        const round_index = step / 16;
        var t = rotl(left[0] +% reference_f(round_index, left[1], left[2], left[3]) +%
            x[word_left[step]] +% constant_left[round_index], rotate_left[step]) +% left[4];
        const next_left = [5]u32{ left[4], t, left[1], rotl(left[2], 10), left[3] };
        left = next_left;
        t = rotl(right[0] +% reference_f(4 - round_index, right[1], right[2], right[3]) +%
            x[word_right[step]] +% constant_right[round_index], rotate_right[step]) +% right[4];
        const next_right = [5]u32{ right[4], t, right[1], rotl(right[2], 10), right[3] };
        right = next_right;
    }
    const t = state[1] +% left[2] +% right[3];
    state[1] = state[2] +% left[3] +% right[4];
    state[2] = state[3] +% left[4] +% right[0];
    state[3] = state[4] +% left[0] +% right[1];
    state[4] = state[0] +% left[1] +% right[2];
    state[0] = t;
}

test "ripemd160: official vectors" {
    const vectors = [_]struct { input: []const u8, digest: Digest }{
        .{ .input = "", .digest = hex_to_digest("9c1185a5c5e9fc54612808977ee8f548b2258d31") },
        .{ .input = "a", .digest = hex_to_digest("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe") },
        .{ .input = "abc", .digest = hex_to_digest("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") },
        .{
            .input = "message digest",
            .digest = hex_to_digest("5d0689ef49d2fae572b881b123a85ffa21595f36"),
        },
        .{
            .input = "abcdefghijklmnopqrstuvwxyz",
            .digest = hex_to_digest("f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        },
        .{
            .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .digest = hex_to_digest("12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        },
        .{
            .input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            .digest = hex_to_digest("b0e20b6e3116640286ed3a87a5713079b21f5189"),
        },
        .{
            .input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            .digest = hex_to_digest("9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
        },
    };
    for (vectors) |vector| {
        try testing.expectEqual(vector.digest, ripemd160(vector.input));
        try testing.expectEqual(vector.digest, reference(vector.input));
    }
}

test "ripemd160: one million 'a'" {
    var hasher = Hasher.init();
    const chunk: [1000]u8 = @splat('a');
    for (0..1000) |_| hasher.update(&chunk);
    try testing.expectEqual(
        hex_to_digest("52783243c1697bdbe16d37f97f68f08325dc1528"),
        hasher.final(),
    );
}

test "ripemd160: precompile output is left padded to 32 bytes" {
    const out = precompile_ripemd160("");
    const zeros: [12]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zeros, out[0..12]);
    try testing.expectEqual(hex_to_digest("9c1185a5c5e9fc54612808977ee8f548b2258d31"), out[12..].*);
    try testing.expectEqual(ripemd160("\x00"), precompile_ripemd160("\x00")[12..].*);
}

test "ripemd160: matches naive reference at every length around block boundaries" {
    var buffer: [block_length * 4]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    for (0..buffer.len + 1) |length| {
        try testing.expectEqual(reference(buffer[0..length]), ripemd160(buffer[0..length]));
    }
}

test "ripemd160: seeded differential fuzz (one-shot, streaming, reference)" {
    var prng = Prng.init(0x726970656d64);
    var buffer: [1024]u8 = undefined;
    for (0..300) |_| {
        const length: usize = @intCast(prng.below(buffer.len + 1));
        prng.fill(buffer[0..length]);
        const expected = reference(buffer[0..length]);
        try testing.expectEqual(expected, ripemd160(buffer[0..length]));

        var hasher = Hasher.init();
        var cursor: usize = 0;
        while (cursor < length) {
            const step: usize = @intCast(prng.range(0, 200));
            const end = @min(length, cursor + step);
            hasher.update(buffer[cursor..end]);
            cursor = end;
        }
        try testing.expectEqual(expected, hasher.final());
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [2048]u8 = undefined;
    const length = smith.slice(&buffer);
    const data = buffer[0..length];
    try testing.expectEqual(reference(data), ripemd160(data));
    var hasher = Hasher.init();
    const split = length / 3;
    hasher.update(data[0..split]);
    hasher.update(data[split..]);
    try testing.expectEqual(reference(data), hasher.final());
}

test "ripemd160: coverage-guided fuzz vs naive reference" {
    try testing.fuzz({}, fuzz_one, .{});
}

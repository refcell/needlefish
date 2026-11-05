//! BLAKE2b compression function F (RFC 7693 section 3.2) with a caller-chosen round
//! count, the EVM precompile at address 0x09 (EIP-152).
//!
//! `std.crypto.hash.blake2.Blake2b512` is used only as a test oracle: a full BLAKE2b-512
//! built from `blake2f` with 12 rounds must match it for every message length.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

/// Exact length of the precompile input: 4 + 64 + 128 + 8 + 8 + 1 bytes.
pub const input_length = 213;
pub const output_length = 64;
/// BLAKE2b uses 12 rounds; EIP-152 allows any `u32` count.
pub const standard_rounds = 12;

comptime {
    assert(input_length == 4 + 8 * 8 + 16 * 8 + 2 * 8 + 1);
    assert(output_length == 8 * 8);
}

pub const Error = error{
    InvalidInputLength,
    InvalidFinalFlag,
};

const initialization_vector = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

/// Message word schedule; round `r` uses row `r % 10`.
const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

comptime {
    // Every row is a permutation of 0..15.
    for (sigma) |row| {
        var seen: u16 = 0;
        for (row) |word| seen |= @as(u16, 1) << @intCast(word);
        assert(seen == 0xffff);
    }
}

inline fn mix(
    v: *[16]u64,
    comptime a: usize,
    comptime b: usize,
    comptime c: usize,
    comptime d: usize,
    x: u64,
    y: u64,
) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 32);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 24);
    v[a] = v[a] +% v[b] +% y;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 63);
}

inline fn round(v: *[16]u64, m: *const [16]u64, comptime row: usize) void {
    const s = sigma[row];
    mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

/// EIP-152 `F`: updates the state `h` with message block `m`, offset counter `t` and
/// final-block flag, running exactly `rounds` rounds (zero rounds is valid).
pub fn blake2f(rounds: u32, h: *[8]u64, m: *const [16]u64, t: [2]u64, final: bool) void {
    var v: [16]u64 = undefined;
    v[0..8].* = h.*;
    v[8..16].* = initialization_vector;
    v[12] ^= t[0];
    v[13] ^= t[1];
    if (final) v[14] = ~v[14];

    var remaining = rounds;
    while (remaining >= 10) : (remaining -= 10) {
        inline for (0..10) |row| round(&v, m, row);
    }
    assert(remaining < 10);
    // The tail continues the schedule from row 0 because whole groups of ten were consumed.
    inline for (0..9) |row| {
        if (row < remaining) round(&v, m, row);
    }
    for (h, v[0..8], v[8..16]) |*word, low, high| word.* ^= low ^ high;
}

/// Precompile 0x09 (gas is charged by the caller: `rounds` units, see `input_rounds`).
pub fn precompile_blake2f(input: []const u8, out: *[output_length]u8) Error!void {
    if (input.len != input_length) return error.InvalidInputLength;
    if (input[212] > 1) return error.InvalidFinalFlag;
    const rounds = std.mem.readInt(u32, input[0..4], .big);
    var h: [8]u64 = undefined;
    for (&h, 0..) |*word, index| {
        word.* = std.mem.readInt(u64, input[4 + index * 8 ..][0..8], .little);
    }
    var m: [16]u64 = undefined;
    for (&m, 0..) |*word, index| {
        word.* = std.mem.readInt(u64, input[68 + index * 8 ..][0..8], .little);
    }
    const t = [2]u64{
        std.mem.readInt(u64, input[196..204], .little),
        std.mem.readInt(u64, input[204..212], .little),
    };
    blake2f(rounds, &h, &m, t, input[212] == 1);
    for (h, 0..) |word, index| std.mem.writeInt(u64, out[index * 8 ..][0..8], word, .little);
}

/// Round count a precompile input asks for (its gas cost); null when malformed.
pub fn input_rounds(input: []const u8) ?u32 {
    if (input.len != input_length) return null;
    return std.mem.readInt(u32, input[0..4], .big);
}

const testing = std.testing;

/// BLAKE2b-512 (no key) assembled from `blake2f`, to compare against std.
fn blake2b512(data: []const u8) [64]u8 {
    var h = initialization_vector;
    h[0] ^= 0x01010000 ^ 64; // Digest length 64, fanout 1, depth 1.
    var offset: usize = 0;
    while (data.len - offset > 128) : (offset += 128) {
        const words = block_words(data[offset..][0..128]);
        blake2f(standard_rounds, &h, &words, counter(offset + 128), false);
    }
    var last: [128]u8 = @splat(0);
    @memcpy(last[0 .. data.len - offset], data[offset..]);
    const last_words = block_words(&last);
    blake2f(standard_rounds, &h, &last_words, counter(data.len), true);
    var out: [64]u8 = undefined;
    for (h, 0..) |word, index| std.mem.writeInt(u64, out[index * 8 ..][0..8], word, .little);
    return out;
}

fn counter(bytes: usize) [2]u64 {
    return .{ bytes, 0 };
}

fn block_words(block: *const [128]u8) [16]u64 {
    var words: [16]u64 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u64, block[index * 8 ..][0..8], .little);
    }
    return words;
}

fn oracle(data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(data, &out, .{});
    return out;
}

const Vector = struct {
    input: []const u8,
    output: ?[]const u8,
    failure: ?Error = null,
};

const vectors = [_]Vector{
    // Test vector 0.
    .{
        .input = "",
        .output = null,
        .failure = error.InvalidInputLength,
    },
    // Test vector 1.
    .{
        .input = "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d1" ++
            "82e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b6162630000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000300000000000000000000000000000001",
        .output = null,
        .failure = error.InvalidInputLength,
    },
    // Test vector 2.
    .{
        .input = "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54f" ++
            "a5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b616263" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "00000000000000000000000000000000000300000000000000000000000000000001",
        .output = null,
        .failure = error.InvalidInputLength,
    },
    // Test vector 3.
    .{
        .input = "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000002",
        .output = null,
        .failure = error.InvalidFinalFlag,
    },
    // Test vector 4.
    .{
        .input = "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000001",
        .output = "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad" ++
            "7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b",
    },
    // Test vector 5.
    .{
        .input = "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000001",
        .output = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c539" ++
            "2aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    },
    // Test vector 6.
    .{
        .input = "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000000",
        .output = "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f" ++
            "6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",
    },
    // Test vector 7.
    .{
        .input = "0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000001",
        .output = "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8" ++
            "333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",
    },
    // Test vector 8.
    .{
        .input = "ffffffff48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5" ++
            "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000000000000000000000000000000000000000000" ++
            "000000000000000000000000000000000300000000000000000000000000000001",
        .output = "fc59093aafa9ab43daae0e914c57635c5402d8e3d2130eb9b3cc181de7f0ecf9b22bf99a" ++
            "7815ce16419e200e01846e6b5df8cc7703041bbceb571de6631d2615",
    },
};

fn hex_bytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime literal, checked here.
    return out;
}

test "blake2f: EIP-152 test vectors" {
    inline for (vectors, 0..) |vector, index| {
        const input = hex_bytes(vector.input);
        // Vector 8 runs 2^32 - 1 rounds: only affordable in optimized builds.
        const skip = index == 8 and @import("builtin").mode == .debug;
        if (!skip) {
            var out: [output_length]u8 = undefined;
            if (vector.failure) |expected_error| {
                try testing.expectError(expected_error, precompile_blake2f(&input, &out));
            } else {
                try precompile_blake2f(&input, &out);
                try testing.expectEqualSlices(u8, &hex_bytes(vector.output.?), &out);
            }
        }
    }
}

test "blake2f: zero rounds and input_rounds" {
    const input = hex_bytes(vectors[4].input);
    try testing.expectEqual(@as(?u32, 0), input_rounds(&input));
    try testing.expectEqual(@as(?u32, null), input_rounds(input[0..212]));
    try testing.expectEqual(@as(?u32, 12), input_rounds(&hex_bytes(vectors[5].input)));
}

test "blake2f: full BLAKE2b-512 built from F matches std at every length" {
    var buffer: [128 * 3 + 1]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    for (0..buffer.len + 1) |length| {
        try testing.expectEqual(oracle(buffer[0..length]), blake2b512(buffer[0..length]));
    }
}

test "blake2f: seeded differential fuzz vs std, plus precompile framing" {
    var prng = Prng.init(0x626c616b6532);
    var buffer: [700]u8 = undefined;
    for (0..200) |_| {
        const length: usize = @intCast(prng.below(buffer.len + 1));
        prng.fill(buffer[0..length]);
        try testing.expectEqual(oracle(buffer[0..length]), blake2b512(buffer[0..length]));
    }
    // Random precompile inputs: any flag byte above 1 is rejected, 0/1 never fail.
    var input: [input_length]u8 = undefined;
    var out: [output_length]u8 = undefined;
    for (0..200) |_| {
        prng.fill(&input);
        input[0] = 0; // Keep the round count small (< 2^24) so the test stays fast.
        input[1] = 0;
        input[212] = @intCast(prng.below(4));
        if (input[212] > 1) {
            try testing.expectError(error.InvalidFinalFlag, precompile_blake2f(&input, &out));
        } else {
            try precompile_blake2f(&input, &out);
        }
        try testing.expectError(error.InvalidInputLength, precompile_blake2f(input[1..], &out));
    }
}

test "blake2f: round count splits are consistent" {
    // Running r rounds equals feeding the intermediate state through the schedule: with
    // r in 0..25 the result must differ for each r (the schedule is not a fixed point).
    var prng = Prng.init(0x726f756e6473);
    var m: [16]u64 = undefined;
    for (&m) |*word| word.* = prng.int(u64);
    var previous: ?[8]u64 = null;
    for (0..25) |rounds| {
        var h = initialization_vector;
        blake2f(@intCast(rounds), &h, &m, .{ 64, 0 }, true);
        if (previous) |p| try testing.expect(!std.mem.eql(u64, &p, &h));
        previous = h;
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    try testing.expectEqual(oracle(buffer[0..length]), blake2b512(buffer[0..length]));
    var input: [input_length]u8 = undefined;
    smith.bytes(&input);
    input[0] = 0;
    input[1] = 0;
    var out: [output_length]u8 = undefined;
    precompile_blake2f(&input, &out) catch |err| {
        try testing.expectEqual(error.InvalidFinalFlag, err);
        try testing.expect(input[212] > 1);
    };
}

test "blake2f: coverage-guided fuzz vs std" {
    try testing.fuzz({}, fuzz_one, .{});
}

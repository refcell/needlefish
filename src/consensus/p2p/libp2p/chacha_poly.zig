//! ChaCha20-Poly1305 (RFC 8439) with a wide ChaCha20 keystream for the noise transport.
//!
//! std's ChaCha20 keeps each block's state in rows and shuffles lanes every round. Here
//! 8 blocks run at once in column layout: state word `w` of all 8 blocks lives in one
//! `@Vector(8, u32)`, so the rounds need no shuffles and only the final output is
//! transposed. On aarch64 (NEON) this is ~3.8x std's keystream speed; on x86 it is at
//! least as fast. Poly1305 is std's. Output is byte-identical to std
//! `ChaCha20Poly1305`, checked by differential tests below.

const std = @import("std");
const assert = std.debug.assert;
const Poly1305 = std.crypto.onetimeauth.Poly1305;

pub const key_length = 32;
pub const nonce_length = 12;
pub const tag_length = 16;

/// Blocks per pass: 16 for long runs (fills the register file better on NEON), 8 for the
/// tail so short messages do not pay for 1 KiB of keystream.
const lanes_wide = 16;
const lanes = 8;
const Quad = @Vector(4, u32);
const chunk_bytes = 64 * lanes;
const chunk_wide_bytes = 64 * lanes_wide;
const constants = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

comptime {
    assert(chunk_bytes == 512 and chunk_wide_bytes == 1024);
    assert(lanes % 4 == 0 and lanes_wide % 4 == 0);
}

const Keystream = struct {
    key: [8]u32,
    nonce: [3]u32,

    fn init(key: *const [key_length]u8, nonce: *const [nonce_length]u8) Keystream {
        var result: Keystream = undefined;
        for (&result.key, 0..) |*word, index| {
            word.* = std.mem.readInt(u32, key[index * 4 ..][0..4], .little);
        }
        for (&result.nonce, 0..) |*word, index| {
            word.* = std.mem.readInt(u32, nonce[index * 4 ..][0..4], .little);
        }
        return result;
    }

    inline fn quarter_round(
        comptime Word: type,
        x: *[16]Word,
        comptime a: usize,
        comptime b: usize,
        comptime c: usize,
        comptime d: usize,
    ) void {
        x[a] +%= x[b];
        x[d] = std.math.rotl(Word, x[d] ^ x[a], 16);
        x[c] +%= x[d];
        x[b] = std.math.rotl(Word, x[b] ^ x[c], 12);
        x[a] +%= x[b];
        x[d] = std.math.rotl(Word, x[d] ^ x[a], 8);
        x[c] +%= x[d];
        x[b] = std.math.rotl(Word, x[b] ^ x[c], 7);
    }

    /// Keystream blocks `counter .. counter + n` into `output`.
    fn blocks(
        keystream: *const Keystream,
        comptime n: usize,
        counter: u32,
        output: *[64 * n]u8,
    ) void {
        const Word = @Vector(n, u32);
        var x: [16]Word = undefined;
        inline for (0..4) |index| x[index] = @splat(constants[index]);
        inline for (0..8) |index| x[4 + index] = @splat(keystream.key[index]);
        x[12] = @as(Word, @splat(counter)) +% std.simd.iota(u32, n);
        inline for (0..3) |index| x[13 + index] = @splat(keystream.nonce[index]);
        const initial = x;
        var round: u32 = 0;
        while (round < 10) : (round += 1) {
            quarter_round(Word, &x, 0, 4, 8, 12);
            quarter_round(Word, &x, 1, 5, 9, 13);
            quarter_round(Word, &x, 2, 6, 10, 14);
            quarter_round(Word, &x, 3, 7, 11, 15);
            quarter_round(Word, &x, 0, 5, 10, 15);
            quarter_round(Word, &x, 1, 6, 11, 12);
            quarter_round(Word, &x, 2, 7, 8, 13);
            quarter_round(Word, &x, 3, 4, 9, 14);
        }
        inline for (0..16) |index| x[index] +%= initial[index];
        inline for (0..n / 4) |half| {
            inline for (0..4) |group| transpose(n, &x, half, group, output);
        }
    }

    /// Writes words `4*group .. 4*group+3` of blocks `4*half .. 4*half+3`.
    inline fn transpose(
        comptime n: usize,
        x: *const [16]@Vector(n, u32),
        comptime half: usize,
        comptime group: usize,
        output: *[64 * n]u8,
    ) void {
        const select = comptime blk: {
            var mask: [4]i32 = undefined;
            for (&mask, 0..) |*item, index| item.* = @intCast(half * 4 + index);
            break :blk mask;
        };
        const a: Quad = @shuffle(u32, x[4 * group], undefined, select);
        const b: Quad = @shuffle(u32, x[4 * group + 1], undefined, select);
        const c: Quad = @shuffle(u32, x[4 * group + 2], undefined, select);
        const d: Quad = @shuffle(u32, x[4 * group + 3], undefined, select);
        const ab_low = @shuffle(u32, a, b, [4]i32{ 0, -1, 1, -2 });
        const ab_high = @shuffle(u32, a, b, [4]i32{ 2, -3, 3, -4 });
        const cd_low = @shuffle(u32, c, d, [4]i32{ 0, -1, 1, -2 });
        const cd_high = @shuffle(u32, c, d, [4]i32{ 2, -3, 3, -4 });
        const rows = [4]Quad{
            @shuffle(u32, ab_low, cd_low, [4]i32{ 0, 1, -1, -2 }),
            @shuffle(u32, ab_low, cd_low, [4]i32{ 2, 3, -3, -4 }),
            @shuffle(u32, ab_high, cd_high, [4]i32{ 0, 1, -1, -2 }),
            @shuffle(u32, ab_high, cd_high, [4]i32{ 2, 3, -3, -4 }),
        };
        inline for (rows, 0..) |row, block| {
            const offset = (half * 4 + block) * 64 + group * 16;
            output[offset..][0..16].* = @bitCast(std.mem.nativeToLittle(Quad, row));
        }
    }
};

/// `output = input XOR keystream(counter..)`. `output` and `input` may alias exactly.
pub fn chacha20_xor(
    output: []u8,
    input: []const u8,
    counter: u32,
    key: *const [key_length]u8,
    nonce: *const [nonce_length]u8,
) void {
    assert(output.len == input.len);
    // The 32-bit block counter must not wrap inside one message.
    assert(input.len / 64 <= std.math.maxInt(u32) - counter);
    const keystream = Keystream.init(key, nonce);
    var block_counter = counter;
    var offset: usize = 0;
    while (input.len - offset >= chunk_wide_bytes) : (offset += chunk_wide_bytes) {
        var wide: [chunk_wide_bytes]u8 = undefined;
        keystream.blocks(lanes_wide, block_counter, &wide);
        block_counter +%= lanes_wide;
        const plain: @Vector(chunk_wide_bytes, u8) = input[offset..][0..chunk_wide_bytes].*;
        const pad: @Vector(chunk_wide_bytes, u8) = wide;
        output[offset..][0..chunk_wide_bytes].* = plain ^ pad;
    }
    var stream: [chunk_bytes]u8 = undefined;
    while (offset < input.len) : (offset += chunk_bytes) {
        keystream.blocks(lanes, block_counter, &stream);
        block_counter +%= lanes;
        const length = @min(chunk_bytes, input.len - offset);
        if (length == chunk_bytes) {
            const plain: @Vector(chunk_bytes, u8) = input[offset..][0..chunk_bytes].*;
            const pad: @Vector(chunk_bytes, u8) = stream;
            output[offset..][0..chunk_bytes].* = plain ^ pad;
        } else {
            for (output[offset..][0..length], input[offset..][0..length], 0..) |*out, in, i| {
                out.* = in ^ stream[i];
            }
        }
    }
}

fn poly1305_tag(
    tag: *[tag_length]u8,
    ad: []const u8,
    ciphertext: []const u8,
    key: *const [key_length]u8,
    nonce: *const [nonce_length]u8,
) void {
    var block: [64]u8 = @splat(0);
    chacha20_xor(&block, &block, 0, key, nonce);
    var mac = Poly1305.init(block[0..32]);
    const zeros: [16]u8 = @splat(0);
    mac.update(ad);
    mac.update(zeros[0 .. (16 - ad.len % 16) % 16]);
    mac.update(ciphertext);
    mac.update(zeros[0 .. (16 - ciphertext.len % 16) % 16]);
    var lengths: [16]u8 = undefined;
    std.mem.writeInt(u64, lengths[0..8], ad.len, .little);
    std.mem.writeInt(u64, lengths[8..16], ciphertext.len, .little);
    mac.update(&lengths);
    mac.final(tag);
}

pub fn encrypt(
    ciphertext: []u8,
    tag: *[tag_length]u8,
    plaintext: []const u8,
    ad: []const u8,
    nonce: [nonce_length]u8,
    key: [key_length]u8,
) void {
    assert(ciphertext.len == plaintext.len);
    chacha20_xor(ciphertext, plaintext, 1, &key, &nonce);
    poly1305_tag(tag, ad, ciphertext, &key, &nonce);
    assert(ciphertext.len == plaintext.len);
}

pub fn decrypt(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [tag_length]u8,
    ad: []const u8,
    nonce: [nonce_length]u8,
    key: [key_length]u8,
) error{AuthenticationFailed}!void {
    assert(plaintext.len == ciphertext.len);
    var expected: [tag_length]u8 = undefined;
    poly1305_tag(&expected, ad, ciphertext, &key, &nonce);
    if (!std.crypto.timing_safe.eql([tag_length]u8, expected, tag)) {
        return error.AuthenticationFailed;
    }
    chacha20_xor(plaintext, ciphertext, 1, &key, &nonce);
}

// --------------------------------------------------------------------------- tests

const testing = std.testing;
const StdAead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

test "chacha_poly: RFC 8439 section 2.8.2 vector" {
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one " ++
        "tip for the future, sunscreen would be it.";
    const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    var key: [32]u8 = undefined;
    for (&key, 0..) |*byte, index| byte.* = @intCast(0x80 + index);
    const nonce = [_]u8{ 7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encrypt(&ciphertext, &tag, plaintext, &ad, nonce, key);
    var expected_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, "1ae10b594f09e26a7e902ecbd0600691");
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    var expected_start: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_start, "d31a8d34648e60db");
    try testing.expectEqualSlices(u8, &expected_start, ciphertext[0..8]);
    var opened: [plaintext.len]u8 = undefined;
    try decrypt(&opened, &ciphertext, tag, &ad, nonce, key);
    try testing.expectEqualStrings(plaintext, &opened);
    tag[0] ^= 1;
    const result = decrypt(&opened, &ciphertext, tag, &ad, nonce, key);
    try testing.expectError(error.AuthenticationFailed, result);
}

fn check_against_std(random: std.Random, buffer: []u8, length: usize) !void {
    assert(length * 3 <= buffer.len);
    const plaintext = buffer[0..length];
    const ours = buffer[length .. 2 * length];
    const theirs = buffer[2 * length .. 3 * length];
    random.bytes(plaintext);
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    var ad: [40]u8 = undefined;
    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&ad);
    const ad_length = random.uintAtMost(usize, ad.len);
    var tag_ours: [16]u8 = undefined;
    var tag_theirs: [16]u8 = undefined;
    encrypt(ours, &tag_ours, plaintext, ad[0..ad_length], nonce, key);
    StdAead.encrypt(theirs, &tag_theirs, plaintext, ad[0..ad_length], nonce, key);
    try testing.expectEqualSlices(u8, theirs, ours);
    try testing.expectEqualSlices(u8, &tag_theirs, &tag_ours);
    try decrypt(theirs, ours, tag_ours, ad[0..ad_length], nonce, key);
    try testing.expectEqualSlices(u8, plaintext, theirs);
}

test "chacha_poly: matches std at chunk boundaries and random lengths" {
    const buffer = try testing.allocator.alloc(u8, 3 * 70_000);
    defer testing.allocator.free(buffer);
    var prng = Prng.init(0x6368_6163);
    const random = prng.random();
    const edges = [_]usize{
        0,    1,    63,   64,   65,   511,  512,  513,   1023,
        1024, 1025, 1536, 1537, 2047, 2048, 2049, 65535,
    };
    for (edges) |length| try check_against_std(random, buffer, length);
    for (0..64) |_| try check_against_std(random, buffer, random.uintLessThan(usize, 70_000));
}

const FuzzContext = struct {};

fn fuzz_one(_: FuzzContext, input: []const u8) anyerror!void {
    if (input.len < 8) return;
    var prng = Prng.init(std.mem.readInt(u64, input[0..8], .little));
    var buffer: [3 * 2048]u8 = undefined;
    const length = @min(input.len - 8, 2048);
    try check_against_std(prng.random(), &buffer, length);
}

test "chacha_poly: fuzz against std" {
    try fuzz.run_bytes(FuzzContext{}, fuzz_one, fuzz.Options{ .input_size_max = 2056 });
}

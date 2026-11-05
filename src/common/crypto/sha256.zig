//! SHA-256 (FIPS 180-4), the EVM precompile at address 0x02.
//!
//! On aarch64 with the SHA2 extension the compression function uses the ARMv8 SHA2
//! instructions: the message schedule goes through the LLVM `sha256su0/su1`
//! intrinsics and the rounds through inline asm (the LLVM `sha256h/h2` intrinsics
//! measured ~10% slower because the register allocator puts a vector copy on the
//! critical dependency chain). Every other target uses a scalar version.
//! `std.crypto.hash.sha2.Sha256` is used only as a test oracle.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const digest_length = 32;
pub const block_length = 64;
pub const Digest = [digest_length]u8;

/// True when the compression function uses the ARMv8 SHA2 instructions.
pub const hardware_accelerated = builtin.cpu.arch == .aarch64 and
    builtin.zig_backend != .stage2_c and builtin.cpu.has(.aarch64, .sha2);

comptime {
    assert(block_length == 64);
    assert(digest_length * 2 == block_length);
}

const initial_state = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

const round_constants = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const V4u32 = @Vector(4, u32);

extern fn @"llvm.aarch64.crypto.sha256su0"(V4u32, V4u32) V4u32;
extern fn @"llvm.aarch64.crypto.sha256su1"(V4u32, V4u32, V4u32) V4u32;

/// Compresses two runs of whole 64-byte blocks into `state`. Taking both runs in
/// one call lets the hardware path hoist the round constants into registers once
/// per hash (message body plus padded tail) instead of once per run.
pub fn compress(state: *[8]u32, first: []const u8, second: []const u8) void {
    assert(first.len % block_length == 0);
    assert(second.len % block_length == 0);
    if (hardware_accelerated) {
        compress_hardware(state, first, second);
    } else {
        compress_scalar(state, first);
        compress_scalar(state, second);
    }
}

fn compress_hardware(state: *[8]u32, first: []const u8, second: []const u8) void {
    comptime assert(hardware_accelerated);
    var abcd: V4u32 = state[0..4].*;
    var efgh: V4u32 = state[4..8].*;
    for ([2][]const u8{ first, second }) |blocks| {
        var offset: usize = 0;
        while (offset < blocks.len) : (offset += block_length) {
            hardware_block(&abcd, &efgh, blocks[offset..][0..block_length]);
        }
    }
    state[0..4].* = abcd;
    state[4..8].* = efgh;
}

inline fn hardware_block(abcd: *V4u32, efgh: *V4u32, block: *const [block_length]u8) void {
    var words: [4]V4u32 = undefined;
    inline for (0..4) |group| {
        const raw: *align(1) const V4u32 = @ptrCast(block[group * 16 ..][0..16]);
        words[group] = byte_swap_lanes(raw.*);
    }
    const saved_abcd = abcd.*;
    const saved_efgh = efgh.*;
    var state_abcd = abcd.*;
    var state_efgh = efgh.*;
    inline for (0..16) |group| {
        if (group >= 4) {
            words[group % 4] = @"llvm.aarch64.crypto.sha256su1"(
                @"llvm.aarch64.crypto.sha256su0"(words[group % 4], words[(group + 1) % 4]),
                words[(group + 2) % 4],
                words[(group + 3) % 4],
            );
        }
        const sum = words[group % 4] +% @as(V4u32, round_constants[group * 4 ..][0..4].*);
        // The copy of the old abcd feeds h2 off the critical chain; h works in place.
        asm volatile (
            \\mov.4s v0, %[abcd]
            \\sha256h.4s %[abcd], %[efgh], %[sum]
            \\sha256h2.4s %[efgh], v0, %[sum]
            : [abcd] "=w" (state_abcd),
              [efgh] "=w" (state_efgh),
            : [_] "0" (state_abcd),
              [_] "1" (state_efgh),
              [sum] "w" (sum),
            : .{ .v0 = true });
    }
    abcd.* = state_abcd +% saved_abcd;
    efgh.* = state_efgh +% saved_efgh;
}

inline fn byte_swap_lanes(vector: V4u32) V4u32 {
    return @byteSwap(vector);
}

inline fn rotr(value: u32, comptime amount: u5) u32 {
    return std.math.rotr(u32, value, amount);
}

fn compress_scalar(state: *[8]u32, blocks: []const u8) void {
    var offset: usize = 0;
    while (offset < blocks.len) : (offset += block_length) {
        var schedule: [16]u32 = undefined;
        for (&schedule, 0..) |*word, index| {
            word.* = std.mem.readInt(u32, blocks[offset + index * 4 ..][0..4], .big);
        }
        var v = state.*;
        inline for (0..64) |step| {
            if (step >= 16) {
                const w15 = schedule[(step + 1) % 16];
                const w2 = schedule[(step + 14) % 16];
                const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
                const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
                schedule[step % 16] +%= s0 +% s1 +% schedule[(step + 9) % 16];
            }
            const big1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
            const choose = (v[4] & v[5]) ^ (~v[4] & v[6]);
            const t1 = v[7] +% big1 +% choose +% round_constants[step] +% schedule[step % 16];
            const big0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
            const majority = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] +% t1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1 +% big0 +% majority;
        }
        for (state, v) |*word, add| word.* +%= add;
    }
}

fn write_digest(state: *const [8]u32) Digest {
    var out: Digest = undefined;
    for (state, 0..) |word, index| std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .big);
    return out;
}

/// Fills `block_tail` with 0x80, zeros and the bit length; returns how many
/// blocks (1 or 2) of `tail_buffer` are valid. `used` is the bytes already in it.
fn pad(tail_buffer: *[2 * block_length]u8, used: usize, total_bytes: u64) usize {
    assert(used < block_length);
    @memset(tail_buffer[used..], 0);
    tail_buffer[used] = 0x80;
    const blocks: usize = if (used + 1 + 8 <= block_length) 1 else 2;
    const end = blocks * block_length;
    std.mem.writeInt(u64, tail_buffer[end - 8 ..][0..8], total_bytes *% 8, .big);
    assert(blocks == 1 or blocks == 2);
    return blocks;
}

/// One-shot SHA-256.
pub fn sha256(data: []const u8) Digest {
    var state = initial_state;
    const whole = data.len - data.len % block_length;
    var tail: [2 * block_length]u8 = undefined;
    const used = data.len - whole;
    @memcpy(tail[0..used], data[whole..]);
    const blocks = pad(&tail, used, data.len);
    compress(&state, data[0..whole], tail[0 .. blocks * block_length]);
    return write_digest(&state);
}

/// Streaming SHA-256. No allocation; state lives inline.
pub const Hasher = struct {
    state: [8]u32 = initial_state,
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
            compress(&hasher.state, &hasher.buffer, "");
            hasher.buffer_len = 0;
        }
        const whole = remaining.len - remaining.len % block_length;
        compress(&hasher.state, remaining[0..whole], "");
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
        compress(&hasher.state, tail[0 .. blocks * block_length], "");
        hasher.buffer_len = 0;
        return write_digest(&hasher.state);
    }
};

/// Precompile 0x02: the digest is the output as is.
pub fn precompile_sha256(input: []const u8) Digest {
    return sha256(input);
}

fn hex_to_digest(comptime hex: *const [64]u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime literal, checked here.
    return out;
}

fn oracle(data: []const u8) Digest {
    var out: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

const testing = std.testing;

test "sha256: known vectors" {
    try testing.expectEqual(
        hex_to_digest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        sha256(""),
    );
    try testing.expectEqual(
        hex_to_digest("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        sha256("abc"),
    );
    try testing.expectEqual(
        hex_to_digest("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    );
}

test "sha256: one million 'a'" {
    var hasher = Hasher.init();
    const chunk: [1000]u8 = @splat('a');
    for (0..1000) |_| hasher.update(&chunk);
    try testing.expectEqual(
        hex_to_digest("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        hasher.final(),
    );
}

test "sha256: matches std oracle at every length around block boundaries" {
    var buffer: [block_length * 4]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    for (0..buffer.len + 1) |length| {
        try testing.expectEqual(oracle(buffer[0..length]), sha256(buffer[0..length]));
    }
}

test "sha256: scalar path matches std oracle" {
    var buffer: [block_length * 3]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 13 +% 5);
    var state = initial_state;
    compress_scalar(&state, &buffer);
    var expected = initial_state;
    compress(&expected, &buffer, "");
    try testing.expectEqual(expected, state);
}

test "sha256: seeded differential fuzz (one-shot, streaming)" {
    var prng = Prng.init(0x73686132353600);
    var buffer: [1024]u8 = undefined;
    for (0..300) |_| {
        const length: usize = @intCast(prng.below(buffer.len + 1));
        prng.fill(buffer[0..length]);
        const expected = oracle(buffer[0..length]);
        try testing.expectEqual(expected, sha256(buffer[0..length]));

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
    try testing.expectEqual(oracle(data), sha256(data));
    var hasher = Hasher.init();
    const split = length / 3;
    hasher.update(data[0..split]);
    hasher.update(data[split..]);
    try testing.expectEqual(oracle(data), hasher.final());
}

test "sha256: coverage-guided fuzz vs std" {
    try testing.fuzz({}, fuzz_one, .{});
}

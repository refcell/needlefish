//! Keccak-256 (the original Keccak padding used by Ethereum, not NIST SHA3-256).
//!
//! The permutation is written once over a generic lane type, so the same code
//! serves the scalar path (`u64`) and the multi-lane SIMD path (`@Vector(n, u64)`),
//! which hashes several equal-length messages at once (e.g. trie keys).
//! `std.crypto.hash.sha3.Keccak256` is used only as a test oracle.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../../testing/prng.zig").Prng;

pub const digest_length = 32;
pub const Digest = [digest_length]u8;

/// Sponge rate for a 256-bit capacity-512 Keccak: 1088 bits.
pub const rate_bytes = 136;
const rate_lanes = rate_bytes / 8;

comptime {
    assert(rate_bytes % 8 == 0);
    assert(rate_lanes == 17);
    assert(rate_lanes < 25);
}

/// keccak256("") — the empty code hash.
pub const empty_digest: Digest = hex_to_digest(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
);

const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

/// The pi step permutes the 24 non-origin lanes in a single cycle starting at
/// lane 1; `pi_cycle[t]` is the t-th destination and `rho_cycle[t]` the rotation
/// applied to the lane moved there: (t + 1)(t + 2) / 2 mod 64.
const pi_cycle = [24]u8{
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};
const rho_cycle: [24]u6 = blk: {
    var table: [24]u6 = undefined;
    for (0..24) |step| table[step] = @intCast(((step + 1) * (step + 2) / 2) % 64);
    break :blk table;
};

comptime {
    // The cycle visits every non-origin lane exactly once and closes at lane 1.
    var seen: [25]bool = @splat(false);
    for (pi_cycle) |lane| {
        assert(lane != 0);
        assert(!seen[lane]);
        seen[lane] = true;
    }
    assert(pi_cycle[23] == 1);
}

inline fn splat(comptime Lane: type, value: u64) Lane {
    return if (Lane == u64) value else @splat(value);
}

inline fn shift_amount(comptime Lane: type, comptime amount: u7) ShiftType(Lane) {
    return if (Lane == u64) @intCast(amount) else @splat(@intCast(amount));
}

fn ShiftType(comptime Lane: type) type {
    if (Lane == u64) return u6;
    return @Vector(@typeInfo(Lane).vector.len, u6);
}

inline fn rotl(comptime Lane: type, value: Lane, comptime amount: u6) Lane {
    if (amount == 0) return value;
    return (value << shift_amount(Lane, amount)) |
        (value >> shift_amount(Lane, @as(u7, 64) - amount));
}

inline fn round(comptime Lane: type, state: *[25]Lane, round_constant: u64) void {
    // Theta, applied in place so only 25 + 5 lanes are live (fits in registers).
    var parity: [5]Lane = undefined;
    inline for (0..5) |x| {
        parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    inline for (0..5) |x| {
        const theta = parity[(x + 4) % 5] ^ rotl(Lane, parity[(x + 1) % 5], 1);
        inline for (0..5) |y| state[x + 5 * y] ^= theta;
    }
    // Rho and pi as one in-place cycle through the 24 non-origin lanes.
    var carried = state[1];
    inline for (pi_cycle, 0..) |destination, step| {
        const displaced = state[destination];
        state[destination] = rotl(Lane, carried, rho_cycle[step]);
        carried = displaced;
    }
    // Chi, row by row.
    var row: [5]Lane = undefined;
    inline for (0..5) |y| {
        inline for (0..5) |x| row[x] = state[x + 5 * y];
        inline for (0..5) |x| {
            state[x + 5 * y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5]);
        }
    }
    state[0] ^= splat(Lane, round_constant);
}

/// Keccak-f[1600] over any lane type (scalar or vector of lanes).
pub fn permute(comptime Lane: type, state: *[25]Lane) void {
    comptime assert(Lane == u64 or @typeInfo(Lane).vector.child == u64);
    // Work on a local copy so the optimizer can keep the lanes in registers.
    // Measured on aarch64: no unrolling beats 2/3/4/6/24-way unrolling.
    var local = state.*;
    for (round_constants) |round_constant| round(Lane, &local, round_constant);
    state.* = local;
}

inline fn absorb_block(state: *[25]u64, block: *const [rate_bytes]u8) void {
    inline for (0..rate_lanes) |lane| {
        state[lane] ^= std.mem.readInt(u64, block[lane * 8 ..][0..8], .little);
    }
    permute(u64, state);
}

fn squeeze(state: *const [25]u64) Digest {
    var out: Digest = undefined;
    inline for (0..4) |lane| {
        std.mem.writeInt(u64, out[lane * 8 ..][0..8], state[lane], .little);
    }
    return out;
}

/// One-shot Keccak-256.
pub fn keccak256(data: []const u8) Digest {
    var state: [25]u64 = @splat(0);
    var remaining = data;
    while (remaining.len >= rate_bytes) {
        absorb_block(&state, remaining[0..rate_bytes]);
        remaining = remaining[rate_bytes..];
    }
    assert(remaining.len < rate_bytes);
    var last: [rate_bytes]u8 = @splat(0);
    @memcpy(last[0..remaining.len], remaining);
    last[remaining.len] ^= 0x01;
    last[rate_bytes - 1] ^= 0x80;
    absorb_block(&state, &last);
    return squeeze(&state);
}

/// Streaming Keccak-256. No allocation; state lives inline.
pub const Hasher = struct {
    state: [25]u64 = @splat(0),
    buffer: [rate_bytes]u8 = undefined,
    buffer_len: u8 = 0,

    pub fn init() Hasher {
        return .{};
    }

    pub fn update(hasher: *Hasher, data: []const u8) void {
        assert(hasher.buffer_len < rate_bytes);
        var remaining = data;
        if (hasher.buffer_len > 0) {
            const take = @min(remaining.len, rate_bytes - hasher.buffer_len);
            @memcpy(hasher.buffer[hasher.buffer_len..][0..take], remaining[0..take]);
            hasher.buffer_len += @intCast(take);
            remaining = remaining[take..];
            if (hasher.buffer_len < rate_bytes) return;
            absorb_block(&hasher.state, &hasher.buffer);
            hasher.buffer_len = 0;
        }
        while (remaining.len >= rate_bytes) {
            absorb_block(&hasher.state, remaining[0..rate_bytes]);
            remaining = remaining[rate_bytes..];
        }
        @memcpy(hasher.buffer[0..remaining.len], remaining);
        hasher.buffer_len = @intCast(remaining.len);
        assert(hasher.buffer_len < rate_bytes);
    }

    pub fn final(hasher: *Hasher) Digest {
        assert(hasher.buffer_len < rate_bytes);
        const used = hasher.buffer_len;
        @memset(hasher.buffer[used..], 0);
        hasher.buffer[used] ^= 0x01;
        hasher.buffer[rate_bytes - 1] ^= 0x80;
        absorb_block(&hasher.state, &hasher.buffer);
        hasher.buffer_len = 0;
        return squeeze(&hasher.state);
    }
};

/// Number of messages hashed together by `keccak256_batch`.
pub const batch_width: comptime_int = batch_width_for_target();

/// Match the batch width to the native vector register: 2 lanes on 128-bit NEON
/// (where LLVM emits the ARMv8.2 SHA3 instructions EOR3/BCAX/XAR/RAX1), 4 on
/// AVX2, 8 on AVX-512.
fn batch_width_for_target() comptime_int {
    const builtin = @import("builtin");
    const cpu = builtin.cpu;
    if (cpu.arch.isX86()) {
        if (std.Target.x86.featureSetHas(cpu.features, .avx512f)) return 8;
        if (std.Target.x86.featureSetHas(cpu.features, .avx2)) return 4;
    }
    return 2;
}
const BatchLane = @Vector(batch_width, u64);

fn absorb_batch_block(
    state: *[25]BatchLane,
    inputs: *const [batch_width][]const u8,
    offset: usize,
    padded: *const [batch_width][rate_bytes]u8,
    use_padded: bool,
) void {
    inline for (0..rate_lanes) |lane| {
        var words: [batch_width]u64 = undefined;
        inline for (0..batch_width) |message| {
            const block = if (use_padded)
                padded[message][lane * 8 ..][0..8]
            else
                inputs[message][offset + lane * 8 ..][0..8];
            words[message] = std.mem.readInt(u64, block, .little);
        }
        state[lane] ^= @as(BatchLane, words);
    }
    permute(BatchLane, state);
}

/// Hashes `batch_width` messages of identical length at once with SIMD lanes.
pub fn keccak256_batch(inputs: *const [batch_width][]const u8, out: *[batch_width]Digest) void {
    const length = inputs[0].len;
    for (inputs) |input| assert(input.len == length);

    var state: [25]BatchLane = @splat(@splat(0));
    var offset: usize = 0;
    var unused: [batch_width][rate_bytes]u8 = undefined;
    while (length - offset >= rate_bytes) : (offset += rate_bytes) {
        absorb_batch_block(&state, inputs, offset, &unused, false);
    }
    const tail = length - offset;
    assert(tail < rate_bytes);
    var padded: [batch_width][rate_bytes]u8 = undefined;
    for (&padded, inputs) |*block, input| {
        @memset(block, 0);
        @memcpy(block[0..tail], input[offset..]);
        block[tail] ^= 0x01;
        block[rate_bytes - 1] ^= 0x80;
    }
    absorb_batch_block(&state, inputs, offset, &padded, true);
    inline for (0..4) |lane| {
        const words: [batch_width]u64 = state[lane];
        for (out, words) |*digest, word| {
            std.mem.writeInt(u64, digest[lane * 8 ..][0..8], word, .little);
        }
    }
}

fn hex_to_digest(comptime hex: *const [64]u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime literal, checked here.
    return out;
}

fn oracle(data: []const u8) Digest {
    var out: Digest = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &out, .{});
    return out;
}

const testing = std.testing;

test "keccak256: known vectors" {
    try testing.expectEqual(empty_digest, keccak256(""));
    try testing.expectEqual(
        hex_to_digest("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        keccak256("abc"),
    );
    // Transfer(address,address,uint256) event topic.
    try testing.expectEqual(
        hex_to_digest("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
        keccak256("Transfer(address,address,uint256)"),
    );
}

test "keccak256: matches std oracle at every length around block boundaries" {
    var buffer: [rate_bytes * 4]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    for (0..buffer.len + 1) |length| {
        try testing.expectEqual(oracle(buffer[0..length]), keccak256(buffer[0..length]));
    }
}

test "keccak256: seeded differential fuzz (one-shot, streaming, batch)" {
    var prng = Prng.init(0x6b656363616b);
    var buffer: [1024]u8 = undefined;
    for (0..300) |_| {
        const length: usize = @intCast(prng.below(buffer.len + 1));
        prng.fill(buffer[0..length]);
        const expected = oracle(buffer[0..length]);
        try testing.expectEqual(expected, keccak256(buffer[0..length]));

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
    var messages: [batch_width][300]u8 = undefined;
    for (0..64) |_| {
        const length: usize = @intCast(prng.below(301));
        var inputs: [batch_width][]const u8 = undefined;
        for (&messages, &inputs) |*message, *input| {
            prng.fill(message[0..length]);
            input.* = message[0..length];
        }
        var digests: [batch_width]Digest = undefined;
        keccak256_batch(&inputs, &digests);
        for (inputs, digests) |input, digest| try testing.expectEqual(oracle(input), digest);
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [2048]u8 = undefined;
    const length = smith.slice(&buffer);
    const data = buffer[0..length];
    try testing.expectEqual(oracle(data), keccak256(data));
    var hasher = Hasher.init();
    const split = length / 3;
    hasher.update(data[0..split]);
    hasher.update(data[split..]);
    try testing.expectEqual(oracle(data), hasher.final());
}

test "keccak256: coverage-guided fuzz vs std" {
    try testing.fuzz({}, fuzz_one, .{});
}

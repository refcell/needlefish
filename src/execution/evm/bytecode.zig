//! Bytecode analysis: a zero-padded copy of the code plus a JUMPDEST bitmap.
//!
//! Padding lets the interpreter read PUSH immediates and the next opcode without
//! bounds checks: running off the end reads 0x00 (STOP), exactly the EVM rule.
//! Analysis memory comes from a LIFO `Arena` that mirrors the frame stack.

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const op = @import("opcode.zig");

/// Enough zero bytes for a PUSH32 on the last byte plus a trailing STOP.
pub const padding_bytes = 33;

pub const Analyzed = struct {
    /// Code followed by `padding_bytes` zeros.
    code: []const u8,
    /// Length of the original code.
    len: u32,
    /// Bit `i` set when byte `i` is a JUMPDEST opcode (not PUSH data).
    jumpdests: []const u8,

    pub inline fn is_jumpdest(analyzed: *const Analyzed, destination: u256) bool {
        if (destination >= analyzed.len) return false;
        const index: u32 = @intCast(destination);
        return (analyzed.jumpdests[index >> 3] >> @intCast(index & 7)) & 1 == 1;
    }

    /// The original code without padding.
    pub fn original(analyzed: *const Analyzed) []const u8 {
        return analyzed.code[0..analyzed.len];
    }
};

pub fn analysis_bytes(code_len: usize) usize {
    return code_len + padding_bytes + (code_len + 7) / 8;
}

/// Analyze `code` into `out`, which must be exactly `analysis_bytes(code.len)` long.
pub fn analyze(code: []const u8, out: []u8) Analyzed {
    assert(out.len == analysis_bytes(code.len));
    assert(code.len <= std.math.maxInt(u32));
    const padded = out[0 .. code.len + padding_bytes];
    const bitmap = out[code.len + padding_bytes ..];
    @memcpy(padded[0..code.len], code);
    @memset(padded[code.len..], 0);
    @memset(bitmap, 0);
    var pc: usize = 0;
    while (pc < code.len) {
        const byte = code[pc];
        if (byte == op.JUMPDEST) {
            bitmap[pc >> 3] |= @as(u8, 1) << @intCast(pc & 7);
            pc += 1;
        } else if (byte >= op.PUSH1 and byte <= op.PUSH32) {
            pc += @as(usize, byte - op.PUSH1) + 2;
        } else {
            pc += 1;
        }
    }
    return .{ .code = padded, .len = @intCast(code.len), .jumpdests = bitmap };
}

/// LIFO bump allocator for analyses. `mark` before a frame, `release` when it ends.
pub const Arena = struct {
    buffer: []u8,
    used: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity_bytes: usize) !Arena {
        assert(capacity_bytes > 0);
        return .{ .buffer = try lazy.alloc(allocator, u8, capacity_bytes) };
    }

    pub fn deinit(arena: *Arena, allocator: std.mem.Allocator) void {
        lazy.free(allocator, arena.buffer);
        arena.* = undefined;
    }

    pub fn analyze_code(arena: *Arena, code: []const u8) error{CodeArenaFull}!Analyzed {
        const size = analysis_bytes(code.len);
        if (arena.buffer.len - arena.used < size) return error.CodeArenaFull;
        const out = arena.buffer[arena.used..][0..size];
        arena.used += size;
        assert(arena.used <= arena.buffer.len);
        return analyze(code, out);
    }

    pub fn mark(arena: *const Arena) usize {
        return arena.used;
    }

    pub fn release(arena: *Arena, position: usize) void {
        assert(position <= arena.used);
        arena.used = position;
    }
};

/// Process-lifetime analyses keyed by code hash. Code behind a hash never changes, so an
/// entry stays valid across transactions, blocks, and reorgs. Bounded twice: a fixed open-
/// addressed table (kept at most 3/4 full) and a fixed byte buffer. Entries are append-only
/// while frames may reference them; when full, `put` returns null (the caller falls back to
/// the frame arena) and `reset` runs only once no frame is live.
pub const AnalysisCache = struct {
    buffer: []u8,
    used: usize = 0,
    entries: []Entry,
    count: u32 = 0,
    full: bool = false,

    const Entry = struct {
        hash: [32]u8,
        analyzed: Analyzed,
        occupied: bool,
    };

    pub fn init(allocator: std.mem.Allocator, bytes: usize, entries_count: u32) !AnalysisCache {
        assert(std.math.isPowerOfTwo(entries_count));
        assert(entries_count >= 4);
        const buffer = try lazy.alloc(allocator, u8, bytes);
        errdefer lazy.free(allocator, buffer);
        const entries = try allocator.alloc(Entry, entries_count);
        for (entries) |*entry| entry.occupied = false;
        return .{ .buffer = buffer, .entries = entries };
    }

    pub fn deinit(cache: *AnalysisCache, allocator: std.mem.Allocator) void {
        lazy.free(allocator, cache.buffer);
        allocator.free(cache.entries);
        cache.* = undefined;
    }

    fn slot(cache: *const AnalysisCache, hash: *const [32]u8) usize {
        // The key is a keccak output: its leading bytes are already uniformly distributed.
        const mask = cache.entries.len - 1;
        return @as(usize, @truncate(std.mem.readInt(u64, hash[0..8], .little))) & mask;
    }

    /// The analysis of the code with `hash`, or null when it is not cached.
    pub fn get(cache: *const AnalysisCache, hash: *const [32]u8) ?Analyzed {
        var index = cache.slot(hash);
        var probes: usize = 0;
        while (probes < cache.entries.len) : (probes += 1) {
            const entry = &cache.entries[index];
            if (!entry.occupied) return null;
            if (std.mem.eql(u8, &entry.hash, hash)) return entry.analyzed;
            index = (index + 1) & (cache.entries.len - 1);
        }
        unreachable; // The table is never more than 3/4 full, so a probe meets an empty slot.
    }

    /// Analyze `code` (whose keccak is `hash`) into the cache; null when the cache is full.
    pub fn put(cache: *AnalysisCache, hash: *const [32]u8, code: []const u8) ?Analyzed {
        assert(cache.get(hash) == null);
        const size = analysis_bytes(code.len);
        const table_full = (cache.count + 1) * 4 > cache.entries.len * 3;
        if (table_full or cache.buffer.len - cache.used < size) {
            cache.full = true;
            return null;
        }
        const analyzed = analyze(code, cache.buffer[cache.used..][0..size]);
        cache.used += size;
        var index = cache.slot(hash);
        while (cache.entries[index].occupied) index = (index + 1) & (cache.entries.len - 1);
        cache.entries[index] = .{ .hash = hash.*, .analyzed = analyzed, .occupied = true };
        cache.count += 1;
        assert(cache.used <= cache.buffer.len);
        return analyzed;
    }

    /// Drop every entry. Only valid while no frame references an analysis.
    pub fn reset(cache: *AnalysisCache) void {
        for (cache.entries) |*entry| entry.occupied = false;
        cache.used = 0;
        cache.count = 0;
        cache.full = false;
    }
};

/// EIP-7702 delegation designator: 0xef0100 followed by a 20-byte address.
pub const delegation_prefix = [3]u8{ 0xef, 0x01, 0x00 };
pub const delegation_len = 23;

pub fn delegation_target(code: []const u8) ?[20]u8 {
    if (code.len != delegation_len) return null;
    if (!std.mem.eql(u8, code[0..3], &delegation_prefix)) return null;
    return code[3..23].*;
}

test "bytecode: analysis cache hits, fills, and resets" {
    var cache = try AnalysisCache.init(std.testing.allocator, 256, 8);
    defer cache.deinit(std.testing.allocator);
    const code = [_]u8{ op.PUSH1, op.JUMPDEST, op.JUMPDEST };
    var hashes: [8][32]u8 = undefined;
    for (&hashes, 0..) |*hash, index| hash.* = @splat(@intCast(index));
    try std.testing.expect(cache.get(&hashes[0]) == null);
    const first = cache.put(&hashes[0], &code).?;
    try std.testing.expect(first.is_jumpdest(2) and !first.is_jumpdest(1));
    try std.testing.expectEqual(first.code.ptr, cache.get(&hashes[0]).?.code.ptr);
    // Six entries fill the 8-slot table to 3/4; the seventh is refused.
    for (hashes[1..6]) |*hash| _ = cache.put(hash, &code).?;
    try std.testing.expect(cache.put(&hashes[6], &code) == null);
    try std.testing.expect(cache.full);
    for (hashes[0..6]) |*hash| try std.testing.expect(cache.get(hash) != null);
    cache.reset();
    try std.testing.expect(cache.get(&hashes[0]) == null and !cache.full);
    // A code larger than the byte buffer is refused.
    const big: [300]u8 = @splat(0);
    try std.testing.expect(cache.put(&hashes[7], &big) == null);
}

test "bytecode: jumpdests skip push data" {
    // PUSH2 0x5b5b JUMPDEST PUSH1 (truncated)
    const code = [_]u8{ op.PUSH1 + 1, 0x5b, 0x5b, op.JUMPDEST, op.PUSH1 };
    var out: [analysis_bytes(code.len)]u8 = undefined;
    const analyzed = analyze(&code, &out);
    try std.testing.expect(!analyzed.is_jumpdest(1));
    try std.testing.expect(!analyzed.is_jumpdest(2));
    try std.testing.expect(analyzed.is_jumpdest(3));
    try std.testing.expect(!analyzed.is_jumpdest(4));
    try std.testing.expect(!analyzed.is_jumpdest(1 << 100));
    try std.testing.expectEqual(@as(u8, 0), analyzed.code[code.len + 32]);
}

test "bytecode: delegation designator" {
    var code: [23]u8 = undefined;
    code[0..3].* = delegation_prefix;
    @memset(code[3..], 0x11);
    try std.testing.expectEqual(@as(u8, 0x11), delegation_target(&code).?[19]);
    try std.testing.expect(delegation_target(code[0..22]) == null);
}

test "bytecode: fuzz analysis never reads out of bounds" {
    const Prng = @import("../../testing/prng.zig").Prng;
    var prng = Prng.init(0x5eed);
    var code: [512]u8 = undefined;
    var out: [analysis_bytes(512)]u8 = undefined;
    for (0..256) |_| {
        const len = prng.below(code.len + 1);
        prng.fill(code[0..len]);
        const analyzed = analyze(code[0..len], out[0..analysis_bytes(len)]);
        for (0..len) |i| {
            if (analyzed.is_jumpdest(i)) try std.testing.expectEqual(op.JUMPDEST, code[i]);
        }
    }
}

fn fuzz_analyze(_: void, smith: *std.testing.Smith) anyerror!void {
    var code: [256]u8 = undefined;
    const len = smith.slice(&code);
    var out: [analysis_bytes(256)]u8 = undefined;
    const analyzed = analyze(code[0..len], out[0..analysis_bytes(len)]);
    for (0..len) |i| {
        if (analyzed.is_jumpdest(i)) try std.testing.expectEqual(op.JUMPDEST, code[i]);
    }
}

test "bytecode: std.testing.fuzz analysis" {
    try std.testing.fuzz({}, fuzz_analyze, .{});
}

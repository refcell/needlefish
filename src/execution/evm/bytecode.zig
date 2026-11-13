//! Bytecode analysis: a zero-padded copy of the code, the bytes the interpreter dispatches on
//! (the code with fused instructions marked), and a JUMPDEST bitmap.
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
    /// What the interpreter dispatches on, as long as `code`: the code, except that an
    /// instruction starting a fused sequence holds its fused byte (`fusions`) and an original
    /// byte in the fused range holds INVALID.
    ops: []const u8,
    /// Length of the original code.
    len: u32,
    /// Bit `i` set when byte `i` is a JUMPDEST opcode (not PUSH data).
    jumpdests: []const u8,

    pub inline fn is_jumpdest(analyzed: *const Analyzed, destination: u256) bool {
        if (destination >= analyzed.len) return false;
        const index: u32 = @intCast(destination);
        // `index < len` and the bitmap has (len + 7) / 8 bytes (`analyze`; the interpreter
        // asserts it once per frame entry), so the read needs no per-JUMP bounds check.
        return (analyzed.jumpdests.ptr[index >> 3] >> @intCast(index & 7)) & 1 == 1;
    }

    /// The original code without padding.
    pub fn original(analyzed: *const Analyzed) []const u8 {
        return analyzed.code[0..analyzed.len];
    }
};

/// Whether the `padding_bytes` that end `padded` are all zero: one 32-byte compare and one
/// byte, where a byte loop cost 9% of the interpreter's time on a 21k-gas transfer (it runs
/// on every frame entry in safe builds).
pub inline fn padding_zero(padded: []const u8) bool {
    comptime assert(padding_bytes == 33);
    assert(padded.len >= padding_bytes);
    const tail = padded[padded.len - padding_bytes ..];
    const word: @Vector(32, u8) = tail[0..32].*;
    return @reduce(.Or, word) == 0 and tail[32] == 0;
}

pub fn analysis_bytes(code_len: usize) usize {
    return 2 * (code_len + padding_bytes) + (code_len + 7) / 8;
}

/// Fused instructions: sequences Base mainnet contracts execute back to back, each run by one
/// handler, so one dispatch (an indirect jump, the interpreter's main misprediction) instead
/// of one per instruction. Chosen from instruction pair and triple counts over 100 mainnet
/// blocks (docs/lanes/evm.md). `analyze` writes `fused_first + i` into `Analyzed.ops` where
/// sequence `i` starts, and the interpreter runs its instructions in order, each with its own
/// checks and gas, so behavior is unchanged. Only the last may jump: execution that enters at
/// the first runs them all, and a jump into the middle dispatches that instruction's own byte.
pub const fusions = [_][]const u8{
    &.{ op.DUP1, PUSH4, op.EQ, op.PUSH2, op.JUMPI },
    &.{ op.PUSH1, op.PUSH1, op.SHL, op.SUB },
    &.{ op.LT, op.ISZERO, op.PUSH2, op.JUMPI },
    &.{ op.GT, op.ISZERO, op.PUSH2, op.JUMPI },
    &.{ op.SLT, op.ISZERO, op.PUSH2, op.JUMPI },
    &.{ op.ISZERO, op.PUSH2, op.JUMPI },
    &.{ op.EQ, op.PUSH2, op.JUMPI },
    &.{ op.LT, op.PUSH2, op.JUMPI },
    &.{ op.GT, op.PUSH2, op.JUMPI },
    &.{ op.SUB, op.PUSH2, op.JUMPI },
    &.{ op.PUSH1, op.PUSH1, op.SHL },
    &.{ op.PUSH1, op.PUSH1, op.MSTORE },
    &.{ op.POP, op.POP, op.POP },
    &.{ op.POP, op.POP, op.JUMP },
    &.{ op.SWAP1, op.POP, op.JUMP },
    &.{ op.ADD, op.PUSH2, op.JUMP },
    &.{ op.SWAP1, op.PUSH2, op.JUMP },
    &.{ DUP2, op.PUSH2, op.JUMP },
    &.{ op.PUSH1, DUP2, op.ADD },
    &.{ op.PUSH1, DUP3, op.ADD },
    &.{ op.PUSH1, DUP4, op.ADD },
    &.{ op.PUSH1, op.ADD, op.MLOAD },
    &.{ DUP3, op.ADD, op.MSTORE },
    &.{ SWAP2, op.POP, op.POP },
    &.{ op.PUSH2, op.JUMPI },
    &.{ op.PUSH2, op.JUMP },
    &.{ op.PUSH1, op.PUSH1 },
    &.{ op.POP, op.POP },
    &.{ op.PUSH1, op.SHL },
    &.{ op.PUSH1, op.SHR },
    &.{ op.MSTORE, op.PUSH1 },
    &.{ op.MLOAD, op.PUSH1 },
    &.{ op.PUSH1, op.ADD },
    &.{ op.PUSH1, op.MSTORE },
    &.{ op.PUSH1, op.MLOAD },
    &.{ op.PUSH1, op.DUP1 },
    &.{ op.PUSH1, DUP2 },
    &.{ op.PUSH1, DUP3 },
    &.{ op.PUSH1, DUP4 },
    &.{ op.PUSH1, op.SWAP1 },
    &.{ op.POP, op.JUMP },
    &.{ op.SWAP1, op.JUMP },
    &.{ op.SWAP1, op.POP },
    &.{ SWAP2, op.POP },
    &.{ op.SWAP1, DUP2 },
    &.{ op.SWAP1, SWAP2 },
    &.{ SWAP2, op.SWAP1 },
    &.{ op.ADD, op.MLOAD },
    &.{ op.ADD, op.MSTORE },
    &.{ op.ADD, op.SWAP1 },
    &.{ DUP2, op.MSTORE },
    &.{ DUP2, op.LT },
    &.{ DUP2, op.ADD },
    &.{ DUP3, op.ADD },
    &.{ DUP4, op.ADD },
    &.{ DUP5, op.ADD },
    &.{ DUP2, DUP2 },
    &.{ op.DUP1, op.ISZERO },
    &.{ op.SUB, op.AND },
};

const PUSH4 = op.PUSH1 + 3;
const DUP2 = op.DUP1 + 1;
const DUP3 = op.DUP1 + 2;
const DUP4 = op.DUP1 + 3;
const DUP5 = op.DUP1 + 4;
const SWAP2 = op.SWAP1 + 1;

/// The first opcode byte of fused instructions; none of `fusions.len` bytes from it is defined
/// in any fork.
pub const fused_first: u8 = 0xb0;
pub const fusion_parts_max = 5;

comptime {
    assert(fused_first + fusions.len <= 0xef); // Below 0xef, the EOF magic.
    for (fused_first..fused_first + fusions.len) |byte| assert(!op.table[byte].defined);
    for (fusions) |parts| {
        assert(parts.len >= 2 and parts.len <= fusion_parts_max);
        for (parts[0 .. parts.len - 1]) |part| assert(part != op.JUMP and part != op.JUMPI);
    }
}

/// The instructions a dispatched byte runs when it is a fused instruction.
pub fn fusion(byte: u8) ?[]const u8 {
    if (byte < fused_first or byte - fused_first >= fusions.len) return null;
    return fusions[byte - fused_first];
}

/// For each opcode, the fusions starting with it, longest first.
const fusions_by_first: [256][]const u8 = by_first: {
    @setEvalBranchQuota(100_000);
    var lists: [256][fusions.len]u8 = undefined;
    var counts: [256]usize = @splat(0);
    var length = fusion_parts_max;
    while (length >= 2) : (length -= 1) {
        for (fusions, 0..) |parts, index| {
            if (parts.len != length) continue;
            lists[parts[0]][counts[parts[0]]] = index;
            counts[parts[0]] += 1;
        }
    }
    var result: [256][]const u8 = undefined;
    for (&result, 0..) |*list, first| {
        const final = lists[first][0..counts[first]].*;
        list.* = &final;
    }
    break :by_first result;
};

/// The fused byte for the longest fusion starting at instruction `pc`, or null.
fn fused_at(code: []const u8, pc: usize) ?u8 {
    assert(pc < code.len);
    candidates: for (fusions_by_first[code[pc]]) |index| {
        var next = pc;
        for (fusions[index]) |part| {
            if (next >= code.len or code[next] != part) continue :candidates;
            next += 1 + @as(usize, op.table[part].immediate_bytes);
        }
        return fused_first + index;
    }
    return null;
}

/// Analyze `code` into `out`, which must be exactly `analysis_bytes(code.len)` long.
pub fn analyze(code: []const u8, out: []u8) Analyzed {
    assert(out.len == analysis_bytes(code.len));
    assert(code.len <= std.math.maxInt(u32));
    const padded_len = code.len + padding_bytes;
    const padded = out[0..padded_len];
    const ops = out[padded_len..][0..padded_len];
    const bitmap = out[2 * padded_len ..];
    assert(bitmap.len == (code.len + 7) / 8);
    @memcpy(padded[0..code.len], code);
    @memset(padded[code.len..], 0);
    @memcpy(ops, padded);
    @memset(bitmap, 0);
    var pc: usize = 0;
    while (pc < code.len) {
        const byte = code[pc];
        if (fusion(byte) != null) {
            ops[pc] = op.INVALID;
        } else if (fused_at(code, pc)) |fused| {
            ops[pc] = fused;
        }
        if (byte == op.JUMPDEST) {
            bitmap[pc >> 3] |= @as(u8, 1) << @intCast(pc & 7);
            pc += 1;
        } else if (byte >= op.PUSH1 and byte <= op.PUSH32) {
            pc += @as(usize, byte - op.PUSH1) + 2;
        } else {
            pc += 1;
        }
    }
    return .{
        .code = padded,
        .ops = ops,
        .len = @intCast(code.len),
        .jumpdests = bitmap,
    };
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
        /// The last code buffer checked equal to `analyzed` (safe builds' hit check).
        source: [*]const u8,
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
        const entry = cache.find(hash) orelse return null;
        return entry.analyzed;
    }

    fn find(cache: *const AnalysisCache, hash: *const [32]u8) ?*Entry {
        var index = cache.slot(hash);
        var probes: usize = 0;
        while (probes < cache.entries.len) : (probes += 1) {
            const entry = &cache.entries[index];
            if (!entry.occupied) return null;
            if (std.mem.eql(u8, &entry.hash, hash)) return entry;
            index = (index + 1) & (cache.entries.len - 1);
        }
        unreachable; // The table is never more than 3/4 full, so a probe meets an empty slot.
    }

    /// Asserts that `code` is the code cached under `hash`. Stored code is never written
    /// in place, so the full compare is skipped for the buffer that last matched (the
    /// same CALL target again) and still runs for every other buffer under this hash.
    pub fn assert_source(cache: *AnalysisCache, hash: *const [32]u8, code: []const u8) void {
        const entry = cache.find(hash).?;
        assert(entry.analyzed.len == code.len);
        if (entry.source == code.ptr) return;
        assert(std.mem.eql(u8, entry.analyzed.original(), code));
        entry.source = code.ptr;
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
        cache.entries[index] = .{
            .hash = hash.*,
            .analyzed = analyzed,
            .source = code.ptr,
            .occupied = true,
        };
        cache.count += 1;
        assert(cache.used <= cache.buffer.len);
        return analyzed;
    }

    /// Analyze `code` ahead of its first call when it fits without filling the cache (a full
    /// cache is dropped before the next message); false when it does not fit.
    pub fn warm(cache: *AnalysisCache, hash: *const [32]u8, code: []const u8) bool {
        if (cache.get(hash) != null) return true;
        const table_room = (cache.count + 1) * 4 <= cache.entries.len * 3;
        if (!table_room or cache.buffer.len - cache.used < analysis_bytes(code.len)) return false;
        const analyzed = cache.put(hash, code).?;
        assert(analyzed.len == code.len);
        assert(!cache.full);
        return true;
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
    const code = [_]u8{ op.PUSH1, op.JUMPDEST, op.JUMPDEST };
    // Room for the six analyses that fill the table, and one byte more.
    var cache = try AnalysisCache.init(std.testing.allocator, 6 * analysis_bytes(code.len) + 1, 8);
    defer cache.deinit(std.testing.allocator);
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
    const big: [6 * analysis_bytes(code.len)]u8 = @splat(0);
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

test "bytecode: fused instructions start only where their sequence does" {
    // PUSH2 JUMPI is fused at 0; JUMPDEST at 4 is not; the fused range byte at 5 is INVALID;
    // POP POP at 6 is fused, and a truncated PUSH1 POP at the end is not.
    const code = [_]u8{
        op.PUSH2, 0, 4, op.JUMPI, op.JUMPDEST, fused_first, op.POP, op.POP, op.PUSH1,
    };
    var out: [analysis_bytes(code.len)]u8 = undefined;
    const analyzed = analyze(&code, &out);
    try std.testing.expectEqualSlices(u8, &.{ op.PUSH2, op.JUMPI }, fusion(analyzed.ops[0]).?);
    try std.testing.expectEqual(op.JUMPDEST, analyzed.ops[4]);
    try std.testing.expectEqual(op.INVALID, analyzed.ops[5]);
    try std.testing.expectEqualSlices(u8, &.{ op.POP, op.POP }, fusion(analyzed.ops[6]).?);
    try std.testing.expectEqual(op.POP, analyzed.ops[7]);
    try std.testing.expectEqual(op.PUSH1, analyzed.ops[8]);
    try std.testing.expectEqualSlices(u8, &code, analyzed.original());
    try std.testing.expect(std.mem.allEqual(u8, analyzed.ops[code.len..], 0));
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

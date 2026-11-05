//! Bytecode analysis: a zero-padded copy of the code plus a JUMPDEST bitmap.
//!
//! Padding lets the interpreter read PUSH immediates and the next opcode without
//! bounds checks: running off the end reads 0x00 (STOP), exactly the EVM rule.
//! Analysis memory comes from a LIFO `Arena` that mirrors the frame stack.

const std = @import("std");
const assert = std.debug.assert;
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
        return .{ .buffer = try allocator.alloc(u8, capacity_bytes) };
    }

    pub fn deinit(arena: *Arena, allocator: std.mem.Allocator) void {
        allocator.free(arena.buffer);
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

/// EIP-7702 delegation designator: 0xef0100 followed by a 20-byte address.
pub const delegation_prefix = [3]u8{ 0xef, 0x01, 0x00 };
pub const delegation_len = 23;

pub fn delegation_target(code: []const u8) ?[20]u8 {
    if (code.len != delegation_len) return null;
    if (!std.mem.eql(u8, code[0..3], &delegation_prefix)) return null;
    return code[3..23].*;
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

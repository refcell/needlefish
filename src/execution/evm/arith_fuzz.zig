//! Differential fuzz of the arithmetic opcode family through the interpreter.
//!
//! Each case runs `PUSH32 c; PUSH32 b; PUSH32 a; OP; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0;
//! RETURN` and compares the returned word with a reference written directly with Zig's
//! builtin wide-integer operators (slow but obviously correct), so the fast paths
//! (`uint.zig` Knuth division, shift and sign handling) are checked end to end.

const std = @import("std");
const assert = std.debug.assert;
const op = @import("opcode.zig");
const evm_module = @import("evm.zig");
const primitives = @import("primitives.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;

const contract = primitives.address_from_int(0xa717);
const gas_limit: u64 = 1_000_000;

const opcodes = [_]u8{
    op.ADD, op.MUL,        op.SUB, op.DIV, op.SDIV, op.MOD, op.SMOD, op.ADDMOD, op.MULMOD,
    op.EXP, op.SIGNEXTEND, op.LT,  op.GT,  op.SLT,  op.SGT, op.EQ,   op.BYTE,   op.SHL,
    op.SHR, op.SAR,
};

fn ternary(opcode: u8) bool {
    return opcode == op.ADDMOD or opcode == op.MULMOD;
}

fn signed(x: u256) i256 {
    return @bitCast(x);
}

fn unsigned(x: i256) u256 {
    return @bitCast(x);
}

/// Reference semantics from the Yellow Paper, using builtin wide arithmetic.
fn reference(opcode: u8, a: u256, b: u256, c: u256) u256 {
    return switch (opcode) {
        op.ADD => a +% b,
        op.MUL => a *% b,
        op.SUB => a -% b,
        op.DIV => if (b == 0) 0 else a / b,
        op.MOD => if (b == 0) 0 else a % b,
        op.SDIV => if (b == 0)
            0
        else if (signed(a) == std.math.minInt(i256) and signed(b) == -1)
            a
        else
            unsigned(@divTrunc(signed(a), signed(b))),
        op.SMOD => if (b == 0 or signed(b) == -1) 0 else unsigned(@rem(signed(a), signed(b))),
        op.ADDMOD => if (c == 0) 0 else @intCast((@as(u257, a) + b) % c),
        op.MULMOD => if (c == 0) 0 else @intCast((@as(u512, a) * b) % c),
        op.EXP => exponent_reference(a, b),
        op.SIGNEXTEND => signextend_reference(a, b),
        op.LT => @intFromBool(a < b),
        op.GT => @intFromBool(a > b),
        op.SLT => @intFromBool(signed(a) < signed(b)),
        op.SGT => @intFromBool(signed(a) > signed(b)),
        op.EQ => @intFromBool(a == b),
        op.BYTE => if (a >= 32) 0 else primitives.u256_to_b256(b)[@intCast(a)],
        op.SHL => if (a >= 256) 0 else b << @intCast(a),
        op.SHR => if (a >= 256) 0 else b >> @intCast(a),
        op.SAR => if (a >= 256)
            (if (signed(b) < 0) std.math.maxInt(u256) else 0)
        else
            unsigned(signed(b) >> @intCast(a)),
        else => unreachable,
    };
}

/// Left-to-right square-and-multiply (the interpreter scans right to left).
fn exponent_reference(base: u256, power: u256) u256 {
    var result: u256 = 1;
    var bit: u32 = 256;
    while (bit > 0) {
        bit -= 1;
        result *%= result;
        if ((power >> @intCast(bit)) & 1 == 1) result *%= base;
    }
    return result;
}

/// Bit-by-bit: copy bit `8 * index + 7` into every higher bit.
fn signextend_reference(index: u256, value: u256) u256 {
    if (index >= 31) return value;
    const sign_position: u8 = @intCast(8 * index + 7);
    const sign_set = (value >> sign_position) & 1 == 1;
    const low_mask = (@as(u256, 1) << (sign_position + 1)) - 1;
    return if (sign_set) value | ~low_mask else value & low_mask;
}

/// Operands biased toward edges: small values, shift amounts, signed extremes, and words
/// with long runs of ones or zeros (the Knuth correction and add-back paths).
fn operand(prng: *Prng) u256 {
    return switch (prng.below(8)) {
        0 => @as(u256, prng.below(300)),
        1 => @as(u256, std.math.maxInt(u256)) - prng.below(4),
        2 => @as(u256, 1) << @intCast(prng.below(256)),
        3 => unsigned(std.math.minInt(i256)) + @as(u256, prng.below(2)),
        else => blk: {
            var value: u256 = 0;
            for (0..4) |limb| {
                const word: u64 = switch (prng.below(4)) {
                    0 => 0,
                    1 => std.math.maxInt(u64),
                    else => prng.int(u64),
                };
                value |= @as(u256, word) << @intCast(limb * 64);
            }
            const bits: u32 = @intCast(prng.below(257));
            if (bits == 256) break :blk value;
            break :blk value & ((@as(u256, 1) << @intCast(bits)) - 1);
        },
    };
}

fn program(buffer: *[110]u8, opcode: u8, a: u256, b: u256, c: u256) []const u8 {
    var length: usize = 0;
    const operands = [3]u256{ c, b, a }; // Pushed in reverse: `a` ends on top.
    const first: usize = if (ternary(opcode)) 0 else 1;
    for (operands[first..]) |value| {
        buffer[length] = op.PUSH32;
        primitives.word_to_be(buffer[length + 1 ..][0..32], value);
        length += 33;
    }
    const tail = [_]u8{ opcode, op.PUSH1, 0, op.MSTORE, op.PUSH1, 32, op.PUSH1, 0, op.RETURN };
    @memcpy(buffer[length..][0..tail.len], &tail);
    length += tail.len;
    assert(length <= buffer.len);
    return buffer[0..length];
}

fn check(h: *Harness, opcode: u8, a: u256, b: u256, c: u256) !void {
    var buffer: [110]u8 = undefined;
    const code = program(&buffer, opcode, a, b, c);
    try h.database.put_account(contract, 0, 1, code);
    h.state.reset(h.database.interface());
    const outcome = try h.call(.osaka, contract, &.{}, gas_limit);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(usize, 32), outcome.output.len);
    const actual = primitives.word_from_be(outcome.output[0..32]);
    const expected = reference(opcode, a, b, c);
    if (actual != expected) {
        std.debug.print("opcode 0x{x:0>2} a={x} b={x} c={x}\n", .{ opcode, a, b, c });
    }
    try std.testing.expectEqual(expected, actual);
}

fn fuzz_arithmetic(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    const take = @min(bytes.len, 8);
    @memcpy(seed[0..take], bytes[0..take]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        const opcode = opcodes[@intCast(prng.below(opcodes.len))];
        try check(h, opcode, operand(&prng), operand(&prng), operand(&prng));
    }
}

test "arith fuzz: known edge cases" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const min = unsigned(std.math.minInt(i256));
    const max = std.math.maxInt(u256);
    try check(&h, op.SDIV, min, max, 0); // minInt / -1 wraps.
    try check(&h, op.SMOD, min, max, 0);
    try check(&h, op.SMOD, unsigned(-7), 3, 0); // Sign of the dividend.
    try check(&h, op.SDIV, unsigned(-7), 2, 0);
    try check(&h, op.MULMOD, max, max, max - 1);
    try check(&h, op.ADDMOD, max, max, 7);
    try check(&h, op.EXP, 3, max, 0);
    try check(&h, op.SIGNEXTEND, 0, 0x80, 0);
    try check(&h, op.SAR, 255, min, 0);
    try check(&h, op.BYTE, 31, 0xab, 0);
}

test "arith fuzz: interpreter against reference formulas" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_arithmetic, .{ .seed = 0xa717_0001, .iterations = 400 });
}

//! The EVM operand stack: 1024 words in a buffer owned by the frame pool.
//!
//! Bounds are checked once per instruction by the interpreter from the opcode's
//! static input/output counts, so the accessors here only assert.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

pub const limit = 1024;

/// Store a whole word with one 32-byte store (evm2's `write_word`). The next opcode often
/// loads the slot as one 32-byte vector (DUP, SWAP, MSTORE); a load spanning four separate
/// 8-byte stores cannot be forwarded from them and stalls until they reach the cache.
/// LLVM folds a plain vector store back into four scalar ones (an ADD becomes four `adc`s to
/// memory), so on x86-64 with AVX the store is inline assembly, as in evm2.
pub inline fn write(slot: *u256, value: u256) void {
    const Lanes = @Vector(4, u64);
    comptime assert(@sizeOf(Lanes) == @sizeOf(u256));
    // Limb by limb: LLVM lowers a `@bitCast` of the u256 through 32-bit lane inserts.
    const lanes: Lanes = .{
        @truncate(value),
        @truncate(value >> 64),
        @truncate(value >> 128),
        @truncate(value >> 192),
    };
    if (comptime single_store_asm) {
        asm volatile ("vmovdqu %[lanes], (%[slot])"
            :
            : [lanes] "x" (lanes),
              [slot] "r" (slot),
            : .{ .memory = true });
    } else {
        @as(*align(@alignOf(u256)) Lanes, @ptrCast(slot)).* = lanes;
    }
}

const single_store_asm = builtin.cpu.arch == .x86_64 and
    builtin.zig_backend == .stage2_llvm and builtin.cpu.has(.x86, .avx);

pub const Stack = struct {
    items: *[limit]u256,
    /// 64 bits although it never exceeds `limit`: the interpreter keeps it in a register and
    /// indexes with it, and a narrower type costs a zero extension on every opcode.
    len: u64 = 0,

    pub fn init(items: *[limit]u256) Stack {
        return .{ .items = items };
    }

    /// True when `inputs` items can be popped and `outputs` pushed afterwards.
    pub inline fn fits(stack: *const Stack, inputs: u32, outputs: u32) bool {
        return stack.len >= inputs and stack.len - inputs + outputs <= limit;
    }

    pub inline fn push(stack: *Stack, value: u256) void {
        assert(stack.len < limit);
        write(&stack.items[stack.len], value);
        stack.len += 1;
    }

    pub inline fn pop(stack: *Stack) u256 {
        assert(stack.len > 0);
        stack.len -= 1;
        return stack.items[stack.len];
    }

    /// Item `depth` from the top: 0 is the top.
    pub inline fn peek(stack: *Stack, depth: u32) *u256 {
        assert(depth < stack.len);
        return &stack.items[stack.len - 1 - depth];
    }

    pub inline fn dup(stack: *Stack, comptime n: u32) void {
        comptime assert(n >= 1 and n <= 16);
        assert(stack.len >= n and stack.len < limit);
        stack.items[stack.len] = stack.items[stack.len - n];
        stack.len += 1;
    }

    pub inline fn swap(stack: *Stack, comptime n: u32) void {
        comptime assert(n >= 1 and n <= 16);
        assert(stack.len > n);
        const top = stack.len - 1;
        const tmp = stack.items[top];
        stack.items[top] = stack.items[top - n];
        stack.items[top - n] = tmp;
    }
};

test "stack: push pop dup swap" {
    var buffer: [limit]u256 = undefined;
    var stack = Stack.init(&buffer);
    try std.testing.expect(!stack.fits(1, 0));
    stack.push(1);
    stack.push(2);
    stack.dup(2);
    try std.testing.expectEqual(@as(u256, 1), stack.peek(0).*);
    stack.swap(1);
    try std.testing.expectEqual(@as(u256, 2), stack.pop());
    try std.testing.expectEqual(@as(u256, 1), stack.pop());
    try std.testing.expectEqual(@as(u256, 1), stack.pop());
    try std.testing.expectEqual(@as(u64, 0), stack.len);
}

test "stack: limit" {
    var buffer: [limit]u256 = undefined;
    var stack = Stack.init(&buffer);
    for (0..limit) |i| stack.push(i);
    try std.testing.expect(!stack.fits(0, 1));
    try std.testing.expect(stack.fits(1, 1));
    try std.testing.expect(stack.fits(2, 1));
}

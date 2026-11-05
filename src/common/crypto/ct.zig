//! Constant-time helpers. `barrier` hides a value from the optimizer so it cannot
//! turn mask arithmetic on secrets back into branches or selective loads (LLVM does
//! this for plain `(a & ~m) | (b & m)` on x86_64; see docs/lanes/crypto.md).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const has_asm_barrier = builtin.zig_backend == .stage2_llvm and
    (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64);

/// Returns `value` unchanged; the optimizer cannot see through it.
pub inline fn barrier(value: u64) u64 {
    if (comptime has_asm_barrier) {
        return asm volatile (""
            : [ret] "=r" (-> u64),
            : [value] "0" (value),
        );
    }
    var copy = value;
    std.mem.doNotOptimizeAway(&copy);
    return copy;
}

/// All ones when `flag` is 1, zero when 0, opaque to the optimizer.
pub inline fn mask(flag: u1) u64 {
    return barrier(0 -% @as(u64, flag));
}

/// 1 when `a == b`, else 0, without a comparison the optimizer can branch on.
pub inline fn equal(a: u64, b: u64) u1 {
    const difference = barrier(a ^ b);
    // difference | -difference has its top bit set exactly when difference != 0.
    return @truncate(~(difference | (0 -% difference)) >> 63);
}

/// 1 when `value != 0`, else 0.
pub inline fn nonzero(value: u64) u1 {
    const hidden = barrier(value);
    return @truncate((hidden | (0 -% hidden)) >> 63);
}

/// `b` when `flag` is 1, else `a`.
pub inline fn select(a: u64, b: u64, flag: u1) u64 {
    const m = mask(flag);
    return (a & ~m) | (b & m);
}

test "ct: helpers" {
    try std.testing.expectEqual(@as(u64, 0), mask(0));
    try std.testing.expectEqual(~@as(u64, 0), mask(1));
    try std.testing.expectEqual(@as(u1, 1), equal(5, 5));
    try std.testing.expectEqual(@as(u1, 0), equal(5, 6));
    try std.testing.expectEqual(@as(u1, 0), equal(0, 1 << 63));
    try std.testing.expectEqual(@as(u1, 0), nonzero(0));
    try std.testing.expectEqual(@as(u1, 1), nonzero(1 << 63));
    try std.testing.expectEqual(@as(u64, 7), select(7, 9, 0));
    try std.testing.expectEqual(@as(u64, 9), select(7, 9, 1));
    for (0..256) |value| {
        assert(equal(value, 17) == @intFromBool(value == 17));
        assert(nonzero(value) == @intFromBool(value != 0));
    }
}

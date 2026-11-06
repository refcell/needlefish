//! Opt-in per-opcode profile for bench builds (`-Devm-opcode-profile`).
//!
//! When enabled, the dispatch loop counts every executed opcode and accumulates hardware
//! timer ticks spent in its handler (child frames run in their own `run` call, so a CALL's
//! ticks exclude the callee). The timer is coarse (24 MHz on Apple silicon) but unbiased
//! over millions of instructions. Disabled builds compile all of this away. It reads the
//! timer directly: a diagnostics-only exception to the `utilities.io` rule, never on in
//! production or simulation builds.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const op = @import("opcode.zig");

pub const enabled: bool = @import("build_options").evm_opcode_profile;

/// Single-threaded bench use only: the EVM runs on one thread per bench process.
var counts: [256]u64 = @splat(0);
var ticks: [256]u64 = @splat(0);

pub inline fn now() u64 {
    if (comptime !enabled) return 0;
    return switch (builtin.cpu.arch) {
        .aarch64 => asm volatile ("mrs %[ticks], cntvct_el0"
            : [ticks] "=r" (-> u64),
        ),
        .x86_64 => tsc: {
            var low: u32 = undefined;
            var high: u32 = undefined;
            asm volatile ("rdtsc"
                : [low] "={eax}" (low),
                  [high] "={edx}" (high),
            );
            break :tsc (@as(u64, high) << 32) | low;
        },
        else => 0,
    };
}

pub inline fn record(opcode: u8, start: u64) void {
    if (comptime !enabled) return;
    counts[opcode] += 1;
    ticks[opcode] +%= now() -% start;
}

pub fn reset() void {
    counts = @splat(0);
    ticks = @splat(0);
}

/// Print the `limit` opcodes with the most ticks, with their share and ticks per execution.
pub fn report(limit: u32) void {
    if (comptime !enabled) return;
    assert(limit > 0 and limit <= 256);
    var total: u64 = 0;
    for (ticks) |value| total +%= value;
    if (total == 0) return;
    var order: [256]u8 = undefined;
    for (&order, 0..) |*item, index| item.* = @intCast(index);
    std.mem.sort(u8, &order, {}, by_ticks);
    std.debug.print("evm opcode profile (handler ticks; children excluded):\n", .{});
    for (order[0..limit]) |opcode| {
        if (ticks[opcode] == 0) break;
        const opcode_ticks: f64 = @floatFromInt(ticks[opcode]);
        const share = opcode_ticks * 100 / @as(f64, @floatFromInt(total));
        const per = opcode_ticks / @as(f64, @floatFromInt(counts[opcode]));
        std.debug.print("  {s:<14} {d:>6.2}%  {d:>12} execs  {d:>8.3} ticks/exec\n", .{
            op.table[opcode].name, share, counts[opcode], per,
        });
    }
}

fn by_ticks(_: void, a: u8, b: u8) bool {
    return ticks[a] > ticks[b];
}

test "opcode profile: disabled builds record nothing" {
    if (enabled) return error.SkipZigTest;
    record(0x01, now());
    try std.testing.expectEqual(@as(u64, 0), counts[0x01]);
    report(10);
}

//! Derivation check, cadence half: how the derived safe head advances along L1. Every
//! derived block is tagged with the L1 block its batch completed in (`derived_from`);
//! consecutive blocks with the same tag become safe together, in one jump. The tracker
//! counts jumps, their size in L2 blocks, and the L1 distance between them, which is the
//! cadence a verifier's safe head moves at (the batcher's submission interval).

const std = @import("std");
const assert = std.debug.assert;

pub const Cadence = struct {
    /// The L1 block of the current (still growing) jump, and its first and last L2 block.
    current_l1: ?u64 = null,
    current_first_l2: u64 = 0,
    current_last_l2: u64 = 0,
    /// Completed jumps.
    jumps: u64 = 0,
    jump_blocks_max: u64 = 0,
    /// L1 blocks between consecutive jumps (sum over `jumps - 1` gaps when jumps > 1).
    gap_l1_sum: u64 = 0,
    gap_l1_max: u64 = 0,
    gaps: u64 = 0,
    blocks: u64 = 0,

    /// Records that L2 block `l2_number` was derived from L1 block `l1_number`. Blocks come
    /// in order; the L1 tag never decreases.
    pub fn record(cadence: *Cadence, l2_number: u64, l1_number: u64) void {
        if (cadence.current_l1) |current| {
            assert(l1_number >= current);
            assert(l2_number == cadence.current_last_l2 + 1);
            if (l1_number == current) {
                cadence.current_last_l2 = l2_number;
                cadence.blocks += 1;
                return;
            }
            cadence.close();
            const gap = l1_number - current;
            cadence.gaps += 1;
            cadence.gap_l1_sum += gap;
            cadence.gap_l1_max = @max(cadence.gap_l1_max, gap);
        }
        cadence.current_l1 = l1_number;
        cadence.current_first_l2 = l2_number;
        cadence.current_last_l2 = l2_number;
        cadence.blocks += 1;
        assert(cadence.current_l1.? == l1_number);
    }

    fn close(cadence: *Cadence) void {
        assert(cadence.current_l1 != null);
        assert(cadence.current_last_l2 >= cadence.current_first_l2);
        const size = cadence.current_last_l2 - cadence.current_first_l2 + 1;
        cadence.jumps += 1;
        cadence.jump_blocks_max = @max(cadence.jump_blocks_max, size);
    }

    /// The jumps seen so far, counting the current one.
    pub fn jumps_total(cadence: *const Cadence) u64 {
        return cadence.jumps + @intFromBool(cadence.current_l1 != null);
    }

    /// Mean L1 blocks between jumps, times 10 (one decimal), or 0 without a gap.
    pub fn gap_l1_mean_tenths(cadence: *const Cadence) u64 {
        if (cadence.gaps == 0) return 0;
        assert(cadence.gaps < cadence.jumps_total());
        return cadence.gap_l1_sum * 10 / cadence.gaps;
    }

    /// Mean L2 blocks per jump, or 0 before the first block.
    pub fn blocks_per_jump_mean(cadence: *const Cadence) u64 {
        const jumps = cadence.jumps_total();
        if (jumps == 0) return 0;
        assert(cadence.blocks >= jumps);
        return cadence.blocks / jumps;
    }
};

const testing = std.testing;

test "derive check cadence: jumps and gaps" {
    var cadence: Cadence = .{};
    try testing.expectEqual(@as(u64, 0), cadence.jumps_total());
    for (101..111) |n| cadence.record(n, 50);
    for (111..131) |n| cadence.record(n, 55);
    cadence.record(131, 61);
    try testing.expectEqual(@as(u64, 3), cadence.jumps_total());
    try testing.expectEqual(@as(u64, 20), cadence.jump_blocks_max);
    try testing.expectEqual(@as(u64, 31), cadence.blocks);
    try testing.expectEqual(@as(u64, 6), cadence.gap_l1_max);
    try testing.expectEqual(@as(u64, 55), cadence.gap_l1_mean_tenths());
    try testing.expectEqual(@as(u64, 10), cadence.blocks_per_jump_mean());
}

test "derive check cadence: seeded fuzz keeps the counters consistent" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x4341_4445);
    for (0..100) |_| {
        var cadence: Cadence = .{};
        var l1: u64 = prng.below(1000);
        const first = prng.below(1_000_000);
        const count = 1 + prng.below(500);
        var jumps: u64 = 1;
        for (0..count) |offset| {
            if (offset > 0 and prng.chance(1, 4)) {
                l1 += 1 + prng.below(20);
                jumps += 1;
            }
            cadence.record(first + offset, l1);
        }
        try testing.expectEqual(jumps, cadence.jumps_total());
        try testing.expectEqual(count, cadence.blocks);
        try testing.expectEqual(jumps - 1, cadence.gaps);
        try testing.expect(cadence.jump_blocks_max <= count);
    }
}

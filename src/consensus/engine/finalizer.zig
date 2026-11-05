//! L2 finalizer: tracks the highest L2 block derived from each L1 block, and when an L1
//! block finalizes, returns the highest L2 block derived from L1 data at or before it.
//! Mirrors base/base `crates/consensus/service/src/actors/derivation/finalizer.rs`.
//!
//! Entries are kept sorted by L1 number in a fixed-capacity array. When full, the oldest
//! entry is dropped (it can only finalize an older L2 block than its successors).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const BlockInfo = @import("../protocol/root.zig").block.BlockInfo;

const Pending = struct { l1_number: u64, l2_number: u64 };

pub const Finalizer = struct {
    /// Sorted by `l1_number`, unique.
    pending: []Pending,
    count: u32 = 0,
    finalized_l1_block: ?BlockInfo = null,

    pub fn init(allocator: Allocator, capacity: u32) Allocator.Error!Finalizer {
        assert(capacity > 0);
        return .{ .pending = try allocator.alloc(Pending, capacity) };
    }

    pub fn deinit(finalizer: *Finalizer, allocator: Allocator) void {
        allocator.free(finalizer.pending);
        finalizer.* = undefined;
    }

    pub fn clear(finalizer: *Finalizer) void {
        finalizer.count = 0;
    }

    /// Records that L2 block `l2_number` was derived from L1 block `l1_number`.
    pub fn enqueue(finalizer: *Finalizer, l1_number: u64, l2_number: u64) void {
        var index: u32 = finalizer.count;
        while (index > 0 and finalizer.pending[index - 1].l1_number > l1_number) index -= 1;
        if (index > 0 and finalizer.pending[index - 1].l1_number == l1_number) {
            const entry = &finalizer.pending[index - 1];
            entry.l2_number = @max(entry.l2_number, l2_number);
            return;
        }
        if (finalizer.count == finalizer.pending.len) {
            if (index == 0) return;
            std.mem.copyForwards(
                Pending,
                finalizer.pending[0 .. index - 1],
                finalizer.pending[1..index],
            );
            finalizer.pending[index - 1] = .{ .l1_number = l1_number, .l2_number = l2_number };
            return;
        }
        std.mem.copyBackwards(
            Pending,
            finalizer.pending[index + 1 .. finalizer.count + 1],
            finalizer.pending[index..finalizer.count],
        );
        finalizer.pending[index] = .{ .l1_number = l1_number, .l2_number = l2_number };
        finalizer.count += 1;
        assert(finalizer.count <= finalizer.pending.len);
    }

    /// Handles a new finalized L1 block; ignores one older than the last seen. Returns the
    /// L2 block number that became final, if any.
    pub fn process_finalized_l1_block(finalizer: *Finalizer, block: BlockInfo) ?u64 {
        if (finalizer.finalized_l1_block) |previous| {
            if (block.number < previous.number) return null;
        }
        finalizer.finalized_l1_block = block;
        return finalizer.try_finalize_next(block);
    }

    /// Retries with the last finalized L1 block (after new blocks were enqueued).
    pub fn try_finalize_pending(finalizer: *Finalizer) ?u64 {
        const block = finalizer.finalized_l1_block orelse return null;
        return finalizer.try_finalize_next(block);
    }

    fn try_finalize_next(finalizer: *Finalizer, block: BlockInfo) ?u64 {
        var count: u32 = 0;
        while (count < finalizer.count and finalizer.pending[count].l1_number <= block.number) {
            count += 1;
        }
        if (count == 0) return null;
        const result = finalizer.pending[count - 1].l2_number;
        std.mem.copyForwards(
            Pending,
            finalizer.pending[0 .. finalizer.count - count],
            finalizer.pending[count..finalizer.count],
        );
        finalizer.count -= count;
        assert(finalizer.count == 0 or finalizer.pending[0].l1_number > block.number);
        return result;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "finalizer: base/base behavior" {
    var finalizer = try Finalizer.init(testing.allocator, 8);
    defer finalizer.deinit(testing.allocator);
    try testing.expectEqual(null, finalizer.process_finalized_l1_block(.{ .number = 1 }));
    finalizer.enqueue(1, 10);
    finalizer.enqueue(1, 9); // Keeps the highest L2 block per L1 block.
    finalizer.enqueue(3, 30);
    finalizer.enqueue(2, 20);
    try testing.expectEqual(@as(?u64, 10), finalizer.try_finalize_pending());
    try testing.expectEqual(@as(?u64, 20), finalizer.process_finalized_l1_block(.{ .number = 2 }));
    try testing.expectEqual(null, finalizer.process_finalized_l1_block(.{ .number = 1 }));
    try testing.expectEqual(@as(?u64, 30), finalizer.process_finalized_l1_block(.{ .number = 5 }));
    try testing.expectEqual(@as(u32, 0), finalizer.count);
    finalizer.enqueue(4, 40);
    finalizer.clear();
    try testing.expectEqual(null, finalizer.try_finalize_pending());
}

test "finalizer: seeded fuzz against a reference map" {
    var prng = Prng.init(0x46494e41);
    var finalizer = try Finalizer.init(testing.allocator, 64);
    defer finalizer.deinit(testing.allocator);
    var reference: [64]?u64 = @splat(null);
    var finalized: u64 = 0;
    for (0..5_000) |_| {
        if (prng.chance(3, 4)) {
            const l1 = prng.below(reference.len);
            const l2 = prng.int(u16);
            finalizer.enqueue(l1, l2);
            reference[l1] = @max(reference[l1] orelse 0, l2);
            continue;
        }
        const target = prng.below(reference.len);
        const got = finalizer.process_finalized_l1_block(.{ .number = target });
        if (target < finalized) {
            try testing.expectEqual(null, got);
            continue;
        }
        finalized = target;
        var want: ?u64 = null;
        for (reference[0 .. target + 1]) |*slot| {
            if (slot.*) |value| want = value;
            slot.* = null;
        }
        try testing.expectEqual(want, got);
    }
}

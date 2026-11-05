//! Nonce allocation (base/base `tx-manager/src/nonce.rs` `NonceManager`).
//!
//! Sans-IO: the tracker never fetches the account nonce itself. While its cache is empty,
//! `reserve` fails with `error.NonceUnknown` and the driver fetches
//! `eth_getTransactionCount` and hands it to `set_chain_nonce` together with the
//! `generation` it read before the fetch. A `reset` in between bumps the generation, so a
//! stale fetch is discarded exactly like base/base's lock-free re-check.
//!
//! Nonces reserved but never published are returned and reissued smallest first, so a
//! failed send does not leave a gap that blocks every later nonce. `reserved_high_water`
//! keeps a post-reset chain value from handing out a nonce that is still in flight.

const std = @import("std");
const assert = std.debug.assert;

pub fn Tracker(comptime returned_max: u32) type {
    comptime assert(returned_max > 0);
    comptime assert(returned_max <= 1024);
    return struct {
        const Self = @This();

        /// Next fresh nonce to hand out; null until the chain value is known.
        nonce: ?u64 = null,
        generation: u64 = 0,
        /// One past the highest nonce ever reserved.
        reserved_high_water: u64 = 0,
        /// Sorted ascending, unique.
        returned: [returned_max]u64 = undefined,
        returned_count: u32 = 0,

        pub const Error = error{ NonceUnknown, NonceOverflow };

        /// Hands out the next nonce: a returned one first, else a fresh one.
        pub fn reserve(tracker: *Self) Error!u64 {
            tracker.assert_invariants();
            const fresh = tracker.nonce orelse return error.NonceUnknown;
            if (tracker.returned_count > 0) {
                const reused = tracker.returned[0];
                std.mem.copyForwards(
                    u64,
                    tracker.returned[0 .. tracker.returned_count - 1],
                    tracker.returned[1..tracker.returned_count],
                );
                tracker.returned_count -= 1;
                tracker.reserved_high_water = @max(tracker.reserved_high_water, reused + 1);
                return reused;
            }
            const effective = @max(fresh, tracker.reserved_high_water);
            const next = std.math.add(u64, effective, 1) catch return error.NonceOverflow;
            tracker.nonce = next;
            tracker.reserved_high_water = next;
            assert(tracker.reserved_high_water > effective);
            return effective;
        }

        /// Installs a chain nonce fetched while `generation` was current. Returns false
        /// when the fetch is stale (a reset happened) or the cache is already populated.
        pub fn set_chain_nonce(tracker: *Self, generation: u64, chain_nonce: u64) bool {
            tracker.assert_invariants();
            if (generation != tracker.generation) return false;
            if (tracker.nonce != null) return false;
            tracker.nonce = chain_nonce;
            // Returned nonces below the chain value were consumed by someone else.
            var kept: u32 = 0;
            for (tracker.returned[0..tracker.returned_count]) |returned| {
                if (returned < chain_nonce) continue;
                tracker.returned[kept] = returned;
                kept += 1;
            }
            tracker.returned_count = kept;
            tracker.assert_invariants();
            return true;
        }

        /// Forgets the cached chain value. Returned nonces stay: they were never published.
        pub fn reset(tracker: *Self) void {
            tracker.nonce = null;
            tracker.generation +%= 1;
            assert(tracker.nonce == null);
        }

        /// Gives back a nonce that never reached a mempool. Returns false when the return
        /// set is full; the nonce is then left as a gap that a later reset can repair.
        pub fn give_back(tracker: *Self, nonce: u64) bool {
            tracker.assert_invariants();
            assert(nonce < tracker.reserved_high_water);
            var index: u32 = 0;
            while (index < tracker.returned_count and tracker.returned[index] < nonce) index += 1;
            if (index < tracker.returned_count and tracker.returned[index] == nonce) return true;
            if (tracker.returned_count == returned_max) return false;
            std.mem.copyBackwards(
                u64,
                tracker.returned[index + 1 .. tracker.returned_count + 1],
                tracker.returned[index..tracker.returned_count],
            );
            tracker.returned[index] = nonce;
            tracker.returned_count += 1;
            tracker.assert_invariants();
            return true;
        }

        pub fn known(tracker: *const Self) bool {
            return tracker.nonce != null;
        }

        fn assert_invariants(tracker: *const Self) void {
            assert(tracker.returned_count <= returned_max);
            if (tracker.returned_count == 0) return;
            for (tracker.returned[1..tracker.returned_count], 0..) |value, index| {
                assert(value > tracker.returned[index]);
            }
        }
    };
}

const testing = std.testing;

test "nonce: unknown until the chain value arrives" {
    var tracker: Tracker(4) = .{};
    try testing.expectError(error.NonceUnknown, tracker.reserve());
    try testing.expect(tracker.set_chain_nonce(0, 7));
    try testing.expectEqual(@as(u64, 7), try tracker.reserve());
    try testing.expectEqual(@as(u64, 8), try tracker.reserve());
    // A second fetch does not overwrite the cache.
    try testing.expect(!tracker.set_chain_nonce(0, 3));
    try testing.expectEqual(@as(u64, 9), try tracker.reserve());
}

test "nonce: stale fetch after reset is discarded" {
    var tracker: Tracker(4) = .{};
    const generation = tracker.generation;
    tracker.reset();
    try testing.expect(!tracker.set_chain_nonce(generation, 5));
    try testing.expect(tracker.set_chain_nonce(tracker.generation, 5));
    try testing.expectEqual(@as(u64, 5), try tracker.reserve());
}

test "nonce: high water skips past in-flight nonces after reset" {
    var tracker: Tracker(4) = .{};
    try testing.expect(tracker.set_chain_nonce(0, 10));
    _ = try tracker.reserve();
    _ = try tracker.reserve();
    tracker.reset();
    // The chain has not seen 10 and 11 yet.
    try testing.expect(tracker.set_chain_nonce(tracker.generation, 10));
    try testing.expectEqual(@as(u64, 12), try tracker.reserve());
}

test "nonce: returned nonces are reissued smallest first and pruned" {
    var tracker: Tracker(4) = .{};
    try testing.expect(tracker.set_chain_nonce(0, 0));
    for (0..4) |_| _ = try tracker.reserve();
    try testing.expect(tracker.give_back(2));
    try testing.expect(tracker.give_back(1));
    try testing.expect(tracker.give_back(2));
    try testing.expectEqual(@as(u64, 1), try tracker.reserve());
    tracker.reset();
    // The chain moved past 2: someone else used it.
    try testing.expect(tracker.set_chain_nonce(tracker.generation, 3));
    try testing.expectEqual(@as(u32, 0), tracker.returned_count);
    try testing.expectEqual(@as(u64, 4), try tracker.reserve());
}

test "nonce: give_back is bounded" {
    var tracker: Tracker(2) = .{};
    try testing.expect(tracker.set_chain_nonce(0, 0));
    for (0..3) |_| _ = try tracker.reserve();
    try testing.expect(tracker.give_back(0));
    try testing.expect(tracker.give_back(1));
    try testing.expect(!tracker.give_back(2));
}

/// Model check: a nonce is never handed out twice while still reserved.
fn check_unique(random: std.Random, steps: u32) !void {
    var tracker: Tracker(8) = .{};
    var held: [64]u64 = undefined;
    var held_count: u32 = 0;
    for (0..steps) |_| {
        switch (random.uintLessThan(u8, 4)) {
            0 => if (held_count < held.len) {
                const nonce = tracker.reserve() catch |err| switch (err) {
                    error.NonceUnknown => continue,
                    error.NonceOverflow => unreachable,
                };
                for (held[0..held_count]) |other| try testing.expect(other != nonce);
                held[held_count] = nonce;
                held_count += 1;
            },
            1 => if (held_count > 0) {
                const index = random.uintLessThan(u32, held_count);
                if (tracker.give_back(held[index])) {
                    held[index] = held[held_count - 1];
                    held_count -= 1;
                }
            },
            2 => tracker.reset(),
            else => {
                // The chain value never exceeds a nonce still held unpublished.
                var low: u64 = tracker.reserved_high_water;
                for (held[0..held_count]) |nonce| low = @min(low, nonce);
                _ = tracker.set_chain_nonce(tracker.generation, random.uintAtMost(u64, low));
            },
        }
    }
}

test "nonce: seeded fuzz uniqueness" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x40_4ce);
    for (0..200) |_| try check_unique(prng.random(), 200);
}

test "nonce: fuzz uniqueness" {
    try testing.fuzz({}, fuzz_unique, .{});
}

fn fuzz_unique(_: void, smith: *testing.Smith) anyerror!void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    try check_unique(prng.random(), 256);
}

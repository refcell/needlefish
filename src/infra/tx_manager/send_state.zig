//! Per-send bookkeeping (base/base `tx-manager/src/send_state.rs` `SendState`).
//!
//! Tracks which published versions of one logical send (same nonce, different fees) are
//! mined, how often the node said "nonce too low", and whether any version reached a
//! mempool. From that it decides when a send must abort: "nonce too low" before anything
//! was published means another transaction took the nonce; repeated "nonce too low"
//! with nothing mined means the same; a send that never reaches a mempool by its
//! deadline is abandoned.

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;

pub const Critical = enum { nonce_too_low, mempool_deadline_expired };

pub fn SendState(comptime mined_max: u32) type {
    comptime assert(mined_max > 0);
    return struct {
        const Self = @This();

        safe_abort_nonce_too_low_count: u64,
        mined: [mined_max]Hash = undefined,
        mined_count: u32 = 0,
        has_published: bool = false,
        nonce_too_low_count: u64 = 0,
        bump_count: u64 = 0,
        mempool_deadline_ms: ?u64 = null,

        pub fn init(safe_abort_nonce_too_low_count: u64, mempool_deadline_ms: ?u64) Self {
            assert(safe_abort_nonce_too_low_count > 0);
            return .{
                .safe_abort_nonce_too_low_count = safe_abort_nonce_too_low_count,
                .mempool_deadline_ms = mempool_deadline_ms,
            };
        }

        pub fn record_nonce_too_low(state: *Self) void {
            state.nonce_too_low_count += 1;
            assert(state.nonce_too_low_count > 0);
        }

        /// Marks `hash` mined. Returns false only when the mined set is full; versions of
        /// one send share a nonce, so at most one can be canonical at a time and a full set
        /// means many reorged-out versions, which the caller treats as a bug.
        pub fn tx_mined(state: *Self, hash: Hash) bool {
            if (state.index_of(hash) != null) return true;
            if (state.mined_count == mined_max) return false;
            state.mined[state.mined_count] = hash;
            state.mined_count += 1;
            assert(state.index_of(hash) != null);
            return true;
        }

        /// Marks `hash` not mined (reorged out or never found).
        pub fn tx_not_mined(state: *Self, hash: Hash) void {
            const index = state.index_of(hash) orelse return;
            state.mined[index] = state.mined[state.mined_count - 1];
            state.mined_count -= 1;
            // A reorg that un-mines everything forgets the "nonce too low" answers it caused.
            if (state.mined_count == 0) state.nonce_too_low_count = 0;
            assert(state.index_of(hash) == null);
        }

        pub fn critical_error(state: *const Self, now_ms: u64) ?Critical {
            if (state.mined_count > 0) return null;
            if (!state.has_published and state.nonce_too_low_count > 0) return .nonce_too_low;
            if (state.nonce_too_low_count >= state.safe_abort_nonce_too_low_count) {
                return .nonce_too_low;
            }
            if (!state.has_published) {
                if (state.mempool_deadline_ms) |deadline_ms| {
                    if (now_ms >= deadline_ms) return .mempool_deadline_expired;
                }
            }
            return null;
        }

        pub fn waiting_for_confirmation(state: *const Self) bool {
            return state.mined_count > 0;
        }

        pub fn record_successful_publish(state: *Self) void {
            state.has_published = true;
        }

        pub fn record_fee_bump(state: *Self) u64 {
            state.bump_count += 1;
            return state.bump_count;
        }

        fn index_of(state: *const Self, hash: Hash) ?u32 {
            assert(state.mined_count <= mined_max);
            for (state.mined[0..state.mined_count], 0..) |mined, index| {
                if (std.mem.eql(u8, &mined, &hash)) return @intCast(index);
            }
            return null;
        }
    };
}

const testing = std.testing;
const State = SendState(4);

fn hash_of(byte: u8) Hash {
    return @splat(byte);
}

test "send_state: nonce too low before publish is critical" {
    var state = State.init(3, null);
    try testing.expectEqual(@as(?Critical, null), state.critical_error(0));
    state.record_nonce_too_low();
    try testing.expectEqual(@as(?Critical, .nonce_too_low), state.critical_error(0));
}

test "send_state: nonce too low after publish needs the safe count" {
    var state = State.init(3, null);
    state.record_successful_publish();
    state.record_nonce_too_low();
    state.record_nonce_too_low();
    try testing.expectEqual(@as(?Critical, null), state.critical_error(0));
    state.record_nonce_too_low();
    try testing.expectEqual(@as(?Critical, .nonce_too_low), state.critical_error(0));
    // A mined version suppresses it.
    try testing.expect(state.tx_mined(hash_of(1)));
    try testing.expectEqual(@as(?Critical, null), state.critical_error(0));
    // Reorging the version out resets the count.
    state.tx_not_mined(hash_of(1));
    try testing.expectEqual(@as(u64, 0), state.nonce_too_low_count);
    try testing.expectEqual(@as(?Critical, null), state.critical_error(0));
}

test "send_state: mempool deadline applies only before publish" {
    var state = State.init(1, 100);
    try testing.expectEqual(@as(?Critical, null), state.critical_error(99));
    try testing.expectEqual(@as(?Critical, .mempool_deadline_expired), state.critical_error(100));
    state.record_successful_publish();
    try testing.expectEqual(@as(?Critical, null), state.critical_error(1000));
}

test "send_state: mined set dedups and is bounded" {
    var state = SendState(2).init(1, null);
    try testing.expect(state.tx_mined(hash_of(1)));
    try testing.expect(state.tx_mined(hash_of(1)));
    try testing.expect(state.tx_mined(hash_of(2)));
    try testing.expect(!state.tx_mined(hash_of(3)));
    try testing.expect(state.waiting_for_confirmation());
    state.tx_not_mined(hash_of(9));
    try testing.expectEqual(@as(u32, 2), state.mined_count);
    try testing.expectEqual(@as(u64, 1), state.record_fee_bump());
}

test "send_state: fuzz mined bookkeeping" {
    try testing.fuzz({}, fuzz_mined, .{});
}

fn fuzz_mined(_: void, smith: *testing.Smith) anyerror!void {
    var ops: [64]u8 = undefined;
    const length = smith.slice(&ops);
    var state = State.init(2, 50);
    var model: [8]bool = @splat(false);
    for (ops[0..length], 0..) |op, step| {
        const which: u8 = op & 7;
        switch (op >> 6) {
            0 => if (state.tx_mined(hash_of(which))) {
                model[which] = true;
            },
            1 => {
                state.tx_not_mined(hash_of(which));
                model[which] = false;
            },
            2 => state.record_nonce_too_low(),
            else => state.record_successful_publish(),
        }
        var count: u32 = 0;
        for (model) |mined| count += @intFromBool(mined);
        try testing.expectEqual(count, state.mined_count);
        if (count > 0) try testing.expectEqual(@as(?Critical, null), state.critical_error(step));
    }
}

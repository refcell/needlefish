//! Sequencer L1 origin selection (base/base `service/src/actors/sequencer/l1_origin/
//! selector.rs`).
//!
//! The next L2 block keeps the unsafe head's L1 origin until the next L1 block's timestamp
//! is reached, or moves to the next L1 block once it is known and due. Past the maximum
//! sequencer drift the next origin is required; if it is unknown, selection fails with
//! `error.NotEnoughData`. With subsecond blocks, a block sharing its parent's timestamp keeps
//! the parent's origin.
//!
//! Non-blocking: the provider returns `error.NotAvailable` while a fetch is in flight. A
//! pending fetch of the *next* origin is not an error (the current origin is used while
//! the drift allows); a pending fetch of the *current* origin is.
//!
//! The provider implements:
//!   fn l1_block_info_by_hash(self, hash: Hash) ProviderError!?BlockInfo
//!   fn l1_block_info_by_number(self, number: u64) ProviderError!?BlockInfo
//! where `l1_block_info_by_number` returns null for blocks the sequencer may not use yet
//! (beyond the confirmation depth).

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const ProviderError = @import("../derive/errors.zig").ProviderError;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;

pub const Error = ProviderError || error{
    /// Past the sequencer drift and the next L1 block is not known yet.
    NotEnoughData,
    /// The unsafe head's L1 origin is unknown to the L1 provider.
    OriginNotFound,
    /// The fetched next L1 block does not extend the current origin (L1 reorg).
    NextOriginOrphaned,
};

pub const OriginSelector = struct {
    rollup: *const RollupConfig,
    current: ?BlockInfo = null,
    next: ?BlockInfo = null,

    pub fn init(rollup: *const RollupConfig) OriginSelector {
        assert(rollup.block_time > 0 or rollup.denim_timestamp_schedule() != null);
        return .{ .rollup = rollup };
    }

    /// Drops cached origins (after an L1 reorg or a sequencer reset).
    pub fn reset(selector: *OriginSelector) void {
        selector.current = null;
        selector.next = null;
        assert(selector.current == null and selector.next == null);
    }

    /// The L1 origin for the L2 block after `unsafe_head`.
    pub fn next_l1_origin(
        selector: *OriginSelector,
        provider: anytype,
        unsafe_head: L2BlockInfo,
    ) Error!BlockInfo {
        try selector.select_origins(provider, unsafe_head);
        const chosen = try selector.choose(unsafe_head);
        assert(chosen.number == unsafe_head.l1_origin.number or
            chosen.number == unsafe_head.l1_origin.number + 1);
        return chosen;
    }

    fn select_origins(
        selector: *OriginSelector,
        provider: anytype,
        unsafe_head: L2BlockInfo,
    ) Error!void {
        const origin_hash = unsafe_head.l1_origin.hash;
        const current_matches = if (selector.current) |current|
            current.hash.eql(origin_hash)
        else
            false;
        if (!current_matches) {
            const promote = if (selector.next) |next| next.hash.eql(origin_hash) else false;
            if (promote) {
                selector.current = selector.next;
            } else {
                selector.current = try provider.l1_block_info_by_hash(origin_hash) orelse
                    return error.OriginNotFound;
            }
            selector.next = null;
        }
        const current = selector.current.?;
        assert(current.hash.eql(origin_hash));
        if (selector.next != null) return;
        const fetched = provider.l1_block_info_by_number(current.number + 1) catch |err| {
            // A pending successor fetch is not an error: the current origin may still do.
            if (err == error.NotAvailable) return;
            return err;
        };
        const next = fetched orelse return;
        if (!next.parent_hash.eql(current.hash)) return error.NextOriginOrphaned;
        assert(next.number == current.number + 1);
        selector.next = next;
    }

    fn choose(selector: *const OriginSelector, unsafe_head: L2BlockInfo) Error!BlockInfo {
        const rollup = selector.rollup;
        const current = selector.current.?;
        const next_l2_timestamp = rollup.l2_block_timestamp(unsafe_head.block_info.number + 1);
        assert(next_l2_timestamp >= unsafe_head.block_info.timestamp);
        if (rollup.is_feature_active(.subsecond_blocks, next_l2_timestamp) and
            next_l2_timestamp == unsafe_head.block_info.timestamp)
        {
            return current;
        }
        if (selector.next) |next| {
            if (next_l2_timestamp >= next.timestamp) return next;
        }
        const drift_max = rollup.max_sequencer_drift_at(current.timestamp);
        if (next_l2_timestamp -| current.timestamp <= drift_max) return current;
        // Past the drift: a known next origin that is not yet due still keeps the current one.
        if (selector.next != null) return current;
        return error.NotEnoughData;
    }
};

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const TestL1 = struct {
    /// L1 block `i` has timestamp `i * 12`.
    count: u64,
    pending: bool = false,
    fork_at: u64 = std.math.maxInt(u64),

    fn info(l1: *const TestL1, number: u64) BlockInfo {
        var hash: Hash = .{ .bytes = @splat(if (number >= l1.fork_at) 0xf0 else 0x10) };
        std.mem.writeInt(u64, hash.bytes[0..8], number, .big);
        const parent_forked = number > 0 and number - 1 >= l1.fork_at;
        var parent: Hash = .{ .bytes = @splat(if (parent_forked) 0xf0 else 0x10) };
        if (number == 0) {
            parent = .zero;
        } else std.mem.writeInt(u64, parent.bytes[0..8], number - 1, .big);
        return .{
            .hash = hash,
            .number = number,
            .parent_hash = parent,
            .timestamp = number * 12,
        };
    }

    pub fn l1_block_info_by_hash(l1: *TestL1, hash: Hash) ProviderError!?BlockInfo {
        const number = std.mem.readInt(u64, hash.bytes[0..8], .big);
        if (number >= l1.count) return null;
        const block = l1.info(number);
        return if (block.hash.eql(hash)) block else null;
    }

    pub fn l1_block_info_by_number(l1: *TestL1, number: u64) ProviderError!?BlockInfo {
        if (l1.pending) return error.NotAvailable;
        if (number >= l1.count) return null;
        return l1.info(number);
    }
};

fn origin_number(selector: *OriginSelector, l1: *TestL1, head: L2BlockInfo) Error!u64 {
    return (try selector.next_l1_origin(l1, head)).number;
}

fn l2_head(l1: *const TestL1, number: u64, origin: u64) L2BlockInfo {
    const origin_block = l1.info(origin);
    return .{
        .block_info = .{ .number = number, .timestamp = number * 2 },
        .l1_origin = .{ .number = origin, .hash = origin_block.hash },
    };
}

test "origin selector: keeps the origin until the next L1 block is due" {
    const rollup: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 600 };
    var l1: TestL1 = .{ .count = 10 };
    var selector = OriginSelector.init(&rollup);
    // Next L2 time 10 < L1 block 1 time 12: keep origin 0.
    try testing.expectEqual(@as(u64, 0), try origin_number(&selector, &l1, l2_head(&l1, 4, 0)));
    // Next L2 time 12: move to origin 1.
    try testing.expectEqual(@as(u64, 1), try origin_number(&selector, &l1, l2_head(&l1, 5, 0)));
    // The ready successor is promoted when the head adopts it.
    try testing.expectEqual(@as(u64, 1), try origin_number(&selector, &l1, l2_head(&l1, 6, 1)));
}

test "origin selector: drift, pending successor, missing origin, reorg" {
    const rollup: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 4 };
    var l1: TestL1 = .{ .count = 1 };
    var selector = OriginSelector.init(&rollup);
    // L1 block 1 unknown; within drift (next time 4 - 0 <= 4) keeps origin 0.
    try testing.expectEqual(@as(u64, 0), try origin_number(&selector, &l1, l2_head(&l1, 1, 0)));
    // Past drift with no successor.
    try testing.expectError(error.NotEnoughData, selector.next_l1_origin(&l1, l2_head(&l1, 2, 0)));
    l1.count = 5;
    l1.pending = true;
    try testing.expectError(error.NotEnoughData, selector.next_l1_origin(&l1, l2_head(&l1, 2, 0)));
    l1.pending = false;
    // Successor known but not due (12 > 6): drift is exceeded yet current stays, as base/base.
    try testing.expectEqual(@as(u64, 0), try origin_number(&selector, &l1, l2_head(&l1, 2, 0)));
    var missing = l2_head(&l1, 3, 0);
    missing.l1_origin.hash = .{ .bytes = @splat(0x77) };
    try testing.expectError(error.OriginNotFound, selector.next_l1_origin(&l1, missing));
    selector.reset();
    l1.fork_at = 2;
    const stale = l2_head(&l1, 8, 1);
    l1.fork_at = 1; // Origin 1 is now orphaned: its hash no longer resolves.
    try testing.expectError(error.OriginNotFound, selector.next_l1_origin(&l1, stale));

    // Cached origin 1, then L1 reorgs above it: the fetched successor does not extend it.
    selector.reset();
    l1.fork_at = std.math.maxInt(u64);
    l1.pending = true;
    const head = l2_head(&l1, 6, 1);
    try testing.expectEqual(@as(u64, 1), try origin_number(&selector, &l1, head));
    l1.pending = false;
    l1.fork_at = 1;
    try testing.expectError(error.NextOriginOrphaned, selector.next_l1_origin(&l1, head));
}

test "origin selector: seeded fuzz against a reference rule" {
    var prng = Prng.init(0x4f524947);
    for (0..200) |_| {
        const rollup: RollupConfig = .{
            .block_time = 1 + prng.below(4),
            .max_sequencer_drift = prng.below(40),
        };
        var l1: TestL1 = .{ .count = 1 + prng.below(30) };
        var selector = OriginSelector.init(&rollup);
        var head = l2_head(&l1, 0, 0);
        head.block_info.timestamp = 0;
        for (0..200) |_| {
            l1.pending = prng.chance(1, 4);
            const chosen = selector.next_l1_origin(&l1, head) catch |err| {
                try testing.expectEqual(error.NotEnoughData, err);
                const next_time = (head.block_info.number + 1) * rollup.block_time;
                const drift = next_time - head.l1_origin.number * 12;
                try testing.expect(drift > rollup.max_sequencer_drift);
                break;
            };
            const next_time = (head.block_info.number + 1) * rollup.block_time;
            // Invariants: origin time never exceeds the L2 time, and origins only step by one.
            try testing.expect(chosen.timestamp <= next_time);
            try testing.expect(chosen.number - head.l1_origin.number <= 1);
            head = .{
                .block_info = .{ .number = head.block_info.number + 1, .timestamp = next_time },
                .l1_origin = .{ .number = chosen.number, .hash = chosen.hash },
            };
        }
    }
}

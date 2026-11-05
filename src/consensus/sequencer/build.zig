//! Sequencer payload attributes for the next block on the unsafe head (base/base
//! `service/src/actors/sequencer/{build,pool}.rs`, `PayloadBuilder::build_on` and
//! `PoolActivation`): select the L1 origin, check it is consistent with the head, prepare
//! attributes with the stateful builder, and decide whether the transaction pool may add
//! transactions (not in recovery mode, past the sequencer drift, or on an upgrade block).
//!
//! Non-blocking: a pending provider fetch defers the build (`.deferred`), so the caller
//! retries on its next tick. Conditions that need an engine reset in base/base are reported
//! as `.reset` with the reason; the caller owns the reset.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const errors = @import("../derive/errors.zig");
const attributes_module = @import("../derive/attributes.zig");
const attributes_queue = @import("../derive/attributes_queue.zig");
const origin_module = @import("origin.zig");

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const ProviderError = errors.ProviderError;
const AttributesBuilder = attributes_module.AttributesBuilder;
const PayloadAttributes = attributes_module.PayloadAttributes;
const OriginSelector = origin_module.OriginSelector;

pub const ResetReason = enum { l1_origin_unavailable, l1_origin_orphaned, l1_origin_inconsistent };

pub const Outcome = union(enum) {
    /// Attributes for the child of `parent`; the caller owns `attributes`.
    ready: struct { attributes: PayloadAttributes, parent: L2BlockInfo, l1_origin: BlockInfo },
    /// Try again on the next tick (data in flight or a temporary error).
    deferred,
    /// Past the sequencer drift and the next L1 origin is not known yet.
    awaiting_l1_origin,
    /// The engine forkchoice must be reset before building again.
    reset: ResetReason,
};

/// Maps the derivation providers' `error.NotFound` to the null the selector expects.
pub fn OriginProvider(comptime L1: type) type {
    return struct {
        l1: L1,

        const Self = @This();

        pub fn l1_block_info_by_hash(self: Self, hash: Hash) ProviderError!?BlockInfo {
            return self.l1.l1_block_info_by_hash(hash) catch |err| switch (err) {
                error.NotFound => null,
                else => err,
            };
        }

        pub fn l1_block_info_by_number(self: Self, number: u64) ProviderError!?BlockInfo {
            return self.l1.l1_block_info_by_number(number) catch |err| switch (err) {
                error.NotFound => null,
                else => err,
            };
        }
    };
}

/// True when the transaction pool may add transactions to the block (`PoolActivation`).
pub fn pool_enabled(
    rollup: *const RollupConfig,
    recovery_mode: bool,
    l1_origin: BlockInfo,
    parent_timestamp: u64,
    timestamp: u64,
) bool {
    assert(timestamp >= parent_timestamp);
    if (recovery_mode) return false;
    if (timestamp > l1_origin.timestamp + rollup.max_sequencer_drift_at(l1_origin.timestamp)) {
        return false;
    }
    const upgrade_features = [_]protocol.rollup_config.Feature{
        .ecotone_upgrade_transactions,  .fjord_upgrade_transactions,
        .granite_transition_no_tx_pool, .holocene_transition_no_tx_pool,
        .isthmus_upgrade_transactions,  .jovian_upgrade_transactions,
    };
    for (upgrade_features) |feature| {
        if (rollup.is_feature_first_block(feature, timestamp, parent_timestamp)) return false;
    }
    return true;
}

/// Prepares the attributes of the block after `unsafe_head`.
pub fn build_on(
    selector: *OriginSelector,
    builder: *AttributesBuilder,
    l1: anytype,
    l2: anytype,
    unsafe_head: L2BlockInfo,
    recovery_mode: bool,
) errors.Error!Outcome {
    const origin_provider: OriginProvider(@TypeOf(l1)) = .{ .l1 = l1 };
    const l1_origin = selector.next_l1_origin(origin_provider, unsafe_head) catch |err| {
        return switch (err) {
            error.OriginNotFound => .{ .reset = .l1_origin_unavailable },
            error.NextOriginOrphaned => .{ .reset = .l1_origin_orphaned },
            error.NotEnoughData => .awaiting_l1_origin,
            else => .deferred,
        };
    };
    const head_origin = unsafe_head.l1_origin.hash;
    if (!head_origin.eql(l1_origin.parent_hash) and !head_origin.eql(l1_origin.hash)) {
        return .{ .reset = .l1_origin_inconsistent };
    }
    const chain: attributes_queue.BuilderChain(@TypeOf(l1), @TypeOf(l2)) = .{ .l1 = l1, .l2 = l2 };
    const epoch = l1_origin.id();
    var attributes = builder.prepare_payload_attributes(chain, unsafe_head, epoch) catch |err|
        switch (errors.kind(err)) {
            .temporary, .reset => return .deferred,
            .critical => return err,
        };
    const parent_timestamp = unsafe_head.block_info.timestamp;
    attributes.no_tx_pool = !pool_enabled(
        builder.rollup,
        recovery_mode,
        l1_origin,
        parent_timestamp,
        attributes.timestamp,
    );
    assert(attributes.transactions.len > 0); // The L1 info deposit comes first.
    return .{ .ready = .{
        .attributes = attributes,
        .parent = unsafe_head,
        .l1_origin = l1_origin,
    } };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const TestChain = @import("../derive/test_chain.zig").TestChain;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;

const Fixture = struct {
    chain: TestChain,
    rollup: RollupConfig,
    schedule: L1BlobSchedule = .{},
    selector: OriginSelector = undefined,
    builder: AttributesBuilder = undefined,
    head: L2BlockInfo = undefined,

    /// L1 blocks 0..3 every 12 s from time 1000; L2 genesis at 1000 with 2 s blocks.
    fn init(fixture: *Fixture) void {
        fixture.* = .{
            .chain = TestChain.init(4, 0, 12),
            .rollup = .{ .block_time = 2, .max_sequencer_drift = 600 },
        };
        fixture.rollup.genesis = .{ .l1 = fixture.chain.blocks[0].id(), .l2_time = 1000 };
        fixture.selector = .init(&fixture.rollup);
        fixture.builder = .init(testing.allocator, &fixture.rollup, &fixture.schedule);
        fixture.set_head(0, 1000, 0);
    }

    fn set_head(fixture: *Fixture, number: u64, timestamp: u64, origin_index: u32) void {
        var hash: Hash = .zero;
        hash.bytes[31] = @intCast(number + 1);
        fixture.head = .{
            .block_info = .{ .hash = hash, .number = number, .timestamp = timestamp },
            .l1_origin = fixture.chain.blocks[origin_index].id(),
        };
        fixture.chain.add_system_config(hash, .{});
    }

    fn build(fixture: *Fixture, recovery_mode: bool) errors.Error!Outcome {
        const chain = &fixture.chain;
        const head = fixture.head;
        return build_on(&fixture.selector, &fixture.builder, chain, chain, head, recovery_mode);
    }
};

test "sequencer build: attributes on the unsafe head, pool gating" {
    var fixture: Fixture = undefined;
    fixture.init();
    var outcome = try fixture.build(false);
    try testing.expect(outcome == .ready);
    var ready = &outcome.ready;
    defer ready.attributes.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 1002), ready.attributes.timestamp);
    try testing.expectEqual(@as(u64, 0), ready.l1_origin.number);
    try testing.expect(!ready.attributes.no_tx_pool);
    try testing.expect(ready.parent.block_info.hash.eql(fixture.head.block_info.hash));
    var empty = try fixture.build(true);
    defer empty.ready.attributes.deinit(testing.allocator);
    try testing.expect(empty.ready.attributes.no_tx_pool);
}

test "sequencer build: next epoch, inconsistent origin, missing data" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.set_head(6, 1012, 0);
    var outcome = try fixture.build(false);
    defer outcome.ready.attributes.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 1), outcome.ready.l1_origin.number);
    // A head whose origin is two L1 blocks behind the selected origin is inconsistent.
    fixture.selector.reset();
    fixture.set_head(7, 1014, 0);
    fixture.head.l1_origin = fixture.chain.blocks[2].id();
    fixture.head.l1_origin.hash.bytes[0] ^= 1;
    const reset = try fixture.build(false);
    try testing.expect(reset == .reset);
    fixture.selector.reset();
    fixture.set_head(7, 1014, 1);
    fixture.chain.unavailable_from = 1;
    try testing.expect(try fixture.build(false) == .deferred);
}

test "sequencer build: pool disabled past drift and on upgrade blocks" {
    var rollup: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 600 };
    const origin: BlockInfo = .{ .number = 1, .timestamp = 1000 };
    try testing.expect(pool_enabled(&rollup, false, origin, 1598, 1600));
    try testing.expect(!pool_enabled(&rollup, false, origin, 1600, 1602));
    try testing.expect(!pool_enabled(&rollup, true, origin, 1000, 1002));
    rollup.upgrades.set(.ecotone, 1010);
    try testing.expect(!pool_enabled(&rollup, false, origin, 1008, 1010));
    try testing.expect(pool_enabled(&rollup, false, origin, 1010, 1012));
}

test "sequencer build: seeded fuzz never builds on an unrelated origin" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x5e9);
    for (0..64) |_| {
        var fixture: Fixture = undefined;
        fixture.init();
        const number = prng.below(30);
        const origin_index: u32 = @intCast(prng.below(4));
        const time = 1000 + number * 2;
        if (time < fixture.chain.blocks[origin_index].timestamp) continue;
        fixture.set_head(number, time, origin_index);
        if (prng.chance(1, 4)) fixture.chain.unavailable_from = prng.below(5);
        const outcome = try fixture.build(prng.chance(1, 2));
        switch (outcome) {
            .ready => |ready| {
                var attributes = ready.attributes;
                defer attributes.deinit(testing.allocator);
                const head_origin = fixture.head.l1_origin.hash;
                try testing.expect(head_origin.eql(ready.l1_origin.hash) or
                    head_origin.eql(ready.l1_origin.parent_hash));
                try testing.expectEqual(time + 2, attributes.timestamp);
            },
            .deferred, .awaiting_l1_origin, .reset => {},
        }
    }
}

fn fuzz_pool_enabled(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [24]u8 = undefined;
    _ = smith.slice(&bytes);
    var rollup: RollupConfig = .{ .block_time = 2, .max_sequencer_drift = 600 };
    rollup.upgrades.set(.holocene, std.mem.readInt(u32, bytes[0..4], .little));
    const origin_time: u64 = std.mem.readInt(u32, bytes[4..8], .little);
    const parent_time: u64 = std.mem.readInt(u32, bytes[8..12], .little);
    const time = parent_time + (bytes[12] % 4);
    const origin: BlockInfo = .{ .number = 1, .timestamp = origin_time };
    const enabled = pool_enabled(&rollup, bytes[13] & 1 == 1, origin, parent_time, time);
    if (enabled) {
        try testing.expect(bytes[13] & 1 == 0);
        try testing.expect(time <= origin_time + 600);
    }
}

test "sequencer build: fuzz pool gating" {
    try testing.fuzz({}, fuzz_pool_enabled, .{});
}

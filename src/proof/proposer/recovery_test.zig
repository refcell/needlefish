//! Recovery tests ported from base/base `crates/proof/proposer/src/proof_recovery.rs`,
//! over the in-memory `FakeChain` (canonical roots are a function of the block).

const std = @import("std");
const testing = std.testing;

const recovery_module = @import("recovery.zig");
const intervals_module = @import("intervals.zig");
const fakes = @import("fakes.zig");
const target = @import("target.zig");

const Recovery = recovery_module.Recovery;
const Cache = recovery_module.Cache;
const FakeChain = fakes.FakeChain;
const Address = target.Address;
const RecoveredState = target.RecoveredState;

const game_type: u32 = 42;
const block_interval: u64 = 512;
const registry: Address = @splat(0xee);
const unlimited = std.math.maxInt(u64);

fn fixed(block: u64, intermediate: u64) intervals_module.Schedule {
    return .fixed(intervals_module.validate(block, intermediate) catch unreachable);
}

fn fake_chain(schedule: intervals_module.Schedule, anchor_block: u64) FakeChain {
    var chain: FakeChain = .{
        .game_type = game_type,
        .anchor_state_registry = registry,
        .schedule = schedule,
        .anchor = undefined,
    };
    chain.anchor = .{ .root = chain.root_at(anchor_block), .l2_block_number = anchor_block };
    return chain;
}

/// `n` canonical games chained from the anchor; returns their addresses.
fn game_chain(chain: *FakeChain, n: u32, out: []Address) void {
    var parent = if (std.mem.allEqual(u8, &chain.anchor_game, 0)) registry else chain.anchor_game;
    for (out[0..n]) |*address| {
        address.* = chain.add_canonical_game(parent);
        parent = address.*;
    }
}

fn recovery_of(chain: *FakeChain) Recovery {
    return .init(.{ .game_type = game_type, .anchor_state_registry = registry }, chain.interface());
}

fn expect_state(chain: *const FakeChain, state: RecoveredState, parent: Address, block: u64) !void {
    try testing.expectEqualSlices(u8, &parent, &state.parent);
    try testing.expectEqual(block, state.l2_block_number);
    if (block != chain.anchor.l2_block_number) {
        try testing.expectEqualSlices(u8, &chain.root_at(block), &state.output_root);
    }
}

test "proposer recovery: anchor when no games" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, registry, 0);
    try testing.expectEqualSlices(u8, &chain.anchor.root, &state.output_root);
    try testing.expect(cache != null);
}

test "proposer recovery: anchor root and game from one snapshot" {
    var chain = fake_chain(fixed(block_interval, block_interval), block_interval);
    chain.anchor.root = @splat(0xaa);
    chain.anchor_game = @splat(0x01);
    chain.unrelated_games = 1;
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try testing.expectEqualSlices(u8, &chain.anchor_game, &state.parent);
    try testing.expectEqual(@as(Hash, @splat(0xaa)), state.output_root);
    try testing.expectEqual(block_interval, state.l2_block_number);
}

const Hash = target.Hash;

test "proposer recovery: forward walk follows the game chain" {
    for ([_]u32{ 1, 2, 5 }) |count| {
        var chain = fake_chain(fixed(block_interval, block_interval), 0);
        var games: [5]Address = undefined;
        game_chain(&chain, count, &games);
        var recovery = recovery_of(&chain);
        var cache: ?Cache = null;
        const state = try recovery.recover_latest_state(&cache, unlimited);
        try expect_state(&chain, state, games[count - 1], block_interval * count);
        try testing.expectEqual(@as(u64, count), cache.?.game_count);
    }
}

test "proposer recovery: forward walk crosses the fast activation block" {
    const schedule: intervals_module.Schedule = .{
        .slow = try intervals_module.validate(100, 50),
        .fast = try intervals_module.validate(200, 100),
        .fast_activation_block = 300,
    };
    var chain = fake_chain(schedule, 0);
    var games: [5]Address = undefined;
    game_chain(&chain, 5, &games);
    try testing.expectEqual(@as(u64, 700), chain.games[4].target_block);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[4], 700);
    // The slow pair applied everywhere stalls the walk at the cadence boundary.
    chain.schedule = fixed(100, 50);
    cache = null;
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[2], 300);
}

test "proposer recovery: games lookup failure propagates" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [2]Address = undefined;
    game_chain(&chain, 2, &games);
    chain.games_should_fail = true;
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    try testing.expectError(error.Unavailable, recovery.recover_latest_state(&cache, unlimited));
    try testing.expectEqual(@as(?Cache, null), cache);
}

test "proposer recovery: walk stops where the rollup node has no block" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [3]Address = undefined;
    game_chain(&chain, 3, &games);
    chain.available_head = block_interval * 2;
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, games[1], block_interval * 2);
}

test "proposer recovery: walk bounded by the finalized head" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [4]Address = undefined;
    game_chain(&chain, 4, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const first = try recovery.recover_latest_state(&cache, block_interval * 2);
    try expect_state(&chain, first, games[1], block_interval * 2);
    // Finalized rises: the game count is unchanged, yet the cursor advances.
    const second = try recovery.recover_latest_state(&cache, block_interval * 4);
    try expect_state(&chain, second, games[3], block_interval * 4);
}

test "proposer recovery: cache hit on an equal game count" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [1]Address = undefined;
    game_chain(&chain, 1, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const first = try recovery.recover_latest_state(&cache, unlimited);
    const walks = recovery.stats.walks;
    const second = try recovery.recover_latest_state(&cache, block_interval);
    try testing.expect(first.eql(second));
    try testing.expectEqual(walks, recovery.stats.walks);
}

test "proposer recovery: cache resumes mid chain" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [5]Address = undefined;
    game_chain(&chain, 5, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = .{ .game_count = 3, .state = .{
        .parent = games[2],
        .output_root = chain.root_at(block_interval * 3),
        .l2_block_number = block_interval * 3,
    } };
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, games[4], block_interval * 5);
    try testing.expectEqual(@as(u64, 5), cache.?.game_count);
}

test "proposer recovery: unrelated games keep the cursor" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [1]Address = undefined;
    game_chain(&chain, 1, &games);
    chain.unrelated_games = 1;
    var recovery = recovery_of(&chain);
    var cache: ?Cache = .{ .game_count = 1, .state = .{
        .parent = games[0],
        .output_root = chain.root_at(block_interval),
        .l2_block_number = block_interval,
    } };
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, games[0], block_interval);
    try testing.expectEqual(@as(u64, 2), cache.?.game_count);
}

test "proposer recovery: a decreased game count invalidates the cache" {
    var chain = fake_chain(fixed(block_interval, block_interval), 0);
    var games: [1]Address = undefined;
    game_chain(&chain, 1, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = .{ .game_count = 5, .state = .{
        .parent = @splat(0x99),
        .output_root = @splat(0xdd),
        .l2_block_number = block_interval * 5,
    } };
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, games[0], block_interval);
    try testing.expectEqual(@as(u64, 1), cache.?.game_count);
}

test "proposer recovery: full walk when the anchor passed the cached tip" {
    const anchor_block = block_interval * 4;
    var chain = fake_chain(fixed(block_interval, block_interval), anchor_block);
    var games: [1]Address = undefined;
    game_chain(&chain, 1, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = .{ .game_count = 0, .state = .{
        .parent = @splat(0x99),
        .output_root = @splat(0xdd),
        .l2_block_number = block_interval,
    } };
    const state = try recovery.recover_latest_state(&cache, unlimited);
    try expect_state(&chain, state, games[0], anchor_block + block_interval);
}

test "proposer recovery: forward walk with intermediate roots" {
    var chain = fake_chain(fixed(4, 2), 0);
    var games: [2]Address = undefined;
    game_chain(&chain, 2, &games);
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[1], 8);
}

test "proposer recovery: bounded walk resumes from the cache" {
    var chain = fake_chain(fixed(4, 2), 0);
    var games: [5]Address = undefined;
    game_chain(&chain, 5, &games);
    var recovery: Recovery = .init(.{
        .game_type = game_type,
        .anchor_state_registry = registry,
        .walk_steps_max = 2,
    }, chain.interface());
    var cache: ?Cache = null;
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[1], 8);
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[3], 16);
    try expect_state(&chain, try recovery.recover_latest_state(&cache, unlimited), games[4], 20);
}

test "proposer recovery: plan skips the walk below the next target" {
    var chain = fake_chain(fixed(4, 2), 0);
    var games: [2]Address = undefined;
    game_chain(&chain, 2, &games);
    chain.finalized_head = 9;
    var recovery = recovery_of(&chain);
    var cache: ?Cache = null;
    const plan = recovery.try_recover_and_plan(&cache).?;
    try expect_state(&chain, plan.state, games[1], 8);
    try testing.expectEqual(@as(u64, 9), plan.finalized_head);
    const walks = recovery.stats.walks;
    chain.games_should_fail = true; // A walk would fail; the cached plan does not walk.
    const again = recovery.try_recover_and_plan(&cache).?;
    try testing.expect(again.state.eql(plan.state));
    try testing.expectEqual(walks, recovery.stats.walks);
    chain.finalized_head = 12;
    try testing.expect(recovery.try_recover_and_plan(&cache) == null);
}

//! Bond manager tests, ported from base/base `crates/proof/challenge/src/bond.rs`.

const std = @import("std");
const testing = std.testing;

const chain = @import("chain.zig");
const bond = @import("bond.zig");
const fake_world = @import("fake_world.zig");

const second = std.time.ns_per_s;
const claim: chain.Address = @splat(0xc1);
const stranger: chain.Address = @splat(0xdd);

fn world_fixture() !*fake_world.World {
    const world = try testing.allocator.create(fake_world.World);
    world.init(3);
    return world;
}

fn manager(claim_address: chain.Address) bond.BondManager {
    return .init(.{
        .claim_addresses = &.{claim_address},
        .lookback_games = 1000,
        .discovery_interval_ns = 10 * second,
    });
}

test "challenger bond: resolves an unresolved bond the challenger may win" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0 });
    game.bond_recipient = stranger;
    game.zk_prover = claim;
    game.expected_resolution_s = 0;
    var bonds = manager(claim);
    try bonds.discover(world.effects(), 2_000 * second);
    try testing.expectEqual(@as(u64, 1), world.stats.txs_sent);
    try testing.expectEqual(@as(u64, 1), bonds.stats.resolves_sent);
    // Within the discovery interval nothing is rescanned.
    try bonds.discover(world.effects(), 2_005 * second);
    try testing.expectEqual(@as(u64, 1), world.stats.txs_sent);
}

test "challenger bond: a zero ZK prover never matches" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0 });
    game.bond_recipient = stranger;
    game.expected_resolution_s = 0;
    var bonds = manager(@splat(0));
    try bonds.discover(world.effects(), 2_000 * second);
    try testing.expectEqual(@as(u64, 0), world.stats.txs_sent);
}

test "challenger bond: unlocks, then withdraws after the delayed WETH delay" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0 });
    game.bond_recipient = claim;
    game.status = .challenger_wins;
    game.resolved_at_s = 50;
    var bonds = manager(claim);
    world.advance(100);
    try bonds.discover(world.effects(), 100 * second);
    try testing.expectEqual(@as(u64, 1), bonds.stats.unlocks_sent);
    // While the unlock is pending the game is skipped.
    try bonds.discover(world.effects(), 120 * second);
    try testing.expectEqual(@as(u64, 1), world.stats.txs_sent);
    world.advance(121);
    try testing.expect(game.bond_unlocked);
    try testing.expectEqual(@as(u64, 121), game.withdrawal_timestamp_s);
    world.advance(150);
    try bonds.discover(world.effects(), 150 * second);
    try testing.expectEqual(@as(u64, 1), world.stats.txs_sent);
    try bonds.discover(world.effects(), 181 * second);
    try testing.expectEqual(@as(u64, 1), bonds.stats.withdrawals_sent);
    world.advance(181);
    try bonds.discover(world.effects(), 200 * second);
    try testing.expect(game.bond_claimed);
    try testing.expectEqual(@as(u64, 1), bonds.stats.withdrawals_completed);
    try bonds.discover(world.effects(), 300 * second);
    try testing.expectEqual(@as(u64, 2), world.stats.txs_sent);
    try testing.expectEqual(@as(u64, 0), world.stats.claims_reverted);
}

test "challenger bond: games owed to others are ignored" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0 });
    game.zk_prover = claim;
    game.status = .defender_wins;
    game.resolved_at_s = 10;
    var bonds = manager(claim);
    try bonds.discover(world.effects(), 100 * second);
    try testing.expectEqual(@as(u64, 0), world.stats.txs_sent);
    var disabled: bond.BondManager = .init(.{
        .claim_addresses = &.{},
        .lookback_games = 1,
        .discovery_interval_ns = second,
    });
    try disabled.discover(world.effects(), 100 * second);
    try testing.expectEqual(@as(?u64, null), disabled.last_scan_ns);
}

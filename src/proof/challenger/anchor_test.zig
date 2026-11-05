//! Anchor updater tests, ported from base/base `crates/proof/challenge/src/anchor.rs`.

const std = @import("std");
const testing = std.testing;

const chain = @import("chain.zig");
const anchor = @import("anchor.zig");
const fake_world = @import("fake_world.zig");

fn world_fixture() !*fake_world.World {
    const world = try testing.allocator.create(fake_world.World);
    world.init(5);
    return world;
}

fn updater(world: *const fake_world.World) anchor.AnchorUpdater {
    return .init(1, world.anchor_state_registry);
}

test "challenger anchor: updates to the next defender win once finalized" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0, .parent = world.anchor_state_registry });
    var anchor_updater = try testing.allocator.create(anchor.AnchorUpdater);
    defer testing.allocator.destroy(anchor_updater);
    anchor_updater.* = updater(world);
    anchor_updater.poll(world.effects(), 0);
    try testing.expect(anchor_updater.cached_next_game != null);
    try testing.expectEqual(@as(u64, 0), world.stats.txs_sent);
    world.advance(600);
    try testing.expect(world.resolve_game(game));
    anchor_updater.poll(world.effects(), 0);
    try testing.expectEqual(@as(u64, 0), world.stats.txs_sent); // Not finalized yet.
    world.advance(610);
    anchor_updater.poll(world.effects(), 0);
    try testing.expectEqual(@as(u64, 1), world.stats.txs_sent);
    world.advance(611);
    anchor_updater.poll(world.effects(), 0);
    try testing.expectEqual(game.proxy, world.anchor.anchor_game);
    try testing.expectEqual(
        @as(?@TypeOf(anchor_updater.cached_next_game.?), null),
        anchor_updater.cached_next_game,
    );
    try testing.expectEqual(@as(u64, 1), anchor_updater.stats.updates_mined);
}

test "challenger anchor: the next game builds on the current anchor game" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const first = world.add_game(.{ .starting_block = 0, .parent = world.anchor_state_registry });
    world.anchor = .{
        .anchor_game = first.proxy,
        .anchor_root = .{ .root = first.info.root_claim, .l2_block_number = 4 },
    };
    // A sibling with a wrong root and the honest successor.
    _ = world.add_game(.{ .starting_block = 4, .parent = first.proxy, .corrupt_index = 0 });
    const next = world.add_game(.{ .starting_block = 4, .parent = first.proxy });
    var anchor_updater = try testing.allocator.create(anchor.AnchorUpdater);
    defer testing.allocator.destroy(anchor_updater);
    anchor_updater.* = updater(world);
    try testing.expectEqual(
        next.proxy,
        anchor_updater.next_game(world.effects().chain, world.anchor).?,
    );
    // An unavailable checkpoint block means no next game yet.
    world.l2_head = 5;
    try testing.expectEqual(
        @as(?chain.Address, null),
        anchor_updater.next_game(world.effects().chain, world.anchor),
    );
}

test "challenger anchor: a challenger win clears the cached next game" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const game = world.add_game(.{ .starting_block = 0, .parent = world.anchor_state_registry });
    var anchor_updater = try testing.allocator.create(anchor.AnchorUpdater);
    defer testing.allocator.destroy(anchor_updater);
    anchor_updater.* = updater(world);
    game.status = .challenger_wins;
    anchor_updater.poll(world.effects(), 0);
    try testing.expect(anchor_updater.cached_next_game == null);
    try testing.expectEqual(@as(u64, 0), world.stats.txs_sent);
}

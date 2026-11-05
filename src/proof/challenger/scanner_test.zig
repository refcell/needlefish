//! Scanner tests, ported from base/base `crates/proof/challenge/src/scanner.rs`.

const std = @import("std");
const testing = std.testing;

const chain = @import("chain.zig");
const scanner_module = @import("scanner.zig");
const fake_world = @import("fake_world.zig");

const Scanner = scanner_module.Scanner;
const CandidateGame = scanner_module.CandidateGame;
const zero: chain.Address = @splat(0);
const other_prover: chain.Address = @splat(0xcc);

fn world_fixture() !*fake_world.World {
    const world = try testing.allocator.create(fake_world.World);
    world.init(7);
    return world;
}

fn scan_indices(scanner: *Scanner, world: *fake_world.World, out: []u64) ![]u64 {
    var candidates: [64]CandidateGame = undefined;
    const result = try scanner.scan(world.effects().chain, &candidates);
    for (result.candidates, 0..) |candidate, index| out[index] = candidate.index;
    return out[0..result.candidates.len];
}

test "challenger scanner: classify every prover state" {
    const tee: chain.Address = @splat(1);
    const zk: chain.Address = @splat(2);
    try testing.expectEqual(scanner_module.GameCategory.invalid_tee_proposal, scanner_module.classify(tee, zero, 0).?);
    try testing.expectEqual(@as(?scanner_module.GameCategory, null), scanner_module.classify(tee, zero, 1));
    try testing.expectEqual(scanner_module.GameCategory.invalid_dual_proposal, scanner_module.classify(tee, zk, 0).?);
    try testing.expectEqual(@as(u64, 2), scanner_module.classify(tee, zk, 3).?.fraudulent_zk_challenge);
    try testing.expectEqual(scanner_module.GameCategory.invalid_zk_proposal, scanner_module.classify(zero, zk, 0).?);
    try testing.expectEqual(@as(?scanner_module.GameCategory, null), scanner_module.classify(zero, zk, 2));
}

test "challenger scanner: happy path keeps in-progress games of every type" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    _ = world.add_game(.{ .starting_block = 90 });
    _ = world.add_game(.{ .starting_block = 140, .game_type = 99 });
    world.add_game(.{ .starting_block = 190 }).status = .challenger_wins;
    _ = world.add_game(.{ .starting_block = 290, .zk = true });
    _ = world.add_game(.{ .starting_block = 390 });
    var scanner: Scanner = .init(4096);
    var candidates: [64]CandidateGame = undefined;
    const result = try scanner.scan(world.effects().chain, &candidates);
    try testing.expectEqual(@as(usize, 4), result.candidates.len);
    const expected_indices = [_]u64{ 0, 1, 3, 4 };
    for (result.candidates, expected_indices) |candidate, index| try testing.expectEqual(index, candidate.index);
    try testing.expectEqual(@as(u32, 99), result.candidates[1].game_type);
    try testing.expectEqual(@as(u64, 94), result.candidates[0].l2_block_number);
    try testing.expectEqual(scanner_module.GameCategory.invalid_dual_proposal, result.candidates[2].category);
    try testing.expectEqual(scanner_module.GameCategory.invalid_tee_proposal, result.candidates[3].category);
    try testing.expectEqual(@as(u64, 2), result.candidates[0].intermediate_block_interval);
}

test "challenger scanner: empty factory and anchor lower bound" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    var scanner: Scanner = .init(4096);
    var indices: [64]u64 = undefined;
    try testing.expectEqual(@as(usize, 0), (try scan_indices(&scanner, world, &indices)).len);
    for (0..100) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    world.anchor.anchor_game = fake_world.game_address(96);
    try testing.expectEqualSlices(u64, &.{ 97, 98, 99 }, try scan_indices(&scanner, world, &indices));
    // A bounded scan evaluates the oldest post-anchor games first.
    world.anchor.anchor_game = zero;
    var bounded: Scanner = .init(3);
    var candidates: [64]CandidateGame = undefined;
    const result = try bounded.scan(world.effects().chain, &candidates);
    try testing.expect(result.truncated);
    try testing.expectEqual(@as(usize, 3), result.candidates.len);
}

test "challenger scanner: anchor lookup returns the match closest to the end and reports errors" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    for (0..6) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    const target = fake_world.game_address(99);
    world.games[1].proxy = target;
    world.games[3].proxy = target;
    const view = world.effects().chain;
    const clean = scanner_module.find_game_index(view, target, 0, 4);
    try testing.expectEqual(@as(?u64, 3), clean.found);
    try testing.expect(!clean.had_errors);
    world.games[4].fail_reads = true;
    const noisy = scanner_module.find_game_index(view, fake_world.game_address(5), 0, 6);
    try testing.expectEqual(@as(?u64, 5), noisy.found);
    try testing.expect(noisy.had_errors);
    const empty = scanner_module.find_game_index(view, target, 4, 4);
    try testing.expectEqual(@as(?u64, null), empty.found);
}

test "challenger scanner: cached anchor survives a failed anchor read" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    for (0..5) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    world.anchor.anchor_game = fake_world.game_address(2);
    var scanner: Scanner = .init(4096);
    var indices: [64]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, try scan_indices(&scanner, world, &indices));
    world.fail_anchor = true;
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, try scan_indices(&scanner, world, &indices));
    // An anchor missing from the factory scans from genesis.
    world.fail_anchor = false;
    world.anchor.anchor_game = fake_world.game_address(77);
    try testing.expectEqual(@as(usize, 5), (try scan_indices(&scanner, world, &indices)).len);
}

test "challenger scanner: errored games are skipped" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    for (0..3) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    world.games[1].fail_reads = true;
    var scanner: Scanner = .init(4096);
    var indices: [64]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 0, 2 }, try scan_indices(&scanner, world, &indices));
    world.games[1].fail_reads = false;
    world.games[0].fail_reads = true;
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, try scan_indices(&scanner, world, &indices));
}

test "challenger scanner: categories of challenged, ZK, dual and nullified games" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const challenged = world.add_game(.{ .starting_block = 0 });
    challenged.zk_prover = other_prover;
    challenged.countered_index = 2;
    _ = world.add_game(.{ .starting_block = 10, .tee = false, .zk = true });
    _ = world.add_game(.{ .starting_block = 20, .zk = true });
    world.add_game(.{ .starting_block = 30 }).tee_prover = zero;
    var scanner: Scanner = .init(4096);
    var candidates: [64]CandidateGame = undefined;
    const result = try scanner.scan(world.effects().chain, &candidates);
    try testing.expectEqual(@as(usize, 3), result.candidates.len);
    try testing.expectEqual(@as(u64, 1), result.candidates[0].category.fraudulent_zk_challenge);
    try testing.expectEqual(scanner_module.GameCategory.invalid_zk_proposal, result.candidates[1].category);
    try testing.expectEqual(scanner_module.GameCategory.invalid_dual_proposal, result.candidates[2].category);
}

test "challenger scanner: old post-anchor games are revisited after late transitions" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    for (0..3) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    var scanner: Scanner = .init(4096);
    var indices: [64]u64 = undefined;
    try testing.expectEqual(@as(usize, 3), (try scan_indices(&scanner, world, &indices)).len);
    world.games[0].zk_prover = other_prover;
    world.games[0].countered_index = 2;
    for (3..6) |index| _ = world.add_game(.{ .starting_block = index * 10 });
    var candidates: [64]CandidateGame = undefined;
    const result = try scanner.scan(world.effects().chain, &candidates);
    try testing.expectEqual(@as(u64, 0), result.candidates[0].index);
    try testing.expectEqual(@as(u64, 1), result.candidates[0].category.fraudulent_zk_challenge);
}

test "challenger scanner: checkpoint start blocks" {
    var candidate: CandidateGame = undefined;
    candidate.starting_block_number = 100;
    candidate.intermediate_block_interval = 5;
    try testing.expectEqual(@as(u64, 110), try candidate.checkpoint_start_block(2));
    try testing.expectError(error.Overflow, candidate.checkpoint_start_block(std.math.maxInt(u64)));
}

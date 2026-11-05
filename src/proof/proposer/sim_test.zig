//! Deterministic simulation of the proposer pipeline over the in-memory fakes.
//!
//! One seed drives everything: the finalized head advances in random steps, the prover
//! completes sessions out of order and sometimes fails or claims a wrong root, the
//! submitter drops or fails transactions, the chain view returns transient errors, the
//! anchor advances to finalized games, and L1 reorgs remove the newest games (including
//! ones the proposer created and built on). After the fault phase the faults stop and the
//! pipeline must catch up while the finalized head still grows, then the finalized head
//! freezes. Invariants are checked after every step:
//!
//! - no two live games cover the same range (unique start block),
//! - every live game commits canonical roots and a finalized target,
//! - live games form one chain from the original anchor (each parent an older live game),
//! - the dispatched ring and the prover's pending sessions stay bounded,
//! - at the end every finalized range is proposed.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const fakes = @import("fakes.zig");
const intervals_module = @import("intervals.zig");
const target = @import("target.zig");
const pipeline_test = @import("pipeline_test.zig");

const Harness = pipeline_test.Harness;
const Faults = pipeline_test.Faults;
const registry = pipeline_test.registry;

/// The finalized head grows ~0.5 blocks per step: it is still growing when the faults
/// stop (step 700, ~350) and frozen at `finalized_final` from ~step 960 on.
const finalized_final: u64 = 480;
const steps_fault: u32 = 700;
const steps_total: u32 = 1600;
const in_flight_max: u32 = 4;

const Summary = struct {
    games_created_total: u64,
    restarts: u64,
    reorgs: u32,
    tip: u64,
};

fn schedule() intervals_module.Schedule {
    return .{
        .slow = intervals_module.validate(6, 2) catch unreachable,
        .fast = intervals_module.validate(4, 2) catch unreachable,
        .fast_activation_block = 60,
    };
}

fn simulate(seed: u64) !Summary {
    var config = Harness.default_config();
    config.proofs_in_flight_max = in_flight_max;
    config.submit_timeout_ns = 10 * pipeline_test.poll_interval_ns;
    config.walk_steps_max = 8;
    const harness = try Harness.create(testing.allocator, seed, schedule(), config);
    defer testing.allocator.destroy(harness);
    set_fault_rates(harness, true);
    var anchor_index: ?u32 = null;
    var reorgs: u32 = 0;
    var step: u32 = 0;
    while (step < steps_total) : (step += 1) {
        const faulty = step < steps_fault;
        if (step == steps_fault) {
            set_fault_rates(harness, false);
            // Recovery skips rereading the factory while the finalized head is below the
            // next target (as base/base), so a reorg is noticed once finalized grows.
            try testing.expect(harness.chain.finalized_head + 32 < finalized_final);
        }
        advance_heads(harness);
        if (faulty and harness.prng.chance(1, 120)) reorgs += reorg(harness, anchor_index);
        if (faulty and harness.prng.chance(1, 200)) advance_anchor(harness, &anchor_index);
        const faults: Faults = if (faulty) .{
            .prover_complete_permille = 300,
            .prover_fail_permille = 60,
            .prover_wrong_permille = 30,
            .mine_permille = 400,
            .drop_permille = 30,
        } else .{};
        harness.step(faults);
        try check_invariants(harness);
    }
    const tip = harness.proposed_tip();
    const interval = harness.chain.schedule.for_starting_block(tip).block_interval;
    try testing.expectEqual(finalized_final, harness.chain.finalized_head);
    // Every finalized range is proposed: the next one is not finalized yet.
    try testing.expect(tip + interval > finalized_final);
    return .{
        .games_created_total = harness.chain.games_created_total,
        .restarts = harness.pipeline.stats.restarts,
        .reorgs = reorgs,
        .tip = tip,
    };
}

fn set_fault_rates(harness: *Harness, faulty: bool) void {
    harness.chain.prng = &harness.prng;
    harness.prover.prng = &harness.prng;
    harness.submitter.prng = &harness.prng;
    harness.chain.fail_permille = if (faulty) 20 else 0;
    harness.prover.fail_permille = if (faulty) 20 else 0;
    harness.submitter.fail_permille = if (faulty) 50 else 0;
}

fn advance_heads(harness: *Harness) void {
    const chain = &harness.chain;
    if (chain.finalized_head < finalized_final and harness.prng.chance(1, 2)) {
        chain.finalized_head += 1;
    }
    chain.safe_head = chain.finalized_head + 3;
    chain.available_head = chain.safe_head;
    assert(chain.finalized_head <= finalized_final);
}

/// An L1 reorg removing 1-3 of the newest games, never the anchor game.
fn reorg(harness: *Harness, anchor_index: ?u32) u32 {
    const chain = &harness.chain;
    const keep_min: u32 = if (anchor_index) |index| index + 1 else 0;
    if (chain.game_count <= keep_min) return 0;
    const removable = chain.game_count - keep_min;
    const removed: u32 = @intCast(harness.prng.range(1, @min(3, removable)));
    chain.truncate(chain.game_count - removed);
    assert(chain.game_count >= keep_min);
    return 1;
}

/// The anchor moves to a live game past the current anchor game (games are finalized).
fn advance_anchor(harness: *Harness, anchor_index: *?u32) void {
    const chain = &harness.chain;
    const first: u32 = if (anchor_index.*) |index| index + 1 else 0;
    if (chain.game_count <= first) return;
    const index: u32 = @intCast(harness.prng.range(first, chain.game_count - 1));
    const game = chain.games[index];
    chain.anchor = .{ .root = game.root_claim, .l2_block_number = game.target_block };
    chain.anchor_game = game.address;
    anchor_index.* = index;
    assert(index < chain.game_count);
}

fn check_invariants(harness: *const Harness) !void {
    const chain = &harness.chain;
    // Live games by target block; a range (start block) has at most one game.
    var by_target: [finalized_final + 1]?u32 = @splat(null);
    var by_start: [finalized_final + 1]bool = @splat(false);
    for (chain.games[0..chain.game_count], 0..) |game, index| {
        try testing.expect(game.canonical);
        try testing.expect(game.target_block <= chain.finalized_head);
        try testing.expect(!by_start[game.start_block]);
        by_start[game.start_block] = true;
        by_target[game.target_block] = @intCast(index);
    }
    // Live games form one chain: each parent is the original anchor sentinel or an older
    // live game ending where the child starts.
    for (chain.games[0..chain.game_count], 0..) |game, index| {
        if (std.mem.eql(u8, &game.parent, &registry)) {
            try testing.expectEqual(@as(u64, 0), game.start_block);
            continue;
        }
        const parent_index = by_target[game.start_block] orelse return error.MissingParent;
        try testing.expect(parent_index < index);
        try testing.expectEqualSlices(u8, &chain.games[parent_index].address, &game.parent);
    }
    try testing.expect(harness.pipeline.dispatcher.in_flight() <= in_flight_max);
    try testing.expect(harness.prover.pending_count() <= 2 * in_flight_max);
    if (harness.pipeline.collector.cursor) |cursor| {
        try testing.expect(cursor.l2_block_number <= chain.finalized_head);
    }
}

test "proposer sim: invariants hold across seeds with faults and L1 reorgs" {
    var reorgs: u32 = 0;
    var seed: u64 = 1;
    while (seed <= 8) : (seed += 1) {
        const summary = simulate(seed) catch |err| {
            std.debug.print("proposer sim: failure seed={d}\n", .{seed});
            return err;
        };
        reorgs += summary.reorgs;
        try testing.expect(summary.games_created_total > 0);
    }
    try testing.expect(reorgs > 0);
}

test "proposer sim: same seed, same execution" {
    const a = try simulate(42);
    const b = try simulate(42);
    try testing.expectEqual(a, b);
}

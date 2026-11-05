//! Pipeline scenarios over the in-memory fakes: the happy path, games created by someone
//! else, prover failures and wrong roots, submission races, timeouts, and the in-flight
//! bound. `Harness` is shared with the simulation test.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const fakes = @import("fakes.zig");
const intervals_module = @import("intervals.zig");
const pipeline_module = @import("pipeline.zig");
const target = @import("target.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Address = target.Address;
const FakeChain = fakes.FakeChain;

pub const game_type: u32 = 7;
pub const registry: Address = @splat(0xee);
pub const poll_interval_ns: u64 = 2 * std.time.ns_per_s;

pub const Faults = struct {
    prover_complete_permille: u32 = 1000,
    prover_fail_permille: u32 = 0,
    prover_wrong_permille: u32 = 0,
    mine_permille: u32 = 1000,
    drop_permille: u32 = 0,
};

/// The fakes and the pipeline at fixed addresses (interfaces hold pointers into it).
pub const Harness = struct {
    chain: FakeChain,
    prover: fakes.FakeProver,
    submitter: fakes.FakeSubmitter,
    pipeline: pipeline_module.Pipeline,
    prng: Prng,
    now_ns: u64 = 0,

    pub fn create(
        allocator: std.mem.Allocator,
        seed: u64,
        schedule: intervals_module.Schedule,
        config: pipeline_module.Config,
    ) !*Harness {
        const harness = try allocator.create(Harness);
        harness.prng = .init(seed);
        harness.now_ns = 0;
        harness.chain = .{
            .game_type = game_type,
            .anchor_state_registry = registry,
            .schedule = schedule,
            .salt = seed,
            .anchor = undefined,
        };
        harness.chain.anchor = .{ .root = harness.chain.root_at(0), .l2_block_number = 0 };
        harness.prover = .{ .chain = &harness.chain };
        harness.submitter = .init(&harness.chain);
        harness.pipeline.init(
            config,
            harness.chain.interface(),
            harness.prover.interface(),
            harness.submitter.interface(),
        );
        assert(harness.pipeline.dispatcher.in_flight() == 0);
        return harness;
    }

    pub fn default_config() pipeline_module.Config {
        return .{
            .game_type = game_type,
            .proposer = @splat(0xab),
            .anchor_state_registry = registry,
            .poll_interval_ns = poll_interval_ns,
        };
    }

    /// One poll interval: the prover and L1 progress, then the pipeline ticks.
    pub fn step(harness: *Harness, faults: Faults) void {
        harness.now_ns += poll_interval_ns;
        harness.prover.step(
            &harness.prng,
            faults.prover_complete_permille,
            faults.prover_fail_permille,
            faults.prover_wrong_permille,
        );
        harness.submitter.step(&harness.prng, faults.mine_permille, faults.drop_permille);
        harness.pipeline.tick(harness.now_ns);
    }

    pub fn run(harness: *Harness, steps: u32, faults: Faults) void {
        var index: u32 = 0;
        while (index < steps) : (index += 1) harness.step(faults);
    }

    /// The highest block of the live game chain followed from the anchor.
    pub fn proposed_tip(harness: *const Harness) u64 {
        var parent = registry;
        var block = harness.chain.anchor.l2_block_number;
        var hops: u32 = 0;
        while (hops < fakes.games_max) : (hops += 1) {
            const next = harness.child_of(parent) orelse break;
            parent = next.address;
            block = next.target_block;
        }
        return block;
    }

    pub fn child_of(harness: *const Harness, parent: Address) ?*const FakeChain.Game {
        for (harness.chain.games[0..harness.chain.game_count]) |*game| {
            if (std.mem.eql(u8, &game.parent, &parent)) return game;
        }
        return null;
    }
};

fn fixed(block: u64, intermediate: u64) intervals_module.Schedule {
    return .fixed(intervals_module.validate(block, intermediate) catch unreachable);
}

test "proposer pipeline: proposes every finalized range in order" {
    const harness = try Harness.create(testing.allocator, 1, fixed(4, 2), Harness.default_config());
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 13;
    harness.run(20, .{});
    try testing.expectEqual(@as(u32, 3), harness.chain.game_count);
    try testing.expectEqual(@as(u64, 12), harness.proposed_tip());
    for (harness.chain.games[0..3]) |game| try testing.expect(game.canonical);
    try testing.expectEqual(@as(u64, 3), harness.prover.requests_new);
    try testing.expectEqual(@as(u64, 0), harness.pipeline.stats.restarts);
    // New finalized blocks are proposed from the last game.
    harness.chain.finalized_head = 20;
    harness.run(10, .{});
    try testing.expectEqual(@as(u64, 20), harness.proposed_tip());
    try testing.expectEqual(@as(u32, 5), harness.chain.game_count);
}

test "proposer pipeline: adopts a game someone else created" {
    const harness = try Harness.create(testing.allocator, 2, fixed(4, 2), Harness.default_config());
    defer testing.allocator.destroy(harness);
    const other = harness.chain.add_canonical_game(registry);
    harness.chain.finalized_head = 8;
    harness.run(10, .{});
    try testing.expectEqual(@as(u32, 2), harness.chain.game_count);
    try testing.expectEqualSlices(u8, &other, &harness.chain.games[1].parent);
    try testing.expectEqual(@as(u64, 1), harness.submitter.sent_total);
}

test "proposer pipeline: prover failures and wrong roots are re-proved" {
    const harness = try Harness.create(testing.allocator, 3, fixed(4, 2), Harness.default_config());
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 8;
    harness.run(3, .{ .prover_fail_permille = 1000 });
    harness.run(3, .{ .prover_wrong_permille = 1000 });
    try testing.expectEqual(@as(u32, 0), harness.chain.game_count);
    try testing.expect(harness.pipeline.stats.restarts >= 2);
    try testing.expect(harness.pipeline.collector.stats.root_mismatches >= 1);
    harness.run(10, .{});
    try testing.expectEqual(@as(u64, 8), harness.proposed_tip());
    const games = harness.chain.games[0..harness.chain.game_count];
    for (games) |game| try testing.expect(game.canonical);
}

test "proposer pipeline: a creation race resolves to the existing game" {
    const harness = try Harness.create(testing.allocator, 4, fixed(4, 2), Harness.default_config());
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 4;
    harness.run(2, .{ .mine_permille = 0 }); // Our creation is pending.
    try testing.expect(harness.pipeline.collector.in_flight != null);
    const other = harness.chain.add_canonical_game(registry); // Someone else lands first.
    harness.run(3, .{});
    try testing.expectEqual(@as(u32, 1), harness.chain.game_count);
    try testing.expectEqualSlices(u8, &other, &harness.pipeline.collector.cursor.?.parent);
    try testing.expect(harness.pipeline.collector.in_flight == null);
}

test "proposer pipeline: a submit timeout restarts and recovers the landed game" {
    var config = Harness.default_config();
    config.submit_timeout_ns = 3 * poll_interval_ns;
    const harness = try Harness.create(testing.allocator, 5, fixed(4, 2), config);
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 8;
    harness.run(6, .{ .mine_permille = 0 });
    try testing.expect(harness.pipeline.collector.stats.timeouts >= 1);
    harness.run(10, .{});
    try testing.expectEqual(@as(u64, 8), harness.proposed_tip());
    try testing.expectEqual(@as(u32, 2), harness.chain.game_count);
}

test "proposer pipeline: dispatch stays within the in-flight bound" {
    var config = Harness.default_config();
    config.proofs_in_flight_max = 3;
    const harness = try Harness.create(testing.allocator, 6, fixed(4, 2), config);
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 400;
    harness.run(10, .{ .prover_complete_permille = 0 });
    try testing.expectEqual(@as(u32, 3), harness.pipeline.dispatcher.in_flight());
    try testing.expectEqual(@as(u32, 3), harness.prover.pending_count());
    harness.run(300, .{});
    try testing.expectEqual(@as(u64, 400), harness.proposed_tip());
    try testing.expect(harness.prover.pending_max <= 3);
}

test "proposer pipeline: an L1 reorg of a created game is re-proposed" {
    const harness = try Harness.create(testing.allocator, 7, fixed(4, 2), Harness.default_config());
    defer testing.allocator.destroy(harness);
    harness.chain.finalized_head = 8;
    harness.run(10, .{});
    try testing.expectEqual(@as(u32, 2), harness.chain.game_count);
    harness.chain.truncate(0);
    harness.chain.finalized_head = 12;
    harness.run(15, .{});
    try testing.expectEqual(@as(u64, 12), harness.proposed_tip());
    try testing.expectEqual(@as(u32, 3), harness.chain.game_count);
}

//! Deterministic simulation of the challenger against the in-memory world: a proposer
//! posts honest games (and fraudulent siblings), an attacker files fraudulent ZK
//! challenges, other parties resolve games, and the prover, chain reads and transactions
//! fail, time out and land out of order, all from one seed. The real driver runs on top.
//!
//! Invariants, checked every second and at the end:
//! - the challenger never disputes a valid root (the fake verifier counts `bad_disputes`),
//! - every fraudulent game is disputed (once per bad proof) and resolves for the
//!   challenger; every honest game resolves for the defender, even when attacked,
//! - no two transactions to one game are in flight at once, queues stay bounded,
//! - every bond the challenger wins is withdrawn exactly once, never before the delay.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const chain = @import("chain.zig");
const driver_module = @import("driver.zig");
const proof_manager = @import("proof_manager.zig");
const bond = @import("bond.zig");
const fake_world = @import("fake_world.zig");
const exporter_module = @import("exporter.zig");
const telemetry = @import("../telemetry/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const second = std.time.ns_per_s;
const propose_until_s = 3600;
const duration_s = 6000;
const proposal_interval_s = 30;
const attack_delay_s = 20;
const external_resolve_delay_s = 30;
const attacker: chain.Address = @splat(0xa7);

const Totals = struct {
    withdrawals: u64 = 0,
    fraudulent_games: u64 = 0,
    attacked_games: u64 = 0,
    disputes: u64 = 0,
    anchor_updates: u64 = 0,
    tee_fallbacks: u64 = 0,
};

const Sim = struct {
    world: *fake_world.World,
    driver: *driver_module.Driver,
    prng: Prng,
    next_start: u64 = 0,
    parent: chain.Address,
    attack_planned: [fake_world.games_max]bool = @splat(false),

    fn propose(sim: *Sim) void {
        const world = sim.world;
        if (world.game_count + 2 > fake_world.games_max) return;
        // The proposer may run up to two blocks ahead of the challenger's L2 view.
        if (sim.next_start + world.intervals.block > world.l2_head + 2) return;
        const zk = sim.prng.chance(4, 10);
        const honest = world.add_game(.{
            .starting_block = sim.next_start,
            .parent = sim.parent,
            .tee = !zk or sim.prng.chance(6, 10),
            .zk = zk,
        });
        const tee_only = chain.is_zero(honest.zk_prover);
        sim.attack_planned[world.game_count - 1] = tee_only and sim.prng.chance(2, 10);
        if (sim.prng.chance(35, 100)) {
            const has_tee = sim.prng.chance(7, 10);
            _ = world.add_game(.{
                .starting_block = sim.next_start,
                .parent = sim.parent,
                .tee = has_tee,
                .zk = !has_tee or sim.prng.chance(3, 10),
                .corrupt_index = @intCast(sim.prng.below(honest.root_count)),
            });
        }
        sim.parent = honest.proxy;
        sim.next_start += world.intervals.block;
        assert(honest.honest);
    }

    /// The attacker challenges planned honest TEE games with a fraudulent ZK proof, and
    /// other parties resolve games a while after their resolution time.
    fn act(sim: *Sim) void {
        const world = sim.world;
        for (world.games[0..world.game_count], 0..) |*game, index| {
            if (game.status != .in_progress) continue;
            const due = game.created_at_s + attack_delay_s <= world.now_s;
            if (sim.attack_planned[index] and !game.attacked and due) {
                game.attacked = true;
                game.zk_prover = attacker;
                game.countered_index = sim.prng.below(game.root_count) + 1;
                game.expected_resolution_s = world.now_s + world.resolution_delay_s;
            }
            if (world.now_s >= game.expected_resolution_s + external_resolve_delay_s) {
                _ = world.resolve_game(game);
            }
        }
    }

    fn check_bounds(sim: *const Sim) !void {
        const world = sim.world;
        try testing.expectEqual(@as(u64, 0), world.stats.bad_disputes);
        try testing.expectEqual(@as(u64, 0), world.stats.concurrent_game_txs);
        try testing.expectEqual(@as(u64, 0), world.stats.claims_reverted);
        try testing.expect(sim.driver.proof_manager.pending_count() <= proof_manager.attempts_max);
        try testing.expect(sim.driver.bond_manager.pending_count() <= bond.pending_max);
        try testing.expect(world.txs_in_flight() < fake_world.txs_max);
        try testing.expect(world.job_count < fake_world.jobs_max);
    }
};

fn configure_faults(world: *fake_world.World) void {
    world.faults = .{
        .read_failure = 20,
        .poll_failure = 50,
        .request_failure = 50,
        .proof_failure = 200,
        .send_rejection = 50,
        .tx_drop = 50,
        .proof_latency_s_min = 5,
        .proof_latency_s_max = 90,
        .tx_latency_s_min = 1,
        .tx_latency_s_max = 20,
    };
    world.resolution_delay_s = 900;
    world.weth_delay_s = 60;
    world.l2_head = 8;
}

fn check_game(game: *const fake_world.Game, totals: *Totals) !void {
    if (game.honest) {
        try testing.expectEqual(chain.GameStatus.defender_wins, game.status);
        if (game.attacked) {
            try testing.expectEqual(@as(u32, 1), game.disputes_ok);
            try testing.expect(chain.is_zero(game.zk_prover));
            totals.attacked_games += 1;
        } else {
            try testing.expectEqual(@as(u32, 0), game.disputes_ok);
        }
        return;
    }
    totals.fraudulent_games += 1;
    try testing.expectEqual(chain.GameStatus.challenger_wins, game.status);
    try testing.expect(game.disputes_ok >= 1);
    try testing.expect(game.disputes_ok <= game.proof_count);
    if (std.mem.eql(u8, &game.bond_recipient, &fake_world.sender)) {
        try testing.expect(game.bond_claimed);
        try testing.expectEqual(@as(u32, 1), game.withdrawals);
    } else {
        try testing.expectEqual(@as(u32, 0), game.withdrawals);
    }
}

fn run(seed: u64, totals: *Totals) !void {
    const world = try testing.allocator.create(fake_world.World);
    defer testing.allocator.destroy(world);
    world.init(seed);
    configure_faults(world);
    const driver = try testing.allocator.create(driver_module.Driver);
    defer testing.allocator.destroy(driver);
    driver.init(.{
        .game_type = 1,
        .sender = fake_world.sender,
        .anchor_state_registry = world.anchor_state_registry,
        .poll_interval_ns = 5 * second,
        .max_proof_duration_ns = 60 * second,
        .tee_submit_retry_limit = 2,
        .bond_claim_addresses = &.{fake_world.sender},
        .bond_lookback_games = 1000,
        .bond_discovery_interval_ns = 30 * second,
    }, world.effects());
    var sim: Sim = .{
        .world = world,
        .driver = driver,
        .prng = .init(seed ^ 0x5eed),
        .parent = world.anchor_state_registry,
    };
    var clock: telemetry.FakeClock = .{};
    var exporter: exporter_module.Exporter = undefined;
    try exporter.init(clock.clock(), .{ .version = "sim", .poll_interval_ns = 5 * second });
    var now_s: u64 = 0;
    while (now_s < duration_s) : (now_s += 1) {
        clock.now_ns = now_s * second;
        world.l2_head = @max(world.l2_head, 8 + now_s / 7);
        world.advance(now_s);
        if (now_s < propose_until_s and now_s % proposal_interval_s == 0) sim.propose();
        sim.act();
        driver.tick(now_s * second);
        exporter_module.observe(&exporter, driver);
        try sim.check_bounds();
    }
    // The metrics follow the driver.
    try testing.expectEqual(driver.stats.steps, exporter.counter("steps"));
    try testing.expectEqual(driver.bond_manager.stats.scans, exporter.counter("bond_scans"));
    try testing.expectEqual(
        driver.anchor_updater.stats.updates_mined,
        exporter.counter("anchor_updates_mined"),
    );
    try testing.expect(exporter.progress_ns != null);
    for (world.games[0..world.game_count]) |*game| try check_game(game, totals);
    try testing.expect(world.stats.anchor_updates > 0);
    totals.withdrawals += world.stats.withdrawals;
    totals.disputes += world.stats.disputes_ok;
    totals.anchor_updates += world.stats.anchor_updates;
    totals.tee_fallbacks += driver.proof_manager.stats.tee_fallbacks;
}

test "challenger sim: seeded runs keep the invariants" {
    var totals: Totals = .{};
    for (0..4) |seed| {
        run(seed, &totals) catch |err| {
            std.debug.print("challenger sim: failing seed {d}\n", .{seed});
            return err;
        };
    }
    // The scenarios must actually happen across the seeds.
    try testing.expect(totals.fraudulent_games > 0);
    try testing.expect(totals.attacked_games > 0);
    try testing.expect(totals.withdrawals > 0);
    try testing.expect(totals.anchor_updates > 0);
}

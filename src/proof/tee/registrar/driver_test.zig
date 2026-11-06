//! Driver tests and the deterministic registrar simulation (base/base `driver.rs` tests):
//! a static discovery list, a fake prover endpoint serving the public Nitro fixture, and
//! the in-memory L1 from `fakes.zig`. A cycle registers the fixture signer on a cold
//! `CertManager` and deregisters an orphan; seeded runs inject readiness and transaction
//! faults and must converge to the same state, reproducibly per seed.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const types = @import("types.zig");
const metrics = @import("metrics.zig");
const prover = @import("prover.zig");
const fakes = @import("fakes.zig");
const discovery_module = @import("discovery.zig");
const signer_manager = @import("signer_manager.zig");
const driver_module = @import("driver.zig");
const planner = @import("planner.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const Address = types.Address;
const Hash = types.Hash;
const Driver = driver_module.Driver;

const orphan: Address = @splat(0xbb);
const poll_interval_ms: u64 = 30_000;
const endpoint_a = "http://prover-a:8000";

/// Uncompressed secp256k1 `public_key` embedded in the fixture attestation.
const fixture_public_key = hex("0433a4701fa871b188983d570e2c2d8cf98fd66eb19ba8ca7617bc8e20e152a5" ++
    "d7f0205eae76e608ce855077e4565be69db4471ef72857253742f9602c11ff04e5");
const fixture_signer = hex("3c32c4ad111a12d7d3af032cffaff7789dfa555f");

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Literal test vectors.
    return out;
}

/// One prover endpoint serving the fixture signer.
const FakeProver = struct {
    keys: []const []const u8 = &.{&fixture_public_key},
    attestations: []const []const u8 = &.{fakes.fixture_attestation},
    fail_readyz: bool = false,
    fail_keys: bool = false,
    fail_attestations: bool = false,
    /// Fails `readyz` with this probability (in percent) when a PRNG is set.
    prng: ?*Prng = null,
    readyz_failure_percent: u8 = 0,
    readyz_calls: u32 = 0,
    attestation_calls: u32 = 0,
    nonces: [prover.signers_max]Hash = undefined,
    nonce_count: u32 = 0,

    fn of(context: *anyopaque, endpoint: []const u8) *FakeProver {
        const fake: *FakeProver = @ptrCast(@alignCast(context));
        assert(std.mem.eql(u8, endpoint, endpoint_a));
        return fake;
    }

    fn readyz(context: *anyopaque, endpoint: []const u8) prover.Error!void {
        const fake = of(context, endpoint);
        fake.readyz_calls += 1;
        if (fake.fail_readyz) return error.ProverClient;
        const prng = fake.prng orelse return;
        if (prng.chance(fake.readyz_failure_percent, 100)) return error.ProverClient;
    }

    fn lists(items: []const []const u8) prover.ByteLists {
        var result: prover.ByteLists = .{};
        for (items) |item| {
            result.items[result.count] = item;
            result.count += 1;
        }
        return result;
    }

    fn signer_public_keys(context: *anyopaque, endpoint: []const u8) prover.Error!prover.ByteLists {
        const fake = of(context, endpoint);
        if (fake.fail_keys) return error.ProverClient;
        return lists(fake.keys);
    }

    fn signer_attestations(
        context: *anyopaque,
        endpoint: []const u8,
        nonces: []const []const u8,
    ) prover.Error!prover.ByteLists {
        const fake = of(context, endpoint);
        fake.attestation_calls += 1;
        for (nonces, fake.nonces[0..nonces.len]) |nonce, *out| out.* = nonce[0..32].*;
        fake.nonce_count = @intCast(nonces.len);
        if (fake.fail_attestations) return error.ProverClient;
        return lists(fake.attestations);
    }

    const vtable: driver_module.EndpointClient.VTable = .{
        .readyz = readyz,
        .signer_public_keys = signer_public_keys,
        .signer_attestations = signer_attestations,
    };

    fn client(fake: *FakeProver) driver_module.EndpointClient {
        return .{ .context = fake, .vtable = &vtable };
    }
};

const Failing = struct {
    calls: u32 = 0,

    fn discover(
        context: *anyopaque,
        out: []types.ProverInstance,
    ) discovery_module.Error![]types.ProverInstance {
        const failing: *Failing = @ptrCast(@alignCast(context));
        assert(out.len > 0);
        failing.calls += 1;
        return error.DiscoveryFailed;
    }
};

/// The simulated registrar: fake L1 with the fixture chain known and an orphan registered.
const Sim = struct {
    fake: fakes.FakeL1,
    prover: FakeProver = .{},
    static: discovery_module.StaticDiscovery,
    failing: Failing = .{},
    stats: metrics.Stats = .{},
    manager: signer_manager.SignerManager,
    driver: Driver,
    tbs: [planner.tbs_size_max]u8,

    fn create(fail_discovery: bool) !*Sim {
        const allocator = testing.allocator;
        const sim = try allocator.create(Sim);
        errdefer allocator.destroy(sim);
        sim.fake = .init(fakes.fixture_timestamp_ms + 1000);
        sim.prover = .{};
        sim.failing = .{};
        sim.stats = .{};
        sim.static = try .parse(endpoint_a);
        const plan = try planner.AttestationPlanner.prepare_registration_plan(
            fakes.fixture_attestation,
            &sim.tbs,
        );
        sim.fake.add_plan(&plan);
        sim.fake.final_signer = plan.signer;
        sim.fake.register(orphan);
        sim.manager = try .init(allocator, .{
            .registry_address = fakes.registry_address,
            .cert_manager_address = fakes.cert_manager_address,
            .tx_retry_delay_ms = 1000,
            .max_attestation_age_s = 24 * 3600,
            .accept_null_nonce_for_tests = true,
        }, .{
            .chain = sim.fake.chain(),
            .transactor = sim.fake.transactor(),
            .clock = sim.fake.clock(),
        }, &sim.stats);
        errdefer sim.manager.deinit(allocator);
        const discovery: discovery_module.Discovery = if (fail_discovery)
            .{ .context = &sim.failing, .discover_fn = Failing.discover }
        else
            sim.static.discovery();
        try sim.driver.init(allocator, .{
            .poll_interval_ms = poll_interval_ms,
            .instance_cache_ttl_cycles = 2,
        }, discovery, sim.prover.client(), &sim.manager);
        sim.fake.cancel_target = &sim.driver.cancel;
        return sim;
    }

    fn destroy(sim: *Sim) void {
        sim.driver.deinit(testing.allocator);
        sim.manager.deinit(testing.allocator);
        testing.allocator.destroy(sim);
    }
};

test "registrar driver: one cycle registers the fixture signer and deregisters an orphan" {
    const sim = try Sim.create(false);
    defer sim.destroy();
    sim.driver.step();
    try testing.expect(sim.fake.is_registered(fixture_signer));
    try testing.expect(!sim.fake.is_registered(orphan));
    // Three CAs and the leaf cached, one registration, one orphan deregistration.
    try testing.expectEqual(@as(u32, 4), sim.fake.tx_count_to(fakes.cert_manager_address));
    try testing.expectEqual(@as(u32, 2), sim.fake.tx_count_to(fakes.registry_address));
    try testing.expectEqual(@as(u64, 1), sim.stats.registrations);
    try testing.expectEqual(@as(u64, 1), sim.stats.deregistrations);
    try testing.expectEqual(@as(u64, 1), sim.stats.proof_tasks_outcome_succeeded);
    try testing.expectEqual(@as(u64, 0), sim.stats.processing_errors);
    try testing.expectEqual(@as(u32, 1), sim.prover.nonce_count);
    const expected = sim.manager.attestation_nonce(fixture_signer);
    try testing.expectEqualSlices(u8, &expected, &sim.prover.nonces[0]);
    try testing.expectEqual(@as(u32, 1), sim.driver.resolution.gauges.active_signers);
    // The next cycle finds the signer registered and sends nothing.
    sim.driver.step();
    try testing.expectEqual(@as(u32, 6), sim.fake.sent_count);
    try testing.expectEqual(@as(u64, 1), sim.stats.registration_stage_already_registered);
    try testing.expectEqual(@as(u64, 2), sim.driver.cycles_completed);
}

test "registrar driver: unreachable instance defers orphan cleanup" {
    const sim = try Sim.create(false);
    defer sim.destroy();
    sim.prover.fail_readyz = true;
    sim.driver.step();
    try testing.expect(sim.fake.is_registered(orphan));
    try testing.expectEqual(@as(u32, 0), sim.fake.sent_count);
    try testing.expectEqual(@as(u32, 0), sim.prover.attestation_calls);
    try testing.expectEqual(@as(u32, 1), sim.driver.resolution.gauges.unresolved_instances);
}

test "registrar driver: failed discovery skips the cycle and orphan cleanup" {
    const sim = try Sim.create(true);
    defer sim.destroy();
    sim.driver.step();
    try testing.expectEqual(@as(u32, 1), sim.failing.calls);
    try testing.expectEqual(@as(u64, 1), sim.stats.processing_errors);
    try testing.expectEqual(@as(u64, 0), sim.stats.discovery_success);
    try testing.expectEqual(@as(u64, 0), sim.driver.cycles_completed);
    try testing.expect(sim.fake.is_registered(orphan));
}

test "registrar driver: missing or mismatched attestations protect but do not register" {
    for (0..3) |mode| {
        const sim = try Sim.create(false);
        defer sim.destroy();
        switch (mode) {
            0 => sim.prover.fail_attestations = true,
            1 => {
                const twice = [_][]const u8{ fakes.fixture_attestation, fakes.fixture_attestation };
                sim.prover.attestations = &twice;
            },
            else => sim.prover.fail_keys = true,
        }
        sim.driver.step();
        try testing.expect(!sim.fake.is_registered(fixture_signer));
        try testing.expectEqual(@as(u64, 0), sim.stats.proof_tasks_spawned);
        try testing.expectEqual(@as(u64, 1), sim.stats.processing_errors);
        try testing.expect(sim.fake.is_registered(orphan));
    }
}

test "registrar driver: shutdown stops the run loop" {
    const sim = try Sim.create(false);
    defer sim.destroy();
    sim.fake.cancel_at_ms = sim.fake.now_ms + poll_interval_ms + 1;
    sim.driver.run(null);
    try testing.expectEqual(@as(u64, 2), sim.driver.cycles);
    sim.driver.step();
    try testing.expectEqual(@as(u32, 6), sim.fake.sent_count);
    try testing.expectEqual(@as(u64, 2), sim.driver.cycles_completed);
}

test "registrar driver: exporter reports counters and progress" {
    const sim = try Sim.create(false);
    defer sim.destroy();
    sim.driver.step();
    const telemetry = @import("../../telemetry/root.zig");
    var clock: telemetry.FakeClock = .{ .now_ns = 5 };
    var exporter: metrics.Exporter = undefined;
    try exporter.init(clock.clock(), .{ .version = "test", .poll_interval_ns = 1 });
    driver_module.observe(&exporter, &sim.driver);
    try testing.expect(exporter.ready());
    try testing.expectEqual(@as(u64, 1), exporter.counter("registrations"));
}

/// Runs a faulty simulation for `seed`; returns a digest of every transaction and the
/// final clock.
fn simulate(seed: u64) !Hash {
    var prng = Prng.init(seed);
    const sim = try Sim.create(false);
    defer sim.destroy();
    sim.prover.prng = &prng;
    sim.prover.readyz_failure_percent = 30;
    const faults = [_]fakes.Outcome{
        .success,           .error_retryable, .apply_then_error,
        .apply_then_revert, .error_permanent,
    };
    var cycle: u32 = 0;
    while (cycle < 16) : (cycle += 1) {
        var outcomes: [4]fakes.Outcome = undefined;
        for (&outcomes) |*outcome| outcome.* = faults[prng.below(faults.len)];
        sim.fake.set_outcomes(&outcomes);
        sim.driver.step();
        if (sim.fake.is_registered(fixture_signer) and !sim.fake.is_registered(orphan)) break;
        _ = sim.fake.clock().sleep_ms(poll_interval_ms, &sim.driver.cancel);
    }
    // Faults stop: the registrar converges.
    sim.fake.set_outcomes(&.{});
    sim.prover.readyz_failure_percent = 0;
    sim.driver.step();
    try testing.expect(sim.fake.is_registered(fixture_signer));
    try testing.expect(!sim.fake.is_registered(orphan));
    try testing.expectEqual(@as(i64, 0), sim.stats.cache_tx_unsettled(.ca));
    try testing.expectEqual(@as(i64, 0), sim.stats.cache_tx_unsettled(.leaf));
    const tasks = sim.driver.tasks.metrics;
    try testing.expectEqual(tasks.spawned, tasks.completed);
    try testing.expectEqual(@as(usize, 0), sim.driver.tasks.pending().len);
    var hasher: std.crypto.hash.sha3.Keccak256 = .init(.{});
    for (sim.fake.sent[0..sim.fake.sent_count]) |*sent| hasher.update(&sent.digest);
    hasher.update(std.mem.asBytes(&sim.fake.now_ms));
    var digest: Hash = undefined;
    hasher.final(&digest);
    return digest;
}

test "registrar driver: seeded simulation converges and reproduces" {
    for ([_]u64{ 1, 2, 3 }) |seed| {
        const first = try simulate(seed);
        const second = try simulate(seed);
        try testing.expectEqualSlices(u8, &first, &second);
    }
}

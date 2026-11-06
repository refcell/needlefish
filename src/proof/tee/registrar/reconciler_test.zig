//! Tests for signer reconciliation (base/base `reconciler.rs` tests). Pending tasks
//! come from a `RegistrationTaskSet` driven directly instead of tokio tasks.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const reconciler_module = @import("reconciler.zig");
const registration_tasks = @import("registration_tasks.zig");
const types = @import("types.zig");
const fuzz = @import("../../../testing/fuzz.zig");

const Address = types.Address;
const Observation = reconciler_module.Observation;
const RegisterableSigner = reconciler_module.RegisterableSigner;
const SignerReconciler = reconciler_module.SignerReconciler;
const SignerReconciliation = reconciler_module.SignerReconciliation;
const RegistrationTaskSet = registration_tasks.RegistrationTaskSet;

const signer_a: Address = @splat(1);
const signer_b: Address = @splat(2);
const signer_absent: Address = @splat(3);
const ep1 = "10.0.0.1:8000";
const ep2 = "10.0.0.2:8000";
const ep3 = "10.0.0.3:8000";

fn instance(endpoint: []const u8, health: types.InstanceHealthStatus) types.ProverInstance {
    var id_buffer: [64]u8 = undefined;
    var url_buffer: [128]u8 = undefined;
    const id = std.fmt.bufPrint(&id_buffer, "i-{s}", .{endpoint}) catch unreachable; // Short.
    const url = std.fmt.bufPrint(&url_buffer, "http://{s}", .{endpoint}) catch unreachable;
    return .{
        .instance_id = types.InstanceId.init(id) catch unreachable,
        .endpoint = types.BoundedString(types.endpoint_size_max).init(url) catch unreachable,
        .health_status = health,
    };
}

fn healthy(endpoint: []const u8) types.ProverInstance {
    return instance(endpoint, .healthy);
}

fn id_of(endpoint: []const u8) []const u8 {
    const static = struct {
        var buffers: [3][64]u8 = undefined;
    };
    const slot: usize = endpoint[7] - '1';
    return std.fmt.bufPrint(&static.buffers[slot], "i-{s}", .{endpoint}) catch unreachable;
}

/// Storage for registerable entries referenced by observations.
const Registerables = struct {
    entries: [8][4]RegisterableSigner = undefined,
    used: u32 = 0,

    fn resolved(
        storage: *Registerables,
        endpoint: []const u8,
        signers: []const Address,
        registerable_signers: []const Address,
    ) Observation {
        assert(registerable_signers.len <= 4 and storage.used < storage.entries.len);
        const row = &storage.entries[storage.used];
        storage.used += 1;
        const source = healthy(endpoint);
        for (registerable_signers, 0..) |signer, index| {
            row[index] = .{ .instance = source, .signer = signer, .attestation = &.{1} };
        }
        return .{ .instance = source, .observation = .{ .resolved = .{
            .signers = signers,
            .registerable = row[0..registerable_signers.len],
        } } };
    }
};

fn resolved_only(endpoint: []const u8, signers: []const Address) Observation {
    return .{ .instance = healthy(endpoint), .observation = .{ .resolved = .{
        .signers = signers,
        .registerable = &.{},
    } } };
}

fn observed(endpoint: []const u8, observation: reconciler_module.InstanceObservation) Observation {
    return .{ .instance = healthy(endpoint), .observation = observation };
}

const Harness = struct {
    reconciler: *SignerReconciler,
    result: *SignerReconciliation,
    tasks: RegistrationTaskSet = .{},

    fn init(ttl_cycles: u32) !Harness {
        const reconciler = try testing.allocator.create(SignerReconciler);
        reconciler.* = SignerReconciler.init(ttl_cycles);
        const result = try testing.allocator.create(SignerReconciliation);
        return .{ .reconciler = reconciler, .result = result };
    }

    fn deinit(harness: *Harness) void {
        testing.allocator.destroy(harness.reconciler);
        testing.allocator.destroy(harness.result);
    }

    fn step(harness: *Harness, observations: []const Observation) !*SignerReconciliation {
        try harness.reconciler.step(observations, harness.tasks.pending(), harness.result);
        return harness.result;
    }

    fn step_without_pending(
        harness: *Harness,
        observations: []const Observation,
    ) !*SignerReconciliation {
        try harness.reconciler.step(observations, &.{}, harness.result);
        return harness.result;
    }

    fn spawn_pending(harness: *Harness, signer: Address, instance_id: []const u8) !void {
        _ = (try harness.tasks.spawn(signer, instance_id)).?;
    }
};

fn expect_cancels(result: *const SignerReconciliation, want: []const Address) !void {
    try testing.expectEqual(want.len, result.cancels().len);
    for (want, result.cancels()) |expected, actual| {
        try testing.expectEqualSlices(u8, &expected, &actual);
    }
}

fn protects(result: *const SignerReconciliation, signer: Address) !bool {
    const protected = result.protected() orelse return error.TestExpectedCleanup;
    return protected.contains(&signer);
}

test "registrar reconciler: spawns once per distinct signer from its first instance" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    const observations = [_]Observation{
        storage.resolved(ep1, &.{signer_a}, &.{signer_a}),
        storage.resolved(ep2, &.{ signer_a, signer_b }, &.{ signer_a, signer_b }),
    };
    const result = try harness.step(&observations);
    try testing.expectEqual(@as(usize, 2), result.spawns().len);
    const first = reconciler_module.spawn_entry(&observations, result.spawns()[0]);
    const second = reconciler_module.spawn_entry(&observations, result.spawns()[1]);
    try testing.expectEqualSlices(u8, &signer_a, &first.signer);
    try testing.expectEqualStrings(id_of(ep1), first.instance.instance_id.slice());
    try testing.expectEqualSlices(u8, &signer_b, &second.signer);
    try testing.expectEqualStrings(id_of(ep2), second.instance.instance_id.slice());
}

test "registrar reconciler: keeps registerable and unresolved pending, cancels the rest" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    try harness.spawn_pending(signer_a, id_of(ep1));
    try harness.spawn_pending(signer_b, id_of(ep2));
    try harness.spawn_pending(signer_absent, id_of(ep3));
    const result = try harness.step(&.{
        storage.resolved(ep1, &.{signer_a}, &.{signer_a}),
        observed(ep2, .failed),
    });
    try expect_cancels(result, &.{signer_absent});
    try testing.expectEqual(@as(usize, 0), result.spawns().len);
}

test "registrar reconciler: cancelled unreaped task blocks respawn and stays protected" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    try harness.spawn_pending(signer_a, id_of(ep1));
    try testing.expect(harness.tasks.cancel(&signer_a));
    const result = try harness.step(&.{storage.resolved(ep1, &.{}, &.{signer_a})});
    try testing.expectEqual(@as(usize, 0), result.spawns().len);
    try testing.expect(try protects(result, signer_a));
}

test "registrar reconciler: protects signers spawned this cycle" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    const result = try harness.step(&.{storage.resolved(ep1, &.{}, &.{signer_a})});
    try testing.expectEqual(@as(usize, 1), result.spawns().len);
    try testing.expect(try protects(result, signer_a));
}

test "registrar reconciler: missing instance events report grace and expiration" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    _ = try harness.step(&.{resolved_only(ep1, &.{signer_a})});
    try testing.expectEqual(@as(usize, 0), harness.result.events().len);
    for (1..4) |ttl_cycles| {
        const result = try harness.step(&.{});
        try testing.expectEqual(@as(usize, 1), result.events().len);
        const event = result.events()[0];
        try testing.expectEqualStrings(id_of(ep1), event.instance_id.slice());
        try testing.expectEqual(@as(u32, @intCast(ttl_cycles)), event.ttl_cycles);
        try testing.expectEqual(ttl_cycles > 2, event.expired);
        try testing.expectEqual(@as(u32, 1), event.cached_signers);
    }
    try testing.expectEqual(@as(usize, 0), (try harness.step(&.{})).events().len);
}

test "registrar reconciler: protects active and cancelled pending signers" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, "absent");
    try testing.expect(harness.tasks.cancel(&signer_b));
    const result = try harness.step(&.{resolved_only(ep1, &.{signer_a})});
    try testing.expect(try protects(result, signer_a));
    try testing.expect(try protects(result, signer_b));
    try testing.expect(!try protects(result, @splat(0)));
}

test "registrar reconciler: unavailable attestations block cleanup" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, id_of(ep1));
    const result = try harness.step(&.{
        observed(ep1, .{ .attestations_unavailable = .{ .signers = &.{signer_a} } }),
    });
    try testing.expectEqual(@as(usize, 0), result.cancels().len);
    try testing.expect(result.protected() == null);
    try testing.expectEqual(@as(usize, 0), result.spawns().len);
}

test "registrar reconciler: empty discovery allows cleanup" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, id_of(ep1));
    const result = try harness.step(&.{});
    try expect_cancels(result, &.{signer_b});
    try testing.expect(!try protects(result, signer_a));
    try testing.expectEqual(@as(usize, 0), result.spawns().len);
}

test "registrar reconciler: missing signers block cleanup until grace expires" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, id_of(ep1));
    _ = try harness.step_without_pending(&.{resolved_only(ep1, &.{signer_a})});
    for (0..2) |_| {
        const result = try harness.step(&.{});
        try testing.expectEqual(@as(usize, 0), result.cancels().len);
        try testing.expect(result.protected() == null);
        try testing.expectEqual(@as(usize, 0), result.spawns().len);
    }
    const expired = try harness.step(&.{});
    try expect_cancels(expired, &.{signer_b});
    try testing.expect(!try protects(expired, signer_a));
}

test "registrar reconciler: initially unreachable defers exactly one grace period" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, id_of(ep1));
    for (1..6) |cycle| {
        const result = try harness.step(&.{observed(ep1, .@"unreachable")});
        try testing.expectEqual(@as(usize, 0), result.spawns().len);
        if (cycle <= 2) {
            try testing.expectEqual(@as(usize, 0), result.cancels().len);
            try testing.expect(result.protected() == null);
        } else {
            try expect_cancels(result, &.{signer_b});
            try testing.expect(!try protects(result, signer_a));
        }
    }
}

test "registrar reconciler: discovered failure blocks cleanup without aging cache" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    try harness.spawn_pending(signer_a, id_of(ep1));
    try harness.spawn_pending(signer_absent, id_of(ep2));
    _ = try harness.step_without_pending(&.{resolved_only(ep1, &.{signer_a})});
    _ = try harness.step_without_pending(&.{});
    const failing = [_]Observation{
        observed(ep1, .failed),
        storage.resolved(ep2, &.{signer_b}, &.{signer_b}),
    };
    for (0..3) |_| {
        const result = try harness.step(&failing);
        try expect_cancels(result, &.{signer_absent});
        try testing.expect(result.protected() == null);
        try testing.expectEqual(@as(usize, 1), result.spawns().len);
    }
    harness.tasks.begin_drain();
    harness.tasks.complete(&signer_a, .succeeded);
    harness.tasks.complete(&signer_absent, .succeeded);
    const result = try harness.step(&.{ observed(ep1, .@"unreachable"), resolved_only(ep2, &.{}) });
    try testing.expect(try protects(result, signer_a));
    const expired = try harness.step(&.{observed(ep1, .@"unreachable")});
    try testing.expect(!try protects(expired, signer_a));
}

test "registrar reconciler: cached unreachable signers stay protected without blocking" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_b, id_of(ep1));
    _ = try harness.step_without_pending(&.{resolved_only(ep1, &.{signer_a})});
    for (0..4) |round| {
        const result = try harness.step(&.{observed(ep1, .@"unreachable")});
        try expect_cancels(result, &.{signer_b});
        try testing.expectEqual(@as(usize, 0), result.spawns().len);
        try testing.expectEqual(round < 2, try protects(result, signer_a));
    }
}

test "registrar reconciler: refresh resets missing grace period" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    for (0..2) |_| {
        const result = try harness.step(&.{resolved_only(ep1, &.{signer_a})});
        try testing.expect(try protects(result, signer_a));
        try testing.expect((try harness.step(&.{})).protected() == null);
    }
    try testing.expect((try harness.step(&.{})).protected() == null);
    try testing.expect(!try protects(try harness.step(&.{}), signer_a));
}

test "registrar reconciler: draining instances protect all signers without registration" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    try harness.spawn_pending(signer_absent, id_of(ep1));
    const signers = [_]Address{ signer_a, signer_b };
    const result = try harness.step(&.{.{
        .instance = instance(ep1, .draining),
        .observation = .{ .resolved = .{ .signers = &signers, .registerable = &.{} } },
    }});
    try expect_cancels(result, &.{signer_absent});
    try testing.expectEqual(@as(usize, 0), result.spawns().len);
    for (signers) |signer| try testing.expect(try protects(result, signer));
}

test "registrar reconciler: failed discovered instances add no cached active signers" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    _ = try harness.step(&.{resolved_only(ep1, &.{signer_a})});
    const result = try harness.step(&.{observed(ep1, .failed)});
    try testing.expectEqual(reconciler_module.Gauges{
        .discovered_instances = 1,
        .active_signers = 0,
        .registerable_signers = 0,
        .unresolved_instances = 1,
    }, result.gauges);
}

test "registrar reconciler: attestation failures refresh and protect resolved signers" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    _ = try harness.step(&.{resolved_only(ep1, &.{signer_b})});
    _ = try harness.step(&.{});
    const unavailable = try harness.step(&.{observed(ep1, .{
        .attestations_unavailable = .{ .signers = &.{ signer_a, signer_a } },
    })});
    try testing.expect(unavailable.protected() == null);
    try testing.expectEqual(@as(usize, 0), unavailable.spawns().len);
    for (0..2) |_| {
        const result = try harness.step(&.{observed(ep1, .@"unreachable")});
        try testing.expect(try protects(result, signer_a));
        try testing.expect(!try protects(result, signer_b));
    }
    const result = try harness.step(&.{observed(ep1, .@"unreachable")});
    try testing.expect(!try protects(result, signer_a));
}

test "registrar reconciler: unresolved cycles count cached and attested active signers" {
    var harness = try Harness.init(2);
    defer harness.deinit();
    var storage: Registerables = .{};
    const doubled = [_]Address{ signer_a, signer_a };
    const resolved = [_]Observation{storage.resolved(ep1, &doubled, &.{signer_a})};
    const unavailable = [_]Observation{
        observed(ep1, .{ .attestations_unavailable = .{ .signers = &doubled } }),
    };
    const rounds = [_]struct { observations: []const Observation, want: [4]u32 }{
        .{ .observations = &resolved, .want = .{ 1, 1, 0, 1 } },
        .{ .observations = &.{}, .want = .{ 1, 0, 1, 0 } },
        .{ .observations = &unavailable, .want = .{ 1, 0, 1, 1 } },
        .{ .observations = &.{observed(ep1, .@"unreachable")}, .want = .{ 1, 0, 0, 1 } },
        .{ .observations = &.{}, .want = .{ 1, 0, 1, 0 } },
        .{ .observations = &.{}, .want = .{ 0, 0, 0, 0 } },
    };
    for (rounds) |round| {
        const gauges = (try harness.step_without_pending(round.observations)).gauges;
        try testing.expectEqual(round.want, [4]u32{
            gauges.active_signers,
            gauges.registerable_signers,
            gauges.unresolved_instances,
            gauges.discovered_instances,
        });
    }
}

/// Property: over random observation sequences, cancels are pending signers,
/// spawns are distinct non-pending registerable signers, and a cleanup set always
/// covers every pending and spawned signer.
fn fuzz_steps(_: void, smith: *testing.Smith) anyerror!void {
    var harness = try Harness.init(smith.valueRangeAtMost(u32, 0, 3));
    defer harness.deinit();
    const endpoints = [_][]const u8{ ep1, ep2, ep3 };
    const pool = [_]Address{ signer_a, signer_b, signer_absent, @splat(4) };
    var cycle: u32 = 0;
    while (cycle < 8 and !smith.eosWeightedSimple(1, 7)) : (cycle += 1) {
        var storage: Registerables = .{};
        var observations: [3]Observation = undefined;
        var count: u32 = 0;
        for (endpoints) |endpoint| {
            const choice = smith.valueRangeAtMost(u8, 0, 4);
            const first = smith.valueRangeLessThan(u32, 0, pool.len);
            const signers = pool[first..@min(pool.len, first + 2)];
            observations[count] = switch (choice) {
                0 => continue,
                1 => observed(endpoint, .@"unreachable"),
                2 => observed(endpoint, .failed),
                3 => observed(endpoint, .{ .attestations_unavailable = .{ .signers = signers } }),
                else => storage.resolved(endpoint, signers, signers[0..1]),
            };
            count += 1;
        }
        if (smith.value(bool)) {
            const signer = pool[smith.valueRangeLessThan(u32, 0, pool.len)];
            _ = try harness.tasks.spawn(signer, endpoints[smith.valueRangeLessThan(u32, 0, 3)]);
        }
        const result = try harness.step(observations[0..count]);
        try check_invariants(&harness, observations[0..count], result);
        for (result.cancels()) |signer| _ = harness.tasks.cancel(&signer);
        if (smith.value(bool) and harness.tasks.pending().len > 0) {
            harness.tasks.complete(&harness.tasks.pending()[0].signer, .succeeded);
        }
    }
}

fn check_invariants(
    harness: *const Harness,
    observations: []const Observation,
    result: *const SignerReconciliation,
) !void {
    for (result.cancels()) |signer| try testing.expect(harness.tasks.contains(&signer));
    var seen: reconciler_module.SignerSet = .{};
    for (result.spawns()) |ref| {
        const signer = reconciler_module.spawn_entry(observations, ref).signer;
        try testing.expect(!harness.tasks.contains(&signer));
        try testing.expect(!seen.contains(&signer));
        try seen.insert(signer);
    }
    const protected = result.protected() orelse return;
    for (harness.tasks.pending()) |*task| try testing.expect(protected.contains(&task.signer));
    for (seen.slice()) |*signer| try testing.expect(protected.contains(signer));
}

test "registrar reconciler: fuzz step sequences" {
    try fuzz.run({}, fuzz_steps, .{ .iterations = 256 });
}

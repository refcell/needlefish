//! Tests for signer lifecycle orchestration (base/base `signer_manager.rs` tests) against
//! the in-memory registrar world in `fakes.zig`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const types = @import("types.zig");
const planner = @import("planner.zig");
const crl = @import("crl.zig");
const l1 = @import("l1.zig");
const metrics = @import("metrics.zig");
const reconciler = @import("reconciler.zig");
const fakes = @import("fakes.zig");
const signer_manager = @import("signer_manager.zig");
const nitro_verify = @import("../nitro/verify.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");

const Address = types.Address;
const Hash = types.Hash;
const SignerManager = signer_manager.SignerManager;
const FakeL1 = fakes.FakeL1;

const signer_a: Address = @splat(0xaa);
const signer_b: Address = @splat(0xbb);
const max_age_s: u64 = 3600;
const retry_delay_ms: u64 = 1000;
const fixture_now_ms = fakes.fixture_timestamp_ms + 1000;
const synthetic_now_ms: u64 = 1_800_000_000_000;
const synthetic_certs = [4][1]u8{ .{1}, .{2}, .{3}, .{4} };

/// A synthetic four-certificate plan whose slices point into the struct itself.
const Synthetic = struct {
    plan: types.RegistrationPlan,
    nonce: Hash,
    tbs: [1]u8,

    fn init(synthetic: *Synthetic, signer: Address, now_ms: u64) void {
        synthetic.nonce = SignerManager.attestation_nonce_for(fakes.registry_address, signer);
        synthetic.tbs = .{signer[19]};
        const plan = &synthetic.plan;
        plan.* = .{
            .signer = signer,
            .pcr0 = @splat(0x42),
            .timestamp_ms = now_ms - 1000,
            .nonce = &synthetic.nonce,
            .root_cert_hash = planner.pinned_root_cert_hash,
            .root_cert = nitro_verify.aws_nitro_root_der,
            .leaf_cert_hash = undefined,
            .attestation_tbs = &synthetic.tbs,
            .signature = @splat(0x66),
            .certs = undefined,
            .cert_count = 4,
        };
        var parent = planner.pinned_root_cert_hash;
        for (plan.certs[0..4], 0..) |*cert, index| {
            const tag: u8 = @intCast(index + 1);
            cert.* = .{
                .kind = if (tag == 4) .leaf else .ca,
                .label = types.Label.init("certificate") catch unreachable, // 11 bytes.
                .cert = &synthetic_certs[index],
                .cert_hash = @splat(tag),
                .parent_cert_hash = parent,
                .revocation_id = @splat(tag + 0x10),
            };
            parent = cert.cert_hash;
        }
        plan.leaf_cert_hash = parent;
    }
};

fn synthetic_hints(allocator: std.mem.Allocator) !*types.RegistrationHints {
    const hints = try allocator.create(types.RegistrationHints);
    hints.cert_count = 4;
    for (hints.cert_signature_hints[0..4], 1..) |*stream, tag| {
        @memset(stream.bytes[0..48], @intCast(tag));
        stream.length = 48;
    }
    @memset(hints.attestation_hints.bytes[0..48], 0x77);
    hints.attestation_hints.length = 48;
    return hints;
}

/// A manager over a fake world; heap-allocated so pointers stay put.
const Harness = struct {
    fake: FakeL1,
    stats: metrics.Stats = .{},
    manager: SignerManager,
    cancel: l1.Cancel = .{},

    fn create(now_ms: u64, options: Options) !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.* = .{ .fake = .init(now_ms), .manager = undefined };
        harness.fake.cancel_target = &harness.cancel;
        harness.manager = try .init(testing.allocator, .{
            .registry_address = fakes.registry_address,
            .cert_manager_address = fakes.cert_manager_address,
            .max_tx_retries = options.max_tx_retries,
            .tx_retry_delay_ms = retry_delay_ms,
            .max_attestation_age_s = options.max_age_s,
            .crl_fetcher = options.crl_fetcher,
            .accept_null_nonce_for_tests = options.accept_null_nonce,
        }, .{
            .chain = harness.fake.chain(),
            .transactor = harness.fake.transactor(),
            .clock = harness.fake.clock(),
        }, &harness.stats);
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.manager.deinit(testing.allocator);
        testing.allocator.destroy(harness);
    }

    const Options = struct {
        max_tx_retries: u32 = signer_manager.default_max_tx_retries,
        max_age_s: u64 = max_age_s,
        crl_fetcher: ?crl.CrlFetcher = null,
        accept_null_nonce: bool = false,
    };

    /// base/base `cache_and_register`: cache every certificate, then register.
    fn cache_and_register(harness: *Harness, plan: *const types.RegistrationPlan) !void {
        const hints = try synthetic_hints(testing.allocator);
        defer testing.allocator.destroy(hints);
        const manager = &harness.manager;
        for (plan.cert_plans(), hints.cert_streams()) |*cert, *stream| {
            const cancel = &harness.cancel;
            const timestamp_ms = plan.timestamp_ms;
            if (!try manager.ensure_cert_cached(cert, stream.slice(), timestamp_ms, cancel)) return;
        }
        try manager.submit_registration(plan.signer, plan, hints, &harness.cancel);
    }
};

fn fixture_plan(tbs: []u8) types.RegistrationPlan {
    const prepare = planner.AttestationPlanner.prepare_registration_plan;
    return prepare(fakes.fixture_attestation, tbs) catch
        unreachable; // The fixture parses.
}

fn crl_infos(
    plan: *const types.RegistrationPlan,
    out: *[types.cert_plan_count_max]crl.CertCrlInfo,
) []crl.CertCrlInfo {
    return crl.CertCrlInfo.from_cert_plans(plan.cert_plans(), out) catch unreachable; // Fixture.
}

var fixture_tbs: [planner.tbs_size_max]u8 = undefined;

test "signer manager: revoked deregistration retries and observes ambiguous success" {
    const cases = [_]struct { outcome: fakes.Outcome, sends: u32 }{
        .{ .outcome = .error_retryable, .sends = 2 },
        .{ .outcome = .apply_then_error, .sends = 1 },
        .{ .outcome = .apply_then_revert, .sends = 1 },
    };
    for (cases) |case| {
        const plan = fixture_plan(&fixture_tbs);
        const harness = try Harness.create(fixture_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&plan);
        harness.fake.register(plan.signer);
        harness.fake.revoke(plan.certs[0].revocation_id);
        harness.fake.set_outcomes(&.{case.outcome});
        try testing.expectError(
            error.RevokedCertificate,
            harness.manager.check_revocations(&plan, &harness.cancel),
        );
        try testing.expect(!harness.fake.is_registered(plan.signer));
        try testing.expectEqual(case.sends, harness.fake.tx_count_to(fakes.registry_address));
    }
}

test "signer manager: cancellation during revoked deregistration backoff stops retry" {
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    harness.fake.register(signer_a);
    harness.fake.set_outcomes(&.{.error_retryable});
    harness.fake.cancel_at_ms = synthetic_now_ms + 500;
    try harness.manager.submit_deregistration(signer_a, &harness.cancel);
    try testing.expect(harness.fake.is_registered(signer_a));
    try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
}

test "signer manager: forged public attestation cannot deregister its signer" {
    for ([_]bool{ true, false }) |onchain_revoked| {
        const signer = fixture_plan(&fixture_tbs).signer;
        const nonce = SignerManager.attestation_nonce_for(fakes.registry_address, signer);
        var forged_buffer: [fakes.fixture_attestation.len + 64]u8 = undefined;
        const forged = fakes.fixture_with_nonce(&nonce, &forged_buffer);
        var tbs: [planner.tbs_size_max]u8 = undefined;
        const plan = try planner.AttestationPlanner.prepare_registration_plan(forged, &tbs);
        var infos_buffer: [types.cert_plan_count_max]crl.CertCrlInfo = undefined;
        const infos = crl_infos(&plan, &infos_buffer);
        var clean_buffer: [160]u8 = undefined;
        var revoked_buffer: [160]u8 = undefined;
        var fake_crl: fakes.FakeCrl = .{ .responses = &.{
            fakes.build_crl(null, &clean_buffer),
            fakes.build_crl(infos[1].serial(), &revoked_buffer),
        } };
        const harness = try Harness.create(fixture_now_ms, .{ .crl_fetcher = fake_crl.fetcher() });
        defer harness.destroy();
        harness.fake.add_plan(&plan);
        harness.fake.register(signer);
        if (onchain_revoked) harness.fake.revoke(plan.certs[0].revocation_id);
        const result = harness.manager.register_signer(signer, forged, &harness.cancel);
        try testing.expect(std.meta.isError(result));
        try testing.expect(result != error.RevokedCertificate);
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
        try testing.expect(harness.fake.is_registered(signer));
    }
}

test "signer manager: tampered plan with prepared hints cannot submit transactions" {
    const hints = try synthetic_hints(testing.allocator);
    defer testing.allocator.destroy(hints);
    for ([_]bool{ true, false }) |revoked| {
        var plan = fixture_plan(&fixture_tbs);
        const nonce = SignerManager.attestation_nonce_for(fakes.registry_address, signer_b);
        plan.signer = signer_b;
        plan.nonce = &nonce;
        const harness = try Harness.create(fixture_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&plan);
        if (revoked) {
            harness.fake.register(signer_b);
            harness.fake.revoke(plan.certs[0].revocation_id);
        }
        try testing.expectError(
            error.PlanMismatch,
            harness.manager.register_plan(signer_b, &plan, hints, &harness.cancel),
        );
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    }
}

test "signer manager: indeterminate CRLs block registration without transactions" {
    var crl_buffer: [160]u8 = undefined;
    const clean = fakes.build_crl(null, &crl_buffer);
    const failures = [_]struct { first: ?[]const u8, expected: anyerror }{
        .{ .first = null, .expected = error.CrlFetchFailed },
        .{ .first = "invalid DER", .expected = error.CrlParse },
    };
    const hints = try synthetic_hints(testing.allocator);
    defer testing.allocator.destroy(hints);
    for (failures) |failure| {
        var fake_crl: fakes.FakeCrl = .{ .responses = &.{ failure.first, clean } };
        var plan = fixture_plan(&fixture_tbs);
        const nonce = SignerManager.attestation_nonce_for(fakes.registry_address, plan.signer);
        plan.nonce = &nonce;
        const harness = try Harness.create(fixture_now_ms, .{ .crl_fetcher = fake_crl.fetcher() });
        defer harness.destroy();
        harness.fake.add_plan(&plan);
        harness.fake.precache(&plan, plan.cert_count);
        try testing.expectError(
            failure.expected,
            harness.manager.register_plan(plan.signer, &plan, hints, &harness.cancel),
        );
        harness.fake.register(plan.signer);
        fake_crl.calls = 0;
        try testing.expectError(
            failure.expected,
            harness.manager.register_plan(plan.signer, &plan, hints, &harness.cancel),
        );
        // Indeterminate status is not evidence for deregistration.
        try testing.expect(harness.fake.is_registered(plan.signer));
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
        try testing.expectEqual(@as(u64, 2), harness.stats.crl_check_outcome_indeterminate);
    }
}

test "signer manager: clean CRLs allow the authenticated chain" {
    var crl_buffer: [160]u8 = undefined;
    var fake_crl: fakes.FakeCrl = .{ .responses = &.{fakes.build_crl(null, &crl_buffer)} };
    const plan = fixture_plan(&fixture_tbs);
    const harness = try Harness.create(fixture_now_ms, .{ .crl_fetcher = fake_crl.fetcher() });
    defer harness.destroy();
    harness.fake.add_plan(&plan);
    try testing.expect(try harness.manager.check_crls(&plan, &harness.cancel));
    harness.fake.register(plan.signer);
    try testing.expect(try harness.manager.check_crls(&plan, &harness.cancel));
    try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    try testing.expectEqual(@as(u64, 2), harness.stats.crl_check_outcome_clean);
}

test "signer manager: CRL revocation blocks registration and deregistration retries" {
    var infos_buffer: [types.cert_plan_count_max]crl.CertCrlInfo = undefined;
    const plan = fixture_plan(&fixture_tbs);
    const infos = crl_infos(&plan, &infos_buffer);
    var revoked_buffer: [160]u8 = undefined;
    var clean_buffer: [160]u8 = undefined;
    var fake_crl: fakes.FakeCrl = .{ .responses = &.{
        fakes.build_crl(infos[0].serial(), &revoked_buffer),
        fakes.build_crl(null, &clean_buffer),
    } };
    const harness = try Harness.create(fixture_now_ms, .{ .crl_fetcher = fake_crl.fetcher() });
    defer harness.destroy();
    harness.fake.add_plan(&plan);
    try testing.expectError(
        error.RevokedCertificate,
        harness.manager.check_crls(&plan, &harness.cancel),
    );
    try testing.expectEqual(@as(u32, 0), harness.fake.tx_count_to(fakes.registry_address));
    try testing.expect(harness.fake.is_revoked_id(plan.certs[0].revocation_id));
    harness.fake.register(plan.signer);
    harness.fake.set_outcomes(&.{.error_permanent});
    for (0..2) |_| {
        try testing.expectError(
            error.RevokedCertificate,
            harness.manager.check_revocations(&plan, &harness.cancel),
        );
    }
    // The durable sentinel must not short-circuit later deregistration retries.
    try testing.expect(!harness.fake.is_registered(plan.signer));
    try testing.expectEqual(@as(u32, 2), harness.fake.tx_count_to(fakes.registry_address));
}

test "signer manager: CRL partial failure deregisters even if persistence fails" {
    var infos_buffer: [types.cert_plan_count_max]crl.CertCrlInfo = undefined;
    const plan = fixture_plan(&fixture_tbs);
    const infos = crl_infos(&plan, &infos_buffer);
    try testing.expect(infos.len >= 2);
    var revoked_buffer: [160]u8 = undefined;
    var fake_crl: fakes.FakeCrl = .{ .responses = &.{
        "invalid DER",
        fakes.build_crl(infos[1].serial(), &revoked_buffer),
    } };
    const harness = try Harness.create(fixture_now_ms, .{ .crl_fetcher = fake_crl.fetcher() });
    defer harness.destroy();
    harness.fake.add_plan(&plan);
    harness.fake.register(plan.signer);
    harness.fake.set_outcomes(&.{.error_permanent});
    try testing.expectError(
        error.RevokedCertificate,
        harness.manager.check_crls(&plan, &harness.cancel),
    );
    try testing.expect(!harness.fake.is_registered(plan.signer));
    try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
    try testing.expectEqual(@as(u64, 1), harness.stats.revoke_cert_tx_failures);
}

test "signer manager: every cache prefix submits only the missing suffix" {
    for (0..5) |prefix| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&synthetic.plan);
        harness.fake.precache(&synthetic.plan, @intCast(prefix));
        try harness.cache_and_register(&synthetic.plan);
        const cache_sends = harness.fake.tx_count_to(fakes.cert_manager_address);
        try testing.expectEqual(@as(u32, @intCast(4 - prefix)), cache_sends);
        try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
        try testing.expectEqual(@as(u32, @intCast(5 - prefix)), harness.fake.sent_count);
    }
}

test "signer manager: registrations sharing a chain cache it once" {
    var plan_a: Synthetic = undefined;
    plan_a.init(signer_a, synthetic_now_ms);
    var plan_b: Synthetic = undefined;
    plan_b.init(signer_b, synthetic_now_ms);
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    harness.fake.add_plan(&plan_a.plan);
    try harness.cache_and_register(&plan_a.plan);
    try harness.cache_and_register(&plan_b.plan);
    try testing.expectEqual(@as(u32, 4), harness.fake.tx_count_to(fakes.cert_manager_address));
    try testing.expectEqual(@as(u32, 2), harness.fake.tx_count_to(fakes.registry_address));
}

test "signer manager: ambiguous cache error and reverted receipt reread usable state" {
    for ([_]fakes.Outcome{ .apply_then_error, .apply_then_revert }) |first| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&synthetic.plan);
        harness.fake.set_outcomes(&.{first});
        try harness.cache_and_register(&synthetic.plan);
        try testing.expectEqual(@as(u32, 4), harness.fake.tx_count_to(fakes.cert_manager_address));
        try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
        try testing.expectEqual(@as(u64, 1), harness.stats.cert_cache_tx_ca_observed_cached);
    }
}

test "signer manager: ambiguous final error and reverted receipt observe registration" {
    for ([_]fakes.Outcome{ .apply_then_error, .apply_then_revert }) |final| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&synthetic.plan);
        harness.fake.final_signer = signer_a;
        harness.fake.set_outcomes(&.{ .success, .success, .success, .success, final });
        try harness.cache_and_register(&synthetic.plan);
        try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
        try testing.expect(harness.fake.is_registered(signer_a));
        try testing.expectEqual(@as(u64, 1), harness.stats.registrations);
    }
}

test "signer manager: expired, revoked and mismatched cached certificates send nothing" {
    for (0..3) |mutation| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        const plan = &synthetic.plan;
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(plan);
        harness.fake.precache(plan, 1);
        const entry = harness.fake.find_cached(plan.certs[0].cert_hash).?;
        const expected: anyerror = switch (mutation) {
            0 => expired: {
                entry.verified.not_after = 1;
                break :expired error.ExpiredCertificate;
            },
            1 => revoked: {
                harness.fake.revoke(plan.certs[0].revocation_id);
                break :revoked error.RevokedCertificate;
            },
            else => parent: {
                entry.parent = @splat(0xfe);
                break :parent error.InvalidAttestationProof;
            },
        };
        try testing.expectError(expected, harness.cache_and_register(plan));
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    }
}

test "signer manager: root and certificate revocations are rejected before caching" {
    const plan = fixture_plan(&fixture_tbs);
    for ([_]Hash{ planner.pinned_root_cert_hash, plan.certs[1].revocation_id }) |cert_id| {
        const harness = try Harness.create(fixture_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&plan);
        harness.fake.revoke(cert_id);
        try testing.expectError(
            error.RevokedCertificate,
            harness.manager.check_revocations(&plan, &harness.cancel),
        );
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    }
}

test "signer manager: already registered signer still checks revocation state" {
    const plan = fixture_plan(&fixture_tbs);
    const harness = try Harness.create(fixture_now_ms, .{});
    defer harness.destroy();
    harness.fake.add_plan(&plan);
    harness.fake.register(plan.signer);
    harness.fake.revoke(plan.certs[0].revocation_id);
    try testing.expectError(
        error.RevokedCertificate,
        harness.manager.check_revocations(&plan, &harness.cancel),
    );
    try testing.expect(!harness.fake.is_registered(plan.signer));
    try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
}

test "signer manager: signer and nonce rejections happen before contract reads" {
    const fixture_signer = fixture_plan(&fixture_tbs).signer;
    for ([_]Address{ signer_b, fixture_signer }) |signer| {
        const harness = try Harness.create(fixture_now_ms, .{});
        defer harness.destroy();
        try testing.expectError(
            error.InvalidAttestationProof,
            harness.manager.register_signer(signer, fakes.fixture_attestation, &harness.cancel),
        );
        try testing.expectEqual(@as(u32, 0), harness.fake.cert_reads);
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    }
}

test "signer manager: debug PCR0, future and stale plans are rejected" {
    const hints = try synthetic_hints(testing.allocator);
    defer testing.allocator.destroy(hints);
    const expected = [_]anyerror{
        error.InvalidAttestationProof,
        error.FutureAttestationProof,
        error.StaleAttestationProof,
    };
    for (expected, 0..) |expected_error, mutation| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        switch (mutation) {
            0 => synthetic.plan.pcr0 = @splat(0),
            1 => synthetic.plan.timestamp_ms = synthetic_now_ms + 10_000,
            else => synthetic.plan.timestamp_ms = synthetic_now_ms - (max_age_s * 1000 + 2_000),
        }
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&synthetic.plan);
        try testing.expectError(
            expected_error,
            harness.manager.register_plan(signer_a, &synthetic.plan, hints, &harness.cancel),
        );
        try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
    }
}

test "signer manager: same-second attestation is not rejected locally" {
    var synthetic: Synthetic = undefined;
    synthetic.init(signer_a, synthetic_now_ms);
    synthetic.plan.timestamp_ms = synthetic_now_ms;
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    try harness.manager.validate_plan(signer_a, &synthetic.plan);
}

test "signer manager: retryable cache error retries the same calldata with backoff" {
    var synthetic: Synthetic = undefined;
    synthetic.init(signer_a, synthetic_now_ms);
    const harness = try Harness.create(synthetic_now_ms, .{ .max_tx_retries = 2 });
    defer harness.destroy();
    harness.fake.add_plan(&synthetic.plan);
    harness.fake.set_outcomes(&.{.error_retryable});
    try harness.cache_and_register(&synthetic.plan);
    try testing.expectEqual(retry_delay_ms, harness.fake.slept_ms);
    try testing.expectEqual(@as(u32, 5), harness.fake.tx_count_to(fakes.cert_manager_address));
    const sent = harness.fake.sent;
    try testing.expectEqualSlices(u8, &sent[0].digest, &sent[1].digest);
}

test "signer manager: every submitted cache transaction reaches one terminal outcome" {
    var stats: metrics.Stats = .{};
    const outcomes = [_]fakes.Outcome{
        .success, .error_retryable, .apply_then_error, .apply_then_revert,
    };
    for (outcomes) |outcome| {
        var synthetic: Synthetic = undefined;
        synthetic.init(signer_a, synthetic_now_ms);
        const harness = try Harness.create(synthetic_now_ms, .{});
        defer harness.destroy();
        harness.fake.add_plan(&synthetic.plan);
        harness.fake.set_outcomes(&.{outcome});
        try harness.cache_and_register(&synthetic.plan);
        inline for (@typeInfo(metrics.Stats).@"struct".field_names) |name| {
            @field(stats, name) += @field(harness.stats, name);
        }
    }
    try testing.expectEqual(@as(i64, 0), stats.cache_tx_unsettled(.ca));
    try testing.expectEqual(@as(i64, 0), stats.cache_tx_unsettled(.leaf));
    try testing.expect(stats.cert_cache_tx_ca_retry > 0);
    try testing.expect(stats.cert_cache_tx_ca_observed_cached > 0);
}

test "signer manager: cancellation during retry backoff stops without another send" {
    var synthetic: Synthetic = undefined;
    synthetic.init(signer_a, synthetic_now_ms);
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    harness.fake.add_plan(&synthetic.plan);
    harness.fake.set_outcomes(&.{.error_retryable});
    harness.fake.cancel_at_ms = synthetic_now_ms + 500;
    const hints = try synthetic_hints(testing.allocator);
    defer testing.allocator.destroy(hints);
    const plan = &synthetic.plan;
    const cached = try harness.manager.ensure_cert_cached(
        &plan.certs[0],
        hints.cert_signature_hints[0].slice(),
        plan.timestamp_ms,
        &harness.cancel,
    );
    try testing.expect(!cached);
    try testing.expectEqual(@as(u32, 1), harness.fake.sent_count);
}

test "signer manager: orphan deregistration submits only unprotected signers" {
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    harness.fake.register(signer_a);
    harness.fake.register(signer_b);
    var protected: reconciler.ProtectedSigners = .{};
    try protected.insert(signer_a);
    try harness.manager.run_orphan_dereg(&protected, &harness.cancel);
    try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
    try testing.expect(harness.fake.is_registered(signer_a));
    try testing.expect(!harness.fake.is_registered(signer_b));
    const selector = harness.fake.sent[0].selector;
    try testing.expectEqualSlices(u8, &registry_abi.deregister_signer, &selector);
}

test "signer manager: orphan deregistration stops when the registry read is cancelled" {
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    harness.fake.register(signer_b);
    harness.fake.cancel_on_registered_signers = true;
    const protected: reconciler.ProtectedSigners = .{};
    try harness.manager.run_orphan_dereg(&protected, &harness.cancel);
    try testing.expectEqual(@as(u32, 0), harness.fake.sent_count);
}

test "signer manager: nonce is bound to registry and signer" {
    const nonce = SignerManager.attestation_nonce_for(fakes.registry_address, signer_a);
    const other_registry = SignerManager.attestation_nonce_for(@splat(2), signer_a);
    const other_signer = SignerManager.attestation_nonce_for(fakes.registry_address, signer_b);
    try testing.expect(!std.mem.eql(u8, &nonce, &other_registry));
    try testing.expect(!std.mem.eql(u8, &nonce, &other_signer));
}

test "signer manager: retry backoff doubles and caps" {
    const harness = try Harness.create(synthetic_now_ms, .{});
    defer harness.destroy();
    try testing.expectEqual(@as(u64, 1000), harness.manager.retry_delay_ms(1));
    try testing.expectEqual(@as(u64, 4000), harness.manager.retry_delay_ms(3));
    try testing.expectEqual(@as(u64, 60_000), harness.manager.retry_delay_ms(40));
}

test "signer manager: fixture attestation registers end to end on a cold chain" {
    const harness = try Harness.create(fixture_now_ms, .{ .accept_null_nonce = true });
    defer harness.destroy();
    const plan = fixture_plan(&fixture_tbs);
    harness.fake.add_plan(&plan);
    harness.fake.final_signer = plan.signer;
    try harness.manager.register_signer(plan.signer, fakes.fixture_attestation, &harness.cancel);
    try testing.expect(harness.fake.is_registered(plan.signer));
    try testing.expectEqual(plan.cert_count, harness.fake.tx_count_to(fakes.cert_manager_address));
    try testing.expectEqual(@as(u32, 1), harness.fake.tx_count_to(fakes.registry_address));
    try testing.expectEqual(@as(u64, 1), harness.stats.registration_stage_proof_succeeded);
    try testing.expect(harness.stats.hint_bytes_attestation > 0);
    // A second pass observes the registration and sends nothing.
    try harness.manager.register_signer(plan.signer, fakes.fixture_attestation, &harness.cancel);
    try testing.expectEqual(@as(u64, 1), harness.stats.registration_stage_already_registered);
    try testing.expectEqual(plan.cert_count + 1, harness.fake.sent_count);
}

//! Registrar metrics (base/base `registrar/src/metrics.rs`) over `proof.telemetry`: every
//! counter is exported as `base_registrar_<name>_total`. base/base's labelled series are
//! flattened into one counter per label value (`registration_stage_tx_submitted` for
//! `registration_stage_total{stage="tx_submitted"}`). The P-384 hint-size histogram is a
//! byte-sum counter per kind, and the cycle gauges (pending tasks, discovered instances,
//! signers) stay in the driver: the shared exporter publishes counters only.

const std = @import("std");
const assert = std.debug.assert;

const telemetry = @import("../../telemetry/root.zig");
const types = @import("types.zig");

pub const Stage = enum {
    already_registered,
    proof_started,
    proof_succeeded,
    proof_failed,
    proof_cancelled,
    proof_invalid,
    proof_stale,
    tx_submitted,
    tx_retry,
    tx_succeeded,
    tx_failed,
    tx_reverted,
    tx_observed_registered,
};

pub const CacheTxOutcome = enum {
    submitted,
    succeeded,
    reverted,
    retry,
    failed,
    observed_cached,
    cancelled,
};

const outcome_names = @typeInfo(CacheTxOutcome).@"enum".field_names;

pub const CrlOutcome = enum { clean, revoked, indeterminate };

pub const HintKind = enum { ca, leaf, attestation };

pub const Stats = struct {
    registrations: u64 = 0,
    deregistrations: u64 = 0,
    discovery_success: u64 = 0,
    processing_errors: u64 = 0,
    crl_checks: u64 = 0,
    crl_check_outcome_clean: u64 = 0,
    crl_check_outcome_revoked: u64 = 0,
    crl_check_outcome_indeterminate: u64 = 0,
    crl_revocations_detected: u64 = 0,
    onchain_revocation_checks: u64 = 0,
    onchain_revocations_detected: u64 = 0,
    revoke_cert_tx_failures: u64 = 0,
    revoke_cert_reverted: u64 = 0,
    revoke_cert_success: u64 = 0,
    proof_tasks_spawned: u64 = 0,
    proof_tasks_cancelled: u64 = 0,
    proof_tasks_completed: u64 = 0,
    proof_tasks_outcome_succeeded: u64 = 0,
    proof_tasks_outcome_failed: u64 = 0,
    proof_tasks_outcome_cancelled: u64 = 0,
    proof_tasks_outcome_join_error: u64 = 0,
    registration_stage_already_registered: u64 = 0,
    registration_stage_proof_started: u64 = 0,
    registration_stage_proof_succeeded: u64 = 0,
    registration_stage_proof_failed: u64 = 0,
    registration_stage_proof_cancelled: u64 = 0,
    registration_stage_proof_invalid: u64 = 0,
    registration_stage_proof_stale: u64 = 0,
    registration_stage_tx_submitted: u64 = 0,
    registration_stage_tx_retry: u64 = 0,
    registration_stage_tx_succeeded: u64 = 0,
    registration_stage_tx_failed: u64 = 0,
    registration_stage_tx_reverted: u64 = 0,
    registration_stage_tx_observed_registered: u64 = 0,
    hint_bytes_ca: u64 = 0,
    hint_bytes_leaf: u64 = 0,
    hint_bytes_attestation: u64 = 0,
    cert_cache_lookup_ca_hit: u64 = 0,
    cert_cache_lookup_ca_miss: u64 = 0,
    cert_cache_lookup_leaf_hit: u64 = 0,
    cert_cache_lookup_leaf_miss: u64 = 0,
    cert_cache_tx_ca_submitted: u64 = 0,
    cert_cache_tx_ca_succeeded: u64 = 0,
    cert_cache_tx_ca_reverted: u64 = 0,
    cert_cache_tx_ca_retry: u64 = 0,
    cert_cache_tx_ca_failed: u64 = 0,
    cert_cache_tx_ca_observed_cached: u64 = 0,
    cert_cache_tx_ca_cancelled: u64 = 0,
    cert_cache_tx_leaf_submitted: u64 = 0,
    cert_cache_tx_leaf_succeeded: u64 = 0,
    cert_cache_tx_leaf_reverted: u64 = 0,
    cert_cache_tx_leaf_retry: u64 = 0,
    cert_cache_tx_leaf_failed: u64 = 0,
    cert_cache_tx_leaf_observed_cached: u64 = 0,
    cert_cache_tx_leaf_cancelled: u64 = 0,

    pub const descriptions = .{
        .registrations = "Signer registrations submitted.",
        .deregistrations = "Signer deregistrations submitted.",
        .discovery_success = "Successful discovery cycles.",
        .processing_errors = "Processing errors encountered.",
        .crl_checks = "CRL chain checks performed.",
        .crl_check_outcome_clean = "CRL chain checks that found no revocation.",
        .crl_check_outcome_revoked = "CRL chain checks that found a revocation.",
        .crl_check_outcome_indeterminate = "CRL chain checks with a failed fetch or parse.",
        .crl_revocations_detected = "Certificate revocations detected via CRL.",
        .onchain_revocation_checks = "Onchain durable revocation pre-checks performed.",
        .onchain_revocations_detected = "Certificates rejected by the onchain revocation set.",
        .revoke_cert_tx_failures = "revokeCert transaction submission failures.",
        .revoke_cert_reverted = "revokeCert transactions that landed but reverted.",
        .revoke_cert_success = "Successful revokeCert transactions.",
        .proof_tasks_spawned = "Signer-registration tasks spawned.",
        .proof_tasks_cancelled = "Signer-registration tasks cancelled.",
        .proof_tasks_completed = "Signer-registration tasks that reached a terminal state.",
        .proof_tasks_outcome_succeeded = "Registration tasks that succeeded.",
        .proof_tasks_outcome_failed = "Registration tasks that failed.",
        .proof_tasks_outcome_cancelled = "Registration tasks that finished cancelled.",
        .proof_tasks_outcome_join_error = "Registration tasks that aborted.",
        .registration_stage_already_registered = "Registrations skipped: already registered.",
        .registration_stage_proof_started = "Hint generations started.",
        .registration_stage_proof_succeeded = "Hint generations that succeeded.",
        .registration_stage_proof_failed = "Hint generations that failed.",
        .registration_stage_proof_cancelled = "Hint generations cancelled.",
        .registration_stage_proof_invalid = "Registrations with an invalid proof.",
        .registration_stage_proof_stale = "Registrations abandoned on a stale attestation.",
        .registration_stage_tx_submitted = "Registration transactions submitted.",
        .registration_stage_tx_retry = "Registration transactions retried.",
        .registration_stage_tx_succeeded = "Registration transactions that succeeded.",
        .registration_stage_tx_failed = "Registration transactions that failed.",
        .registration_stage_tx_reverted = "Registration transactions that reverted.",
        .registration_stage_tx_observed_registered = "Registrations observed onchain.",
        .hint_bytes_ca = "P-384 hint bytes generated for CA certificates.",
        .hint_bytes_leaf = "P-384 hint bytes generated for leaf certificates.",
        .hint_bytes_attestation = "P-384 hint bytes generated for attestation signatures.",
        .cert_cache_lookup_ca_hit = "CA certificate cache hits.",
        .cert_cache_lookup_ca_miss = "CA certificate cache misses.",
        .cert_cache_lookup_leaf_hit = "Leaf certificate cache hits.",
        .cert_cache_lookup_leaf_miss = "Leaf certificate cache misses.",
        .cert_cache_tx_ca_submitted = "CA cache transactions submitted.",
        .cert_cache_tx_ca_succeeded = "CA cache transactions that cached the certificate.",
        .cert_cache_tx_ca_reverted = "CA cache transactions that reverted.",
        .cert_cache_tx_ca_retry = "CA cache transactions retried.",
        .cert_cache_tx_ca_failed = "CA cache transactions that failed.",
        .cert_cache_tx_ca_observed_cached = "CA cache transactions observed cached.",
        .cert_cache_tx_ca_cancelled = "CA cache transactions cancelled.",
        .cert_cache_tx_leaf_submitted = "Leaf cache transactions submitted.",
        .cert_cache_tx_leaf_succeeded = "Leaf cache transactions that cached the certificate.",
        .cert_cache_tx_leaf_reverted = "Leaf cache transactions that reverted.",
        .cert_cache_tx_leaf_retry = "Leaf cache transactions retried.",
        .cert_cache_tx_leaf_failed = "Leaf cache transactions that failed.",
        .cert_cache_tx_leaf_observed_cached = "Leaf cache transactions observed cached.",
        .cert_cache_tx_leaf_cancelled = "Leaf cache transactions cancelled.",
    };

    pub fn record_stage(stats: *Stats, stage: Stage) void {
        switch (stage) {
            inline else => |tag| @field(stats, "registration_stage_" ++ @tagName(tag)) += 1,
        }
    }

    pub fn record_crl_outcome(stats: *Stats, outcome: CrlOutcome) void {
        switch (outcome) {
            inline else => |tag| @field(stats, "crl_check_outcome_" ++ @tagName(tag)) += 1,
        }
    }

    pub fn record_hint_size(stats: *Stats, kind: HintKind, size_bytes: usize) void {
        switch (kind) {
            inline else => |tag| @field(stats, "hint_bytes_" ++ @tagName(tag)) += size_bytes,
        }
    }

    pub fn record_cache_lookup(stats: *Stats, kind: types.CertKind, hit: bool) void {
        switch (kind) {
            inline else => |tag| {
                const prefix = "cert_cache_lookup_" ++ @tagName(tag);
                if (hit) {
                    @field(stats, prefix ++ "_hit") += 1;
                } else {
                    @field(stats, prefix ++ "_miss") += 1;
                }
            },
        }
    }

    pub fn record_cache_tx(stats: *Stats, kind: types.CertKind, outcome: CacheTxOutcome) void {
        switch (kind) {
            inline else => |kind_tag| switch (outcome) {
                inline else => |outcome_tag| {
                    const name = "cert_cache_tx_" ++ @tagName(kind_tag) ++ "_" ++
                        @tagName(outcome_tag);
                    @field(stats, name) += 1;
                },
            },
        }
    }

    /// Submitted cache transactions minus terminal outcomes, for one kind (always 0 when
    /// every submission reached exactly one outcome).
    pub fn cache_tx_unsettled(stats: *const Stats, kind: types.CertKind) i64 {
        var terminal: u64 = 0;
        var submitted: u64 = 0;
        switch (kind) {
            inline else => |kind_tag| inline for (outcome_names) |field_name| {
                const name = "cert_cache_tx_" ++ @tagName(kind_tag) ++ "_" ++ field_name;
                if (comptime std.mem.eql(u8, field_name, "submitted")) {
                    submitted = @field(stats, name);
                } else terminal += @field(stats, name);
            },
        }
        assert(submitted <= std.math.maxInt(i64) and terminal <= std.math.maxInt(i64));
        return @as(i64, @intCast(submitted)) - @as(i64, @intCast(terminal));
    }
};

pub const Exporter = telemetry.Exporter(Stats, "base_registrar");

test "registrar metrics: labelled series flatten into counters" {
    var stats: Stats = .{};
    stats.record_stage(.tx_submitted);
    stats.record_crl_outcome(.indeterminate);
    stats.record_hint_size(.attestation, 96);
    stats.record_cache_lookup(.leaf, false);
    stats.record_cache_tx(.ca, .submitted);
    try std.testing.expectEqual(@as(i64, 1), stats.cache_tx_unsettled(.ca));
    stats.record_cache_tx(.ca, .observed_cached);
    try std.testing.expectEqual(@as(u64, 1), stats.registration_stage_tx_submitted);
    try std.testing.expectEqual(@as(u64, 1), stats.crl_check_outcome_indeterminate);
    try std.testing.expectEqual(@as(u64, 96), stats.hint_bytes_attestation);
    try std.testing.expectEqual(@as(u64, 1), stats.cert_cache_lookup_leaf_miss);
    try std.testing.expectEqual(@as(i64, 0), stats.cache_tx_unsettled(.ca));
}

test "registrar metrics: exporter names" {
    var clock: telemetry.FakeClock = .{ .now_ns = 1 };
    var exporter: Exporter = undefined;
    try exporter.init(clock.clock(), .{ .version = "test", .poll_interval_ns = 1 });
    exporter.observe(.{ .registrations = 2 }, 1);
    var buffer: [64 * 1024]u8 = undefined;
    var response = telemetry.get(&exporter, &buffer, "/metrics");
    try std.testing.expect(telemetry.contains(&response, "base_registrar_registrations_total 2"));
    try std.testing.expect(telemetry.contains(
        &response,
        "base_registrar_cert_cache_tx_leaf_observed_cached_total",
    ));
}

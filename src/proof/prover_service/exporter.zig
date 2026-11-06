//! Health, readiness and metrics for `base prover-service` and `base prover-worker`
//! (base/base `prover-service/src/metrics.rs`) over `proof.telemetry`: the service's
//! request count and job outcomes as `prover_service_*_total`, the worker's lease
//! outcomes as `prover_worker_*_total`. Both are ready while their loop runs.

const std = @import("std");
const assert = std.debug.assert;

const telemetry = @import("../telemetry/root.zig");
const store_module = @import("store.zig");
const worker_module = @import("worker.zig");

pub const ServiceStats = struct {
    requests: u64 = 0,
    created: u64 = 0,
    retried: u64 = 0,
    succeeded: u64 = 0,
    failed: u64 = 0,
    cancelled: u64 = 0,
    abandoned: u64 = 0,
    expired: u64 = 0,

    pub const descriptions = .{
        .requests = "JSON-RPC requests handled.",
        .created = "Proof requests created.",
        .retried = "Failed proof requests requeued by a retry.",
        .succeeded = "Proof requests completed successfully.",
        .failed = "Proof requests failed.",
        .cancelled = "Proof requests cancelled.",
        .abandoned = "Jobs abandoned by a worker.",
        .expired = "Expired worker leases reaped (stuck requests).",
    };
};

pub const WorkerStats = struct {
    ticks: u64 = 0,
    claimed: u64 = 0,
    submitted: u64 = 0,
    abandoned: u64 = 0,
    lost: u64 = 0,
    heartbeats: u64 = 0,
    not_ready: u64 = 0,

    pub const descriptions = .{
        .ticks = "Worker loop ticks.",
        .claimed = "Jobs claimed.",
        .submitted = "Proofs submitted.",
        .abandoned = "Jobs abandoned after a backend failure.",
        .lost = "Jobs given up because the lease was lost, expired or cancelled.",
        .heartbeats = "Lease heartbeats sent.",
        .not_ready = "Discovery rounds skipped because the backend was not ready to claim.",
    };
};

pub const ServiceExporter = telemetry.Exporter(ServiceStats, "prover_service");
pub const WorkerExporter = telemetry.Exporter(WorkerStats, "prover_worker");

/// Copies the service counters; `loops` counts the service loop's iterations.
pub fn observe_service(
    exporter: *ServiceExporter,
    requests: u64,
    store: store_module.Stats,
    loops: u64,
) void {
    assert(loops > 0);
    var stats: ServiceStats = .{ .requests = requests };
    inline for (@typeInfo(store_module.Stats).@"struct".field_names) |name| {
        @field(stats, name) = @field(store, name);
    }
    exporter.observe(stats, loops);
    assert(exporter.counter("requests") == requests);
}

/// Copies the worker counters after `ticks` loop ticks.
pub fn observe_worker(exporter: *WorkerExporter, worker: worker_module.Stats, ticks: u64) void {
    assert(ticks > 0);
    var stats: WorkerStats = .{ .ticks = ticks };
    inline for (@typeInfo(worker_module.Stats).@"struct".field_names) |name| {
        @field(stats, name) = @field(worker, name);
    }
    exporter.observe(stats, ticks);
    assert(exporter.counter("ticks") == ticks);
}

const testing = std.testing;

test "prover service exporter: service and worker counters" {
    var fake: telemetry.FakeClock = .{ .now_ns = std.time.ns_per_s };
    var buffer: [8192]u8 = undefined;
    var service: ServiceExporter = undefined;
    try service.init(fake.clock(), .{ .version = "v", .poll_interval_ns = std.time.ns_per_s });
    try testing.expect(!service.ready());
    observe_service(&service, 7, .{ .created = 2, .succeeded = 1, .expired = 1 }, 1);
    try testing.expect(service.ready());
    var response = telemetry.get(&service, &buffer, "/metrics");
    try testing.expect(telemetry.contains(&response, "prover_service_requests_total 7"));
    try testing.expect(telemetry.contains(&response, "prover_service_expired_total 1"));
    var worker: WorkerExporter = undefined;
    try worker.init(fake.clock(), .{ .version = "v", .poll_interval_ns = std.time.ns_per_s });
    observe_worker(&worker, .{ .claimed = 1, .submitted = 1, .heartbeats = 3 }, 4);
    response = telemetry.get(&worker, &buffer, "/metrics");
    try testing.expect(telemetry.contains(&response, "prover_worker_heartbeats_total 3"));
    try testing.expect(telemetry.contains(&response, "prover_worker_ticks_total 4"));
    // A stalled loop stops being ready.
    fake.now_ns += 10 * std.time.ns_per_s;
    try testing.expect(!worker.ready());
}

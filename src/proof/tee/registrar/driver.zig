//! Registration driver (base/base `registrar/src/driver.rs`): each cycle discovers prover
//! instances, probes `readyz`, fetches signer public keys and nonce-bound attestations,
//! feeds the completed cycle to `SignerReconciler`, applies its task decisions through
//! `RegistrationTaskSet`, and runs orphan cleanup when every instance resolved.
//!
//! base/base resolves instances and runs registration tasks concurrently on tokio. Here a
//! cycle is synchronous and deterministic: instances resolve in discovery order, and each
//! spawned registration runs to completion before the next, then reports its outcome to
//! the task set. Attestations are copied into a per-cycle arena sized at startup.

const std = @import("std");
const assert = std.debug.assert;

const types = @import("types.zig");
const l1 = @import("l1.zig");
const metrics = @import("metrics.zig");
const prover = @import("prover.zig");
const reconciler_module = @import("reconciler.zig");
const registration_tasks = @import("registration_tasks.zig");
const discovery_module = @import("discovery.zig");
const signer_manager = @import("signer_manager.zig");

const Address = types.Address;
const Hash = types.Hash;
const ProverInstance = types.ProverInstance;
const Observation = reconciler_module.Observation;
const InstanceObservation = reconciler_module.InstanceObservation;
const RegisterableSigner = reconciler_module.RegisterableSigner;
const SignerManager = signer_manager.SignerManager;

pub const instances_max: u32 = reconciler_module.instance_count_max;
const signers_max: u32 = reconciler_module.instance_signer_count_max;
/// Five cycles is roughly 2.5 minutes at the default 30 s poll interval.
pub const default_instance_cache_ttl_cycles: u32 = 5;
pub const default_attestation_bytes_max: u32 = 4 * 1024 * 1024;

comptime {
    assert(prover.signers_max == signers_max);
    assert(discovery_module.instances_max == instances_max);
}

/// Talks to one prover instance endpoint (base/base `EnclaveEndpointClient`). Public keys
/// and attestations come back in the same stable signer order; results borrow the client
/// until its next call for that endpoint.
pub const EndpointClient = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readyz: *const fn (*anyopaque, []const u8) prover.Error!void,
        signer_public_keys: *const fn (*anyopaque, []const u8) prover.Error!prover.ByteLists,
        signer_attestations: *const fn (
            *anyopaque,
            []const u8,
            []const []const u8,
        ) prover.Error!prover.ByteLists,
    };

    pub fn readyz(client: EndpointClient, endpoint: []const u8) prover.Error!void {
        assert(endpoint.len > 0);
        return client.vtable.readyz(client.context, endpoint);
    }

    pub fn signer_public_keys(
        client: EndpointClient,
        endpoint: []const u8,
    ) prover.Error!prover.ByteLists {
        assert(endpoint.len > 0);
        const keys = try client.vtable.signer_public_keys(client.context, endpoint);
        assert(keys.count <= signers_max);
        return keys;
    }

    pub fn signer_attestations(
        client: EndpointClient,
        endpoint: []const u8,
        nonces: []const []const u8,
    ) prover.Error!prover.ByteLists {
        assert(nonces.len <= signers_max);
        const context = client.context;
        const attestations = try client.vtable.signer_attestations(context, endpoint, nonces);
        assert(attestations.count <= signers_max);
        return attestations;
    }
};

pub const Config = struct {
    poll_interval_ms: u64,
    instance_cache_ttl_cycles: u32 = default_instance_cache_ttl_cycles,
    /// Attestation bytes one cycle may hold.
    attestation_bytes_max: u32 = default_attestation_bytes_max,
};

pub const Driver = struct {
    config: Config,
    discovery: discovery_module.Discovery,
    client: EndpointClient,
    manager: *SignerManager,
    stats: *metrics.Stats,
    cancel: l1.Cancel = .{},
    tasks: registration_tasks.RegistrationTaskSet = .{},
    reconciler: reconciler_module.SignerReconciler,
    resolution: reconciler_module.SignerReconciliation = .{},
    instances: [instances_max]ProverInstance = undefined,
    observations: [instances_max]Observation = undefined,
    signers: [instances_max][signers_max]Address = undefined,
    registerable: [instances_max][signers_max]RegisterableSigner = undefined,
    attestation_arena: []u8,
    attestation_used: u32 = 0,
    /// Cycles started and cycles whose discovery completed (readiness progress).
    cycles: u64 = 0,
    cycles_completed: u64 = 0,

    /// In place: the driver is large; allocate it on the heap.
    pub fn init(
        driver: *Driver,
        allocator: std.mem.Allocator,
        config: Config,
        discovery: discovery_module.Discovery,
        client: EndpointClient,
        manager: *SignerManager,
    ) !void {
        assert(config.poll_interval_ms > 0);
        assert(config.attestation_bytes_max > 0);
        const arena = try allocator.alloc(u8, config.attestation_bytes_max);
        driver.* = .{
            .config = config,
            .discovery = discovery,
            .client = client,
            .manager = manager,
            .stats = manager.stats,
            .reconciler = .init(config.instance_cache_ttl_cycles),
            .attestation_arena = arena,
        };
    }

    pub fn deinit(driver: *Driver, allocator: std.mem.Allocator) void {
        allocator.free(driver.attestation_arena);
        driver.* = undefined;
    }

    /// Runs cycles every `poll_interval_ms` until cancelled or `cycles_max` cycles ran.
    pub fn run(driver: *Driver, cycles_max: ?u64) void {
        const clock = driver.manager.world.clock;
        while (cycles_max == null or driver.cycles < cycles_max.?) {
            driver.step();
            if (!clock.sleep_ms(driver.config.poll_interval_ms, &driver.cancel)) break;
        }
        assert(cycles_max == null or driver.cycles <= cycles_max.?);
    }

    /// One discovery and registration cycle.
    pub fn step(driver: *Driver) void {
        driver.cycles += 1;
        defer driver.sync_task_stats();
        const discovered = driver.discover_and_resolve() catch {
            driver.stats.processing_errors += 1;
            return;
        };
        const observations = discovered orelse return;
        driver.reconciler.step(observations, driver.tasks.pending(), &driver.resolution) catch {
            driver.stats.processing_errors += 1;
            return;
        };
        driver.cycles_completed += 1;
        driver.apply_task_decisions(observations);
        const protected = driver.resolution.protected() orelse return;
        driver.manager.run_orphan_dereg(protected, &driver.cancel) catch {
            driver.stats.processing_errors += 1;
        };
    }

    /// Applies cancellations and runs spawned registrations unless shutdown has started.
    fn apply_task_decisions(driver: *Driver, observations: []const Observation) void {
        if (driver.cancel.is_cancelled()) return;
        for (driver.resolution.cancels()) |*signer| _ = driver.tasks.cancel(signer);
        for (driver.resolution.spawns()) |ref| {
            const entry = reconciler_module.spawn_entry(observations, ref);
            const spawned = driver.tasks.spawn(entry.signer, entry.instance.instance_id.slice());
            const task_id = spawned catch {
                driver.stats.processing_errors += 1;
                continue;
            };
            if (task_id == null) continue;
            const result = driver.manager.register_signer(
                entry.signer,
                entry.attestation,
                &driver.cancel,
            );
            if (driver.cancel.is_cancelled()) _ = driver.tasks.cancel(&entry.signer);
            if (result) |_| {
                driver.tasks.complete(&entry.signer, .succeeded);
            } else |_| {
                driver.stats.processing_errors += 1;
                driver.tasks.complete(&entry.signer, .failed);
            }
            assert(!driver.tasks.contains(&entry.signer));
        }
    }

    fn sync_task_stats(driver: *Driver) void {
        const task_metrics = driver.tasks.metrics;
        const stats = driver.stats;
        assert(task_metrics.spawned >= stats.proof_tasks_spawned);
        stats.proof_tasks_spawned = task_metrics.spawned;
        stats.proof_tasks_cancelled = task_metrics.cancelled;
        stats.proof_tasks_completed = task_metrics.completed;
        stats.proof_tasks_outcome_succeeded = task_metrics.outcome_succeeded;
        stats.proof_tasks_outcome_failed = task_metrics.outcome_failed;
        stats.proof_tasks_outcome_cancelled = task_metrics.outcome_cancelled;
        stats.proof_tasks_outcome_join_error = task_metrics.outcome_join_error;
    }

    /// Discovery and endpoint IO; null when cancelled mid-cycle.
    fn discover_and_resolve(driver: *Driver) discovery_module.Error!?[]const Observation {
        const instances = try driver.discovery.discover(&driver.instances);
        driver.stats.discovery_success += 1;
        driver.attestation_used = 0;
        for (instances, 0..) |*instance, index| {
            if (driver.cancel.is_cancelled()) return null;
            const observation = driver.observe_instance(instance, @intCast(index));
            driver.observations[index] = .{ .instance = instance.*, .observation = observation };
        }
        if (driver.cancel.is_cancelled()) return null;
        assert(instances.len <= instances_max);
        return driver.observations[0..instances.len];
    }

    /// Probes each non-draining instance right before resolving it: a registration-gated
    /// health check alone would deadlock bootstrap.
    fn observe_instance(
        driver: *Driver,
        instance: *ProverInstance,
        index: u32,
    ) InstanceObservation {
        assert(index < instances_max);
        if (instance.health_status != .draining) {
            const ready = if (driver.client.readyz(instance.endpoint.slice())) true else |_| false;
            instance.health_status = if (ready) .healthy else .unhealthy;
        }
        if (instance.health_status == .unhealthy) return .@"unreachable";
        const endpoint = instance.endpoint.slice();
        const keys = driver.client.signer_public_keys(endpoint) catch {
            driver.stats.processing_errors += 1;
            return .failed;
        };
        const signers = &driver.signers[index];
        for (keys.slice(), signers[0..keys.count]) |key, *signer| {
            signer.* = prover.derive_address(key) catch {
                driver.stats.processing_errors += 1;
                return .failed;
            };
        }
        const resolved = signers[0..keys.count];
        if (resolved.len == 0 or instance.health_status != .healthy) {
            return .{ .resolved = .{ .signers = resolved, .registerable = &.{} } };
        }
        return driver.fetch_attestations(instance, index, resolved);
    }

    fn fetch_attestations(
        driver: *Driver,
        instance: *const ProverInstance,
        index: u32,
        signers: []const Address,
    ) InstanceObservation {
        assert(signers.len > 0 and signers.len <= signers_max);
        const count = signers.len;
        var nonces: [signers_max]Hash = undefined;
        var nonce_slices: [signers_max][]const u8 = undefined;
        for (signers, nonces[0..count], nonce_slices[0..count]) |signer, *nonce, *item| {
            nonce.* = driver.manager.attestation_nonce(signer);
            item.* = nonce;
        }
        const unavailable: InstanceObservation = .{
            .attestations_unavailable = .{ .signers = signers },
        };
        const endpoint = instance.endpoint.slice();
        const client = driver.client;
        const attestations = client.signer_attestations(endpoint, nonce_slices[0..count]) catch {
            driver.stats.processing_errors += 1;
            return unavailable;
        };
        if (attestations.count != signers.len) {
            driver.stats.processing_errors += 1;
            return unavailable;
        }
        const registerable = &driver.registerable[index];
        for (attestations.slice(), signers, registerable[0..signers.len]) |raw, signer, *entry| {
            const copy = driver.copy_attestation(raw) orelse {
                driver.stats.processing_errors += 1;
                return unavailable;
            };
            entry.* = .{ .instance = instance.*, .signer = signer, .attestation = copy };
        }
        const resolved = registerable[0..signers.len];
        return .{ .resolved = .{ .signers = signers, .registerable = resolved } };
    }

    fn copy_attestation(driver: *Driver, raw: []const u8) ?[]const u8 {
        const free = driver.attestation_arena.len - driver.attestation_used;
        if (raw.len == 0 or raw.len > free) return null;
        const copy = driver.attestation_arena[driver.attestation_used..][0..raw.len];
        @memcpy(copy, raw);
        driver.attestation_used += @intCast(raw.len);
        assert(driver.attestation_used <= driver.attestation_arena.len);
        return copy;
    }
};

/// Copies the driver's counters into the exporter; completed discovery cycles are progress.
pub fn observe(exporter: *metrics.Exporter, driver: *const Driver) void {
    assert(driver.cycles_completed <= driver.cycles);
    exporter.observe(driver.stats.*, driver.cycles_completed);
}

test {
    _ = @import("driver_test.zig");
}

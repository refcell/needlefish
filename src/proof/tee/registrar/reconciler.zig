//! Signer reconciliation and unavailable-instance grace across discovery cycles
//! (base/base `registrar/src/reconciler.rs`).
//!
//! Pure: observations and pending tasks in, decisions out, no endpoint I/O. Sets are
//! fixed-capacity arrays with linear search (tens of instances, a few signers each);
//! hitting a capacity is an explicit error instead of an unbounded allocation.
//! base/base logs grace warnings and sets gauges; here both are returned in the
//! reconciliation (`grace_events`, `gauges`) for the driver to log and export.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
const registration_tasks = @import("registration_tasks.zig");

const Address = types.Address;
const InstanceId = types.InstanceId;
const PendingRegistration = registration_tasks.PendingRegistration;

/// Instances per discovery cycle.
pub const instance_count_max: u32 = 64;
/// Grace cache entries (discovered plus recently missing instances).
pub const cache_count_max: u32 = 2 * instance_count_max;
/// Distinct signers one instance may report.
pub const instance_signer_count_max: u32 = 16;
/// Distinct signers in any per-cycle set.
pub const signer_count_max: u32 =
    cache_count_max * instance_signer_count_max + registration_tasks.pending_count_max;
const unresolved_count_max: u32 = cache_count_max + instance_count_max;

pub const Error = error{
    ReconcilerTooManyInstances,
    ReconcilerTooManySigners,
    ReconcilerCacheFull,
};

/// A signer and attestation ready to be spawned as a registration task.
pub const RegisterableSigner = struct {
    instance: types.ProverInstance,
    signer: Address,
    /// Pre-fetched attestation blob, borrowed.
    attestation: []const u8,
};

/// Endpoint I/O outcome for one discovered instance, before cache grace.
pub const InstanceObservation = union(enum) {
    /// The readiness probe failed.
    @"unreachable",
    /// Signers resolved; draining instances have no registerable signers.
    resolved: struct { signers: []const Address, registerable: []const RegisterableSigner },
    /// Signers resolved, but attestations failed or had the wrong count.
    attestations_unavailable: struct { signers: []const Address },
    /// Public key fetching or address derivation failed.
    failed,
};

pub const Observation = struct {
    instance: types.ProverInstance,
    observation: InstanceObservation,
};

/// Fixed-capacity set of signer addresses.
pub const SignerSet = struct {
    items: [signer_count_max]Address = undefined,
    count: u32 = 0,

    pub fn contains(set: *const SignerSet, signer: *const Address) bool {
        assert(set.count <= signer_count_max);
        for (set.items[0..set.count]) |*item| {
            if (std.mem.eql(u8, item, signer)) return true;
        }
        return false;
    }

    pub fn insert(set: *SignerSet, signer: Address) Error!void {
        if (set.contains(&signer)) return;
        if (set.count == signer_count_max) return error.ReconcilerTooManySigners;
        set.items[set.count] = signer;
        set.count += 1;
        assert(set.contains(&signer));
    }

    pub fn slice(set: *const SignerSet) []const Address {
        assert(set.count <= signer_count_max);
        return set.items[0..set.count];
    }
};

/// Signers orphan cleanup must retain; only built when no instance is unresolved.
pub const ProtectedSigners = SignerSet;

/// Reference to `observations[observation].resolved.registerable[entry]`.
pub const SpawnRef = struct { observation: u32, entry: u32 };

pub const GraceEvent = struct {
    instance_id: InstanceId,
    ttl_cycles: u32,
    cached_signers: u32,
    /// True when the cache entry expired; false when it was preserved.
    expired: bool,
};

/// base/base `RegistrarMetrics` gauges set by each step.
pub const Gauges = struct {
    discovered_instances: u32 = 0,
    active_signers: u32 = 0,
    registerable_signers: u32 = 0,
    unresolved_instances: u32 = 0,
};

/// Per-cycle signer decisions consumed by registration and orphan cleanup.
pub const SignerReconciliation = struct {
    /// Signers whose pending tasks to cancel, each listed once.
    cancel: [registration_tasks.pending_count_max]Address = undefined,
    cancel_count: u32 = 0,
    /// Registerable signers to spawn tasks for, one per signer, first instance wins.
    spawn: [instance_count_max * instance_signer_count_max]SpawnRef = undefined,
    spawn_count: u32 = 0,
    /// Protected signers, valid only when `orphan_cleanup_ready`.
    orphan_cleanup: ProtectedSigners = .{},
    orphan_cleanup_ready: bool = false,
    grace_events: [cache_count_max]GraceEvent = undefined,
    grace_event_count: u32 = 0,
    gauges: Gauges = .{},

    pub fn cancels(result: *const SignerReconciliation) []const Address {
        assert(result.cancel_count <= result.cancel.len);
        return result.cancel[0..result.cancel_count];
    }

    pub fn spawns(result: *const SignerReconciliation) []const SpawnRef {
        assert(result.spawn_count <= result.spawn.len);
        return result.spawn[0..result.spawn_count];
    }

    pub fn protected(result: *const SignerReconciliation) ?*const ProtectedSigners {
        assert(result.orphan_cleanup_ready or result.orphan_cleanup.count == 0);
        return if (result.orphan_cleanup_ready) &result.orphan_cleanup else null;
    }

    pub fn events(result: *const SignerReconciliation) []const GraceEvent {
        assert(result.grace_event_count <= cache_count_max);
        return result.grace_events[0..result.grace_event_count];
    }
};

/// Resolve a spawn reference against the observations passed to `step`.
pub fn spawn_entry(observations: []const Observation, ref: SpawnRef) *const RegisterableSigner {
    const registerable = observations[ref.observation].observation.resolved.registerable;
    assert(ref.entry < registerable.len);
    return &registerable[ref.entry];
}

/// Cached signers and elapsed grace cycles for an instance.
pub const CachedInstance = struct {
    instance_id: InstanceId,
    signers: [instance_signer_count_max]Address,
    signer_count: u32,
    ttl_cycles: u32,
};

/// Fixed-capacity set of instance ids.
fn IdSet(comptime capacity: u32) type {
    return struct {
        const Self = @This();
        items: [capacity]InstanceId = undefined,
        count: u32 = 0,

        fn contains(set: *const Self, id: []const u8) bool {
            assert(set.count <= capacity);
            for (set.items[0..set.count]) |*item| {
                if (std.mem.eql(u8, item.slice(), id)) return true;
            }
            return false;
        }

        /// Returns true when `id` was not yet present.
        fn insert(set: *Self, id: *const InstanceId) Error!bool {
            if (set.contains(id.slice())) return false;
            if (set.count == capacity) return error.ReconcilerTooManyInstances;
            set.items[set.count] = id.*;
            set.count += 1;
            return true;
        }
    };
}

/// Scratch for one step; lives in the reconciler so `step` uses no large stack.
const StepState = struct {
    active: SignerSet = .{},
    unresolved: IdSet(unresolved_count_max) = .{},
    unhealthy: IdSet(instance_count_max) = .{},
    registerable: [instance_count_max * instance_signer_count_max]SpawnRef = undefined,
    registerable_count: u32 = 0,
};

/// Owns the unavailable-instance grace cache across completed discovery cycles.
pub const SignerReconciler = struct {
    cache: [cache_count_max]CachedInstance = undefined,
    cache_count: u32 = 0,
    unhealthy_with_grace: IdSet(instance_count_max) = .{},
    instance_cache_ttl_cycles: u32,
    state: StepState = .{},

    pub fn init(instance_cache_ttl_cycles: u32) SignerReconciler {
        return .{ .instance_cache_ttl_cycles = instance_cache_ttl_cycles };
    }

    /// Apply observations and pending registrations.
    ///
    /// Each step ages missing and unreachable entries once. Pending signers stay
    /// protected until reaped, including cancelled tasks, and block a respawn. A
    /// cancelled, unreaped task may be listed in `cancel` again.
    pub fn step(
        reconciler: *SignerReconciler,
        observations: []const Observation,
        pending: []const PendingRegistration,
        result: *SignerReconciliation,
    ) Error!void {
        if (observations.len > instance_count_max) return error.ReconcilerTooManyInstances;
        assert(pending.len <= registration_tasks.pending_count_max);
        result.* = .{};
        reconciler.state = .{};
        const state = &reconciler.state;
        for (observations, 0..) |*observed, index| {
            try reconciler.observe(observed, @intCast(index));
        }
        try reconciler.refresh_unhealthy_grace();
        result.gauges.discovered_instances = count_distinct(observations);
        try reconciler.age_cache(observations, result);
        result.gauges.active_signers = state.active.count;
        result.gauges.registerable_signers = state.registerable_count;
        result.gauges.unresolved_instances = state.unresolved.count;
        try reconciler.decide(observations, pending, result);
        assert(result.cancel_count <= pending.len);
    }

    fn observe(reconciler: *SignerReconciler, observed: *const Observation, index: u32) Error!void {
        const state = &reconciler.state;
        const id = &observed.instance.instance_id;
        const signers: []const Address = switch (observed.observation) {
            .@"unreachable" => {
                _ = try state.unhealthy.insert(id);
                return;
            },
            // Failed key resolution neither refreshes nor ages cached signers.
            .failed => {
                _ = try state.unresolved.insert(id);
                return;
            },
            .attestations_unavailable => |value| blk: {
                _ = try state.unresolved.insert(id);
                break :blk value.signers;
            },
            .resolved => |value| blk: {
                if (value.registerable.len > instance_signer_count_max) {
                    return error.ReconcilerTooManySigners;
                }
                for (0..value.registerable.len) |entry| {
                    assert(state.registerable_count < state.registerable.len);
                    state.registerable[state.registerable_count] = .{
                        .observation = index,
                        .entry = @intCast(entry),
                    };
                    state.registerable_count += 1;
                }
                break :blk value.signers;
            },
        };
        var distinct: CachedInstance = .{
            .instance_id = id.*,
            .signers = undefined,
            .signer_count = 0,
            .ttl_cycles = 0,
        };
        for (signers) |signer| {
            try state.active.insert(signer);
            try add_distinct(&distinct, signer);
        }
        if (distinct.signer_count == 0) {
            reconciler.cache_remove(id.slice());
        } else {
            try reconciler.cache_upsert(&distinct);
        }
    }

    /// A restarted process has no signers to cache: keep an empty entry for one
    /// unhealthy period so global orphan cleanup waits for the grace TTL.
    fn refresh_unhealthy_grace(reconciler: *SignerReconciler) Error!void {
        const state = &reconciler.state;
        const grace = &reconciler.unhealthy_with_grace;
        var kept: u32 = 0;
        for (grace.items[0..grace.count]) |item| {
            if (!state.unhealthy.contains(item.slice())) continue;
            grace.items[kept] = item;
            kept += 1;
        }
        grace.count = kept;
        for (state.unhealthy.items[0..state.unhealthy.count]) |*id| {
            const inserted = try grace.insert(id);
            if (inserted and reconciler.cache_find(id.slice()) == null) {
                try reconciler.cache_upsert(&.{
                    .instance_id = id.*,
                    .signers = undefined,
                    .signer_count = 0,
                    .ttl_cycles = 0,
                });
            }
        }
        assert(grace.count == state.unhealthy.count);
    }

    fn age_cache(
        reconciler: *SignerReconciler,
        observations: []const Observation,
        result: *SignerReconciliation,
    ) Error!void {
        const state = &reconciler.state;
        var kept: u32 = 0;
        for (0..reconciler.cache_count) |index| {
            var entry = reconciler.cache[index];
            const id = entry.instance_id.slice();
            const keep = if (discovered(observations, id) and !state.unhealthy.contains(id))
                true
            else
                try reconciler.age_entry(&entry, result);
            if (!keep) continue;
            reconciler.cache[kept] = entry;
            kept += 1;
        }
        reconciler.cache_count = kept;
        assert(result.grace_event_count <= cache_count_max);
    }

    /// Age a missing or unhealthy entry once; returns whether it survives.
    fn age_entry(
        reconciler: *SignerReconciler,
        entry: *CachedInstance,
        result: *SignerReconciliation,
    ) Error!bool {
        const state = &reconciler.state;
        entry.ttl_cycles +|= 1;
        const preserved = entry.ttl_cycles <= reconciler.instance_cache_ttl_cycles;
        result.grace_events[result.grace_event_count] = .{
            .instance_id = entry.instance_id,
            .ttl_cycles = entry.ttl_cycles,
            .cached_signers = entry.signer_count,
            .expired = !preserved,
        };
        result.grace_event_count += 1;
        if (!preserved) return false;
        for (entry.signers[0..entry.signer_count]) |signer| try state.active.insert(signer);
        // An unhealthy instance first seen after a restart has no signers to
        // protect; a missing one could have changed signers since its refresh.
        if (entry.signer_count == 0 or !state.unhealthy.contains(entry.instance_id.slice())) {
            _ = try state.unresolved.insert(&entry.instance_id);
        }
        return true;
    }

    fn decide(
        reconciler: *SignerReconciler,
        observations: []const Observation,
        pending: []const PendingRegistration,
        result: *SignerReconciliation,
    ) Error!void {
        const state = &reconciler.state;
        const registerable = state.registerable[0..state.registerable_count];
        for (pending) |*task| {
            if (registerable_contains(observations, registerable, &task.signer)) continue;
            if (state.unresolved.contains(task.instance_id.slice())) continue;
            result.cancel[result.cancel_count] = task.signer;
            result.cancel_count += 1;
        }
        var spawned: SignerSet = .{};
        for (registerable) |ref| {
            const signer = spawn_entry(observations, ref).signer;
            if (pending_contains(pending, &signer) or spawned.contains(&signer)) continue;
            try spawned.insert(signer);
            result.spawn[result.spawn_count] = ref;
            result.spawn_count += 1;
        }
        if (state.unresolved.count != 0) return;
        result.orphan_cleanup = state.active;
        for (pending) |*task| try result.orphan_cleanup.insert(task.signer);
        for (spawned.slice()) |signer| try result.orphan_cleanup.insert(signer);
        result.orphan_cleanup_ready = true;
    }

    pub fn cache_find(reconciler: *const SignerReconciler, id: []const u8) ?*const CachedInstance {
        assert(reconciler.cache_count <= cache_count_max);
        for (reconciler.cache[0..reconciler.cache_count]) |*entry| {
            if (std.mem.eql(u8, entry.instance_id.slice(), id)) return entry;
        }
        return null;
    }

    fn cache_upsert(reconciler: *SignerReconciler, entry: *const CachedInstance) Error!void {
        assert(entry.signer_count <= instance_signer_count_max);
        for (reconciler.cache[0..reconciler.cache_count]) |*existing| {
            if (existing.instance_id.eql(&entry.instance_id)) {
                existing.* = entry.*;
                return;
            }
        }
        if (reconciler.cache_count == cache_count_max) return error.ReconcilerCacheFull;
        reconciler.cache[reconciler.cache_count] = entry.*;
        reconciler.cache_count += 1;
    }

    fn cache_remove(reconciler: *SignerReconciler, id: []const u8) void {
        var kept: u32 = 0;
        for (0..reconciler.cache_count) |index| {
            if (std.mem.eql(u8, reconciler.cache[index].instance_id.slice(), id)) continue;
            reconciler.cache[kept] = reconciler.cache[index];
            kept += 1;
        }
        reconciler.cache_count = kept;
        assert(reconciler.cache_find(id) == null);
    }
};

fn add_distinct(entry: *CachedInstance, signer: Address) Error!void {
    for (entry.signers[0..entry.signer_count]) |*existing| {
        if (std.mem.eql(u8, existing, &signer)) return;
    }
    if (entry.signer_count == instance_signer_count_max) return error.ReconcilerTooManySigners;
    entry.signers[entry.signer_count] = signer;
    entry.signer_count += 1;
}

fn discovered(observations: []const Observation, id: []const u8) bool {
    for (observations) |*observed| {
        if (std.mem.eql(u8, observed.instance.instance_id.slice(), id)) return true;
    }
    return false;
}

fn count_distinct(observations: []const Observation) u32 {
    var count: u32 = 0;
    for (observations, 0..) |*observed, index| {
        if (!discovered(observations[0..index], observed.instance.instance_id.slice())) count += 1;
    }
    assert(count <= observations.len);
    return count;
}

fn registerable_contains(
    observations: []const Observation,
    registerable: []const SpawnRef,
    signer: *const Address,
) bool {
    for (registerable) |ref| {
        if (std.mem.eql(u8, &spawn_entry(observations, ref).signer, signer)) return true;
    }
    return false;
}

fn pending_contains(pending: []const PendingRegistration, signer: *const Address) bool {
    for (pending) |*task| {
        if (std.mem.eql(u8, &task.signer, signer)) return true;
    }
    return false;
}

test {
    _ = @import("reconciler_test.zig");
}

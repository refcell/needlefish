//! Resource metering in transaction selection: the builder-side driver of a schedule over
//! one build. Mirrors base/base `ResourceMeteringConfig` (`crates/execution/payload/src/
//! config.rs`: `check_simulated_usage`, `check_executed_usage`, `unthrottled_usage`,
//! `apply_accounted_usage`) and how `execute_best_transactions` and
//! `execute_sequencer_transactions` call it.
//!
//! Per build: `begin_build` zeroes the cumulative usage. Attribute (sequencer) transactions
//! are accounted unthrottled after execution (`account_unthrottled`). Each pool candidate
//! is checked before execution against its simulated sample from the `MeteringStore`
//! (`check_simulated`; a missing sample fails open). An included candidate's executed usage
//! (actual gas used plus the simulated rows) is checked and added to the cumulative usage
//! (`account_executed`). Dry-run throttles never exclude, and their usage still counts so
//! later enforced dimensions see the real remaining budget. Calculation failures (overflow)
//! fail open and add nothing. Metering is active only when enabled with a non-empty
//! schedule; inactive, every call is a no-op and the builder behaves exactly as without it.
//!
//! Two gaps against base/base, both tracked in the builder lane backlog: the executor does
//! not report post-state `STATE_*` counts yet, so the executed sample keeps the simulated
//! `STATE_*` rows instead of replacing them; and the executor cannot undo an applied
//! transaction, so an executed-only overrun is counted (`Build.executed_overruns`) but the
//! transaction stays in the block (base/base drops it with `CommitChanges::No`).

const std = @import("std");
const assert = std.debug.assert;

const schedule_module = @import("schedule.zig");
const sample_module = @import("sample.zig");
const store_module = @import("root.zig");

const Schedule = schedule_module.Schedule;
const Decision = schedule_module.Decision;
const Observation = schedule_module.Observation;
const Sample = sample_module.Sample;
const MeteringStore = store_module.MeteringStore;
const B256 = store_module.B256;

/// Counters for the current build (base/base logs `throttled` per payload scan).
pub const Build = struct {
    /// Candidates excluded by an enforced simulated overrun.
    throttled: u32 = 0,
    /// Of those, transaction-scope (permanent pool evictions).
    permanent: u32 = 0,
    /// Usage calculations that overflowed (failed open).
    calculation_failed: u32 = 0,
    /// Included transactions whose executed usage was over an enforced budget.
    executed_overruns: u32 = 0,
};

/// The result of a simulated check: whether to exclude the candidate and the sample to
/// carry into the executed check.
pub const Admission = struct {
    decision: Decision,
    sample: ?*const Sample,

    pub fn should_exclude(admission: Admission) bool {
        return admission.decision.should_exclude();
    }

    pub fn is_permanent(admission: Admission) bool {
        return admission.decision.is_permanent();
    }
};

pub const ResourceMetering = struct {
    /// `--builder.enable-resource-metering`.
    enabled: bool,
    schedule: *const Schedule,
    /// The `meterBundle` results; null behaves as an empty store (everything fails open).
    store: ?*MeteringStore,
    cumulative: [schedule_module.dimensions_max]u128 = @splat(0),
    usage: [schedule_module.dimensions_max]u128 = @splat(0),
    build: Build = .{},
    /// Optional observer of every non-allow decision (metrics, logs).
    on_decision: ?Observer = null,

    pub const Observer = struct {
        context: *anyopaque,
        record: *const fn (context: *anyopaque, decision: Decision) void,
    };

    pub fn init(
        enabled: bool,
        schedule: *const Schedule,
        store: ?*MeteringStore,
    ) ResourceMetering {
        const metering: ResourceMetering = .{
            .enabled = enabled,
            .schedule = schedule,
            .store = store,
        };
        assert(metering.build.throttled == 0);
        assert(metering.cumulative[0] == 0);
        return metering;
    }

    /// base/base `is_active`: enabled with a non-empty schedule.
    pub fn is_active(metering: *const ResourceMetering) bool {
        return metering.enabled and !metering.schedule.is_empty();
    }

    /// Cumulative usage of the current build, one value per schedule dimension.
    pub fn cumulative_usage(metering: *const ResourceMetering) []const u128 {
        const count = metering.schedule.dimension_list().len;
        assert(count <= metering.cumulative.len);
        return metering.cumulative[0..count];
    }

    pub fn begin_build(metering: *ResourceMetering) void {
        metering.cumulative = @splat(0);
        metering.build = .{};
        assert(metering.cumulative_usage().len == 0 or metering.cumulative_usage()[0] == 0);
    }

    /// base/base `check_simulated_usage`: decides from the simulated sample before
    /// execution; adds nothing to the cumulative usage.
    pub fn check_simulated(metering: *ResourceMetering, hash: B256, now_ns: u64) Admission {
        if (!metering.is_active()) return .{ .decision = .allow, .sample = null };
        const sample = metering.sample_of(hash, now_ns) orelse
            return .{ .decision = .allow, .sample = null };
        var buffer: [sample_module.observations_max]Observation = undefined;
        const decision = metering.schedule.decide(
            sample.gas_used,
            sample.observations(&buffer),
            metering.cumulative_usage(),
            &metering.usage,
        );
        if (decision.should_exclude()) {
            metering.build.throttled += 1;
            if (decision.is_permanent()) metering.build.permanent += 1;
            metering.record(decision);
        }
        assert(metering.build.permanent <= metering.build.throttled);
        return .{ .decision = decision, .sample = sample };
    }

    /// base/base `check_executed_usage` + `apply_accounted_usage` for an included pool
    /// transaction: evaluates actual gas plus the simulated rows, records the decision, and
    /// adds the usage unless the calculation failed.
    pub fn account_executed(
        metering: *ResourceMetering,
        gas_used: u64,
        sample: ?*const Sample,
    ) Decision {
        if (!metering.is_active()) return .allow;
        var buffer: [sample_module.observations_max]Observation = undefined;
        const observations: []const Observation = if (sample) |found|
            found.observations(&buffer)
        else
            &.{};
        const decision = metering.schedule.decide(
            gas_used,
            observations,
            metering.cumulative_usage(),
            &metering.usage,
        );
        if (decision.should_exclude()) metering.build.executed_overruns += 1;
        metering.record(decision);
        if (decision.has_usage()) metering.apply_usage();
        assert(decision != .calculation_failed or metering.build.calculation_failed > 0);
        return decision;
    }

    /// base/base `unthrottled_usage` + `apply_accounted_usage` for an attribute
    /// transaction: always included; failures fail open.
    pub fn account_unthrottled(
        metering: *ResourceMetering,
        hash: B256,
        gas_used: u64,
        now_ns: u64,
    ) void {
        if (!metering.is_active()) return;
        var buffer: [sample_module.observations_max]Observation = undefined;
        const observations: []const Observation = if (metering.sample_of(hash, now_ns)) |found|
            found.observations(&buffer)
        else
            &.{};
        const dimensions = metering.schedule.dimension_list().len;
        metering.schedule.evaluate(gas_used, observations, metering.usage[0..dimensions]) catch {
            metering.record(.calculation_failed);
            return;
        };
        metering.apply_usage();
    }

    fn sample_of(metering: *ResourceMetering, hash: B256, now_ns: u64) ?*const Sample {
        assert(metering.is_active());
        const store = metering.store orelse return null;
        return store.sample_of(hash, now_ns);
    }

    /// Adds `usage` to the cumulative usage atomically; overflow fails open.
    fn apply_usage(metering: *ResourceMetering) void {
        const dimensions = metering.schedule.dimension_list().len;
        const usage = metering.usage[0..dimensions];
        schedule_module.add_usage(metering.cumulative[0..dimensions], usage) catch {
            metering.record(.calculation_failed);
        };
    }

    fn record(metering: *ResourceMetering, decision: Decision) void {
        if (decision == .allow) return;
        if (decision == .calculation_failed) metering.build.calculation_failed += 1;
        if (metering.on_decision) |observer| observer.record(observer.context, decision);
    }
};

test {
    _ = @import("resource_test.zig");
}

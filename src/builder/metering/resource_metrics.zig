//! Resource-metering metrics, named as base/base `ResourceMeteringMetrics`
//! (`crates/execution/payload/src/resource_metering_metrics.rs`, scope
//! `base_payload.resource_metering`): calculation failures, budget observations
//! (`limit_exceeded_total`) and enforced throttles (`throttled_total`), both labeled by
//! dimension and scope. Counters are fixed arrays over the schedule's dimension bound;
//! `register` exports only the loaded dimensions. Pinned once registered or observing.

const std = @import("std");
const assert = std.debug.assert;

const metrics = @import("../../utilities/metrics/root.zig");
const schedule_module = @import("schedule.zig");
const resource = @import("resource.zig");

const Schedule = schedule_module.Schedule;
const Decision = schedule_module.Decision;
const Counter = metrics.Counter;
const Label = metrics.Label;
const dimensions_max = schedule_module.dimensions_max;
const scopes = [_][]const u8{ "transaction", "block" };

pub const name_calculation_failed = "base_payload_resource_metering_calculation_failed";
pub const name_limit_exceeded = "base_payload_resource_metering_limit_exceeded_total";
pub const name_throttled = "base_payload_resource_metering_throttled_total";

pub const ResourceMeteringMetrics = struct {
    schedule: *const Schedule,
    calculation_failed: Counter = .{},
    limit_exceeded: [dimensions_max][scopes.len]Counter = @splat(@splat(.{})),
    throttled: [dimensions_max][scopes.len]Counter = @splat(@splat(.{})),
    labels: [dimensions_max][scopes.len][2]Label = undefined,

    pub fn init(schedule: *const Schedule) ResourceMeteringMetrics {
        const result: ResourceMeteringMetrics = .{ .schedule = schedule };
        assert(result.calculation_failed.get() == 0);
        assert(result.throttled[0][0].get() == 0);
        return result;
    }

    /// The observer to install as `ResourceMetering.on_decision`.
    pub fn observer(self: *ResourceMeteringMetrics) resource.ResourceMetering.Observer {
        return .{ .context = self, .record = record_opaque };
    }

    /// base/base `record_decision` / `ResourceMeteringMetrics::record_limit`: a budget
    /// observation, and a throttle when the overrun is enforced (not dry-run).
    pub fn record(self: *ResourceMeteringMetrics, decision: Decision) void {
        switch (decision) {
            .allow => {},
            .calculation_failed => self.calculation_failed.increment(),
            .throttle => |limit| {
                assert(limit.dimension < self.schedule.dimension_list().len);
                const scope = @backingInt(limit.scope);
                self.limit_exceeded[limit.dimension][scope].increment();
                if (!limit.dry_run) self.throttled[limit.dimension][scope].increment();
            },
        }
    }

    fn record_opaque(context: *anyopaque, decision: Decision) void {
        const self: *ResourceMeteringMetrics = @ptrCast(@alignCast(context));
        self.record(decision);
    }

    /// Entries `register` adds for the loaded schedule.
    pub fn entries_count(self: *const ResourceMeteringMetrics) u32 {
        const dimensions: u32 = @intCast(self.schedule.dimension_list().len);
        return 1 + 2 * @as(u32, scopes.len) * dimensions;
    }

    /// Registers every metric in a `*metrics.Registry(capacity)`.
    pub fn register(
        self: *ResourceMeteringMetrics,
        registry: anytype,
    ) metrics.RegisterError!void {
        const count_before = registry.count;
        try registry.counter(
            name_calculation_failed,
            "Transactions whose resource-metering usage could not be calculated",
            &self.calculation_failed,
        );
        for (self.schedule.dimension_list(), 0..) |*dimension, index| {
            for (scopes, 0..) |scope, scope_index| {
                const labels = &self.labels[index][scope_index];
                labels.* = .{
                    .{ .name = "dimension", .value = dimension.name() },
                    .{ .name = "scope", .value = scope },
                };
                try registry.register(.{
                    .name = name_limit_exceeded,
                    .help = "Transactions that would be throttled by a resource-metering budget",
                    .labels = labels,
                    .metric = .{ .counter = &self.limit_exceeded[index][scope_index] },
                });
                try registry.register(.{
                    .name = name_throttled,
                    .help = "Transactions throttled by a resource-metering budget",
                    .labels = labels,
                    .metric = .{ .counter = &self.throttled[index][scope_index] },
                });
            }
        }
        assert(registry.count - count_before == self.entries_count());
    }
};

comptime {
    assert(@backingInt(schedule_module.Scope.transaction) == 0);
    assert(@backingInt(schedule_module.Scope.block) == 1);
}

test "resource metrics: limits, throttles and failures by dimension and scope" {
    var schedule = try Schedule.init(std.testing.allocator, .{ .rules_max = 4 });
    defer schedule.deinit(std.testing.allocator);
    try schedule.load(
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":10,"baseGasWeight":1,
        \\"dryRun":false},{"name":"io","blockLimit":10,"baseGasWeight":1,"dryRun":true}]}
    );
    var self = ResourceMeteringMetrics.init(&schedule);
    const enforced: schedule_module.LimitExceeded = .{
        .dimension = 0,
        .scope = .block,
        .used = 11,
        .transaction_cost = 5,
        .limit = 10,
        .dry_run = false,
    };
    var dry = enforced;
    dry.dimension = 1;
    dry.scope = .transaction;
    dry.dry_run = true;
    const observer = self.observer();
    observer.record(observer.context, .{ .throttle = enforced });
    observer.record(observer.context, .{ .throttle = dry });
    observer.record(observer.context, .calculation_failed);
    observer.record(observer.context, .allow);
    try std.testing.expectEqual(@as(u64, 1), self.throttled[0][1].get());
    try std.testing.expectEqual(@as(u64, 1), self.limit_exceeded[1][0].get());
    try std.testing.expectEqual(@as(u64, 0), self.throttled[1][0].get());
    try std.testing.expectEqual(@as(u64, 1), self.calculation_failed.get());
    var registry: metrics.Registry(16) = .{};
    try self.register(&registry);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try registry.write_prometheus(&writer);
    const text = writer.buffered();
    const throttled_line = name_throttled ++ "{dimension=\"cpu\",scope=\"block\"} 1";
    try std.testing.expect(std.mem.indexOf(u8, text, throttled_line) != null);
    const limit_line = name_limit_exceeded ++ "{dimension=\"io\",scope=\"transaction\"} 1";
    try std.testing.expect(std.mem.indexOf(u8, text, limit_line) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, name_calculation_failed ++ " 1") != null);
}

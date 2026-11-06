//! Builder resource metering from startup flags: base/base `ResourceMeteringConfig::
//! from_parts` (`crates/execution/payload/src/config.rs`) with `--builder.enable-resource-
//! metering` and `--payload.resource-metering-schedule`. `BuilderMetering` owns the schedule,
//! the metering store, the per-build driver installed on the block builder, and the metrics.
//!
//! Enabled with a schedule: the schedule is loaded and must have at least one dimension (an
//! empty schedule fails closed, `EmptySchedule`, because the operator asked for one).
//! Enabled without a schedule: the store runs but throttling is inactive. Disabled: the
//! caller does not create it at all, so a disabled builder allocates nothing for metering.
//! The schedule JSON is passed in (the binary reads the file); everything is allocated in
//! `init`. Pinned once `init` ran (the driver and metrics point into it).

const std = @import("std");
const assert = std.debug.assert;

const store_module = @import("root.zig");
const schedule_module = @import("schedule.zig");
const resource = @import("resource.zig");
const resource_metrics = @import("resource_metrics.zig");

const Schedule = schedule_module.Schedule;
const MeteringStore = store_module.MeteringStore;

pub const Config = struct {
    /// `--builder.enable-resource-metering`.
    enabled: bool = false,
    /// The contents of `--payload.resource-metering-schedule`, when given.
    schedule_json: ?[]const u8 = null,
    store_capacity: u32 = store_module.capacity_default,
    store_ttl_ns: u64 = store_module.ttl_ns_default,
    schedule: schedule_module.Config = .{},
};

pub const Error = schedule_module.Error || std.mem.Allocator.Error || error{EmptySchedule};

pub const BuilderMetering = struct {
    schedule: Schedule,
    store: MeteringStore,
    driver: resource.ResourceMetering,
    metrics: resource_metrics.ResourceMeteringMetrics,

    pub fn init(self: *BuilderMetering, allocator: std.mem.Allocator, config: Config) Error!void {
        assert(config.enabled);
        assert(config.store_capacity > 0 and config.store_ttl_ns > 0);
        self.schedule = try Schedule.init(allocator, config.schedule);
        errdefer self.schedule.deinit(allocator);
        if (config.schedule_json) |text| {
            try self.schedule.load(text);
            if (self.schedule.is_empty()) return error.EmptySchedule;
        }
        self.store = try MeteringStore.init(
            allocator,
            true,
            config.store_capacity,
            config.store_ttl_ns,
        );
        self.metrics = resource_metrics.ResourceMeteringMetrics.init(&self.schedule);
        self.driver = resource.ResourceMetering.init(true, &self.schedule, &self.store);
        self.driver.on_decision = self.metrics.observer();
        assert(self.driver.is_active() == (config.schedule_json != null));
    }

    pub fn deinit(self: *BuilderMetering, allocator: std.mem.Allocator) void {
        self.store.deinit(allocator);
        self.schedule.deinit(allocator);
        self.* = undefined;
    }
};

test "builder metering: from_parts" {
    const allocator = std.testing.allocator;
    var metering: BuilderMetering = undefined;
    // Enabled without a schedule: store only, throttling inactive.
    try metering.init(allocator, .{ .enabled = true, .store_capacity = 4 });
    try std.testing.expect(!metering.driver.is_active());
    try std.testing.expect(metering.store.is_enabled());
    metering.deinit(allocator);
    // A schedule with no dimensions fails closed.
    try std.testing.expectError(error.EmptySchedule, metering.init(allocator, .{
        .enabled = true,
        .schedule_json = "{\"version\":1,\"dimensions\":[]}",
        .store_capacity = 4,
    }));
    try std.testing.expectError(error.ParseJson, metering.init(allocator, .{
        .enabled = true,
        .schedule_json = "",
        .store_capacity = 4,
    }));
    try metering.init(allocator, .{
        .enabled = true,
        .schedule_json =
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":10,"baseGasWeight":1,
        \\"dryRun":false}]}
        ,
        .store_capacity = 4,
    });
    defer metering.deinit(allocator);
    try std.testing.expect(metering.driver.is_active());
    metering.driver.begin_build();
    _ = metering.driver.account_executed(6, null);
    _ = metering.driver.account_executed(6, null); // 12 > 10: block scope, still counted.
    try std.testing.expectEqual(@as(u64, 0), metering.metrics.throttled[0][0].get());
    try std.testing.expectEqual(@as(u64, 1), metering.metrics.throttled[0][1].get());
}

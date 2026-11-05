//! Live upgrade-signal observer (base/base `upgrade-signal` runtime refresher + metrics).
//!
//! Reads the schedule immediately on `start`, then on the block tag's interval. Live polls
//! make a single attempt and are skipped while a read is still in flight. A read failure is
//! only counted (`l1_read_errors_total`, per upgrade as in base/base): the last observed
//! schedule is kept. On the first observation and on every change, `on_update` runs with the
//! new schedule and the per-upgrade `signal_updates_total` counters move for changed entries.
//! Applying the schedule (runtime-admin mode) is the callback owner's job.

const std = @import("std");
const assert = std.debug.assert;

const metrics = @import("../metrics/root.zig");
const time = @import("../time/root.zig");
const contract = @import("contract.zig");
const reader_module = @import("reader.zig");
const Schedule = reader_module.Schedule;

pub const Layer = enum {
    execution,
    consensus,

    pub fn label(layer: Layer) []const u8 {
        return switch (layer) {
            .execution => "el",
            .consensus => "cl",
        };
    }
};

pub const Options = struct {
    layer: Layer,
    reader: reader_module.Options = .{},
};

const upgrades = contract.upgrade_ids.len;

/// Metrics with base/base names (`base_upgrade_signal_*`), per upgrade where base/base labels
/// by upgrade. The protocol version gauge uses base/base's `major*1e6 + minor*1e3 + patch`.
pub const Metrics = struct {
    activation_timestamp: [upgrades]metrics.Gauge = @splat(.{}),
    expected_protocol_version: [upgrades]metrics.Gauge = @splat(.{}),
    last_l1_read_block: [upgrades]metrics.Gauge = @splat(.{}),
    l1_read_errors_total: [upgrades]metrics.Counter = @splat(.{}),
    signal_updates_total: [upgrades]metrics.Counter = @splat(.{}),
    empty_schedule_reads_total: metrics.Counter = .{},
};

pub fn Observer(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Reader = reader_module.Reader(IO, *Self);
        pub const OnUpdate = *const fn (context: Context, schedule: *const Schedule) void;

        reader: Reader,
        ticker: time.Ticker(IO, *Self),
        layer: Layer,
        context: Context,
        on_update: OnUpdate,
        /// The last successfully read schedule; valid when `observed`.
        last: Schedule = .{},
        observed: bool = false,
        polls_skipped: u64 = 0,
        metrics: Metrics = .{},
        labels: [upgrades][2]metrics.Label = undefined,
        layer_label: [1]metrics.Label = undefined,

        /// In place: the ticker and reader callbacks keep pointers to the observer.
        pub fn init(
            observer: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            l1_endpoint: reader_module.Address,
            contract_address: [20]u8,
            options: Options,
            context: Context,
            on_update: OnUpdate,
        ) !void {
            const interval_ns = options.reader.block_tag.poll_interval_ns();
            observer.* = .{
                .reader = try .init(allocator, io, l1_endpoint, contract_address, options.reader),
                .ticker = .init(io, interval_ns, observer, on_tick),
                .layer = options.layer,
                .context = context,
                .on_update = on_update,
            };
            const layer = metrics.Label{ .name = "layer", .value = options.layer.label() };
            observer.layer_label = .{layer};
            for (&observer.labels, contract.upgrade_ids) |*labels, id| {
                labels.* = .{ layer, .{ .name = "upgrade", .value = id } };
            }
        }

        pub fn deinit(observer: *Self) void {
            assert(observer.stopped());
            observer.reader.deinit();
            observer.* = undefined;
        }

        pub fn start(observer: *Self) void {
            assert(!observer.ticker.running);
            observer.poll();
            observer.ticker.start();
        }

        /// Stops polling; an in-flight read still completes.
        pub fn stop(observer: *Self) void {
            observer.ticker.stop();
        }

        pub fn stopped(observer: *const Self) bool {
            return !observer.ticker.running and !observer.reader.busy();
        }

        /// Registers every metric (6 per upgrade family, `5 * upgrades + 1` entries).
        pub fn register(observer: *Self, registry: anytype) !void {
            const prefix = "base_upgrade_signal_";
            const m = &observer.metrics;
            for (0..upgrades) |index| {
                const labels = &observer.labels[index];
                try registry.register(.{
                    .name = prefix ++ "activation_timestamp",
                    .help = "Configured activation timestamp read from L1",
                    .labels = labels,
                    .metric = .{ .gauge = &m.activation_timestamp[index] },
                });
                try registry.register(.{
                    .name = prefix ++ "expected_protocol_version",
                    .help = "Minimum node protocol version read from L1",
                    .labels = labels,
                    .metric = .{ .gauge = &m.expected_protocol_version[index] },
                });
                try registry.register(.{
                    .name = prefix ++ "last_l1_read_block",
                    .help = "Last L1 block number used for a successful upgrade signal read",
                    .labels = labels,
                    .metric = .{ .gauge = &m.last_l1_read_block[index] },
                });
                try registry.register(.{
                    .name = prefix ++ "l1_read_errors_total",
                    .help = "Total failed attempts to read the L1 upgrade signal",
                    .labels = labels,
                    .metric = .{ .counter = &m.l1_read_errors_total[index] },
                });
                try registry.register(.{
                    .name = prefix ++ "signal_updates_total",
                    .help = "Total observed L1 upgrade signal value changes while the node is live",
                    .labels = labels,
                    .metric = .{ .counter = &m.signal_updates_total[index] },
                });
            }
            try registry.register(.{
                .name = prefix ++ "empty_schedule_reads_total",
                .help = "Total L1 upgrade signal reads that succeeded but returned an empty " ++
                    "schedule",
                .labels = &observer.layer_label,
                .metric = .{ .counter = &m.empty_schedule_reads_total },
            });
        }

        fn on_tick(observer: *Self) void {
            observer.reader.tick();
            observer.poll();
        }

        fn poll(observer: *Self) void {
            if (observer.reader.busy()) {
                observer.polls_skipped += 1;
                return;
            }
            observer.reader.read(observer, on_read) catch observer.record_read_error();
        }

        fn record_read_error(observer: *Self) void {
            for (&observer.metrics.l1_read_errors_total) |*counter| counter.increment();
        }

        fn on_read(observer: *Self, result: reader_module.Error!*const Schedule) void {
            const schedule = result catch |err| {
                if (err == error.EmptySchedule) {
                    observer.metrics.empty_schedule_reads_total.increment();
                } else {
                    observer.record_read_error();
                }
                return;
            };
            assert(schedule.count > 0);
            const changed = observer.record_schedule(schedule);
            if (!changed and observer.observed) return;
            observer.last = schedule.*;
            observer.observed = true;
            observer.on_update(observer.context, &observer.last);
        }

        /// Updates gauges and change counters; returns whether any signal changed.
        fn record_schedule(observer: *Self, schedule: *const Schedule) bool {
            const m = &observer.metrics;
            const version = schedule.minimum_version;
            const version_value: i64 = @intCast(@as(u64, version.major()) * 1_000_000 +
                @as(u64, version.minor()) * 1_000 + version.patch());
            var changed = !observer.last.minimum_version.eql(version);
            for (0..schedule.signals_count()) |index| {
                const timestamp = schedule.timestamps[index];
                const known = observer.observed and index < observer.last.signals_count();
                const same = known and observer.last.timestamps[index] == timestamp;
                if (observer.observed and !same) {
                    m.signal_updates_total[index].increment();
                    changed = true;
                }
                m.activation_timestamp[index].set(@intCast(@min(timestamp, std.math.maxInt(i64))));
                m.expected_protocol_version[index].set(version_value);
                m.last_l1_read_block[index].set(@intCast(@min(
                    schedule.l1_block_number,
                    std.math.maxInt(i64),
                )));
            }
            if (observer.observed and schedule.signals_count() != observer.last.signals_count()) {
                changed = true;
            }
            return changed;
        }
    };
}

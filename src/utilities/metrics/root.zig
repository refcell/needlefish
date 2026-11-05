//! Metrics with a static registry and Prometheus text exposition.
//!
//! Metrics are plain structs (`Counter`, `Gauge`, `Histogram`) owned by components and
//! registered once at startup into a fixed-capacity `Registry`; there is no global state and
//! no allocation. Updates are single atomic operations, so the event loop thread and any
//! helper thread can update them without locks. `Registry.write_prometheus` renders text
//! format 0.0.4 for a `/metrics` endpoint.

const std = @import("std");
const assert = std.debug.assert;

pub const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub fn increment(counter: *Counter) void {
        _ = counter.value.fetchAdd(1, .monotonic);
    }

    pub fn add(counter: *Counter, amount: u64) void {
        _ = counter.value.fetchAdd(amount, .monotonic);
    }

    pub fn get(counter: *const Counter) u64 {
        return counter.value.load(.monotonic);
    }
};

/// A signed gauge (queue depths, peers, head numbers).
pub const Gauge = struct {
    value: std.atomic.Value(i64) = .init(0),

    pub fn set(gauge: *Gauge, value: i64) void {
        gauge.value.store(value, .monotonic);
    }

    pub fn add(gauge: *Gauge, amount: i64) void {
        _ = gauge.value.fetchAdd(amount, .monotonic);
    }

    pub fn get(gauge: *const Gauge) i64 {
        return gauge.value.load(.monotonic);
    }
};

pub const buckets_max = 16;

/// Exponential default buckets for latencies in seconds: 1 ms .. ~16 s.
pub const latency_buckets_s = [_]f64{
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 16,
};

/// A histogram with fixed upper bounds. Observations are in the metric's base unit (usually
/// seconds). The sum is kept in nanounits as an integer so updates stay atomic.
pub const Histogram = struct {
    bounds: []const f64,
    counts: [buckets_max]std.atomic.Value(u64) = @splat(.init(0)),
    count: std.atomic.Value(u64) = .init(0),
    sum_nano: std.atomic.Value(u64) = .init(0),

    pub fn init(bounds: []const f64) Histogram {
        assert(bounds.len > 0 and bounds.len <= buckets_max);
        for (bounds[1..], bounds[0 .. bounds.len - 1]) |upper, lower| assert(upper > lower);
        return .{ .bounds = bounds };
    }

    pub fn observe(histogram: *Histogram, value: f64) void {
        assert(!std.math.isNan(value));
        // Non-cumulative per-bucket counts; rendering accumulates them.
        for (histogram.bounds, 0..) |bound, index| {
            if (value <= bound) {
                _ = histogram.counts[index].fetchAdd(1, .monotonic);
                break;
            }
        }
        _ = histogram.count.fetchAdd(1, .monotonic);
        // Clamp to 2^62 nanounits (~146 years of seconds) so the cast cannot overflow.
        const nano_max: f64 = 4.611686018427388e18;
        const nano = if (value <= 0) 0 else @min(value * 1e9, nano_max);
        _ = histogram.sum_nano.fetchAdd(@intFromFloat(nano), .monotonic);
    }

    /// Records a duration given in nanoseconds into a histogram measured in seconds.
    pub fn observe_ns(histogram: *Histogram, duration_ns: u64) void {
        histogram.observe(@as(f64, @floatFromInt(duration_ns)) / 1e9);
    }
};

pub const Kind = enum { counter, gauge, histogram };

pub const Label = struct { name: []const u8, value: []const u8 };

pub const Entry = struct {
    name: []const u8,
    help: []const u8,
    labels: []const Label = &.{},
    metric: union(Kind) {
        counter: *Counter,
        gauge: *Gauge,
        histogram: *Histogram,
    },
};

pub const RegisterError = error{ RegistryFull, InvalidName, DuplicateMetric };

/// A fixed-capacity list of metrics. Register everything at startup.
pub fn Registry(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        entries: [capacity]Entry = undefined,
        count: u32 = 0,

        pub fn register(registry: *Self, entry: Entry) RegisterError!void {
            if (!valid_name(entry.name)) return error.InvalidName;
            for (entry.labels) |label| if (!valid_name(label.name)) return error.InvalidName;
            for (registry.entries[0..registry.count]) |existing| {
                const same_name = std.mem.eql(u8, existing.name, entry.name);
                if (same_name and labels_equal(existing, entry)) {
                    return error.DuplicateMetric;
                }
            }
            if (registry.count == capacity) return error.RegistryFull;
            registry.entries[registry.count] = entry;
            registry.count += 1;
        }

        pub fn counter(
            registry: *Self,
            name: []const u8,
            help: []const u8,
            metric: *Counter,
        ) RegisterError!void {
            const entry: Entry = .{ .name = name, .help = help, .metric = .{ .counter = metric } };
            try registry.register(entry);
        }

        pub fn gauge(
            registry: *Self,
            name: []const u8,
            help: []const u8,
            metric: *Gauge,
        ) RegisterError!void {
            const entry: Entry = .{ .name = name, .help = help, .metric = .{ .gauge = metric } };
            try registry.register(entry);
        }

        pub fn histogram(
            registry: *Self,
            name: []const u8,
            help: []const u8,
            metric: *Histogram,
        ) RegisterError!void {
            const entry: Entry = .{
                .name = name,
                .help = help,
                .metric = .{ .histogram = metric },
            };
            try registry.register(entry);
        }

        /// Renders all metrics in Prometheus text format. `# HELP`/`# TYPE` lines are written
        /// once per metric name (entries sharing a name differ only in labels).
        pub fn write_prometheus(
            registry: *const Self,
            out: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            for (registry.entries[0..registry.count], 0..) |entry, index| {
                const first_of_name = for (registry.entries[0..index]) |previous| {
                    if (std.mem.eql(u8, previous.name, entry.name)) break false;
                } else true;
                if (first_of_name) {
                    try out.print("# HELP {s} ", .{entry.name});
                    try write_help(out, entry.help);
                    try out.print("\n# TYPE {s} {s}\n", .{ entry.name, @tagName(entry.metric) });
                }
                try write_entry(out, entry);
            }
        }
    };
}

fn labels_equal(a: Entry, b: Entry) bool {
    if (a.labels.len != b.labels.len) return false;
    for (a.labels, b.labels) |x, y| {
        if (!std.mem.eql(u8, x.name, y.name) or !std.mem.eql(u8, x.value, y.value)) return false;
    }
    return true;
}

/// Prometheus metric and label names: `[a-zA-Z_:][a-zA-Z0-9_:]*`.
pub fn valid_name(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name, 0..) |byte, index| {
        const ok = std.ascii.isAlphabetic(byte) or byte == '_' or byte == ':' or
            (index > 0 and std.ascii.isDigit(byte));
        if (!ok) return false;
    }
    return true;
}

fn write_entry(out: *std.Io.Writer, entry: Entry) std.Io.Writer.Error!void {
    switch (entry.metric) {
        .counter => |c| {
            try write_series(out, entry.name, "", entry.labels, null);
            try out.print(" {d}\n", .{c.get()});
        },
        .gauge => |g| {
            try write_series(out, entry.name, "", entry.labels, null);
            try out.print(" {d}\n", .{g.get()});
        },
        .histogram => |h| try write_histogram(out, entry, h),
    }
}

fn write_histogram(
    out: *std.Io.Writer,
    entry: Entry,
    h: *const Histogram,
) std.Io.Writer.Error!void {
    var cumulative: u64 = 0;
    for (h.bounds, 0..) |bound, index| {
        cumulative += h.counts[index].load(.monotonic);
        var le_buffer: [32]u8 = undefined;
        const le = std.fmt.bufPrint(&le_buffer, "{d}", .{bound}) catch unreachable;
        try write_series(out, entry.name, "_bucket", entry.labels, le);
        try out.print(" {d}\n", .{cumulative});
    }
    const count = h.count.load(.monotonic);
    try write_series(out, entry.name, "_bucket", entry.labels, "+Inf");
    try out.print(" {d}\n", .{count});
    const sum_nano = h.sum_nano.load(.monotonic);
    try write_series(out, entry.name, "_sum", entry.labels, null);
    try out.print(" {d}.{d:0>9}\n", .{ sum_nano / 1_000_000_000, sum_nano % 1_000_000_000 });
    try write_series(out, entry.name, "_count", entry.labels, null);
    try out.print(" {d}\n", .{count});
}

fn write_series(
    out: *std.Io.Writer,
    name: []const u8,
    suffix: []const u8,
    labels: []const Label,
    le: ?[]const u8,
) std.Io.Writer.Error!void {
    try out.print("{s}{s}", .{ name, suffix });
    if (labels.len == 0 and le == null) return;
    try out.writeByte('{');
    for (labels, 0..) |label, index| {
        if (index > 0) try out.writeByte(',');
        try out.print("{s}=\"", .{label.name});
        try write_label_value(out, label.value);
        try out.writeByte('"');
    }
    if (le) |bound| {
        if (labels.len > 0) try out.writeByte(',');
        try out.print("le=\"{s}\"", .{bound});
    }
    try out.writeByte('}');
}

fn write_label_value(out: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    for (value) |byte| switch (byte) {
        '\\' => try out.writeAll("\\\\"),
        '"' => try out.writeAll("\\\""),
        '\n' => try out.writeAll("\\n"),
        else => try out.writeByte(byte),
    };
}

fn write_help(out: *std.Io.Writer, help: []const u8) std.Io.Writer.Error!void {
    for (help) |byte| switch (byte) {
        '\\' => try out.writeAll("\\\\"),
        '\n' => try out.writeAll("\\n"),
        else => try out.writeByte(byte),
    };
}

test "metrics: prometheus exposition" {
    var requests: Counter = .{};
    var peers: Gauge = .{};
    var latency = Histogram.init(&.{ 0.01, 0.1, 1 });
    var errors_a: Counter = .{};
    var errors_b: Counter = .{};
    var registry: Registry(8) = .{};
    try registry.counter("rpc_requests_total", "RPC requests served.", &requests);
    try registry.gauge("p2p_peers", "Connected peers.", &peers);
    try registry.histogram("rpc_latency_seconds", "RPC latency.", &latency);
    try registry.register(.{
        .name = "rpc_errors_total",
        .help = "Errors by method.",
        .labels = &.{.{ .name = "method", .value = "eth_call" }},
        .metric = .{ .counter = &errors_a },
    });
    try registry.register(.{
        .name = "rpc_errors_total",
        .help = "Errors by method.",
        .labels = &.{.{ .name = "method", .value = "say \"hi\"" }},
        .metric = .{ .counter = &errors_b },
    });
    const duplicate = registry.counter("p2p_peers", "", &requests);
    try std.testing.expectError(error.DuplicateMetric, duplicate);
    try std.testing.expectError(error.InvalidName, registry.counter("9bad", "", &requests));

    requests.add(3);
    peers.set(-2);
    latency.observe(0.005);
    latency.observe(0.5);
    latency.observe_ns(2 * std.time.ns_per_s);
    errors_a.increment();

    var buffer: [2048]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try registry.write_prometheus(&out);
    try std.testing.expectEqualStrings(
        \\# HELP rpc_requests_total RPC requests served.
        \\# TYPE rpc_requests_total counter
        \\rpc_requests_total 3
        \\# HELP p2p_peers Connected peers.
        \\# TYPE p2p_peers gauge
        \\p2p_peers -2
        \\# HELP rpc_latency_seconds RPC latency.
        \\# TYPE rpc_latency_seconds histogram
        \\rpc_latency_seconds_bucket{le="0.01"} 1
        \\rpc_latency_seconds_bucket{le="0.1"} 1
        \\rpc_latency_seconds_bucket{le="1"} 2
        \\rpc_latency_seconds_bucket{le="+Inf"} 3
        \\rpc_latency_seconds_sum 2.505000000
        \\rpc_latency_seconds_count 3
        \\# HELP rpc_errors_total Errors by method.
        \\# TYPE rpc_errors_total counter
        \\rpc_errors_total{method="eth_call"} 1
        \\rpc_errors_total{method="say \"hi\""} 0
        \\
    , out.buffered());
}

test "metrics: registry capacity" {
    var counter: Counter = .{};
    var registry: Registry(1) = .{};
    try registry.counter("a", "", &counter);
    try std.testing.expectError(error.RegistryFull, registry.counter("b", "", &counter));
}

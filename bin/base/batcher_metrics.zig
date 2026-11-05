//! `base batcher --metrics.port`: serves `GET /metrics` on the event-loop IO, which the
//! batcher drives while it waits between steps.

const std = @import("std");
const builtin = @import("builtin");
const base = @import("base");

const io = base.utilities.io;
const Metrics = base.batcher.metrics.Metrics;
const Server = base.utilities.http.Server(io.IO, *Metrics, Metrics.handle);

pub const MetricsServer = struct {
    os_io: io.IO,
    server: Server,

    /// Binds 0.0.0.0:`port`. `metrics_server` must not move afterwards.
    pub fn start(
        metrics_server: *MetricsServer,
        allocator: std.mem.Allocator,
        metrics: *Metrics,
        port: u16,
    ) !void {
        const linux = builtin.os.tag == .linux;
        metrics_server.os_io = if (linux) try io.IO.init(.{}) else try io.IO.init();
        errdefer metrics_server.os_io.deinit();
        try metrics_server.server.init(allocator, &metrics_server.os_io, metrics, .{
            .connections_max = 4,
            .recv_buffer_size = 16 * 1024,
            .send_buffer_size = 16 * 1024,
            .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 4 * 1024 },
        });
        errdefer metrics_server.server.deinit();
        _ = try metrics_server.server.listen(io.Address.ip4(.{ 0, 0, 0, 0 }, port));
    }

    /// Serves requests for `duration_ms` (the wait between batcher steps).
    pub fn serve_for(metrics_server: *MetricsServer, duration_ms: u64) !void {
        assert(duration_ms > 0);
        try metrics_server.os_io.run_for_ns(duration_ms * std.time.ns_per_ms);
    }
};

const assert = std.debug.assert;

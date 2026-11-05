//! `base batcher` HTTP endpoints on the event-loop IO, served while the batcher waits
//! between steps: Prometheus `GET /metrics` (`--metrics.port`) and the admin JSON-RPC
//! API (`--admin-port`). Both are optional: a bind failure only disables that endpoint.

const std = @import("std");
const builtin = @import("builtin");
const base = @import("base");

const assert = std.debug.assert;
const io = base.utilities.io;
const http = base.utilities.http;
const Metrics = base.batcher.metrics.Metrics;
const Admin = base.batcher.admin.Admin;
const MetricsServer = http.Server(io.IO, *Metrics, Metrics.handle);
const AdminServer = http.Server(io.IO, *Admin, Admin.handle);

const server_options: http.server.Options = .{
    .connections_max = 4,
    .recv_buffer_size = 16 * 1024,
    .send_buffer_size = 16 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 4 * 1024 },
};

pub const Servers = struct {
    os_io: io.IO,
    metrics: ?MetricsServer = null,
    admin: ?AdminServer = null,

    /// `servers` must not move afterwards.
    pub fn init(servers: *Servers) !void {
        const linux = builtin.os.tag == .linux;
        servers.* = .{ .os_io = if (linux) try io.IO.init(.{}) else try io.IO.init() };
    }

    pub fn serve_metrics(
        servers: *Servers,
        allocator: std.mem.Allocator,
        metrics: *Metrics,
        port: u16,
    ) bool {
        assert(servers.metrics == null);
        servers.metrics = @as(MetricsServer, undefined);
        const server = &servers.metrics.?;
        const address: io.Address = .ip4(.{ 0, 0, 0, 0 }, port);
        start(MetricsServer, server, allocator, &servers.os_io, metrics, address) catch |err| {
            std.debug.print("batcher: metrics disabled, port {d}: {t}\n", .{ port, err });
            servers.metrics = null;
            return false;
        };
        std.debug.print("batcher: metrics on :{d}/metrics\n", .{port});
        return true;
    }

    pub fn serve_admin(
        servers: *Servers,
        allocator: std.mem.Allocator,
        admin: *Admin,
        address: io.Address,
    ) bool {
        assert(servers.admin == null);
        servers.admin = @as(AdminServer, undefined);
        const server = &servers.admin.?;
        start(AdminServer, server, allocator, &servers.os_io, admin, address) catch |err| {
            std.debug.print("batcher: admin API disabled, port {d}: {t}\n", .{ address.port, err });
            servers.admin = null;
            return false;
        };
        std.debug.print("batcher: admin API on port {d}\n", .{address.port});
        return true;
    }

    pub fn active(servers: *const Servers) bool {
        return servers.metrics != null or servers.admin != null;
    }

    /// Serves requests for `duration_ms` (the wait between batcher steps).
    pub fn serve_for(servers: *Servers, duration_ms: u64) !void {
        assert(servers.active());
        assert(duration_ms > 0);
        try servers.os_io.run_for_ns(duration_ms * std.time.ns_per_ms);
    }
};

fn start(
    comptime Server: type,
    server: *Server,
    allocator: std.mem.Allocator,
    os_io: *io.IO,
    context: anytype,
    address: io.Address,
) !void {
    try server.init(allocator, os_io, context, server_options);
    errdefer server.deinit();
    _ = try server.listen(address);
}

//! A small Prometheus endpoint for tools whose main loop is not IO-driven (`load-test`,
//! `withdrawer`, `fee-jobs`): one `utilities/http` server answering `GET /metrics` from a
//! fixed registry, plus `/` and `/healthz` through `utilities/health`.
//!
//! The tool keeps its blocking loop and calls `wait_ns` where it used to sleep: that runs
//! the IO for the same duration, so scrapes are answered while the tool idles and no thread
//! is needed. While the tool is inside a blocking RPC call a scrape waits for the next
//! `wait_ns` (bounded by the tool's RPC timeout).

const std = @import("std");
const assert = std.debug.assert;

const health = @import("../../utilities/health/root.zig");
const http = @import("../../utilities/http/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");

pub const server_options: http.server.Options = .{
    .connections_max = 4,
    .recv_buffer_size = 8 * 1024 + 1024,
    .send_buffer_size = 64 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
};

/// Copies a cumulative count kept elsewhere into a Prometheus counter (never decreasing).
pub fn sync_counter(counter: *metrics.Counter, value: u64) void {
    const current = counter.get();
    assert(value >= current);
    counter.add(value - current);
    assert(counter.get() == value);
}

pub fn Endpoint(comptime IO: type, comptime entries_max: u32) type {
    comptime assert(entries_max > 0);
    return struct {
        const Self = @This();

        pub const Registry = metrics.Registry(entries_max);

        /// The handler context: the registry and the version for `/healthz`.
        pub const Pages = struct {
            registry: Registry = .{},
            version: []const u8,
            scrapes: u64 = 0,

            pub fn handle(
                pages: *Pages,
                request: *const http.Request,
                response: *http.ResponseBuilder,
            ) void {
                if (health.respond(pages.version, request, response)) return;
                if (request.method != .GET and request.method != .HEAD) {
                    return response.fail(405);
                }
                const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse
                    request.target.len;
                if (!std.mem.eql(u8, request.target[0..path_end], "/metrics")) {
                    return response.fail(404);
                }
                pages.scrapes += 1;
                response.content_type = "text/plain; version=0.0.4";
                pages.registry.write_prometheus(response.writer()) catch response.fail(500);
                assert(pages.scrapes > 0);
            }
        };

        const Server = http.Server(IO, *Pages, Pages.handle);

        io: *IO,
        pages: Pages,
        server: Server,
        listening: bool = false,

        /// In place: the server keeps a pointer to `endpoint.pages`. Register metrics in
        /// `endpoint.pages.registry` before the first scrape.
        pub fn init(
            endpoint: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            version: []const u8,
        ) !void {
            assert(version.len > 0);
            endpoint.* = .{ .io = io, .pages = .{ .version = version }, .server = undefined };
            try endpoint.server.init(allocator, io, &endpoint.pages, server_options);
            assert(endpoint.pages.registry.count == 0);
        }

        /// Stops the server, drains its connections, and frees it.
        pub fn deinit(endpoint: *Self) void {
            if (endpoint.listening) {
                endpoint.server.stop();
                var rounds: u32 = 0;
                while (!endpoint.server.stopped() and rounds < 1_000) : (rounds += 1) {
                    endpoint.io.run_for_ns(std.time.ns_per_ms) catch break;
                }
            }
            endpoint.server.deinit();
            endpoint.* = undefined;
        }

        /// Binds and starts accepting. Returns the bound address (port 0 picks one).
        pub fn listen(endpoint: *Self, address: http.server.Address) !http.server.Address {
            assert(!endpoint.listening);
            const bound = try endpoint.server.listen(address);
            endpoint.listening = true;
            assert(bound.port != 0);
            return bound;
        }

        /// Serves requests for `duration_ns` (the tool's sleep).
        pub fn wait_ns(endpoint: *Self, duration_ns: u64) !void {
            assert(endpoint.listening);
            assert(duration_ns > 0);
            endpoint.server.tick();
            try endpoint.io.run_for_ns(duration_ns);
        }
    };
}

test {
    _ = @import("tests.zig");
}

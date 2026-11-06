//! The audit archiver service over the completion-based IO: one `utilities/http` server
//! for Vector ingest, JSON-RPC queries, health, and metrics (base/base serves ingest and
//! RPC on the same port).
//!
//! Endpoints:
//!   POST <ingest path>  NDJSON batch ingest (`ingest.zig`), default
//!                       `/v1/transaction-events/batch`
//!   POST any other path JSON-RPC (`rpc.zig`)
//!   GET  /, /healthz    liveness and version (`utilities/health`)
//!   GET  /readyz        200 while listening
//!   GET  /metrics       Prometheus text
//!
//! Everything is allocated in `init`. The owner replays its journal into `store` before
//! `listen`, and calls `tick()` periodically: it drives server timeouts and evicts expired
//! events from the head of the store.

const std = @import("std");
const assert = std.debug.assert;

const http = @import("../../utilities/http/root.zig");
const health = @import("../../utilities/health/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const io_common = @import("../../utilities/io/common.zig");
const store_module = @import("store.zig");
const ingest_module = @import("ingest.zig");
const rpc_module = @import("rpc.zig");

pub const Address = io_common.Address;

pub const Options = struct {
    store: store_module.Options,
    ingest: ingest_module.Limits = .{},
    ingest_path: []const u8 = ingest_module.default_path,
    server: http.server.Options = .{},
    version: []const u8 = "unknown",
};

const metrics_max = 24;
const prefix = "audit_transaction_events_";
const batch_buckets = [_]f64{ 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 4000 };

pub fn Archiver(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Server = http.Server(IO, *Self, handle);

        io: *IO,
        allocator: std.mem.Allocator,
        options: Options,
        store: store_module.Store,
        ingest: ingest_module.Ingest,
        journal: ?ingest_module.Journal = null,
        server: Server,
        listening: bool = false,
        stopping: bool = false,

        registry: metrics.Registry(metrics_max) = .{},
        received: metrics.Counter = .{},
        persisted: metrics.Counter = .{},
        duplicate: metrics.Counter = .{},
        rejected: metrics.Counter = .{},
        validation_failures: metrics.Counter = .{},
        journal_failures: metrics.Counter = .{},
        expired: metrics.Counter = .{},
        future: metrics.Counter = .{},
        evicted_capacity: metrics.Counter = .{},
        evicted_retention: metrics.Counter = .{},
        rpc_requests: metrics.Counter = .{},
        stored_events: metrics.Gauge = .{},
        stored_bytes: metrics.Gauge = .{},
        capacity_events: metrics.Gauge = .{},
        batch_size: metrics.Histogram = .init(&batch_buckets),

        /// In place: the server and registry keep pointers into `archiver`.
        pub fn init(
            archiver: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            options: Options,
        ) !void {
            assert(options.ingest_path.len > 0 and options.ingest_path[0] == '/');
            assert(options.server.limits.body_size_max >= options.ingest.request_bytes_max);
            const record_max = options.ingest.event.event_bytes_max +
                store_module.record_overhead_bytes;
            assert(options.store.arena_bytes >= record_max);
            archiver.* = .{
                .io = io,
                .allocator = allocator,
                .options = options,
                .store = try store_module.Store.init(allocator, options.store),
                .ingest = undefined,
                .server = undefined,
            };
            errdefer archiver.store.deinit(allocator);
            archiver.ingest = try ingest_module.Ingest.init(allocator, options.ingest);
            errdefer archiver.ingest.deinit(allocator);
            try archiver.server.init(allocator, io, archiver, options.server);
            errdefer archiver.server.deinit();
            try archiver.register_metrics();
        }

        pub fn deinit(archiver: *Self) void {
            assert(archiver.store.slots.len > 0);
            archiver.server.deinit();
            archiver.ingest.deinit(archiver.allocator);
            archiver.store.deinit(archiver.allocator);
            archiver.* = undefined;
        }

        fn register_metrics(archiver: *Self) !void {
            const registry = &archiver.registry;
            const counters = [_]struct { []const u8, []const u8, *metrics.Counter }{
                .{ prefix ++ "received_total", "Events received over HTTP.", &archiver.received },
                .{ prefix ++ "persisted_total", "Events newly stored.", &archiver.persisted },
                .{ prefix ++ "duplicate_total", "Duplicate events skipped.", &archiver.duplicate },
                .{
                    prefix ++ "rejected_total",
                    "Events (and whole batches) rejected before storage.",
                    &archiver.rejected,
                },
                .{
                    prefix ++ "validation_failures_total",
                    "Event validation failures.",
                    &archiver.validation_failures,
                },
                .{
                    prefix ++ "journal_failures_total",
                    "Batches answered 503 because the journal write failed.",
                    &archiver.journal_failures,
                },
            };
            for (counters) |entry| {
                const name, const help, const counter = entry;
                try registry.register(.{
                    .name = name,
                    .help = help,
                    .metric = .{ .counter = counter },
                });
            }
            try archiver.register_labeled();
            try archiver.register_gauges();
            assert(registry.count == 15);
        }

        fn register_labeled(archiver: *Self) !void {
            const registry = &archiver.registry;
            const outside = prefix ++ "outside_retention_window_total";
            const outside_help = "Events rejected because event_time is outside the retention " ++
                "window.";
            try registry.register(labeled(outside, outside_help, "reason", "expired", .{
                .counter = &archiver.expired,
            }));
            try registry.register(labeled(outside, outside_help, "reason", "future", .{
                .counter = &archiver.future,
            }));
            const evicted = prefix ++ "evicted_total";
            const evicted_help = "Stored events evicted.";
            try registry.register(labeled(evicted, evicted_help, "reason", "capacity", .{
                .counter = &archiver.evicted_capacity,
            }));
            try registry.register(labeled(evicted, evicted_help, "reason", "retention", .{
                .counter = &archiver.evicted_retention,
            }));
        }

        fn register_gauges(archiver: *Self) !void {
            const registry = &archiver.registry;
            try registry.counter(
                "audit_rpc_requests_total",
                "JSON-RPC requests.",
                &archiver.rpc_requests,
            );
            try registry.gauge(prefix ++ "stored", "Events in the store.", &archiver.stored_events);
            try registry.gauge(
                prefix ++ "stored_bytes",
                "Arena bytes held by stored events.",
                &archiver.stored_bytes,
            );
            try registry.gauge(
                prefix ++ "capacity",
                "Store capacity in events.",
                &archiver.capacity_events,
            );
            try registry.histogram(
                "audit_transaction_event_batch_size",
                "Events per HTTP ingest batch.",
                &archiver.batch_size,
            );
        }

        fn labeled(
            comptime name: []const u8,
            comptime help: []const u8,
            comptime label: []const u8,
            comptime value: []const u8,
            metric: @FieldType(metrics.Entry, "metric"),
        ) metrics.Entry {
            const labels = [_]metrics.Label{.{ .name = label, .value = value }};
            return .{ .name = name, .help = help, .labels = &labels, .metric = metric };
        }

        pub fn listen(archiver: *Self, address: Address) !Address {
            assert(!archiver.listening);
            const bound = try archiver.server.listen(address);
            archiver.listening = true;
            return bound;
        }

        pub fn stop(archiver: *Self) void {
            assert(!archiver.stopping);
            archiver.stopping = true;
            archiver.listening = false;
            archiver.server.stop();
        }

        pub fn stopped(archiver: *const Self) bool {
            return archiver.server.stopped();
        }

        pub fn tick(archiver: *Self) void {
            archiver.server.tick();
            _ = archiver.store.prune(archiver.io.now_realtime_ns());
        }

        /// HTTP handler for `Server`.
        pub fn handle(
            archiver: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (health.respond(archiver.options.version, request, response)) return;
            const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse
                request.target.len;
            const path = request.target[0..path_end];
            if (request.method == .POST) {
                if (std.mem.eql(u8, path, archiver.options.ingest_path)) {
                    return archiver.handle_ingest(request, response);
                }
                return archiver.handle_rpc(request, response);
            }
            if (request.method != .GET and request.method != .HEAD) return response.fail(405);
            if (std.mem.eql(u8, path, "/readyz")) {
                response.content_type = "text/plain";
                response.status = if (archiver.listening) 200 else 503;
                return;
            }
            if (!std.mem.eql(u8, path, "/metrics")) return response.fail(404);
            archiver.sync_metrics();
            response.content_type = "text/plain; version=0.0.4";
            archiver.registry.write_prometheus(response.writer()) catch response.fail(500);
        }

        fn handle_ingest(
            archiver: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            assert(request.method == .POST);
            if (request.body.len > archiver.options.ingest.request_bytes_max) {
                return response.fail(413);
            }
            const now_ns = archiver.io.now_realtime_ns();
            _ = archiver.store.prune(now_ns);
            const outcome = archiver.ingest.run(
                &archiver.store,
                archiver.journal,
                request.body,
                now_ns,
                response.writer(),
            );
            if (outcome.events > 0) archiver.batch_size.observe(@floatFromInt(outcome.events));
            if (outcome.http_status == 500) return response.fail(500);
            response.status = outcome.http_status;
            response.content_type = "application/json";
        }

        fn handle_rpc(
            archiver: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            assert(request.method == .POST);
            archiver.rpc_requests.increment();
            var context: rpc_module.Context = .{
                .store = &archiver.store,
                .now_ns = archiver.io.now_realtime_ns(),
            };
            const outcome = rpc_module.Router.handle(&context, request.body, response.writer());
            if (outcome == .empty) response.status = 204;
            response.content_type = "application/json";
        }

        /// Copies the ingest and store counters into the metrics (pull model: on scrape).
        fn sync_metrics(archiver: *Self) void {
            const counts = archiver.ingest.counts;
            const stats = archiver.store.stats;
            const pairs = [_]struct { *metrics.Counter, u64 }{
                .{ &archiver.received, counts.received },
                .{ &archiver.persisted, counts.persisted },
                .{ &archiver.duplicate, counts.duplicate },
                .{ &archiver.rejected, counts.rejected },
                .{ &archiver.validation_failures, counts.validation_failures },
                .{ &archiver.journal_failures, counts.journal_failures },
                .{ &archiver.expired, counts.expired },
                .{ &archiver.future, counts.future },
                .{ &archiver.evicted_capacity, stats.evicted_capacity },
                .{ &archiver.evicted_retention, stats.evicted_retention },
            };
            for (pairs) |pair| {
                const counter, const value = pair;
                assert(value >= counter.get());
                counter.add(value - counter.get());
            }
            archiver.stored_events.set(archiver.store.count);
            archiver.stored_bytes.set(@intCast(archiver.store.arena_used));
            archiver.capacity_events.set(archiver.options.store.events_max);
            assert(archiver.store.count <= archiver.options.store.events_max);
        }
    };
}

test {
    _ = @import("archiver_test.zig");
}

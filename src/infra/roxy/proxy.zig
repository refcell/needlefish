//! The roxy JSON-RPC reverse proxy over the completion-based IO.
//!
//! One `utilities/http` server receives requests and defers each JSON-RPC POST into a
//! bounded pending set (full: 503 at once). Each upstream has a fixed pool of HTTP clients,
//! one request in flight per client. A queued request goes to an idle client of the upstream
//! the `Pool` selects; a transport failure or a 5xx response counts against that upstream and
//! is retried on another one (at most `attempts_max` sends, never the same upstream twice).
//! The final upstream response (status and body) resumes the deferred HTTP response; with no
//! upstream left, the client gets 502 and a JSON-RPC error.
//!
//! With a non-empty allowlist every request (and every entry of a batch) is checked before
//! it is queued: a disallowed method gets JSON-RPC error -32601 without touching upstreams.
//!
//! With `rate_limit.requests_per_s > 0`, each client IP (resolved through `trusted_proxy`,
//! so clients behind a trusted load balancer are told apart) has a token bucket; a client
//! over its rate gets 429 and JSON-RPC error -32016 before anything else is checked.
//!
//! Endpoints: `POST` any path (proxied to the same path), `GET /` and `GET /healthz`
//! (`utilities/health`), `GET /readyz` (200 once listening with at least one upstream not
//! ejected), `GET /metrics` (Prometheus text).
//!
//! Everything is allocated in `init`. The owner calls `tick()` every few hundred
//! milliseconds: it drives server and client timeouts and retries requests waiting for a
//! client.

const std = @import("std");
const assert = std.debug.assert;

const http = @import("../../utilities/http/root.zig");
const health = @import("../../utilities/health/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const io_common = @import("../../utilities/io/common.zig");
const pool_module = @import("pool.zig");
const methods = @import("methods.zig");
const Allowlist = @import("allowlist.zig").Allowlist;
const trusted_proxy = @import("../../utilities/trusted_proxy/root.zig");
const rate_limit = @import("rate_limit.zig");

/// Client buckets tracked at once (about 40 bytes each).
pub const rate_limit_buckets_max = 4096;
const Limiter = rate_limit.Limiter(rate_limit_buckets_max);

pub const Address = io_common.Address;
pub const Mask = pool_module.Mask;
pub const upstreams_max = pool_module.upstreams_max;

pub const Options = struct {
    upstreams: []const Address,
    clients_per_upstream: u32 = 4,
    /// Requests queued or in flight; beyond this new requests get 503.
    pending_max: u32 = 256,
    /// Sends per request, the first included; each goes to a different upstream.
    attempts_max: u32 = 3,
    pool: pool_module.Options = .{},
    allowlist: Allowlist = .{},
    rate_limit: rate_limit.Options = .{},
    /// Proxies whose forwarding header is trusted when resolving the client IP.
    trusted_proxy: trusted_proxy.Config = .{},
    server: http.server.Options = .{},
    client: http.client.Options = .{},
    version: []const u8 = "unknown",
};

const label_size_max = 24;
const metrics_max = 9 + 3 * upstreams_max;
const content_type_json = [_]http.parser.Header{
    .{ .name = "Content-Type", .value = "application/json" },
};

pub fn Proxy(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Server = http.Server(IO, *Self, handle);
        const Client = http.Client(IO);

        const SlotState = enum { free, queued, in_flight };

        /// One proxied request. `target` and `body` point into the server's receive buffer
        /// and stay valid while `token` is (see `http.Server.deferred_valid`).
        const Slot = struct {
            state: SlotState = .free,
            token: http.Deferred = undefined,
            target: []const u8 = "",
            body: []const u8 = "",
            tried: Mask = 0,
            attempts: u32 = 0,
        };

        const UpstreamClient = struct {
            proxy: *Self,
            client: Client,
            upstream: u32,
            slot: ?u32 = null,
        };

        io: *IO,
        allocator: std.mem.Allocator,
        options: Options,
        pool: pool_module.Pool,
        server: Server,
        clients: []UpstreamClient,
        slots: []Slot,
        /// FIFO of queued slot indices (ring).
        queue: []u32,
        queue_head: u32 = 0,
        queue_count: u32 = 0,
        /// Stack of free slot indices.
        free: []u32,
        free_count: u32,
        listening: bool = false,
        stopping: bool = false,
        dispatching: bool = false,
        dispatch_again: bool = false,
        /// Scratch for the allowlist check.
        entries: [methods.batch_max]methods.Entry = undefined,
        limiter: ?*Limiter = null,

        registry: metrics.Registry(metrics_max) = .{},
        requests: metrics.Counter = .{},
        retries: metrics.Counter = .{},
        rejected_method: metrics.Counter = .{},
        rejected_invalid: metrics.Counter = .{},
        rejected_overload: metrics.Counter = .{},
        rejected_rate_limit: metrics.Counter = .{},
        unavailable: metrics.Counter = .{},
        pending: metrics.Gauge = .{},
        upstream_failures: [upstreams_max]metrics.Counter = @splat(.{}),
        upstream_ejections: [upstreams_max]metrics.Counter = @splat(.{}),
        upstream_ejected: [upstreams_max]metrics.Gauge = @splat(.{}),
        upstream_label_text: [upstreams_max][label_size_max]u8 = undefined,
        upstream_labels: [upstreams_max][1]metrics.Label = undefined,

        /// In place: the server, clients, and registry keep pointers into `proxy`.
        pub fn init(
            proxy: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            options: Options,
        ) !void {
            const count: u32 = @intCast(options.upstreams.len);
            assert(count > 0 and count <= upstreams_max);
            assert(options.clients_per_upstream > 0 and options.pending_max > 0);
            assert(options.attempts_max > 0);
            proxy.* = .{
                .io = io,
                .allocator = allocator,
                .options = options,
                .pool = .init(count, options.pool),
                .server = undefined,
                .clients = &.{},
                .slots = try allocator.alloc(Slot, options.pending_max),
                .queue = &.{},
                .free = &.{},
                .free_count = 0,
            };
            errdefer allocator.free(proxy.slots);
            proxy.queue = try allocator.alloc(u32, options.pending_max);
            errdefer allocator.free(proxy.queue);
            proxy.free = try allocator.alloc(u32, options.pending_max);
            errdefer allocator.free(proxy.free);
            for (proxy.slots, 0..) |*slot, index| {
                slot.* = .{};
                proxy.free[options.pending_max - 1 - index] = @intCast(index);
            }
            proxy.free_count = options.pending_max;
            if (options.rate_limit.enabled()) {
                const limiter = try allocator.create(Limiter);
                limiter.* = Limiter.init(options.rate_limit);
                proxy.limiter = limiter;
            }
            errdefer if (proxy.limiter) |limiter| allocator.destroy(limiter);
            try proxy.init_clients(count);
            errdefer proxy.deinit_clients();
            try proxy.server.init(allocator, io, proxy, options.server);
            errdefer proxy.server.deinit();
            try proxy.register_metrics(count);
        }

        fn init_clients(proxy: *Self, count: u32) !void {
            const per = proxy.options.clients_per_upstream;
            proxy.clients = try proxy.allocator.alloc(UpstreamClient, count * per);
            var initialized: u32 = 0;
            errdefer {
                for (proxy.clients[0..initialized]) |*entry| entry.client.deinit();
                proxy.allocator.free(proxy.clients);
            }
            for (proxy.clients, 0..) |*entry, index| {
                const upstream: u32 = @intCast(index / per);
                entry.* = .{
                    .proxy = proxy,
                    .upstream = upstream,
                    .client = try Client.init(
                        proxy.allocator,
                        proxy.io,
                        proxy.options.upstreams[upstream],
                        proxy.options.client,
                    ),
                };
                initialized += 1;
            }
            assert(initialized == count * per);
        }

        fn deinit_clients(proxy: *Self) void {
            for (proxy.clients) |*entry| entry.client.deinit();
            proxy.allocator.free(proxy.clients);
        }

        /// Frees everything. Call `stop()` and run the IO until `stopped()` first.
        pub fn deinit(proxy: *Self) void {
            assert(proxy.slots.len > 0);
            proxy.server.deinit();
            proxy.deinit_clients();
            if (proxy.limiter) |limiter| proxy.allocator.destroy(limiter);
            proxy.allocator.free(proxy.free);
            proxy.allocator.free(proxy.queue);
            proxy.allocator.free(proxy.slots);
            proxy.* = undefined;
        }

        fn register_metrics(proxy: *Self, count: u32) !void {
            const registry = &proxy.registry;
            try registry.counter(
                "roxy_requests_total",
                "Requests accepted for proxying.",
                &proxy.requests,
            );
            try registry.counter(
                "roxy_retries_total",
                "Requests retried on another upstream.",
                &proxy.retries,
            );
            try registry.register(rejected_entry("method", &proxy.rejected_method));
            try registry.register(rejected_entry("invalid", &proxy.rejected_invalid));
            try registry.register(rejected_entry("overload", &proxy.rejected_overload));
            try registry.register(rejected_entry("rate_limit", &proxy.rejected_rate_limit));
            try registry.counter(
                "roxy_unavailable_total",
                "Requests answered 502 because every attempt failed.",
                &proxy.unavailable,
            );
            try registry.gauge("roxy_pending", "Requests queued or in flight.", &proxy.pending);
            for (0..count) |index| try proxy.register_upstream(@intCast(index));
            assert(registry.count == 8 + 3 * count);
        }

        fn rejected_entry(comptime reason: []const u8, counter: *metrics.Counter) metrics.Entry {
            const labels = [_]metrics.Label{.{ .name = "reason", .value = reason }};
            return .{
                .name = "roxy_rejected_total",
                .help = "Requests answered by the proxy without an upstream.",
                .labels = &labels,
                .metric = .{ .counter = counter },
            };
        }

        fn register_upstream(proxy: *Self, index: u32) !void {
            assert(index < proxy.pool.count);
            const text = std.fmt.bufPrint(
                &proxy.upstream_label_text[index],
                "{f}",
                .{proxy.options.upstreams[index]},
            ) catch unreachable; // An IPv4 address and port fit in `label_size_max`.
            proxy.upstream_labels[index] = .{.{ .name = "upstream", .value = text }};
            const labels: []const metrics.Label = &proxy.upstream_labels[index];
            try proxy.registry.register(.{
                .name = "roxy_upstream_failures_total",
                .help = "Failed attempts (transport error or 5xx).",
                .labels = labels,
                .metric = .{ .counter = &proxy.upstream_failures[index] },
            });
            try proxy.registry.register(.{
                .name = "roxy_upstream_ejections_total",
                .help = "Times the upstream was ejected.",
                .labels = labels,
                .metric = .{ .counter = &proxy.upstream_ejections[index] },
            });
            try proxy.registry.register(.{
                .name = "roxy_upstream_ejected",
                .help = "1 while the upstream is ejected.",
                .labels = labels,
                .metric = .{ .gauge = &proxy.upstream_ejected[index] },
            });
        }

        pub fn listen(proxy: *Self, address: Address) !Address {
            assert(!proxy.listening);
            const bound = try proxy.server.listen(address);
            proxy.listening = true;
            return bound;
        }

        /// Stops accepting; deferred requests are answered 503. Run the IO until `stopped()`.
        pub fn stop(proxy: *Self) void {
            assert(!proxy.stopping);
            proxy.stopping = true;
            proxy.listening = false;
            proxy.server.stop();
            proxy.dispatch(); // Frees the queued requests the server just abandoned.
        }

        pub fn stopped(proxy: *const Self) bool {
            if (!proxy.server.stopped()) return false;
            for (proxy.clients) |*entry| if (entry.client.busy()) return false;
            return true;
        }

        /// Drives timeouts and dispatches requests waiting for a client. Call periodically.
        pub fn tick(proxy: *Self) void {
            proxy.server.tick();
            for (proxy.clients) |*entry| entry.client.tick();
            proxy.dispatch();
        }

        /// Listening with at least one upstream not ejected.
        pub fn ready(proxy: *const Self) bool {
            if (!proxy.listening) return false;
            return proxy.pool.any_admitted(proxy.io.now_monotonic_ns());
        }

        /// HTTP handler for `Server`.
        pub fn handle(
            proxy: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (health.respond(proxy.options.version, request, response)) return;
            if (request.method == .POST) return proxy.handle_rpc(request, response);
            if (request.method != .GET and request.method != .HEAD) return response.fail(405);
            const path_end = std.mem.indexOfScalar(u8, request.target, '?') orelse
                request.target.len;
            const path = request.target[0..path_end];
            if (std.mem.eql(u8, path, "/readyz")) {
                response.content_type = "text/plain";
                response.status = if (proxy.ready()) 200 else 503;
                return;
            }
            if (!std.mem.eql(u8, path, "/metrics")) return response.fail(404);
            proxy.sync_metrics();
            response.content_type = "text/plain; version=0.0.4";
            proxy.registry.write_prometheus(response.writer()) catch response.fail(500);
        }

        fn handle_rpc(
            proxy: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            assert(request.method == .POST);
            if (proxy.over_rate_limit(request, response)) return;
            if (!proxy.options.allowlist.allows_all()) {
                if (proxy.reject_disallowed(request.body, response)) return;
            }
            if (proxy.free_count == 0) {
                proxy.rejected_overload.increment();
                return response.fail(503);
            }
            proxy.free_count -= 1;
            const index = proxy.free[proxy.free_count];
            const slot = &proxy.slots[index];
            assert(slot.state == .free);
            slot.* = .{
                .state = .queued,
                .token = response.defer_response(),
                .target = request.target,
                .body = request.body,
            };
            proxy.requests.increment();
            proxy.queue_push(index);
            proxy.dispatch();
        }

        /// Answers 429 when the request's client is over its rate; returns true if it did.
        fn over_rate_limit(
            proxy: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) bool {
            const limiter = proxy.limiter orelse return false;
            const headers = request.headers.slice();
            const client = proxy.options.trusted_proxy.client_ip(response.peer, headers);
            const now_ms = proxy.io.now_monotonic_ns() / std.time.ns_per_ms;
            if (limiter.allow(client, now_ms)) return false;
            proxy.rejected_rate_limit.increment();
            response.status = 429;
            response.writer().writeAll(rate_limit.over_limit_body) catch response.fail(500);
            return true;
        }

        /// Answers a request that is invalid or calls a disallowed method; returns true if it
        /// did. In a batch with a disallowed method every entry gets an error.
        fn reject_disallowed(
            proxy: *Self,
            body: []const u8,
            response: *http.ResponseBuilder,
        ) bool {
            const out = response.writer();
            const summary = methods.extract(body, &proxy.entries) catch |err| {
                proxy.rejected_invalid.increment();
                const code, const message = switch (err) {
                    error.ParseError => .{ rpc.code.parse_error, "parse error" },
                    error.InvalidRequest => .{ rpc.code.invalid_request, "invalid request" },
                    error.BatchTooLarge => .{ rpc.code.invalid_request, "batch too large" },
                };
                methods.write_error(out, "null", code, message) catch response.fail(500);
                return true;
            };
            const entries = proxy.entries[0..summary.count];
            var disallowed: u32 = 0;
            for (entries) |*entry| disallowed += @intFromBool(!proxy.allowed(entry));
            if (disallowed == 0) return false;
            proxy.rejected_method.increment();
            write_rejection(proxy, out, summary.batch, entries) catch response.fail(500);
            return true;
        }

        fn allowed(proxy: *const Self, entry: *const methods.Entry) bool {
            const name = entry.name() orelse return false;
            return proxy.options.allowlist.allows(name);
        }

        fn write_rejection(
            proxy: *const Self,
            out: *std.Io.Writer,
            batch: bool,
            entries: []const methods.Entry,
        ) std.Io.Writer.Error!void {
            assert(entries.len > 0);
            assert(batch or entries.len == 1);
            const code = rpc.code.method_not_found;
            if (!batch) return methods.write_error(out, entries[0].id, code, "method not allowed");
            try out.writeByte('[');
            for (entries, 0..) |*entry, index| {
                if (index > 0) try out.writeByte(',');
                const message = if (proxy.allowed(entry))
                    "batch rejected: another entry's method is not allowed"
                else
                    "method not allowed";
                try methods.write_error(out, entry.id, code, message);
            }
            try out.writeByte(']');
        }

        fn queue_push(proxy: *Self, index: u32) void {
            assert(proxy.queue_count < proxy.queue.len);
            assert(proxy.slots[index].state == .queued);
            const length: u32 = @intCast(proxy.queue.len);
            proxy.queue[(proxy.queue_head + proxy.queue_count) % length] = index;
            proxy.queue_count += 1;
        }

        fn queue_pop(proxy: *Self) u32 {
            assert(proxy.queue_count > 0);
            const index = proxy.queue[proxy.queue_head];
            proxy.queue_head = (proxy.queue_head + 1) % @as(u32, @intCast(proxy.queue.len));
            proxy.queue_count -= 1;
            assert(proxy.slots[index].state == .queued);
            return index;
        }

        fn slot_free(proxy: *Self, index: u32) void {
            const slot = &proxy.slots[index];
            assert(slot.state != .free);
            assert(proxy.free_count < proxy.free.len);
            slot.* = .{};
            proxy.free[proxy.free_count] = index;
            proxy.free_count += 1;
        }

        /// Sends every queued request that can go now. Re-entrant calls (a client that
        /// fails synchronously inside `request`) are folded into another round.
        fn dispatch(proxy: *Self) void {
            if (proxy.dispatching) {
                proxy.dispatch_again = true;
                return;
            }
            proxy.dispatching = true;
            defer proxy.dispatching = false;
            // Each extra round follows a synchronous completion, which consumes an attempt.
            const rounds_max = proxy.slots.len * proxy.options.attempts_max + 1;
            var rounds: usize = 0;
            while (rounds < rounds_max) : (rounds += 1) {
                proxy.dispatch_again = false;
                proxy.dispatch_round();
                if (!proxy.dispatch_again) break;
            }
            assert(proxy.queue_count <= proxy.queue.len);
        }

        fn dispatch_round(proxy: *Self) void {
            const queued = proxy.queue_count;
            var visited: u32 = 0;
            while (visited < queued and proxy.queue_count > 0) : (visited += 1) {
                const index = proxy.queue_pop();
                if (!proxy.dispatch_slot(index)) proxy.queue_push(index);
            }
        }

        /// Returns false if the request must keep waiting for a client.
        fn dispatch_slot(proxy: *Self, index: u32) bool {
            const slot = &proxy.slots[index];
            assert(slot.state == .queued);
            if (!proxy.server.deferred_valid(slot.token)) {
                proxy.slot_free(index); // Timed out or stopped: the server answered it.
                return true;
            }
            const now_ns = proxy.io.now_monotonic_ns();
            switch (proxy.pool.select(now_ns, slot.tried, proxy.busy_mask())) {
                .wait => return false,
                .exhausted => proxy.answer_unavailable(index),
                .upstream => |upstream| proxy.send(index, upstream),
            }
            return true;
        }

        /// Upstreams with no idle client.
        fn busy_mask(proxy: *const Self) Mask {
            const per = proxy.options.clients_per_upstream;
            var busy: Mask = 0;
            for (0..proxy.pool.count) |upstream| {
                const clients = proxy.clients[upstream * per ..][0..per];
                const idle = for (clients) |*entry| {
                    if (entry.slot == null) break true;
                } else false;
                if (!idle) busy |= pool_module.bit(@intCast(upstream));
            }
            return busy;
        }

        fn idle_client(proxy: *Self, upstream: u32) *UpstreamClient {
            const per = proxy.options.clients_per_upstream;
            for (proxy.clients[upstream * per ..][0..per]) |*entry| {
                assert(entry.upstream == upstream);
                if (entry.slot == null) return entry;
            }
            unreachable; // `select` only picks upstreams outside `busy_mask`.
        }

        fn send(proxy: *Self, index: u32, upstream: u32) void {
            const slot = &proxy.slots[index];
            assert(slot.state == .queued);
            assert(slot.tried & pool_module.bit(upstream) == 0);
            const entry = proxy.idle_client(upstream);
            assert(!entry.client.busy());
            slot.state = .in_flight;
            slot.tried |= pool_module.bit(upstream);
            slot.attempts += 1;
            entry.slot = index;
            entry.client.request(
                *UpstreamClient,
                entry,
                on_upstream_response,
                .POST,
                slot.target,
                &content_type_json,
                slot.body,
            ) catch |err| {
                assert(err == error.RequestTooLarge); // The client was idle.
                entry.slot = null;
                proxy.answer_status(index, 413);
            };
        }

        fn on_upstream_response(
            entry: *UpstreamClient,
            client: *Client,
            result: http.client.Error!*const http.Response,
        ) void {
            const proxy = entry.proxy;
            assert(client == &entry.client);
            const index = entry.slot.?;
            entry.slot = null;
            const slot = &proxy.slots[index];
            assert(slot.state == .in_flight);
            const now_ns = proxy.io.now_monotonic_ns();
            const failed = if (result) |response| response.status >= 500 else |_| true;
            if (failed) {
                proxy.upstream_failures[entry.upstream].increment();
                _ = proxy.pool.record_failure(entry.upstream, now_ns);
            } else {
                proxy.pool.record_success(entry.upstream);
            }
            if (!proxy.server.deferred_valid(slot.token)) {
                proxy.slot_free(index);
            } else if (failed and proxy.retry_possible(slot)) {
                proxy.retries.increment();
                slot.state = .queued;
                proxy.queue_push(index);
            } else if (result) |response| {
                proxy.answer_upstream(index, response);
            } else |_| {
                proxy.answer_unavailable(index);
            }
            proxy.dispatch();
        }

        fn retry_possible(proxy: *const Self, slot: *const Slot) bool {
            assert(slot.attempts > 0);
            if (slot.attempts >= proxy.options.attempts_max) return false;
            if (proxy.stopping) return false;
            return pool_module.mask_all(proxy.pool.count) & ~slot.tried != 0;
        }

        fn answer_upstream(proxy: *Self, index: u32, response: *const http.Response) void {
            const slot = &proxy.slots[index];
            assert(slot.state == .in_flight);
            const resumed = proxy.server.resume_deferred(slot.token, response, write_upstream);
            assert(resumed); // Checked by the caller; nothing ran in between.
            proxy.slot_free(index);
        }

        fn write_upstream(response: *const http.Response, builder: *http.ResponseBuilder) void {
            builder.status = response.status;
            const out = builder.writer();
            // Asking for the capacity up front moves a large body into a large send buffer.
            out.ensureUnusedCapacity(response.body.len + 1) catch return builder.fail(502);
            out.writeAll(response.body) catch return builder.fail(502);
            assert(out.end == response.body.len);
        }

        fn answer_unavailable(proxy: *Self, index: u32) void {
            proxy.unavailable.increment();
            proxy.answer_status(index, 502);
        }

        /// Answers with `status` and a JSON-RPC error.
        fn answer_status(proxy: *Self, index: u32, status: u16) void {
            const slot = &proxy.slots[index];
            assert(slot.state != .free);
            assert(status >= 400);
            _ = proxy.server.resume_deferred(slot.token, status, write_status);
            proxy.slot_free(index);
        }

        fn write_status(status: u16, builder: *http.ResponseBuilder) void {
            builder.status = status;
            const message = if (status == 413) "request too large" else "no upstream available";
            const code = rpc.code.internal_error;
            methods.write_error(builder.writer(), "null", code, message) catch builder.fail(500);
        }

        /// Copies pool state into the metrics (pull model: only on scrape).
        fn sync_metrics(proxy: *Self) void {
            const now_ns = proxy.io.now_monotonic_ns();
            for (0..proxy.pool.count) |index| {
                const upstream = &proxy.pool.upstreams[index];
                sync_counter(&proxy.upstream_ejections[index], upstream.ejections_total);
                const ejected = proxy.pool.ejected(@intCast(index), now_ns);
                proxy.upstream_ejected[index].set(@intFromBool(ejected));
            }
            const pending = proxy.slots.len - proxy.free_count;
            proxy.pending.set(@intCast(pending));
        }

        fn sync_counter(counter: *metrics.Counter, value: u64) void {
            const current = counter.get();
            assert(value >= current);
            counter.add(value - current);
            assert(counter.get() == value);
        }
    };
}

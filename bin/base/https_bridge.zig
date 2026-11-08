//! `base https-bridge`: plain HTTP on loopback, forwarded to HTTPS upstreams.
//!
//! The consensus node's L1 JSON-RPC and beacon clients speak plain HTTP over the injected
//! `utilities.io` (so the simulator can replace them) and have no TLS. Public L1 endpoints
//! are HTTPS only, so this binary-only bridge sits between them: each `--routes` entry
//! `PORT=URL` serves `127.0.0.1:PORT` and forwards every request (method, path and query,
//! body, `Content-Type` and `Accept`) to `URL ++ path` with `std.http.Client`, then answers
//! with the upstream status, body, and `Content-Type`. Every other request header (`Host`,
//! `Connection`, `Authorization`, cookies, ...) is dropped.
//!
//! Bounds: `--connections-max` workers per route, each owning one connection at a time and
//! fixed buffers sized by `--request-size-max` and `--response-size-max` (a keep-alive
//! client pins its worker until it closes; further connections wait in the kernel backlog).
//! Each request has a total deadline (`--timeout-ms`) covering every attempt and backoff.
//! Transport failures, timeouts, and 429/502/503/504 answers are retried up to `--retries`
//! times with exponential backoff, for idempotent methods and for POST: the bridge assumes
//! POST bodies are JSON-RPC reads (all a verifier sends); a resent `eth_sendRawTransaction`
//! is rejected by its nonce. Upstream redirects are returned, not followed. Listening is
//! loopback only: the bridge adds no authentication.

const std = @import("std");
const base = @import("base");

const Io = std.Io;
const http = std.http;
const cli = base.utilities.cli;
const assert = std.debug.assert;

const env_prefix = "BASE_HTTPS_BRIDGE_";

pub const routes_max = 8;
pub const upstream_size_max = 256;
pub const target_size_max = 8 * 1024;
pub const header_value_size_max = 256;
/// Connection read buffer: holds the request head (`std.http.Server` needs it whole).
const head_size_max = 16 * 1024;
const write_buffer_size = 64 * 1024;
const backoff_ms_initial: u64 = 250;
const backoff_ms_max: u64 = 4_000;
const requests_per_connection_max: u32 = 1 << 20;

pub const Spec = struct {
    routes: []const u8,
    connections_max: u32 = 8,
    request_size_max: u32 = 1024 * 1024,
    response_size_max: u32 = 64 * 1024 * 1024,
    timeout_ms: u32 = 25_000,
    retries: u32 = 4,
    verbose: bool = false,

    pub const help = .{
        .routes = "Comma-separated PORT=URL: serve 127.0.0.1:PORT, forward to URL (https://host)",
        .connections_max = "Concurrent client connections per route",
        .request_size_max = "Largest request body in bytes (larger: 413)",
        .response_size_max = "Largest upstream response body in bytes (larger: 502)",
        .timeout_ms = "Deadline of one request, all attempts and backoff included (then 504)",
        .retries = "Retries after a transport error, timeout, or 429/502/503/504",
        .verbose = "Log every request (failures and retries are always logged)",
    };
};

pub const Route = struct {
    port: u16,
    /// `http(s)://host[:port][/path]`, no trailing slash; a slice of the arguments.
    upstream: []const u8,
};

pub const Settings = struct {
    routes: [routes_max]Route = undefined,
    route_count: u32 = 0,
    connections_max: u32,
    request_size_max: u32,
    response_size_max: u32,
    timeout_ms: u32,
    retries: u32,
    verbose: bool,

    pub fn route_list(settings: *const Settings) []const Route {
        return settings.routes[0..settings.route_count];
    }
};

pub fn settings_of(spec: Spec) !Settings {
    const valid = spec.connections_max > 0 and spec.connections_max <= 64 and
        spec.request_size_max > 0 and spec.request_size_max <= 64 * 1024 * 1024 and
        spec.response_size_max >= 64 * 1024 and spec.response_size_max <= 1024 * 1024 * 1024 and
        spec.timeout_ms >= 100 and spec.timeout_ms <= 600_000 and spec.retries <= 16;
    if (!valid) return error.InvalidValue;
    var settings: Settings = .{
        .connections_max = spec.connections_max,
        .request_size_max = spec.request_size_max,
        .response_size_max = spec.response_size_max,
        .timeout_ms = spec.timeout_ms,
        .retries = spec.retries,
        .verbose = spec.verbose,
    };
    var parts = std.mem.splitScalar(u8, spec.routes, ',');
    while (parts.next()) |part| {
        const text = std.mem.trim(u8, part, " ");
        if (text.len == 0) continue;
        if (settings.route_count == routes_max) return error.TooManyRoutes;
        const route = try parse_route(text);
        for (settings.route_list()) |other| {
            if (other.port == route.port) return error.DuplicatePort;
        }
        settings.routes[settings.route_count] = route;
        settings.route_count += 1;
    }
    if (settings.route_count == 0) return error.NoRoutes;
    assert(settings.route_count <= routes_max);
    return settings;
}

/// Parses `PORT=URL`.
pub fn parse_route(text: []const u8) !Route {
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidRoute;
    const port = std.fmt.parseInt(u16, text[0..equals], 10) catch return error.InvalidRoute;
    if (port == 0) return error.InvalidRoute;
    var upstream = text[equals + 1 ..];
    const scheme_end = if (std.mem.startsWith(u8, upstream, "https://"))
        "https://".len
    else if (std.mem.startsWith(u8, upstream, "http://"))
        "http://".len
    else
        return error.UnsupportedUrl;
    while (upstream.len > scheme_end and upstream[upstream.len - 1] == '/') {
        upstream = upstream[0 .. upstream.len - 1];
    }
    if (upstream.len == scheme_end or upstream.len > upstream_size_max) return error.InvalidUrl;
    for (upstream) |byte| {
        if (byte <= ' ' or byte >= 0x7f or byte == '?' or byte == '#') return error.InvalidUrl;
    }
    _ = std.Uri.parse(upstream) catch return error.InvalidUrl;
    assert(upstream.len > scheme_end);
    return .{ .port = port, .upstream = upstream };
}

/// `upstream ++ target` into `buffer`. `target` must be origin-form (`/path?query`) of
/// visible ASCII: absolute-form targets would let a client pick another host.
pub fn upstream_url(buffer: []u8, upstream: []const u8, target: []const u8) ![]const u8 {
    assert(upstream.len > 0);
    if (target.len == 0 or target[0] != '/') return error.InvalidTarget;
    if (target.len > target_size_max) return error.InvalidTarget;
    for (target) |byte| {
        if (byte <= ' ' or byte >= 0x7f or byte == '#') return error.InvalidTarget;
    }
    if (upstream.len + target.len > buffer.len) return error.InvalidTarget;
    @memcpy(buffer[0..upstream.len], upstream);
    @memcpy(buffer[upstream.len..][0..target.len], target);
    const url = buffer[0 .. upstream.len + target.len];
    assert(std.mem.startsWith(u8, url, upstream));
    return url;
}

pub const ForwardedHeader = enum { content_type, accept };

/// The request headers the upstream sees. Everything else is dropped: `Host` and the
/// connection headers belong to this hop, and credentials or cookies never leave loopback.
pub fn forwarded_header(name: []const u8) ?ForwardedHeader {
    if (std.ascii.eqlIgnoreCase(name, "content-type")) return .content_type;
    if (std.ascii.eqlIgnoreCase(name, "accept")) return .accept;
    return null;
}

/// A bounded copy of one header value.
pub const Value = struct {
    bytes: [header_value_size_max]u8 = undefined,
    len: u16 = 0,
    present: bool = false,

    pub fn get(value: *const Value) ?[]const u8 {
        assert(value.len <= header_value_size_max);
        return if (value.present) value.bytes[0..value.len] else null;
    }

    fn set(value: *Value, text: []const u8) !void {
        if (text.len > header_value_size_max) return error.HeaderTooLarge;
        @memcpy(value.bytes[0..text.len], text);
        value.len = @intCast(text.len);
        value.present = true;
    }
};

pub const Headers = struct {
    content_type: Value = .{},
    accept: Value = .{},
};

/// Copies the forwarded headers of a request head; the first of a repeated header wins.
pub fn copy_headers(iterator: *http.HeaderIterator, headers: *Headers) !void {
    headers.* = .{};
    var count: u32 = 0;
    while (iterator.next()) |header| : (count += 1) {
        if (count >= 256) return error.TooManyHeaders;
        const kind = forwarded_header(header.name) orelse continue;
        const value = switch (kind) {
            .content_type => &headers.content_type,
            .accept => &headers.accept,
        };
        if (!value.present) try value.set(header.value);
    }
    assert(count <= 256);
}

/// The outcome of one upstream attempt.
pub const Fetched = union(enum) {
    /// The response body is in the worker's response buffer.
    answered: struct { status: http.Status, length: u32 },
    failed,
    timed_out,
    too_large,
};

/// Whether another attempt may fix `fetched`. POST counts as retryable: see the file doc.
pub fn retryable(method: http.Method, fetched: Fetched) bool {
    if (!method.idempotent() and method != .POST) return false;
    return switch (fetched) {
        .failed, .timed_out => true,
        .too_large => false,
        .answered => |answer| switch (@backingInt(answer.status)) {
            429, 502, 503, 504 => true,
            else => false,
        },
    };
}

/// Backoff before retry `attempt` (1-based): 250 ms doubling, at most 4 s.
pub fn backoff_ms(attempt: u32) u64 {
    assert(attempt > 0);
    const shift: u6 = @intCast(@min(attempt - 1, 16));
    const wait_ms = @min(backoff_ms_initial << shift, backoff_ms_max);
    assert(wait_ms >= backoff_ms_initial and wait_ms <= backoff_ms_max);
    return wait_ms;
}

/// The status a bridge-side failure answers with.
pub fn failure_status(fetched: Fetched) http.Status {
    assert(fetched != .answered);
    return switch (fetched) {
        .answered => unreachable,
        .failed, .too_large => .bad_gateway,
        .timed_out => .gateway_timeout,
    };
}

fn failure_body(fetched: Fetched) []const u8 {
    return switch (fetched) {
        .answered => unreachable,
        .failed => "https-bridge: upstream unreachable\n",
        .timed_out => "https-bridge: upstream timed out\n",
        .too_large => "https-bridge: upstream response exceeds --response-size-max\n",
    };
}

/// A request as forwarded upstream.
const Exchange = struct {
    method: http.Method,
    url: []const u8,
    body: []const u8,
    headers: *const Headers,
};

/// Large buffers come straight from the page allocator, uninitialized: the kernel backs
/// pages only when a response touches them, so idle workers cost almost nothing.
fn alloc_lazy(len: usize) ![]u8 {
    assert(len > 0);
    const page = std.heap.page_allocator;
    const pointer = page.rawAlloc(len, .@"1", @returnAddress()) orelse return error.OutOfMemory;
    return pointer[0..len];
}

fn free_lazy(buffer: []u8) void {
    std.heap.page_allocator.rawFree(buffer, .@"1", @returnAddress());
}

pub const Worker = struct {
    io: Io,
    allocator: std.mem.Allocator,
    route: Route,
    settings: *const Settings,
    client: std.http.Client,
    connection_read: []u8,
    connection_write: []u8,
    request_body: []u8,
    response_body: []u8,
    decompress: []u8,
    url: [upstream_size_max + target_size_max]u8 = undefined,
    target: [target_size_max]u8 = undefined,
    headers: Headers = .{},
    response_content_type: Value = .{},

    pub fn init(
        worker: *Worker,
        allocator: std.mem.Allocator,
        io: Io,
        route: Route,
        settings: *const Settings,
    ) !void {
        assert(settings.request_size_max > 0 and settings.response_size_max > 0);
        const connection_read = try allocator.alloc(u8, head_size_max);
        errdefer allocator.free(connection_read);
        const connection_write = try allocator.alloc(u8, write_buffer_size);
        errdefer allocator.free(connection_write);
        const decompress = try allocator.alloc(u8, std.compress.flate.max_window_len);
        errdefer allocator.free(decompress);
        const request_body = try alloc_lazy(settings.request_size_max);
        errdefer free_lazy(request_body);
        const response_body = try alloc_lazy(settings.response_size_max);
        worker.* = .{
            .io = io,
            .allocator = allocator,
            .route = route,
            .settings = settings,
            .client = .{ .allocator = allocator, .io = io },
            .connection_read = connection_read,
            .connection_write = connection_write,
            .request_body = request_body,
            .response_body = response_body,
            .decompress = decompress,
        };
    }

    pub fn deinit(worker: *Worker) void {
        worker.client.deinit();
        free_lazy(worker.response_body);
        free_lazy(worker.request_body);
        worker.allocator.free(worker.decompress);
        worker.allocator.free(worker.connection_write);
        worker.allocator.free(worker.connection_read);
        worker.* = undefined;
    }

    /// Accepts and serves connections until cancelled.
    pub fn run(worker: *Worker, server: *Io.net.Server) void {
        // A server runs until the process stops; each pass serves one bounded connection.
        while (true) {
            const stream = server.accept(worker.io) catch |err| {
                if (err == error.Canceled) return;
                std.debug.print("https-bridge: :{d} accept failed: {t}\n", .{
                    worker.route.port,
                    err,
                });
                worker.io.sleep(.fromMilliseconds(100), .awake) catch return;
                continue;
            };
            worker.serve_connection(stream);
        }
    }

    /// Serves requests on one connection until the client closes it or an exchange fails.
    pub fn serve_connection(worker: *Worker, stream: Io.net.Stream) void {
        defer stream.close(worker.io);
        var reader = stream.reader(worker.io, worker.connection_read);
        var writer = stream.writer(worker.io, worker.connection_write);
        var server = http.Server.init(&reader.interface, &writer.interface);
        var served: u32 = 0;
        while (served < requests_per_connection_max) : (served += 1) {
            var request = server.receiveHead() catch |err| {
                if (err != error.HttpConnectionClosing) {
                    std.debug.print("https-bridge: :{d} bad request: {t}\n", .{
                        worker.route.port,
                        err,
                    });
                }
                return;
            };
            if (!worker.serve_request(&request)) return;
        }
        assert(served == requests_per_connection_max);
    }

    /// Forwards one request and answers it; false when the connection must close.
    fn serve_request(worker: *Worker, request: *http.Server.Request) bool {
        const start_ms = worker.now_ms();
        const method = request.head.method;
        const target_length = request.head.target.len;
        const local: ?http.Status = worker.copy_head(request);
        if (local) |status| {
            const keep_alive = status != .payload_too_large;
            const shown = request.head.target[0..@min(target_length, 64)];
            worker.log(method, shown, @backingInt(status));
            request.respond("", .{ .status = status, .keep_alive = keep_alive }) catch return false;
            return keep_alive;
        }
        const target = worker.target[0..target_length];
        const body = worker.read_body(request) catch |err| {
            if (err == error.ConnectionFailed) return false;
            request.respond("", .{ .status = .payload_too_large, .keep_alive = false }) catch {};
            return false;
        };
        const url = upstream_url(&worker.url, worker.route.upstream, target) catch unreachable;
        const exchange: Exchange = .{
            .method = method,
            .url = url,
            .body = body,
            .headers = &worker.headers,
        };
        const result = worker.forward(&exchange);
        const elapsed_ms: u64 = @intCast(@max(worker.now_ms() - start_ms, 0));
        switch (result.fetched) {
            .answered => |answer| {
                const content_type = worker.response_content_type.get();
                const extra = [_]http.Header{
                    .{ .name = "content-type", .value = content_type orelse "" },
                };
                request.respond(worker.response_body[0..answer.length], .{
                    .status = answer.status,
                    .extra_headers = if (content_type != null) &extra else &.{},
                }) catch return false;
                const code = @backingInt(answer.status);
                if (worker.settings.verbose or code != 200 or result.attempts > 1) {
                    const attempts = result.attempts;
                    worker.log_exchange(&exchange, code, answer.length, elapsed_ms, attempts);
                }
            },
            else => |fetched| {
                const status = failure_status(fetched);
                request.respond(failure_body(fetched), .{ .status = status }) catch return false;
                worker.log_exchange(&exchange, @backingInt(status), 0, elapsed_ms, result.attempts);
            },
        }
        return true;
    }

    /// Copies the target and forwarded headers out of the head (reading the body may
    /// overwrite it); a status when the request is answered locally instead.
    fn copy_head(worker: *Worker, request: *http.Server.Request) ?http.Status {
        const target = request.head.target;
        if (target.len > target_size_max) return .uri_too_long;
        @memcpy(worker.target[0..target.len], target);
        _ = upstream_url(&worker.url, worker.route.upstream, target) catch return .bad_request;
        var iterator = request.iterateHeaders();
        copy_headers(&iterator, &worker.headers) catch return .request_header_fields_too_large;
        if (request.head.content_length) |length| {
            if (length > worker.settings.request_size_max) return .payload_too_large;
        }
        assert(target.len <= target_size_max);
        return null;
    }

    fn read_body(worker: *Worker, request: *http.Server.Request) ![]const u8 {
        if (!request.head.method.requestHasBody()) return "";
        var transfer: [64]u8 = undefined;
        const reader = request.readerExpectContinue(&transfer) catch return error.ConnectionFailed;
        var writer: Io.Writer = .fixed(worker.request_body);
        _ = reader.streamRemaining(&writer) catch |err| switch (err) {
            error.WriteFailed => return error.RequestTooLarge,
            error.ReadFailed => return error.ConnectionFailed,
        };
        const body = writer.buffered();
        assert(body.len <= worker.settings.request_size_max);
        return body;
    }

    const Forwarded = struct { fetched: Fetched, attempts: u32 };

    /// Up to `retries + 1` attempts within one `timeout_ms` deadline.
    fn forward(worker: *Worker, exchange: *const Exchange) Forwarded {
        const settings = worker.settings;
        const deadline_ms = worker.now_ms() + settings.timeout_ms;
        var fetched: Fetched = .timed_out;
        var attempt: u32 = 0;
        while (attempt <= settings.retries) : (attempt += 1) {
            if (attempt > 0) {
                const wait_ms: i64 = @intCast(backoff_ms(attempt));
                if (worker.now_ms() + wait_ms >= deadline_ms) break;
                worker.io.sleep(.fromMilliseconds(wait_ms), .awake) catch break;
            }
            const remaining_ms = deadline_ms - worker.now_ms();
            if (remaining_ms <= 0) break;
            fetched = worker.fetch_timed(exchange, @intCast(remaining_ms));
            if (!retryable(exchange.method, fetched)) {
                return .{ .fetched = fetched, .attempts = attempt + 1 };
            }
            if (worker.settings.verbose) {
                std.debug.print("https-bridge: :{d} attempt {d}: {s}\n", .{
                    worker.route.port,
                    attempt + 1,
                    @tagName(fetched),
                });
            }
        }
        assert(attempt <= settings.retries + 1);
        return .{ .fetched = fetched, .attempts = @max(attempt, 1) };
    }

    const Outcome = union(enum) { fetched: Fetched, timed_out: Io.Cancelable!void };

    /// `fetch` raced against the timeout (as `http_transport.zig`); a late fetch is cancelled
    /// and the client replaced so the cancelled connection is never reused.
    fn fetch_timed(worker: *Worker, exchange: *const Exchange, timeout_ms: u64) Fetched {
        assert(timeout_ms > 0);
        var buffer: [2]Outcome = undefined;
        var select = Io.Select(Outcome).init(worker.io, &buffer);
        select.concurrent(.fetched, fetch, .{ worker, exchange }) catch
            return fetch(worker, exchange); // No concurrency: no timeout.
        const duration: Io.Clock.Duration = .{
            .raw = .fromMilliseconds(@intCast(timeout_ms)),
            .clock = .awake,
        };
        select.concurrent(.timed_out, sleep, .{ worker.io, duration }) catch {
            const outcome = select.await() catch unreachable; // Proof: only the fetch runs.
            return outcome.fetched;
        };
        const first = select.await() catch {
            select.cancelDiscard();
            return .failed;
        };
        select.cancelDiscard(); // Waits for the loser, so the buffers are free again.
        switch (first) {
            .fetched => |fetched| return fetched,
            .timed_out => {
                worker.client.deinit();
                worker.client = .{ .allocator = worker.allocator, .io = worker.io };
                return .timed_out;
            },
        }
    }

    fn sleep(io: Io, duration: Io.Clock.Duration) Io.Cancelable!void {
        return duration.sleep(io);
    }

    fn fetch(worker: *Worker, exchange: *const Exchange) Fetched {
        const uri = std.Uri.parse(exchange.url) catch |err| return worker.failed(err);
        const headers = exchange.headers;
        var extra: [1]http.Header = undefined;
        var extra_count: usize = 0;
        if (headers.accept.get()) |accept| {
            extra[0] = .{ .name = "accept", .value = accept };
            extra_count = 1;
        }
        const content_type: http.Client.Request.Headers.Value =
            if (headers.content_type.get()) |value| .{ .override = value } else .omit;
        var request = worker.client.request(exchange.method, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{ .content_type = content_type },
            .extra_headers = extra[0..extra_count],
        }) catch |err| return worker.failed(err);
        defer request.deinit();
        if (exchange.method.requestHasBody()) {
            request.transfer_encoding = .{ .content_length = exchange.body.len };
            var body = request.sendBodyUnflushed(&.{}) catch |err| return worker.failed(err);
            body.writer.writeAll(exchange.body) catch |err| return worker.failed(err);
            body.end() catch |err| return worker.failed(err);
            request.connection.?.flush() catch |err| return worker.failed(err);
        } else {
            request.sendBodiless() catch |err| return worker.failed(err);
        }
        var response = request.receiveHead(&.{}) catch |err| return worker.failed(err);
        worker.response_content_type = .{};
        if (response.head.content_type) |value| {
            worker.response_content_type.set(value) catch {}; // Too long: sent without one.
        }
        const decompress: []u8 = switch (response.head.content_encoding) {
            .identity => &.{},
            .deflate, .gzip => worker.decompress,
            // Never offered in `Accept-Encoding`.
            .zstd, .compress => return worker.failed(error.UnsupportedCompressionMethod),
        };
        var transfer: [64]u8 = undefined;
        var decompressor: http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer, &decompressor, decompress);
        var writer: Io.Writer = .fixed(worker.response_body);
        _ = reader.streamRemaining(&writer) catch |err| switch (err) {
            error.WriteFailed => return .too_large,
            error.ReadFailed => return worker.failed(response.bodyErr() orelse err),
        };
        const length: u32 = @intCast(writer.buffered().len);
        assert(length <= worker.settings.response_size_max);
        return .{ .answered = .{ .status = response.head.status, .length = length } };
    }

    /// Logs a transport failure (always: they explain retries and 502s).
    fn failed(worker: *const Worker, err: anyerror) Fetched {
        std.debug.print("https-bridge: :{d} upstream transport error: {t}\n", .{
            worker.route.port,
            err,
        });
        return .failed;
    }

    fn now_ms(worker: *const Worker) i64 {
        return Io.Clock.awake.now(worker.io).toMilliseconds();
    }

    fn log(worker: *const Worker, method: http.Method, target: []const u8, code: u16) void {
        std.debug.print("https-bridge: :{d} {t} {s} -> {d} (answered locally)\n", .{
            worker.route.port, method, target, code,
        });
    }

    fn log_exchange(
        worker: *const Worker,
        exchange: *const Exchange,
        code: u16,
        length: u32,
        elapsed_ms: u64,
        attempts: u32,
    ) void {
        const target = exchange.url[worker.route.upstream.len..];
        std.debug.print("https-bridge: :{d} {t} {s} -> {d}, {d} bytes, {d} ms, {d} attempts\n", .{
            worker.route.port,
            exchange.method,
            target[0..@min(target.len, 120)],
            code,
            length,
            elapsed_ms,
            attempts,
        });
    }
};

fn print_help() void {
    var buffer: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base https-bridge --routes PORT=URL[,PORT=URL...]\n{s}", .{
        writer.buffered(),
    });
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args, env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("https-bridge: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    const settings = settings_of(spec) catch |err| {
        std.debug.print("https-bridge: invalid flags: {t}\n", .{err});
        return 2;
    };
    var servers: [routes_max]Io.net.Server = undefined;
    var listening: u32 = 0;
    defer for (servers[0..listening]) |*server| server.deinit(init.io);
    for (settings.route_list()) |route| {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(route.port) };
        servers[listening] = try address.listen(init.io, .{ .reuse_address = true });
        listening += 1;
        std.debug.print("https-bridge: 127.0.0.1:{d} -> {s}\n", .{ route.port, route.upstream });
    }
    assert(listening == settings.route_count);
    const workers = try init.gpa.alloc(Worker, settings.route_count * settings.connections_max);
    defer init.gpa.free(workers);
    var ready: usize = 0;
    defer for (workers[0..ready]) |*worker| worker.deinit();
    for (workers, 0..) |*worker, index| {
        const route = settings.routes[index / settings.connections_max];
        try worker.init(init.gpa, init.io, route, &settings);
        ready += 1;
    }
    var group: Io.Group = .init;
    defer group.cancel(init.io);
    for (workers, 0..) |*worker, index| {
        const server = &servers[index / settings.connections_max];
        group.concurrent(init.io, Worker.run, .{ worker, server }) catch {
            std.debug.print("https-bridge: needs a concurrent Io\n", .{});
            return 1;
        };
    }
    group.await(init.io) catch {};
    return 0;
}

const testing = std.testing;

test "https bridge: routes" {
    const settings = try settings_of(.{
        .routes = "18545=https://ethereum-sepolia-rpc.publicnode.com/, " ++
            "15052=https://ethereum-sepolia-beacon-api.publicnode.com",
    });
    try testing.expectEqual(@as(u32, 2), settings.route_count);
    try testing.expectEqual(@as(u16, 18545), settings.routes[0].port);
    try testing.expectEqualStrings(
        "https://ethereum-sepolia-rpc.publicnode.com",
        settings.routes[0].upstream,
    );
    try testing.expectEqual(@as(u16, 15052), settings.routes[1].port);
    try testing.expectError(error.NoRoutes, settings_of(.{ .routes = " , " }));
    const duplicate = "1=https://a.example,1=https://b.example";
    try testing.expectError(error.DuplicatePort, settings_of(.{ .routes = duplicate }));
    const small = Spec{ .routes = "1=https://a.example", .response_size_max = 1024 };
    try testing.expectError(error.InvalidValue, settings_of(small));
    try testing.expectError(error.UnsupportedUrl, parse_route("1=ftp://a.example"));
    try testing.expectError(error.InvalidRoute, parse_route("0=https://a.example"));
    try testing.expectError(error.InvalidRoute, parse_route("https://a.example"));
    try testing.expectError(error.InvalidUrl, parse_route("1=https://"));
    try testing.expectError(error.InvalidUrl, parse_route("1=https://a.example?x=1"));
    const with_path = try parse_route("8=http://127.0.0.1:9/v1//");
    try testing.expectEqualStrings("http://127.0.0.1:9/v1", with_path.upstream);
}

test "https bridge: upstream url" {
    var buffer: [upstream_size_max + target_size_max]u8 = undefined;
    const upstream = "https://beacon.example";
    const target = "/eth/v1/beacon/blobs/5?versioned_hashes=0x01,0x02";
    const url = try upstream_url(&buffer, upstream, target);
    try testing.expectEqualStrings(upstream ++ target, url);
    try testing.expectEqualStrings(upstream ++ "/", try upstream_url(&buffer, upstream, "/"));
    const absolute = "http://evil.example/";
    try testing.expectError(error.InvalidTarget, upstream_url(&buffer, upstream, absolute));
    try testing.expectError(error.InvalidTarget, upstream_url(&buffer, upstream, ""));
    try testing.expectError(error.InvalidTarget, upstream_url(&buffer, upstream, "/a b"));
    try testing.expectError(error.InvalidTarget, upstream_url(&buffer, upstream, "/a#b"));
    var long: [target_size_max + 1]u8 = @splat('a');
    long[0] = '/';
    try testing.expectError(error.InvalidTarget, upstream_url(&buffer, upstream, &long));
    var small: [24]u8 = undefined;
    try testing.expectError(error.InvalidTarget, upstream_url(&small, upstream, "/abc"));
}

test "https bridge: only content-type and accept are forwarded" {
    const head = "POST / HTTP/1.1\r\n" ++
        "Host: 127.0.0.1:18545\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Authorization: Bearer secret\r\n" ++
        "Connection: keep-alive\r\n" ++
        "ACCEPT: application/json\r\n" ++
        "accept: text/plain\r\n" ++
        "Cookie: a=b\r\n" ++
        "Content-Length: 2\r\n\r\n";
    var iterator = http.HeaderIterator.init(head);
    var headers: Headers = .{};
    try copy_headers(&iterator, &headers);
    try testing.expectEqualStrings("application/json", headers.content_type.get().?);
    try testing.expectEqualStrings("application/json", headers.accept.get().?);
    const dropped = [_][]const u8{
        "host", "Authorization", "connection", "cookie", "content-length",
    };
    for (dropped) |name| {
        try testing.expect(forwarded_header(name) == null);
    }
    try testing.expectEqual(ForwardedHeader.accept, forwarded_header("Accept").?);
    var bare = http.HeaderIterator.init("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try copy_headers(&bare, &headers);
    try testing.expect(headers.content_type.get() == null and headers.accept.get() == null);
    const long_value: [header_value_size_max + 1]u8 = @splat('a');
    const oversized = "GET / HTTP/1.1\r\nAccept: " ++ long_value ++ "\r\n\r\n";
    var too_long = http.HeaderIterator.init(oversized);
    try testing.expectError(error.HeaderTooLarge, copy_headers(&too_long, &headers));
}

test "https bridge: retry rules" {
    const limited: Fetched = .{ .answered = .{ .status = .too_many_requests, .length = 0 } };
    const missing: Fetched = .{ .answered = .{ .status = .not_found, .length = 0 } };
    const unavailable: Fetched = .{ .answered = .{ .status = .service_unavailable, .length = 0 } };
    try testing.expect(retryable(.POST, limited));
    try testing.expect(retryable(.GET, limited));
    try testing.expect(retryable(.GET, unavailable));
    try testing.expect(retryable(.GET, .failed));
    try testing.expect(retryable(.POST, .timed_out));
    try testing.expect(!retryable(.GET, missing));
    try testing.expect(!retryable(.GET, .too_large));
    try testing.expect(!retryable(.PATCH, limited));
    try testing.expectEqual(@as(u64, 250), backoff_ms(1));
    try testing.expectEqual(@as(u64, 500), backoff_ms(2));
    try testing.expectEqual(@as(u64, 4_000), backoff_ms(16));
    try testing.expectEqual(http.Status.gateway_timeout, failure_status(.timed_out));
    try testing.expectEqual(http.Status.bad_gateway, failure_status(.too_large));
}

/// Test upstream: answers each scripted status in turn on one keep-alive connection and
/// records the last request's `Host` and `Authorization` presence.
const FakeUpstream = struct {
    server: Io.net.Server,
    statuses: []const http.Status,
    body: []const u8,
    host: [64]u8 = undefined,
    host_len: usize = 0,
    saw_authorization: bool = false,
    served: u32 = 0,

    fn serve(fake: *FakeUpstream, io: Io) !void {
        var stream = try fake.server.accept(io);
        defer stream.close(io);
        var read_buffer: [4096]u8 = undefined;
        var write_buffer: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buffer);
        var writer = stream.writer(io, &write_buffer);
        var server = http.Server.init(&reader.interface, &writer.interface);
        for (fake.statuses) |status| {
            var request = try server.receiveHead();
            var iterator = request.iterateHeaders();
            while (iterator.next()) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "host")) {
                    fake.host_len = @min(header.value.len, fake.host.len);
                    @memcpy(fake.host[0..fake.host_len], header.value[0..fake.host_len]);
                }
                if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
                    fake.saw_authorization = true;
                }
            }
            const extra = [_]http.Header{.{ .name = "content-type", .value = "application/json" }};
            try request.respond(fake.body, .{ .status = status, .extra_headers = &extra });
            fake.served += 1;
        }
    }
};

fn test_settings(port: u16, buffer: []u8, response_size_max: u32) !Settings {
    const routes = try std.fmt.bufPrint(buffer, "1=http://127.0.0.1:{d}", .{port});
    return settings_of(.{
        .routes = routes,
        .response_size_max = response_size_max,
        .timeout_ms = 10_000,
        .retries = 2,
    });
}

fn forward_once(worker: *Worker, method: http.Method, body: []const u8) Worker.Forwarded {
    const url = upstream_url(&worker.url, worker.route.upstream, "/eth/v1/x?y=1") catch
        unreachable; // Proof: a short valid target fits the buffer.
    var headers: Headers = .{};
    headers.accept.set("application/json") catch unreachable; // Proof: short value.
    const exchange: Exchange = .{ .method = method, .url = url, .body = body, .headers = &headers };
    return worker.forward(&exchange);
}

test "https bridge: a 429 is retried, then the answer forwarded" {
    const io = testing.io;
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var fake: FakeUpstream = .{
        .server = try address.listen(io, .{ .reuse_address = true }),
        .statuses = &.{ .too_many_requests, .ok },
        .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}",
    };
    defer fake.server.deinit(io);
    var routes: [64]u8 = undefined;
    const port = fake.server.socket.address.getPort();
    const settings = try test_settings(port, &routes, 64 * 1024);
    var worker: Worker = undefined;
    try worker.init(testing.allocator, io, settings.routes[0], &settings);
    defer worker.deinit();
    var task = try io.concurrent(FakeUpstream.serve, .{ &fake, io });
    const result = forward_once(&worker, .POST, "{}");
    try task.await(io);
    try testing.expectEqual(@as(u32, 2), result.attempts);
    try testing.expectEqual(@as(u32, 2), fake.served);
    const answer = result.fetched.answered;
    try testing.expectEqual(http.Status.ok, answer.status);
    try testing.expectEqualStrings(fake.body, worker.response_body[0..answer.length]);
    try testing.expectEqualStrings("application/json", worker.response_content_type.get().?);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{port});
    try testing.expectEqualStrings(host, fake.host[0..fake.host_len]);
    try testing.expect(!fake.saw_authorization);
}

test "https bridge: a response over the limit is not forwarded" {
    const io = testing.io;
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const large: [64 * 1024 + 1]u8 = @splat('x');
    var fake: FakeUpstream = .{
        .server = try address.listen(io, .{ .reuse_address = true }),
        .statuses = &.{.ok},
        .body = &large,
    };
    defer fake.server.deinit(io);
    var routes: [64]u8 = undefined;
    const settings = try test_settings(fake.server.socket.address.getPort(), &routes, 64 * 1024);
    var worker: Worker = undefined;
    try worker.init(testing.allocator, io, settings.routes[0], &settings);
    defer worker.deinit();
    var task = try io.concurrent(FakeUpstream.serve, .{ &fake, io });
    const result = forward_once(&worker, .GET, "");
    task.await(io) catch {}; // The worker may close before reading the whole body.
    try testing.expectEqual(Fetched.too_large, result.fetched);
    try testing.expectEqual(@as(u32, 1), result.attempts);
}

/// Checks the parsers' invariants on arbitrary bytes: a route always names an http(s)
/// upstream without a trailing slash, a forwarded URL always starts with its upstream and
/// never carries control bytes, and a kept header value fits its bound.
fn check_parsers(bytes: []const u8) !void {
    if (parse_route(bytes)) |route| {
        try testing.expect(route.port > 0 and route.upstream.len <= upstream_size_max);
        try testing.expect(route.upstream[route.upstream.len - 1] != '/');
        try testing.expect(std.mem.startsWith(u8, route.upstream, "http"));
    } else |_| {}
    var buffer: [upstream_size_max + target_size_max]u8 = undefined;
    if (upstream_url(&buffer, "https://a.example", bytes)) |url| {
        try testing.expect(std.mem.startsWith(u8, url, "https://a.example/"));
        for (url) |byte| try testing.expect(byte > ' ' and byte < 0x7f);
    } else |_| {}
    // The server only hands out heads it parsed, ending in an empty line.
    const prefix = "GET / HTTP/1.1\r\n";
    var head: [prefix.len + 512 + 4]u8 = undefined;
    if (bytes.len > 512) return;
    // Proof: `head` holds the prefix, at most 512 bytes, and the terminator.
    const text = std.fmt.bufPrint(&head, "{s}{s}\r\n\r\n", .{ prefix, bytes }) catch unreachable;
    _ = http.Server.Request.Head.parse(text) catch return;
    var iterator = http.HeaderIterator.init(text);
    var headers: Headers = .{};
    copy_headers(&iterator, &headers) catch return;
    if (headers.accept.get()) |value| try testing.expect(value.len <= header_value_size_max);
}

fn fuzz_parsers(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    const length = smith.slice(&bytes);
    try check_parsers(bytes[0..length]);
}

test "https bridge: fuzz parsers" {
    try testing.fuzz({}, fuzz_parsers, .{});
}

test "https bridge: seeded fuzz parsers" {
    var prng = base.testing.Prng.init(0xb41d6e);
    const alphabet = "0123456789=:/.?#hpst \r\nACEPTacept-";
    var bytes: [256]u8 = undefined;
    for (0..2_000) |_| {
        const length: usize = @intCast(prng.below(bytes.len + 1));
        for (bytes[0..length]) |*byte| {
            byte.* = if (prng.chance(1, 8))
                @truncate(prng.int(u8))
            else
                alphabet[@intCast(prng.below(alphabet.len))];
        }
        if (length > 0 and prng.chance(1, 2)) bytes[0] = '/';
        try check_parsers(bytes[0..length]);
    }
}

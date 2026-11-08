//! `base derive-check` network glue: one HTTP(S) endpoint with fixed request and response
//! buffers, pacing between requests, a per-request timeout, and bounded retries with
//! exponential backoff (rate limits answer 429). JSON-RPC single and batch calls on top.
//!
//! Binary-only: library code sees providers built on this, never sockets.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const rpc_client = base.utilities.rpc.client;
const object = base.consensus.sources.json_object;
const assert = std.debug.assert;

/// Attempts per HTTP exchange before the endpoint gives up on it.
pub const retries_max = 8;
/// Attempts of a JSON-RPC call whose response does not parse or carries an error.
const call_attempts_max = 3;
const backoff_ms_max: u64 = 32_000;
/// Calls per batch: public endpoints count every element against their rate limit.
pub const batch_max = 20;

pub const Error = error{ EndpointFailed, NotFound, ResponseTooLarge, RequestTooLarge } ||
    Io.Cancelable;

pub const Stats = struct {
    requests: u64 = 0,
    /// 429 answers.
    limited: u64 = 0,
    /// Transport errors, timeouts, and other non-200 answers.
    failures: u64 = 0,
    timeouts: u64 = 0,
    bytes: u64 = 0,
    /// Responses that did not parse or carried a JSON-RPC error.
    invalid: u64 = 0,
};

pub const Endpoint = struct {
    name: []const u8,
    url: []const u8,
    client: std.http.Client,
    allocator: std.mem.Allocator,
    io: Io,
    request: []u8,
    url_buffer: []u8,
    response: []u8,
    /// Spacing per item (call or GET) between request starts: a batch of n calls waits n
    /// intervals before the next request.
    item_interval_ms: u32,
    timeout_ms: u32 = 60_000,
    next_ms: i64 = 0,
    verbose: bool = false,
    stats: Stats = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        name: []const u8,
        url: []const u8,
        response_bytes: usize,
        item_interval_ms: u32,
    ) !Endpoint {
        assert(response_bytes >= 4096);
        assert(std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://"));
        const request = try allocator.alloc(u8, 64 * 1024);
        errdefer allocator.free(request);
        const url_buffer = try allocator.alloc(u8, 8 * 1024);
        errdefer allocator.free(url_buffer);
        const response = try allocator.alloc(u8, response_bytes);
        return .{
            .name = name,
            .url = url,
            .client = .{ .allocator = allocator, .io = io },
            .allocator = allocator,
            .io = io,
            .request = request,
            .url_buffer = url_buffer,
            .response = response,
            .item_interval_ms = item_interval_ms,
        };
    }

    pub fn deinit(endpoint: *Endpoint) void {
        endpoint.client.deinit();
        endpoint.allocator.free(endpoint.response);
        endpoint.allocator.free(endpoint.url_buffer);
        endpoint.allocator.free(endpoint.request);
        endpoint.* = undefined;
    }

    /// GET `url ++ path`; returns the body, valid until the next request.
    pub fn get(endpoint: *Endpoint, path: []const u8) Error![]const u8 {
        const url = std.fmt.bufPrint(endpoint.url_buffer, "{s}{s}", .{ endpoint.url, path }) catch
            return error.RequestTooLarge;
        return endpoint.exchange(.GET, url, null, 1);
    }

    /// POST `body` to `url`; returns the response body, valid until the next request.
    pub fn post(endpoint: *Endpoint, body: []const u8, items: u32) Error![]const u8 {
        assert(body.len > 0);
        assert(items > 0);
        return endpoint.exchange(.POST, endpoint.url, body, items);
    }

    fn now_ms(endpoint: *const Endpoint) i64 {
        return Io.Clock.awake.now(endpoint.io).toMilliseconds();
    }

    fn pace(endpoint: *Endpoint, items: u32) Io.Cancelable!void {
        assert(items > 0);
        const now = endpoint.now_ms();
        if (endpoint.next_ms > now) {
            try endpoint.io.sleep(.fromMilliseconds(endpoint.next_ms - now), .awake);
        }
        const spacing: i64 = @as(i64, items) * endpoint.item_interval_ms;
        endpoint.next_ms = @max(now, endpoint.next_ms) + spacing;
        assert(endpoint.next_ms >= now);
    }

    /// Waits before retrying a rejected response (rate-limit errors inside a 200 answer).
    fn backoff(endpoint: *Endpoint, attempt: u32) Io.Cancelable!void {
        const wait_ms = @min(@as(u64, 2000) << @intCast(attempt), backoff_ms_max);
        try endpoint.io.sleep(.fromMilliseconds(@intCast(wait_ms)), .awake);
    }

    fn exchange(
        endpoint: *Endpoint,
        method: std.http.Method,
        url: []const u8,
        payload: ?[]const u8,
        items: u32,
    ) Error![]const u8 {
        var attempt: u32 = 0;
        while (attempt < retries_max) : (attempt += 1) {
            if (attempt > 0) {
                const wait_ms = @min(@as(u64, 1000) << @intCast(attempt - 1), backoff_ms_max);
                try endpoint.io.sleep(.fromMilliseconds(@intCast(wait_ms)), .awake);
            }
            try endpoint.pace(items);
            endpoint.stats.requests += 1;
            switch (endpoint.fetch_timed(method, url, payload)) {
                .body => |length| {
                    endpoint.stats.bytes += length;
                    return endpoint.response[0..length];
                },
                .status => |code| {
                    if (code == 404) return error.NotFound;
                    if (code == 429) endpoint.stats.limited += 1 else endpoint.stats.failures += 1;
                    if (endpoint.verbose or attempt >= 2) {
                        std.debug.print("  {s}: http {d}, retry {d}\n", .{
                            endpoint.name,
                            code,
                            attempt + 1,
                        });
                    }
                },
                .failed => {
                    endpoint.stats.failures += 1;
                    if (endpoint.verbose or attempt >= 2) {
                        std.debug.print("  {s}: transport failure, retry {d}\n", .{
                            endpoint.name,
                            attempt + 1,
                        });
                    }
                },
                .too_large => return error.ResponseTooLarge,
            }
        }
        return error.EndpointFailed;
    }

    const Fetched = union(enum) { body: usize, status: u16, failed, too_large };
    const Outcome = union(enum) { fetched: Fetched, timed_out: Io.Cancelable!void };

    /// `fetch` raced against the timeout (as `http_transport.zig`); a late fetch is cancelled
    /// and the client replaced so the cancelled connection is never reused.
    fn fetch_timed(
        endpoint: *Endpoint,
        method: std.http.Method,
        url: []const u8,
        payload: ?[]const u8,
    ) Fetched {
        var buffer: [2]Outcome = undefined;
        var select = Io.Select(Outcome).init(endpoint.io, &buffer);
        select.concurrent(.fetched, fetch, .{ endpoint, method, url, payload }) catch
            return fetch(endpoint, method, url, payload); // No concurrency: no timeout.
        const duration: Io.Clock.Duration = .{
            .raw = .fromMilliseconds(endpoint.timeout_ms),
            .clock = .awake,
        };
        select.concurrent(.timed_out, sleep, .{ endpoint.io, duration }) catch {
            const outcome = select.await() catch unreachable; // Proof: only the fetch runs.
            return outcome.fetched;
        };
        const first = select.await() catch {
            select.cancelDiscard();
            return .failed;
        };
        select.cancelDiscard(); // Waits for the loser, so `response` is free again.
        switch (first) {
            .fetched => |fetched| return fetched,
            .timed_out => {
                endpoint.stats.timeouts += 1;
                endpoint.client.deinit();
                endpoint.client = .{ .allocator = endpoint.allocator, .io = endpoint.io };
                return .failed;
            },
        }
    }

    fn sleep(io: Io, duration: Io.Clock.Duration) Io.Cancelable!void {
        return duration.sleep(io);
    }

    fn fetch(
        endpoint: *Endpoint,
        method: std.http.Method,
        url: []const u8,
        payload: ?[]const u8,
    ) Fetched {
        var writer: Io.Writer = .fixed(endpoint.response);
        const content_type: std.http.Client.Request.Headers.Value = if (payload != null)
            .{ .override = "application/json" }
        else
            .default;
        const result = endpoint.client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = payload,
            .headers = .{ .content_type = content_type },
            .response_writer = &writer,
        }) catch |err| switch (err) {
            error.WriteFailed => return .too_large,
            else => return .failed,
        };
        if (result.status != .ok) return .{ .status = @backingInt(result.status) };
        return .{ .body = writer.buffered().len };
    }

    /// One JSON-RPC call; returns the raw `result`, or null for a JSON `null` result.
    /// `params` is a JSON array literal.
    pub fn call(endpoint: *Endpoint, method: []const u8, params: []const u8) Error!?[]const u8 {
        assert(params.len >= 2 and params[0] == '[');
        var attempt: u32 = 0;
        while (attempt < call_attempts_max) : (attempt += 1) {
            const body = std.fmt.bufPrint(
                endpoint.request,
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}",
                .{ method, params },
            ) catch return error.RequestTooLarge;
            const text = try endpoint.post(body, 1);
            const result = rpc_client.parse_response(text, 1) catch {
                endpoint.note_invalid(text);
                try endpoint.backoff(attempt);
                continue;
            };
            switch (result) {
                .ok => |raw| return if (std.mem.eql(u8, raw, "null")) null else raw,
                .rpc_error => {
                    endpoint.note_invalid(text);
                    try endpoint.backoff(attempt);
                },
            }
        }
        return error.EndpointFailed;
    }

    fn note_invalid(endpoint: *Endpoint, text: []const u8) void {
        endpoint.stats.invalid += 1;
        const tail = text[text.len -| 80..];
        std.debug.print("  {s}: bad response ({d} bytes): {s} ... {s}\n", .{
            endpoint.name,
            text.len,
            text[0..@min(text.len, 120)],
            tail,
        });
    }

    /// A batch of calls of one method; `results[i]` is the raw result of `params[i]` (null
    /// for a JSON `null`), valid until the next request.
    pub fn call_batch(
        endpoint: *Endpoint,
        method: []const u8,
        params: []const []const u8,
        results: []?[]const u8,
    ) Error!void {
        assert(params.len == results.len);
        assert(params.len > 0 and params.len <= batch_max);
        var attempt: u32 = 0;
        while (attempt < call_attempts_max) : (attempt += 1) {
            const body = try endpoint.batch_body(method, params);
            const text = try endpoint.post(body, @intCast(params.len));
            if (parse_batch(text, results)) return;
            endpoint.note_invalid(text);
            try endpoint.backoff(attempt);
        }
        return error.EndpointFailed;
    }

    fn batch_body(endpoint: *Endpoint, method: []const u8, params: []const []const u8) Error![]u8 {
        var writer: Io.Writer = .fixed(endpoint.request);
        writer.writeByte('[') catch return error.RequestTooLarge;
        for (params, 0..) |param, index| {
            if (index > 0) writer.writeByte(',') catch return error.RequestTooLarge;
            writer.print(
                "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}",
                .{ index, method, param },
            ) catch return error.RequestTooLarge;
        }
        writer.writeByte(']') catch return error.RequestTooLarge;
        return writer.buffered();
    }
};

/// Fills `results` from a batch response; false when it is malformed, incomplete, or holds
/// an error.
fn parse_batch(text: []const u8, results: []?[]const u8) bool {
    var filled: [batch_max]bool = @splat(false);
    var iterator = object.ArrayIterator.init(text) catch return false;
    var count: u32 = 0;
    while (iterator.next() catch return false) |element| : (count += 1) {
        if (count >= results.len) return false;
        const response = rpc_client.parse_response_any(element.raw) catch return false;
        if (response.id >= results.len or filled[response.id]) return false;
        const raw = switch (response.result) {
            .ok => |raw| raw,
            .rpc_error => return false,
        };
        results[response.id] = if (std.mem.eql(u8, raw, "null")) null else raw;
        filled[response.id] = true;
    }
    assert(count <= results.len);
    return count == results.len;
}

test "derive check net: batch responses in any order" {
    const text =
        \\[{"jsonrpc":"2.0","id":1,"result":{"a":1}},{"jsonrpc":"2.0","id":0,"result":null}]
    ;
    var results: [2]?[]const u8 = undefined;
    try std.testing.expect(parse_batch(text, &results));
    try std.testing.expectEqual(@as(?[]const u8, null), results[0]);
    try std.testing.expectEqualStrings("{\"a\":1}", results[1].?);
    try std.testing.expect(!parse_batch("[{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":1}]", &results));
    const failed =
        \\[{"jsonrpc":"2.0","id":0,"result":1},{"jsonrpc":"2.0","id":1,"error":{"code":-1}}]
    ;
    try std.testing.expect(!parse_batch(failed, &results));
    try std.testing.expect(!parse_batch("{\"code\":429}", &results));
}

//! roxy over SimIo: three fake upstreams (utilities/rpc Router behind utilities/http), the
//! proxy, and a test client. Covers retry and ejection with re-admission, the allowlist,
//! and the pending-limit 503.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const roxy = @import("root.zig");
const trusted_proxy = @import("../../utilities/trusted_proxy/root.zig");

const Address = io.Address;
const SimIo = io.SimIo;
const ms = std.time.ns_per_ms;
const upstream_count = 3;

const FakeUpstream = struct {
    const Mode = enum { ok, status_500, hang };

    index: u8,
    mode: Mode = .ok,
    calls: u32 = 0,

    fn chain_id(upstream: *FakeUpstream, call: *rpc.Call) rpc.HandlerError!void {
        try call.params.finish();
        try call.writer.quantity(@as(u64, 10 + upstream.index));
    }

    fn send_raw(upstream: *FakeUpstream, call: *rpc.Call) rpc.HandlerError!void {
        _ = upstream;
        _ = try call.params.string();
        try call.params.finish();
        try call.writer.string("0x00");
    }

    const methods = [_]rpc.Method(*FakeUpstream){
        .{ .name = "eth_chainId", .handler = chain_id },
        .{ .name = "eth_sendRawTransaction", .handler = send_raw },
    };
    const Router = rpc.Router(*FakeUpstream, &methods);

    fn handle(
        upstream: *FakeUpstream,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        upstream.calls += 1;
        switch (upstream.mode) {
            .ok => _ = Router.handle(upstream, request.body, response.writer()),
            .status_500 => response.fail(500),
            .hang => _ = response.defer_response(), // Never resumed; stop answers 503.
        }
    }
};

const UpstreamServer = http.Server(SimIo, *FakeUpstream, FakeUpstream.handle);
const Proxy = roxy.Proxy(SimIo);
const Client = http.Client(SimIo);

const small_limits: http.Limits = .{ .head_size_max = 1024, .body_size_max = 2048 };

const Harness = struct {
    world: io.SimWorld,
    upstream_ios: [upstream_count]SimIo,
    upstreams: [upstream_count]FakeUpstream,
    servers: [upstream_count]UpstreamServer,
    /// Upstream `i` listens only when `listening[i]`; otherwise connects are refused.
    listening: [upstream_count]bool,
    addresses: [upstream_count]Address,
    proxy_io: SimIo,
    proxy: Proxy,
    client_io: SimIo,
    bound: Address,

    /// `options.upstreams` is filled in by the harness.
    fn init(
        harness: *Harness,
        seed: u64,
        listening: [upstream_count]bool,
        options: roxy.Options,
    ) !void {
        const allocator = testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 256 });
        harness.listening = listening;
        var addresses: [upstream_count]Address = undefined;
        for (0..upstream_count) |index| {
            const host: u8 = @intCast(index + 1);
            try SimIo.init(&harness.upstream_ios[index], allocator, &harness.world, .{
                .host = Address.ip4(.{ 10, 0, 0, host }, 0),
            });
            harness.upstreams[index] = .{ .index = @intCast(index) };
            addresses[index] = Address.ip4(.{ 10, 0, 0, host }, 8545);
            const upstream_io = &harness.upstream_ios[index];
            const upstream = &harness.upstreams[index];
            try harness.servers[index].init(allocator, upstream_io, upstream, .{
                .connections_max = 8,
                .recv_buffer_size = 4096,
                .send_buffer_size = 4096,
                .limits = small_limits,
                .io_timeout_ns = 60_000 * ms,
            });
            if (listening[index]) _ = try harness.servers[index].listen(addresses[index]);
        }
        try SimIo.init(&harness.proxy_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 10 }, 0),
        });
        try SimIo.init(&harness.client_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 20 }, 0),
        });
        harness.addresses = addresses;
        var proxy_options = options;
        proxy_options.upstreams = &harness.addresses;
        try harness.proxy.init(allocator, &harness.proxy_io, proxy_options);
        harness.bound = try harness.proxy.listen(Address.ip4(.{ 10, 0, 0, 10 }, 8080));
    }

    fn deinit(harness: *Harness) void {
        harness.proxy.stop();
        for (&harness.servers) |*server| server.stop();
        var rounds: u32 = 0;
        while (rounds < 20_000) : (rounds += 1) {
            if (harness.all_stopped()) break;
            harness.world.run_for_ns(ms);
            harness.proxy.tick();
        }
        std.debug.assert(harness.all_stopped());
        harness.proxy.deinit();
        for (&harness.servers) |*server| server.deinit();
        harness.client_io.deinit();
        harness.proxy_io.deinit();
        for (&harness.upstream_ios) |*upstream_io| upstream_io.deinit();
        harness.world.deinit();
    }

    fn all_stopped(harness: *const Harness) bool {
        if (!harness.proxy.stopped()) return false;
        for (&harness.servers) |*server| if (!server.stopped()) return false;
        return true;
    }

    fn run_ticking(harness: *Harness, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ms) {
            harness.world.run_for_ns(10 * ms);
            harness.proxy.tick();
            for (&harness.servers) |*server| server.tick();
        }
    }

    fn client(harness: *Harness) !Client {
        return Client.init(testing.allocator, &harness.client_io, harness.bound, .{
            .send_buffer_size = 4096,
            .recv_buffer_size = 4096,
            .limits = small_limits,
        });
    }

    /// Sends one request and runs until it is answered (or 2 s pass).
    fn call(harness: *Harness, target: []const u8, body: []const u8) !Result {
        return harness.call_with(target, &.{}, body);
    }

    fn call_with(
        harness: *Harness,
        target: []const u8,
        headers: []const http.parser.Header,
        body: []const u8,
    ) !Result {
        var test_client = try harness.client();
        defer test_client.deinit();
        var result: Result = .{};
        try test_client.request(*Result, &result, Result.on_response, .POST, target, headers, body);
        var elapsed_ns: u64 = 0;
        while (result.calls == 0 and elapsed_ns < 2000 * ms) : (elapsed_ns += 10 * ms) {
            harness.run_ticking(10 * ms);
        }
        try testing.expectEqual(@as(u32, 1), result.calls);
        return result;
    }

    fn get(harness: *Harness, target: []const u8, buffer: []u8) http.ResponseBuilder {
        var response = http.ResponseBuilder.init(buffer);
        const request: http.Request = .{
            .method = .GET,
            .method_text = "GET",
            .target = target,
            .version = .http_1_1,
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
        harness.proxy.handle(&request, &response);
        return response;
    }
};

const Result = struct {
    status: u16 = 0,
    body: [1024]u8 = undefined,
    body_size: usize = 0,
    calls: u32 = 0,
    failed: bool = false,

    fn on_response(
        result: *Result,
        client: *Client,
        response: http.client.Error!*const http.Response,
    ) void {
        _ = client;
        result.calls += 1;
        const r = response catch {
            result.failed = true;
            return;
        };
        result.status = r.status;
        @memcpy(result.body[0..r.body.len], r.body);
        result.body_size = r.body.len;
    }

    fn text(result: *const Result) []const u8 {
        return result.body[0..result.body_size];
    }
};

const chain_id_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}";

const base_options: roxy.Options = .{
    .upstreams = &.{},
    .clients_per_upstream = 2,
    .pending_max = 8,
    .attempts_max = 3,
    .pool = .{
        .failures_to_eject = 2,
        .backoff_initial_ns = 1000 * ms,
        .backoff_max_ns = 4000 * ms,
    },
    .server = .{
        .connections_max = 8,
        .recv_buffer_size = 4096,
        .send_buffer_size = 4096,
        .limits = small_limits,
        .io_timeout_ns = 5000 * ms,
    },
    .client = .{
        .send_buffer_size = 4096,
        .recv_buffer_size = 4096,
        .limits = small_limits,
        .request_timeout_ns = 1000 * ms,
    },
    .version = "v-test",
};

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "roxy: retries around a 500ing and a refusing upstream, ejects, then re-admits" {
    var harness: Harness = undefined;
    // Upstream 2 does not listen: every connect to it is refused.
    try harness.init(51, .{ true, true, false }, base_options);
    defer harness.deinit();
    harness.upstreams[1].mode = .status_500;
    for (0..12) |_| {
        const result = try harness.call("/", chain_id_body);
        try testing.expectEqual(@as(u16, 200), result.status);
        const expected = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xa\"}";
        try testing.expectEqualStrings(expected, result.text());
    }
    const now_ns = harness.proxy_io.now_monotonic_ns();
    try testing.expect(harness.proxy.pool.ejected(1, now_ns));
    try testing.expect(harness.proxy.pool.ejected(2, now_ns));
    try testing.expect(!harness.proxy.pool.ejected(0, now_ns));
    try testing.expect(harness.proxy.retries.get() >= 4);
    // Ejected upstreams see no traffic: two failures each before ejection.
    try testing.expectEqual(@as(u32, 2), harness.upstreams[1].calls);
    var buffer: [8192]u8 = undefined;
    var metrics_response = harness.get("/metrics", &buffer);
    const text = metrics_response.body.buffered();
    try testing.expect(contains(text, "roxy_requests_total 12"));
    try testing.expect(contains(text, "roxy_upstream_ejected{upstream=\"10.0.0.2:8545\"} 1"));
    const failures = "roxy_upstream_failures_total{upstream=\"10.0.0.3:8545\"} 2";
    try testing.expect(contains(text, failures));

    // Upstream 1 recovers; after its backoff it is re-admitted and serves again.
    harness.upstreams[1].mode = .ok;
    harness.run_ticking(1500 * ms);
    var served_by_one: u32 = 0;
    for (0..6) |_| {
        const result = try harness.call("/", chain_id_body);
        try testing.expectEqual(@as(u16, 200), result.status);
        served_by_one += @intFromBool(contains(result.text(), "\"0xb\""));
    }
    try testing.expect(served_by_one >= 2);
    try testing.expect(!harness.proxy.pool.ejected(1, harness.proxy_io.now_monotonic_ns()));
    try testing.expect(!harness.proxy.pool.upstreams[1].probation);
}

test "roxy: all upstreams failing fails open, then answers the last 5xx" {
    var harness: Harness = undefined;
    try harness.init(52, .{ true, true, true }, base_options);
    defer harness.deinit();
    for (&harness.upstreams) |*upstream| upstream.mode = .status_500;
    for (0..4) |_| {
        const result = try harness.call("/", chain_id_body);
        try testing.expectEqual(@as(u16, 500), result.status);
    }
    const now_ns = harness.proxy_io.now_monotonic_ns();
    try testing.expect(!harness.proxy.pool.any_admitted(now_ns));
    var buffer: [2048]u8 = undefined;
    try testing.expectEqual(@as(u16, 503), harness.get("/readyz", &buffer).status);
    // Fail open: requests still reach an (ejected) upstream and succeed once it recovers.
    harness.upstreams[0].mode = .ok;
    harness.upstreams[1].mode = .ok;
    harness.upstreams[2].mode = .ok;
    const result = try harness.call("/", chain_id_body);
    try testing.expectEqual(@as(u16, 200), result.status);
    try testing.expectEqual(@as(u16, 200), harness.get("/readyz", &buffer).status);
}

test "roxy: allowlist rejects single and batch requests without upstream traffic" {
    var harness: Harness = undefined;
    var options = base_options;
    options.allowlist = try roxy.Allowlist.parse("eth_chainId");
    try harness.init(53, .{ true, true, true }, options);
    defer harness.deinit();
    const send = "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"eth_sendRawTransaction\"," ++
        "\"params\":[\"0x00\"]}";
    var result = try harness.call("/", send);
    try testing.expectEqual(@as(u16, 200), result.status);
    const expected = "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":-32601," ++
        "\"message\":\"method not allowed\"}}";
    try testing.expectEqualStrings(expected, result.text());
    const batch = "[" ++ chain_id_body ++ "," ++ send ++ "]";
    result = try harness.call("/", batch);
    try testing.expect(std.mem.startsWith(u8, result.text(), "[{\"jsonrpc\":\"2.0\",\"id\":1,"));
    try testing.expect(contains(result.text(), "another entry's method is not allowed"));
    result = try harness.call("/", "{\"method\":");
    try testing.expect(contains(result.text(), "-32700"));
    for (harness.upstreams) |upstream| try testing.expectEqual(@as(u32, 0), upstream.calls);
    try testing.expectEqual(@as(u64, 2), harness.proxy.rejected_method.get());
    // Allowed methods (also in a batch) pass through.
    result = try harness.call("/", "[" ++ chain_id_body ++ "]");
    try testing.expect(contains(result.text(), "\"result\":\"0x"));
    var buffer: [2048]u8 = undefined;
    var health = harness.get("/healthz", &buffer);
    try testing.expectEqualStrings("{\"version\":\"v-test\"}", health.body.buffered());
    try testing.expectEqual(@as(u16, 404), harness.get("/nope", &buffer).status);
}

test "roxy: a full pending set answers 503 at once" {
    var harness: Harness = undefined;
    var options = base_options;
    options.pending_max = 2;
    options.clients_per_upstream = 1;
    try harness.init(54, .{ true, false, false }, options);
    defer harness.deinit();
    harness.upstreams[0].mode = .hang;
    // Two requests fill the set: one in flight, one queued behind it.
    var clients: [3]Client = undefined;
    var results: [3]Result = @splat(.{});
    for (&clients, &results) |*test_client, *result| {
        test_client.* = try harness.client();
        const on_response = Result.on_response;
        try test_client.request(*Result, result, on_response, .POST, "/", &.{}, chain_id_body);
        harness.run_ticking(50 * ms);
    }
    defer for (&clients) |*test_client| test_client.deinit();
    try testing.expectEqual(@as(u32, 1), results[2].calls);
    try testing.expectEqual(@as(u16, 503), results[2].status);
    try testing.expectEqual(@as(u32, 0), results[0].calls + results[1].calls);
    try testing.expectEqual(@as(u64, 1), harness.proxy.rejected_overload.get());
    try testing.expectEqual(@as(u32, 1), harness.upstreams[0].calls);
    // The upstream request times out (1 s) and the retries hit refusing upstreams, so the
    // in-flight request ends with 502 and the queued one follows.
    harness.run_ticking(4000 * ms);
    try testing.expectEqual(@as(u32, 1), results[0].calls);
    try testing.expectEqual(@as(u32, 1), results[1].calls);
    try testing.expectEqual(@as(u16, 502), results[0].status);
}

test "roxy: per-client rate limits, with clients behind a trusted proxy told apart" {
    var harness: Harness = undefined;
    var options = base_options;
    options.rate_limit = .{ .requests_per_s = 1, .burst = 2 };
    // The test client (10.0.0.20) acts as a trusted load balancer.
    var cidrs = [_]trusted_proxy.Cidr{try trusted_proxy.Cidr.parse("10.0.0.20/32")};
    options.trusted_proxy = .{ .cidrs = &cidrs };
    try harness.init(55, .{ true, true, true }, options);
    defer harness.deinit();
    const alice = [_]http.parser.Header{.{ .name = "X-Forwarded-For", .value = "203.0.113.1" }};
    const bob = [_]http.parser.Header{.{ .name = "X-Forwarded-For", .value = "203.0.113.2" }};
    for (0..2) |_| {
        const result = try harness.call_with("/", &alice, chain_id_body);
        try testing.expectEqual(@as(u16, 200), result.status);
    }
    var result = try harness.call_with("/", &alice, chain_id_body);
    try testing.expectEqual(@as(u16, 429), result.status);
    try testing.expect(contains(result.text(), "-32016"));
    // Bob has his own bucket; the balancer itself (no header) has a third.
    result = try harness.call_with("/", &bob, chain_id_body);
    try testing.expectEqual(@as(u16, 200), result.status);
    result = try harness.call("/", chain_id_body);
    try testing.expectEqual(@as(u16, 200), result.status);
    // A second later Alice has one token again.
    harness.run_ticking(1000 * ms);
    result = try harness.call_with("/", &alice, chain_id_body);
    try testing.expectEqual(@as(u16, 200), result.status);
    try testing.expectEqual(@as(u64, 1), harness.proxy.rejected_rate_limit.get());
}

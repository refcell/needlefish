//! `base roxy`: JSON-RPC reverse proxy over N upstreams with retries, passive health
//! (ejection with exponential backoff), a method allowlist, method routing with batch
//! splitting, block-lag exclusion, and consensus block tags. Serves `/healthz`,
//! `/readyz`, and `/metrics` on the same port. See `src/infra/roxy`.

const std = @import("std");
const base = @import("base");
const consensus = @import("consensus.zig");

const io = base.utilities.io;
const cli = base.utilities.cli;
const roxy = base.infra.roxy;
const trusted_proxy = base.utilities.trusted_proxy;
const Proxy = roxy.Proxy(io.IO);

const env_prefix = "BASE_ROXY_";

pub const Spec = struct {
    listen_addr: []const u8 = "0.0.0.0:8545",
    upstreams: []const u8,
    allowed_methods: []const u8 = "",
    retries: u32 = 2,
    clients_per_upstream: u32 = 8,
    pending_max: u32 = 1024,
    upstream_timeout_ms: u32 = 10_000,
    failures_to_eject: u32 = 3,
    ejection_backoff_ms: u32 = 1_000,
    ejection_backoff_max_ms: u32 = 60_000,
    request_size_max: u32 = 512 * 1024,
    response_size_max: u32 = 4 * 1024 * 1024,
    rate_limit_rps: u32 = 0,
    rate_limit_burst: u32 = 20,
    trusted_proxies: []const u8 = "",
    routes: []const u8 = "",
    lag_max_blocks: u64 = 0,
    lag_poll_ms: u32 = 1_000,
    split_batches_max: u32 = 4,
    consensus_tags: bool = false,
    consensus_rewrite_bytes: u32 = 16 * 1024,

    pub const help = .{
        .listen_addr = "Address to serve on, IPv4:PORT",
        .upstreams = "Comma-separated upstream JSON-RPC endpoints, http://IPv4:PORT,...",
        .allowed_methods = "Comma-separated JSON-RPC methods to allow (empty: allow all)",
        .retries = "Retries on another upstream after a transport error or 5xx",
        .clients_per_upstream = "Concurrent requests per upstream",
        .pending_max = "Requests queued or in flight before new ones get 503",
        .upstream_timeout_ms = "Timeout of one upstream attempt",
        .failures_to_eject = "Consecutive failures that eject an upstream",
        .ejection_backoff_ms = "First ejection duration; doubles per ejection in a row",
        .ejection_backoff_max_ms = "Longest ejection duration",
        .request_size_max = "Largest request body in bytes",
        .response_size_max = "Largest upstream response body in bytes",
        .rate_limit_rps = "Requests per second per client IP (0: unlimited)",
        .rate_limit_burst = "Requests a client may burst after idling",
        .trusted_proxies = "Comma-separated CIDRs whose X-Forwarded-For is trusted",
        .lag_max_blocks = "Skip upstreams this many blocks behind the best head (0: off)",
        .lag_poll_ms = "eth_blockNumber polling interval for --lag-max-blocks",
        .split_batches_max = "Batches split across routes at once (0: reject such batches)",
        .consensus_tags = "Rewrite latest block params to the consensus head (needs lag)",
        .consensus_rewrite_bytes = "Per-request rewrite buffer; larger bodies go unmodified",
        .routes = "Pin methods to upstreams: m1,m2=0|1;m3=2 (indices into --upstreams)",
    };
};

pub const Settings = struct {
    listen: io.Address,
    upstreams: [roxy.pool.upstreams_max]io.Address = undefined,
    upstream_count: u32 = 0,
    cidrs: [trusted_proxies_max]trusted_proxy.Cidr = undefined,
    cidr_count: u32 = 0,
    options: roxy.Options,

    pub fn upstream_list(settings: *const Settings) []const io.Address {
        return settings.upstreams[0..settings.upstream_count];
    }

    pub fn cidr_list(settings: *const Settings) []const trusted_proxy.Cidr {
        return settings.cidrs[0..settings.cidr_count];
    }
};

const trusted_proxies_max = 16;

/// Validates parsed flags into runtime settings. `options.upstreams` and
/// `options.trusted_proxy.cidrs` are left empty: point them at `upstream_list()` and
/// `cidr_list()` once the settings are at their final address.
pub fn settings_of(spec: Spec) !Settings {
    const values_valid = spec.clients_per_upstream > 0 and spec.pending_max > 0 and
        spec.upstream_timeout_ms > 0 and spec.failures_to_eject > 0 and
        spec.ejection_backoff_ms > 0 and
        spec.ejection_backoff_ms <= spec.ejection_backoff_max_ms and
        spec.request_size_max > 0 and spec.response_size_max > 0 and spec.retries < 64 and
        spec.rate_limit_burst > 0;
    if (!values_valid) return error.InvalidValue;
    var settings: Settings = .{ .listen = try parse_listen(spec.listen_addr), .options = .{
        .upstreams = &.{},
        .allowlist = try roxy.Allowlist.parse(spec.allowed_methods),
    } };
    var parts = std.mem.splitScalar(u8, spec.upstreams, ',');
    while (parts.next()) |part| {
        const text = std.mem.trim(u8, part, " ");
        if (text.len == 0) continue;
        if (settings.upstream_count == settings.upstreams.len) return error.TooManyUpstreams;
        settings.upstreams[settings.upstream_count] = try consensus.parse_url(text);
        settings.upstream_count += 1;
    }
    if (settings.upstream_count == 0) return error.NoUpstreams;
    var cidr_parts = std.mem.splitScalar(u8, spec.trusted_proxies, ',');
    while (cidr_parts.next()) |part| {
        const text = std.mem.trim(u8, part, " ");
        if (text.len == 0) continue;
        if (settings.cidr_count == settings.cidrs.len) return error.TooManyTrustedProxies;
        settings.cidrs[settings.cidr_count] = try trusted_proxy.Cidr.parse(text);
        settings.cidr_count += 1;
    }
    settings.options = options_of(spec, settings.options.allowlist);
    settings.options.routes = try roxy.Routes.parse(spec.routes, settings.upstream_count);
    if (spec.lag_poll_ms == 0) return error.InvalidValue;
    if (spec.consensus_tags and spec.lag_max_blocks == 0) return error.ConsensusTagsNeedLag;
    if (spec.consensus_rewrite_bytes == 0) return error.InvalidValue;
    settings.options.splits_max = spec.split_batches_max;
    settings.options.consensus_tags = spec.consensus_tags;
    settings.options.rewrite_size_max = spec.consensus_rewrite_bytes;
    settings.options.lag = .{
        .max_blocks = spec.lag_max_blocks,
        .poll_interval_ns = @as(u64, spec.lag_poll_ms) * std.time.ns_per_ms,
    };
    settings.options.rate_limit = .{
        .requests_per_s = spec.rate_limit_rps,
        .burst = spec.rate_limit_burst,
    };
    return settings;
}

fn options_of(spec: Spec, allowlist: roxy.Allowlist) roxy.Options {
    const ms = std.time.ns_per_ms;
    const timeout_ns = @as(u64, spec.upstream_timeout_ms) * ms;
    const attempts = spec.retries + 1;
    const head_size_max = 16 * 1024;
    return .{
        .upstreams = &.{},
        .clients_per_upstream = spec.clients_per_upstream,
        .pending_max = spec.pending_max,
        .attempts_max = attempts,
        .allowlist = allowlist,
        .pool = .{
            .failures_to_eject = spec.failures_to_eject,
            .backoff_initial_ns = @as(u64, spec.ejection_backoff_ms) * ms,
            .backoff_max_ns = @as(u64, spec.ejection_backoff_max_ms) * ms,
        },
        .server = .{
            .connections_max = 256,
            .recv_buffer_size = head_size_max + spec.request_size_max,
            .send_buffer_size = 64 * 1024,
            .limits = .{ .head_size_max = head_size_max, .body_size_max = spec.request_size_max },
            .large_send_buffers_max = 16,
            .large_send_buffer_size = @max(64 * 1024 + 1, spec.response_size_max + 4096),
            // A deferred request may wait for every attempt; answer 504 only after that.
            .io_timeout_ns = timeout_ns * attempts + 5 * std.time.ns_per_s,
        },
        .client = .{
            .send_buffer_size = head_size_max + spec.request_size_max,
            .recv_buffer_size = head_size_max + spec.response_size_max,
            .limits = .{ .head_size_max = head_size_max, .body_size_max = spec.response_size_max },
            .request_timeout_ns = timeout_ns,
        },
        .version = base.build_options.version,
    };
}

fn parse_listen(text: []const u8) !io.Address {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.MissingPort;
    const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text[0..colon], '.');
    for (&bytes) |*byte| byte.* = try std.fmt.parseInt(u8, parts.next() orelse "", 10);
    if (parts.next() != null) return error.InvalidAddress;
    return io.Address.ip4(bytes, port);
}

fn print_help() void {
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base roxy --upstreams URL,URL [--listen-addr IP:PORT]\n{s}", .{
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
        std.debug.print("roxy: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    const settings = try init.gpa.create(Settings);
    defer init.gpa.destroy(settings);
    settings.* = settings_of(spec) catch |err| {
        std.debug.print("roxy: invalid flags: {t}\n", .{err});
        return 2;
    };
    settings.options.upstreams = settings.upstream_list();
    settings.options.trusted_proxy.cidrs = settings.cidr_list();
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    const proxy = try init.gpa.create(Proxy);
    defer init.gpa.destroy(proxy);
    try proxy.init(init.gpa, &os_io, settings.options);
    defer proxy.deinit();
    const bound = try proxy.listen(settings.listen);
    std.debug.print("roxy: serving on port {d} with {d} upstreams\n", .{
        bound.port,
        settings.upstream_count,
    });
    while (true) {
        try os_io.run_for_ns(100 * std.time.ns_per_ms);
        proxy.tick();
    }
}

const testing = std.testing;

test "roxy: flags to settings" {
    const settings = try settings_of(.{
        .upstreams = "http://127.0.0.1:8545, http://127.0.0.1:9545",
        .allowed_methods = "eth_chainId,eth_call",
        .retries = 1,
    });
    try testing.expectEqual(@as(u32, 2), settings.upstream_count);
    try testing.expectEqual(@as(u16, 9545), settings.upstreams[1].port);
    try testing.expectEqual(@as(u16, 8545), settings.listen.port);
    try testing.expectEqual(@as(u32, 2), settings.options.attempts_max);
    try testing.expect(settings.options.allowlist.allows("eth_call"));
    try testing.expect(!settings.options.allowlist.allows("eth_sendRawTransaction"));
    try testing.expectError(error.NoUpstreams, settings_of(.{ .upstreams = " , " }));
    const limited = try settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .rate_limit_rps = 50,
        .trusted_proxies = "10.0.0.0/8, 192.168.0.0/16",
    });
    try testing.expectEqual(@as(u32, 2), limited.cidr_count);
    try testing.expectEqual(@as(u32, 50), limited.options.rate_limit.requests_per_s);
    const routed = try settings_of(.{
        .upstreams = "http://127.0.0.1:8545,http://127.0.0.1:9545",
        .routes = "eth_sendRawTransaction=1",
    });
    try testing.expectEqual(@as(?roxy.Mask, 0b10), routed.options.routes.mask_for(
        "eth_sendRawTransaction",
    ));
    try testing.expectEqual(@as(u32, 4), routed.options.splits_max);
    try testing.expect(!routed.options.consensus_tags);
    const tagged = try settings_of(.{
        .upstreams = "http://127.0.0.1:8545,http://127.0.0.1:9545",
        .lag_max_blocks = 4,
        .consensus_tags = true,
        .consensus_rewrite_bytes = 4096,
        .split_batches_max = 0,
    });
    try testing.expect(tagged.options.consensus_tags);
    try testing.expectEqual(@as(u32, 4096), tagged.options.rewrite_size_max);
    try testing.expectEqual(@as(u32, 0), tagged.options.splits_max);
    try testing.expectError(error.ConsensusTagsNeedLag, settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .consensus_tags = true,
    }));
    try testing.expectError(error.UpstreamIndexTooLarge, settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .routes = "eth_call=1",
    }));
    try testing.expectError(error.InvalidCidr, settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .trusted_proxies = "10.0.0.0/33",
    }));
    try testing.expectError(error.InvalidValue, settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .ejection_backoff_ms = 10,
        .ejection_backoff_max_ms = 5,
    }));
    try testing.expectError(error.InvalidMethodName, settings_of(.{
        .upstreams = "http://127.0.0.1:8545",
        .allowed_methods = "eth-call",
    }));
}

test "roxy: cli spec parses with env fallback" {
    var diagnostic: cli.Diagnostic = .{};
    const args = [_][]const u8{
        "--listen-addr",    "127.0.0.1:9000", "--consensus-tags",
        "--lag-max-blocks", "3",
    };
    const Lookup = struct {
        fn get(context: ?*const anyopaque, name: []const u8) ?[]const u8 {
            _ = context;
            if (std.mem.eql(u8, name, "BASE_ROXY_UPSTREAMS")) return "http://127.0.0.1:8545";
            return null;
        }
    };
    const env: cli.Env = .{ .context = null, .get = Lookup.get };
    const spec = try cli.parse(Spec, env_prefix, &args, env, &diagnostic);
    try testing.expectEqualStrings("127.0.0.1:9000", spec.listen_addr);
    try testing.expectEqualStrings("http://127.0.0.1:8545", spec.upstreams);
    try testing.expectEqual(@as(u32, 2), spec.retries);
    try testing.expect(spec.consensus_tags);
    try testing.expectEqual(@as(u64, 3), spec.lag_max_blocks);
}

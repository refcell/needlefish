//! `base sidecrush`: block-production health sidecar. Polls an execution node's latest
//! block, classifies production as healthy/delayed/unhealthy/error against the 200 ms
//! cadence, logs every state change, and serves Prometheus metrics, liveness (`/`,
//! `/healthz`), and readiness (`/readyz`). See `src/infra/sidecrush`.

const std = @import("std");
const base = @import("base");
const consensus = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const cli = base.utilities.cli;
const sidecrush = base.infra.sidecrush;
const Checker = sidecrush.Checker(io.IO);
const Server = http.Server(io.IO, *Checker, Checker.handle);

const env_prefix = "BASE_SIDECRUSH_";

pub const Spec = struct {
    rpc_url: []const u8 = "http://127.0.0.1:8545",
    poll_interval_ms: u32 = 200,
    grace_period_ms: u64 = 2_000,
    unhealthy_threshold_ms: u64 = 3_000,
    new_instance: bool = true,
    metrics_addr: []const u8 = "0.0.0.0",
    metrics_port: u16 = 7300,

    pub const help = .{
        .rpc_url = "Execution node JSON-RPC, http://IPv4:PORT",
        .poll_interval_ms = "Milliseconds between polls of the latest block",
        .grace_period_ms = "Head age beyond this is delayed",
        .unhealthy_threshold_ms = "Head age at or beyond this is unhealthy",
        .new_instance = "Report healthy until the node first reaches the tip",
        .metrics_addr = "IPv4 address for the HTTP endpoints",
        .metrics_port = "Port for the HTTP endpoints",
    };
};

pub const Settings = struct {
    endpoint: io.Address,
    listen: io.Address,
    options: sidecrush.Options,
};

pub fn settings_of(spec: Spec) !Settings {
    if (spec.poll_interval_ms == 0) return error.InvalidValue;
    const options: sidecrush.Options = .{
        .poll_interval_ns = @as(u64, spec.poll_interval_ms) * std.time.ns_per_ms,
        .thresholds = .{
            .grace_ms = spec.grace_period_ms,
            .unhealthy_ms = spec.unhealthy_threshold_ms,
        },
        .new_instance = spec.new_instance,
        .version = base.build_options.version,
    };
    if (!options.thresholds.valid()) return error.InvalidThresholds;
    return .{
        .endpoint = try consensus.parse_url(spec.rpc_url),
        .listen = io.Address.ip4(try parse_ip4(spec.metrics_addr), spec.metrics_port),
        .options = options,
    };
}

fn parse_ip4(text: []const u8) ![4]u8 {
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&bytes) |*byte| byte.* = try std.fmt.parseInt(u8, parts.next() orelse "", 10);
    if (parts.next() != null) return error.InvalidAddress;
    return bytes;
}

fn print_help() void {
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base sidecrush [--rpc-url URL]\n{s}", .{writer.buffered()});
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args, env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("sidecrush: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    const settings = settings_of(spec) catch |err| {
        std.debug.print("sidecrush: invalid flags: {t}\n", .{err});
        return 2;
    };
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    const checker = try init.gpa.create(Checker);
    defer init.gpa.destroy(checker);
    try checker.init(init.gpa, &os_io, settings.endpoint, settings.options);
    defer checker.deinit();
    const server = try init.gpa.create(Server);
    defer init.gpa.destroy(server);
    try server.init(init.gpa, &os_io, checker, .{
        .connections_max = 8,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
    });
    defer server.deinit();
    const bound = try server.listen(settings.listen);
    std.debug.print("sidecrush: serving on port {d}\n", .{bound.port});
    checker.start();
    var previous: ?sidecrush.State = null;
    while (true) {
        try os_io.run_for_ns(50 * std.time.ns_per_ms);
        const current = checker.state();
        if (previous != current) {
            const number = checker.head.last_number orelse 0;
            std.debug.print("sidecrush: {t} (head {d})\n", .{ current, number });
            previous = current;
        }
    }
}

test "sidecrush: flags to settings" {
    const settings = try settings_of(.{ .rpc_url = "http://127.0.0.1:9545" });
    try std.testing.expectEqual(@as(u16, 9545), settings.endpoint.port);
    const interval_ns = settings.options.poll_interval_ns;
    try std.testing.expectEqual(@as(u64, 200 * std.time.ns_per_ms), interval_ns);
    try std.testing.expectError(error.InvalidThresholds, settings_of(.{
        .grace_period_ms = 3_000,
        .unhealthy_threshold_ms = 3_000,
    }));
}

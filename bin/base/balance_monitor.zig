//! `base balance-monitor`: polls one account's L1 or L2 balance and serves Prometheus
//! metrics, liveness (`/`, `/healthz`), and readiness (`/readyz`) on one HTTP port.
//! See `src/infra/balance_monitor`.

const std = @import("std");
const base = @import("base");
const consensus = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const cli = base.utilities.cli;
const Exporter = base.infra.balance_monitor.Exporter(io.IO);
const Server = http.Server(io.IO, *Exporter, Exporter.handle);

const env_prefix = "BASE_BALANCE_MONITOR_";

pub const Spec = struct {
    rpc_url: []const u8,
    account: []const u8,
    poll_interval_s: u32 = 12,
    stale_after_intervals: u32 = 3,
    metrics_addr: []const u8 = "0.0.0.0",
    metrics_port: u16 = 7300,

    pub const help = .{
        .rpc_url = "JSON-RPC endpoint, http://IPv4:PORT",
        .account = "Account to watch, 0x-prefixed 20-byte hex address",
        .poll_interval_s = "Seconds between balance reads",
        .stale_after_intervals = "/readyz fails after this many intervals without a read",
        .metrics_addr = "IPv4 address for the HTTP endpoints",
        .metrics_port = "Port for the HTTP endpoints",
    };
};

pub const Settings = struct {
    endpoint: io.Address,
    account: [20]u8,
    listen: io.Address,
    options: base.infra.balance_monitor.Options,
};

/// Validates parsed flags into runtime settings.
pub fn settings_of(spec: Spec) !Settings {
    if (spec.poll_interval_s == 0 or spec.stale_after_intervals == 0) return error.InvalidValue;
    const has_prefix = std.mem.startsWith(u8, spec.account, "0x");
    const digits = if (has_prefix) spec.account[2..] else spec.account;
    if (digits.len != 40) return error.InvalidAddress;
    var account: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&account, digits) catch return error.InvalidAddress;
    return .{
        .endpoint = try consensus.parse_url(spec.rpc_url),
        .account = account,
        .listen = io.Address.ip4(try parse_ip4(spec.metrics_addr), spec.metrics_port),
        .options = .{
            .monitor = .{ .poll_interval_ns = @as(u64, spec.poll_interval_s) * std.time.ns_per_s },
            .stale_after_intervals = spec.stale_after_intervals,
            .version = base.build_options.version,
        },
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
    std.debug.print("usage: base balance-monitor --rpc-url URL --account ADDRESS\n{s}", .{
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
        std.debug.print("balance-monitor: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    const settings = settings_of(spec) catch |err| {
        std.debug.print("balance-monitor: invalid flags: {t}\n", .{err});
        return 2;
    };
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    const exporter = try init.gpa.create(Exporter);
    defer init.gpa.destroy(exporter);
    try exporter.init(init.gpa, &os_io, settings.endpoint, settings.account, settings.options);
    defer exporter.deinit();
    const server = try init.gpa.create(Server);
    defer init.gpa.destroy(server);
    try server.init(init.gpa, &os_io, exporter, .{
        .connections_max = 8,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
    });
    defer server.deinit();
    const bound = try server.listen(settings.listen);
    std.debug.print("balance-monitor: serving on port {d}\n", .{bound.port});
    exporter.start();
    while (true) try os_io.run_for_ns(100 * std.time.ns_per_ms);
}

const testing = std.testing;

test "balance-monitor: flags to settings" {
    const settings = try settings_of(.{
        .rpc_url = "http://127.0.0.1:8545",
        .account = "0xabababababababababababababababababababab",
        .poll_interval_s = 5,
    });
    try testing.expectEqual(@as(u16, 8545), settings.endpoint.port);
    try testing.expectEqual(@as(u8, 0xab), settings.account[19]);
    const interval_ns = settings.options.monitor.poll_interval_ns;
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), interval_ns);
    try testing.expectError(error.InvalidAddress, settings_of(.{
        .rpc_url = "http://127.0.0.1:8545",
        .account = "0x1234",
    }));
    try testing.expectError(error.InvalidValue, settings_of(.{
        .rpc_url = "http://127.0.0.1:8545",
        .account = "abababababababababababababababababababab",
        .poll_interval_s = 0,
    }));
}

test "balance-monitor: cli spec parses with env fallback" {
    var diagnostic: cli.Diagnostic = .{};
    const args = [_][]const u8{
        "--rpc-url",
        "http://10.0.0.1:8545",
        "--account",
        "0x0101010101010101010101010101010101010101",
    };
    const spec = try cli.parse(Spec, env_prefix, &args, .{}, &diagnostic);
    try testing.expectEqual(@as(u16, 7300), spec.metrics_port);
    try testing.expectEqualStrings("http://10.0.0.1:8545", spec.rpc_url);
}

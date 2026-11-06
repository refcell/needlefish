//! The optional `--metrics-port` endpoint of tools with a blocking main loop (`load-test`,
//! `withdrawer`): `src/infra/metrics_endpoint` on the OS IO backend. The tool calls `sleep`
//! where it used to sleep; with metrics on, that runs the IO for the same time and answers
//! scrapes, so no thread is needed. Port 0 (the default) turns the endpoint off.

const std = @import("std");
const assert = std.debug.assert;
const base = @import("base");

const io = base.utilities.io;
const metrics_endpoint = base.infra.metrics_endpoint;

pub const sync_counter = metrics_endpoint.sync_counter;

pub fn parse_ip4(text: []const u8) ![4]u8 {
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&bytes) |*byte| byte.* = try std.fmt.parseInt(u8, parts.next() orelse "", 10);
    if (parts.next() != null) return error.InvalidAddress;
    return bytes;
}

/// The listen address for `--metrics-addr`/`--metrics-port`, or null when the port is 0.
pub fn listen_address(addr_text: []const u8, port: u16) !?io.Address {
    const host = try parse_ip4(addr_text);
    if (port == 0) return null;
    const address = io.Address.ip4(host, port);
    assert(address.port == port);
    return address;
}

pub fn Server(comptime entries_max: u32) type {
    return struct {
        const Self = @This();
        pub const Endpoint = metrics_endpoint.Endpoint(io.IO, entries_max);

        os_io: io.IO,
        endpoint: Endpoint,

        /// Heap-allocates the server (the IO backend is large and must not move).
        pub fn create(gpa: std.mem.Allocator) !*Self {
            const server = try gpa.create(Self);
            errdefer gpa.destroy(server);
            server.os_io = if (@import("builtin").os.tag == .linux)
                try io.IO.init(.{})
            else
                try io.IO.init();
            errdefer server.os_io.deinit();
            try server.endpoint.init(gpa, &server.os_io, base.build_options.version);
            assert(server.endpoint.pages.registry.count == 0);
            return server;
        }

        pub fn destroy(server: *Self, gpa: std.mem.Allocator) void {
            server.endpoint.deinit();
            server.os_io.deinit();
            gpa.destroy(server);
        }

        pub fn registry(server: *Self) *Endpoint.Registry {
            return &server.endpoint.pages.registry;
        }

        /// Port 0 binds an ephemeral port (tests); flags never pass 0 (`listen_address`).
        pub fn listen(server: *Self, address: io.Address) !io.Address {
            assert(!server.endpoint.listening);
            return server.endpoint.listen(address);
        }

        /// Sleeps `duration_ms`, answering scrapes meanwhile when `server` is set.
        pub fn sleep(server: ?*Self, std_io: std.Io, duration_ms: u64) !void {
            assert(duration_ms > 0);
            if (server) |active| {
                return active.endpoint.wait_ns(duration_ms * std.time.ns_per_ms);
            }
            try std_io.sleep(.fromMilliseconds(@intCast(duration_ms)), .awake);
        }
    };
}

const testing = std.testing;

test "metrics server: port 0 turns the endpoint off" {
    try testing.expectEqual(@as(?io.Address, null), try listen_address("0.0.0.0", 0));
    const address = (try listen_address("127.0.0.1", 7301)).?;
    try testing.expectEqual(@as(u16, 7301), address.port);
    try testing.expectError(error.InvalidAddress, listen_address("1.2.3.4.5", 7301));
    try testing.expectError(error.InvalidCharacter, listen_address("localhost", 7301));
}

test "metrics server: serves a counter on the OS backend" {
    const server = Server(1).create(testing.allocator) catch |err| {
        const any: anyerror = err;
        if (any == error.IoUringUnavailable) return error.SkipZigTest;
        return err;
    };
    defer server.destroy(testing.allocator);
    var sent: base.utilities.metrics.Counter = .{};
    try server.registry().counter("tool_sent_total", "Sent.", &sent);
    const bound = try server.listen(io.Address.loopback(0));
    try testing.expect(bound.port != 0);
    sync_counter(&sent, 4);
    try Server(1).sleep(server, undefined, 1);
    try testing.expectEqual(@as(u64, 4), sent.get());
}

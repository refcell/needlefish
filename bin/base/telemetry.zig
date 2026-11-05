//! The proof services' health/readiness/metrics servers (`proof.telemetry` exporters):
//! the health port (`--health.addr/--health.port`, 0 disables) and the metrics port when
//! `--metrics.enabled` and different; both serve the same endpoints.

const std = @import("std");
const base = @import("base");

const io = base.utilities.io;
const http = base.utilities.http;
const telemetry = base.proof.telemetry;

pub const server_options: http.server.Options = .{
    .connections_max = 8,
    .recv_buffer_size = 16 * 1024,
    .send_buffer_size = 16 * 1024,
    .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
};

fn now_ns(context: *anyopaque) u64 {
    const os_io: *io.IO = @ptrCast(@alignCast(context));
    return os_io.now_monotonic_ns();
}

pub fn clock(os_io: *io.IO) telemetry.Clock {
    return .{ .context = os_io, .now_ns = now_ns };
}

/// Stops `servers` (optionals of `*http.Server`) and runs the IO until they stopped.
pub fn stop_all(os_io: *io.IO, servers: anytype) void {
    inline for (servers) |slot| if (slot) |server| server.stop();
    var rounds: u32 = 0;
    while (rounds < 1000) : (rounds += 1) {
        var stopped = true;
        inline for (servers) |slot| {
            if (slot) |server| stopped = stopped and server.stopped();
        }
        if (stopped) break;
        os_io.run_for_ns(std.time.ns_per_ms) catch break;
    }
}

pub fn Servers(comptime Exporter: type) type {
    return struct {
        const Self = @This();
        pub const Server = http.Server(io.IO, *Exporter, Exporter.handle);

        exporter: Exporter,
        servers: [2]?*Server = .{ null, null },

        /// `flags` has `health_addr/port`, `metrics_enabled` and `metrics_addr/port`.
        pub fn open(
            self: *Self,
            allocator: std.mem.Allocator,
            os_io: *io.IO,
            flags: anytype,
            options: telemetry.Options,
            label: []const u8,
        ) !void {
            self.servers = .{ null, null };
            try self.exporter.init(clock(os_io), options);
            errdefer self.close(allocator, os_io);
            const health = io.Address.ip4(flags.health_addr, flags.health_port);
            const metrics = io.Address.ip4(flags.metrics_addr, flags.metrics_port);
            const same = flags.health_port == flags.metrics_port and
                std.mem.eql(u8, &flags.health_addr, &flags.metrics_addr);
            const wanted = [2]bool{ flags.health_port != 0, flags.metrics_enabled and !same };
            for (wanted, [2]io.Address{ health, metrics }, &self.servers) |on, at, *slot| {
                if (!on) continue;
                const server = try allocator.create(Server);
                errdefer allocator.destroy(server);
                try server.init(allocator, os_io, &self.exporter, server_options);
                slot.* = server;
                const bound = try server.listen(at);
                std.debug.print("{s}: serving health and metrics on port {d}\n", .{
                    label,
                    bound.port,
                });
            }
        }

        pub fn close(self: *Self, allocator: std.mem.Allocator, os_io: *io.IO) void {
            stop_all(os_io, self.servers);
            for (&self.servers) |*slot| if (slot.*) |server| {
                server.deinit();
                allocator.destroy(server);
                slot.* = null;
            };
        }
    };
}

/// The health/metrics flags for commands that parse their own flags.
pub const Flags = struct {
    health_addr: [4]u8 = @splat(0),
    /// Off unless set: these commands' own ports default near the usual 8080/7300.
    health_port: u16 = 0,
    metrics_enabled: bool = false,
    metrics_addr: [4]u8 = @splat(0),
    metrics_port: u16 = 9300,

    pub const usage = "[--health.addr 0.0.0.0] [--health.port 0 (off)] [--metrics.enabled] " ++
        "[--metrics.addr 0.0.0.0] [--metrics.port 9300]";

    /// Consumes a telemetry flag at `args[index.*]`; false when it is another flag.
    pub fn parse_one(flags: *Flags, args: []const []const u8, index: *usize) !bool {
        const name = args[index.*];
        if (std.mem.eql(u8, name, "--metrics.enabled")) {
            flags.metrics_enabled = true;
            index.* += 1;
            return true;
        }
        const names = [_][]const u8{
            "--health.addr", "--health.port", "--metrics.addr", "--metrics.port",
        };
        const which = for (names, 0..) |known, position| {
            if (std.mem.eql(u8, name, known)) break position;
        } else return false;
        if (index.* + 1 == args.len) return error.InvalidArguments;
        const value = args[index.* + 1];
        const ip4 = base.proof.proposer.config.parse_ip4;
        switch (which) {
            0 => flags.health_addr = try ip4(value),
            1 => flags.health_port = try std.fmt.parseUnsigned(u16, value, 10),
            2 => flags.metrics_addr = try ip4(value),
            3 => flags.metrics_port = try std.fmt.parseUnsigned(u16, value, 10),
            else => unreachable,
        }
        index.* += 2;
        return true;
    }
};

test "telemetry flags: switches and values" {
    var flags: Flags = .{};
    const args = [_][]const u8{ "--metrics.enabled", "--health.port", "8081", "--other" };
    var index: usize = 0;
    try std.testing.expect(try flags.parse_one(&args, &index));
    try std.testing.expect(try flags.parse_one(&args, &index));
    try std.testing.expect(!try flags.parse_one(&args, &index));
    try std.testing.expectEqual(@as(usize, 3), index);
    try std.testing.expect(flags.metrics_enabled);
    try std.testing.expectEqual(@as(u16, 8081), flags.health_port);
    const missing = [_][]const u8{"--metrics.port"};
    index = 0;
    try std.testing.expectError(error.InvalidArguments, flags.parse_one(&missing, &index));
}

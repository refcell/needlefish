//! Periodic onchain balance monitoring (base/base `balance-monitor`).
//!
//! `Monitor(IO)` polls `eth_getBalance(account, "latest")` immediately on `start`, then every
//! `poll_interval_ns` (drift-free `time.Ticker`). Every successful read publishes: `balance`
//! is updated and `updates` increments even when the value is unchanged, so readers can treat
//! `updates` like a watch-channel version. `balance` starts at the placeholder zero; wait for
//! `updates > 0` before trusting it. Failed reads only count in `failures`. A poll that finds
//! the previous request still in flight is skipped (`polls_skipped`) rather than queued.
//!
//! The monitor owns its own JSON-RPC connection (base/base reuses the provider transport;
//! here a dedicated `rpc.Client` keeps it from contending with the owner's requests).

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");
const rpc = @import("../rpc/root.zig");
const time = @import("../time/root.zig");
const http_client = @import("../http/client.zig");

pub const Address = rpc.client.Address;

/// base/base `BalanceMonitorLayer::DEFAULT_POLL_INTERVAL`.
pub const poll_interval_default_ns: u64 = 12 * std.time.ns_per_s;

pub const Options = struct {
    poll_interval_ns: u64 = poll_interval_default_ns,
    http: http_client.Options = .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 8 * 1024,
        .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 1024 },
    },
};

pub fn Monitor(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Rpc = rpc.Client(IO);

        rpc: Rpc,
        ticker: time.Ticker(IO, *Self),
        account: [20]u8,
        balance: u256 = 0,
        /// Successful reads, including unchanged balances.
        updates: u64 = 0,
        failures: u64 = 0,
        polls_skipped: u64 = 0,
        last_update_ns: u64 = 0,

        /// In place: the ticker keeps a pointer to the monitor, which must not move.
        pub fn init(
            monitor: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            endpoint: Address,
            account: [20]u8,
            options: Options,
        ) !void {
            assert(options.poll_interval_ns > 0);
            assert(options.http.limits.body_size_max > 64);
            monitor.* = .{
                .rpc = try Rpc.init(
                    allocator,
                    io,
                    endpoint,
                    options.http,
                    options.http.limits.body_size_max,
                ),
                .ticker = .init(io, options.poll_interval_ns, monitor, on_tick),
                .account = account,
            };
        }

        /// Requires `stopped()` once started.
        pub fn deinit(monitor: *Self) void {
            assert(monitor.stopped());
            monitor.rpc.deinit();
            monitor.* = undefined;
        }

        /// Polls now, then every interval.
        pub fn start(monitor: *Self) void {
            assert(!monitor.ticker.running);
            monitor.poll();
            monitor.ticker.start();
        }

        /// Stops polling; an in-flight read still completes (and still publishes).
        pub fn stop(monitor: *Self) void {
            monitor.ticker.stop();
        }

        pub fn stopped(monitor: *const Self) bool {
            return !monitor.ticker.running and !monitor.rpc.http.busy();
        }

        fn on_tick(monitor: *Self) void {
            monitor.rpc.http.tick(); // Enforces the request timeout.
            monitor.poll();
        }

        fn poll(monitor: *Self) void {
            if (monitor.rpc.http.busy()) {
                monitor.polls_skipped += 1;
                return;
            }
            monitor.rpc.call(
                *Self,
                monitor,
                on_result,
                "eth_getBalance",
                monitor,
                write_params,
            ) catch {
                monitor.failures += 1;
            };
        }

        fn write_params(monitor: *Self, writer: *json.Writer) json.Writer.WriteError!void {
            try writer.data(&monitor.account);
            try writer.string("latest");
        }

        fn on_result(
            monitor: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &monitor.rpc);
            const value = result catch return monitor.record_failure();
            const raw = switch (value) {
                .ok => |raw| raw,
                .rpc_error => return monitor.record_failure(),
            };
            monitor.balance = parse_balance(raw) catch return monitor.record_failure();
            monitor.updates += 1;
            monitor.last_update_ns = client.http.io.now_monotonic_ns();
        }

        fn record_failure(monitor: *Self) void {
            monitor.failures += 1;
        }
    };
}

/// Parses a JSON string QUANTITY (`"0x..."`, quotes included) into a balance.
pub fn parse_balance(raw: []const u8) error{InvalidBalance}!u256 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '"' or trimmed[trimmed.len - 1] != '"') {
        return error.InvalidBalance;
    }
    return json.parse_quantity(u256, trimmed[1 .. trimmed.len - 1]) catch error.InvalidBalance;
}

test {
    _ = @import("tests.zig");
}

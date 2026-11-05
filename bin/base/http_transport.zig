//! Blocking HTTP transport for `batcher.rpc.Client`, on `std.http.Client`.
//!
//! Binary-only glue: library code sees the injected `Transport` interface, so tests
//! and the simulator never touch sockets.
//!
//! Each request may have a timeout (base/base `--network-timeout`): the fetch runs as a
//! concurrent task raced against a sleep, and a late fetch is cancelled and fails like any
//! other transport error, so callers retry it on their next step. The client is then
//! replaced so a cancelled connection is never reused. When the `Io` cannot run tasks
//! concurrently the request runs without a timeout (the timeout is optional).

const std = @import("std");
const base = @import("base");
const rpc = base.batcher.rpc;

const assert = std.debug.assert;

pub const HttpTransport = struct {
    client: std.http.Client,
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    /// 0 disables the timeout.
    timeout_ms: u64 = 0,
    timeouts: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, url: []const u8) HttpTransport {
        assert(std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://"));
        return .{
            .client = .{ .allocator = allocator, .io = io },
            .allocator = allocator,
            .io = io,
            .url = url,
        };
    }

    pub fn deinit(http: *HttpTransport) void {
        http.client.deinit();
    }

    pub fn transport(http: *HttpTransport) rpc.Transport {
        return .{ .context = http, .send_fn = send };
    }

    const Outcome = union(enum) {
        fetched: rpc.TransportError!usize,
        timed_out: std.Io.Cancelable!void,
    };

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const http: *HttpTransport = @ptrCast(@alignCast(context));
        if (http.timeout_ms == 0) return fetch(http, body, response);
        var buffer: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(http.io, &buffer);
        select.concurrent(.fetched, fetch, .{ http, body, response }) catch
            return fetch(http, body, response); // No concurrency: no timeout.
        const duration: std.Io.Clock.Duration = .{
            .raw = .fromMilliseconds(@intCast(http.timeout_ms)),
            .clock = .awake,
        };
        select.concurrent(.timed_out, sleep, .{ http.io, duration }) catch {
            const outcome = select.await() catch unreachable; // Only the fetch runs.
            return outcome.fetched;
        };
        const first = select.await() catch {
            select.cancelDiscard();
            return error.TransportFailed;
        };
        select.cancelDiscard(); // Waits for the loser, so `response` is free again.
        switch (first) {
            .fetched => |result| return result,
            .timed_out => {
                http.timeouts += 1;
                http.reset_client();
                return error.TransportFailed;
            },
        }
    }

    fn sleep(io: std.Io, duration: std.Io.Clock.Duration) std.Io.Cancelable!void {
        return duration.sleep(io);
    }

    /// Drops every pooled connection, including the one the cancelled fetch used.
    fn reset_client(http: *HttpTransport) void {
        http.client.deinit();
        http.client = .{ .allocator = http.allocator, .io = http.io };
    }

    fn fetch(http: *HttpTransport, body: []const u8, response: []u8) rpc.TransportError!usize {
        var writer: std.Io.Writer = .fixed(response);
        const result = http.client.fetch(.{
            .location = .{ .url = http.url },
            .method = .POST,
            .payload = body,
            .headers = .{ .content_type = .{ .override = "application/json" } },
            .response_writer = &writer,
        }) catch |err| switch (err) {
            error.WriteFailed => return error.ResponseTooLarge,
            else => return error.TransportFailed,
        };
        if (result.status != .ok) return error.TransportFailed;
        return writer.buffered().len;
    }
};

// A local server that accepts and never answers; with a timeout a request must fail
// quickly instead of hanging.
test "http transport: a silent server times out" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var url_buffer: [64]u8 = undefined;
    const port = server.socket.address.getPort();
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/", .{port});
    var http = HttpTransport.init(std.testing.allocator, io, url);
    defer http.deinit();
    http.timeout_ms = 200;
    var response: [256]u8 = undefined;
    const start = std.Io.Clock.awake.now(io);
    const result = http.transport().send("{}", &response);
    const elapsed_ms = start.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try std.testing.expectError(error.TransportFailed, result);
    try std.testing.expect(elapsed_ms < 5_000);
    try std.testing.expectEqual(@as(u64, 1), http.timeouts);
}

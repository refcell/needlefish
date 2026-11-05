//! Blocking HTTP transport for `batcher.rpc.Client`, on `std.http.Client`.
//!
//! Binary-only glue: library code sees the injected `Transport` interface, so tests
//! and the simulator never touch sockets.

const std = @import("std");
const base = @import("base");
const rpc = base.batcher.rpc;

pub const HttpTransport = struct {
    client: std.http.Client,
    url: []const u8,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, url: []const u8) HttpTransport {
        std.debug.assert(std.mem.startsWith(u8, url, "http://") or
            std.mem.startsWith(u8, url, "https://"));
        return .{ .client = .{ .allocator = allocator, .io = io }, .url = url };
    }

    pub fn deinit(http: *HttpTransport) void {
        http.client.deinit();
    }

    pub fn transport(http: *HttpTransport) rpc.Transport {
        return .{ .context = http, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const http: *HttpTransport = @ptrCast(@alignCast(context));
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

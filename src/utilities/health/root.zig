//! HTTP health checks for RPC servers.
//!
//! Mirrors base/base `health`: a bare `GET /` (no body, no query) answers 200 with an empty
//! body for load-balancer liveness checks (go-ethereum compatible, restricted to the root
//! path), and `GET /healthz` answers `{"version":"<version>"}`, the result of the `healthz`
//! JSON-RPC method. Call `respond` at the top of an HTTP handler; it returns `false` for
//! every other request so the handler continues with JSON-RPC.

const std = @import("std");
const assert = std.debug.assert;

const http = @import("../http/root.zig");

/// Handles health-check requests. Returns `true` when `response` has been filled.
pub fn respond(
    version: []const u8,
    request: *const http.Request,
    response: *http.ResponseBuilder,
) bool {
    if (request.method != .GET) return false;
    if (std.mem.eql(u8, request.target, "/")) {
        if (request.body.len != 0) return false;
        response.status = 200;
        response.content_type = "text/plain";
        return true;
    }
    if (std.mem.eql(u8, request.target, "/healthz")) {
        write_healthz(version, response.writer()) catch response.fail(500);
        response.status = 200;
        return true;
    }
    return false;
}

/// The `healthz` JSON-RPC method result.
pub fn write_healthz(version: []const u8, out: *std.Io.Writer) !void {
    var writer = @import("../json/root.zig").Writer.init(out);
    try writer.begin_object();
    try writer.key("version");
    try writer.string(version);
    try writer.end_object();
}

fn test_request(method: http.Method, target: []const u8, body: []const u8) http.Request {
    return .{
        .method = method,
        .method_text = @tagName(method),
        .target = target,
        .version = .http_1_1,
        .headers = .{},
        .body = body,
        .keep_alive = true,
    };
}

test "health: root liveness and healthz" {
    var buffer: [4096]u8 = undefined;
    var response = http.ResponseBuilder.init(&buffer);
    try std.testing.expect(respond("v1.2.3", &test_request(.GET, "/healthz", ""), &response));
    try std.testing.expectEqualStrings("{\"version\":\"v1.2.3\"}", response.body.buffered());
    try std.testing.expectEqual(@as(u16, 200), response.status);

    response = http.ResponseBuilder.init(&buffer);
    try std.testing.expect(respond("v1", &test_request(.GET, "/", ""), &response));
    try std.testing.expectEqual(@as(usize, 0), response.body.end);

    const passthrough = [_]http.Request{
        test_request(.POST, "/", "{}"),
        test_request(.GET, "/", "x"),
        test_request(.GET, "/?a=1", ""),
        test_request(.GET, "/metrics", ""),
    };
    for (passthrough) |request| {
        response = http.ResponseBuilder.init(&buffer);
        try std.testing.expect(!respond("v1", &request, &response));
    }
}

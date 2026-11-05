//! HTTP/1.1 on the completion-based IO: an incremental parser, response/request writers,
//! and a keep-alive, pipelining-capable server and client with bounded buffers.

const std = @import("std");

pub const parser = @import("parser.zig");
pub const Limits = parser.Limits;
pub const Method = parser.Method;
pub const Request = parser.Request;
pub const Response = parser.Response;
pub const Headers = parser.Headers;
pub const parse_request = parser.parse_request;
pub const parse_response = parser.parse_response;

pub const server = @import("server.zig");
pub const client = @import("client.zig");
pub const Server = server.Server;
pub const ResponseBuilder = server.ResponseBuilder;
pub const Grow = server.Grow;
pub const Deferred = server.Deferred;
pub const Client = client.Client;

test {
    std.testing.refAllDecls(@This());
    _ = @import("server_test.zig");
    _ = @import("timeout_test.zig");
    _ = @import("framing_test.zig");
    _ = @import("large_test.zig");
    _ = @import("deferred_test.zig");
}

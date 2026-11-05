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

test {
    std.testing.refAllDecls(@This());
}

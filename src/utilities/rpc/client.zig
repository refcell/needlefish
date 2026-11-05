//! JSON-RPC 2.0 client over the HTTP client: builds a request with caller-written params,
//! sends it, and hands the callback the raw `result` JSON (or an RPC error). Optional bearer
//! auth (JWT for the Engine API) is attached per request.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");
const http_client = @import("../http/client.zig");
const parser = @import("../http/parser.zig");

pub const Address = http_client.Address;

pub const Error = http_client.Error || error{ HttpStatus, InvalidResponse, IdMismatch };

/// A JSON-RPC error returned by the server.
pub const RpcError = struct {
    code: i64,
    /// Raw (still escaped) message bytes from the response.
    message: []const u8,
};

pub const Result = union(enum) {
    /// The raw JSON value of `result`.
    ok: []const u8,
    rpc_error: RpcError,
};

/// Parses a single (non-batch) JSON-RPC response body.
pub const ParseError = error{ InvalidResponse, IdMismatch };

/// A params writer: emits zero or more values inside the request's params array.
pub fn ParamsWriter(comptime Context: type) type {
    return fn (Context, *json.Writer) json.Writer.WriteError!void;
}

pub fn parse_response(body: []const u8, id_expected: u64) ParseError!Result {
    const response = try parse_response_any(body);
    if (response.id != id_expected) return error.IdMismatch;
    return response.result;
}

pub const Response = struct { id: u64, result: Result };

/// Parses a single response with any numeric id (for transports with several in flight).
pub fn parse_response_any(body: []const u8) ParseError!Response {
    var scanner = json.Scanner.init(body);
    json.validate(body) catch return error.InvalidResponse;
    const first = scanner.next() catch unreachable;
    if (first.tag != .object_begin) return error.InvalidResponse;
    var result: ?Result = null;
    var id: ?u64 = null;
    var iterations: usize = 0;
    while (iterations < body.len) : (iterations += 1) {
        const key = scanner.next() catch unreachable;
        if (key.tag == .object_end) break;
        const value = scanner.next() catch unreachable;
        const start = raw_start(&scanner, value);
        scanner.skip(value) catch unreachable;
        const raw = body[start..scanner.offset()];
        if (std.mem.eql(u8, key.bytes, "id")) {
            if (value.tag != .number) return error.InvalidResponse;
            id = std.fmt.parseInt(u64, value.bytes, 10) catch return error.InvalidResponse;
        } else if (std.mem.eql(u8, key.bytes, "result")) {
            result = .{ .ok = raw };
        } else if (std.mem.eql(u8, key.bytes, "error")) {
            if (value.tag != .object_begin) return error.InvalidResponse;
            result = .{ .rpc_error = try parse_error_object(raw) };
        }
    }
    return .{
        .id = id orelse return error.InvalidResponse,
        .result = result orelse return error.InvalidResponse,
    };
}

fn parse_error_object(raw: []const u8) error{InvalidResponse}!RpcError {
    var scanner = json.Scanner.init(raw);
    _ = scanner.next() catch unreachable;
    var rpc_error: RpcError = .{ .code = 0, .message = "" };
    var iterations: usize = 0;
    while (iterations < raw.len) : (iterations += 1) {
        const key = scanner.next() catch unreachable;
        if (key.tag == .object_end) break;
        const value = scanner.next() catch unreachable;
        if (std.mem.eql(u8, key.bytes, "code") and value.tag == .number) {
            rpc_error.code = std.fmt.parseInt(i64, value.bytes, 10) catch
                return error.InvalidResponse;
        } else if (std.mem.eql(u8, key.bytes, "message") and value.tag == .string) {
            rpc_error.message = value.bytes;
        }
        scanner.skip(value) catch unreachable;
    }
    return rpc_error;
}

fn raw_start(scanner: *const json.Scanner, value: json.Token) usize {
    const base = @intFromPtr(scanner.input.ptr);
    return switch (value.tag) {
        .object_begin, .array_begin => scanner.offset() - 1,
        .string => @intFromPtr(value.bytes.ptr) - base - 1,
        .number => @intFromPtr(value.bytes.ptr) - base,
        .true, .null => scanner.offset() - 4,
        .false => scanner.offset() - 5,
        else => unreachable,
    };
}

pub fn Client(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Http = http_client.Client(IO);
        const Callback = *const fn (?*anyopaque, *Self, Error!Result) void;

        http: Http,
        id_next: u64 = 1,
        id_pending: u64 = 0,
        body_buffer: []u8,
        allocator: std.mem.Allocator,
        callback: Callback = undefined,
        context: ?*anyopaque = null,
        authorization: [512]u8 = undefined,
        authorization_size: u32 = 0,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            address: Address,
            options: http_client.Options,
            body_size_max: u32,
        ) !Self {
            assert(body_size_max > 64);
            var http = try Http.init(allocator, io, address, options);
            errdefer http.deinit();
            const body_buffer = try allocator.alloc(u8, body_size_max);
            return .{ .http = http, .body_buffer = body_buffer, .allocator = allocator };
        }

        pub fn deinit(client: *Self) void {
            client.allocator.free(client.body_buffer);
            client.http.deinit();
            client.* = undefined;
        }

        /// Sets the `Authorization: Bearer <token>` header for later requests.
        pub fn set_bearer(client: *Self, token: []const u8) void {
            const prefix = "Bearer ";
            assert(prefix.len + token.len <= client.authorization.len);
            @memcpy(client.authorization[0..prefix.len], prefix);
            @memcpy(client.authorization[prefix.len..][0..token.len], token);
            client.authorization_size = @intCast(prefix.len + token.len);
        }

        /// Sends `method` with params written by `write_params(params_context, writer)`
        /// inside the params array.
        pub fn call(
            client: *Self,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Result) void,
            method: []const u8,
            params_context: anytype,
            comptime write_params: ParamsWriter(@TypeOf(params_context)),
        ) !void {
            if (client.http.busy()) return error.Busy;
            const id = client.id_next;
            client.id_next += 1;
            var out: std.Io.Writer = .fixed(client.body_buffer);
            var writer = json.Writer.init(&out);
            build_request(&writer, id, method, params_context, write_params) catch
                return error.RequestTooLarge;
            client.id_pending = id;
            client.context = if (Context == void) null else @ptrCast(@constCast(context));
            client.callback = &struct {
                fn erased(opaque_context: ?*anyopaque, self: *Self, result: Error!Result) void {
                    callback(typed(Context, opaque_context), self, result);
                }
            }.erased;
            const authorization = client.authorization[0..client.authorization_size];
            const headers: [2]parser.Header = .{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Authorization", .value = authorization },
            };
            const header_count: usize = if (authorization.len > 0) 2 else 1;
            const used = headers[0..header_count];
            try client.http.request(*Self, client, on_http, .POST, "/", used, out.buffered());
        }

        fn on_http(
            client: *Self,
            http: *Http,
            result: http_client.Error!*const parser.Response,
        ) void {
            assert(http == &client.http);
            const response = result catch |err| return client.callback(client.context, client, err);
            if (response.status != 200) {
                return client.callback(client.context, client, error.HttpStatus);
            }
            const parsed = parse_response(response.body, client.id_pending);
            client.callback(client.context, client, parsed);
        }
    };
}

/// Writes a JSON-RPC 2.0 request object.
pub fn build_request(
    writer: *json.Writer,
    id: u64,
    method: []const u8,
    params_context: anytype,
    comptime write_params: ParamsWriter(@TypeOf(params_context)),
) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("jsonrpc");
    try writer.string("2.0");
    try writer.key("id");
    try writer.integer(id);
    try writer.key("method");
    try writer.string(method);
    try writer.key("params");
    try writer.begin_array();
    try write_params(params_context, writer);
    try writer.end_array();
    try writer.end_object();
}

fn typed(comptime Context: type, opaque_context: ?*anyopaque) Context {
    if (Context == void) return {};
    return @ptrCast(@alignCast(opaque_context));
}

/// For `call` with no params.
pub fn no_params(context: void, writer: *json.Writer) json.Writer.WriteError!void {
    _ = context;
    _ = writer;
}

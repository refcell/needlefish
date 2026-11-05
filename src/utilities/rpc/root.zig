//! JSON-RPC 2.0: request parsing, a typed positional-params cursor, a comptime method-table
//! router with batch support, and a client over HTTP.
//!
//! The router writes responses into a fixed `std.Io.Writer` (e.g. the HTTP server's response
//! body). A handler writes its result value through `call.writer`; if it fails, the router
//! rewinds the output to where that response began and writes an error object instead, so a
//! half-written result never leaks. Nothing allocates.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");

pub const client = @import("client.zig");
pub const Client = client.Client;

/// Standard JSON-RPC 2.0 error codes, plus those Ethereum clients use.
pub const code = struct {
    pub const parse_error: i32 = -32700;
    pub const invalid_request: i32 = -32600;
    pub const method_not_found: i32 = -32601;
    pub const invalid_params: i32 = -32602;
    pub const internal_error: i32 = -32603;
    /// Generic server error (execution reverted, resource unavailable, ...).
    pub const server_error: i32 = -32000;
    /// Engine API: unknown payload.
    pub const unknown_payload: i32 = -38001;
    pub const invalid_forkchoice_state: i32 = -38002;
    pub const invalid_payload_attributes: i32 = -38003;
    pub const too_large_request: i32 = -38004;
    pub const unsupported_fork: i32 = -38005;
};

pub const batch_size_max = 100;

/// The fields of one request object. Slices point into the request body.
pub const Request = struct {
    /// Raw JSON of the id (number, string with quotes, or `null`); empty for notifications.
    id: []const u8,
    method: []const u8,
    /// Raw JSON of the params (array or object); empty when absent.
    params: []const u8,
};

pub const RequestError = error{ InvalidRequest, ParseError };

/// Parses one request object whose `object_begin` token was just returned by `scanner`.
pub fn parse_request(scanner: *json.Scanner) RequestError!Request {
    var request: Request = .{ .id = "", .method = "", .params = "" };
    var version_ok = false;
    var method_seen = false;
    var iterations: u32 = 0;
    while (iterations < scanner.input.len) : (iterations += 1) {
        const key = scanner.next() catch return error.ParseError;
        if (key.tag == .object_end) break;
        assert(key.key);
        const value = scanner.next() catch return error.ParseError;
        const start = value_start(scanner, value);
        scanner.skip(value) catch return error.ParseError;
        const raw = scanner.input[start..scanner.offset()];
        if (std.mem.eql(u8, key.bytes, "jsonrpc")) {
            version_ok = value.tag == .string and std.mem.eql(u8, value.bytes, "2.0");
        } else if (std.mem.eql(u8, key.bytes, "method")) {
            if (value.tag != .string or value.escaped) return error.InvalidRequest;
            request.method = value.bytes;
            method_seen = true;
        } else if (std.mem.eql(u8, key.bytes, "params")) {
            if (value.tag != .array_begin and value.tag != .object_begin) {
                return error.InvalidRequest;
            }
            request.params = raw;
        } else if (std.mem.eql(u8, key.bytes, "id")) {
            switch (value.tag) {
                .string, .number, .null => request.id = raw,
                else => return error.InvalidRequest,
            }
        }
    }
    if (!version_ok or !method_seen) return error.InvalidRequest;
    return request;
}

/// Byte offset where `value` (just returned by `scanner`) begins in the input.
fn value_start(scanner: *const json.Scanner, value: json.Token) u32 {
    const input_start = @intFromPtr(scanner.input.ptr);
    return switch (value.tag) {
        .object_begin, .array_begin => scanner.offset() - 1,
        // Include the opening quote.
        .string => @intCast(@intFromPtr(value.bytes.ptr) - input_start - 1),
        .number => @intCast(@intFromPtr(value.bytes.ptr) - input_start),
        .true => scanner.offset() - 4,
        .false => scanner.offset() - 5,
        .null => scanner.offset() - 4,
        .object_end, .array_end, .end => unreachable,
    };
}

pub const ParamsError = error{InvalidParams};

/// A cursor over positional params. Missing trailing params read as null for `optional_*`.
pub const Params = struct {
    scanner: json.Scanner,
    /// Params were given as an object (named); positional accessors reject them.
    named: bool,
    finished: bool = false,
    index: u32 = 0,

    pub fn init(raw_params: []const u8) ParamsError!Params {
        const text = if (raw_params.len == 0) "[]" else raw_params;
        const named = text[0] == '{';
        var params: Params = .{ .scanner = json.Scanner.init(text), .named = named };
        const first = params.scanner.next() catch return error.InvalidParams;
        assert(first.tag == .array_begin or first.tag == .object_begin);
        return params;
    }

    /// The next value as a token, or null if the array has ended.
    fn next_token(params: *Params) ParamsError!?json.Token {
        if (params.named) return error.InvalidParams;
        if (params.finished) return null;
        const token = params.scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) {
            params.finished = true;
            return null;
        }
        params.index += 1;
        return token;
    }

    /// The next value as raw JSON (for handlers that decode structured objects themselves).
    pub fn raw(params: *Params) ParamsError![]const u8 {
        const token = try params.next_token() orelse return error.InvalidParams;
        const start = value_start(&params.scanner, token);
        params.scanner.skip(token) catch return error.InvalidParams;
        return params.scanner.input[start..params.scanner.offset()];
    }

    pub fn optional_raw(params: *Params) ParamsError!?[]const u8 {
        if (params.finished or params.peek_end()) {
            _ = try params.next_token();
            return null;
        }
        return try params.raw();
    }

    fn peek_end(params: *Params) bool {
        var probe = params.scanner;
        const token = probe.next() catch return false;
        return token.tag == .array_end;
    }

    pub fn quantity(params: *Params, comptime T: type) ParamsError!T {
        return try params.optional_quantity(T) orelse error.InvalidParams;
    }

    pub fn optional_quantity(params: *Params, comptime T: type) ParamsError!?T {
        const token = try params.next_token() orelse return null;
        if (token.tag == .null) return null;
        if (token.tag != .string) return error.InvalidParams;
        return json.parse_quantity(T, token.bytes) catch error.InvalidParams;
    }

    pub fn data(params: *Params, out: []u8) ParamsError![]u8 {
        const token = try params.next_token() orelse return error.InvalidParams;
        if (token.tag != .string) return error.InvalidParams;
        return json.parse_data(token.bytes, out) catch error.InvalidParams;
    }

    pub fn fixed(params: *Params, comptime N: usize) ParamsError![N]u8 {
        const token = try params.next_token() orelse return error.InvalidParams;
        if (token.tag != .string) return error.InvalidParams;
        return json.parse_fixed(N, token.bytes) catch error.InvalidParams;
    }

    /// A string param without escapes (method names, block tags like "latest").
    pub fn string(params: *Params) ParamsError![]const u8 {
        const token = try params.next_token() orelse return error.InvalidParams;
        if (token.tag != .string or token.escaped) return error.InvalidParams;
        return token.bytes;
    }

    pub fn boolean(params: *Params) ParamsError!bool {
        return try params.optional_boolean() orelse error.InvalidParams;
    }

    pub fn optional_boolean(params: *Params) ParamsError!?bool {
        const token = try params.next_token() orelse return null;
        return switch (token.tag) {
            .true => true,
            .false => false,
            .null => null,
            else => error.InvalidParams,
        };
    }

    /// Requires that no params remain.
    pub fn finish(params: *Params) ParamsError!void {
        if (params.named) return;
        if (try params.next_token() != null) return error.InvalidParams;
        assert(params.finished);
    }
};

/// What a handler sees: its params, a writer for the result value, and a way to fail with a
/// specific code.
pub const Call = struct {
    method: []const u8,
    params: Params,
    writer: *json.Writer,
    error_code: i32 = code.internal_error,
    error_message: []const u8 = "internal error",

    /// Fails the call with `error_code` and a static `message`.
    pub fn fail(call: *Call, error_code: i32, message: []const u8) HandlerError {
        call.error_code = error_code;
        call.error_message = message;
        return error.Failed;
    }
};

pub const HandlerError = error{
    /// Params missing or malformed: replies -32602.
    InvalidParams,
    /// Set by `Call.fail`: replies with the code and message stored in the call.
    Failed,
    /// The result did not fit the output buffer.
    WriteFailed,
};

pub fn Method(comptime Context: type) type {
    return struct {
        name: []const u8,
        handler: *const fn (Context, *Call) HandlerError!void,
    };
}

/// Dispatches requests to a comptime method table.
pub fn Router(comptime Context: type, comptime methods: []const Method(Context)) type {
    comptime {
        for (methods, 0..) |a, i| for (methods[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.name, b.name)) @compileError("duplicate method " ++ a.name);
        };
    }
    return struct {
        /// Handles one HTTP/WebSocket body. `out` must be a fixed-buffer writer.
        pub fn handle(context: Context, body: []const u8, out: *std.Io.Writer) Outcome {
            const start = out.end;
            var scanner = json.Scanner.init(body);
            const first = scanner.next() catch return write_bare_error(out, code.parse_error);
            json.validate(body) catch return write_bare_error(out, code.parse_error);
            const outcome = switch (first.tag) {
                .object_begin => handle_single(context, &scanner, out),
                .array_begin => handle_batch(context, &scanner, out),
                else => write_bare_error(out, code.invalid_request),
            };
            assert(out.end >= start);
            return outcome;
        }

        fn handle_batch(context: Context, scanner: *json.Scanner, out: *std.Io.Writer) Outcome {
            const start = out.end;
            out.writeByte('[') catch return overflow(out, start);
            var count: u32 = 0;
            var responses: u32 = 0;
            while (count <= batch_size_max) : (count += 1) {
                const element = scanner.next() catch unreachable; // Validated.
                if (element.tag == .array_end) break;
                if (count == batch_size_max) {
                    out.end = start;
                    return write_bare_error(out, code.too_large_request);
                }
                const mark = out.end;
                if (responses > 0) out.writeByte(',') catch return overflow(out, start);
                const outcome = if (element.tag == .object_begin)
                    handle_single(context, scanner, out)
                else blk: {
                    scanner.skip(element) catch unreachable;
                    break :blk write_bare_error(out, code.invalid_request);
                };
                if (outcome == .empty) out.end = mark else responses += 1;
            }
            if (count == 0) {
                out.end = start;
                return write_bare_error(out, code.invalid_request);
            }
            if (responses == 0) {
                out.end = start;
                return .empty;
            }
            out.writeByte(']') catch return overflow(out, start);
            return .response;
        }

        fn handle_single(context: Context, scanner: *json.Scanner, out: *std.Io.Writer) Outcome {
            const object_depth = scanner.depth;
            assert(object_depth > 0);
            const request = parse_request(scanner) catch |err| {
                // Skip the rest of a malformed object so a batch can continue.
                skip_object_rest(scanner, object_depth);
                const error_code = switch (err) {
                    error.ParseError => code.parse_error,
                    error.InvalidRequest => code.invalid_request,
                };
                return write_bare_error(out, error_code);
            };
            const notification = request.id.len == 0;
            const start = out.end;
            write_response_head(out, request.id) catch return overflow(out, start);
            var failure: Failure = .{};
            dispatch(context, request, out, &failure) catch |err| {
                out.end = start;
                return write_failure(out, request.id, err, failure);
            };
            if (notification) {
                out.end = start;
                return .empty;
            }
            return .response;
        }

        const DispatchError = HandlerError || error{MethodNotFound};

        const Failure = struct {
            error_code: i32 = code.internal_error,
            message: []const u8 = "internal error",
        };

        fn dispatch(
            context: Context,
            request: Request,
            out: *std.Io.Writer,
            failure: *Failure,
        ) DispatchError!void {
            inline for (methods) |method| {
                if (std.mem.eql(u8, request.method, method.name)) {
                    var writer = json.Writer.init(out);
                    var call: Call = .{
                        .method = request.method,
                        .params = Params.init(request.params) catch return error.InvalidParams,
                        .writer = &writer,
                    };
                    method.handler(context, &call) catch |err| {
                        failure.error_code = call.error_code;
                        failure.message = call.error_message;
                        return err;
                    };
                    if (writer.depth != 0) return error.WriteFailed;
                    out.writeByte('}') catch return error.WriteFailed;
                    return;
                }
            }
            return error.MethodNotFound;
        }

        fn write_failure(
            out: *std.Io.Writer,
            id: []const u8,
            err: DispatchError,
            failure: Failure,
        ) Outcome {
            const error_code: i32, const message: []const u8 = switch (err) {
                error.MethodNotFound => .{ code.method_not_found, "method not found" },
                error.InvalidParams => .{ code.invalid_params, "invalid params" },
                error.WriteFailed => .{ code.internal_error, "response too large" },
                error.Failed => .{ failure.error_code, failure.message },
            };
            if (id.len == 0) return .empty; // Notifications get no reply, even on error.
            write_error(out, id, error_code, message) catch return overflow(out, out.end);
            return .response;
        }
    };
}

/// Advances past the end of the object opened at `object_depth`, if not already past it.
fn skip_object_rest(scanner: *json.Scanner, object_depth: u32) void {
    var iterations: usize = 0;
    while (scanner.depth >= object_depth and iterations < scanner.input.len) : (iterations += 1) {
        const token = scanner.next() catch return; // The body was validated up front.
        if (token.tag == .end) return;
    }
    assert(scanner.depth < object_depth or iterations == scanner.input.len);
}

fn write_response_head(out: *std.Io.Writer, id: []const u8) std.Io.Writer.Error!void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(if (id.len == 0) "null" else id);
    try out.writeAll(",\"result\":");
}

pub fn write_error(
    out: *std.Io.Writer,
    id: []const u8,
    error_code: i32,
    message: []const u8,
) std.Io.Writer.Error!void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(if (id.len == 0) "null" else id);
    try out.print(",\"error\":{{\"code\":{d},\"message\":", .{error_code});
    try json.write_string_escaped(out, message);
    try out.writeAll("}}");
}

fn write_bare_error(out: *std.Io.Writer, error_code: i32) Outcome {
    const message = switch (error_code) {
        code.parse_error => "parse error",
        code.too_large_request => "batch too large",
        else => "invalid request",
    };
    write_error(out, "", error_code, message) catch return .empty;
    return .response;
}

pub const Outcome = enum {
    /// `out` holds a response (single or batch).
    response,
    /// Only notifications (or nothing fit): send no body (HTTP 204, no WebSocket frame).
    empty,
};

fn overflow(out: *std.Io.Writer, start: usize) Outcome {
    out.end = start;
    return .empty;
}

test {
    _ = @import("tests.zig");
}

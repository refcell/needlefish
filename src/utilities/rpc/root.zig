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
pub const ws = @import("ws.zig");
pub const WsClient = ws.WsClient;

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
    /// jsonrpsee: a response past the server's size bound ("Response is too big").
    pub const oversized_response: i32 = -32008;
    /// jsonrpsee: a batch response past the bound ("The batch response was too large").
    pub const oversized_batch_response: i32 = -32011;
};

pub const batch_size_max = 100;

/// The largest response, as reth's default `--rpc.max-response-size` (160 MiB): a server
/// sizes its output to it, and a response that does not fit fails as jsonrpsee's oversized
/// response, whose data names this bound.
pub const response_bytes_max: u32 = 160 << 20;

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
            if (value.tag != .string) return error.InvalidRequest;
            // An escaped name keeps its backslashes, which no method name has: jsonrpsee
            // answers a valid request for an unknown method. (An escape spelling a known
            // name is the one case this does not decode.)
            request.method = value.bytes;
            method_seen = true;
        } else if (std.mem.eql(u8, key.bytes, "params")) {
            // jsonrpsee takes any value (null as none); the method refuses other scalars
            // as invalid params.
            request.params = if (value.tag == .null) "" else raw;
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
        if (first.tag != .array_begin and first.tag != .object_begin) return error.InvalidParams;
        assert(params.scanner.depth == 1);
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
        // An explicit null is an absent optional parameter, as serde's `Option` reads it.
        const text = try params.raw();
        return if (std.mem.eql(u8, text, "null")) null else text;
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

    /// A 32-byte hash param (`json.parse_hash`: a capital `0X` prefix is refused).
    pub fn hash(params: *Params) ParamsError![32]u8 {
        const token = try params.next_token() orelse return error.InvalidParams;
        if (token.tag != .string) return error.InvalidParams;
        return json.parse_hash(token.bytes) catch error.InvalidParams;
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

    /// A boolean that may be left out (null when absent) but not given as null, as serde
    /// reads a trailing `bool` argument.
    pub fn absent_or_boolean(params: *Params) ParamsError!?bool {
        const token = try params.next_token() orelse return null;
        return switch (token.tag) {
            .true => true,
            .false => false,
            else => error.InvalidParams,
        };
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
    /// The error object's `data` (written as hex when non-empty).
    error_data: []const u8 = &.{},

    /// Fails the call with `error_code` and a static `message`.
    pub fn fail(call: *Call, error_code: i32, message: []const u8) HandlerError {
        call.error_code = error_code;
        call.error_message = message;
        return error.Failed;
    }

    /// Fails the call with `error_code`, `message` and hex `data` (e.g. revert output). Both
    /// slices must outlive the handler.
    pub fn fail_data(
        call: *Call,
        error_code: i32,
        message: []const u8,
        data: []const u8,
    ) HandlerError {
        call.error_data = data;
        return call.fail(error_code, message);
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
        @setEvalBranchQuota(1000 + 64 * methods.len * methods.len);
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
            out.writeByte('[') catch return oversized_batch(out, start);
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
                if (responses > 0) out.writeByte(',') catch return oversized_batch(out, start);
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
            out.writeByte(']') catch return oversized_batch(out, start);
            return .response;
        }

        fn handle_single(context: Context, scanner: *json.Scanner, out: *std.Io.Writer) Outcome {
            const object_depth = scanner.depth;
            assert(object_depth > 0);
            const object_start = scanner.offset() - 1;
            const request = parse_request(scanner) catch |err| {
                // Skip the rest of a malformed object so a batch can continue.
                skip_object_rest(scanner, object_depth);
                switch (err) {
                    error.ParseError => return write_bare_error(out, code.parse_error),
                    error.InvalidRequest => {},
                }
                // jsonrpsee `prepare_error`: the response keeps the id when it reads as one.
                const object = scanner.input[object_start..scanner.offset()];
                const id = recover_id(object);
                write_error(out, id, code.invalid_request, "invalid request") catch return .empty;
                return .response;
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
            data: []const u8 = &.{},
        };

        fn dispatch(
            context: Context,
            request: Request,
            out: *std.Io.Writer,
            failure: *Failure,
        ) DispatchError!void {
            inline for (methods) |method| {
                if (std.mem.eql(u8, request.method, method.name)) {
                    var growing: Growing = .init(out);
                    var writer = json.Writer.init(&growing.writer);
                    var call: Call = .{
                        .method = request.method,
                        .params = Params.init(request.params) catch return error.InvalidParams,
                        .writer = &writer,
                    };
                    const result = method.handler(context, &call);
                    growing.finish();
                    result catch |err| {
                        failure.error_code = call.error_code;
                        failure.message = call.error_message;
                        failure.data = call.error_data;
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
                error.WriteFailed => .{ code.oversized_response, "Response is too big" },
                error.Failed => .{ failure.error_code, failure.message },
            };
            if (id.len == 0) return .empty; // Notifications get no reply, even on error.
            if (err == error.WriteFailed) {
                write_oversized(out, id, error_code, message) catch return overflow(out, out.end);
                return .response;
            }
            const data = if (err == error.Failed) failure.data else &.{};
            const start = out.end;
            write_error_data(out, id, error_code, message, data) catch {
                // Too large with its data: reply without it.
                out.end = start;
                write_error(out, id, error_code, message) catch return overflow(out, out.end);
            };
            return .response;
        }
    };
}

/// The raw id of an invalid request object, as jsonrpsee's `InvalidRequest` reads it: a
/// string, `null`, or a number that fits a u64; "" (written as null) for anything else.
fn recover_id(object: []const u8) []const u8 {
    assert(object.len >= 2 and object[0] == '{');
    var scanner = json.Scanner.init(object);
    _ = scanner.next() catch unreachable; // A validated object.
    var id: []const u8 = "";
    var keys: u32 = 0;
    while (keys < object.len) : (keys += 1) {
        const key = scanner.next() catch unreachable; // A validated object.
        if (key.tag == .object_end) break;
        const value = scanner.next() catch unreachable;
        const start = value_start(&scanner, value);
        scanner.skip(value) catch unreachable;
        if (!std.mem.eql(u8, key.bytes, "id")) continue;
        if (id.len > 0) return ""; // serde refuses a duplicate field.
        const raw = scanner.input[start..scanner.offset()];
        id = switch (value.tag) {
            .string, .null => raw,
            .number => if (std.fmt.parseInt(u64, raw, 10)) |_| raw else |_| return "",
            else => return "",
        };
    }
    return id;
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

/// `write_error` with the error object's `data` as hex (omitted when empty).
pub fn write_error_data(
    out: *std.Io.Writer,
    id: []const u8,
    error_code: i32,
    message: []const u8,
    data: []const u8,
) std.Io.Writer.Error!void {
    if (data.len == 0) return write_error(out, id, error_code, message);
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(if (id.len == 0) "null" else id);
    try out.print(",\"error\":{{\"code\":{d},\"message\":", .{error_code});
    try json.write_string_escaped(out, message);
    try out.writeAll(",\"data\":\"0x");
    const digits = "0123456789abcdef";
    for (data) |byte| {
        try out.writeByte(digits[byte >> 4]);
        try out.writeByte(digits[byte & 0x0f]);
    }
    try out.writeAll("\"}}");
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

/// jsonrpsee's oversized response error: its data names the bound as a string.
fn write_oversized(
    out: *std.Io.Writer,
    id: []const u8,
    error_code: i32,
    message: []const u8,
) std.Io.Writer.Error!void {
    assert(error_code == code.oversized_response or error_code == code.oversized_batch_response);
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(if (id.len == 0) "null" else id);
    try out.print(",\"error\":{{\"code\":{d},\"message\":\"{s}\",", .{ error_code, message });
    try out.print("\"data\":\"Exceeded max limit of {d}\"}}}}", .{response_bytes_max});
}

/// jsonrpsee `reject_too_big_batch_response`: the whole batch is answered by one error.
fn oversized_batch(out: *std.Io.Writer, start: usize) Outcome {
    out.end = start;
    const message = "The batch response was too large";
    const error_code = code.oversized_batch_response;
    write_oversized(out, "", error_code, message) catch return overflow(out, start);
    return .response;
}

/// A writer over `inner`'s own buffer that asks `inner` for room (`rebase`, as
/// `ensureUnusedCapacity` does) when a write does not fit, so a handler's plain writes grow
/// a response as far as `inner` allows: an HTTP response moves into a large send buffer
/// once (`http.ResponseBuilder`), a fixed writer fails as before. The two share the bytes
/// and their offsets; `finish` hands the end back to `inner`.
const Growing = struct {
    inner: *std.Io.Writer,
    writer: std.Io.Writer,

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .flush = std.Io.Writer.noopFlush,
        .rebase = rebase,
    };

    fn init(inner: *std.Io.Writer) Growing {
        return .{
            .inner = inner,
            .writer = .{ .vtable = &vtable, .buffer = inner.buffer, .end = inner.end },
        };
    }

    fn finish(growing: *Growing) void {
        assert(growing.writer.buffer.ptr == growing.inner.buffer.ptr);
        assert(growing.writer.end <= growing.inner.buffer.len);
        growing.inner.end = growing.writer.end;
    }

    fn rebase(writer: *std.Io.Writer, preserve: usize, capacity: usize) std.Io.Writer.Error!void {
        const growing: *Growing = @alignCast(@fieldParentPtr("writer", writer));
        growing.inner.end = writer.end;
        try growing.inner.rebase(preserve, capacity);
        writer.buffer = growing.inner.buffer;
        writer.end = growing.inner.end;
        assert(writer.buffer.len - writer.end >= capacity);
    }

    /// Makes room for all of `data` (the last slice `splat` times), then copies it.
    fn drain(
        writer: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        if (data.len == 0) return 0;
        const pattern = data[data.len - 1];
        var total = std.math.mul(usize, pattern.len, splat) catch return error.WriteFailed;
        for (data[0 .. data.len - 1]) |bytes| total +|= bytes.len;
        try rebase(writer, writer.end, total);
        for (data[0 .. data.len - 1]) |bytes| {
            @memcpy(writer.buffer[writer.end..][0..bytes.len], bytes);
            writer.end += bytes.len;
        }
        for (0..splat) |_| {
            @memcpy(writer.buffer[writer.end..][0..pattern.len], pattern);
            writer.end += pattern.len;
        }
        return total;
    }
};

fn overflow(out: *std.Io.Writer, start: usize) Outcome {
    out.end = start;
    return .empty;
}

test {
    _ = @import("tests.zig");
    _ = ws;
}

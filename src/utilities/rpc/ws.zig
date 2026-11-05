//! JSON-RPC over WebSocket: a client with several calls in flight plus subscription
//! notifications (`eth_subscribe` / `eth_subscription`), and server-side helpers that run a
//! `Router` on WebSocket messages and push notifications.
//!
//! Calls are matched to responses by id in a bounded pending table (`pending_max`); when the
//! connection closes, every pending call completes with `ConnectionClosed` before `on_close`.
//! Notifications are messages without an id whose `params` hold `subscription` and `result`;
//! they are handed over raw (JSON text), so callers decode only what they use.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");
const ws = @import("../ws/root.zig");
const client_module = @import("client.zig");

pub const Result = client_module.Result;
pub const ParamsWriter = client_module.ParamsWriter;
pub const pending_max = 64;

pub const CallError = error{ ConnectionClosed, InvalidResponse };

pub const Notification = struct {
    /// Raw string contents of `method` (escapes not decoded), e.g. `eth_subscription`.
    method: []const u8,
    /// Raw JSON of `params.subscription` (usually a quoted hex id).
    subscription: []const u8,
    /// Raw JSON of `params.result`.
    result: []const u8,
};

pub fn Handlers(comptime ClientType: type, comptime Context: type) type {
    return struct {
        on_open: *const fn (Context, *ClientType) void,
        /// `result` slices are valid only during the callback.
        on_result: *const fn (Context, *ClientType, u64, CallError!Result) void,
        on_notification: *const fn (Context, *ClientType, Notification) void,
        on_close: *const fn (Context, *ClientType, ws.client.Closed) void,
    };
}

pub const Options = struct {
    ws: ws.client.Options = .{},
    request_size_max: u32 = 64 * 1024,
};

pub const CallStartError = error{ Busy, RequestTooLarge } || ws.client.SendError;

pub fn WsClient(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Ws = ws.Client(IO, *Self);
        const ws_handlers: ws.client.Handlers(Ws, *Self) = .{
            .on_open = on_ws_open,
            .on_message = on_ws_message,
            .on_close = on_ws_close,
        };

        ws: Ws,
        allocator: std.mem.Allocator,
        context: Context,
        handlers: *const Handlers(Self, Context),
        /// Ids of calls awaiting a response; 0 marks a free slot (ids start at 1).
        pending: [pending_max]u64 = @splat(0),
        pending_count: u32 = 0,
        id_next: u64 = 1,
        request_buffer: []u8,
        invalid_messages: u64 = 0,
        unmatched_responses: u64 = 0,

        /// In place: the WebSocket client's callbacks point back at `client`.
        pub fn init(
            client: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            address: ws.client.Address,
            options: Options,
            context: Context,
            handlers: *const Handlers(Self, Context),
        ) !void {
            assert(options.request_size_max >= 64);
            const request_buffer = try allocator.alloc(u8, options.request_size_max);
            errdefer allocator.free(request_buffer);
            client.* = .{
                .ws = try Ws.init(allocator, io, address, options.ws, client, &ws_handlers),
                .allocator = allocator,
                .context = context,
                .handlers = handlers,
                .request_buffer = request_buffer,
            };
        }

        pub fn deinit(client: *Self) void {
            assert(client.pending_count == 0);
            client.ws.deinit();
            client.allocator.free(client.request_buffer);
            client.* = undefined;
        }

        pub fn connect(client: *Self) void {
            client.ws.connect();
        }

        pub fn close(client: *Self) void {
            client.ws.close(.normal);
        }

        pub fn abort(client: *Self) void {
            client.ws.abort();
        }

        pub fn idle(client: *const Self) bool {
            return client.ws.idle();
        }

        /// Sends a call; its response arrives through `on_result` with the returned id.
        pub fn call(
            client: *Self,
            method: []const u8,
            params_context: anytype,
            comptime write_params: ParamsWriter(@TypeOf(params_context)),
        ) CallStartError!u64 {
            if (client.pending_count == pending_max) return error.Busy;
            const id = client.id_next;
            var out: std.Io.Writer = .fixed(client.request_buffer);
            var writer = json.Writer.init(&out);
            client_module.build_request(&writer, id, method, params_context, write_params) catch
                return error.RequestTooLarge;
            try client.ws.send_text(out.buffered());
            client.id_next += 1;
            const slot = std.mem.findScalar(u64, &client.pending, 0) orelse unreachable;
            client.pending[slot] = id;
            client.pending_count += 1;
            return id;
        }

        fn on_ws_open(client: *Self, inner: *Ws) void {
            assert(inner == &client.ws);
            client.handlers.on_open(client.context, client);
        }

        fn on_ws_message(client: *Self, inner: *Ws, message: ws.client.Message) void {
            assert(inner == &client.ws);
            const payload = message.payload;
            const has_id = (json.find_path(payload, &.{"id"}) catch null) != null;
            if (!has_id) return client.dispatch_notification(payload);
            const response = client_module.parse_response_any(payload) catch {
                client.invalid_messages += 1;
                return;
            };
            const slot = std.mem.findScalar(u64, &client.pending, response.id) orelse {
                client.unmatched_responses += 1;
                return;
            };
            client.release(slot);
            client.handlers.on_result(client.context, client, response.id, response.result);
        }

        fn dispatch_notification(client: *Self, payload: []const u8) void {
            const notification = parse_notification(payload) catch {
                client.invalid_messages += 1;
                return;
            };
            client.handlers.on_notification(client.context, client, notification);
        }

        fn release(client: *Self, slot: usize) void {
            assert(client.pending[slot] != 0);
            assert(client.pending_count > 0);
            client.pending[slot] = 0;
            client.pending_count -= 1;
        }

        fn on_ws_close(client: *Self, inner: *Ws, closed: ws.client.Closed) void {
            assert(inner == &client.ws);
            for (&client.pending, 0..) |id, slot| {
                if (id == 0) continue;
                client.release(slot);
                client.handlers.on_result(client.context, client, id, error.ConnectionClosed);
            }
            assert(client.pending_count == 0);
            client.handlers.on_close(client.context, client, closed);
        }
    };
}

/// Parses a subscription notification: `{"method":"...","params":{"subscription":..,
/// "result":..}}` without an id.
pub fn parse_notification(payload: []const u8) error{InvalidNotification}!Notification {
    const invalid = error.InvalidNotification;
    const method = (json.find_path(payload, &.{"method"}) catch return invalid) orelse
        return invalid;
    if (method.len < 2 or method[0] != '"') return invalid;
    const subscription = (json.find_path(payload, &.{ "params", "subscription" }) catch
        return invalid) orelse return invalid;
    const result = (json.find_path(payload, &.{ "params", "result" }) catch return invalid) orelse
        return invalid;
    json.validate(payload) catch return invalid;
    return .{
        .method = method[1 .. method.len - 1],
        .subscription = subscription,
        .result = result,
    };
}

/// Runs `Router` on one WebSocket message and replies on the same connection, unless the
/// message held only notifications. `scratch` bounds the response size.
pub fn serve_message(
    comptime Router: type,
    context: anytype,
    server: anytype,
    connection: ws.server.ConnectionId,
    message: ws.server.Message,
    scratch: []u8,
) ws.server.SendError!void {
    var out: std.Io.Writer = .fixed(scratch);
    const outcome = Router.handle(context, message.payload, &out);
    if (outcome != .response) return;
    assert(out.buffered().len > 0);
    try server.send(connection, .text, out.buffered());
}

/// Writes `{"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"<id>",
/// "result":<written by write_result>}}`.
pub fn write_notification(
    out: *std.Io.Writer,
    subscription: []const u8,
    result_context: anytype,
    comptime write_result: fn (@TypeOf(result_context), *json.Writer) json.Writer.WriteError!void,
) json.Writer.WriteError!void {
    var writer = json.Writer.init(out);
    try writer.begin_object();
    try writer.key("jsonrpc");
    try writer.string("2.0");
    try writer.key("method");
    try writer.string("eth_subscription");
    try writer.key("params");
    try writer.begin_object();
    try writer.key("subscription");
    try writer.string(subscription);
    try writer.key("result");
    try write_result(result_context, &writer);
    try writer.end_object();
    try writer.end_object();
}

test {
    _ = @import("ws_test.zig");
}

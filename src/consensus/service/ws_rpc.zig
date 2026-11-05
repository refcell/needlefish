//! WebSocket JSON-RPC for the consensus node (base/base `rpc/src/ws.rs` and `dev.rs`,
//! `--rpc.ws-enabled`): head subscriptions `ws_subscribe_{unsafe,safe,finalized}_head`
//! (items are `L2BlockInfo`) and `dev_subscribe_engine_queue_size` (an integer), each with
//! its `*_unsubscribe_*` method. Every other request is answered by the node's router, so
//! the HTTP methods work over the socket too.
//!
//! Like jsonrpsee: the subscribe call returns a numeric subscription id; notifications are
//! `{"jsonrpc":"2.0","method":<subscribe method>,"params":{"subscription":id,"result":..}}`
//! and are sent only when the value changes after subscribing. `publish` samples the node
//! each tick. Deviation: base/base upgrades the HTTP port; this listens on its own port.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const ws = @import("../../utilities/ws/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc_ws = @import("../../utilities/rpc/ws.zig");
const protocol = @import("../protocol/root.zig");
const rollup_rpc = @import("../rpc/rollup.zig");
const SyncState = @import("../engine/state.zig").SyncState;

const L2BlockInfo = protocol.block.L2BlockInfo;
const ConnectionId = ws.server.ConnectionId;

pub const Topic = enum(u8) { unsafe_head, safe_head, finalized_head, engine_queue_size };
const topic_count = @typeInfo(Topic).@"enum".field_names.len;

const subscribe_methods = [topic_count][]const u8{
    "ws_subscribe_unsafe_head",
    "ws_subscribe_safe_head",
    "ws_subscribe_finalized_head",
    "dev_subscribe_engine_queue_size",
};
const unsubscribe_methods = [topic_count][]const u8{
    "ws_unsubscribe_unsafe_head",
    "ws_unsubscribe_safe_head",
    "ws_unsubscribe_finalized_head",
    "dev_unsubscribe_engine_queue_size",
};

pub const server_options: ws.server.Options = .{
    .connections_max = 16,
    .message_size_max = 64 * 1024,
    .send_buffer_size = 256 * 1024,
};
const scratch_size = 64 * 1024;

/// What subscribers watch, sampled from the node.
pub const Sample = struct { sync_state: SyncState, queue_size: u64 };

const Slot = struct {
    connection: ?ConnectionId = null,
    /// Subscription id per topic; 0 when not subscribed.
    subscriptions: [topic_count]u64 = @splat(0),
};

pub fn WsRpc(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Server = ws.Server(IO, *Self);
        const handlers: ws.server.Handlers(Server, *Self) = .{
            .on_open = on_open,
            .on_message = on_message,
            .on_close = on_close,
        };

        server: Server,
        backend: *const rollup_rpc.Backend,
        allocator: Allocator,
        slots: []Slot,
        scratch: []u8,
        next_id: u64 = 1,
        last: ?Sample = null,
        notifications: u64 = 0,
        send_failures: u64 = 0,

        /// `ws_rpc` must not move afterwards.
        pub fn init(
            ws_rpc: *Self,
            allocator: Allocator,
            io: *IO,
            backend: *const rollup_rpc.Backend,
        ) !void {
            const slots = try allocator.alloc(Slot, server_options.connections_max);
            errdefer allocator.free(slots);
            @memset(slots, .{});
            const scratch = try allocator.alloc(u8, scratch_size);
            errdefer allocator.free(scratch);
            ws_rpc.* = .{
                .server = undefined,
                .backend = backend,
                .allocator = allocator,
                .slots = slots,
                .scratch = scratch,
            };
            try ws_rpc.server.init(allocator, io, ws_rpc, &handlers, server_options);
            assert(ws_rpc.slots.len == server_options.connections_max);
        }

        /// Requires `stopped()`.
        pub fn deinit(ws_rpc: *Self) void {
            ws_rpc.server.deinit();
            ws_rpc.allocator.free(ws_rpc.slots);
            ws_rpc.allocator.free(ws_rpc.scratch);
            ws_rpc.* = undefined;
        }

        pub fn listen(ws_rpc: *Self, address: ws.server.Address) !ws.server.Address {
            return ws_rpc.server.listen(address);
        }

        pub fn stop(ws_rpc: *Self) void {
            ws_rpc.server.stop();
        }

        pub fn stopped(ws_rpc: *const Self) bool {
            return ws_rpc.server.stopped();
        }

        fn on_open(ws_rpc: *Self, _: *Server, id: ConnectionId) void {
            assert(id.index < ws_rpc.slots.len);
            ws_rpc.slots[id.index] = .{ .connection = id };
        }

        fn on_close(ws_rpc: *Self, _: *Server, id: ConnectionId, _: ws.server.Closed) void {
            assert(id.index < ws_rpc.slots.len);
            ws_rpc.slots[id.index] = .{};
        }

        fn on_message(
            ws_rpc: *Self,
            server: *Server,
            id: ConnectionId,
            message: ws.server.Message,
        ) void {
            assert(&ws_rpc.server == server);
            const payload = message.payload;
            if (ws_rpc.subscription_call(id, payload)) return;
            const Router = rollup_rpc.NodeRouter;
            const backend = ws_rpc.backend;
            rpc_ws.serve_message(Router, backend, server, id, message, ws_rpc.scratch) catch {
                ws_rpc.send_failures += 1;
            };
        }

        /// Handles a (un)subscribe request; false for any other message.
        fn subscription_call(ws_rpc: *Self, id: ConnectionId, payload: []const u8) bool {
            const method_raw = (json.find_path(payload, &.{"method"}) catch null) orelse
                return false;
            if (method_raw.len < 2 or method_raw[0] != '"') return false;
            const method = method_raw[1 .. method_raw.len - 1];
            const request_id = (json.find_path(payload, &.{"id"}) catch null) orelse "null";
            for (subscribe_methods, 0..) |name, index| {
                if (!std.mem.eql(u8, name, method)) continue;
                const subscription = ws_rpc.next_id;
                ws_rpc.next_id += 1;
                ws_rpc.slots[id.index].subscriptions[index] = subscription;
                ws_rpc.reply(id, request_id, "{d}", .{subscription});
                return true;
            }
            for (unsubscribe_methods, 0..) |name, index| {
                if (!std.mem.eql(u8, name, method)) continue;
                const params = (json.find_path(payload, &.{"params"}) catch null) orelse "[]";
                const wanted = parse_subscription_id(params) orelse 0;
                const slot = &ws_rpc.slots[id.index];
                const found = wanted != 0 and slot.subscriptions[index] == wanted;
                if (found) slot.subscriptions[index] = 0;
                ws_rpc.reply(id, request_id, "{}", .{found});
                return true;
            }
            return false;
        }

        fn reply(
            ws_rpc: *Self,
            id: ConnectionId,
            request_id: []const u8,
            comptime result_format: []const u8,
            result: anytype,
        ) void {
            const text = std.fmt.bufPrint(
                ws_rpc.scratch,
                "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":" ++ result_format ++ "}}",
                .{request_id} ++ result,
            ) catch {
                ws_rpc.send_failures += 1; // An id close to the 64 KiB message limit.
                return;
            };
            ws_rpc.server.send(id, .text, text) catch {
                ws_rpc.send_failures += 1;
            };
        }

        /// Notifies subscribers of every value that changed since the last sample.
        pub fn publish(ws_rpc: *Self, sample: Sample) void {
            const last = ws_rpc.last orelse {
                ws_rpc.last = sample;
                return;
            };
            ws_rpc.last = sample;
            const now = &sample.sync_state;
            const before = &last.sync_state;
            if (!now.unsafe_head.eql(before.unsafe_head)) {
                ws_rpc.notify_head(.unsafe_head, now.unsafe_head);
            }
            if (!now.safe_head.eql(before.safe_head)) ws_rpc.notify_head(.safe_head, now.safe_head);
            if (!now.finalized_head.eql(before.finalized_head)) {
                ws_rpc.notify_head(.finalized_head, now.finalized_head);
            }
            if (sample.queue_size != last.queue_size) ws_rpc.notify_queue(sample.queue_size);
            assert(ws_rpc.last != null);
        }

        fn notify_head(ws_rpc: *Self, topic: Topic, head: L2BlockInfo) void {
            ws_rpc.notify(topic, &head, write_head);
        }

        fn notify_queue(ws_rpc: *Self, size: u64) void {
            ws_rpc.notify(.engine_queue_size, &size, write_size);
        }

        fn notify(
            ws_rpc: *Self,
            topic: Topic,
            item: anytype,
            comptime write_item: fn (@TypeOf(item), *json.Writer) json.Writer.WriteError!void,
        ) void {
            const index = @backingInt(topic);
            for (ws_rpc.slots) |*slot| {
                const connection = slot.connection orelse continue;
                const subscription = slot.subscriptions[index];
                if (subscription == 0) continue;
                var out: std.Io.Writer = .fixed(ws_rpc.scratch);
                const method = subscribe_methods[index];
                // Proof: a head or an integer is far below the scratch size.
                write_notification(&out, method, subscription, item, write_item) catch unreachable;
                ws_rpc.server.send(connection, .text, out.buffered()) catch {
                    ws_rpc.send_failures += 1;
                    continue;
                };
                ws_rpc.notifications += 1;
            }
        }
    };
}

fn write_head(head: *const L2BlockInfo, writer: *json.Writer) json.Writer.WriteError!void {
    try rollup_rpc.write_l2_block_info(writer, head.*);
}

fn write_size(size: *const u64, writer: *json.Writer) json.Writer.WriteError!void {
    try writer.integer(size.*);
}

fn write_notification(
    out: *std.Io.Writer,
    method: []const u8,
    subscription: u64,
    item: anytype,
    comptime write_item: fn (@TypeOf(item), *json.Writer) json.Writer.WriteError!void,
) json.Writer.WriteError!void {
    var writer = json.Writer.init(out);
    try writer.begin_object();
    try writer.key("jsonrpc");
    try writer.string("2.0");
    try writer.key("method");
    try writer.string(method);
    try writer.key("params");
    try writer.begin_object();
    try writer.key("subscription");
    try writer.integer(subscription);
    try writer.key("result");
    try write_item(item, &writer);
    try writer.end_object();
    try writer.end_object();
}

/// The id in `[id]` (a number, or a quoted decimal or hex string); null when malformed.
pub fn parse_subscription_id(params: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, params, " \t\r\n");
    if (trimmed.len < 3 or trimmed[0] != '[' or trimmed[trimmed.len - 1] != ']') return null;
    var text = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t\r\n");
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') {
        text = text[1 .. text.len - 1];
    }
    if (std.mem.startsWith(u8, text, "0x")) return json.parse_quantity(u64, text) catch null;
    return std.fmt.parseInt(u64, text, 10) catch null;
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;

test "ws rpc: parse_subscription_id" {
    try testing.expectEqual(@as(?u64, 7), parse_subscription_id("[7]"));
    try testing.expectEqual(@as(?u64, 7), parse_subscription_id("[ \"7\" ]"));
    try testing.expectEqual(@as(?u64, 255), parse_subscription_id("[\"0xff\"]"));
    try testing.expectEqual(@as(?u64, null), parse_subscription_id("[]"));
    try testing.expectEqual(@as(?u64, null), parse_subscription_id("7"));
    try testing.expectEqual(@as(?u64, null), parse_subscription_id("[-1]"));
}

test "ws rpc: seeded fuzz over parse_subscription_id" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x75);
    const alphabet = "[]\"0x1fz -9,";
    for (0..2048) |_| {
        var buffer: [12]u8 = undefined;
        const len = prng.below(buffer.len + 1);
        for (buffer[0..len]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        _ = parse_subscription_id(buffer[0..len]);
        const value = prng.int(u32);
        var text: [24]u8 = undefined;
        const formatted = try std.fmt.bufPrint(&text, "[{d}]", .{value});
        try testing.expectEqual(@as(?u64, value), parse_subscription_id(formatted));
    }
}

fn fuzz_parse(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [64]u8 = undefined;
    const len = smith.slice(&input);
    _ = parse_subscription_id(input[0..len]);
}

test "ws rpc: fuzz parse_subscription_id" {
    try testing.fuzz({}, fuzz_parse, .{});
}

test "ws rpc: notification format" {
    var buffer: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    const size: u64 = 3;
    try write_notification(&out, "dev_subscribe_engine_queue_size", 9, &size, write_size);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"dev_subscribe_engine_queue_size","params":{"subscription":9,"result":3}}
    , out.buffered());
}

const sim_io = @import("../../utilities/io/root.zig");
const rpc_client = @import("../../utilities/rpc/client.zig");
const SimIo = sim_io.SimIo;
const SimWsRpc = WsRpc(SimIo);

const StubBackend = struct {
    const vtable: rollup_rpc.Backend.VTable = .{
        .sync_status = status_of,
        .output_at_block = output_of,
        .safe_db = db_of,
    };
    fn status_of(_: *anyopaque) rollup_rpc.SyncStatus {
        return .{};
    }
    fn output_of(
        _: *anyopaque,
        _: rollup_rpc.BlockTag,
    ) error{ NotAvailable, NotFound }!rollup_rpc.OutputAtBlock {
        return error.NotAvailable;
    }
    fn db_of(_: *anyopaque) ?*const @import("../safedb/root.zig").SafeDB {
        return null;
    }
};

const Recorder = struct {
    results: [8][64]u8 = undefined,
    result_sizes: [8]usize = @splat(0),
    result_count: usize = 0,
    methods: [8][40]u8 = undefined,
    method_sizes: [8]usize = @splat(0),
    numbers: [8]u64 = @splat(0),
    notification_count: usize = 0,

    const Client = rpc_ws.WsClient(SimIo, *Recorder);
    const handlers: rpc_ws.Handlers(Client, *Recorder) = .{
        .on_open = on_open,
        .on_result = on_result,
        .on_notification = on_notification,
        .on_close = on_close,
    };

    fn on_open(_: *Recorder, _: *Client) void {}
    fn on_close(_: *Recorder, _: *Client, _: ws.client.Closed) void {}

    fn on_result(
        recorder: *Recorder,
        _: *Client,
        _: u64,
        result: rpc_ws.CallError!rpc_ws.Result,
    ) void {
        const index = recorder.result_count;
        recorder.result_count += 1;
        const value = result catch return;
        const text = switch (value) {
            .ok => |raw| raw,
            .rpc_error => "error",
        };
        const size = @min(text.len, 64);
        @memcpy(recorder.results[index][0..size], text[0..size]);
        recorder.result_sizes[index] = size;
    }

    fn on_notification(recorder: *Recorder, _: *Client, notification: rpc_ws.Notification) void {
        const index = recorder.notification_count;
        recorder.notification_count += 1;
        const size = @min(notification.method.len, 40);
        @memcpy(recorder.methods[index][0..size], notification.method[0..size]);
        recorder.method_sizes[index] = size;
        const raw = json.find_path(notification.result, &.{"number"}) catch null;
        const number_text = raw orelse notification.result;
        recorder.numbers[index] = std.fmt.parseInt(u64, number_text, 10) catch 0;
    }

    fn result_text(recorder: *const Recorder, index: usize) []const u8 {
        return recorder.results[index][0..recorder.result_sizes[index]];
    }

    fn method(recorder: *const Recorder, index: usize) []const u8 {
        return recorder.methods[index][0..recorder.method_sizes[index]];
    }
};

fn unsubscribe_params(id: u64, writer: *json.Writer) json.Writer.WriteError!void {
    try writer.integer(id);
}

fn head_at(number: u64) SyncState {
    var state: SyncState = .{};
    state.unsafe_head.block_info.number = number;
    state.unsafe_head.block_info.hash.bytes[0] = @truncate(number);
    return state;
}

test "ws rpc: subscriptions notify on change; other methods go to the router" {
    const allocator = testing.allocator;
    var world = try sim_io.SimWorld.init(allocator, .{ .seed = 0x75 });
    defer world.deinit();
    var server_io: SimIo = undefined;
    const server_io_host = sim_io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
    try SimIo.init(&server_io, allocator, &world, .{ .host = server_io_host });
    defer server_io.deinit();
    var client_io: SimIo = undefined;
    const client_io_host = sim_io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
    try SimIo.init(&client_io, allocator, &world, .{ .host = client_io_host });
    defer client_io.deinit();
    var stub: u8 = 0;
    const rollup: protocol.rollup_config.RollupConfig = .{ .block_time = 2 };
    const backend: rollup_rpc.Backend = .{
        .context = &stub,
        .vtable = &StubBackend.vtable,
        .version = "test",
        .rollup = &rollup,
    };
    const ws_rpc = try allocator.create(SimWsRpc);
    defer allocator.destroy(ws_rpc);
    try ws_rpc.init(allocator, &server_io, &backend);
    defer {
        ws_rpc.stop();
        var rounds: u32 = 0;
        while (!ws_rpc.stopped() and rounds < 1000) : (rounds += 1) {
            world.run_for_ns(std.time.ns_per_ms);
        }
        ws_rpc.deinit();
    }
    const bound = try ws_rpc.listen(sim_io.Address.ip4(.{ 10, 0, 0, 1 }, 7546));
    var recorder: Recorder = .{};
    var client: Recorder.Client = undefined;
    try client.init(allocator, &client_io, bound, .{
        .ws = .{ .message_size_max = 4096, .send_buffer_size = 8192, .seed = 5 },
        .request_size_max = 1024,
    }, &recorder, &Recorder.handlers);
    defer client.deinit();
    client.connect();
    world.run_for_ns(100 * std.time.ns_per_ms);
    _ = try client.call("ws_subscribe_unsafe_head", {}, rpc_client.no_params);
    _ = try client.call("dev_subscribe_engine_queue_size", {}, rpc_client.no_params);
    world.run_for_ns(100 * std.time.ns_per_ms);
    try testing.expectEqualStrings("1", recorder.result_text(0));
    try testing.expectEqualStrings("2", recorder.result_text(1));
    ws_rpc.publish(.{ .sync_state = head_at(4), .queue_size = 0 }); // Baseline: no notification.
    ws_rpc.publish(.{ .sync_state = head_at(5), .queue_size = 2 });
    ws_rpc.publish(.{ .sync_state = head_at(5), .queue_size = 2 }); // Unchanged.
    world.run_for_ns(100 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 2), recorder.notification_count);
    try testing.expectEqualStrings("ws_subscribe_unsafe_head", recorder.method(0));
    try testing.expectEqual(@as(u64, 5), recorder.numbers[0]);
    try testing.expectEqualStrings("dev_subscribe_engine_queue_size", recorder.method(1));
    try testing.expectEqual(@as(u64, 2), recorder.numbers[1]);
    _ = try client.call("ws_unsubscribe_unsafe_head", @as(u64, 1), unsubscribe_params);
    _ = try client.call("ws_unsubscribe_unsafe_head", @as(u64, 1), unsubscribe_params);
    _ = try client.call("optimism_version", {}, rpc_client.no_params);
    world.run_for_ns(100 * std.time.ns_per_ms);
    try testing.expectEqualStrings("true", recorder.result_text(2));
    try testing.expectEqualStrings("false", recorder.result_text(3));
    try testing.expectEqualStrings("\"test\"", recorder.result_text(4));
    ws_rpc.publish(.{ .sync_state = head_at(6), .queue_size = 2 });
    world.run_for_ns(100 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 2), recorder.notification_count);
    try testing.expectEqual(@as(u64, 2), ws_rpc.notifications);
    client.abort();
    world.run_for_ns(100 * std.time.ns_per_ms);
}

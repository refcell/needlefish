//! Test harness: one simulated world with a server node running an HTTP handler and a
//! client node for the component under test, plus a canned JSON-RPC responder.

const std = @import("std");
const assert = std.debug.assert;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const object = @import("json_object.zig");

pub const limits: http.Limits = .{ .head_size_max = 2048, .body_size_max = 1024 * 1024 };

pub const client_options: http_client.Options = .{
    .send_buffer_size = 8 * 1024,
    .recv_buffer_size = limits.head_size_max + limits.body_size_max,
    .limits = limits,
};

pub fn Harness(comptime Context: type, comptime handler: http.server.Handler(Context)) type {
    return struct {
        const Self = @This();
        const Server = http.Server(io.SimIo, Context, handler);

        world: io.SimWorld,
        server_io: io.SimIo,
        client_io: io.SimIo,
        server: Server,
        address: io.Address,

        /// `harness` must not move afterwards.
        pub fn init(harness: *Self, context: Context, seed: u64) !void {
            try harness.init_world(context, .{ .seed = seed });
            assert(harness.world.options.seed == seed);
        }

        /// Like `init` with explicit world options (latency range, resets, refusals).
        pub fn init_world(harness: *Self, context: Context, options: io.sim.Options) !void {
            const allocator = std.testing.allocator;
            harness.world = try io.SimWorld.init(allocator, options);
            errdefer harness.world.deinit();
            const server_host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
            try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{
                .host = server_host,
            });
            errdefer harness.server_io.deinit();
            const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
            try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{
                .host = client_host,
            });
            errdefer harness.client_io.deinit();
            try harness.server.init(allocator, &harness.server_io, context, .{
                .connections_max = 2,
                .recv_buffer_size = 16 * 1024,
                .send_buffer_size = limits.body_size_max + 4096,
                .limits = .{ .head_size_max = 2048, .body_size_max = 8 * 1024 },
            });
            errdefer harness.server.deinit();
            harness.address = try harness.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));
            assert(harness.address.port == 8545);
        }

        pub fn deinit(harness: *Self) void {
            harness.server.deinit();
            harness.client_io.deinit();
            harness.server_io.deinit();
            harness.world.deinit();
        }

        pub fn run(harness: *Self) void {
            harness.world.run_for_ns(std.time.ns_per_s);
        }
    };
}

/// Answers JSON-RPC requests from a table: the first entry whose method matches and whose
/// `params` contain `params_contain` provides the raw `result` (unknown requests get null).
pub const FakeRpc = struct {
    pub const Entry = struct {
        method: []const u8,
        params_contain: []const u8 = "",
        result: []const u8 = "null",
        /// When set, answers with this raw JSON-RPC error object instead of `result`.
        rpc_error: ?[]const u8 = null,
    };

    entries: [32]Entry = undefined,
    count: u32 = 0,
    requests: u32 = 0,
    /// Last request body seen, for assertions on the wire format.
    last_body: [2048]u8 = undefined,
    last_body_size: usize = 0,
    /// Authorization header of the last request.
    last_authorization: [600]u8 = undefined,
    last_authorization_size: usize = 0,

    pub fn add(fake: *FakeRpc, entry: Entry) void {
        assert(fake.count < fake.entries.len);
        fake.entries[fake.count] = entry;
        fake.count += 1;
    }

    pub fn body(fake: *const FakeRpc) []const u8 {
        return fake.last_body[0..fake.last_body_size];
    }

    pub fn authorization(fake: *const FakeRpc) []const u8 {
        return fake.last_authorization[0..fake.last_authorization_size];
    }

    pub fn handle(
        fake: *FakeRpc,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        fake.requests += 1;
        const size = @min(request.body.len, fake.last_body.len);
        @memcpy(fake.last_body[0..size], request.body[0..size]);
        fake.last_body_size = size;
        const header = request.headers.get("Authorization") orelse "";
        const header_size = @min(header.len, fake.last_authorization.len);
        @memcpy(fake.last_authorization[0..header_size], header[0..header_size]);
        fake.last_authorization_size = header_size;
        const parsed = parse(request.body) catch return response.fail(400);
        const entry = fake.lookup(parsed.method, parsed.params);
        const member = if (entry.rpc_error != null) "error" else "result";
        const value = entry.rpc_error orelse entry.result;
        response.writer().print("{{\"jsonrpc\":\"2.0\",\"id\":{s},\"{s}\":{s}}}", .{
            parsed.id, member, value,
        }) catch return response.fail(500);
    }

    fn lookup(fake: *const FakeRpc, method: []const u8, params: []const u8) Entry {
        for (fake.entries[0..fake.count]) |entry| {
            if (!std.mem.eql(u8, entry.method, method)) continue;
            if (std.mem.indexOf(u8, params, entry.params_contain) == null) continue;
            return entry;
        }
        return .{ .method = method };
    }

    const Parsed = struct { id: []const u8, method: []const u8, params: []const u8 };

    fn parse(text: []const u8) object.Error!Parsed {
        var iterator = try object.ObjectIterator.init(text);
        var parsed: Parsed = .{ .id = "null", .method = "", .params = "" };
        while (try iterator.next()) |field| {
            if (std.mem.eql(u8, field.key, "id")) parsed.id = field.raw;
            if (std.mem.eql(u8, field.key, "method")) parsed.method = field.value.bytes;
            if (std.mem.eql(u8, field.key, "params")) parsed.params = field.raw;
        }
        return parsed;
    }
};

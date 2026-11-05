//! Large responses over SimIo: a handler that sizes its body up front
//! (`ensureUnusedCapacity`) past the connection's send buffer gets a shared large send
//! buffer, held until the response is sent. Plain writes past the end still fail with 500,
//! and a request that finds the pool busy or too small fails like a full buffer.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const io = @import("../io/root.zig");
const parser = @import("parser.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");

const Address = io.Address;
const send_buffer_size = 64 * 1024;
const large_send_buffer_size = 4 << 20;
/// Over 1 MiB, as a storage-heavy witness (~2.6 MB of JSON).
const large_body_bytes = 3 << 20;

/// The request body names the response: "sized:<n>" sizes `n` bytes up front, "plain:<n>"
/// writes them without asking.
const Producer = struct {
    fn handle(
        producer: *Producer,
        request: *const parser.Request,
        response: *server_module.ResponseBuilder,
    ) void {
        _ = producer;
        const separator = std.mem.indexOfScalar(u8, request.body, ':') orelse
            return response.fail(400);
        const size = std.fmt.parseInt(u32, request.body[separator + 1 ..], 10) catch
            return response.fail(400);
        const writer = response.writer();
        if (std.mem.eql(u8, request.body[0..separator], "sized")) {
            writer.ensureUnusedCapacity(size + 1) catch return response.fail(503);
        }
        write_pattern(writer, size) catch return response.fail(500);
    }
};

fn pattern_byte(index: usize) u8 {
    return "0123456789abcdef"[index % 16];
}

fn write_pattern(writer: *std.Io.Writer, size: u32) std.Io.Writer.Error!void {
    var index: u32 = 0;
    while (index < size) : (index += 1) try writer.writeByte(pattern_byte(index));
}

const Server = server_module.Server(io.SimIo, *Producer, Producer.handle);
const Client = client_module.Client(io.SimIo);

const Answer = struct {
    status: u16 = 0,
    size: usize = 0,
    pattern_ok: bool = false,
    done: bool = false,

    fn on_response(
        answer: *Answer,
        client: *Client,
        result: client_module.Error!*const parser.Response,
    ) void {
        _ = client;
        const response = result catch return;
        answer.status = response.status;
        answer.size = response.body.len;
        answer.pattern_ok = true;
        for (response.body, 0..) |byte, index| {
            if (byte != pattern_byte(index)) answer.pattern_ok = false;
        }
        answer.done = true;
    }
};

const Harness = struct {
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    producer: Producer = .{},
    server: Server,

    fn init(harness: *Harness) !void {
        harness.world = try io.SimWorld.init(testing.allocator, .{ .seed = 53 });
        try io.SimIo.init(&harness.server_io, testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.client_io, testing.allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.producer = .{};
        try harness.server.init(testing.allocator, &harness.server_io, &harness.producer, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = send_buffer_size,
            .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
            .large_send_buffers_max = 1,
            .large_send_buffer_size = large_send_buffer_size,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
    }

    fn client(harness: *Harness, address: Address) !Client {
        return Client.init(testing.allocator, &harness.client_io, address, .{
            .send_buffer_size = 4096,
            .recv_buffer_size = large_send_buffer_size,
            .limits = .{ .head_size_max = 1024, .body_size_max = large_send_buffer_size - 1024 },
        });
    }
};

fn send_request(client: *Client, answer: *Answer, body: []const u8) !void {
    answer.* = .{};
    try client.request(*Answer, answer, Answer.on_response, .POST, "/", &.{}, body);
}

test "http: a response sized up front over 1 MiB grows into a large send buffer" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    var client = try harness.client(bound);
    defer client.deinit();
    var answer: Answer = .{};

    try send_request(&client, &answer, std.fmt.comptimePrint("sized:{d}", .{large_body_bytes}));
    harness.world.run_for_ns(4 * std.time.ns_per_s);
    try testing.expect(answer.done);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expectEqual(@as(usize, large_body_bytes), answer.size);
    try testing.expect(answer.pattern_ok);
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    for (harness.server.connections) |*connection| {
        try testing.expect(connection.large_index == null);
    }

    // Writing past the end without sizing first still overflows into a 500.
    try send_request(&client, &answer, "plain:100000");
    harness.world.run_for_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 500), answer.status);
    // Beyond the large buffer: the rebase fails like a full buffer.
    const too_large = std.fmt.comptimePrint("sized:{d}", .{large_send_buffer_size});
    try send_request(&client, &answer, too_large);
    harness.world.run_for_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 503), answer.status);
    // Small responses stay in the connection's buffer.
    try send_request(&client, &answer, "sized:100");
    harness.world.run_for_ns(std.time.ns_per_s);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expectEqual(@as(usize, 100), answer.size);
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
}

test "http: a busy large send buffer pool fails like a full buffer" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
    var first = try harness.client(bound);
    defer first.deinit();
    var second = try harness.client(bound);
    defer second.deinit();
    var answers: [2]Answer = .{ .{}, .{} };
    const body = std.fmt.comptimePrint("sized:{d}", .{large_body_bytes});
    // Both requests arrive before the first response finishes sending.
    try send_request(&first, &answers[0], body);
    try send_request(&second, &answers[1], body);
    harness.world.run_for_ns(4 * std.time.ns_per_s);
    try testing.expect(answers[0].done and answers[1].done);
    var served: u32 = 0;
    var refused: u32 = 0;
    for (answers) |answer| {
        if (answer.status == 200 and answer.size == large_body_bytes and answer.pattern_ok) {
            served += 1;
        }
        if (answer.status == 503) refused += 1;
    }
    try testing.expectEqual(@as(u32, 1), served);
    try testing.expectEqual(@as(u32, 1), refused);
    try testing.expectEqual(@as(u64, 1), harness.server.responses_grown);
    for (harness.server.connections) |*connection| {
        try testing.expect(connection.large_index == null);
    }
}

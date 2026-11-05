const std = @import("std");

const io = @import("../io/root.zig");
const http = @import("../http/root.zig");
const json = @import("../json/root.zig");
const rpc = @import("../rpc/root.zig");
const upgrade_signal = @import("root.zig");
const contract = upgrade_signal.contract;

const Address = io.Address;
const contract_address: [20]u8 = @splat(0xc0);
const pinned_hash: [32]u8 = @splat(0xab);

const FakeL1 = struct {
    schedule: [20]u64 = undefined,
    schedule_count: u32 = 3,
    version: upgrade_signal.Version = .pack(1, 2, 3, 0),
    fail_call: bool = false,
    corrupt_schedule: bool = false,
    tags_seen: [16]u8 = undefined,
    tag_size: usize = 0,

    fn block_by_number(l1: *FakeL1, call: *rpc.Call) rpc.HandlerError!void {
        const tag = try call.params.string();
        _ = try call.params.boolean();
        try call.params.finish();
        @memcpy(l1.tags_seen[0..tag.len], tag);
        l1.tag_size = tag.len;
        try call.writer.begin_object();
        try call.writer.key("number");
        try call.writer.quantity(@as(u64, 777));
        try call.writer.key("hash");
        try call.writer.data(&pinned_hash);
        try call.writer.end_object();
    }

    fn eth_call(l1: *FakeL1, call: *rpc.Call) rpc.HandlerError!void {
        const transaction = try call.params.raw();
        const block = try call.params.raw();
        try call.params.finish();
        const to = json.find_path(transaction, &.{"to"}) catch null;
        const hash = json.find_path(block, &.{"blockHash"}) catch null;
        const data = (json.find_path(transaction, &.{"data"}) catch null) orelse
            return call.fail(rpc.code.invalid_params, "no data");
        // The reader calls the configured contract at the pinned block hash.
        const to_bytes = json.parse_fixed(20, to.?[1 .. to.?.len - 1]) catch unreachable;
        const hash_bytes = json.parse_fixed(32, hash.?[1 .. hash.?.len - 1]) catch unreachable;
        std.debug.assert(std.mem.eql(u8, &to_bytes, &contract_address));
        std.debug.assert(std.mem.eql(u8, &hash_bytes, &pinned_hash));
        if (l1.fail_call) return call.fail(-32000, "execution reverted");
        var selector: [4]u8 = undefined;
        _ = json.parse_data(data[1 .. data.len - 1], &selector) catch
            return call.fail(rpc.code.invalid_params, "bad selector");
        var buffer: [64 + 32 * 20]u8 = undefined;
        if (std.mem.eql(u8, &selector, &contract.get_schedule_selector)) {
            const encoded = contract.encode_schedule(l1.schedule[0..l1.schedule_count], &buffer);
            if (l1.corrupt_schedule) encoded[31] = 0x40;
            return call.writer.data(encoded);
        }
        std.mem.writeInt(u256, buffer[0..32], l1.version.packed_value, .big);
        try call.writer.data(buffer[0..32]);
    }

    const methods = [_]rpc.Method(*FakeL1){
        .{ .name = "eth_getBlockByNumber", .handler = block_by_number },
        .{ .name = "eth_call", .handler = eth_call },
    };
    const Router = rpc.Router(*FakeL1, &methods);

    fn handle(
        l1: *FakeL1,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        _ = Router.handle(l1, request.body, response.writer());
    }
};

const Outcome = struct {
    done: bool = false,
    result: upgrade_signal.reader.Error!*const upgrade_signal.Schedule = undefined,

    fn on_read(
        outcome: *Outcome,
        result: upgrade_signal.reader.Error!*const upgrade_signal.Schedule,
    ) void {
        std.debug.assert(!outcome.done);
        outcome.done = true;
        outcome.result = result;
    }
};

const Harness = struct {
    world: io.SimWorld,
    l1_io: io.SimIo,
    node_io: io.SimIo,
    l1: FakeL1,
    server: http.Server(io.SimIo, *FakeL1, FakeL1.handle),
    reader: upgrade_signal.Reader(io.SimIo, *Outcome),

    fn init(harness: *Harness, seed: u64, tag: upgrade_signal.BlockTag) !void {
        const allocator = std.testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 23 });
        try io.SimIo.init(&harness.l1_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.node_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.l1 = .{};
        harness.l1.schedule[0..3].* = .{ 0, 1_700_000_000, 1_800_000_000 };
        try harness.server.init(allocator, &harness.l1_io, &harness.l1, .{
            .connections_max = 2,
            .recv_buffer_size = 4096,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 2048 },
        });
        const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        harness.reader = try .init(allocator, &harness.node_io, bound, contract_address, .{
            .block_tag = tag,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.reader.deinit();
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 1000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.node_io.deinit();
        harness.l1_io.deinit();
        harness.world.deinit();
    }

    fn read(harness: *Harness, outcome: *Outcome) !void {
        outcome.* = .{};
        try harness.reader.read(outcome, Outcome.on_read);
        try std.testing.expectError(error.Busy, harness.reader.read(outcome, Outcome.on_read));
        var rounds: u32 = 0;
        while (!outcome.done and rounds < 1000) : (rounds += 1) {
            harness.world.run_for_ns(10 * std.time.ns_per_ms);
        }
        try std.testing.expect(outcome.done and !harness.reader.busy());
    }
};

test "upgrade_signal: reader pins a block and reads both views" {
    var harness: Harness = undefined;
    try harness.init(61, .safe);
    defer harness.deinit();
    var outcome: Outcome = .{};
    try harness.read(&outcome);
    const schedule = try outcome.result;
    try std.testing.expectEqualStrings("safe", harness.l1.tags_seen[0..harness.l1.tag_size]);
    try std.testing.expectEqual(@as(u64, 777), schedule.l1_block_number);
    try std.testing.expectEqual(@as(u32, 3), schedule.signals_count());
    try std.testing.expectEqual(@as(?u64, 0), schedule.activation("regolith"));
    try std.testing.expectEqual(@as(?u64, 1_800_000_000), schedule.activation("delta"));
    try std.testing.expect(schedule.activation("ecotone") == null);
    try std.testing.expect(schedule.minimum_version.eql(.pack(1, 2, 3, 0)));
    // Entries beyond the known upgrade IDs are ignored.
    harness.l1.schedule_count = 20;
    for (harness.l1.schedule[3..20], 3..) |*t, i| t.* = 1_900_000_000 + i;
    try harness.read(&outcome);
    const longer = try outcome.result;
    try std.testing.expectEqual(@as(u32, 20), longer.count);
    try std.testing.expectEqual(@as(u32, contract.upgrade_ids.len), longer.signals_count());
    try std.testing.expectEqual(@as(?u64, 1_900_000_014), longer.activation("everest"));
}

test "upgrade_signal: reader errors" {
    var harness: Harness = undefined;
    try harness.init(62, .finalized);
    defer harness.deinit();
    var outcome: Outcome = .{};
    harness.l1.fail_call = true;
    try harness.read(&outcome);
    try std.testing.expectError(error.Provider, outcome.result);
    harness.l1.fail_call = false;
    harness.l1.corrupt_schedule = true;
    try harness.read(&outcome);
    try std.testing.expectError(error.Decode, outcome.result);
    harness.l1.corrupt_schedule = false;
    harness.l1.schedule_count = 0;
    try harness.read(&outcome);
    try std.testing.expectError(error.EmptySchedule, outcome.result);
    try std.testing.expectEqualStrings("finalized", harness.l1.tags_seen[0..harness.l1.tag_size]);
}

test "upgrade_signal: block tag poll intervals" {
    const BlockTag = upgrade_signal.BlockTag;
    const s = std.time.ns_per_s;
    try std.testing.expectEqual(@as(u64, 900 * s), BlockTag.finalized.poll_interval_ns());
    try std.testing.expectEqual(@as(u64, 384 * s), BlockTag.safe.poll_interval_ns());
    try std.testing.expectEqual(@as(u64, 12 * s), BlockTag.latest.poll_interval_ns());
}

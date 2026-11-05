const std = @import("std");

const io = @import("../io/root.zig");
const http = @import("../http/root.zig");
const json = @import("../json/root.zig");
const rpc = @import("../rpc/root.zig");
const l1_head = @import("root.zig");

const Address = io.Address;
const expectEqual = std.testing.expectEqual;

fn block_hash(number: u64) [32]u8 {
    var hash: [32]u8 = @splat(0xb0);
    std.mem.writeInt(u64, hash[24..32], number, .big);
    return hash;
}

/// Serves both sides: a rollup node (`optimism_outputAtBlock`) and L1 (`eth_getBlockByNumber`).
const FakeChain = struct {
    /// L2 block `n` has L1 origin `n / 6`.
    finalized: u64 = 100,
    /// Blocks above this are unknown (`null`).
    known_max: u64 = 1000,
    /// One block number this node does not have.
    missing: ?u64 = null,
    fail_output: bool = false,
    quoted_origin: bool = false,

    fn output_at_block(chain: *FakeChain, call: *rpc.Call) rpc.HandlerError!void {
        const l2 = try call.params.quantity(u64);
        try call.params.finish();
        if (chain.fail_output) return call.fail(rpc.code.internal_error, "no output");
        const writer = call.writer;
        try writer.begin_object();
        try writer.key("version");
        try writer.quantity(@as(u64, 0));
        try writer.key("blockRef");
        try writer.begin_object();
        try writer.key("number");
        try writer.integer(l2);
        try writer.key("l1origin");
        try writer.begin_object();
        try writer.key("hash");
        try writer.data(&block_hash(l2 / 6));
        try writer.key("number");
        if (chain.quoted_origin) try writer.quantity(l2 / 6) else try writer.integer(l2 / 6);
        try writer.end_object();
        try writer.end_object();
        try writer.end_object();
    }

    fn block_by_number(chain: *FakeChain, call: *rpc.Call) rpc.HandlerError!void {
        const tag = try call.params.raw();
        _ = try call.params.boolean();
        try call.params.finish();
        const number = if (std.mem.eql(u8, tag, "\"finalized\""))
            chain.finalized
        else
            json.parse_quantity(u64, tag[1 .. tag.len - 1]) catch
                return call.fail(rpc.code.invalid_params, "bad block");
        if (number > chain.known_max or number == chain.missing) {
            return call.writer.null_value();
        }
        const writer = call.writer;
        try writer.begin_object();
        try writer.key("parentHash");
        try writer.data(&block_hash(number -| 1));
        try writer.key("number");
        try writer.quantity(number);
        try writer.key("hash");
        try writer.data(&block_hash(number));
        try writer.end_object();
    }

    const methods = [_]rpc.Method(*FakeChain){
        .{ .name = "optimism_outputAtBlock", .handler = output_at_block },
        .{ .name = "eth_getBlockByNumber", .handler = block_by_number },
    };
    const Router = rpc.Router(*FakeChain, &methods);

    fn handle(
        chain: *FakeChain,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        _ = Router.handle(chain, request.body, response.writer());
    }
};

const Outcome = struct {
    result: ?(l1_head.Error!l1_head.Head) = null,

    fn done(outcome: *Outcome, result: l1_head.Error!l1_head.Head) void {
        std.debug.assert(outcome.result == null);
        outcome.result = result;
    }
};

const Harness = struct {
    world: io.SimWorld,
    node_io: io.SimIo,
    prover_io: io.SimIo,
    chain: FakeChain,
    server: http.Server(io.SimIo, *FakeChain, FakeChain.handle),
    calculator: l1_head.Calculator(io.SimIo, *Outcome),

    fn init(harness: *Harness, seed: u64) !void {
        const allocator = std.testing.allocator;
        harness.world = try io.SimWorld.init(allocator, .{ .seed = seed, .segment_size_max = 17 });
        try io.SimIo.init(&harness.node_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        try io.SimIo.init(&harness.prover_io, allocator, &harness.world, .{
            .host = Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        harness.chain = .{};
        try harness.server.init(allocator, &harness.node_io, &harness.chain, .{
            .connections_max = 4,
            .recv_buffer_size = 4096,
            .send_buffer_size = 4096,
            .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
        });
        const bound = try harness.server.listen(Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        harness.calculator = try .init(allocator, &harness.prover_io, bound, bound, .{});
    }

    fn deinit(harness: *Harness) void {
        harness.calculator.deinit();
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 1000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.prover_io.deinit();
        harness.node_io.deinit();
        harness.world.deinit();
    }

    fn run(harness: *Harness, l2: u64, window: u64) !(l1_head.Error!l1_head.Head) {
        var outcome: Outcome = .{};
        try harness.calculator.calculate(l2, window, &outcome, Outcome.done);
        try std.testing.expectError(
            error.Busy,
            harness.calculator.calculate(l2, window, &outcome, Outcome.done),
        );
        var rounds: u32 = 0;
        while (outcome.result == null and rounds < 1000) : (rounds += 1) {
            harness.world.run_for_ns(10 * std.time.ns_per_ms);
        }
        try std.testing.expect(!harness.calculator.busy());
        return outcome.result.?;
    }
};

test "l1_head: cap_head" {
    try expectEqual(@as(u64, 15), try l1_head.cap_head(10, 5, 100));
    try expectEqual(@as(u64, 12), try l1_head.cap_head(10, 5, 12));
    try expectEqual(@as(u64, 0), try l1_head.cap_head(0, 0, 0));
    try std.testing.expectError(
        error.SequenceWindowOverflow,
        l1_head.cap_head(std.math.maxInt(u64), 1, 5),
    );
}

test "l1_head: calculator over SimIo" {
    var harness: Harness = undefined;
    try harness.init(41);
    defer harness.deinit();
    // Below finalized: origin 60 / 6 = 10, plus window 5, fetched by number.
    const below = try (try harness.run(60, 5));
    try expectEqual(@as(u64, 15), below.number);
    try std.testing.expectEqualSlices(u8, &block_hash(15), &below.hash);
    // Capped at finalized (100): uses the finalized block's hash directly.
    harness.chain.quoted_origin = true;
    const capped = try (try harness.run(600, 3600));
    try expectEqual(@as(u64, 100), capped.number);
    try std.testing.expectEqualSlices(u8, &block_hash(100), &capped.hash);
    // Exactly finalized.
    const exact = try (try harness.run(540, 10));
    try expectEqual(@as(u64, 100), exact.number);
}

test "l1_head: calculator errors" {
    var harness: Harness = undefined;
    try harness.init(42);
    defer harness.deinit();
    harness.chain.fail_output = true;
    try std.testing.expectError(error.L1OriginFetch, try harness.run(60, 5));
    harness.chain.fail_output = false;
    const overflow = try harness.run(60, std.math.maxInt(u64));
    try std.testing.expectError(error.SequenceWindowOverflow, overflow);
    harness.chain.known_max = 50; // Finalized (100) is unknown.
    try std.testing.expectError(error.FinalizedBlockMissing, try harness.run(60, 5));
    harness.chain.known_max = 1000;
    harness.chain.missing = 15; // Finalized exists, the capped head does not.
    try std.testing.expectError(error.BlockMissing, try harness.run(60, 5));
    harness.chain.missing = null;
    const head = try (try harness.run(60, 5));
    try expectEqual(@as(u64, 15), head.number);
}

test "l1_head: parsers" {
    try expectEqual(@as(u64, 7), try l1_head.parse_number("7"));
    try expectEqual(@as(u64, 255), try l1_head.parse_number("\"0xff\""));
    try std.testing.expectError(error.Invalid, l1_head.parse_number("-1"));
    try std.testing.expectError(error.Invalid, l1_head.parse_number("\"7\""));
    try std.testing.expectError(error.Missing, l1_head.parse_block(" null "));
    try std.testing.expectError(error.Invalid, l1_head.parse_block("{\"number\":\"0x1\"}"));
    try std.testing.expectError(error.Invalid, l1_head.parse_l1_origin("{\"blockRef\":{}}"));
}

fn parse_arbitrary(raw: []const u8) void {
    _ = l1_head.parse_block(raw) catch {};
    _ = l1_head.parse_l1_origin(raw) catch {};
    _ = l1_head.parse_number(raw) catch {};
}

test "l1_head: seeded fuzz parsers" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x11ead);
    const pieces = [_][]const u8{
        "{",    "}",          ":",        ",",        "[",            "]",            "12",
        "null", "\"number\"", "\"hash\"", "\"0x1f\"", "\"blockRef\"", "\"l1origin\"", "\"0xab\"",
    };
    var buffer: [256]u8 = undefined;
    for (0..3000) |_| {
        var size: usize = 0;
        for (0..prng.below(16)) |_| {
            const piece = pieces[prng.below(pieces.len)];
            if (size + piece.len > buffer.len) break;
            @memcpy(buffer[size..][0..piece.len], piece);
            size += piece.len;
        }
        parse_arbitrary(buffer[0..size]);
    }
}

fn fuzz_parsers(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var buffer: [256]u8 = undefined;
    parse_arbitrary(buffer[0..smith.slice(&buffer)]);
}

test "l1_head: fuzz parsers" {
    try std.testing.fuzz({}, fuzz_parsers, .{});
}

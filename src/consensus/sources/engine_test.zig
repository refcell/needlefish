//! Engine API tests: request encoding, result decoding, L2 block info from the L1 info
//! deposit, and the authenticated client over the simulated network.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const json = @import("../../utilities/json/root.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const format = @import("../../execution/rpc/format.zig");
const protocol = @import("../protocol/root.zig");
const harness_module = @import("sim_harness.zig");
const engine_json = @import("engine_json.zig");
const engine_client = @import("engine_client.zig");
const l2_block = @import("l2_block.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Engine = engine_client.EngineClient(io.SimIo);
const Header = @import("../../common/consensus/root.zig").Header;

fn contains(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

fn render(buffer: []u8, comptime write: anytype, args: anytype) ![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try writer.begin_array();
    try @call(.auto, write, .{&writer} ++ args);
    try writer.end_array();
    return out.buffered();
}

test "engine json: forkchoice params with OP attributes" {
    const state: engine_json.ForkchoiceState = .{
        .head_block_hash = .init(@splat(1)),
        .safe_block_hash = .init(@splat(2)),
        .finalized_block_hash = .init(@splat(3)),
    };
    const transactions = [_][]const u8{"\x7e\x01"};
    const attributes: engine_json.PayloadAttributes = .{
        .timestamp = 0x10,
        .prev_randao = .zero,
        .suggested_fee_recipient = .zero,
        .withdrawals = &.{},
        .parent_beacon_block_root = .zero,
        .transactions = &transactions,
        .no_tx_pool = true,
        .gas_limit = 30_000_000,
        .eip1559_params = .{ 0, 0, 0, 0xfa, 0, 0, 0, 6 },
        .min_base_fee = 1,
    };
    var buffer: [2048]u8 = undefined;
    const text = try render(&buffer, engine_json.write_forkchoice_params, .{ &state, &attributes });
    const zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    try testing.expect(std.mem.startsWith(u8, text, "[{\"headBlockHash\":\"0x0101"));
    try testing.expect(contains(text, "\"timestamp\":\"0x10\",\"prevRandao\":\"" ++ zero));
    try testing.expect(contains(text, "\"withdrawals\":[],\"parentBeaconBlockRoot\""));
    try testing.expect(contains(text, "\"transactions\":[\"0x7e01\"],\"noTxPool\":true," ++
        "\"gasLimit\":\"0x1c9c380\",\"eip1559Params\":\"0x000000fa00000006\"," ++
        "\"minBaseFee\":\"0x1\"}]"));
    try json.validate(text);
    const bare = try render(&buffer, engine_json.write_forkchoice_params, .{ &state, null });
    try testing.expect(std.mem.endsWith(u8, bare, "},null]"));
}

fn test_payload(transactions: []const []const u8) engine_json.ExecutionPayload {
    return .{
        .parent_hash = .init(@splat(1)),
        .fee_recipient = .zero,
        .state_root = .init(@splat(2)),
        .receipts_root = .init(@splat(3)),
        .logs_bloom = .zero,
        .prev_randao = .init(@splat(4)),
        .block_number = 77,
        .gas_limit = 30_000_000,
        .gas_used = 21_000,
        .timestamp = 1_700_000_002,
        .extra_data = &.{ 0, 0, 0, 0, 0x32, 0, 0, 0, 6 },
        .base_fee_per_gas = 1_000_000_000,
        .block_hash = .init(@splat(5)),
        .transactions = transactions,
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .withdrawals_root = .init(@splat(6)),
    };
}

test "engine json: new payload params and payload envelope round trip" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const transactions = [_][]const u8{ "\x7e\xaa", "\x02\xbb\xcc" };
    const payload = test_payload(&transactions);
    const params: engine_json.NewPayloadParams = .{ .parent_beacon_block_root = .init(@splat(9)) };
    var buffer: [4096]u8 = undefined;
    const write_params = engine_json.write_new_payload_params;
    const v4 = try render(&buffer, write_params, .{ .v4, &payload, &params });
    try testing.expect(std.mem.indexOf(u8, v4, "},[],\"0x0909") != null);
    try testing.expect(std.mem.endsWith(u8, v4, "\",[]]"));
    const v2 = try render(&buffer, write_params, .{ .v2, &payload, &params });
    try testing.expect(std.mem.endsWith(u8, v2, "}]"));

    var out: std.Io.Writer = .fixed(&buffer);
    var writer = json.Writer.init(&out);
    try writer.begin_object();
    try writer.key("executionPayload");
    try engine_json.write_payload(&writer, &payload);
    try writer.key("blockValue");
    try writer.quantity(@as(u64, 0x1234));
    try writer.key("blobsBundle");
    try writer.raw("{\"commitments\":[],\"proofs\":[],\"blobs\":[]}");
    try writer.key("shouldOverrideBuilder");
    try writer.boolean(false);
    try writer.key("parentBeaconBlockRoot");
    try writer.data(&params.parent_beacon_block_root.?.bytes);
    try writer.key("executionRequests");
    try writer.raw("[]");
    try writer.end_object();
    const allocator = arena.allocator();
    const envelope = try engine_json.decode_payload_envelope(allocator, out.buffered(), .{});
    try testing.expectEqual(@as(u256, 0x1234), envelope.block_value);
    try testing.expect(envelope.parent_beacon_block_root.?.eql(params.parent_beacon_block_root.?));
    const decoded = envelope.payload;
    try testing.expectEqual(@as(u64, 77), decoded.block_number);
    try testing.expectEqual(@as(usize, 2), decoded.transactions.len);
    try testing.expectEqualStrings(transactions[1], decoded.transactions[1]);
    try testing.expectEqualSlices(u8, payload.extra_data, decoded.extra_data);
    try testing.expect(decoded.withdrawals_root.?.eql(payload.withdrawals_root.?));
    try testing.expectEqual(@as(u256, 1_000_000_000), decoded.base_fee_per_gas);
    try testing.expectEqual(@as(usize, 0), envelope.execution_requests.?.len);
}

test "engine json: payload status and forkchoice results" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const valid = try engine_json.decode_forkchoice_updated(allocator,
        \\{"payloadStatus":{"status":"VALID","latestValidHash":"0x0101010101010101010101010101010101010101010101010101010101010101","validationError":null},"payloadId":"0x0102030405060708"}
    , .{});
    try testing.expectEqual(.valid, valid.payload_status.status);
    try testing.expectEqual(@as(u8, 8), valid.payload_id.?[7]);
    const invalid = try engine_json.decode_payload_status(allocator,
        \\{"status":"INVALID","latestValidHash":null,"validationError":"bad block"}
    , .{});
    try testing.expectEqual(.invalid, invalid.status);
    try testing.expectEqualStrings("bad block", invalid.validation_error.?);
    try testing.expectError(error.InvalidField, engine_json.decode_payload_status(allocator,
        \\{"status":"MAYBE"}
    , .{}));
    try testing.expectError(error.MissingField, engine_json.decode_forkchoice_updated(allocator,
        \\{"payloadId":null}
    , .{}));
}

/// An L2 block JSON whose first transaction is an Ecotone L1 info deposit.
fn l2_block_json(buffer: []u8, number: u64) ![]const u8 {
    const info: protocol.l1_info.L1BlockInfo = .{
        .format = .ecotone,
        .number = 500,
        .time = 1_700_000_000,
        .block_hash = .init(@splat(0x55)),
        .sequence_number = 3,
    };
    var calldata: [protocol.l1_info.calldata_length_max]u8 = undefined;
    const input = info.encode_calldata(&calldata);
    const l2_header: Header = .{ .number = number, .timestamp = 2 };
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try writer.begin_object();
    try format.header_fields(&writer, &l2_header, l2_header.hash().bytes, 100);
    try writer.key("transactions");
    try writer.begin_array();
    try writer.begin_object();
    try format.field_quantity(&writer, "type", @as(u8, 0x7e));
    try format.field_data(&writer, "input", input);
    try writer.end_object();
    try writer.end_array();
    try writer.end_object();
    return out.buffered();
}

test "l2 block: origin from the L1 info deposit, genesis from the rollup config" {
    var buffer: [4096]u8 = undefined;
    const text = try l2_block_json(&buffer, 9);
    const genesis: protocol.rollup_config.ChainGenesis = .{
        .l1 = .{ .number = 400, .hash = .init(@splat(0x44)) },
        .l2 = .{ .number = 0, .hash = .init(@splat(0x01)) },
    };
    const info = try l2_block.decode(text, &genesis);
    try testing.expectEqual(@as(u64, 9), info.block_info.number);
    try testing.expectEqual(@as(u64, 500), info.l1_origin.number);
    try testing.expect(info.l1_origin.hash.eql(.init(@splat(0x55))));
    try testing.expectEqual(@as(u64, 3), info.sequence_number);
    var at_genesis = genesis;
    at_genesis.l2.number = 9;
    try testing.expectError(error.GenesisMismatch, l2_block.decode(text, &at_genesis));
    at_genesis.l2.hash = info.block_info.hash;
    const anchored = try l2_block.decode(text, &at_genesis);
    try testing.expectEqual(@as(u64, 400), anchored.l1_origin.number);
    try testing.expectEqual(@as(u64, 0), anchored.sequence_number);
}

const Outcome = struct {
    response: ?engine_client.Error!engine_client.Response = null,

    fn on_response(
        outcome: *Outcome,
        engine: *Engine,
        result: engine_client.Error!engine_client.Response,
    ) void {
        _ = engine;
        outcome.response = result;
    }
};

test "engine client: authenticated calls over SimIo" {
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "engine_forkchoiceUpdatedV3", .result =
        \\{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":null}
    });
    fake.add(.{ .method = "engine_getPayloadV4", .rpc_error =
        \\{"code":-38001,"message":"Unknown payload"}
    });
    var block_buffer: [4096]u8 = undefined;
    const block_text = try l2_block_json(&block_buffer, 9);
    const by_number = "eth_getBlockByNumber";
    fake.add(.{ .method = by_number, .params_contain = "\"0x9\"", .result = block_text });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x33);
    defer harness.deinit();
    const secret: jwt.Secret = .{ .bytes = @splat(0x11) };
    var engine: Engine = undefined;
    const http_options = harness_module.client_options;
    try engine.init(testing.allocator, &harness.client_io, harness.address, http_options, secret, .{
        .genesis = .{},
        .request_size_max = 4096,
    });
    defer engine.deinit();

    var outcome: Outcome = .{};
    const state: engine_json.ForkchoiceState = .{
        .head_block_hash = .zero,
        .safe_block_hash = .zero,
        .finalized_block_hash = .zero,
    };
    try engine.forkchoice_updated(.v3, &state, null, *Outcome, &outcome, Outcome.on_response);
    const busy = engine.get_payload(.v4, @splat(0), *Outcome, &outcome, Outcome.on_response);
    try testing.expectError(error.Busy, busy);
    harness.run();
    const updated = (try outcome.response.?).forkchoice_updated;
    try testing.expectEqual(.syncing, updated.payload_status.status);
    try testing.expect(contains(fake.body(), "\"method\":\"engine_forkchoiceUpdatedV3\""));
    const token = jwt.bearer_token(fake.authorization()).?;
    const now_s = harness.client_io.now_realtime_ns() / std.time.ns_per_s;
    _ = try jwt.verify(secret, token, now_s);

    try engine.get_payload(.v4, @splat(7), *Outcome, &outcome, Outcome.on_response);
    harness.run();
    try testing.expectError(error.UnknownPayload, outcome.response.?);
    try testing.expectEqual(@as(i64, -38001), engine.last_rpc_error_code);

    try engine.l2_block_info(.{ .number = 9 }, *Outcome, &outcome, Outcome.on_response);
    harness.run();
    const block = (try outcome.response.?).l2_block;
    try testing.expectEqual(@as(u64, 3), block.sequence_number);
    try engine.l2_block_info(.latest, *Outcome, &outcome, Outcome.on_response);
    harness.run();
    try testing.expectError(error.BlockNotFound, outcome.response.?);
}

fn decode_engine_arbitrary(input: []const u8) void {
    var memory: [32 * 1024]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    const allocator = fixed.allocator();
    json.validate(input) catch return;
    _ = engine_json.decode_payload_envelope(allocator, input, .{}) catch {};
    fixed.reset();
    _ = engine_json.decode_forkchoice_updated(allocator, input, .{}) catch {};
    const genesis: protocol.rollup_config.ChainGenesis = .{};
    _ = l2_block.decode(input, &genesis) catch {};
}

test "engine json: seeded fuzz of mutated results" {
    var block_buffer: [4096]u8 = undefined;
    const block = try l2_block_json(&block_buffer, 9);
    const seeds = [_][]const u8{
        block,
        \\{"payloadStatus":{"status":"VALID","latestValidHash":null},"payloadId":"0x0102030405060708"}
        ,
        \\{"executionPayload":{"parentHash":"0x00","transactions":["0x01"],"withdrawals":[]},"blockValue":"0x1"}
    };
    var prng = Prng.init(0xe9);
    var buffer: [4096]u8 = undefined;
    for (0..1000) |_| {
        const seed = seeds[prng.below(seeds.len)];
        @memcpy(buffer[0..seed.len], seed);
        var size = seed.len;
        for (0..prng.range(1, 3)) |_| {
            const position = prng.below(size);
            switch (prng.below(3)) {
                0 => buffer[position] = "{}[],:\"0x1fn"[prng.below(12)],
                1 => size = position + 1,
                2 => buffer[position] = prng.int(u8),
                else => unreachable,
            }
        }
        decode_engine_arbitrary(buffer[0..size]);
    }
}

fn fuzz_engine(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [2048]u8 = undefined;
    const size = smith.slice(&input);
    decode_engine_arbitrary(input[0..size]);
}

test "engine json: fuzz decoders" {
    try std.testing.fuzz({}, fuzz_engine, .{});
}

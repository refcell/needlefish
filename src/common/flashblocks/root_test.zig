const std = @import("std");
const testing = std.testing;
const flashblocks = @import("root.zig");
const comp = @import("../../batcher/comp/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const zero_bloom = "0x" ++ @as([512]u8, @splat('0'));

/// base/base `V0_4_1_PAYLOAD_JSON`, plus an old-format metadata extra field.
const v0_4_1_json =
    \\{"payload_id":"0x0000000000000000","index":0,"base":{
    \\"parent_beacon_block_root":"0x0101010101010101010101010101010101010101010101010101010101010101",
    \\"parent_hash":"0x0202020202020202020202020202020202020202020202020202020202020202",
    \\"fee_recipient":"0x0000000000000000000000000000000000000000",
    \\"prev_randao":"0x0303030303030303030303030303030303030303030303030303030303030303",
    \\"block_number":"0x9","gas_limit":"0xf4240","timestamp":"0x6553f100",
    \\"extra_data":"0xaabb","base_fee_per_gas":"0xa"},"diff":{
    \\"state_root":"0x0404040404040404040404040404040404040404040404040404040404040404",
    \\"receipts_root":"0x0505050505050505050505050505050505050505050505050505050505050505",
    \\"logs_bloom":"
++ zero_bloom ++
    \\","gas_used":"0x7a120",
    \\"block_hash":"0x0606060606060606060606060606060606060606060606060606060606060606",
    \\"transactions":["0x0102"],"withdrawals":[],
    \\"withdrawals_root":"0x0707070707070707070707070707070707070707070707070707070707070707",
    \\"blob_gas_used":"0x2c"},"metadata":{"block_number":1234,"receipts":{}}}
;

fn expect_v0_4_1(flashblock: flashblocks.Flashblock) !void {
    try testing.expectEqual(@as(u64, 0), flashblock.index);
    const base = flashblock.base.?;
    try testing.expectEqual(@as(u64, 9), base.block_number);
    try testing.expectEqual(@as(u64, 1_000_000), base.gas_limit);
    try testing.expectEqual(@as(u64, 1_700_000_000), base.timestamp);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, base.extra_data);
    try testing.expectEqual(@as(u256, 10), base.base_fee_per_gas);
    try testing.expectEqual(@as(u8, 0x02), base.parent_hash.bytes[31]);
    try testing.expectEqual(@as(u64, 500_000), flashblock.diff.gas_used);
    try testing.expectEqual(@as(?u64, 44), flashblock.diff.blob_gas_used);
    try testing.expectEqual(@as(usize, 1), flashblock.diff.transactions.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, flashblock.diff.transactions[0]);
    try testing.expectEqual(@as(u64, 1234), flashblock.metadata.block_number);
    try testing.expectEqual(@as(u64, 0), flashblock.metadata.prev_flashblock_id.block_number);
}

test "flashblocks: v0.4.1 wire format, plain and brotli" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try expect_v0_4_1(try flashblocks.decode_message(arena, v0_4_1_json));
    const compressed = try arena.alloc(u8, comp.brotli_bound(v0_4_1_json.len));
    const stream = try comp.brotli_compress_stored(v0_4_1_json, compressed);
    // Drop the channel version byte: flashblock messages are bare brotli streams.
    try expect_v0_4_1(try flashblocks.decode_message(arena, stream[1..]));
}

test "flashblocks: write and decode round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var original = try flashblocks.decode_message(arena, v0_4_1_json);
    original.index = 3;
    original.metadata.prev_flashblock_id = .{ .block_number = 1234, .index = 2 };
    const withdrawals = [_]flashblocks.Withdrawal{.{
        .index = 1,
        .validator_index = 2,
        .address = .zero,
        .amount_gwei = 3,
    }};
    original.diff.withdrawals = &withdrawals;
    var buffer: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try flashblocks.write_json(&w, original);
    const again = try flashblocks.decode_message(arena, w.buffered());
    try testing.expectEqual(@as(u64, 3), again.index);
    try testing.expectEqual(@as(u64, 2), again.metadata.prev_flashblock_id.index);
    try testing.expectEqual(@as(u64, 2), again.diff.withdrawals[0].validator_index);
    try testing.expectEqualSlices(u8, original.base.?.extra_data, again.base.?.extra_data);
    try testing.expect(again.diff.state_root.eql(original.diff.state_root));
    original.base = null;
    var w2: std.Io.Writer = .fixed(&buffer);
    try flashblocks.write_json(&w2, original);
    try testing.expect(std.mem.indexOf(u8, w2.buffered(), "\"base\"") == null);
    try testing.expect((try flashblocks.decode_message(arena, w2.buffered())).base == null);
}

test "flashblocks: rejects invalid messages" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(error.Decompress, flashblocks.decode_message(arena, "not brotli data"));
    try testing.expectError(error.PayloadParse, flashblocks.decode_message(arena, "{}"));
    const no_block_number = comptime blk: {
        @setEvalBranchQuota(100_000);
        const marker = "{\"block_number\":1234,\"receipts\":{}}";
        const at = std.mem.indexOf(u8, v0_4_1_json, marker).?;
        break :blk v0_4_1_json[0..at] ++ "{}}";
    };
    const missing = flashblocks.decode_message(arena, no_block_number);
    try testing.expectError(error.MetadataParse, missing);
    const bad_hash = comptime blk: {
        @setEvalBranchQuota(100_000);
        const at = std.mem.indexOf(u8, v0_4_1_json, "0x0606").?;
        break :blk v0_4_1_json[0..at] ++ "0x06" ++ v0_4_1_json[at + 6 ..];
    };
    try testing.expectError(error.InvalidField, flashblocks.decode_message(arena, bad_hash));
    const oversized = try arena.alloc(u8, flashblocks.max_decompressed_bytes + 1);
    @memset(oversized, ' ');
    oversized[0] = '{';
    try testing.expectError(error.PayloadTooLarge, flashblocks.decode_message(arena, oversized));
}

test "flashblocks: id parse and format" {
    const id = try flashblocks.FlashblockId.parse("18446744073709551615-7");
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), id.block_number);
    var buffer: [41]u8 = undefined;
    try testing.expectEqualStrings("18446744073709551615-7", id.format(&buffer));
    try testing.expectError(error.InvalidFlashblockId, flashblocks.FlashblockId.parse("12"));
    try testing.expectError(error.InvalidFlashblockId, flashblocks.FlashblockId.parse("a-1"));
    try testing.expectError(error.InvalidFlashblockId, flashblocks.FlashblockId.parse("1-"));
}

fn decode_any(input: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const flashblock = flashblocks.decode_message(arena_state.allocator(), input) catch return;
    try testing.expect(flashblock.diff.transactions.len <= input.len);
}

test "flashblocks: seeded fuzz mutated messages" {
    var prng = Prng.init(0xf1a5);
    var message: [v0_4_1_json.len]u8 = undefined;
    for (0..300) |_| {
        message = v0_4_1_json.*;
        for (0..prng.range(1, 4)) |_| message[prng.below(message.len)] = prng.int(u8);
        try decode_any(message[0..prng.range(0, message.len)]);
    }
}

test "flashblocks: fuzz" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var input: [2048]u8 = undefined;
            const length = smith.slice(&input);
            try decode_any(input[0..length]);
        }
    }.run, .{});
}

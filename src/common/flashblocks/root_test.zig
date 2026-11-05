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

const brotli_encoder = @import("../../batcher/comp/brotli.zig");

fn random_bytes(arena: std.mem.Allocator, prng: *Prng, length_max: u64) ![]u8 {
    const bytes = try arena.alloc(u8, prng.range(0, length_max));
    prng.fill(bytes);
    return bytes;
}

fn random_fixed(comptime T: type, prng: *Prng) T {
    var value: T = undefined;
    prng.fill(&value.bytes);
    return value;
}

/// A structurally arbitrary flashblock: every field random, `base` and the optional
/// `blob_gas_used` present or absent.
fn random_flashblock(arena: std.mem.Allocator, prng: *Prng) !flashblocks.Flashblock {
    const B256 = @FieldType(flashblocks.Delta, "state_root");
    const Address = @FieldType(flashblocks.Withdrawal, "address");
    const transactions = try arena.alloc([]const u8, prng.range(0, 6));
    for (transactions) |*transaction| transaction.* = try random_bytes(arena, prng, 200);
    const withdrawals = try arena.alloc(flashblocks.Withdrawal, prng.range(0, 4));
    for (withdrawals) |*withdrawal| withdrawal.* = .{
        .index = prng.int(u64),
        .validator_index = prng.int(u64),
        .address = random_fixed(Address, prng),
        .amount_gwei = prng.int(u64),
    };
    const base: ?flashblocks.PayloadBase = if (prng.chance(1, 2)) .{
        .parent_beacon_block_root = random_fixed(B256, prng),
        .parent_hash = random_fixed(B256, prng),
        .fee_recipient = random_fixed(Address, prng),
        .prev_randao = random_fixed(B256, prng),
        .block_number = prng.int(u64),
        .gas_limit = prng.int(u64),
        .timestamp = prng.int(u64),
        .extra_data = try random_bytes(arena, prng, 32),
        .base_fee_per_gas = prng.int(u256),
    } else null;
    var payload_id: [8]u8 = undefined;
    prng.fill(&payload_id);
    return .{
        .payload_id = payload_id,
        .index = prng.int(u64),
        .base = base,
        .diff = .{
            .state_root = random_fixed(B256, prng),
            .receipts_root = random_fixed(B256, prng),
            .logs_bloom = random_fixed(@FieldType(flashblocks.Delta, "logs_bloom"), prng),
            .gas_used = prng.int(u64),
            .block_hash = random_fixed(B256, prng),
            .transactions = transactions,
            .withdrawals = withdrawals,
            .withdrawals_root = random_fixed(B256, prng),
            .blob_gas_used = if (prng.chance(1, 2)) prng.int(u64) else null,
        },
        .metadata = .{
            .block_number = prng.int(u64),
            .prev_flashblock_id = .{ .block_number = prng.int(u64), .index = prng.int(u64) },
        },
    };
}

fn expect_flashblock_equal(a: flashblocks.Flashblock, b: flashblocks.Flashblock) !void {
    try testing.expectEqualSlices(u8, &a.payload_id, &b.payload_id);
    try testing.expectEqual(a.index, b.index);
    try testing.expectEqual(a.base == null, b.base == null);
    if (a.base) |base| {
        try testing.expectEqualDeep(base.parent_hash, b.base.?.parent_hash);
        try testing.expectEqual(base.base_fee_per_gas, b.base.?.base_fee_per_gas);
        try testing.expectEqualSlices(u8, base.extra_data, b.base.?.extra_data);
    }
    try testing.expect(a.diff.block_hash.eql(b.diff.block_hash));
    try testing.expect(a.diff.logs_bloom.eql(b.diff.logs_bloom));
    try testing.expectEqual(a.diff.gas_used, b.diff.gas_used);
    try testing.expectEqual(a.diff.blob_gas_used, b.diff.blob_gas_used);
    try testing.expectEqual(a.diff.transactions.len, b.diff.transactions.len);
    for (a.diff.transactions, b.diff.transactions) |x, y| try testing.expectEqualSlices(u8, x, y);
    try testing.expectEqualDeep(a.diff.withdrawals, b.diff.withdrawals);
    try testing.expectEqualDeep(a.metadata, b.metadata);
}

/// Encode → decode → encode is byte-exact, plain and brotli.
fn round_trip(seed: u64, encoder: *brotli_encoder.Encoder) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = Prng.init(seed);
    const original = try random_flashblock(arena, &prng);
    const json = try flashblocks.encode_json(original, try arena.alloc(u8, 16 * 1024));
    const decoded = try flashblocks.decode_message(arena, json);
    try expect_flashblock_equal(original, decoded);
    const again = try flashblocks.encode_json(decoded, try arena.alloc(u8, json.len));
    try testing.expectEqualSlices(u8, json, again);
    const compressed_buffer = try arena.alloc(u8, flashblocks.brotli_bound(json.len));
    const compressed = try flashblocks.encode_brotli(encoder, json, compressed_buffer);
    try testing.expect(compressed.len <= compressed_buffer.len);
    const from_brotli = try flashblocks.decode_message(arena, compressed);
    const third = try flashblocks.encode_json(from_brotli, try arena.alloc(u8, json.len));
    try testing.expectEqualSlices(u8, json, third);
}

test "flashblocks: seeded fuzz encode round trip is byte exact" {
    var encoder = try brotli_encoder.Encoder.init(testing.allocator, 16 * 1024);
    defer encoder.deinit(testing.allocator);
    var prng = Prng.init(0xf1a5_e4c0);
    for (0..200) |_| try round_trip(prng.int(u64), &encoder);
}

test "flashblocks: encode rejects a small buffer and stored brotli fallback fits" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const flashblock = try flashblocks.decode_message(arena, v0_4_1_json);
    var tiny: [64]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, flashblocks.encode_json(flashblock, &tiny));
    try testing.expectError(error.OutputTooSmall, flashblocks.encode_json(flashblock, tiny[0..1]));
    // Random bytes inside a JSON string do not compress: the stored form must still fit.
    var prng = Prng.init(7);
    var text: [3000]u8 = undefined;
    for (&text) |*byte| byte.* = "0123456789abcdef"[prng.below(16)];
    text[0] = '{';
    text[text.len - 1] = '}';
    var encoder = try brotli_encoder.Encoder.init(testing.allocator, text.len);
    defer encoder.deinit(testing.allocator);
    const out = try arena.alloc(u8, flashblocks.brotli_bound(text.len));
    const stream = try flashblocks.encode_brotli(&encoder, &text, out);
    const decompressed = try @import("../../consensus/protocol/brotli.zig").decompress(
        arena,
        stream,
        flashblocks.max_decompressed_bytes,
    );
    try testing.expectEqualSlices(u8, &text, decompressed);
}

test "flashblocks: fuzz encode round trip" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var encoder = try brotli_encoder.Encoder.init(testing.allocator, 16 * 1024);
            defer encoder.deinit(testing.allocator);
            try round_trip(smith.value(u64), &encoder);
        }
    }.run, .{});
}

test "flashblocks: id parse matches Rust u64::from_str" {
    const Id = flashblocks.FlashblockId;
    try testing.expectError(error.InvalidFlashblockId, Id.parse("1_0-2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("1-2_0"));
    try testing.expectEqual(Id{ .block_number = 61, .index = 2 }, try Id.parse("+61-2"));
    try testing.expectEqual(Id{ .block_number = 61, .index = 2 }, try Id.parse("61-+2"));
    try testing.expectEqual(Id{ .block_number = 7, .index = 0 }, try Id.parse("007-0"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("+-2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("++1-2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("1--2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("-1-2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse(" 1-2"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("18446744073709551616-0"));
    try testing.expectError(error.InvalidFlashblockId, Id.parse("1-2-3"));
    const max = Id.parse_decimal("+18446744073709551615");
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), max);
}

/// Independent model: validate, drop leading zeros, then accumulate in u128 so overflow
/// is a range check.
fn model_decimal(text: []const u8) ?u64 {
    var digits = text;
    if (digits.len > 0 and digits[0] == '+') digits = digits[1..];
    if (digits.len == 0) return null;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return null;
    const significant = std.mem.trimStart(u8, digits, "0");
    if (significant.len > 20) return null;
    var value: u128 = 0;
    for (significant) |byte| value = value * 10 + (byte - '0');
    return std.math.cast(u64, value);
}

test "flashblocks: seeded fuzz decimal parse against a model" {
    const alphabet = "0123456789+-_ a9";
    var prng = Prng.init(0xdec1_3a1);
    var text: [40]u8 = undefined;
    for (0..20_000) |_| {
        const length = prng.below(text.len + 1);
        for (text[0..length]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        if (prng.chance(1, 4) and length > 0) text[0] = '+';
        try testing.expectEqual(
            model_decimal(text[0..length]),
            flashblocks.FlashblockId.parse_decimal(text[0..length]),
        );
    }
}

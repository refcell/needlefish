const std = @import("std");
const testing = std.testing;
const rpc = @import("root.zig");
const primitives = @import("../primitives/root.zig");
const consensus = @import("../consensus/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const hex = primitives.hex;
const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = consensus.tx.Envelope;
const Writer = std.Io.Writer;
const Value = std.json.Value;

const eip155_example_hex =
    "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764" ++
    "00008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cb" ++
    "e9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

const base_deposit_hex =
    "7ef8f8a0417d134467f4737fcdf2475f0ecdd2a0ed6d87ecffc888ba9f60ee7e3b8ac26a94deadde" ++
    "addeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080" ++
    "830f424080b8a4440a5e20000008dd00101c1200000000000000040000000066c352bb0000000001" ++
    "39c4f500000000000000000000000000000000000000000000000000000000c0cff1460000000000" ++
    "000000000000000000000000000000000000000000000000000001d4c88f4065ac9671e8b1329b90" ++
    "773e89b5ddff9cf8675b2b5e9c1b28320609930000000000000000000000005050f69a9786f08150" ++
    "9234f1a7f4684b5e5b76c9";

fn parse(text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, testing.allocator, text, .{});
}

fn expect_string(object: Value, name: []const u8, expected: []const u8) !void {
    const value = object.object.get(name) orelse return error.MissingField;
    try testing.expectEqualStrings(expected, value.string);
}

fn expect_absent(object: Value, name: []const u8) !void {
    try testing.expect(object.object.get(name) == null);
}

test "rpc types: EIP-155 legacy transaction" {
    var bytes: [256]u8 = undefined;
    const envelope = try Envelope.decode(try hex.decode_into(&bytes, eip155_example_hex));
    var buffer: [2048]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try rpc.write_transaction(&w, envelope, .{
        .hash = envelope.hash(),
        .from = Address.comptime_hex("9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"),
    });
    const parsed = try parse(w.buffered());
    defer parsed.deinit();
    const object = parsed.value;
    try expect_string(object, "type", "0x0");
    try expect_string(object, "nonce", "0x9");
    try expect_string(object, "gasPrice", "0x4a817c800");
    try expect_string(object, "gas", "0x5208");
    try expect_string(object, "value", "0xde0b6b3a7640000");
    try expect_string(object, "input", "0x");
    try expect_string(object, "chainId", "0x1");
    try expect_string(object, "v", "0x25");
    try expect_string(
        object,
        "r",
        "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276",
    );
    try expect_string(object, "from", "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F");
    try expect_string(object, "to", "0x3535353535353535353535353535353535353535");
    try testing.expect(object.object.get("blockHash").? == .null);
    try expect_absent(object, "yParity");
}

test "rpc types: Base deposit transaction" {
    var bytes: [512]u8 = undefined;
    const envelope = try Envelope.decode(try hex.decode_into(&bytes, base_deposit_hex));
    var buffer: [2048]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try rpc.write_transaction(&w, envelope, .{
        .hash = envelope.hash(),
        .from = .zero,
        .position = .{ .block_hash = .zero, .block_number = 18_000_000, .transaction_index = 0 },
        .deposit_nonce = 17,
        .deposit_receipt_version = 1,
    });
    const parsed = try parse(w.buffered());
    defer parsed.deinit();
    const object = parsed.value;
    try expect_string(object, "type", "0x7e");
    try expect_string(
        object,
        "hash",
        "0xc468b38a20375922828c8126912740105125143b9856936085474b2590bbca91",
    );
    try expect_string(object, "from", "0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");
    try expect_string(object, "to", "0x4200000000000000000000000000000000000015");
    try expect_string(object, "mint", "0x0");
    try expect_string(object, "gas", "0xf4240");
    try expect_string(object, "nonce", "0x11");
    try expect_string(object, "depositReceiptVersion", "0x1");
    try expect_string(object, "blockNumber", "0x112a880");
    try testing.expect(object.object.get("isSystemTx").?.bool == false);
    try expect_absent(object, "v");
}

test "rpc types: receipt with logs and L1 fee fields" {
    var topics_buffer: [128]u8 = undefined;
    var logs_buffer: [512]u8 = undefined;
    var topic: B256 = .zero;
    topic.bytes[0] = 0xaa;
    const log: consensus.receipt.Log = .{
        .address = Address.comptime_hex("4200000000000000000000000000000000000006"),
        .topics = consensus.tx_fields.HashList.build(&topics_buffer, &.{topic}),
        .data = &.{0x01},
    };
    const logs = consensus.receipt.Logs.build(&logs_buffer, &.{ log, log });
    const receipt: consensus.receipt.Receipt = .{
        .tx_type = .eip1559,
        .status = true,
        .cumulative_gas_used = 50_000,
        .logs_bloom = logs.bloom(),
        .logs = logs,
    };
    var buffer: [4096]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try rpc.write_receipt(&w, receipt, .{
        .position = .{
            .block_hash = .zero,
            .block_number = 5,
            .transaction_index = 2,
            .transaction_hash = topic,
        },
        .from = .zero,
        .to = null,
        .contract_address = Address.comptime_hex("4200000000000000000000000000000000000042"),
        .gas_used = 21_000,
        .effective_gas_price = 1_000_000,
        .first_log_index = 7,
        .l1_block_info = .{ .l1_fee = 255, .l1_base_fee_scalar = 1_368, .l1_fee_scalar = "0.684" },
    });
    const parsed = try parse(w.buffered());
    defer parsed.deinit();
    const object = parsed.value;
    try expect_string(object, "status", "0x1");
    try expect_string(object, "type", "0x2");
    try expect_string(object, "cumulativeGasUsed", "0xc350");
    try expect_string(object, "l1Fee", "0xff");
    try expect_string(object, "l1FeeScalar", "0.684");
    try expect_string(object, "l1BaseFeeScalar", "0x558");
    try expect_absent(object, "l1GasPrice");
    try expect_absent(object, "phaseStatuses");
    try testing.expect(object.object.get("to").? == .null);
    const logs_json = object.object.get("logs").?.array;
    try testing.expectEqual(@as(usize, 2), logs_json.items.len);
    try expect_string(logs_json.items[1], "logIndex", "0x8");
    try expect_string(logs_json.items[1], "transactionIndex", "0x2");
    try expect_string(logs_json.items[0], "data", "0x01");
}

test "rpc types: header and block" {
    const header: consensus.header.Header = .{
        .number = 1,
        .gas_limit = 30_000_000,
        .timestamp = 1_700_000_000,
        .base_fee_per_gas = 7,
        .withdrawals_root = primitives.empty_root_hash,
        .extra_data = &.{ 0x00, 0x01 },
    };
    var buffer: [4096]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    const hashes = [_]B256{ .zero, header.hash() };
    try rpc.write_block(&w, header, header.hash(), 600, .{ .hashes = &hashes });
    const parsed = try parse(w.buffered());
    defer parsed.deinit();
    const object = parsed.value;
    try expect_string(object, "number", "0x1");
    try expect_string(object, "baseFeePerGas", "0x7");
    try expect_string(object, "extraData", "0x0001");
    try expect_string(object, "nonce", "0x0000000000000000");
    try expect_string(object, "size", "0x258");
    try expect_absent(object, "blobGasUsed");
    try testing.expectEqual(@as(usize, 2), object.object.get("transactions").?.array.items.len);
    try testing.expectEqual(@as(usize, 0), object.object.get("withdrawals").?.array.items.len);
}

test "rpc types: EIP-8130 transaction and receipt" {
    const aa = consensus.eip8130;
    var phase_buffer: [256]u8 = undefined;
    var calls_buffer: [256]u8 = undefined;
    var changes_buffer: [256]u8 = undefined;
    const target = Address.comptime_hex("4200000000000000000000000000000000000007");
    const call: aa.Call = .{ .to = target, .value = 5, .data = &.{ 0xde, 0xad } };
    const phase = aa.Phase.build(&phase_buffer, &.{call});
    const delegation: aa.AccountChange = .{ .delegation = target };
    const signed: aa.Signed = .{
        .tx = .{
            .chain_id = 8453,
            .nonce_sequence = 7,
            .max_fee_per_gas = 2,
            .gas_limit = 100_000,
            .account_changes = aa.AccountChanges.build(&changes_buffer, &.{delegation}),
            .calls = aa.Calls.build(&calls_buffer, &.{ phase, phase }),
            .metadata = "memo",
        },
        .sender_auth = &.{0x01},
    };
    var buffer: [4096]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try rpc.write_transaction(&w, .{ .eip8130 = signed }, .{ .hash = .zero, .from = target });
    const parsed = try parse(w.buffered());
    defer parsed.deinit();
    const object = parsed.value;
    try expect_string(object, "type", "0x79");
    try expect_string(object, "nonce", "0x7");
    try expect_string(object, "metadata", "0x6d656d6f");
    try testing.expect(object.object.get("payer").? == .null);
    const change = object.object.get("accountChanges").?.array.items[0];
    try expect_string(change, "type", "0x1");
    try expect_string(change, "target", "0x4200000000000000000000000000000000000007");
    const calls = object.object.get("calls").?.array;
    try testing.expectEqual(@as(usize, 2), calls.items.len);
    try expect_string(calls.items[1].array.items[0], "data", "0xdead");

    const receipt: consensus.receipt.Receipt = .{
        .tx_type = .eip8130,
        .status = false,
        .cumulative_gas_used = 1,
        .committed_phases = 1,
    };
    var w2: Writer = .fixed(&buffer);
    try rpc.write_receipt(&w2, receipt, .{
        .position = .{ .transaction_hash = .zero },
        .from = target,
        .to = null,
        .gas_used = 1,
        .effective_gas_price = 2,
        .first_log_index = 0,
        .phase_count = 2,
        .metadata = "memo",
    });
    const parsed_receipt = try parse(w2.buffered());
    defer parsed_receipt.deinit();
    const statuses = parsed_receipt.value.object.get("phaseStatuses").?.array;
    try testing.expectEqual(@as(usize, 2), statuses.items.len);
    try testing.expectEqualStrings("0x1", statuses.items[0].string);
    try testing.expectEqualStrings("0x0", statuses.items[1].string);
}

fn write_any(input: []const u8, buffer: []u8) !void {
    const envelope = Envelope.decode(input) catch return;
    var w: Writer = .fixed(buffer);
    rpc.write_transaction(&w, envelope, .{ .hash = .zero, .from = .zero }) catch |err| {
        // Only an undersized buffer may fail; the writer itself never errors.
        try testing.expectEqual(error.WriteFailed, err);
        return;
    };
    try testing.expect(try std.json.validate(testing.allocator, w.buffered()));
}

test "rpc types: seeded fuzz decoded envelopes serialize to valid JSON" {
    var prng = Prng.init(0x7c);
    var bytes: [512]u8 = undefined;
    var encoded: [256]u8 = undefined;
    var legacy_encoded: [128]u8 = undefined;
    const vectors = [_][]const u8{
        try hex.decode_into(&encoded, base_deposit_hex),
        try hex.decode_into(&legacy_encoded, eip155_example_hex),
    };
    var buffer: [16 * 1024]u8 = undefined;
    for (0..2_000) |_| {
        const vector = vectors[prng.below(vectors.len)];
        @memcpy(bytes[0..vector.len], vector);
        const length = prng.range(1, vector.len);
        if (prng.chance(1, 2)) bytes[prng.below(length)] = prng.int(u8);
        try write_any(bytes[0..length], &buffer);
    }
    for (vectors) |vector| try write_any(vector, &buffer);
}

test "rpc types: fuzz" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var input: [512]u8 = undefined;
            var buffer: [16 * 1024]u8 = undefined;
            const length = smith.slice(&input);
            try write_any(input[0..length], &buffer);
        }
    }.run, .{});
}

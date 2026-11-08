//! L1 JSON decoding tests: transactions, blocks, and receipts written by the execution
//! lane's eth formatter, tampering cases, and fuzz targets for every decoder.

const std = @import("std");
const testing = std.testing;

const fixtures = @import("fixtures.zig");
const header_json = @import("header_json.zig");
const transaction_json = @import("transaction_json.zig");
const receipt_json = @import("receipt_json.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn transaction_text(buffer: []u8, index: usize) ![]const u8 {
    const transactions = fixtures.signed_transactions();
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try fixtures.write_transaction(&writer, transactions[index]);
    return out.buffered();
}

test "l1 json: rebuilds and recovers every transaction type" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const transactions = fixtures.signed_transactions();
    for (transactions, 0..) |envelope, index| {
        var buffer: [2048]u8 = undefined;
        const text = try transaction_text(&buffer, index);
        const allocator = arena.allocator();
        const decoded = try transaction_json.decode(allocator, allocator, text, .{});
        const transaction = decoded.transaction;
        try testing.expect(decoded.envelope.?.hash().eql(envelope.hash()));
        try testing.expectEqual(@as(u8, @backingInt(envelope.tx_type())), transaction.tx_type);
        try testing.expect(transaction.from.eql(fixtures.dev_address));
        try testing.expectEqualStrings(envelope.input(), transaction.input);
        try testing.expectEqual(envelope.kind().to() == null, transaction.to == null);
    }
    var buffer: [2048]u8 = undefined;
    const blob_text = try transaction_text(&buffer, 3);
    const blob = try transaction_json.decode(arena.allocator(), arena.allocator(), blob_text, .{});
    try testing.expectEqual(@as(usize, 2), blob.transaction.blob_hashes.len);
    try testing.expect(blob.transaction.blob_hashes[1].eql(fixtures.blob_hashes[1]));
}

fn replace_once(buffer: []u8, text: []const u8, needle: []const u8, with: []const u8) []u8 {
    const at = std.mem.indexOf(u8, text, needle).?;
    std.debug.assert(needle.len == with.len);
    @memcpy(buffer[0..text.len], text);
    @memcpy(buffer[at..][0..with.len], with);
    return buffer[0..text.len];
}

test "l1 json: rejects a forged sender, a tampered input, and bad signatures" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var buffer: [2048]u8 = undefined;
    const text = try transaction_text(&buffer, 2);
    var tampered: [2048]u8 = undefined;
    const sender_hex = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const forged_hex = "f39fd6e51aad88f6f4ce6ab8827279cfffb92267";
    const forged = replace_once(&tampered, text, sender_hex, forged_hex);
    try testing.expectError(
        error.SenderMismatch,
        transaction_json.decode(allocator, allocator, forged, .{}),
    );
    // Recovery skipped for transactions to other addresses: the RPC `from` is kept.
    const other = primitives.Address.comptime_hex("0x0000000000000000000000000000000000000001");
    const options: transaction_json.Options = .{ .recover_to = other };
    const kept = try transaction_json.decode(allocator, allocator, forged, options);
    try testing.expect(!kept.transaction.from.eql(fixtures.dev_address));
    const input_hex = "6672616d652064617461"; // "frame data"
    const changed = replace_once(&tampered, text, input_hex, "6672616d652064617462");
    try testing.expectError(
        error.HashMismatch,
        transaction_json.decode(allocator, allocator, changed, .{}),
    );
    const parity_at = std.mem.indexOf(u8, text, "\"yParity\":\"0x").? + 13;
    @memcpy(tampered[0..text.len], text);
    tampered[parity_at] = '2';
    try testing.expectError(
        error.InvalidSignature,
        transaction_json.decode(allocator, allocator, tampered[0..text.len], .{}),
    );
}

test "l1 json: unknown types keep the rpc sender and fail strict roots" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const text =
        \\{"type":"0x7f","from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","to":null,
        \\"input":"0x01","hash":"0x0000000000000000000000000000000000000000000000000000000000000001"}
    ;
    const decoded = try transaction_json.decode(allocator, allocator, text, .{});
    try testing.expect(decoded.envelope == null);
    try testing.expectEqual(@as(u8, 0x7f), decoded.transaction.tx_type);
    const block = "[" ++ text ++ "]";
    try testing.expectError(
        error.UnsupportedTransaction,
        transaction_json.decode_block(allocator, allocator, block, .zero, .{}),
    );
    const trusted = try transaction_json.decode_block(allocator, allocator, block, .zero, .{
        .verify_root = false,
    });
    try testing.expectEqual(@as(usize, 1), trusted.len);
}

test "l1 json: full block verifies header hash and transactions root" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const transactions = fixtures.signed_transactions();
    const header = fixtures.header_for(&transactions, 100, .init(@splat(9)));
    var buffer: [16 * 1024]u8 = undefined;
    const text = try fixtures.block_json(&buffer, &header, &transactions, true);
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(text, &extra);
    try testing.expect(decoded.hash.eql(header.hash()));
    try testing.expectEqual(@as(u64, 100), decoded.block_info().number);
    const raw = (try header_json.transactions_raw(text)).?;
    const root = decoded.header.transactions_root;
    const list = try transaction_json.decode_block(allocator, allocator, raw, root, .{});
    try testing.expectEqual(@as(usize, 4), list.len);
    try testing.expectError(
        error.RootMismatch,
        transaction_json.decode_block(allocator, allocator, raw, .zero, .{}),
    );
    var hashes_buffer: [8 * 1024]u8 = undefined;
    const hashes_only = try fixtures.block_json(&hashes_buffer, &header, &transactions, false);
    _ = try header_json.decode(hashes_only, &extra);
}

test "l1 json: receipts decode and verify the receipts root" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var set: fixtures.ReceiptSet = undefined;
    set.init(3);
    var buffer: [16 * 1024]u8 = undefined;
    const text = try set.json_text(&buffer, .init(@splat(5)));
    const receipts = try receipt_json.decode_block(allocator, allocator, text, set.root(), .{});
    try testing.expectEqual(@as(usize, 3), receipts.len);
    try testing.expect(receipts[0].success);
    try testing.expect(!receipts[1].success);
    try testing.expectEqual(@as(usize, 1), receipts[2].logs.len);
    try testing.expect(receipts[2].logs[0].address.eql(fixtures.inbox));
    try testing.expectEqual(@as(usize, 2), receipts[2].logs[0].topics.len);
    try testing.expectEqualStrings("log data", receipts[2].logs[0].data);
    try testing.expectError(
        error.RootMismatch,
        receipt_json.decode_block(allocator, allocator, text, .zero, .{}),
    );
    const trusted = try receipt_json.decode_block(allocator, allocator, text, null, .{});
    try testing.expectEqual(@as(usize, 3), trusted.len);
}

/// Every decoder on arbitrary bytes: errors are fine, crashes and leaks are not.
fn decode_arbitrary(input: []const u8) void {
    var memory: [64 * 1024]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    const allocator = fixed.allocator();
    json.validate(input) catch return;
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    _ = header_json.decode(input, &extra) catch {};
    _ = header_json.transactions_raw(input) catch {};
    fixed.reset();
    _ = transaction_json.decode(allocator, allocator, input, .{}) catch {};
    fixed.reset();
    _ = transaction_json.decode_block(allocator, allocator, input, .zero, .{}) catch {};
    fixed.reset();
    _ = receipt_json.decode_block(allocator, allocator, input, .zero, .{}) catch {};
    fixed.reset();
    _ = receipt_json.decode_block(allocator, allocator, input, null, .{}) catch {};
}

fn mutate(prng: *Prng, buffer: []u8, seed: []const u8) []u8 {
    @memcpy(buffer[0..seed.len], seed);
    var size = seed.len;
    for (0..prng.range(1, 4)) |_| {
        const position = prng.below(size);
        switch (prng.below(4)) {
            0 => buffer[position] = "{}[],:\"0x1fn"[prng.below(12)],
            1 => size = position + 1,
            2 => buffer[position] = prng.int(u8),
            3 => buffer[position] = "0123456789abcdef"[prng.below(16)],
            else => unreachable,
        }
    }
    return buffer[0..size];
}

test "l1 json: seeded fuzz of mutated transactions, blocks, and receipts" {
    var seeds: [4][]const u8 = undefined;
    var tx_buffer: [2048]u8 = undefined;
    seeds[0] = try transaction_text(&tx_buffer, 3);
    const transactions = fixtures.signed_transactions();
    const header = fixtures.header_for(transactions[0..2], 7, .zero);
    var block_buffer: [8 * 1024]u8 = undefined;
    seeds[1] = try fixtures.block_json(&block_buffer, &header, transactions[0..2], true);
    var set: fixtures.ReceiptSet = undefined;
    set.init(2);
    var receipt_buffer: [8 * 1024]u8 = undefined;
    seeds[2] = try set.json_text(&receipt_buffer, .zero);
    var tx_list: [2100]u8 = undefined;
    seeds[3] = try std.fmt.bufPrint(&tx_list, "[{s}]", .{seeds[0]});
    var prng = Prng.init(0x50c5);
    var buffer: [8 * 1024]u8 = undefined;
    for (0..400) |_| {
        const seed = seeds[prng.below(seeds.len)];
        decode_arbitrary(mutate(&prng, &buffer, seed));
    }
}

fn fuzz_decoders(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [4096]u8 = undefined;
    const size = smith.slice(&input);
    decode_arbitrary(input[0..size]);
}

test "l1 json: fuzz decoders" {
    try std.testing.fuzz({}, fuzz_decoders, .{});
}

// Ethereum Sepolia block 12090253 (public), an Amsterdam header: `blockAccessListHash`
// (EIP-7928) and `slotNumber` (EIP-7843) follow `requestsHash` and are part of the hash.
// The transaction list is truncated and withdrawals dropped: neither is hashed here.
const amsterdam_header = @embedFile("testdata/sepolia_l1_12090253_header.json");

test "l1 json: amsterdam header fields are hashed" {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(amsterdam_header, &extra);
    try testing.expectEqual(@as(u64, 12_090_253), decoded.header.number);
    try testing.expectEqual(@as(?u64, 0xaffd0a), decoded.header.slot_number);
    try testing.expect(decoded.header.block_access_list_hash != null);
    const expected = primitives.B256.comptime_hex(
        "bb528dde0066f2187e97eddaba129037d4421843720843ab3ddb961729c13b0b",
    );
    try testing.expect(decoded.hash.eql(expected));
    // Without the Amsterdam fields the header no longer hashes to the block hash.
    var header = decoded.header;
    header.slot_number = null;
    header.block_access_list_hash = null;
    try testing.expect(!header.hash().eql(expected));
}

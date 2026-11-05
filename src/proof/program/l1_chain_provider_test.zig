//! L1 chain provider tests: a small L1 chain whose headers, transaction tries and receipt
//! tries are served through the in-process oracle.

const std = @import("std");
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const test_oracle = @import("../test_oracle.zig");
const fuzz = @import("../../testing/fuzz.zig");
const l1_chain_provider = @import("l1_chain_provider.zig");
const L1ChainProvider = l1_chain_provider.L1ChainProvider;

const B256 = primitives.B256;
const Address = primitives.Address;

fn key(n: u8) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[31] = n;
    return bytes;
}

fn address_of(n: u8) Address {
    return consensus.signature.address_from_private(key(n)).?;
}

const inbox: Address = .{ .bytes = @splat(0xff) };

const Fixture = struct {
    store: test_oracle.MapStore,
    harness: preimage.InProcess,
    resolver: mpt.OracleResolver,
    hashes: [3]B256 = undefined,

    fn init(fixture: *Fixture) !void {
        fixture.store = .init();
        try fixture.harness.init(
            testing.allocator,
            fixture.store.fetcher(),
            preimage.in_process.ignore_hints,
            .{ .channel_bytes = 8192 },
        );
        fixture.resolver = try .init(testing.allocator, fixture.harness.oracle_reader(), .{
            .bytes_max = 1 << 20,
            .entries_max = 4096,
        });
        try fixture.build_chain();
    }

    fn deinit(fixture: *Fixture) void {
        fixture.resolver.deinit(testing.allocator);
        fixture.harness.deinit(testing.allocator);
        fixture.store.deinit();
    }

    fn signed(nonce: u64, to: Address, input: []const u8, buffer: []u8) ![]const u8 {
        const tx: consensus.Eip1559 = .{
            .chain_id = 1,
            .nonce = nonce,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 100,
            .gas_limit = 50_000,
            .to = .{ .call = to },
            .value = 0,
            .input = input,
            .access_list = .empty,
        };
        const envelope = try consensus.tx.sign(tx, key(1));
        return envelope.encode_to(buffer);
    }

    fn receipt(status: bool, gas: u64, logs: consensus.receipt.Logs) consensus.Receipt {
        return .{ .tx_type = .eip1559, .status = status, .cumulative_gas_used = gas, .logs = logs };
    }

    /// Block 1 carries two transactions and their receipts; blocks 0 and 2 are empty.
    fn build_chain(fixture: *Fixture) !void {
        var tx_buffers: [2][256]u8 = undefined;
        const transactions = [_][]const u8{
            try signed(0, inbox, "frame", &tx_buffers[0]),
            try signed(1, address_of(9), "other", &tx_buffers[1]),
        };
        var topics_buffer: [66]u8 = undefined;
        const topic_items = [_]B256{ .{ .bytes = @splat(7) }, .{ .bytes = @splat(8) } };
        const topics = consensus.HashList.build(&topics_buffer, &topic_items);
        var logs_buffer: [256]u8 = undefined;
        const log: consensus.receipt.Log = .{ .address = inbox, .topics = topics, .data = "log" };
        const logs = consensus.receipt.Logs.build(&logs_buffer, &.{log});
        var receipt_buffers: [2][512]u8 = undefined;
        const receipts = [_][]const u8{
            receipt(true, 1, logs).encode_to(&receipt_buffers[0]),
            receipt(false, 2, .empty).encode_to(&receipt_buffers[1]),
        };
        var parent: B256 = .zero;
        for (&fixture.hashes, 0..) |*hash, number| {
            var header: consensus.Header = .{
                .parent_hash = parent,
                .number = number,
                .timestamp = 12 * number,
            };
            if (number == 1) {
                const store = &fixture.store;
                const transactions_root = try test_oracle.store_list(store, &transactions);
                header.transactions_root = .{ .bytes = transactions_root };
                header.receipts_root = .{ .bytes = try test_oracle.store_list(store, &receipts) };
            }
            var buffer: [1024]u8 = undefined;
            const encoded = rlp.encode_to(&buffer, header);
            hash.* = header.hash();
            try fixture.store.put(.keccak256(hash.bytes), encoded);
            parent = hash.*;
        }
    }

    fn provider(fixture: *Fixture) !L1ChainProvider {
        return .init(
            testing.allocator,
            &fixture.resolver,
            fixture.harness.hint_writer(),
            fixture.hashes[2].bytes,
            .{ .items_max = 16, .logs_max = 16, .topics_max = 32, .recover_to = inbox },
        );
    }
};

test "l1_chain_provider: block info by number walks back from the head" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider();
    defer provider.deinit(testing.allocator);
    try testing.expectError(error.NotFound, provider.l1_block_info_by_number(3));
    for ([_]u64{ 2, 0, 1 }) |number| {
        const info = try provider.l1_block_info_by_number(number);
        try testing.expect(info.hash.eql(fixture.hashes[number]));
        try testing.expectEqual(number * 12, info.timestamp);
    }
    const header = try provider.l1_header_by_hash(fixture.hashes[1]);
    try testing.expect(header.parent_hash.eql(fixture.hashes[0]));
    try testing.expectEqual(@as(?l1_chain_provider.Failure, null), provider.failure);
}

test "l1_chain_provider: transactions and receipts come from the header roots" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider();
    defer provider.deinit(testing.allocator);
    const transactions = try provider.l1_transactions_by_hash(fixture.hashes[1]);
    try testing.expectEqual(@as(usize, 2), transactions.len);
    try testing.expect(transactions[0].to.?.eql(inbox));
    try testing.expect(transactions[0].from.eql(address_of(1)));
    try testing.expectEqualStrings("frame", transactions[0].input);
    // Not sent to the inbox: the sender is not recovered.
    try testing.expect(transactions[1].from.eql(.zero));
    try testing.expectEqual(@as(u8, 2), transactions[1].tx_type);
    const receipts = try provider.l1_receipts_by_hash(fixture.hashes[1]);
    try testing.expectEqual(@as(usize, 2), receipts.len);
    try testing.expect(receipts[0].success and !receipts[1].success);
    try testing.expectEqual(@as(usize, 1), receipts[0].logs.len);
    try testing.expect(receipts[0].logs[0].topics[1].eql(B256{ .bytes = @splat(8) }));
    try testing.expectEqualStrings("log", receipts[0].logs[0].data);
    const empty = try provider.l1_receipts_by_hash(fixture.hashes[2]);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "l1_chain_provider: a corrupt preimage is a recorded failure" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider();
    defer provider.deinit(testing.allocator);
    fixture.store.tamper = true;
    try testing.expectError(error.NotFound, provider.l1_transactions_by_hash(fixture.hashes[1]));
    try testing.expect(provider.failure != null);
}

fn fuzz_decode(provider: *L1ChainProvider, smith: *std.testing.Smith) anyerror!void {
    var buffers: [4][300]u8 = undefined;
    var count: u32 = 0;
    while (count < buffers.len and !smith.eos()) : (count += 1) {
        const length = smith.slice(&buffers[count]);
        provider.values[count] = buffers[count][0..length];
    }
    // Arbitrary trie values must decode or fail cleanly, never crash.
    if (provider.decode_transactions(count)) |items| {
        try testing.expectEqual(count, items.len);
    } else |_| {}
    if (provider.decode_receipts(count)) |items| {
        try testing.expectEqual(count, items.len);
    } else |_| {}
}

test "l1_chain_provider: fuzz body decoding" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider();
    defer provider.deinit(testing.allocator);
    try fuzz.run(&provider, fuzz_decode, .{ .iterations = 256 });
}

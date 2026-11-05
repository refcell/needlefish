//! L1 provider tests over the simulated network: cache misses return NotAvailable and
//! enqueue one fetch, completions fill the caches, null results surface once as NotFound,
//! unverifiable responses never reach the caller, and the request queue stays bounded.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const fixtures = @import("fixtures.zig");
const harness_module = @import("sim_harness.zig");
const l1_provider = @import("l1_provider.zig");
const primitives = @import("../../common/primitives/root.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Provider = l1_provider.L1Provider(io.SimIo);

/// JSON bodies of one block (by number, header, full) and its receipts.
const Chain = struct {
    header: primitives.B256 = .zero,
    number_text: [16 * 1024]u8 = undefined,
    full_text: [32 * 1024]u8 = undefined,
    receipts_text: [16 * 1024]u8 = undefined,
    number_json: []const u8 = "",
    full_json: []const u8 = "",
    receipts_json: []const u8 = "",
    hash_hex: [66]u8 = undefined,

    fn init(chain: *Chain, fake: *FakeRpc) !void {
        const transactions = fixtures.signed_transactions();
        var set: fixtures.ReceiptSet = undefined;
        set.init(4);
        var header = fixtures.header_for(&transactions, 100, .init(@splat(9)));
        header.receipts_root = set.root();
        chain.header = header.hash();
        const number_text = &chain.number_text;
        chain.number_json = try fixtures.block_json(number_text, &header, &transactions, false);
        chain.full_json = try fixtures.block_json(&chain.full_text, &header, &transactions, true);
        chain.receipts_json = try set.json_text(&chain.receipts_text, chain.header);
        _ = try std.fmt.bufPrint(&chain.hash_hex, "0x{x}", .{&chain.header.bytes});
        const hash_hex = &chain.hash_hex;
        add(fake, "eth_getBlockByNumber", "\"0x64\"", chain.number_json);
        add(fake, "eth_getBlockByHash", "true", chain.full_json);
        add(fake, "eth_getBlockByHash", hash_hex, chain.number_json);
        add(fake, "eth_getBlockReceipts", hash_hex, chain.receipts_json);
    }
};

fn add(fake: *FakeRpc, method: []const u8, params_contain: []const u8, result: []const u8) void {
    fake.add(.{ .method = method, .params_contain = params_contain, .result = result });
}

fn setup(
    harness: *Harness,
    provider: *Provider,
    fake: *FakeRpc,
    options: l1_provider.Options,
) !void {
    try harness.init(fake, 0x11);
    errdefer harness.deinit();
    const http_options = harness_module.client_options;
    const io_client = &harness.client_io;
    try provider.init(testing.allocator, io_client, harness.address, http_options, options);
}

test "l1 provider: misses enqueue, completions fill the caches" {
    var fake: FakeRpc = .{};
    var chain: Chain = .{};
    try chain.init(&fake);
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{ .batch_inbox = fixtures.inbox });
    defer harness.deinit();
    defer provider.deinit();

    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(100));
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(100));
    harness.run();
    const info = try provider.l1_block_info_by_number(100);
    try testing.expect(info.hash.eql(chain.header));
    try testing.expectEqual(@as(u32, 1), fake.requests);

    // The by-number fetch also cached the header, so receipts go straight to the RPC.
    const header = try provider.l1_header_by_hash(chain.header);
    try testing.expectEqual(@as(u64, 100), header.number);
    try testing.expectError(error.NotAvailable, provider.l1_receipts_by_hash(chain.header));
    try testing.expectError(error.NotAvailable, provider.l1_transactions_by_hash(chain.header));
    harness.run();
    const receipts = try provider.l1_receipts_by_hash(chain.header);
    try testing.expectEqual(@as(usize, 4), receipts.len);
    const transactions = try provider.l1_transactions_by_hash(chain.header);
    try testing.expectEqual(@as(usize, 4), transactions.len);
    for (transactions) |transaction| try testing.expect(transaction.from.eql(fixtures.dev_address));
    try testing.expectEqual(@as(u32, 3), fake.requests);
    try testing.expectEqual(@as(u64, 0), provider.stats.failures);
}

test "l1 provider: null results surface once as NotFound" {
    var fake: FakeRpc = .{};
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{});
    defer harness.deinit();
    defer provider.deinit();
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(7));
    harness.run();
    try testing.expectError(error.NotFound, provider.l1_block_info_by_number(7));
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(7));
    const unknown: primitives.B256 = .init(@splat(0xee));
    try testing.expectError(error.NotAvailable, provider.l1_receipts_by_hash(unknown));
    harness.run();
    // Untrusted receipts first need the header, which does not exist.
    try testing.expectError(error.NotFound, provider.l1_receipts_by_hash(unknown));
    // The second NotAvailable for 7 re-requested it.
    try testing.expectEqual(@as(u64, 3), provider.stats.not_found);
}

test "l1 provider: unverifiable responses never reach the caller" {
    var fake: FakeRpc = .{};
    var chain: Chain = .{};
    try chain.init(&fake);
    // Number 101 answers with block 100; hash lookups for another hash return block 100.
    add(&fake, "eth_getBlockByNumber", "\"0x65\"", chain.number_json);
    fake.add(.{ .method = "eth_getBlockByHash", .result = chain.number_json });
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{});
    defer harness.deinit();
    defer provider.deinit();
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(101));
    const other: primitives.B256 = .init(@splat(0x42));
    try testing.expectError(error.NotAvailable, provider.l1_header_by_hash(other));
    harness.run();
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(101));
    try testing.expectError(error.NotAvailable, provider.l1_header_by_hash(other));
    try testing.expectEqual(@as(u64, 2), provider.stats.failures);
    harness.run();
    try testing.expectEqual(@as(u64, 4), provider.stats.failures);
}

test "l1 provider: by-number results expire, the queue stays bounded" {
    var fake: FakeRpc = .{};
    var chain: Chain = .{};
    try chain.init(&fake);
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    const ttl_ns = std.time.ns_per_s / 2;
    try setup(&harness, &provider, &fake, .{ .queue_size = 4, .block_by_number_ttl_ns = ttl_ns });
    defer harness.deinit();
    defer provider.deinit();
    for (0..32) |number| {
        const result = provider.l1_block_info_by_number(1000 + number);
        try testing.expectError(error.NotAvailable, result);
    }
    try testing.expectEqual(@as(u32, 4), provider.queue_count);
    try testing.expectEqual(@as(u64, 27), provider.stats.dropped);
    try testing.expectEqual(@as(u64, 1), provider.stats.requests);
    harness.run();
    try testing.expect(!provider.busy());
    try testing.expectEqual(@as(u32, 5), fake.requests);
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(100));
    harness.run();
    // The one-second run outlives the half-second TTL: the result is fetched again.
    try testing.expectError(error.NotAvailable, provider.l1_block_info_by_number(100));
    harness.run();
    try testing.expectEqual(@as(u32, 7), fake.requests);
}

test "l1 provider: drives the derive data source" {
    const derive = @import("../derive/root.zig");
    const protocol = @import("../protocol/root.zig");
    var fake: FakeRpc = .{};
    var chain: Chain = .{};
    try chain.init(&fake);
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{ .batch_inbox = fixtures.inbox });
    defer harness.deinit();
    defer provider.deinit();
    const rollup: protocol.RollupConfig = .{ .batch_inbox_address = fixtures.inbox };
    var source = derive.sources.DataSource.init(testing.allocator, &rollup);
    defer source.deinit();
    var blobs_unused = derive.test_chain.TestChain.init(0, 0, 12);
    const block: protocol.BlockInfo = .{ .hash = chain.header, .number = 100 };
    const batcher = fixtures.dev_address;
    const unused = &blobs_unused;
    try testing.expectError(error.NotAvailable, source.next(&provider, unused, block, batcher));
    harness.run();
    try testing.expectEqualStrings("legacy", try source.next(&provider, unused, block, batcher));
    const second = try source.next(&provider, unused, block, batcher);
    try testing.expectEqualStrings("frame data", second);
}

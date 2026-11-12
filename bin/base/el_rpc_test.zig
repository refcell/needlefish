//! Tests of el-run's JSON-RPC (`el_rpc.zig`) over a fake node: block, transaction and
//! receipt reads from the RPC ring (eviction, unknown and future blocks), head-only state
//! reads, `eth_call` bounds, block parameter parsing; with a fake archive, older blocks and
//! state at older blocks (views opened and closed around each read); the pool.

const std = @import("std");
const base = @import("base");
const el_rpc = @import("el_rpc.zig");
const el_ring = @import("el_ring.zig");
const import_run_cli = @import("import_run.zig");

const testing = std.testing;
const consensus = base.common.consensus;
const primitives = base.common.primitives;
const Executor = base.execution.node.executor.Executor;
const BlockEnv = base.execution.node.executor.BlockEnv;
const B256 = primitives.B256;
const Hash = [32]u8;
const Address = [20]u8;

const spec = import_run_cli.chains[0].spec;

/// Consecutive blocks `first ..`, each with two deposits and their receipts.
const Fixture = struct {
    const count = 6;
    const first = 100;
    /// Cumulative gas after each transaction of every block.
    const gas = [2]u64{ 50_000, 71_000 };

    header_rlp: [count][1024]u8 = undefined,
    header_sizes: [count]usize = undefined,
    deposits: [count][2][200]u8 = undefined,
    transactions: [count][2][]const u8 = undefined,
    receipts: [count][2]consensus.Receipt = undefined,
    hashes: [count]Hash = undefined,

    fn init(fixture: *Fixture) void {
        var parent: B256 = .init(@splat(0x99));
        for (0..count) |index| {
            for (0..2) |which| {
                var source: B256 = .init(@splat(@intCast(which + 1)));
                source.bytes[0] = @intCast(index);
                const envelope: consensus.Envelope = .{ .deposit = .{
                    .source_hash = source,
                    .from = .init(@splat(0xde)),
                    .to = .{ .call = .init(@splat(0x15)) },
                    .mint = 0,
                    .value = 0,
                    .gas_limit = 1_000_000,
                    .is_system_transaction = false,
                    .input = "hi",
                } };
                fixture.transactions[index][which] =
                    envelope.encode_to(&fixture.deposits[index][which]);
                fixture.receipts[index][which] = .{
                    .tx_type = .deposit,
                    .status = true,
                    .cumulative_gas_used = gas[which],
                    .deposit_nonce = 7 + which,
                    .deposit_receipt_version = 1,
                };
            }
            const header: consensus.Header = .{
                .parent_hash = parent,
                .number = first + index,
                .gas_limit = 60_000_000,
                .gas_used = gas[1],
                .timestamp = 1_750_000_000 + 2 * index,
                .base_fee_per_gas = 1_000_000,
                .withdrawals_root = .init(@splat(0x77)),
            };
            const encoded = base.common.rlp.encode_to(&fixture.header_rlp[index], header);
            fixture.header_sizes[index] = encoded.len;
            fixture.hashes[index] = header.hash().bytes;
            parent = .{ .bytes = fixture.hashes[index] };
        }
    }

    fn block(fixture: *const Fixture, index: usize) el_ring.Block {
        return .{
            .number = first + index,
            .hash = fixture.hashes[index],
            .header_rlp = fixture.header_rlp[index][0..fixture.header_sizes[index]],
            .transactions = &fixture.transactions[index],
        };
    }

    fn tx_hash(fixture: *const Fixture, index: usize, which: usize) Hash {
        return primitives.keccak256(fixture.transactions[index][which]).bytes;
    }
};

/// The node behind the fixture: head `head_index`, one account with code and a slot.
const FakeNode = struct {
    fixture: *const Fixture,
    head_index: usize = 0,
    /// The gas and block of the last simulated call.
    call_gas: ?u64 = null,
    call_number: u64 = 0,
    /// The block an archive view shows (null: the head).
    view: ?u64 = null,
    /// The nonce and balance of `dev_address` (the pool test's sender).
    dev_nonce: u64 = 0,

    const address: Address = @splat(0xaa);
    const code = [_]u8{ 0x60, 0x00 };

    fn of(context: *anyopaque) *FakeNode {
        return @ptrCast(@alignCast(context));
    }

    fn node(fake: *FakeNode) el_rpc.Node {
        return .{
            .context = fake,
            .recoverer = no_recovery,
            .head_fn = head,
            .header_fn = header,
            .canonical_hash_fn = canonical_hash,
            .account_fn = account,
            .storage_fn = storage,
            .code_fn = code_of,
            .proof_fn = proof,
            .simulate_fn = simulate,
            .release_fn = release,
        };
    }

    fn no_recovery(_: B256, _: consensus.Signature) ?primitives.Address {
        return null;
    }

    fn head(context: *anyopaque) el_rpc.Label {
        const fake = of(context);
        const index = fake.head_index;
        return .{ .number = Fixture.first + index, .hash = fake.fixture.hashes[index] };
    }

    fn header(context: *anyopaque, hash: Hash) ?[]const u8 {
        const fixture = of(context).fixture;
        for (0..Fixture.count) |index| {
            if (std.mem.eql(u8, &fixture.hashes[index], &hash)) {
                return fixture.header_rlp[index][0..fixture.header_sizes[index]];
            }
        }
        return null;
    }

    fn canonical_hash(context: *anyopaque, number: u64) ?Hash {
        const fake = of(context);
        if (number < Fixture.first or number > Fixture.first + fake.head_index) return null;
        return fake.fixture.hashes[@intCast(number - Fixture.first)];
    }

    fn account(context: *anyopaque, wanted: Address) ?el_rpc.Account {
        const fake = of(context);
        if (std.mem.eql(u8, &wanted, &dev_address)) {
            const empty = base.execution.trie.node.empty_code_hash;
            return .{ .nonce = fake.dev_nonce, .balance = 1 << 80, .code_hash = empty };
        }
        if (!std.mem.eql(u8, &wanted, &address)) return null;
        const code_hash = primitives.keccak256(&code).bytes;
        // At an older block: a balance that names the block.
        const balance: u256 = if (fake.view) |number| 1000 * number else 1_000_000_007;
        return .{ .nonce = 3, .balance = balance, .code_hash = code_hash };
    }

    fn storage(_: *anyopaque, wanted: Address, slot: u256) u256 {
        if (!std.mem.eql(u8, &wanted, &address) or slot != 5) return 0;
        return 0x1234;
    }

    fn code_of(_: *anyopaque, code_hash: Hash) ?[]const u8 {
        if (!std.mem.eql(u8, &code_hash, &primitives.keccak256(&code).bytes)) return null;
        return &code;
    }

    fn proof(
        _: *anyopaque,
        _: Address,
        _: []const u256,
        _: *el_rpc.AccountProof,
        _: []el_rpc.StorageProof,
        _: []u256,
    ) anyerror!?el_rpc.AccountState {
        return error.HistoryUnavailable;
    }

    fn simulate(
        context: *anyopaque,
        env: *const BlockEnv,
        call: Executor.Call,
    ) base.execution.node.executor.Error!Executor.Simulated {
        const fake = of(context);
        std.debug.assert(env.number == fake.view orelse Fixture.first + fake.head_index);
        fake.call_gas = call.gas;
        fake.call_number = env.number;
        const output = &.{ 0xbe, 0xef };
        return .{ .executed = .{ .success = true, .gas_used = 21_000, .output = output } };
    }

    fn release(_: *anyopaque) void {}
};

const Setup = struct {
    fixture: Fixture = .{},
    fake: FakeNode = undefined,
    api: el_rpc.Api = undefined,
    out_buffer: [64 * 1024]u8 = undefined,

    /// Blocks `0 ..= head_index` committed, the ring holding the newest `ring_blocks`.
    fn init(setup: *Setup, ring_blocks: u32, head_index: usize) !void {
        setup.fixture.init();
        setup.fake = .{ .fixture = &setup.fixture };
        const flags: el_rpc.Flags = .{
            .ring_blocks = ring_blocks,
            .ring_mib = 1,
            .index_entries = 64,
        };
        try setup.api.init(testing.allocator, spec, setup.fake.node(), &flags);
        for (0..head_index + 1) |index| {
            setup.fake.head_index = index;
            const block = setup.fixture.block(index);
            _ = setup.api.store.on_block(&block, &setup.fixture.receipts[index]);
        }
    }

    fn deinit(setup: *Setup) void {
        setup.api.deinit(testing.allocator);
    }

    /// The response to `body`, which must parse as JSON.
    fn request(setup: *Setup, body: []const u8) ![]const u8 {
        var out: std.Io.Writer = .fixed(&setup.out_buffer);
        _ = el_rpc.Router.handle(&setup.api, body, &out);
        const text = out.buffered();
        try base.utilities.json.validate(text);
        return text;
    }
};

/// The archive behind the fixture: every block's record (a store holding all of them), the
/// window `oldest..head`, and views that set the fake node's `view`.
const FakeHistory = struct {
    store: el_rpc.Store,
    fake: *FakeNode,
    oldest: u64,
    views_open: u32 = 0,
    views: u32 = 0,

    fn init(history: *FakeHistory, setup: *Setup, oldest: u64) !void {
        const flags: el_rpc.Flags = .{ .ring_blocks = 16, .ring_mib = 1, .index_entries = 64 };
        history.* = .{
            .store = try el_rpc.Store.init(testing.allocator, &flags),
            .fake = &setup.fake,
            .oldest = oldest,
        };
        for (0..setup.fake.head_index + 1) |index| {
            const block = setup.fixture.block(index);
            _ = history.store.on_block(&block, &setup.fixture.receipts[index]);
        }
        setup.api.history = .{
            .context = history,
            .window_fn = window,
            .block_fn = block_at,
            .find_block_fn = find_block,
            .find_transaction_fn = find_transaction,
            .view_begin_fn = view_begin,
            .view_end_fn = view_end,
        };
    }

    fn deinit(history: *FakeHistory) void {
        history.store.deinit(testing.allocator);
    }

    fn of(context: *anyopaque) *FakeHistory {
        return @ptrCast(@alignCast(context));
    }

    fn window(context: *anyopaque) ?el_rpc.Window {
        const history = of(context);
        return .{ .oldest = history.oldest, .head = Fixture.first + history.fake.head_index };
    }

    fn block_at(context: *anyopaque, number: u64) anyerror!?el_rpc.Archived {
        const history = of(context);
        if (number < history.oldest) return null;
        const stored = history.store.record(number) orelse return null;
        return .{ .hash = stored.hash, .bytes = stored.bytes };
    }

    fn find_block(context: *anyopaque, hash: Hash) anyerror!?u64 {
        const history = of(context);
        var number = history.oldest;
        while (number <= Fixture.first + history.fake.head_index) : (number += 1) {
            const stored = history.store.record(number) orelse continue;
            if (std.mem.eql(u8, &stored.hash, &hash)) return number;
        }
        return null;
    }

    fn find_transaction(context: *anyopaque, hash: Hash) anyerror!?el_rpc.Location {
        const location = of(context).store.find(&hash) orelse return null;
        if (location.number < of(context).oldest) return null;
        return location;
    }

    fn view_begin(context: *anyopaque, number: u64, state_root: Hash) void {
        const history = of(context);
        std.debug.assert(history.views_open == 0);
        std.debug.assert(state_root.len == 32);
        history.views_open += 1;
        history.views += 1;
        history.fake.view = number;
    }

    fn view_end(context: *anyopaque) void {
        const history = of(context);
        std.debug.assert(history.views_open == 1);
        history.views_open -= 1;
        history.fake.view = null;
    }
};

const address_hex = repeat("aa", 20);
/// The dev mnemonic's first account (every Ethereum devnet's): the pool test's sender.
const dev_key = [32]u8{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};
const dev_address: Address = .{
    0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce,
    0x6a, 0xb8, 0x82, 0x72, 0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
};

/// `text` `count` times.
fn repeat(comptime text: []const u8, comptime count: usize) []const u8 {
    comptime var result: []const u8 = "";
    inline for (0..count) |_| result = result ++ text;
    return result;
}

fn expect_contains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, text });
        return error.TestExpectedContains;
    }
}

fn hex(bytes: []const u8, buffer: []u8) []const u8 {
    buffer[0] = '0';
    buffer[1] = 'x';
    base.utilities.json.hex_encode(buffer[2..][0 .. 2 * bytes.len], bytes);
    return buffer[0 .. 2 + 2 * bytes.len];
}

test "el rpc: blocks by number and hash from the ring; evicted, future and unknown blocks" {
    var setup: Setup = .{};
    try setup.init(4, 5); // Blocks 100..105, the ring keeps 102..105.
    defer setup.deinit();
    var text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}
    );
    try expect_contains(text, "\"result\":\"0x69\"");
    // Fees: the head's base fee (1,000,000 wei) plus op-geth's 0.001 gwei tip floor.
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_maxPriorityFeePerGas","params":[]}
    );
    try expect_contains(text, "\"result\":\"0xf4240\"");
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_gasPrice","params":[]}
    );
    try expect_contains(text, "\"result\":\"0x1e8480\"");
    var hash_text: [66]u8 = undefined;
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x67",false]}
    );
    try expect_contains(text, hex(&setup.fixture.hashes[3], &hash_text));
    try expect_contains(text, hex(&setup.fixture.tx_hash(3, 1), &hash_text));
    try expect_contains(text, "\"number\":\"0x67\"");
    // Executed but evicted: an error naming the ring, never a wrong or empty block.
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x65",true]}
    );
    try expect_contains(text, "\"code\":-32000");
    try expect_contains(text, "blocks 102..105");
    // Above the head, and an unknown hash: null.
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x6a",false]}
    );
    try expect_contains(text, "\"result\":null");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByHash\"," ++
        "\"params\":[\"0x" ++ comptime repeat("11", 32) ++ "\",false]}");
    try expect_contains(text, "\"result\":null");
    // By hash, with full transactions.
    var body_buffer: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getBlockByHash\",\"params\":[\"{s}\",true]}}", .{
        hex(&setup.fixture.hashes[5], &hash_text),
    });
    text = try setup.request(body);
    try expect_contains(text, "\"number\":\"0x69\"");
    try expect_contains(text, "\"transactionIndex\":\"0x1\"");
    try expect_contains(text, "\"sourceHash\"");
    // `latest` is the head; `safe` needs the Engine API.
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}
    );
    try expect_contains(text, hex(&setup.fixture.hashes[5], &hash_text));
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["safe",false]}
    );
    try expect_contains(text, "--engine.addr");
}

test "el rpc: transactions and receipts by hash" {
    var setup: Setup = .{};
    try setup.init(4, 5);
    defer setup.deinit();
    var hash_text: [66]u8 = undefined;
    var body_buffer: [256]u8 = undefined;
    const receipt_body = "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getTransactionReceipt\",\"params\":[\"{s}\"]}}";
    // The second transaction of block 104: its own gas (71000 - 50000), cumulative gas, the
    // block, and its deposit fields.
    var body = try std.fmt.bufPrint(&body_buffer, receipt_body, .{
        hex(&setup.fixture.tx_hash(4, 1), &hash_text),
    });
    var text = try setup.request(body);
    try expect_contains(text, "\"gasUsed\":\"0x5208\"");
    try expect_contains(text, "\"cumulativeGasUsed\":\"0x11558\"");
    try expect_contains(text, "\"blockNumber\":\"0x68\"");
    try expect_contains(text, "\"transactionIndex\":\"0x1\"");
    try expect_contains(text, "\"depositNonce\":\"0x8\"");
    try expect_contains(text, hex(&setup.fixture.hashes[4], &hash_text));
    // A transaction of an evicted block is unknown: null.
    body = try std.fmt.bufPrint(&body_buffer, receipt_body, .{
        hex(&setup.fixture.tx_hash(1, 0), &hash_text),
    });
    text = try setup.request(body);
    try expect_contains(text, "\"result\":null");
    body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getTransactionByHash\",\"params\":[\"{s}\"]}}", .{
        hex(&setup.fixture.tx_hash(2, 0), &hash_text),
    });
    text = try setup.request(body);
    try expect_contains(text, "\"blockNumber\":\"0x66\"");
    try expect_contains(text, "\"transactionIndex\":\"0x0\"");
    // As op-reth: a deposit shows its receipt's nonce and version, and the block's time.
    try expect_contains(text, "\"nonce\":\"0x7\"");
    try expect_contains(text, "\"depositReceiptVersion\":\"0x1\"");
    try expect_contains(text, "\"blockTimestamp\":\"0x684ee184\"");
    try expect_contains(text, hex(&setup.fixture.tx_hash(2, 0), &hash_text));
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["0x69"]}
    );
    try expect_contains(text, "\"gasUsed\":\"0xc350\"");
    try expect_contains(text, "\"gasUsed\":\"0x5208\"");
}

test "el rpc: the transaction index never answers from a reused bucket" {
    var setup: Setup = .{};
    // One bucket: every block's transactions overwrite the older ones' entries.
    setup.fixture.init();
    setup.fake = .{ .fixture = &setup.fixture };
    const flags: el_rpc.Flags = .{ .ring_blocks = 8, .ring_mib = 1, .index_entries = 4 };
    try setup.api.init(testing.allocator, spec, setup.fake.node(), &flags);
    defer setup.deinit();
    for (0..Fixture.count) |index| {
        setup.fake.head_index = index;
        _ = setup.api.store.on_block(&setup.fixture.block(index), &setup.fixture.receipts[index]);
    }
    for (0..Fixture.count) |index| {
        for (0..2) |which| {
            const found = setup.api.store.find(&setup.fixture.tx_hash(index, which));
            // The newest two blocks keep their four entries; older ones are forgotten.
            if (index + 2 < Fixture.count) {
                try testing.expect(found == null);
            } else {
                try testing.expectEqual(Fixture.first + index, found.?.number);
                try testing.expectEqual(@as(u32, @intCast(which)), found.?.index);
            }
        }
    }
}

test "el rpc: state is served at the head only" {
    var setup: Setup = .{};
    try setup.init(4, 5);
    defer setup.deinit();
    var text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"latest\"]}");
    try expect_contains(text, "\"result\":\"0x3b9aca07\"");
    // The head by number is the head; any older block is refused, not answered.
    const count_method = "\"eth_getTransactionCount\",";
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++ count_method ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"0x69\"]}");
    try expect_contains(text, "\"result\":\"0x3\"");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"0x68\"]}");
    try expect_contains(text, "historical state unavailable");
    try expect_contains(text, "\"code\":-32000");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getStorageAt\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"0x05\",\"latest\"]}");
    try expect_contains(text, "\"result\":\"0x" ++ comptime repeat("00", 30) ++ "1234\"");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\"]}");
    try expect_contains(text, "\"result\":\"0x6000\"");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\"," ++
        "\"params\":[\"0x" ++ comptime repeat("bb", 20) ++ "\",\"latest\"]}");
    try expect_contains(text, "\"result\":\"0x\"");
}

test "el rpc: eth_call runs at the head with its gas capped" {
    var setup: Setup = .{};
    try setup.init(4, 5);
    defer setup.deinit();
    var text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\"," ++
        "\"params\":[{\"to\":\"0x" ++ address_hex ++ "\",\"gas\":\"0xffffffffffff\"},\"latest\"]}");
    try expect_contains(text, "\"result\":\"0xbeef\"");
    try testing.expectEqual(@as(?u64, el_rpc.call_gas_max), setup.fake.call_gas);
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\"," ++
        "\"params\":[{\"to\":\"0x" ++ address_hex ++ "\",\"gas\":\"0x5208\"}]}");
    try testing.expectEqual(@as(?u64, 21_000), setup.fake.call_gas);
    // Without gas the executor picks its (EIP-7825-capped) default.
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\"," ++
        "\"params\":[{\"to\":\"0x" ++ address_hex ++ "\"}]}");
    try testing.expectEqual(@as(?u64, null), setup.fake.call_gas);
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\"," ++
        "\"params\":[{\"to\":\"0x" ++ address_hex ++ "\"},\"0x64\"]}");
    try expect_contains(text, "historical state unavailable");
}

test "el rpc: block parameters and slots" {
    const parse_tag = el_rpc.parse_tag;
    try testing.expectEqual(el_rpc.Tag.latest, try parse_tag("\"pending\""));
    try testing.expectEqual(el_rpc.Tag{ .number = 0 }, try parse_tag("\"earliest\""));
    try testing.expectEqual(el_rpc.Tag{ .number = 0x1a }, try parse_tag("\"0x1a\""));
    const by_number = try parse_tag("{\"blockNumber\":\"0x10\"}");
    try testing.expectEqual(el_rpc.Tag{ .number = 16 }, by_number);
    const by_hash = try parse_tag("{\"blockHash\":\"0x" ++ comptime repeat("ab", 32) ++ "\"}");
    try testing.expectEqualSlices(u8, &@as(Hash, @splat(0xab)), &by_hash.hash);
    try testing.expectError(error.InvalidParams, parse_tag("\"newest\""));
    try testing.expectError(error.InvalidParams, parse_tag("16"));
    try testing.expectError(error.InvalidParams, parse_tag("{\"other\":1}"));
    try testing.expectEqual(@as(u256, 5), try el_rpc.parse_slot("0x05"));
    const padded = "0x" ++ comptime repeat("0", 63) ++ "5";
    try testing.expectEqual(@as(u256, 5), try el_rpc.parse_slot(padded));
    const too_long = "0x" ++ comptime repeat("0", 65);
    try testing.expectError(error.InvalidParams, el_rpc.parse_slot(too_long));
    try testing.expectError(error.InvalidParams, el_rpc.parse_slot("5"));
}

test "el rpc: flags" {
    var flags: el_rpc.Flags = .{};
    try testing.expect(!try flags.parse("--db", "x"));
    flags.enable();
    try testing.expectEqualStrings(el_rpc.default_addr, flags.addr.?);
    try testing.expect(try flags.parse("--rpc.addr", "127.0.0.1:9545"));
    flags.enable();
    try testing.expectEqualStrings("127.0.0.1:9545", flags.addr.?);
    try testing.expect(try flags.parse("--rpc.tx-index", "1024"));
    try testing.expectError(error.InvalidArguments, flags.parse("--rpc.tx-index", "1000"));
    try testing.expectError(error.InvalidArguments, flags.parse("--rpc.ring-blocks", "1"));
    try testing.expectError(error.InvalidArguments, flags.parse("--rpc.ring-mb", "0"));
}

test "el rpc: the archive serves blocks past the ring and state at older blocks" {
    var setup: Setup = .{};
    try setup.init(2, 5); // Blocks 100..105, the ring keeps 104..105.
    defer setup.deinit();
    var history: FakeHistory = undefined;
    try history.init(&setup, 101);
    defer history.deinit();
    var hash_text: [66]u8 = undefined;
    // Block 102 left the ring: the archive answers by number, by hash, and its transaction.
    var text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x66",false]}
    );
    try expect_contains(text, hex(&setup.fixture.hashes[2], &hash_text));
    var body_buffer: [256]u8 = undefined;
    var body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getBlockByHash\",\"params\":[\"{s}\",false]}}", .{hash_text});
    text = try setup.request(body);
    try expect_contains(text, "\"number\":\"0x66\"");
    var tx_text: [66]u8 = undefined;
    _ = hex(&setup.fixture.tx_hash(2, 1), &tx_text);
    body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getTransactionReceipt\",\"params\":[\"{s}\"]}}", .{tx_text});
    text = try setup.request(body);
    try expect_contains(text, "\"blockNumber\":\"0x66\"");
    try expect_contains(text, "\"cumulativeGasUsed\":\"0x11558\"");
    // Block 100 is below the window: executed, but not held.
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x64",false]}
    );
    try expect_contains(text, "archive keeps blocks 101..105");
    // State at an older block reads through a view of it; the head reads the head.
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"0x66\"]}");
    try expect_contains(text, "\"result\":\"0x18e70\""); // 1000 * 102.
    try testing.expectEqual(@as(?u64, null), setup.fake.view);
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"latest\"]}");
    try expect_contains(text, "\"result\":\"0x3b9aca07\"");
    // The state after block 100 is block 101's pre-state: in the window; 99 is not.
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\"," ++
        "\"params\":[{\"to\":\"0x" ++ address_hex ++ "\"},\"0x64\"]}");
    try expect_contains(text, "\"result\":\"0xbeef\"");
    try testing.expectEqual(@as(u64, 100), setup.fake.call_number);
    history.oldest = 102;
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\"," ++
        "\"params\":[\"0x" ++ address_hex ++ "\",\"0x64\"]}");
    try expect_contains(text, "keeps the state of blocks 101..105, not block 100");
    try testing.expectEqual(@as(u32, 2), history.views);
    try testing.expectEqual(@as(u32, 0), history.views_open);
}

test "el rpc: eth_sendRawTransaction pools the transaction until a block includes it" {
    var setup: Setup = .{};
    try setup.init(4, 5);
    defer setup.deinit();
    setup.api.node.recoverer = consensus.signature.recover_address;
    const transaction: consensus.Eip1559 = .{
        .chain_id = spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 21_000,
        .to = .{ .call = .{ .bytes = @splat(0x22) } },
        .value = 1,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(transaction, dev_key);
    var raw_buffer: [256]u8 = undefined;
    const raw = envelope.encode_to(&raw_buffer);
    var body_buffer: [800]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x{x}\"]}}", .{raw});
    var hash_text: [66]u8 = undefined;
    _ = hex(&envelope.hash().bytes, &hash_text);
    var text = try setup.request(body);
    try expect_contains(text, &hash_text);
    // The same transaction again: the pool already has it.
    text = try setup.request(body);
    try expect_contains(text, "AlreadyKnown");
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"txpool_status","params":[]}
    );
    try expect_contains(text, "\"pending\":\"0x1\",\"queued\":\"0x0\"");
    const dev_hex = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getTransactionCount\",\"params\":[\"" ++ dev_hex ++ "\",\"pending\"]}");
    try expect_contains(text, "\"result\":\"0x1\"");
    text = try setup.request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"eth_getTransactionCount\",\"params\":[\"" ++ dev_hex ++ "\",\"latest\"]}");
    try expect_contains(text, "\"result\":\"0x0\"");
    var by_hash: [256]u8 = undefined;
    const by_hash_body = try std.fmt.bufPrint(&by_hash, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"method\":\"eth_getTransactionByHash\",\"params\":[\"{s}\"]}}", .{hash_text});
    text = try setup.request(by_hash_body);
    try expect_contains(text, "\"from\":\"" ++ dev_hex ++ "\"");
    try expect_contains(text, "\"blockHash\":null");
    // A block includes it: the pool drops it, the sender's nonce moves on.
    setup.fake.dev_nonce = 1;
    var block = setup.fixture.block(5);
    const included = [_][]const u8{raw};
    block.transactions = &included;
    const receipts = [_]consensus.Receipt{.{
        .tx_type = .eip1559,
        .status = true,
        .cumulative_gas_used = 21_000,
    }};
    _ = setup.api.on_block(&block, &receipts);
    text = try setup.request(
        \\{"jsonrpc":"2.0","id":1,"method":"txpool_status","params":[]}
    );
    try expect_contains(text, "\"pending\":\"0x0\"");
    // A transaction for another chain never enters the pool.
    var other = transaction;
    other.chain_id = 1;
    const other_raw = (try consensus.tx.sign(other, dev_key)).encode_to(&raw_buffer);
    const other_body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x{x}\"]}}", .{other_raw});
    text = try setup.request(other_body);
    try expect_contains(text, "WrongChainId");
}

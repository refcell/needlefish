//! The withdrawal flow over fake L1 and L2 JSON-RPC transports: the L2 serves the public
//! Base Sepolia fixture (receipt, header, proof), the L1 runs a scripted portal, registry,
//! factory and game that react to the signed transactions it mines. Covers prove then
//! finalize, paused and status-only runs, resuming from a journal after a crash, and
//! initiating on L2.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const registry = @import("../../proof/contracts/anchor_state_registry.zig");
const factory = @import("../../proof/contracts/dispute_game_factory.zig");
const calldata = @import("calldata.zig");
const flow_module = @import("flow.zig");
const journal_module = @import("journal.zig");
const reader_module = @import("reader.zig");
const withdrawal_module = @import("withdrawal.zig");

const Hash = [32]u8;
const Address = [20]u8;

const fixture_json = @embedFile("testdata/base_sepolia_withdrawal_proof.json");
const portal: Address = @splat(0x50);
const factory_address: Address = @splat(0xfa);
const registry_address: Address = @splat(0xa5);
const game_proxy: Address = @splat(0x9a);
const fixture_transaction = "809b89557a33bbb8a20141e46e0c74129db40c184d0e3b9ed2f4e7c78eb74b85";
const sends_max = 16;

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    receipt: []const u8,
    header: []const u8,
    proof: []const u8,
    header_number: u64,
    receipt_block: u64,
    root_claim: Hash,

    fn load(fixture: *Fixture) !void {
        fixture.arena = .init(testing.allocator);
        const allocator = fixture.arena.allocator();
        const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, fixture_json, .{});
        const stringify = std.json.Stringify.valueAlloc;
        fixture.receipt = try stringify(allocator, root.object.get("receipt").?, .{});
        const header = root.object.get("header").?;
        fixture.header = try stringify(allocator, header, .{});
        fixture.proof = try stringify(allocator, root.object.get("proof").?, .{});
        fixture.header_number = try parse_hex(header.object.get("number").?.string);
        const receipt = root.object.get("receipt").?;
        fixture.receipt_block = try parse_hex(receipt.object.get("blockNumber").?.string);
        const claim = root.object.get("game").?.object.get("rootClaim").?.string;
        _ = try std.fmt.hexToBytes(&fixture.root_claim, claim[2..]);
    }

    fn parse_hex(text: []const u8) !u64 {
        return std.fmt.parseInt(u64, text[2..], 16);
    }
};

const Sent = struct { hash: Hash, nonce: u64, selector: [4]u8, block: u64 = 0 };

const Chain = struct {
    fixture: *const Fixture,
    is_l2: bool,
    head: u64 = 10,
    time_s: u64 = 1_000,
    account_nonce: u64 = 0,
    sent: [sends_max]Sent = undefined,
    sent_count: u32 = 0,
    proven_at: u64 = 0,
    finalized: bool = false,
    paused: bool = false,
    game_finalized: bool = true,
    finalize_success: bool = true,

    fn transport(chain: *Chain) rpc.Transport {
        return .{ .context = chain, .send_fn = send };
    }

    fn block_hash(number: u64) Hash {
        var hash: Hash = @splat(0xbb);
        std.mem.writeInt(u64, hash[0..8], number, .big);
        return hash;
    }

    /// Mines every pending transaction in one block at `time_s`.
    fn mine(chain: *Chain, time_s: u64) void {
        chain.head += 1;
        chain.time_s = time_s;
        for (chain.sent[0..chain.sent_count]) |*sent| {
            if (sent.block != 0 or sent.nonce != chain.account_nonce) continue;
            sent.block = chain.head;
            chain.account_nonce += 1;
            if (std.mem.eql(u8, &sent.selector, &calldata.prove_withdrawal_transaction)) {
                chain.proven_at = time_s;
            }
            if (std.mem.eql(u8, &sent.selector, &calldata.finalize_withdrawal_transaction)) {
                chain.finalized = chain.finalize_success;
            }
        }
    }

    fn count(chain: *const Chain, selector: [4]u8) u32 {
        var total: u32 = 0;
        for (chain.sent[0..chain.sent_count]) |sent| {
            if (std.mem.eql(u8, &sent.selector, &selector)) total += 1;
        }
        return total;
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const chain: *Chain = @ptrCast(@alignCast(context));
        var arena_memory: [64 * 1024]u8 = undefined;
        var arena: std.heap.FixedBufferAllocator = .init(&arena_memory);
        const Value = std.json.Value;
        const request = std.json.parseFromSliceLeaky(Value, arena.allocator(), body, .{}) catch
            return error.TransportFailed;
        const id = request.object.get("id").?.integer;
        const method = request.object.get("method").?.string;
        const params = request.object.get("params").?.array.items;
        var writer: std.Io.Writer = .fixed(response);
        writer.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":", .{id}) catch
            return error.ResponseTooLarge;
        chain.answer(method, params, &writer) catch |err| switch (err) {
            error.WriteFailed => return error.ResponseTooLarge,
            else => return error.TransportFailed,
        };
        writer.writeAll("}") catch return error.ResponseTooLarge;
        return writer.buffered().len;
    }

    fn answer(
        chain: *Chain,
        method: []const u8,
        params: []const std.json.Value,
        w: *std.Io.Writer,
    ) !void {
        const eql = std.mem.eql;
        if (eql(u8, method, "eth_getBlockByNumber")) return chain.block(params[0].string, w);
        if (eql(u8, method, "eth_maxPriorityFeePerGas")) return w.writeAll("\"0x1\"");
        if (eql(u8, method, "eth_estimateGas")) return w.writeAll("\"0x30d40\"");
        if (eql(u8, method, "eth_getTransactionCount")) {
            return w.print("\"0x{x}\"", .{chain.account_nonce});
        }
        if (eql(u8, method, "eth_sendRawTransaction")) return chain.accept(params[0].string, w);
        if (eql(u8, method, "eth_getTransactionReceipt")) return chain.receipt(params[0].string, w);
        if (eql(u8, method, "eth_getProof")) return w.writeAll(chain.fixture.proof);
        if (eql(u8, method, "eth_call")) return chain.call(params[0], w);
        return error.UnknownMethod;
    }

    fn block(chain: *Chain, tag: []const u8, w: *std.Io.Writer) !void {
        const number = if (std.mem.eql(u8, tag, "latest"))
            chain.head
        else
            try std.fmt.parseInt(u64, tag[2..], 16);
        if (chain.is_l2 and number == chain.fixture.header_number) {
            return w.writeAll(chain.fixture.header);
        }
        // The withdrawal's L2 block is older than every game.
        const timestamp = if (chain.is_l2) 1_500 else chain.time_s;
        try w.print("{{\"number\":\"0x{x}\",\"timestamp\":\"0x{x}\",\"baseFeePerGas\":\"0x7\"," ++
            "\"hash\":\"0x{x}\"}}", .{ number, timestamp, &block_hash(number) });
    }

    fn accept(chain: *Chain, hex: []const u8, w: *std.Io.Writer) !void {
        var raw: [16 * 1024]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, hex[2..]);
        const envelope = try consensus.tx.Envelope.decode(bytes);
        const input = envelope.input();
        assert(chain.sent_count < sends_max);
        chain.sent[chain.sent_count] = .{
            .hash = envelope.hash().bytes,
            .nonce = envelope.nonce().?,
            .selector = input[0..4].*,
        };
        chain.sent_count += 1;
        try w.print("\"0x{x}\"", .{&envelope.hash().bytes});
    }

    fn receipt(chain: *Chain, hex: []const u8, w: *std.Io.Writer) !void {
        var hash: Hash = undefined;
        _ = try std.fmt.hexToBytes(&hash, hex[2..]);
        var expected: Hash = undefined;
        _ = try std.fmt.hexToBytes(&expected, fixture_transaction);
        if (chain.is_l2 and std.mem.eql(u8, &hash, &expected)) {
            return w.writeAll(chain.fixture.receipt);
        }
        for (chain.sent[0..chain.sent_count]) |sent| {
            if (!std.mem.eql(u8, &sent.hash, &hash) or sent.block == 0) continue;
            try w.print("{{\"status\":\"0x1\",\"blockNumber\":\"0x{x}\",\"blockHash\":\"0x{x}\"," ++
                "\"logs\":[", .{ sent.block, &block_hash(sent.block) });
            if (std.mem.eql(u8, &sent.selector, &calldata.finalize_withdrawal_transaction)) {
                try chain.finalized_log(w);
            }
            return w.writeAll("]}");
        }
        try w.writeAll("null");
    }

    fn finalized_log(chain: *Chain, w: *std.Io.Writer) !void {
        var out: [4]withdrawal_module.Withdrawal = undefined;
        _ = &out;
        const withdrawal_hash = withdrawal_hash_of(chain.fixture);
        try w.print("{{\"address\":\"0x{x}\",\"topics\":[\"0x{x}\",\"0x{x}\"]," ++
            "\"data\":\"0x{x}\"}}", .{
            &portal,
            &calldata.withdrawal_finalized_topic,
            &withdrawal_hash,
            &word(@intFromBool(chain.finalize_success)),
        });
    }

    fn call(chain: *Chain, request: std.json.Value, w: *std.Io.Writer) !void {
        var to: Address = undefined;
        _ = try std.fmt.hexToBytes(&to, request.object.get("to").?.string[2..]);
        var input_buffer: [256]u8 = undefined;
        const data_hex = request.object.get("data").?.string[2..];
        const input = try std.fmt.hexToBytes(&input_buffer, data_hex);
        const selector = input[0..4].*;
        if (is(selector, calldata.check_withdrawal)) return w.writeAll("\"0x\"");
        var result: [3][32]u8 = undefined;
        const words = try chain.call_words(selector, &result);
        try w.writeAll("\"0x");
        for (result[0..words]) |item| try w.print("{x}", .{&item});
        try w.writeAll("\"");
    }

    fn call_words(chain: *Chain, selector: [4]u8, out: *[3][32]u8) !usize {
        if (is(selector, calldata.dispute_game_factory)) {
            return one(out, address_word(factory_address));
        }
        if (is(selector, calldata.anchor_state_registry)) {
            return one(out, address_word(registry_address));
        }
        if (is(selector, calldata.finalized_withdrawals)) return one(out, flag(chain.finalized));
        if (is(selector, registry.paused)) return one(out, flag(chain.paused));
        if (is(selector, calldata.proven_withdrawals)) {
            out[0] = address_word(if (chain.proven_at == 0) @splat(0) else game_proxy);
            out[1] = word(chain.proven_at);
            return 2;
        }
        if (is(selector, registry.is_game_blacklisted)) return one(out, word(0));
        if (is(selector, registry.is_game_retired)) return one(out, word(0));
        if (is(selector, registry.is_game_proper)) return one(out, word(1));
        if (is(selector, registry.is_game_respected)) return one(out, word(1));
        if (is(selector, registry.is_game_finalized)) return one(out, flag(chain.game_finalized));
        if (is(selector, calldata.game_status)) return one(out, word(2));
        if (is(selector, calldata.proof_maturity_delay_seconds)) return one(out, word(100));
        if (is(selector, calldata.game_resolved_at)) return one(out, word(500));
        if (is(selector, registry.dispute_game_finality_delay_seconds)) return one(out, word(200));
        if (is(selector, factory.game_count)) return one(out, word(1));
        if (is(selector, factory.game_at_index)) {
            out[0] = word(621);
            out[1] = word(2_000);
            out[2] = address_word(game_proxy);
            return 3;
        }
        if (is(selector, calldata.game_extra_data)) {
            out[0] = word(32);
            out[1] = word(32);
            out[2] = word(chain.fixture.header_number);
            return 3;
        }
        if (is(selector, calldata.game_root_claim)) return one(out, chain.fixture.root_claim);
        return error.UnknownSelector;
    }
};

fn is(selector: [4]u8, expected: [4]u8) bool {
    return std.mem.eql(u8, &selector, &expected);
}

fn flag(value: bool) [32]u8 {
    return word(@intFromBool(value));
}

fn one(out: *[3][32]u8, value: [32]u8) usize {
    out[0] = value;
    return 1;
}

fn word(value: u64) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u64, out[24..32], value, .big);
    return out;
}

fn address_word(address: Address) [32]u8 {
    var out: [32]u8 = @splat(0);
    out[12..32].* = address;
    return out;
}

fn withdrawal_hash_of(fixture: *const Fixture) Hash {
    _ = fixture;
    // From the fixture's MessagePassed event (its last data word).
    var hash: Hash = undefined;
    const hex = "125349959253c566b91cfcfa02a87a02" ++ "6715f60038c56262047ef3622a12c4ea";
    // A 64-digit literal always decodes.
    _ = std.fmt.hexToBytes(&hash, hex) catch unreachable;
    return hash;
}

const MemoryJournal = struct {
    bytes: [64 * journal_module.record_bytes]u8 = undefined,
    length: usize = 0,
    fail: bool = false,

    fn sink(journal: *MemoryJournal) flow_module.JournalSink {
        return .{ .context = journal, .append = append };
    }

    fn append(context: *anyopaque, record: journal_module.Record) bool {
        const journal: *MemoryJournal = @ptrCast(@alignCast(context));
        if (journal.fail) return false;
        assert(journal.length + journal_module.record_bytes <= journal.bytes.len);
        const size = journal_module.record_bytes;
        journal_module.encode(record, journal.bytes[journal.length..][0..size]);
        journal.length += journal_module.record_bytes;
        return true;
    }

    fn replay(journal: *const MemoryJournal) !journal_module.Replay {
        return journal_module.replay(journal.bytes[0..journal.length]);
    }
};

const Harness = struct {
    fixture: Fixture = undefined,
    l1: Chain = undefined,
    l2: Chain = undefined,
    l1_client: rpc.Client = undefined,
    l2_client: rpc.Client = undefined,
    reader: reader_module.Reader = undefined,
    l1_driver: flow_module.SendDriver = undefined,
    l2_driver: flow_module.SendDriver = undefined,
    journal: MemoryJournal = .{},
    now_ms: u64 = 1_000_000,

    fn init(harness: *Harness) !void {
        try harness.fixture.load();
        harness.l1 = .{ .fixture = &harness.fixture, .is_l2 = false };
        harness.l2 = .{ .fixture = &harness.fixture, .is_l2 = true };
        const limits: rpc.Limits = .{
            .request_bytes_max = 64 * 1024,
            .response_bytes_max = 64 * 1024,
            .parse_bytes_max = 1024 * 1024,
        };
        harness.l1_client = try rpc.Client.init(testing.allocator, harness.l1.transport(), limits);
        harness.l2_client = try rpc.Client.init(testing.allocator, harness.l2.transport(), limits);
        const sender = accounts.derive_dev(0);
        harness.reader = try reader_module.Reader.init(
            testing.allocator,
            &harness.l1_client,
            &harness.l2_client,
            portal,
            sender.address.bytes,
            .{},
        );
        _ = try harness.reader.resolve_contracts();
        const driver_config: @import("../tx_manager/root.zig").driver.Config = .{
            .chain_id = 900,
            .private_key = sender.private_key,
            .from = sender.address,
            .data_bytes_max = 16 * 1024,
            .manager = .{
                .num_confirmations = 1,
                .resubmission_timeout_ms = 30_000,
                .receipt_query_interval_ms = 1_000,
            },
        };
        harness.l1_driver = try flow_module.SendDriver.init(testing.allocator, driver_config);
        harness.l2_driver = try flow_module.SendDriver.init(testing.allocator, driver_config);
    }

    fn deinit(harness: *Harness) void {
        harness.l2_driver.deinit(testing.allocator);
        harness.l1_driver.deinit(testing.allocator);
        harness.reader.deinit(testing.allocator);
        harness.l2_client.deinit(testing.allocator);
        harness.l1_client.deinit(testing.allocator);
        harness.fixture.arena.deinit();
    }

    fn start(harness: *Harness, config: flow_module.Config) !flow_module.Flow {
        var result = try flow_module.Flow.init(
            testing.allocator,
            config,
            &harness.reader,
            &harness.l1_driver,
            &harness.l2_driver,
            harness.journal.sink(),
            try harness.journal.replay(),
        );
        // The hook needs the flow's final address; callers re-point it after moving.
        _ = &result;
        return result;
    }

    /// Steps the flow with one block mined per simulated second.
    fn run(harness: *Harness, subject: *flow_module.Flow, seconds_max: u32) !flow_module.Progress {
        harness.l1_driver.config.publish_hook = subject.publish_hook();
        harness.l2_driver.config.publish_hook = subject.publish_hook();
        var progress: flow_module.Progress = .working;
        for (0..seconds_max) |_| {
            harness.now_ms += 1_000;
            const time_s = harness.now_ms / 1_000;
            harness.l1.mine(time_s);
            harness.l2.mine(time_s);
            progress = try subject.step(harness.now_ms);
            if (progress == .done) return progress;
        }
        return progress;
    }
};

const finalize_selector = calldata.finalize_withdrawal_transaction;
const run_config: flow_module.Config = .{
    .command = .run,
    .l2_transaction = fixture_hash(),
    .poll_interval_ms = 1_000,
};

fn fixture_hash() Hash {
    var hash: Hash = undefined;
    _ = std.fmt.hexToBytes(&hash, fixture_transaction) catch unreachable;
    return hash;
}

test "withdrawer flow: run proves, waits out the delays, and finalizes" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var flow = try harness.start(run_config);
    defer flow.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&flow, 600));
    try testing.expectEqual(@as(u32, 1), harness.l1.count(calldata.prove_withdrawal_transaction));
    try testing.expectEqual(@as(u32, 1), harness.l1.count(finalize_selector));
    try testing.expect(harness.l1.finalized);
    const results = flow.results();
    try testing.expectEqual(@as(usize, 1), results.len);
    try testing.expectEqual(flow_module.Status.finalized, results[0].status);
    const journal = try harness.journal.replay();
    try testing.expect(journal.step(.prove).confirmed != null);
    try testing.expect(journal.step(.finalize).confirmed != null);
    // The proof was submitted no earlier than maturity allows.
    try testing.expect(harness.l1.time_s >= harness.l1.proven_at + 101);
}

test "withdrawer flow: tx_manager metrics count the prove and finalize sends" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var tx_metrics: @import("../tx_manager/root.zig").metrics.Metrics = .{};
    var config = run_config;
    config.tx_metrics = &tx_metrics;
    var flow = try harness.start(config);
    defer flow.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&flow, 600));
    try testing.expectEqual(@as(u64, 2), tx_metrics.submitted.get());
    try testing.expectEqual(@as(u64, 2), tx_metrics.confirmed.get());
    try testing.expectEqual(@as(u64, 2), tx_metrics.done_count());
}

fn accept_none(context: ?*const anyopaque, withdrawal: *const withdrawal_module.Withdrawal) bool {
    assert(context == null);
    assert(withdrawal.transaction.data.len > 0);
    return false;
}

fn accept_bridge(context: ?*const anyopaque, withdrawal: *const withdrawal_module.Withdrawal) bool {
    const sender: *const Address = @ptrCast(@alignCast(context.?));
    return std.mem.eql(u8, &withdrawal.transaction.sender, sender);
}

test "withdrawer flow: a filter that rejects every withdrawal fails without sending" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var config = run_config;
    config.filter = .{ .accept = accept_none };
    var flow = try harness.start(config);
    defer flow.deinit(testing.allocator);
    try testing.expectError(error.NoMatchingWithdrawal, harness.run(&flow, 10));
    try testing.expectEqual(@as(usize, 1), flow.skipped_withdrawals().len);
    try testing.expectEqualSlices(
        u8,
        &withdrawal_hash_of(&harness.fixture),
        &flow.skipped_withdrawals()[0],
    );
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "withdrawer flow: an accepting filter keeps the default behavior" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    const messenger: Address = consensus.predeploys.l2_cross_domain_messenger.bytes;
    var config = run_config;
    config.filter = .{ .context = &messenger, .accept = accept_bridge };
    var flow = try harness.start(config);
    defer flow.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&flow, 600));
    try testing.expectEqual(@as(usize, 0), flow.skipped_withdrawals().len);
    try testing.expect(harness.l1.finalized);
}

test "withdrawer flow: status and paused runs never send" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var status = try harness.start(.{ .command = .status, .l2_transaction = fixture_hash() });
    defer status.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&status, 5));
    try testing.expectEqual(flow_module.Status.prove, status.results()[0].status);
    harness.l1.paused = true;
    var paused = try harness.start(run_config);
    defer paused.deinit(testing.allocator);
    const progress = try harness.run(&paused, 20);
    try testing.expect(progress != .done);
    try testing.expectEqual(flow_module.Status.paused, paused.results()[0].status);
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "withdrawer flow: a restart settles journaled broadcasts instead of resending" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var prove = try harness.start(.{ .command = .prove, .l2_transaction = fixture_hash() });
    // Crash right after the broadcast: one step publishes, nothing is mined yet.
    harness.l1_driver.config.publish_hook = prove.publish_hook();
    harness.now_ms += 1_000;
    while (harness.l1.sent_count == 0) _ = try prove.step(harness.now_ms);
    prove.deinit(testing.allocator);
    const journaled = try harness.journal.replay();
    try testing.expectEqual(@as(usize, 1), journaled.step(.prove).pending().len);
    // A fresh process (new driver state) resumes: the prove is mined meanwhile.
    harness.l1_driver.deinit(testing.allocator);
    const sender = accounts.derive_dev(0);
    harness.l1_driver = try flow_module.SendDriver.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = sender.private_key,
        .from = sender.address,
        .data_bytes_max = 16 * 1024,
        .manager = .{ .num_confirmations = 1, .receipt_query_interval_ms = 1_000 },
    });
    var resumed = try harness.start(run_config);
    defer resumed.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&resumed, 600));
    try testing.expectEqual(@as(u32, 1), harness.l1.count(calldata.prove_withdrawal_transaction));
    try testing.expectEqual(@as(u32, 1), harness.l1.count(finalize_selector));
}

test "withdrawer flow: a failing journal holds every broadcast back" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    harness.journal.fail = true;
    var flow = try harness.start(.{ .command = .prove, .l2_transaction = fixture_hash() });
    defer flow.deinit(testing.allocator);
    _ = harness.run(&flow, 30) catch {};
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "withdrawer flow: initiate sends initiateWithdrawal to the message passer" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var flow = try harness.start(.{
        .command = .initiate,
        .initiate = .{ .target = @splat(0x77), .value = 5, .data = "hi" },
        .poll_interval_ms = 1_000,
    });
    defer flow.deinit(testing.allocator);
    try testing.expectEqual(flow_module.Progress.done, try harness.run(&flow, 60));
    try testing.expectEqual(@as(u32, 1), harness.l2.count(calldata.initiate_withdrawal));
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
    const journal = try harness.journal.replay();
    const confirmed = journal.step(.initiate).confirmed.?;
    try testing.expectEqualSlices(u8, &harness.l2.sent[0].hash, &confirmed.transaction);
    try testing.expectEqualSlices(u8, &confirmed.transaction, &flow.l2_transaction.?);
    // Without a transaction or initiate parameters, a journal with a confirmed initiate
    // resumes from it.
    var resumed = try harness.start(.{ .command = .status });
    defer resumed.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &confirmed.transaction, &resumed.l2_transaction.?);
}

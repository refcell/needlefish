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
const fake_chain = @import("fake_chain.zig");
const Chain = fake_chain.Chain;
const portal = fake_chain.portal;
const fixture_transaction = "809b89557a33bbb8a20141e46e0c74129db40c184d0e3b9ed2f4e7c78eb74b85";

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    receipt: []const u8,
    header: []const u8,
    proof: []const u8,
    header_number: u64,
    receipt_block: u64,
    root_claim: Hash,
    receipts: [1]fake_chain.Receipt,
    /// What the fake chains serve; points into `fixture` (load in place).
    chain: fake_chain.Fixture,

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
        fixture.receipts = .{.{ .hash = fixture_hash(), .json = fixture.receipt }};
        fixture.chain = .{
            .receipts = &fixture.receipts,
            .header = fixture.header,
            .header_number = fixture.header_number,
            .proof = fixture.proof,
            .root_claim = fixture.root_claim,
            .withdrawal_hash = withdrawal_hash_of(fixture),
        };
    }

    fn parse_hex(text: []const u8) !u64 {
        return std.fmt.parseInt(u64, text[2..], 16);
    }
};

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
        harness.l1 = .{ .fixture = &harness.fixture.chain, .is_l2 = false };
        harness.l2 = .{ .fixture = &harness.fixture.chain, .is_l2 = true };
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

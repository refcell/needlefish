//! `fee-jobs confirm` tests over fake L1/L2 chains (`withdrawer/fake_chain.zig`).
//!
//! The FeeDisburser withdrawal is synthetic: a `relayMessage(finalizeBridgeETH)` envelope
//! from the messenger, whose message passer storage proof, account proof, header, and output
//! root are built here as single-leaf tries, so the real proof verification runs. The public
//! Base Sepolia fixture withdrawal (an ERC-20 bridge withdrawal) plays the foreign one.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const abi = @import("../../proof/contracts/abi.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const header_json = @import("../../consensus/sources/header_json.zig");
const state_trie = @import("../../execution/trie/state_trie.zig");
const trie_node = @import("../../execution/trie/node.zig");
const withdrawer = @import("../withdrawer/root.zig");
const fake_chain = @import("../withdrawer/fake_chain.zig");
const confirm = @import("confirm.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const withdrawal_module = withdrawer.withdrawal;
const calldata = withdrawer.calldata;
const Hash = [32]u8;
const Address = [20]u8;
const keccak256 = withdrawal_module.keccak256;

const fixture_json = @embedFile("../withdrawer/testdata/base_sepolia_withdrawal_proof.json");
const fee_disburser: Address = @splat(0x44);
const disbursal: Hash = @splat(0xd1);
const foreign_disbursal: Hash = @splat(0xd2);
const missing_disbursal: Hash = @splat(0xd3);
const value_wei: u256 = 500_000_000_000_000_000;

/// The relayMessage(finalizeBridgeETH) calldata of a bridge withdrawal.
fn bridge_data(out: []u8, relay_sender: Address, from: Address, nonce: u256) ![]u8 {
    var message_buffer: [256]u8 = undefined;
    const message = try abi.encode_call(&message_buffer, confirm.finalize_bridge_eth, &.{
        .{ .address = from },
        .{ .address = @splat(0x66) },
        .{ .uint = value_wei },
        .{ .bytes = "" },
    });
    return abi.encode_call(out, confirm.relay_message, &.{
        .{ .uint = nonce },
        .{ .address = relay_sender },
        .{ .address = @splat(0x55) },
        .{ .uint = value_wei },
        .{ .uint = 0 },
        .{ .bytes = message },
    });
}

fn withdrawal_of(sender: Address, data: []const u8, block: u64) withdrawal_module.Withdrawal {
    return .{
        .transaction = .{
            .nonce = (@as(u256, 1) << 240) | 7,
            .sender = sender,
            .target = @splat(0x11),
            .value = value_wei,
            .gas_limit = 300_000,
            .data = data,
        },
        .block_number = block,
    };
}

fn word_of(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

fn address_word(address: Address) [32]u8 {
    return fake_chain.address_word(address);
}

/// The `MessagePassed` log of `withdrawal` as receipt JSON.
fn write_message_passed(w: *std.Io.Writer, withdrawal: *const withdrawal_module.Withdrawal) !void {
    const transaction = &withdrawal.transaction;
    try w.print("{{\"address\":\"0x{x}\",\"topics\":[\"0x{x}\",\"0x{x}\",\"0x{x}\",\"0x{x}\"]," ++
        "\"data\":\"0x{x}{x}{x}{x}{x}{x}", .{
        &withdrawal_module.message_passer,
        &withdrawal_module.message_passed_topic,
        &word_of(transaction.nonce),
        &address_word(transaction.sender),
        &address_word(transaction.target),
        &word_of(transaction.value),
        &word_of(transaction.gas_limit),
        &word_of(4 * 32),
        &withdrawal.hash(),
        &word_of(transaction.data.len),
        transaction.data,
    });
    const zeros: [32]u8 = @splat(0);
    try w.print("{x}\"}}", .{zeros[0 .. (32 - transaction.data.len % 32) % 32]});
}

/// A single-leaf trie node: rlp([hex_prefix(key, leaf), value]) for a 32-byte key.
fn leaf_node(out: []u8, key: Hash, value: []const u8) []u8 {
    var value_header: [3]u8 = undefined;
    const value_header_len = string_header(&value_header, value);
    const payload = 34 + value_header_len + value.len;
    var length: usize = 0;
    if (payload < 56) {
        out[0] = @intCast(0xc0 + payload);
        length = 1;
    } else {
        assert(payload < 256);
        out[0] = 0xf8;
        out[1] = @intCast(payload);
        length = 2;
    }
    out[length] = 0xa1;
    out[length + 1] = 0x20; // Even-length leaf path.
    @memcpy(out[length + 2 ..][0..32], &key);
    length += 34;
    @memcpy(out[length..][0..value_header_len], value_header[0..value_header_len]);
    length += value_header_len;
    @memcpy(out[length..][0..value.len], value);
    return out[0 .. length + value.len];
}

fn string_header(out: *[3]u8, value: []const u8) usize {
    if (value.len == 1 and value[0] < 0x80) return 0;
    if (value.len < 56) {
        out[0] = @intCast(0x80 + value.len);
        return 1;
    }
    assert(value.len < 256);
    out[0] = 0xb8;
    out[1] = @intCast(value.len);
    return 2;
}

const Synthetic = struct {
    arena: std.heap.ArenaAllocator,
    fixture: fake_chain.Fixture,
    receipts: [2]fake_chain.Receipt,
    data_buffer: [1024]u8,
    withdrawal_hash: Hash,

    /// The fee withdrawal at the fixture header's block minus 10, proven by single-leaf
    /// tries. `logs` lists the disbursals `eth_getLogs` reports.
    fn build(synthetic: *Synthetic, sender: Address, relay: Address, from: Address) !void {
        synthetic.arena = .init(testing.allocator);
        errdefer synthetic.arena.deinit();
        const allocator = synthetic.arena.allocator();
        const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, fixture_json, .{});
        const stringify = std.json.Stringify.valueAlloc;
        const header_text = try stringify(allocator, root.object.get("header").?, .{});
        var extra: [header_json.extra_data_size_max]u8 = undefined;
        var decoded = try header_json.decode(header_text, &extra);
        const header_number = decoded.header.number;
        const data = try bridge_data(&synthetic.data_buffer, relay, from, (1 << 240) | 7);
        const withdrawal = withdrawal_of(sender, data, header_number - 10);
        synthetic.withdrawal_hash = withdrawal.hash();
        const proof = try synthetic.build_proof(allocator, &withdrawal, &decoded.header);
        const block_hash = decoded.header.hash().bytes;
        const header = try replace_hash(allocator, header_text, decoded.hash.bytes, block_hash);
        const header_final = try replace_hash(
            allocator,
            header,
            root_of(root.object.get("header").?, "stateRoot"),
            decoded.header.state_root.bytes,
        );
        const output: withdrawal_module.OutputRootProof = .{
            .state_root = decoded.header.state_root.bytes,
            .message_passer_storage_root = proof.storage_root,
            .latest_blockhash = block_hash,
        };
        const foreign_log = try stringify(allocator, foreign_log_value(root), .{});
        synthetic.receipts = .{
            .{ .hash = disbursal, .json = try receipt_json(allocator, &withdrawal, foreign_log) },
            .{ .hash = foreign_disbursal, .json = try stringify(
                allocator,
                root.object.get("receipt").?,
                .{},
            ) },
        };
        synthetic.fixture = .{
            .receipts = &synthetic.receipts,
            .header = header_final,
            .header_number = header_number,
            .proof = proof.json,
            .root_claim = output.root(),
            .withdrawal_hash = synthetic.withdrawal_hash,
            .logs = try logs_json(allocator, &.{disbursal}),
        };
    }

    const Proof = struct { json: []const u8, storage_root: Hash };

    /// Single-leaf storage and account tries; sets `header.state_root` to the account root.
    fn build_proof(
        synthetic: *Synthetic,
        allocator: std.mem.Allocator,
        withdrawal: *const withdrawal_module.Withdrawal,
        header: anytype,
    ) !Proof {
        _ = synthetic;
        const slot = withdrawal.slot();
        var storage_buffer: [64]u8 = undefined;
        const storage_leaf = leaf_node(&storage_buffer, keccak256(&slot), &.{0x01});
        const storage_root = keccak256(storage_leaf);
        var account_rlp: [state_trie.account_rlp_bytes_max]u8 = undefined;
        const empty: state_trie.Account = .{};
        const account = state_trie.encode_account(&empty, &storage_root, &account_rlp);
        var account_buffer: [160]u8 = undefined;
        const passer = withdrawal_module.message_passer;
        const account_leaf = leaf_node(&account_buffer, keccak256(&passer), account);
        header.state_root = .{ .bytes = keccak256(account_leaf) };
        const json = try std.fmt.allocPrint(allocator, "{{\"address\":\"0x{x}\",\"balance\":" ++
            "\"0x0\",\"codeHash\":\"0x{x}\",\"nonce\":\"0x0\",\"storageHash\":\"0x{x}\"," ++
            "\"accountProof\":[\"0x{x}\"],\"storageProof\":[{{\"key\":\"0x{x}\"," ++
            "\"value\":\"0x1\",\"proof\":[\"0x{x}\"]}}]}}", .{
            &passer,
            &trie_node.empty_code_hash,
            &storage_root,
            account_leaf,
            &slot,
            storage_leaf,
        });
        return .{ .json = json, .storage_root = storage_root };
    }

    fn deinit(synthetic: *Synthetic) void {
        synthetic.arena.deinit();
    }
};

fn root_of(header: std.json.Value, key: []const u8) Hash {
    var out: Hash = undefined;
    // The fixture's header fields are 32-byte hex strings.
    _ = std.fmt.hexToBytes(&out, header.object.get(key).?.string[2..]) catch unreachable;
    return out;
}

fn replace_hash(allocator: std.mem.Allocator, text: []const u8, old: Hash, new: Hash) ![]u8 {
    var old_hex: [64]u8 = undefined;
    var new_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&old_hex, "{x}", .{&old});
    _ = try std.fmt.bufPrint(&new_hex, "{x}", .{&new});
    const result = try std.mem.replaceOwned(u8, allocator, text, &old_hex, &new_hex);
    assert(std.mem.indexOf(u8, result, &new_hex) != null);
    return result;
}

fn foreign_log_value(root: std.json.Value) std.json.Value {
    return root.object.get("receipt").?.object.get("logs").?.array.items[0];
}

fn receipt_json(
    allocator: std.mem.Allocator,
    withdrawal: *const withdrawal_module.Withdrawal,
    foreign_log: []const u8,
) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(allocator);
    const w = &buffer.writer;
    try w.print("{{\"transactionHash\":\"0x{x}\",\"blockNumber\":\"0x{x}\",\"status\":\"0x1\"," ++
        "\"logs\":[{s},", .{ &disbursal, withdrawal.block_number, foreign_log });
    try write_message_passed(w, withdrawal);
    try w.writeAll("]}");
    return buffer.toOwnedSlice();
}

fn logs_json(allocator: std.mem.Allocator, transactions: []const Hash) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(allocator);
    const w = &buffer.writer;
    try w.writeAll("[");
    for (transactions, 0..) |transaction, index| {
        if (index > 0) try w.writeAll(",");
        try w.print("{{\"address\":\"0x{x}\",\"topics\":[\"0x{x}\"],\"data\":\"0x\"," ++
            "\"blockNumber\":\"0x5\",\"logIndex\":\"0x{x}\",\"transactionHash\":\"0x{x}\"}}", .{
            &fee_disburser,
            &confirm.fees_disbursed_topic,
            index,
            &transaction,
        });
    }
    try w.writeAll("]");
    return buffer.toOwnedSlice();
}

const Collector = struct {
    ranges: u32 = 0,
    skipped: [4]Hash = undefined,
    skipped_count: u32 = 0,
    outcomes: [4]confirm.Outcome = undefined,
    withdrawals: [4]Hash = undefined,
    outcome_count: u32 = 0,
    failed: [4]anyerror = undefined,
    failed_transactions: [4]Hash = undefined,
    failed_count: u32 = 0,

    fn events(collector: *Collector) confirm.Events {
        return .{ .context = collector, .emit = emit };
    }

    fn emit(context: *anyopaque, event: confirm.Event) void {
        const collector: *Collector = @ptrCast(@alignCast(context));
        switch (event) {
            .range => collector.ranges += 1,
            .skipped => |skipped| {
                collector.skipped[collector.skipped_count] = skipped.withdrawal;
                collector.skipped_count += 1;
            },
            .withdrawal => |withdrawal| {
                collector.outcomes[collector.outcome_count] = withdrawal.outcome;
                collector.withdrawals[collector.outcome_count] = withdrawal.withdrawal;
                collector.outcome_count += 1;
            },
            .failed => |failed| {
                collector.failed[collector.failed_count] = failed.err;
                collector.failed_transactions[collector.failed_count] = failed.transaction;
                collector.failed_count += 1;
            },
        }
    }
};

const Harness = struct {
    synthetic: Synthetic = undefined,
    l1: fake_chain.Chain = undefined,
    l2: fake_chain.Chain = undefined,
    l1_client: rpc.Client = undefined,
    l2_client: rpc.Client = undefined,
    reader: withdrawer.reader.Reader = undefined,
    l1_driver: withdrawer.flow.SendDriver = undefined,
    collector: Collector = .{},
    clock_ms: u64 = 1_000_000,

    fn init(harness: *Harness) !void {
        try harness.synthetic.build(confirm.messenger, confirm.standard_bridge, fee_disburser);
        errdefer harness.synthetic.deinit();
        const fixture = &harness.synthetic.fixture;
        harness.l1 = .{ .fixture = fixture, .is_l2 = false };
        harness.l2 = .{ .fixture = fixture, .is_l2 = true, .head = 100 };
        const limits: rpc.Limits = .{
            .request_bytes_max = 64 * 1024,
            .response_bytes_max = 64 * 1024,
            .parse_bytes_max = 1024 * 1024,
        };
        harness.l1_client = try rpc.Client.init(testing.allocator, harness.l1.transport(), limits);
        harness.l2_client = try rpc.Client.init(testing.allocator, harness.l2.transport(), limits);
        const sender = accounts.derive_dev(0);
        harness.reader = try withdrawer.reader.Reader.init(
            testing.allocator,
            &harness.l1_client,
            &harness.l2_client,
            fake_chain.portal,
            sender.address.bytes,
            .{},
        );
        _ = try harness.reader.resolve_contracts();
        harness.l1_driver = try withdrawer.flow.SendDriver.init(testing.allocator, .{
            .chain_id = 900,
            .private_key = sender.private_key,
            .from = sender.address,
            .data_bytes_max = 16 * 1024,
            .manager = .{
                .num_confirmations = 1,
                .resubmission_timeout_ms = 30_000,
                .receipt_query_interval_ms = 1_000,
            },
        });
    }

    fn deinit(harness: *Harness) void {
        harness.l1_driver.deinit(testing.allocator);
        harness.reader.deinit(testing.allocator);
        harness.l2_client.deinit(testing.allocator);
        harness.l1_client.deinit(testing.allocator);
        harness.synthetic.deinit();
    }

    fn job(harness: *Harness, dry_run: bool) confirm.Job {
        harness.collector = .{};
        return .{
            .allocator = testing.allocator,
            .config = .{
                .fee_disburser = fee_disburser,
                .window = .{ .lookback_ms = 18_000, .block_time_ms = 2_000, .blocks_per_query = 4 },
                .dry_run = dry_run,
                .poll_interval_ms = 1_000,
            },
            .reader = &harness.reader,
            .l1_driver = &harness.l1_driver,
            .events = harness.collector.events(),
        };
    }

    /// The fake clock: sleeping mines one block per elapsed second on both chains.
    pub fn now_ms(harness: *const Harness) u64 {
        return harness.clock_ms;
    }

    pub fn sleep_ms(harness: *Harness, duration_ms: u64) void {
        const before_s = harness.clock_ms / 1_000;
        harness.clock_ms += duration_ms;
        const after_s = harness.clock_ms / 1_000;
        if (after_s == before_s) return;
        harness.l1.mine(after_s);
        harness.l2.mine(after_s);
    }
};

fn create_harness() !*Harness {
    const harness = try testing.allocator.create(Harness);
    errdefer testing.allocator.destroy(harness);
    harness.* = .{};
    try harness.init();
    return harness;
}

fn destroy_harness(harness: *Harness) void {
    harness.deinit();
    testing.allocator.destroy(harness);
}

const prove_selector = calldata.prove_withdrawal_transaction;
const finalize_selector = calldata.finalize_withdrawal_transaction;

test "fee-jobs confirm: proves the fee withdrawal, skips the foreign one, finalizes later" {
    const harness = try create_harness();
    defer destroy_harness(harness);
    var job = harness.job(false);
    const report = try job.run(harness);
    try testing.expectEqual(@as(u32, 1), report.disbursals);
    try testing.expectEqual(@as(u32, 1), report.withdrawals);
    try testing.expectEqual(@as(u32, 1), report.skipped);
    try testing.expectEqual(@as(u32, 0), report.failures);
    try testing.expectEqual(@as(u32, 1), harness.l1.count(prove_selector));
    try testing.expectEqual(@as(u32, 0), harness.l1.count(finalize_selector));
    try testing.expectEqual(confirm.Outcome.proven, harness.collector.outcomes[0]);
    const synthetic_hash = harness.synthetic.withdrawal_hash;
    try testing.expectEqualSlices(u8, &synthetic_hash, &harness.collector.withdrawals[0]);
    // The skipped one is the fixture's ERC-20 bridge withdrawal.
    try testing.expect(!std.mem.eql(u8, &synthetic_hash, &harness.collector.skipped[0]));
    try testing.expectEqual(@as(u32, 3), harness.collector.ranges);

    // Before maturity a later run is a pending no-op; after it, the run finalizes.
    job = harness.job(false);
    _ = try job.run(harness);
    try testing.expectEqual(confirm.Outcome.pending, harness.collector.outcomes[0]);
    try testing.expectEqual(@as(u32, 1), harness.l1.sent_count);
    harness.sleep_ms(1_000_000);
    job = harness.job(false);
    const final = try job.run(harness);
    try testing.expectEqual(@as(u32, 0), final.failures);
    try testing.expectEqual(confirm.Outcome.finalized, harness.collector.outcomes[0]);
    try testing.expectEqual(@as(u32, 1), harness.l1.count(finalize_selector));
    try testing.expect(harness.l1.finalized);
    job = harness.job(false);
    _ = try job.run(harness);
    try testing.expectEqual(confirm.Outcome.already_finalized, harness.collector.outcomes[0]);
}

test "fee-jobs confirm: dry run decides without sending" {
    const harness = try create_harness();
    defer destroy_harness(harness);
    var job = harness.job(true);
    const report = try job.run(harness);
    try testing.expectEqual(@as(u32, 1), report.withdrawals);
    try testing.expectEqual(confirm.Outcome.would_prove, harness.collector.outcomes[0]);
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "fee-jobs confirm: a receipt without a FeeDisburser withdrawal fails, the run continues" {
    const harness = try create_harness();
    defer destroy_harness(harness);
    const logs = try logs_json(
        harness.synthetic.arena.allocator(),
        &.{ missing_disbursal, foreign_disbursal, disbursal, foreign_disbursal },
    );
    harness.synthetic.fixture.logs = logs;
    var job = harness.job(false);
    const report = try job.run(harness);
    // Deduplicated in log order; the missing and foreign receipts fail, the fee one proves.
    try testing.expectEqual(@as(u32, 3), report.disbursals);
    try testing.expectEqual(@as(u32, 2), report.failures);
    try testing.expectEqual(@as(u32, 1), report.withdrawals);
    try testing.expectEqual(@as(u32, 2), harness.collector.failed_count);
    const first_failed = harness.collector.failed_transactions[0];
    try testing.expectEqualSlices(u8, &missing_disbursal, &first_failed);
    try testing.expectEqual(error.MissingReceipt, harness.collector.failed[0]);
    try testing.expectEqual(error.NoMatchingWithdrawal, harness.collector.failed[1]);
    try testing.expectEqual(@as(u32, 1), harness.l1.count(prove_selector));
}

test "fee-jobs confirm: no disbursal in the window is a successful no-op" {
    const harness = try create_harness();
    defer destroy_harness(harness);
    harness.synthetic.fixture.logs = "[]";
    var job = harness.job(false);
    const report = try job.run(harness);
    try testing.expectEqual(confirm.Report{}, report);
    try testing.expectEqual(@as(u32, 3), harness.l2.get_logs_calls);
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "fee-jobs confirm: a paused portal fails the withdrawal without sending" {
    const harness = try create_harness();
    defer destroy_harness(harness);
    harness.l1.paused = true;
    var job = harness.job(false);
    const report = try job.run(harness);
    try testing.expectEqual(@as(u32, 1), report.failures);
    try testing.expectEqual(error.Paused, harness.collector.failed[0]);
    try testing.expectEqual(@as(u32, 0), harness.l1.sent_count);
}

test "fee-jobs confirm: only the authenticated FeeDisburser bridge envelope matches" {
    var buffer: [1024]u8 = undefined;
    const good = try bridge_data(&buffer, confirm.standard_bridge, fee_disburser, 1);
    const matching = withdrawal_of(confirm.messenger, good, 1);
    try testing.expect(confirm.is_fee_withdrawal(&matching, fee_disburser));
    // base/base's unrelated senders: wrong message passer sender, relay sender, or `_from`.
    const other: Address = @splat(0x99);
    try testing.expect(!confirm.is_fee_withdrawal(&withdrawal_of(other, good, 1), fee_disburser));
    var relay_buffer: [1024]u8 = undefined;
    const wrong_relay = try bridge_data(&relay_buffer, other, fee_disburser, 1);
    try testing.expect(!confirm.is_fee_withdrawal(
        &withdrawal_of(confirm.messenger, wrong_relay, 1),
        fee_disburser,
    ));
    var from_buffer: [1024]u8 = undefined;
    const wrong_from = try bridge_data(&from_buffer, confirm.standard_bridge, other, 1);
    try testing.expect(!confirm.is_fee_withdrawal(
        &withdrawal_of(confirm.messenger, wrong_from, 1),
        fee_disburser,
    ));
    // Non-canonical encodings: a trailing word, a shifted offset, a truncated tail.
    var padded: [1024]u8 = undefined;
    @memcpy(padded[0..good.len], good);
    @memset(padded[good.len..][0..32], 0);
    const messenger = confirm.messenger;
    const trailing = withdrawal_of(messenger, padded[0 .. good.len + 32], 1);
    try testing.expect(!confirm.is_fee_withdrawal(&trailing, fee_disburser));
    padded[4 + 5 * 32 + 31] +%= 32;
    const shifted = withdrawal_of(messenger, padded[0 .. good.len + 32], 1);
    try testing.expect(!confirm.is_fee_withdrawal(&shifted, fee_disburser));
    const truncated = withdrawal_of(messenger, good[0 .. good.len - 1], 1);
    try testing.expect(!confirm.is_fee_withdrawal(&truncated, fee_disburser));
}

test "fee-jobs confirm: the fixture's ERC-20 bridge withdrawal never matches" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, fixture_json, .{});
    const log_value = foreign_log_value(root);
    var topics: [4]Hash = undefined;
    for (log_value.object.get("topics").?.array.items, 0..) |topic, index| {
        _ = try std.fmt.hexToBytes(&topics[index], topic.string[2..]);
    }
    const data_hex = log_value.object.get("data").?.string[2..];
    const data = try allocator.alloc(u8, data_hex.len / 2);
    _ = try std.fmt.hexToBytes(data, data_hex);
    const withdrawal = (try withdrawal_module.decode_message_passed(.{
        .address = withdrawal_module.message_passer,
        .topics = &topics,
        .data = data,
    }, 1)).?;
    // It relays from the standard bridge, but with finalizeBridgeERC20, not finalizeBridgeETH.
    try testing.expectEqualSlices(u8, &confirm.messenger, &withdrawal.transaction.sender);
    try testing.expect(!confirm.is_fee_withdrawal(&withdrawal, fee_disburser));
    const local_token = withdrawal.transaction.data[4 + 7 * 32 + 4 + 12 ..][0..20].*;
    try testing.expect(!confirm.is_fee_withdrawal(&withdrawal, local_token));
}

test "fee-jobs confirm: windows round up, clamp at genesis, and chunk inclusively" {
    const day_ms: u64 = 24 * 60 * 60 * 1000;
    const Case = struct {
        current: u64,
        lookback_ms: u64,
        block_ms: u64,
        chunk: u64,
        ranges: []const confirm.Range,
    };
    const max = std.math.maxInt(u64);
    const two: []const confirm.Range = &.{ .{ .from = 97, .to = 99 }, .{ .from = 100, .to = 100 } };
    const clamped: []const confirm.Range = &.{ .{ .from = 0, .to = 3 }, .{ .from = 4, .to = 5 } };
    const cases = [_]Case{
        // base/base protocol_window, round_up, subsecond, genesis_clamp, at_genesis,
        // maximum_duration, maximum_head.
        .{
            .current = 1_000_000,
            .lookback_ms = 21 * day_ms,
            .block_ms = 2_000,
            .chunk = 1_000_000,
            .ranges = &.{.{ .from = 92_800, .to = 1_000_000 }},
        },
        .{ .current = 100, .lookback_ms = 5_000, .block_ms = 2_000, .chunk = 3, .ranges = two },
        .{ .current = 100, .lookback_ms = 5, .block_ms = 2, .chunk = 3, .ranges = two },
        .{ .current = 5, .lookback_ms = 20_000, .block_ms = 2_000, .chunk = 4, .ranges = clamped },
        .{
            .current = 0,
            .lookback_ms = 5_000,
            .block_ms = 2_000,
            .chunk = 4,
            .ranges = &.{.{ .from = 0, .to = 0 }},
        },
        .{ .current = 5, .lookback_ms = max, .block_ms = 1, .chunk = 4, .ranges = clamped },
        .{
            .current = max,
            .lookback_ms = 1_000,
            .block_ms = 2_000,
            .chunk = 10,
            .ranges = &.{.{ .from = max - 1, .to = max }},
        },
    };
    for (cases) |case| {
        var ranges = confirm.Ranges.init(case.current, .{
            .lookback_ms = case.lookback_ms,
            .block_time_ms = case.block_ms,
            .blocks_per_query = case.chunk,
        });
        try testing.expectEqual(@as(u64, case.ranges.len), ranges.count());
        for (case.ranges) |expected| try testing.expectEqual(expected, ranges.next().?);
        try testing.expectEqual(@as(?confirm.Range, null), ranges.next());
    }
    const zero = [_]confirm.Window{
        .{ .lookback_ms = 0, .block_time_ms = 2_000, .blocks_per_query = 3_000 },
        .{ .lookback_ms = 5_000, .block_time_ms = 0, .blocks_per_query = 3_000 },
        .{ .lookback_ms = 5_000, .block_time_ms = 2_000, .blocks_per_query = 0 },
    };
    for (zero) |window| try testing.expect(!window.valid());
}

test "fee-jobs confirm: the default window needs 303 log queries" {
    var ranges = confirm.Ranges.init(2_000_000, .{
        .lookback_ms = 21 * 24 * 60 * 60 * 1000,
        .block_time_ms = 2_000,
        .blocks_per_query = 3_000,
    });
    try testing.expectEqual(@as(u64, 303), ranges.count());
    try testing.expectEqual(@as(u64, 2_000_000 - 907_200), ranges.next().?.from);
    var last: confirm.Range = undefined;
    var queries: u32 = 1;
    while (ranges.next()) |range| : (queries += 1) last = range;
    try testing.expectEqual(@as(u32, 303), queries);
    try testing.expectEqual(@as(u64, 2_000_000), last.to);
}

/// Answers `eth_blockNumber` 100 and `eth_getLogs` per `fromBlock` (base/base's scan test).
const ScanChain = struct {
    filters: [4][256]u8 = undefined,
    filter_sizes: [4]usize = @splat(0),
    queries: u32 = 0,

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const chain: *ScanChain = @ptrCast(@alignCast(context));
        var writer: std.Io.Writer = .fixed(response);
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id_end = std.mem.indexOfAnyPos(u8, body, id_start, ",}").?;
        const id = body[id_start..id_end];
        writer.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":", .{id}) catch
            return error.ResponseTooLarge;
        if (std.mem.indexOf(u8, body, "eth_blockNumber") != null) {
            writer.writeAll("\"0x64\"}") catch return error.ResponseTooLarge;
            return writer.buffered().len;
        }
        const params = std.mem.indexOf(u8, body, "[{").?;
        const params_end = std.mem.indexOf(u8, body, "}]").? + 2;
        @memcpy(chain.filters[chain.queries][0 .. params_end - params], body[params..params_end]);
        chain.filter_sizes[chain.queries] = params_end - params;
        chain.queries += 1;
        const logs = if (std.mem.indexOf(u8, body, "\"fromBlock\":\"0x5b\"") != null)
            comptime (log_entry(94, 1, 3) ++ "," ++ log_entry(91, 2, 1) ++ "," ++
                log_entry(91, 1, 1))
        else if (std.mem.indexOf(u8, body, "\"fromBlock\":\"0x5f\"") != null)
            ""
        else
            comptime (log_entry(100, 0, 2) ++ "," ++ log_entry(99, 0, 1));
        writer.print("[{s}]}}", .{logs}) catch return error.ResponseTooLarge;
        return writer.buffered().len;
    }

    fn log_entry(comptime block: u64, comptime index: u64, comptime byte: u8) []const u8 {
        const hash: [32]u8 = @splat(byte);
        return std.fmt.comptimePrint("{{\"blockNumber\":\"0x{x}\",\"logIndex\":\"0x{x}\"," ++
            "\"transactionHash\":\"0x{x}\"}}", .{ block, index, &hash });
    }
};

test "fee-jobs confirm: scans inclusive chunks and deduplicates in block and log order" {
    var chain: ScanChain = .{};
    const transport: rpc.Transport = .{ .context = &chain, .send_fn = ScanChain.send };
    var client = try rpc.Client.init(testing.allocator, transport, .{
        .request_bytes_max = 4096,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var collector: Collector = .{};
    var out: [confirm.disbursals_max]Hash = undefined;
    const found = try confirm.scan_disbursals(&client, @splat(4), .{
        .lookback_ms = 18_000,
        .block_time_ms = 2_000,
        .blocks_per_query = 4,
    }, &out, collector.events());
    try testing.expectEqual(@as(usize, 3), found.len);
    try testing.expectEqual(@as(u8, 1), found[0][0]);
    try testing.expectEqual(@as(u8, 3), found[1][0]);
    try testing.expectEqual(@as(u8, 2), found[2][0]);
    try testing.expectEqual(@as(u32, 3), chain.queries);
    const expected_ranges = [_][2][]const u8{
        .{ "\"fromBlock\":\"0x5b\"", "\"toBlock\":\"0x5e\"" },
        .{ "\"fromBlock\":\"0x5f\"", "\"toBlock\":\"0x62\"" },
        .{ "\"fromBlock\":\"0x63\"", "\"toBlock\":\"0x64\"" },
    };
    for (expected_ranges, 0..) |range, index| {
        const filter = chain.filters[index][0..chain.filter_sizes[index]];
        try testing.expect(std.mem.indexOf(u8, filter, range[0]) != null);
        try testing.expect(std.mem.indexOf(u8, filter, range[1]) != null);
    }
    const first = chain.filters[0][0..chain.filter_sizes[0]];
    const contract: Address = @splat(4);
    var address_text: [64]u8 = undefined;
    const address_field = try std.fmt.bufPrint(
        &address_text,
        "\"address\":\"0x{x}\"",
        .{&contract},
    );
    try testing.expect(std.mem.indexOf(u8, first, address_field) != null);
    var topic_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&topic_hex, "{x}", .{&confirm.fees_disbursed_topic});
    try testing.expect(std.mem.indexOf(u8, first, &topic_hex) != null);
}

fn check_matcher(data: []const u8, sender_byte: u8) !void {
    const sender: Address = if (sender_byte % 2 == 0) confirm.messenger else @splat(sender_byte);
    const withdrawal = withdrawal_of(sender, data, 1);
    const matched = confirm.is_fee_withdrawal(&withdrawal, fee_disburser);
    if (matched) try testing.expectEqualSlices(u8, &confirm.messenger, &sender);
}

test "fee-jobs confirm: seeded fuzz of the withdrawal matcher" {
    var prng = Prng.init(0xfee5);
    var buffer: [1024]u8 = undefined;
    const good = try bridge_data(&buffer, confirm.standard_bridge, fee_disburser, 3);
    var mutated: [1024]u8 = undefined;
    for (0..4_000) |_| {
        const length: usize = @intCast(prng.below(good.len + 40));
        @memcpy(mutated[0..@min(length, good.len)], good[0..@min(length, good.len)]);
        if (length > good.len) @memset(mutated[good.len..length], 0);
        const flips = prng.below(4);
        for (0..flips) |_| {
            if (length == 0) break;
            mutated[@intCast(prng.below(length))] = @truncate(prng.below(256));
        }
        try check_matcher(mutated[0..length], @truncate(prng.below(256)));
    }
}

test "fee-jobs confirm: fuzz the withdrawal matcher" {
    try testing.fuzz({}, fuzz_matcher, .{});
}

fn fuzz_matcher(_: void, smith: *testing.Smith) anyerror!void {
    var data: [1024]u8 = undefined;
    const length = smith.slice(&data);
    try check_matcher(data[0..length], smith.value(u8));
}

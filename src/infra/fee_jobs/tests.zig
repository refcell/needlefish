//! fee_jobs tests: the precondition boundaries (base/base `job.rs` cases), and full runs
//! against a fake chain that decodes the signed transaction and mines it.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const tx_manager = @import("../tx_manager/root.zig");
const fee_jobs = @import("root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const keccak = @import("../../common/crypto/keccak.zig");

const Driver = tx_manager.driver.Driver(.{ .sends_max = 2, .hashes_max = 4 });
const contract: fee_jobs.Address = .{ .bytes = @splat(0xfe) };

test "fee_jobs: selectors match the Solidity signatures" {
    // Cross-check the comptime std Keccak against needlefish's own implementation.
    const cases = [_]struct { signature: []const u8, selector: [4]u8 }{
        .{ .signature = "disburseFees()", .selector = fee_jobs.selectors.disburse_fees },
        .{
            .signature = "lastDisbursementTime()",
            .selector = fee_jobs.selectors.last_disbursement_time,
        },
        .{
            .signature = "FEE_DISBURSEMENT_INTERVAL()",
            .selector = fee_jobs.selectors.fee_disbursement_interval,
        },
        .{ .signature = "processFees()", .selector = fee_jobs.selectors.process_fees },
        .{ .signature = "withdrawETH()", .selector = fee_jobs.selectors.withdraw_eth },
    };
    for (cases) |case| {
        const digest = keccak.keccak256(case.signature);
        try testing.expectEqualSlices(u8, digest[0..4], &case.selector);
    }
    // Known vector: ERC-20 transfer(address,uint256).
    const transfer = keccak.keccak256("transfer(address,uint256)");
    try testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, transfer[0..4]);
}

test "fee_jobs: disburse waits for the interval and never overflows" {
    const window = struct {
        fn of(last_s: u256, interval_s: u256, timestamp_s: u64) fee_jobs.Reading {
            return .{ .window = .{
                .last_s = last_s,
                .interval_s = interval_s,
                .timestamp_s = timestamp_s,
            } };
        }
    };
    try testing.expect(!fee_jobs.ready(.disburse, window.of(100, 30, 129)));
    try testing.expect(fee_jobs.ready(.disburse, window.of(100, 30, 130)));
    try testing.expect(fee_jobs.ready(.disburse, window.of(100, 30, 131)));
    const max = std.math.maxInt(u256);
    try testing.expect(!fee_jobs.ready(.disburse, window.of(max, 1, std.math.maxInt(u64))));
}

test "fee_jobs: process and sweep need their minimum balances" {
    const process_min = fee_jobs.min_process_balance_wei;
    const sweep_min = fee_jobs.min_sweep_balance_wei;
    try testing.expect(!fee_jobs.ready(.process, .{ .balance_wei = process_min - 1 }));
    try testing.expect(fee_jobs.ready(.process, .{ .balance_wei = process_min }));
    try testing.expect(!fee_jobs.ready(.sweep, .{ .balance_wei = sweep_min - 1 }));
    try testing.expect(fee_jobs.ready(.sweep, .{ .balance_wei = sweep_min }));
}

test "fee_jobs: seeded disburse readiness matches the reference arithmetic" {
    var prng = Prng.init(0xfee5);
    const random = prng.random();
    for (0..1000) |_| {
        const last_s: u256 = random.int(u64);
        const interval_s: u256 = random.int(u32);
        const timestamp_s = random.int(u64);
        const expected = @as(u256, timestamp_s) >= last_s + interval_s;
        try testing.expectEqual(expected, fee_jobs.ready(.disburse, .{ .window = .{
            .last_s = last_s,
            .interval_s = interval_s,
            .timestamp_s = timestamp_s,
        } }));
    }
}

const FakeChain = struct {
    head: u64 = 10,
    timestamp_s: u64 = 1_000,
    last_disbursement_s: u64 = 900,
    interval_s: u64 = 60,
    balance_wei: u256 = fee_jobs.min_process_balance_wei,
    reverting: bool = false,
    rejecting: bool = false,
    sends: u32 = 0,
    sent_hash: ?[32]u8 = null,
    sent_block: u64 = 0,
    sent_selector: [4]u8 = @splat(0),
    sent_to: [20]u8 = @splat(0),

    fn transport(chain: *FakeChain) rpc.Transport {
        return .{ .context = chain, .send_fn = send };
    }

    fn block_hash(number: u64) [32]u8 {
        var hash: [32]u8 = @splat(0x11);
        std.mem.writeInt(u64, hash[0..8], number, .little);
        return hash;
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const chain: *FakeChain = @ptrCast(@alignCast(context));
        const id = between(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = between(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        var result_buffer: [512]u8 = undefined;
        const result = chain.answer(method, body, &result_buffer) catch |err| {
            if (err != error.Rejected) return error.TransportFailed;
            const text = std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                "\"error\":{{\"code\":-32000,\"message\":\"insufficient funds\"}}}}", .{id}) catch
                return error.ResponseTooLarge;
            return text.len;
        };
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{
            id,
            result,
        }) catch return error.ResponseTooLarge;
        return text.len;
    }

    fn answer(chain: *FakeChain, method: []const u8, body: []const u8, out: []u8) ![]const u8 {
        if (eql(method, "eth_call")) {
            const data = between(body, "\"data\":\"0x", "\"").?;
            var function: [4]u8 = undefined;
            _ = try std.fmt.hexToBytes(&function, data);
            const last_selector = fee_jobs.selectors.last_disbursement_time;
            const value = if (std.mem.eql(u8, &function, &last_selector))
                chain.last_disbursement_s
            else
                chain.interval_s;
            return std.fmt.bufPrint(out, "\"0x{x:0>64}\"", .{value});
        }
        if (eql(method, "eth_getBalance")) {
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{chain.balance_wei});
        }
        if (eql(method, "eth_getTransactionCount")) return "\"0x0\"";
        if (eql(method, "eth_maxPriorityFeePerGas")) return "\"0x1\"";
        if (eql(method, "eth_estimateGas")) return "\"0x7530\"";
        if (eql(method, "eth_getBlockByNumber")) return chain.block(body, out);
        if (eql(method, "eth_sendRawTransaction")) return chain.accept(body, out);
        if (eql(method, "eth_getTransactionReceipt")) {
            const hash = chain.sent_hash orelse return "null";
            const asked_hex = between(body, "\"params\":[\"0x", "\"").?;
            var asked: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&asked, asked_hex);
            if (!std.mem.eql(u8, &asked, &hash) or chain.head < chain.sent_block) return "null";
            return std.fmt.bufPrint(out, "{{\"blockNumber\":\"0x{x}\",\"blockHash\":\"0x{x}\"," ++
                "\"status\":\"0x{d}\"}}", .{
                chain.sent_block,
                &block_hash(chain.sent_block),
                @intFromBool(!chain.reverting),
            });
        }
        return error.UnknownMethod;
    }

    fn block(chain: *FakeChain, body: []const u8, out: []u8) ![]const u8 {
        const tag = between(body, "\"params\":[\"", "\"").?;
        const number = if (eql(tag, "latest"))
            chain.head
        else
            try std.fmt.parseInt(u64, tag[2..], 16);
        if (number > chain.head) return "null";
        return std.fmt.bufPrint(out, "{{\"number\":\"0x{x}\",\"timestamp\":\"0x{x}\"," ++
            "\"baseFeePerGas\":\"0x7\",\"hash\":\"0x{x}\"}}", .{
            number,
            chain.timestamp_s,
            &block_hash(number),
        });
    }

    fn accept(chain: *FakeChain, body: []const u8, out: []u8) ![]const u8 {
        chain.sends += 1;
        if (chain.rejecting) return error.Rejected;
        const hex = between(body, "\"params\":[\"0x", "\"").?;
        var raw: [512]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, hex);
        const envelope = try consensus.tx.Envelope.decode(bytes);
        const signed = envelope.eip1559;
        assert(signed.tx.input.len == 4);
        chain.sent_selector = signed.tx.input[0..4].*;
        chain.sent_to = signed.tx.to.call.bytes;
        const hash = envelope.hash().bytes;
        chain.sent_hash = hash;
        chain.sent_block = chain.head + 1;
        return std.fmt.bufPrint(out, "\"0x{x}\"", .{&hash});
    }

    /// Advances the chain one block per clock step.
    fn mine(chain: *FakeChain) void {
        chain.head += 1;
        chain.timestamp_s += 2;
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn between(text: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const begin = (std.mem.indexOf(u8, text, start) orelse return null) + start.len;
    const length = std.mem.indexOf(u8, text[begin..], end) orelse return null;
    return text[begin..][0..length];
}

const FakeClock = struct {
    now: u64 = 0,
    chain: *FakeChain,

    pub fn now_ms(clock: *const FakeClock) u64 {
        return clock.now;
    }

    pub fn sleep_ms(clock: *FakeClock, duration_ms: u64) void {
        clock.now += duration_ms;
        clock.chain.mine();
    }
};

const Fixture = struct {
    chain: FakeChain = .{},
    client: rpc.Client = undefined,
    driver: Driver = undefined,

    fn init(fixture: *Fixture) !void {
        fixture.client = try rpc.Client.init(testing.allocator, fixture.chain.transport(), .{
            .request_bytes_max = 4096,
            .response_bytes_max = 4096,
            .parse_bytes_max = 64 * 1024,
        });
        const sender = accounts.derive_dev(3);
        fixture.driver = try Driver.init(testing.allocator, .{
            .chain_id = 900,
            .private_key = sender.private_key,
            .from = sender.address,
            .data_bytes_max = 64,
            .manager = .{
                .num_confirmations = 3,
                .resubmission_timeout_ms = 10_000,
                .receipt_query_interval_ms = 200,
                .tx_send_timeout_ms = 30_000,
            },
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.driver.deinit(testing.allocator);
        fixture.client.deinit(testing.allocator);
    }

    fn run(fixture: *Fixture, kind: fee_jobs.Kind) fee_jobs.RunError!fee_jobs.Outcome {
        var clock: FakeClock = .{ .chain = &fixture.chain };
        return fee_jobs.run(&fixture.driver, &fixture.client, &clock, kind, contract, 200);
    }
};

test "fee_jobs: disburse sends disburseFees once the interval elapsed" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.chain.last_disbursement_s = 1_000 - 60;
    const outcome = try fixture.run(.disburse);
    try testing.expect(outcome == .confirmed);
    try testing.expectEqual(fixture.chain.sent_block, outcome.confirmed.block_number);
    const sent = &fixture.chain.sent_selector;
    try testing.expectEqualSlices(u8, &fee_jobs.selectors.disburse_fees, sent);
    try testing.expectEqualSlices(u8, &contract.bytes, &fixture.chain.sent_to);
}

test "fee_jobs: an early disburse skips without sending" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.chain.last_disbursement_s = 1_000 - 59;
    const outcome = try fixture.run(.disburse);
    try testing.expect(outcome == .skipped);
    try testing.expectEqual(@as(u32, 0), fixture.chain.sends);
}

test "fee_jobs: process and sweep follow the balance" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.chain.balance_wei = fee_jobs.min_sweep_balance_wei;
    try testing.expect(try fixture.run(.process) == .skipped);
    try testing.expectEqual(@as(u32, 0), fixture.chain.sends);
    try testing.expect(try fixture.run(.sweep) == .confirmed);
    const sent = &fixture.chain.sent_selector;
    try testing.expectEqualSlices(u8, &fee_jobs.selectors.withdraw_eth, sent);
}

test "fee_jobs: a reverted receipt fails the job" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.chain.reverting = true;
    try testing.expectError(error.Reverted, fixture.run(.process));
}

test "fee_jobs: a rejected send fails the job" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.chain.rejecting = true;
    const result = fixture.run(.process);
    try testing.expect(result == error.SendFailed or result == error.Timeout);
    try testing.expect(fixture.chain.sends > 0);
}

//! Driver tests over a JSON-RPC fake L1 that decodes the signed transactions it gets.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const driver_module = @import("driver.zig");
const fees = @import("fees.zig");

const Hash = driver_module.Hash;
const Driver = driver_module.Driver(.{ .sends_max = 4, .hashes_max = 4 });
const nonces_max = 64;

const FakeL1 = struct {
    head: u64 = 1,
    /// Bumped on every reorg so re-mined blocks get new hashes.
    fork: u8 = 0,
    account_nonce: u64 = 0,
    base_fee_wei: u128 = 7,
    pool: [nonces_max]?PoolTx = @splat(null),
    mined: [nonces_max]?Mined = @splat(null),
    sends: u32 = 0,
    reject_with: ?[]const u8 = null,
    /// Message of the current rejection.
    rejection: []const u8 = "",
    last_to: [20]u8 = @splat(0),

    const PoolTx = struct { hash: Hash, tip_wei: u128, fee_cap_wei: u128 };
    const Mined = struct { hash: Hash, block_number: u64, fork: u8 };

    fn transport(l1: *FakeL1) rpc.Transport {
        return .{ .context = l1, .send_fn = send };
    }

    fn block_hash(number: u64, fork: u8) Hash {
        var hash: Hash = @splat(fork);
        std.mem.writeInt(u64, hash[0..8], number, .little);
        return hash;
    }

    fn mine(l1: *FakeL1) void {
        l1.head += 1;
        while (l1.account_nonce < nonces_max) {
            const tx = l1.pool[l1.account_nonce] orelse break;
            if (tx.fee_cap_wei < l1.base_fee_wei) break;
            l1.mined[l1.account_nonce] = .{
                .hash = tx.hash,
                .block_number = l1.head,
                .fork = l1.fork,
            };
            l1.pool[l1.account_nonce] = null;
            l1.account_nonce += 1;
        }
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const l1: *FakeL1 = @ptrCast(@alignCast(context));
        const id = between(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = between(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        var result_buffer: [256]u8 = undefined;
        const result = l1.answer(method, body, &result_buffer) catch |err| switch (err) {
            error.Rejected => {
                const text = std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                    "\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}", .{
                    id,
                    l1.rejection,
                }) catch return error.ResponseTooLarge;
                return text.len;
            },
            else => return error.TransportFailed,
        };
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{
            id,
            result,
        }) catch return error.ResponseTooLarge;
        return text.len;
    }

    fn answer(l1: *FakeL1, method: []const u8, body: []const u8, out: []u8) ![]const u8 {
        if (std.mem.eql(u8, method, "eth_getTransactionCount")) {
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{l1.account_nonce});
        }
        if (std.mem.eql(u8, method, "eth_maxPriorityFeePerGas")) return "\"0x2\"";
        if (std.mem.eql(u8, method, "eth_estimateGas")) return "\"0x5208\"";
        if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
            const tag = between(body, "\"params\":[\"", "\"").?;
            const number = if (std.mem.eql(u8, tag, "latest"))
                l1.head
            else
                try std.fmt.parseInt(u64, tag[2..], 16);
            if (number > l1.head) return "null";
            return std.fmt.bufPrint(out, "{{\"number\":\"0x{x}\",\"baseFeePerGas\":\"0x{x}\"," ++
                "\"hash\":\"0x{x}\"}}", .{ number, l1.base_fee_wei, &block_hash(number, l1.fork) });
        }
        if (std.mem.eql(u8, method, "eth_getTransactionReceipt")) {
            const hex = between(body, "\"params\":[\"0x", "\"").?;
            var hash: Hash = undefined;
            _ = try std.fmt.hexToBytes(&hash, hex);
            for (l1.mined[0..l1.account_nonce]) |entry| {
                const tx = entry.?;
                if (!std.mem.eql(u8, &tx.hash, &hash)) continue;
                const format = "{{\"blockNumber\":\"0x{x}\",\"blockHash\":\"0x{x}\"}}";
                return std.fmt.bufPrint(out, format, .{
                    tx.block_number,
                    &block_hash(tx.block_number, tx.fork),
                });
            }
            return "null";
        }
        if (std.mem.eql(u8, method, "eth_sendRawTransaction")) return l1.accept(body);
        return error.UnknownMethod;
    }

    fn accept(l1: *FakeL1, body: []const u8) ![]const u8 {
        l1.sends += 1;
        if (l1.reject_with) |message| {
            l1.rejection = message;
            return error.Rejected;
        }
        const hex = between(body, "\"params\":[\"0x", "\"").?;
        var raw: [1024]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, hex);
        const envelope = try consensus.tx.Envelope.decode(bytes);
        const tx = envelope.eip1559.tx;
        l1.last_to = tx.to.call.bytes;
        if (tx.nonce < l1.account_nonce) {
            l1.rejection = "nonce too low";
            return error.Rejected;
        }
        assert(tx.nonce < nonces_max);
        const hash = envelope.hash().bytes;
        if (l1.pool[tx.nonce]) |old| {
            const tip_ok = tx.max_priority_fee_per_gas >= fees.threshold(old.tip_wei, false);
            const cap_ok = tx.max_fee_per_gas >= fees.threshold(old.fee_cap_wei, false);
            assert(tip_ok and cap_ok);
        }
        l1.pool[tx.nonce] = .{
            .hash = hash,
            .tip_wei = tx.max_priority_fee_per_gas,
            .fee_cap_wei = tx.max_fee_per_gas,
        };
        return "\"0x00\"";
    }
};

fn between(text: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const begin = (std.mem.indexOf(u8, text, start) orelse return null) + start.len;
    const length = std.mem.indexOf(u8, text[begin..], end) orelse return null;
    return text[begin..][0..length];
}

const Fixture = struct {
    l1: FakeL1 = .{},
    client: rpc.Client = undefined,
    driver: Driver = undefined,

    fn init(fixture: *Fixture) !void {
        fixture.client = try rpc.Client.init(testing.allocator, fixture.l1.transport(), .{
            .request_bytes_max = 64 * 1024,
            .response_bytes_max = 4096,
            .parse_bytes_max = 64 * 1024,
        });
        const sender = accounts.derive_dev(0);
        fixture.driver = try Driver.init(testing.allocator, .{
            .chain_id = 900,
            .private_key = sender.private_key,
            .from = sender.address,
            .data_bytes_max = 256,
            .manager = .{
                .num_confirmations = 2,
                .resubmission_timeout_ms = 3_000,
                .receipt_query_interval_ms = 1_000,
            },
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.driver.deinit(testing.allocator);
        fixture.client.deinit(testing.allocator);
    }

    fn run(fixture: *Fixture, now_ms: *u64, steps: u32, mine: bool) !void {
        for (0..steps) |_| {
            now_ms.* += 1_000;
            if (mine) fixture.l1.mine();
            try fixture.driver.step(&fixture.client, now_ms.*);
        }
    }
};

test "driver: transfers are signed, published in nonce order, and confirmed" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    var now_ms: u64 = 0;
    const to: driver_module.Address = .{ .bytes = @splat(0xab) };
    for (0..3) |_| _ = try fixture.driver.send(&fixture.client, .{ .to = to, .value = 1 }, now_ms);
    try fixture.run(&now_ms, 6, true);
    var confirmed: u32 = 0;
    while (fixture.driver.take_completion()) |completion| {
        try testing.expect(completion.outcome == .confirmed);
        try testing.expectEqual(@as(u64, 0), completion.bump_count);
        confirmed += 1;
    }
    try testing.expectEqual(@as(u32, 3), confirmed);
    try testing.expectEqual(@as(u64, 3), fixture.l1.account_nonce);
    try testing.expectEqualSlices(u8, &to.bytes, &fixture.l1.last_to);
}

test "driver: a dropped transaction is re-published with bumped fees" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    var now_ms: u64 = 0;
    const to: driver_module.Address = .{ .bytes = @splat(0xcd) };
    _ = try fixture.driver.send(&fixture.client, .{ .to = to, .data = "hello" }, now_ms);
    try fixture.run(&now_ms, 1, false);
    const first = fixture.l1.pool[0].?;
    fixture.l1.pool[0] = null; // Dropped from the mempool.
    try fixture.run(&now_ms, 4, false);
    const second = fixture.l1.pool[0].?;
    try testing.expect(!std.mem.eql(u8, &first.hash, &second.hash));
    try testing.expect(second.tip_wei > first.tip_wei);
    try fixture.run(&now_ms, 4, true);
    const completion = fixture.driver.take_completion().?;
    try testing.expectEqual(@as(u64, 1), completion.bump_count);
    try testing.expectEqualSlices(u8, &second.hash, &completion.outcome.confirmed.hash);
}

test "driver: a receipt from a reorged-out block is not trusted" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    var now_ms: u64 = 0;
    _ = try fixture.driver.send(&fixture.client, .{ .to = .{ .bytes = @splat(1) } }, now_ms);
    try fixture.run(&now_ms, 1, false);
    fixture.l1.mine();
    // The block that holds the tx is replaced: same height, new hash.
    fixture.l1.fork +%= 1;
    try fixture.run(&now_ms, 3, false);
    try testing.expect(fixture.driver.take_completion() == null);
    // Re-mined on the new fork, it confirms.
    fixture.l1.mined[0].?.fork = fixture.l1.fork;
    try fixture.run(&now_ms, 3, true);
    try testing.expect(fixture.driver.take_completion().?.outcome == .confirmed);
}

test "driver: rejection messages are classified" {
    var fixture: Fixture = .{};
    try fixture.init();
    defer fixture.deinit();
    fixture.l1.reject_with = "insufficient funds for gas * price + value";
    _ = try fixture.driver.send(&fixture.client, .{ .to = .{ .bytes = @splat(2) } }, 0);
    var now_ms: u64 = 0;
    try fixture.run(&now_ms, 1, false);
    const completion = fixture.driver.take_completion().?;
    try testing.expect(completion.outcome.failed == .publish_rejected);
    try testing.expectEqual(.insufficient_funds, completion.publish_error.?);
    try testing.expectError(error.DataTooLarge, fixture.driver.send(&fixture.client, .{
        .to = .{ .bytes = @splat(2) },
        .data = &@as([257]u8, @splat(0)),
    }, now_ms));
}

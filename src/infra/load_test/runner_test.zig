//! Load test runner over a fake chain: one block producer, one account per sender, each
//! sender's client talks to the chain through its own transport view (so the fake knows
//! the sender without recovering signatures). Deterministic: same seed, same report.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const runner_module = @import("runner.zig");
const workload = @import("workload.zig");

const nonces_max = 512;
const Hash = [32]u8;

const FakeChain = struct {
    head: u64 = 1,
    base_fee_wei: u128 = 1_000_000_000,
    /// Per block, at most this many transactions are included across all senders.
    block_capacity: u32 = 1_000,
    accounts: [runner_module.senders_max]Account = @splat(.{}),
    sends: u64 = 0,

    const Account = struct {
        nonce: u64 = 0,
        pool: [nonces_max]?Hash = @splat(null),
        mined: [nonces_max]?u64 = @splat(null),
        mined_hash: [nonces_max]Hash = undefined,
    };

    fn mine(chain: *FakeChain) void {
        chain.head += 1;
        var included: u32 = 0;
        for (&chain.accounts) |*account| {
            while (included < chain.block_capacity and account.nonce < nonces_max) {
                const hash = account.pool[account.nonce] orelse break;
                account.mined[account.nonce] = chain.head;
                account.mined_hash[account.nonce] = hash;
                account.pool[account.nonce] = null;
                account.nonce += 1;
                included += 1;
            }
        }
    }

    fn answer(
        chain: *FakeChain,
        sender: u32,
        method: []const u8,
        body: []const u8,
        out: []u8,
    ) ![]const u8 {
        const account = &chain.accounts[sender];
        if (std.mem.eql(u8, method, "eth_getTransactionCount")) {
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{account.nonce});
        }
        if (std.mem.eql(u8, method, "eth_maxPriorityFeePerGas")) return "\"0x1\"";
        if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
            const tag = between(body, "\"params\":[\"", "\"").?;
            const number = if (std.mem.eql(u8, tag, "latest"))
                chain.head
            else
                try std.fmt.parseInt(u64, tag[2..], 16);
            return std.fmt.bufPrint(out, "{{\"number\":\"0x{x}\",\"baseFeePerGas\":\"0x{x}\"," ++
                "\"hash\":\"0x{x:0>64}\"}}", .{ number, chain.base_fee_wei, number });
        }
        if (std.mem.eql(u8, method, "eth_getTransactionReceipt")) {
            var hash: Hash = undefined;
            _ = try std.fmt.hexToBytes(&hash, between(body, "\"params\":[\"0x", "\"").?);
            for (account.mined[0..account.nonce], 0..) |block, nonce| {
                if (!std.mem.eql(u8, &account.mined_hash[nonce], &hash)) continue;
                return std.fmt.bufPrint(out, "{{\"blockNumber\":\"0x{x}\"," ++
                    "\"blockHash\":\"0x{x:0>64}\"}}", .{ block.?, block.? });
            }
            return "null";
        }
        if (std.mem.eql(u8, method, "eth_sendRawTransaction")) {
            chain.sends += 1;
            var raw: [8192]u8 = undefined;
            const bytes = try std.fmt.hexToBytes(&raw, between(body, "\"params\":[\"0x", "\"").?);
            const envelope = try consensus.tx.Envelope.decode(bytes);
            const nonce = envelope.eip1559.tx.nonce;
            if (nonce < account.nonce) return error.NonceTooLow;
            assert(nonce < nonces_max);
            account.pool[nonce] = envelope.hash().bytes;
            return "\"0x00\"";
        }
        return error.UnknownMethod;
    }
};

const View = struct {
    chain: *FakeChain,
    sender: u32,

    fn transport(view: *View) rpc.Transport {
        return .{ .context = view, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const view: *View = @ptrCast(@alignCast(context));
        const id = between(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = between(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        var buffer: [256]u8 = undefined;
        const text = if (view.chain.answer(view.sender, method, body, &buffer)) |result|
            std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}", .{
                id,
                result,
            })
        else |err| switch (err) {
            error.NonceTooLow => std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                "\"error\":{{\"code\":-32000,\"message\":\"nonce too low\"}}}}", .{id}),
            else => return error.TransportFailed,
        };
        return (text catch return error.ResponseTooLarge).len;
    }
};

fn between(text: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const begin = (std.mem.indexOf(u8, text, start) orelse return null) + start.len;
    const length = std.mem.indexOf(u8, text[begin..], end) orelse return null;
    return text[begin..][0..length];
}

const Setup = struct {
    chain: FakeChain = .{},
    views: [3]View = undefined,
    clients: [3]rpc.Client = undefined,
    client_pointers: [3]*rpc.Client = undefined,
    runner: runner_module.Runner = undefined,

    fn init(setup: *Setup, config: runner_module.Config) !void {
        const views = &setup.views;
        for (views, &setup.clients, &setup.client_pointers, 0..) |*view, *client, *pointer, index| {
            view.* = .{ .chain = &setup.chain, .sender = @intCast(index) };
            client.* = try rpc.Client.init(testing.allocator, view.transport(), .{
                .request_bytes_max = 32 * 1024,
                .response_bytes_max = 4096,
                .parse_bytes_max = 64 * 1024,
            });
            pointer.* = client;
        }
        try setup.runner.init(testing.allocator, config, &setup.client_pointers, 0);
    }

    fn deinit(setup: *Setup) void {
        setup.runner.deinit(testing.allocator);
        for (&setup.clients) |*client| client.deinit(testing.allocator);
    }

    /// Steps every 100 ms, a block every `block_ms`, until the runner is done.
    fn run(setup: *Setup, block_ms: u64) u64 {
        var now_ms: u64 = 0;
        while (!setup.runner.done(now_ms)) {
            now_ms += 100;
            if (now_ms % block_ms == 0) setup.chain.mine();
            setup.runner.step(now_ms);
            assert(now_ms < 10 * 60 * 1000);
        }
        return now_ms;
    }
};

fn test_config(seed: u64) !runner_module.Config {
    return .{
        .chain_id = 901,
        .account_indices = &.{ 2, 3, 4 },
        .rate_per_s = 15,
        .duration_ms = 10_000,
        .drain_ms = 30_000,
        .workload = .{
            .seed = seed,
            .mix = try workload.Mix.parse("transfer=60,calldata=30,erc20_transfer=10"),
            .calldata_bytes_max = 512,
        },
    };
}

test "load_test runner: offered load is confirmed with block-time latency" {
    const setup = try testing.allocator.create(Setup);
    defer testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(try test_config(42));
    defer setup.deinit();
    _ = setup.run(2_000);
    const summary = setup.runner.recorder.summary();
    // 15 tx/s for 10 s, the last cycle at 9.9 s.
    try testing.expectEqual(@as(u64, 148), summary.submitted);
    try testing.expectEqual(summary.submitted, summary.confirmed);
    try testing.expectEqual(@as(u64, 0), summary.failed);
    // Blocks every 2 s plus a 1 s receipt poll: latency stays within about 3 s.
    try testing.expect(summary.latency_p50_ms >= 100 and summary.latency_p99_ms <= 3_200);
    try testing.expect(summary.throughput_milli_tps > 10_000);
}

test "load_test runner: a congested chain shows up as latency and backpressure" {
    const setup = try testing.allocator.create(Setup);
    defer testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(try test_config(43));
    defer setup.deinit();
    setup.chain.block_capacity = 6; // 3 tx/s capacity against 15 tx/s offered.
    _ = setup.run(2_000);
    const summary = setup.runner.recorder.summary();
    // Senders fill up (16 in flight each), so most owed sends are dropped by the open loop.
    try testing.expect(summary.submitted < 120);
    try testing.expect(summary.latency_p90_ms > 4_000);
    try testing.expectEqual(summary.submitted, summary.confirmed + summary.failed);
}

test "load_test runner: deterministic per seed" {
    var reports: [2][2048]u8 = undefined;
    var lengths: [2]usize = undefined;
    for (0..2) |round| {
        const setup = try testing.allocator.create(Setup);
        defer testing.allocator.destroy(setup);
        setup.* = .{};
        try setup.init(try test_config(7));
        defer setup.deinit();
        _ = setup.run(1_000);
        var writer: std.Io.Writer = .fixed(&reports[round]);
        try setup.runner.recorder.write_report(&writer);
        lengths[round] = writer.end;
    }
    try testing.expectEqualStrings(reports[0][0..lengths[0]], reports[1][0..lengths[1]]);
}

//! Load test runner over a fake chain: one block producer, one account per sender, each
//! sender's client talks to the chain through its own transport view (so the fake knows
//! the sender without recovering signatures). The fake decodes every transaction: it
//! records contract creations (and serves their code), value transfers (which fund a
//! sender), and calls to deployed contracts. Deterministic: same seed, same report.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const evm = @import("../../execution/evm/evm.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const runner_module = @import("runner.zig");
const workload = @import("workload.zig");
const contracts = @import("contracts.zig");
const chain_prep = @import("chain_prep.zig");

const nonces_max = 512;
const views_max = 9;
const created_max = 8;
const funded_max = 64;
const Hash = [32]u8;
const Address = workload.Address;

const FakeChain = struct {
    head: u64 = 1,
    base_fee_wei: u128 = 1_000_000_000,
    /// Per block, at most this many transactions are included across all senders.
    block_capacity: u32 = 1_000,
    accounts: [views_max]Account = @splat(.{}),
    sends: u64 = 0,
    /// Creations confirm but leave no code (an out-of-gas deploy).
    creations_fail: bool = false,
    created: [created_max]Created = undefined,
    created_count: u32 = 0,
    funded: [funded_max]Address = undefined,
    funded_count: u32 = 0,
    /// Sends from views that must be funded first, before they were.
    unfunded_sends: u64 = 0,
    /// Mined calls per contract kind.
    contract_calls: [3]u64 = @splat(0),

    const Created = struct { address: Address, kind: contracts.Kind };

    const Tx = struct {
        hash: Hash,
        create: ?contracts.Kind,
        to: Address,
        value: u256,
    };

    const Account = struct {
        nonce: u64 = 0,
        pool: [nonces_max]?Tx = @splat(null),
        mined: [nonces_max]?u64 = @splat(null),
        mined_hash: [nonces_max]Hash = undefined,
    };

    fn mine(chain: *FakeChain, views: []const View) void {
        chain.head += 1;
        var included: u32 = 0;
        for (chain.accounts[0..views.len], views) |*account, view| {
            while (included < chain.block_capacity and account.nonce < nonces_max) {
                const tx = account.pool[account.nonce] orelse break;
                chain.apply(view.address, account.nonce, tx);
                account.mined[account.nonce] = chain.head;
                account.mined_hash[account.nonce] = tx.hash;
                account.pool[account.nonce] = null;
                account.nonce += 1;
                included += 1;
            }
        }
    }

    fn apply(chain: *FakeChain, sender: Address, nonce: u64, tx: Tx) void {
        if (tx.create) |kind| {
            if (chain.creations_fail) return;
            assert(chain.created_count < created_max);
            const address = evm.create_address(sender.bytes, nonce);
            const created: Created = .{ .address = .{ .bytes = address }, .kind = kind };
            chain.created[chain.created_count] = created;
            chain.created_count += 1;
            return;
        }
        if (tx.value > 0 and chain.funded_count < funded_max) {
            chain.funded[chain.funded_count] = tx.to;
            chain.funded_count += 1;
        }
        if (chain.created_at(tx.to)) |kind| chain.contract_calls[@backingInt(kind)] += 1;
    }

    fn created_at(chain: *const FakeChain, address: Address) ?contracts.Kind {
        for (chain.created[0..chain.created_count]) |created| {
            if (std.mem.eql(u8, &created.address.bytes, &address.bytes)) return created.kind;
        }
        return null;
    }

    fn is_funded(chain: *const FakeChain, address: Address) bool {
        for (chain.funded[0..chain.funded_count]) |funded| {
            if (std.mem.eql(u8, &funded.bytes, &address.bytes)) return true;
        }
        return false;
    }

    fn answer(
        chain: *FakeChain,
        view: *const View,
        method: []const u8,
        body: []const u8,
        out: []u8,
    ) ![]const u8 {
        const account = &chain.accounts[view.index];
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
        if (std.mem.eql(u8, method, "eth_getCode")) {
            var address: Address = undefined;
            _ = try std.fmt.hexToBytes(&address.bytes, between(body, "\"params\":[\"0x", "\"").?);
            const kind = chain.created_at(address) orelse return "\"0x\"";
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{contracts.runtime_of(kind)});
        }
        if (std.mem.eql(u8, method, "eth_sendRawTransaction")) return chain.receive(view, body);
        return error.UnknownMethod;
    }

    fn receive(chain: *FakeChain, view: *const View, body: []const u8) ![]const u8 {
        const account = &chain.accounts[view.index];
        chain.sends += 1;
        var raw: [8192]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, between(body, "\"params\":[\"0x", "\"").?);
        const envelope = try consensus.tx.Envelope.decode(bytes);
        const tx = envelope.eip1559.tx;
        if (tx.nonce < account.nonce) return error.NonceTooLow;
        assert(tx.nonce < nonces_max);
        if (view.must_be_funded and !chain.is_funded(view.address)) chain.unfunded_sends += 1;
        account.pool[tx.nonce] = .{
            .hash = envelope.hash().bytes,
            .create = if (tx.to == .create) kind_of(tx.input) else null,
            .to = if (tx.to == .call) tx.to.call else .{ .bytes = @splat(0) },
            .value = tx.value,
        };
        return "\"0x00\"";
    }

    fn kind_of(init_code: []const u8) contracts.Kind {
        for (std.enums.values(contracts.Kind)) |kind| {
            if (std.mem.eql(u8, contracts.init_code_of(kind), init_code)) return kind;
        }
        unreachable; // The prep phase only deploys the workload contracts.
    }
};

const View = struct {
    chain: *FakeChain,
    index: u32,
    address: Address,
    must_be_funded: bool,

    fn transport(view: *View) rpc.Transport {
        return .{ .context = view, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const view: *View = @ptrCast(@alignCast(context));
        const id = between(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = between(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        var buffer: [2048]u8 = undefined;
        const text = if (view.chain.answer(view, method, body, &buffer)) |result|
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
    views: [views_max]View = undefined,
    clients: [views_max]rpc.Client = undefined,
    client_pointers: [views_max]*rpc.Client = undefined,
    view_count: u32 = 0,
    runner: runner_module.Runner = undefined,

    fn init(setup: *Setup, config: runner_module.Config) !void {
        const senders: u32 = if (config.stream_senders > 0)
            config.stream_senders
        else
            @intCast(config.account_indices.len);
        setup.view_count = senders + @intFromBool(config.prep != null);
        assert(setup.view_count <= views_max);
        for (0..setup.view_count) |index| {
            const is_funder = index == senders;
            const address = if (is_funder)
                accounts.derive_dev(config.prep.?.funder_index).address
            else if (config.stream_senders > 0)
                @import("key_stream.zig").derive(config.key_seed, @intCast(index)).address
            else
                accounts.derive_dev(config.account_indices[index]).address;
            setup.views[index] = .{
                .chain = &setup.chain,
                .index = @intCast(index),
                .address = address,
                .must_be_funded = !is_funder and config.stream_senders > 0,
            };
            setup.clients[index] = try rpc.Client.init(
                testing.allocator,
                setup.views[index].transport(),
                .{
                    .request_bytes_max = 32 * 1024,
                    .response_bytes_max = 4096,
                    .parse_bytes_max = 64 * 1024,
                },
            );
            setup.client_pointers[index] = &setup.clients[index];
        }
        const pointers = setup.client_pointers[0..setup.view_count];
        try setup.runner.init(testing.allocator, config, pointers, 0);
    }

    fn deinit(setup: *Setup) void {
        setup.runner.deinit(testing.allocator);
        for (setup.clients[0..setup.view_count]) |*client| client.deinit(testing.allocator);
    }

    /// Steps every 100 ms, a block every `block_ms`, until the runner is done.
    fn run(setup: *Setup, block_ms: u64) u64 {
        var now_ms: u64 = 0;
        while (!setup.runner.done(now_ms)) {
            now_ms += 100;
            if (now_ms % block_ms == 0) setup.chain.mine(setup.views[0..setup.view_count]);
            setup.runner.step(now_ms);
            assert(now_ms < 20 * 60 * 1000);
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
            .mix = try workload.Mix.parse("transfer=60,calldata=30,precompile=10"),
            .calldata_bytes_max = 512,
        },
    };
}

fn create_setup(config: runner_module.Config) !*Setup {
    const setup = try testing.allocator.create(Setup);
    errdefer testing.allocator.destroy(setup);
    setup.* = .{};
    try setup.init(config);
    return setup;
}

fn destroy_setup(setup: *Setup) void {
    setup.deinit();
    testing.allocator.destroy(setup);
}

test "load_test runner: offered load is confirmed with block-time latency" {
    const setup = try create_setup(try test_config(42));
    defer destroy_setup(setup);
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
    const setup = try create_setup(try test_config(43));
    defer destroy_setup(setup);
    setup.chain.block_capacity = 6; // 3 tx/s capacity against 15 tx/s offered.
    _ = setup.run(2_000);
    const summary = setup.runner.recorder.summary();
    // Senders fill up (16 in flight each), so most owed sends are dropped by the open loop.
    try testing.expect(summary.submitted < 120);
    try testing.expect(summary.latency_p90_ms > 4_000);
    try testing.expectEqual(summary.submitted, summary.confirmed + summary.failed);
}

test "load_test runner: deterministic per seed" {
    var reports: [2][4096]u8 = undefined;
    var lengths: [2]usize = undefined;
    for (0..2) |round| {
        const setup = try create_setup(try test_config(7));
        defer destroy_setup(setup);
        _ = setup.run(1_000);
        var writer: std.Io.Writer = .fixed(&reports[round]);
        try setup.runner.write_report(&writer);
        lengths[round] = writer.end;
    }
    try testing.expectEqualStrings(reports[0][0..lengths[0]], reports[1][0..lengths[1]]);
}

fn prep_config(seed: u64) !runner_module.Config {
    var config = try test_config(seed);
    config.stream_senders = 6;
    config.key_seed = seed;
    config.workload.mix = try workload.Mix.parse(
        "transfer=20,erc20_transfer=30,storage=25,looper=25",
    );
    config.workload.looper_iterations = 100;
    config.prep = .{ .funder_index = 8, .fund_wei = 100_000_000_000_000_000, .in_flight_max = 4 };
    return config;
}

test "load_test runner: prep deploys, funds, and mints before the load targets contracts" {
    const setup = try create_setup(try prep_config(11));
    defer destroy_setup(setup);
    _ = setup.run(1_000);
    const prep = setup.runner.prep.?;
    try testing.expectEqual(chain_prep.Phase.done, prep.phase);
    try testing.expectEqual(@as(u32, 6), prep.funded);
    try testing.expectEqual(@as(u32, 6), prep.minted);
    // Contracts sit at the funder's CREATE addresses for nonces 0, 1, 2.
    const funder = accounts.derive_dev(8).address;
    const deployed = prep.contracts_deployed().?;
    const expected = [_]Address{ deployed.token, deployed.storage, deployed.looper };
    for (expected, 0..) |address, nonce| {
        try testing.expectEqual(evm.create_address(funder.bytes, nonce), address.bytes);
    }
    try testing.expectEqual(@as(u32, 3), setup.chain.created_count);
    try testing.expectEqual(deployed, setup.runner.generator.config.contracts.?);
    // No sender sent before it was funded; every load transaction confirmed.
    try testing.expectEqual(@as(u64, 0), setup.chain.unfunded_sends);
    const summary = setup.runner.recorder.summary();
    try testing.expectEqual(@as(u64, 148), summary.submitted);
    try testing.expectEqual(summary.submitted, summary.confirmed);
    // Mints plus the load's token transfers; storage and looper calls from the load.
    const calls = setup.chain.contract_calls;
    const generated = setup.runner.generator.generated;
    const erc20 = generated[@backingInt(workload.Kind.erc20_transfer)];
    try testing.expectEqual(6 + erc20, calls[@backingInt(contracts.Kind.token)]);
    try testing.expectEqual(generated[@backingInt(workload.Kind.storage)], calls[1]);
    try testing.expectEqual(generated[@backingInt(workload.Kind.looper)], calls[2]);
    try testing.expect(erc20 > 0 and calls[1] > 0 and calls[2] > 0);
}

test "load_test runner: a deploy without code fails the prep and ends the run" {
    const setup = try create_setup(try prep_config(12));
    defer destroy_setup(setup);
    setup.chain.creations_fail = true;
    const end_ms = setup.run(1_000);
    try testing.expect(setup.runner.prep_failed());
    try testing.expect(end_ms < 60_000);
    try testing.expectEqual(@as(u64, 0), setup.runner.recorder.submitted);
    try testing.expectEqual(@as(u32, 0), setup.chain.funded_count);
    try testing.expect(setup.runner.prep.?.contracts_deployed() == null);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try setup.runner.write_json(&writer);
    const json = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, json, "\"phase\":\"failed\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"contracts\":null") != null);
}

test "load_test runner: contract payloads need a prep phase" {
    var config = try prep_config(13);
    config.prep = null;
    const setup = try testing.allocator.create(Setup);
    defer testing.allocator.destroy(setup);
    setup.* = .{};
    try testing.expectError(error.ContractsRequired, setup.init(config));
    for (setup.clients[0..setup.view_count]) |*client| client.deinit(testing.allocator);
}

test "load_test runner: json report parses" {
    const setup = try create_setup(try prep_config(14));
    defer destroy_setup(setup);
    _ = setup.run(1_000);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try setup.runner.write_json(&writer);
    const Value = std.json.Value;
    const parsed = try std.json.parseFromSlice(Value, testing.allocator, writer.buffered(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqual(@as(i64, 148), root.get("submitted").?.integer);
    try testing.expectEqual(@as(i64, 6), root.get("senders").?.integer);
    const prep = root.get("prep").?.object;
    try testing.expectEqualStrings("done", prep.get("phase").?.string);
    try testing.expectEqual(@as(i64, 6), prep.get("funded").?.integer);
    const token = prep.get("contracts").?.object.get("token").?.string;
    try testing.expectEqual(@as(usize, 42), token.len);
    try testing.expect(root.get("latency_ms").?.object.get("p50").?.integer > 0);
}

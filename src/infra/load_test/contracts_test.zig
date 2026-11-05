//! Runs the hand-assembled workload contracts in needlefish's own EVM: deploy through the
//! init code, then call, asserting storage, balances, logs, return data, and that the
//! locally computed gas budgets cover the execution.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const evm_root = @import("../../execution/evm/root.zig");
const contracts = @import("contracts.zig");

const primitives = evm_root.primitives;
const Address = primitives.Address;
const Fork = evm_root.Fork;

const fork: Fork = .osaka;
const deployer = primitives.address_from_int(0xde9107e5);
const alice = primitives.address_from_int(0xa11ce);
const bob = primitives.address_from_int(0xb0b);

const Harness = struct {
    database: evm_root.MemoryDatabase,
    state: evm_root.State,
    evm: evm_root.Evm,

    fn init(harness: *Harness) !void {
        const allocator = testing.allocator;
        harness.database = evm_root.MemoryDatabase.init(allocator);
        errdefer harness.database.deinit();
        harness.state = try evm_root.State.init(allocator, harness.database.interface(), .{
            .accounts_max = 256,
            .slots_max = 4096,
            .transient_slots_max = 16,
            .journal_entries_max = 1 << 14,
            .logs_max = 16,
            .log_data_bytes_max = 4096,
            .code_bytes_max = 1 << 16,
        });
        errdefer harness.state.deinit(allocator);
        harness.evm = try evm_root.Evm.init(allocator, .{
            .memory_bytes_max = 1 << 16,
            .code_arena_bytes = 1 << 18,
            .modexp_modulus_bytes_max = 1024,
        }, &harness.state);
        try harness.database.put_account(deployer, 0, 0, &.{});
    }

    fn deinit(harness: *Harness) void {
        harness.evm.deinit(testing.allocator);
        harness.state.deinit(testing.allocator);
        harness.database.deinit();
    }

    /// Deploys with exactly the execution share of `deploy_gas` (no intrinsic part).
    fn deploy(harness: *Harness, kind: contracts.Kind) !Address {
        const code = contracts.init_code_of(kind);
        const intrinsic = evm_root_calldata_floor(code);
        const gas_limit = contracts.deploy_gas(kind) - intrinsic;
        harness.state.begin_transaction();
        const outcome = try harness.evm.execute(fork, .{
            .kind = .create,
            .caller = deployer,
            .input = code,
            .gas_limit = gas_limit,
        });
        try testing.expectEqual(evm_root.evm.Status.success, outcome.status);
        return outcome.created.?;
    }

    fn call(harness: *Harness, from: Address, to: Address, input: []const u8, gas: u64) !Result {
        harness.state.begin_transaction();
        const outcome = try harness.evm.execute(fork, .{
            .kind = .call,
            .caller = from,
            .target = to,
            .input = input,
            .gas_limit = gas,
        });
        assert(outcome.gas_remaining <= gas);
        return .{ .outcome = outcome, .gas_used = gas - outcome.gas_remaining };
    }

    fn storage(harness: *Harness, address: Address, slot: u256) !u256 {
        const account = try harness.state.load(address);
        const access = try harness.state.storage_access(account, slot);
        return access.slot.present;
    }
};

const Result = struct { outcome: evm_root.evm.Outcome, gas_used: u64 };

/// The intrinsic part of `deploy_gas` that a bare `execute` does not charge.
fn evm_root_calldata_floor(code: []const u8) u64 {
    const words: u64 = (code.len + 31) / 32;
    return @import("../../batcher/txdata/root.zig").calldata_gas(code) + 32_000 + 2 * words;
}

fn word(value: u256) [32]u8 {
    return primitives.u256_to_b256(value);
}

fn address_word(address: Address) [32]u8 {
    return word(primitives.address_to_u256(address));
}

fn balance_of(h: *Harness, token: Address, owner: Address) !u256 {
    return h.storage(token, primitives.address_to_u256(owner));
}

test "contracts: looper bytecode is pinned" {
    const expected = [_]u8{
        0x60, 0x00, 0x35, 0x5b, 0x80, 0x15, 0x61, 0x00, 0x12, 0x57,
        0x60, 0x01, 0x90, 0x03, 0x61, 0x00, 0x03, 0x56, 0x5b, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, &contracts.looper_runtime);
    const prefix = [_]u8{ 0x61, 0x00, 0x14, 0x80, 0x60, 0x0c };
    try testing.expectEqualSlices(u8, &prefix, contracts.looper_init[0..6]);
}

fn token_call(selector: [4]u8, to: Address, amount: u256) [68]u8 {
    return selector ++ address_word(to) ++ word(amount);
}

test "contracts: deploy returns the exact runtime code" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const kinds = [_]contracts.Kind{ .token, .storage, .looper };
    const runtimes = [_][]const u8{
        &contracts.token_runtime, &contracts.storage_runtime, &contracts.looper_runtime,
    };
    for (kinds, runtimes, 0..) |kind, runtime, nonce| {
        const address = try h.deploy(kind);
        try testing.expectEqualSlices(u8, &evm_root.evm.create_address(deployer, nonce), &address);
        const account = try h.state.load(address);
        try testing.expectEqualSlices(u8, runtime, account.info.code.?);
    }
}

test "contracts: token mint, transfer, balanceOf, and short-balance revert" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const token = try h.deploy(.token);
    const mint = token_call(contracts.selector_mint, alice, 1000);
    const minted = try h.call(deployer, token, &mint, contracts.token_mint_gas);
    try testing.expectEqual(evm_root.evm.Status.success, minted.outcome.status);
    try testing.expectEqual(@as(usize, 1), h.state.transaction_logs().len);
    try testing.expectEqual(@as(u256, 1000), try balance_of(&h, token, alice));
    const transfer = token_call(contracts.selector_transfer, bob, 300);
    const sent = try h.call(alice, token, &transfer, contracts.token_transfer_gas);
    try testing.expectEqual(evm_root.evm.Status.success, sent.outcome.status);
    try testing.expectEqual(@as(u256, 1), primitives.b256_to_u256(sent.outcome.output[0..32].*));
    const logs = h.state.transaction_logs();
    try testing.expectEqual(@as(usize, 1), logs.len);
    try testing.expectEqualSlices(u8, &contracts.transfer_topic, &logs[0].topics[0]);
    try testing.expectEqualSlices(u8, &address_word(alice), &logs[0].topics[1]);
    try testing.expectEqualSlices(u8, &address_word(bob), &logs[0].topics[2]);
    try testing.expectEqualSlices(u8, &word(300), logs[0].data);
    const query = contracts.selector_balance_of ++ address_word(bob);
    const balance = try h.call(alice, token, &query, 30_000);
    const returned = primitives.b256_to_u256(balance.outcome.output[0..32].*);
    try testing.expectEqual(@as(u256, 300), returned);
    try testing.expectEqual(@as(u256, 700), try balance_of(&h, token, alice));
    // Bob holds 300; sending 301 reverts and changes nothing.
    const too_much = token_call(contracts.selector_transfer, alice, 301);
    const reverted = try h.call(bob, token, &too_much, contracts.token_transfer_gas);
    try testing.expectEqual(evm_root.evm.Status.revert, reverted.outcome.status);
    try testing.expectEqual(@as(u256, 300), try h.storage(token, primitives.address_to_u256(bob)));
    // Self-transfer keeps the balance; unknown selectors revert.
    const self = token_call(contracts.selector_transfer, bob, 300);
    _ = try h.call(bob, token, &self, contracts.token_transfer_gas);
    try testing.expectEqual(@as(u256, 300), try h.storage(token, primitives.address_to_u256(bob)));
    const unknown = try h.call(bob, token, &[_]u8{ 1, 2, 3, 4 }, 30_000);
    try testing.expectEqual(evm_root.evm.Status.revert, unknown.outcome.status);
}

test "contracts: storage writer gas is exact per fresh slot" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const writer = try h.deploy(.storage);
    for ([_]u64{ 0, 1, 7 }, 0..) |count, round| {
        const first: u256 = 1_000 * (round + 1);
        const input = word(first) ++ word(count) ++ word(0xabc);
        const expected = contracts.storage_gas_base + count * contracts.storage_gas_per_slot;
        const result = try h.call(deployer, writer, &input, expected);
        try testing.expectEqual(evm_root.evm.Status.success, result.outcome.status);
        try testing.expectEqual(expected, result.gas_used);
        for (0..count) |index| {
            try testing.expectEqual(@as(u256, 0xabc), try h.storage(writer, first + index));
        }
        try testing.expectEqual(@as(u256, 0), try h.storage(writer, first + count));
    }
}

test "contracts: looper burns exactly the computed gas" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const looper = try h.deploy(.looper);
    for ([_]u64{ 0, 1, 1000 }) |iterations| {
        const per_iteration = contracts.looper_gas_per_iteration;
        const expected = contracts.looper_gas_base + iterations * per_iteration;
        const result = try h.call(deployer, looper, &word(iterations), expected);
        try testing.expectEqual(evm_root.evm.Status.success, result.outcome.status);
        try testing.expectEqual(expected, result.gas_used);
        const short = try h.call(deployer, looper, &word(iterations), expected - 1);
        try testing.expect(short.outcome.status != .success);
    }
}

test "contracts: generated payloads succeed within their local gas limits" {
    const workload = @import("workload.zig");
    const txdata = @import("../../batcher/txdata/root.zig");
    const key_stream = @import("key_stream.zig");
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const token = try h.deploy(.token);
    const deployed: workload.Contracts = .{
        .token = .{ .bytes = token },
        .storage = .{ .bytes = try h.deploy(.storage) },
        .looper = .{ .bytes = try h.deploy(.looper) },
    };
    const mint = token_call(contracts.selector_mint, alice, 1 << 64);
    _ = try h.call(deployer, token, &mint, contracts.token_mint_gas);
    const seed = 5;
    var generator = workload.Generator(256).init(.{
        .seed = seed,
        .mix = try workload.Mix.parse("erc20_transfer=1,storage=1,looper=1,precompile=3"),
        .calldata_bytes_max = 256,
        .looper_iterations = 500,
        .contracts = deployed,
    });
    const signer = key_stream.derive(seed, std.math.maxInt(u32)).address;
    for (0..200) |_| {
        const payload = generator.next();
        // The EIP-7623 floor is at least the standard intrinsic cost, so this leaves the
        // payload exactly the execution budget it was given (or less).
        const execution = payload.gas_limit - txdata.calldata_gas(payload.data);
        const result = try h.call(alice, payload.to.bytes, payload.data, execution);
        try testing.expectEqual(evm_root.evm.Status.success, result.outcome.status);
        const is_ecrecover = payload.kind == .precompile and payload.to.bytes[19] == 1;
        if (is_ecrecover) {
            try testing.expectEqualSlices(u8, &signer.bytes, result.outcome.output[12..32]);
        }
    }
    for (generator.generated, 0..) |count, index| {
        const kind: workload.Kind = @fromBackingInt(@intCast(index));
        try testing.expectEqual(generator.config.mix.weight_of(kind) > 0, count > 0);
    }
}

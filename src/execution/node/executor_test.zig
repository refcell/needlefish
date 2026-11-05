//! Block executor tests: transfers, logs, invalid transactions leaving state untouched,
//! withdrawals, and a seeded model-checked fuzz of random transfer blocks.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const evm = @import("../evm/root.zig");
const executor_module = @import("executor.zig");
const state_db = @import("state_db.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Executor = executor_module.Executor;
const StateDb = state_db.StateDb;
const spec = &chainspec.ChainSpec.presets.l1_dev;

fn key(n: u8) [32]u8 {
    var k: [32]u8 = @splat(0);
    k[31] = n;
    return k;
}

fn address_of(n: u8) [20]u8 {
    return consensus.signature.address_from_private(key(n)).?.bytes;
}

const Fixture = struct {
    db: StateDb,
    executor: Executor,

    fn init(fixture: *Fixture) !void {
        try fixture.init_with(spec);
    }

    fn init_with(fixture: *Fixture, chain_spec: *const chainspec.ChainSpec) !void {
        fixture.db = try StateDb.init(testing.allocator, .{
            .trie = .{ .accounts_max = 256, .account_nodes_max = 4096, .storage_nodes_max = 4096 },
            .code_bytes_max = 1 << 16,
            .codes_max = 64,
        });
        errdefer fixture.db.deinit(testing.allocator);
        fixture.executor = try Executor.init(testing.allocator, chain_spec, &fixture.db, .{
            .scratch_bytes = 1 << 20,
            .transactions_max = 64,
            .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
            .limits = .{
                .accounts_max = 256,
                .slots_max = 1024,
                .transient_slots_max = 64,
                .journal_entries_max = 4096,
                .logs_max = 64,
                .log_data_bytes_max = 4096,
                .code_bytes_max = 1 << 16,
            },
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.executor.deinit(testing.allocator);
        fixture.db.deinit(testing.allocator);
    }
};

fn transfer(buffer: []u8, from: u8, nonce: u64, to: [20]u8, value: u256, tip: u128) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = tip,
        .max_fee_per_gas = 100,
        .gas_limit = 21_000,
        .to = .{ .call = .{ .bytes = to } },
        .value = value,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, key(from));
    return envelope.encode_to(buffer);
}

fn block_env(number: u64) executor_module.BlockEnv {
    return .{
        .number = number,
        .timestamp = number * 12,
        .beneficiary = @splat(0xcb),
        .gas_limit = 30_000_000,
        .base_fee = 10,
        .prev_randao = @splat(0),
        .parent_hash = @splat(0),
        .parent_beacon_block_root = @splat(0),
        .excess_blob_gas = 0,
    };
}

const eth: u256 = 1_000_000_000_000_000_000;

test "executor: transfer pays value, base fee burn and tip" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try f.db.put_account(address_of(1), eth, 0, &.{});
    var buffer: [256]u8 = undefined;
    const to: [20]u8 = @splat(0x22);
    const raw = try transfer(&buffer, 1, 0, to, 1000, 3);
    const out = try f.executor.execute_block(&block_env(1), &.{raw}, &.{});
    try testing.expectEqual(@as(u64, 21_000), out.gas_used);
    try testing.expect(out.receipts[0].status);
    try testing.expectEqual(@as(u64, 21_000), out.receipts[0].cumulative_gas_used);
    const sender = f.db.get_account(address_of(1)).?;
    try testing.expectEqual(eth - 1000 - 21_000 * 13, sender.balance);
    try testing.expectEqual(@as(u64, 1), sender.nonce);
    try testing.expectEqual(@as(u256, 1000), f.db.get_account(to).?.balance);
    try testing.expectEqual(@as(u256, 21_000 * 3), f.db.get_account(@splat(0xcb)).?.balance);
    try testing.expectEqual(@as(usize, 0), out.requests.len);
    try testing.expectEqualSlices(u8, &out.state_root, &(try f.db.root()));
}

test "executor: invalid transaction leaves state untouched" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try f.db.put_account(address_of(1), eth, 0, &.{});
    const before = try f.db.root();
    var a: [256]u8 = undefined;
    var b: [256]u8 = undefined;
    const ok = try transfer(&a, 1, 0, @splat(0x22), 1, 1);
    const bad_nonce = try transfer(&b, 1, 5, @splat(0x22), 1, 1);
    const result = f.executor.execute_block(&block_env(1), &.{ ok, bad_nonce }, null);
    try testing.expectError(error.InvalidTransaction, result);
    try testing.expectEqual(@as(?u32, 1), f.executor.invalid_index);
    try testing.expectEqualSlices(u8, &before, &(try f.db.root()));
    // The executor is reusable after a failed block.
    _ = try f.executor.execute_block(&block_env(1), &.{ok}, null);
}

test "executor: logs, bloom and receipts root" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const emitter: [20]u8 = @splat(0x44);
    // PUSH1 0x2a PUSH1 0 MSTORE8 PUSH1 0xbe PUSH1 1 PUSH1 0 LOG1 STOP
    const code = [_]u8{ 0x60, 0x2a, 0x60, 0x00, 0x53, 0x60, 0xbe } ++
        [_]u8{ 0x60, 0x01, 0x60, 0x00, 0xa1, 0x00 };
    try f.db.put_account(emitter, 0, 1, &code);
    try f.db.put_account(address_of(1), eth, 0, &.{});
    const tx: consensus.Eip1559 = .{
        .chain_id = spec.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 100,
        .gas_limit = 100_000,
        .to = .{ .call = .{ .bytes = emitter } },
        .value = 0,
        .input = &.{},
        .access_list = .empty,
    };
    var buffer: [256]u8 = undefined;
    const raw = (try consensus.tx.sign(tx, key(1))).encode_to(&buffer);
    const out = try f.executor.execute_block(&block_env(1), &.{raw}, null);
    try testing.expectEqual(@as(u32, 1), out.receipts[0].logs.count);
    var it = out.receipts[0].logs.iterator();
    const log = it.next().?;
    try testing.expectEqualSlices(u8, &emitter, &log.address.bytes);
    try testing.expectEqualSlices(u8, &.{0x2a}, log.data);
    try testing.expectEqual(@as(u8, 0xbe), log.topics.get(0).bytes[31]);
    try testing.expect(!out.logs_bloom.eql(primitives.Bloom.zero));
    try testing.expect(!std.mem.eql(u8, &out.receipts_root, &primitives.empty_root_hash.bytes));
}

test "executor: withdrawals credit gwei" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const to: primitives.Address = .{ .bytes = @splat(0x77) };
    const withdrawals = [_]@import("../payload/root.zig").Withdrawal{
        .{ .index = 0, .validator_index = 1, .address = to, .amount_gwei = 5 },
        .{
            .index = 1,
            .validator_index = 1,
            .address = .{ .bytes = @splat(0x78) },
            .amount_gwei = 0,
        },
    };
    _ = try f.executor.execute_block(&block_env(1), &.{}, &withdrawals);
    try testing.expectEqual(@as(u256, 5_000_000_000), f.db.get_account(to.bytes).?.balance);
    try testing.expect(f.db.get_account(@splat(0x78)) == null);
}

test "executor: simulate runs a call without committing" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const target: [20]u8 = @splat(0x55);
    // PUSH1 0x2a PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
    const code = [_]u8{ 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    try f.db.put_account(target, 0, 1, &code);
    const before = try f.db.root();
    const result = try f.executor.simulate(&block_env(1), .{ .to = target, .value = 0 });
    try testing.expect(result.executed.success);
    try testing.expectEqual(@as(u8, 0x2a), result.executed.output[31]);
    try testing.expect(result.executed.gas_used > 21_000);
    try testing.expectEqualSlices(u8, &before, &(try f.db.root()));
    const transfer_result = try f.executor.simulate(&block_env(1), .{ .to = @splat(0x09) });
    try testing.expect(transfer_result.executed.success);
    try testing.expectEqual(@as(u64, 21_000), transfer_result.executed.gas_used);
    const poor = try f.executor.simulate(&block_env(1), .{ .to = target, .value = 1 });
    try testing.expect(poor == .invalid);
}

/// Random transfer blocks checked against a balance/nonce model.
fn random_blocks(prng: *Prng) !void {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const senders = 4;
    var balances: [senders]u256 = undefined;
    var nonces: [senders]u64 = @splat(0);
    for (0..senders) |i| {
        balances[i] = eth;
        try f.db.put_account(address_of(@intCast(i + 1)), eth, 0, &.{});
    }
    var buffers: [8][256]u8 = undefined;
    var txs: [8][]const u8 = undefined;
    for (1..6) |number| {
        const count = prng.below(8);
        var expected = balances;
        var expected_nonces = nonces;
        var valid = true;
        for (0..count) |i| {
            const from = prng.below(senders);
            const nonce_skew = if (prng.chance(1, 10)) prng.range(1, 3) else 0;
            const value = prng.below(1000);
            const target = address_of(@intCast(prng.below(senders) + 1));
            const nonce = expected_nonces[from] + nonce_skew;
            txs[i] = try transfer(&buffers[i], @intCast(from + 1), nonce, target, value, 2);
            if (nonce_skew != 0) valid = false;
            expected[from] -= value + 21_000 * 12;
            expected_nonces[from] += 1;
            const to_index = for (0..senders) |s| {
                if (std.mem.eql(u8, &address_of(@intCast(s + 1)), &target)) break s;
            } else unreachable;
            expected[to_index] += value;
        }
        const result = f.executor.execute_block(&block_env(number), txs[0..count], null);
        if (!valid) {
            try testing.expectError(error.InvalidTransaction, result);
            continue;
        }
        _ = try result;
        balances = expected;
        nonces = expected_nonces;
        for (0..senders) |s| {
            const account = f.db.get_account(address_of(@intCast(s + 1))).?;
            try testing.expectEqual(balances[s], account.balance);
            try testing.expectEqual(nonces[s], account.nonce);
        }
    }
}

test "executor: seeded fuzz transfer blocks match model" {
    var prng = Prng.init(0xe7ec);
    for (0..4) |_| try random_blocks(&prng);
}

fn fuzz_executor(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try random_blocks(&prng);
}

test "executor: fuzz" {
    try testing.fuzz({}, fuzz_executor, .{});
}

test "executor: L2 deposit mints, records its nonce, and fees go to the vaults" {
    const l2 = &chainspec.ChainSpec.presets.base_devnet;
    var f: Fixture = undefined;
    try f.init_with(l2);
    defer f.deinit();
    try f.db.put_account(address_of(1), eth, 0, &.{});
    const depositor: [20]u8 = @splat(0xde);
    const deposit: consensus.Envelope = .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(1) },
        .from = .{ .bytes = depositor },
        .to = .{ .call = .{ .bytes = @splat(0x33) } },
        .mint = 5000,
        .value = 1000,
        .gas_limit = 100_000,
        .is_system_transaction = false,
        .input = &.{},
    } };
    var deposit_buffer: [256]u8 = undefined;
    const deposit_raw = deposit.encode_to(&deposit_buffer);
    const tx: consensus.Eip1559 = .{
        .chain_id = l2.chain_id,
        .nonce = 0,
        .max_priority_fee_per_gas = 3,
        .max_fee_per_gas = 100,
        .gas_limit = 21_000,
        .to = .{ .call = .{ .bytes = @splat(0x22) } },
        .value = 1,
        .input = &.{},
        .access_list = .empty,
    };
    var tx_buffer: [256]u8 = undefined;
    const tx_raw = (try consensus.tx.sign(tx, key(1))).encode_to(&tx_buffer);
    const out = try f.executor.execute_block(&block_env(1), &.{ deposit_raw, tx_raw }, &.{});
    try testing.expectEqual(@as(usize, 2), out.receipts.len);
    const receipt = out.receipts[0];
    try testing.expectEqual(consensus.TxType.deposit, receipt.tx_type);
    try testing.expectEqual(@as(?u64, 0), receipt.deposit_nonce);
    try testing.expectEqual(@as(?u64, 1), receipt.deposit_receipt_version);
    try testing.expectEqual(@as(u256, 4000), f.db.get_account(depositor).?.balance);
    try testing.expectEqual(@as(u64, 1), f.db.get_account(depositor).?.nonce);
    try testing.expectEqual(@as(u256, 1000), f.db.get_account(@splat(0x33)).?.balance);
    // Base fee goes to the base fee vault (not burnt); the tip to the fee recipient.
    const vault = evm.op.base_fee_vault;
    try testing.expectEqual(@as(u256, 21_000 * 10), f.db.get_account(vault).?.balance);
    try testing.expectEqual(@as(u256, 21_000 * 3), f.db.get_account(@splat(0xcb)).?.balance);
    try testing.expectEqual(@as(u256, 21_000 * 3), out.fees);
    try testing.expectEqual(@as(usize, 0), out.requests.len);
    // An L1 executor rejects the same deposit.
    var l1: Fixture = undefined;
    try l1.init();
    defer l1.deinit();
    const rejected = l1.executor.execute_block(&block_env(1), &.{deposit_raw}, &.{});
    try testing.expectError(error.TxTypeNotSupported, rejected);
}

const eip8130 = consensus.tx.eip8130;

/// Base devnet with every upgrade through Everest active at genesis.
const everest_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    result.upgrades = @splat(0);
    break :blk result;
};

/// slot[0] += 1 (PUSH0 SLOAD PUSH1 1 ADD PUSH0 SSTORE STOP).
const counter_code = [_]u8{ 0x5f, 0x54, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x00 };

const Eip8130Built = struct {
    sender_auth: [65]u8,
    phase_buffer: [256]u8,
    calls_buffer: [512]u8,
    envelope_buffer: [1024]u8,

    /// One phase calling `target` once, signed by `key(from)`.
    fn build(built: *Eip8130Built, from: u8, target: [20]u8, gas_limit: u64) ![]const u8 {
        const calls = [_]eip8130.Call{.{ .to = .init(target), .value = 0, .data = &.{} }};
        const phase = eip8130.Phase.build(&built.phase_buffer, &calls);
        var tx: eip8130.TxEip8130 = .{
            .chain_id = everest_spec.chain_id,
            .gas_limit = gas_limit,
            .max_fee_per_gas = 100,
            .max_priority_fee_per_gas = 3,
        };
        tx.calls = eip8130.Calls.build(&built.calls_buffer, &.{phase});
        built.sender_auth = try eip8130.sign_sender(tx, key(from));
        const signed: eip8130.Signed = .{ .tx = tx, .sender_auth = &built.sender_auth };
        return signed.encode_to(&built.envelope_buffer);
    }
};

test "executor: EIP-8130 transactions run their phases from Everest and report them" {
    var f: Fixture = undefined;
    try f.init_with(&everest_spec);
    defer f.deinit();
    try f.db.put_account(address_of(1), eth, 0, &.{});
    const counter: [20]u8 = @splat(0x44);
    try f.db.put_account(counter, 0, 1, &counter_code);
    var built: Eip8130Built = undefined;
    const raw = try built.build(1, counter, 300_000);
    try testing.expectEqual(@as(u8, 0x79), raw[0]);
    const out = try f.executor.execute_block(&block_env(1), &.{raw}, &.{});
    try testing.expectEqual(@as(usize, 1), out.receipts.len);
    const receipt = out.receipts[0];
    try testing.expectEqual(consensus.TxType.eip8130, receipt.tx_type);
    try testing.expect(receipt.status);
    try testing.expectEqual(@as(?u64, 1), receipt.committed_phases);
    try receipt.validate_committed_phases(1);
    try testing.expectEqual(@as(u256, 1), f.db.get_storage(counter, 0));
    try testing.expect(f.db.get_account(address_of(1)).?.balance < eth);
    try testing.expect(out.fees > 0);
    // An unfunded sender is rejected before any phase runs, leaving the state alone.
    var unfunded: Eip8130Built = undefined;
    const poor = try unfunded.build(2, counter, 300_000);
    const refused = f.executor.execute_block(&block_env(2), &.{poor}, &.{});
    try testing.expectError(error.InvalidTransaction, refused);
    try testing.expectEqual(@as(u256, 1), f.db.get_storage(counter, 0));
    // Before Everest the type is not supported.
    var early: Fixture = undefined;
    try early.init_with(&chainspec.ChainSpec.presets.base_devnet);
    defer early.deinit();
    try early.db.put_account(address_of(1), eth, 0, &.{});
    const rejected = early.executor.execute_block(&block_env(1), &.{raw}, &.{});
    try testing.expectError(error.TxTypeNotSupported, rejected);
}

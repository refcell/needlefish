//! End-to-end EIP-8130 transaction execution through `transaction.transact`.
const std = @import("std");
const testing = std.testing;

const primitives = @import("primitives.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const op_stack = @import("op.zig");
const op = @import("opcode.zig");
const native = @import("native.zig");
const nonce = @import("eip8130_nonce.zig");
const execute = @import("eip8130_execute.zig");
const Harness = @import("evm_test.zig").Harness;
const eip8130 = @import("../../common/consensus/eip8130.zig");
const common = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

const chain_id: u64 = 8453;
const base_fee: u256 = 7;
const coinbase = primitives.address_from_int(0xc01b);
const store_target = primitives.address_from_int(0x5107e);
const revert_target = primitives.address_from_int(0x2e7e27);
const funding: u256 = 1 << 60;

/// Hardhat account 0, the publicly known devnet key.
const dev_key = blk: {
    var bytes: [32]u8 = undefined;
    const text = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    break :blk bytes;
};
const dev_address = blk: {
    var bytes: Address = undefined;
    _ = std.fmt.hexToBytes(&bytes, "f39fd6e51aad88f6f4ce6ab8827279cfffb92266") catch unreachable;
    break :blk bytes;
};

/// Hardhat account 1, the publicly known devnet key.
const payer_key = blk: {
    var bytes: [32]u8 = undefined;
    const text = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    break :blk bytes;
};
const payer_address = blk: {
    var bytes: Address = undefined;
    _ = std.fmt.hexToBytes(&bytes, "70997970c51812dc3a010c7d01b50e0d17dc79c8") catch unreachable;
    break :blk bytes;
};

/// slot[calldata word 0] += 1.
const store_code = [_]u8{
    op.PUSH1, 0,        op.CALLDATALOAD, op.DUP1, op.SLOAD, op.PUSH1, 1,
    op.ADD,   op.SWAP1, op.SSTORE,       op.STOP,
};
const revert_code = [_]u8{ op.PUSH1, 0, op.PUSH1, 0, op.REVERT };

const Built = struct {
    signed: eip8130.Signed,
    sender_auth: [65]u8,
    payer_auth: [65]u8,
    envelope_buffer: [1024]u8,
    envelope: []const u8,
    calls_buffer: [512]u8,
    phase_buffers: [4][256]u8,

    /// `phases[i]` lists call targets; each call passes calldata word `i`.
    fn init(built: *Built, base: eip8130.TxEip8130, phases: []const []const Address) !void {
        var phase_lists: [4]eip8130.Phase = undefined;
        var datas: [4][32]u8 = undefined;
        for (phases, 0..) |targets, index| {
            datas[index] = @splat(0);
            datas[index][31] = @intCast(index);
            var calls: [4]eip8130.Call = undefined;
            for (targets, 0..) |target, call_index| {
                calls[call_index] = .{ .to = .init(target), .value = 0, .data = &datas[index] };
            }
            phase_lists[index] = eip8130.Phase.build(
                &built.phase_buffers[index],
                calls[0..targets.len],
            );
        }
        var tx = base;
        tx.calls = eip8130.Calls.build(&built.calls_buffer, phase_lists[0..phases.len]);
        built.sender_auth = try eip8130.sign_sender(tx, dev_key);
        built.signed = .{ .tx = tx, .sender_auth = &built.sender_auth };
        built.envelope = built.signed.encode_to(&built.envelope_buffer);
    }

    /// re-sign with `key` as the open payer (`tx.payer` must be the open marker).
    fn sponsor(built: *Built, key: [32]u8) !void {
        const sender = common.Address.init(dev_address);
        built.payer_auth = try eip8130.sign_payer(built.signed.tx, sender, key);
        built.signed.payer_auth = &built.payer_auth;
        built.envelope = built.signed.encode_to(&built.envelope_buffer);
    }

    fn env(built: *const Built) transaction.TxEnv {
        return .{
            .tx_type = .eip8130,
            .caller = dev_address,
            .gas_limit = built.signed.tx.gas_limit,
            .envelope = built.envelope,
            .eip8130 = &built.signed,
        };
    }
};

fn base_tx() eip8130.TxEip8130 {
    return .{
        .chain_id = chain_id,
        .gas_limit = 300_000,
        .max_fee_per_gas = 10,
        .max_priority_fee_per_gas = 2,
    };
}

fn setup(h: *Harness) !void {
    try h.init(testing.allocator);
    h.evm.config.chain_id = chain_id;
    h.evm.block.op = .{ .upgrade = .everest };
    h.evm.block.base_fee = base_fee;
    h.evm.block.coinbase = coinbase;
    h.evm.block.timestamp = 1_000;
    try h.database.put_account(dev_address, funding, 0, &.{});
    try h.database.put_account(store_target, 0, 1, &store_code);
    try h.database.put_account(revert_target, 0, 1, &revert_code);
}

fn balance(h: *Harness, address: Address) !u256 {
    return (try h.state.load(address)).info.balance;
}

/// Every wei the payer lost went to a fee recipient.
fn expect_fees_conserved(h: *Harness, executed: transaction.Executed) !void {
    const paid = funding - try balance(h, dev_address);
    const received = try balance(h, coinbase) + try balance(h, op_stack.base_fee_vault) +
        try balance(h, op_stack.l1_fee_vault) + try balance(h, op_stack.operator_fee_vault);
    try testing.expectEqual(paid, received);
    try testing.expectEqual(@as(u256, executed.gas_used) * base_fee, try balance(
        h,
        op_stack.base_fee_vault,
    ));
    // Effective price min(10, 7 + 2) = 9: the tip is 2 per gas.
    try testing.expectEqual(@as(u256, executed.gas_used) * 2, try balance(h, coinbase));
}

test "eip8130 execute: a self-paid EOA transaction runs its phases and pays fees" {
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    var built: Built = undefined;
    const phases = [_][]const Address{ &.{ store_target, store_target }, &.{store_target} };
    try built.init(base_tx(), &phases);
    const env = built.env();
    const executed = (try transaction.transact(&h.evm, .osaka, &env)).executed;
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u64, 2), executed.committed_phases);
    try testing.expectEqual(@as(u256, 2), try h.storage(store_target, 0));
    try testing.expectEqual(@as(u256, 1), try h.storage(store_target, 1));
    try testing.expectEqual(@as(u64, 1), (try h.state.load(dev_address)).info.nonce);
    try testing.expect(executed.gas_used > 2 * 22_100);
    try testing.expect(executed.gas_used < built.signed.tx.gas_limit);
    try expect_fees_conserved(&h, executed);
}

test "eip8130 execute: an open payer sponsors the fee" {
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    try h.database.put_account(dev_address, 0, 0, &.{});
    try h.database.put_account(payer_address, funding, 0, &.{});
    var built: Built = undefined;
    const phases = [_][]const Address{&.{store_target}};
    var sponsored = base_tx();
    sponsored.payer = eip8130.open_payer;
    try built.init(sponsored, &phases);
    // Without a payer signature the sender would have to pay, and cannot.
    try testing.expectError(error.PayerRecovery, execute.execute(.osaka, &h.evm, &built.env()));
    try built.sponsor(payer_key);
    const env = built.env();
    const executed = (try transaction.transact(&h.evm, .osaka, &env)).executed;
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u256, 1), try h.storage(store_target, 0));
    try testing.expectEqual(@as(u256, 0), try balance(&h, dev_address));
    try testing.expectEqual(@as(u64, 1), (try h.state.load(dev_address)).info.nonce);
    const paid = funding - try balance(&h, payer_address);
    try testing.expectEqual(@as(u256, executed.gas_used) * 9, paid);
    try testing.expectEqual(@as(u64, 0), (try h.state.load(payer_address)).info.nonce);
}

test "eip8130 execute: a reverting phase rolls back alone and is still charged" {
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    var built: Built = undefined;
    const phases = [_][]const Address{
        &.{store_target},
        &.{ store_target, revert_target },
        &.{store_target},
    };
    try built.init(base_tx(), &phases);
    const env = built.env();
    const executed = (try transaction.transact(&h.evm, .osaka, &env)).executed;
    try testing.expectEqual(evm_module.Status.revert, executed.status);
    try testing.expectEqual(@as(u64, 1), executed.committed_phases);
    try testing.expectEqual(@as(u256, 1), try h.storage(store_target, 0));
    try testing.expectEqual(@as(u256, 0), try h.storage(store_target, 1));
    try testing.expectEqual(@as(u256, 0), try h.storage(store_target, 2));
    try testing.expectEqual(@as(u64, 1), (try h.state.load(dev_address)).info.nonce);
    try expect_fees_conserved(&h, executed);
}

test "eip8130 execute: rejections discard every state change" {
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    var built: Built = undefined;
    const phases = [_][]const Address{&.{store_target}};
    var foreign = base_tx();
    foreign.chain_id = 1;
    try built.init(foreign, &phases);
    try expect_rejected(&h, &built, error.ChainIdMismatch);

    try built.init(base_tx(), &phases);
    h.evm.block.op = .{ .upgrade = .denim };
    try expect_rejected(&h, &built, error.NotActive);
    h.evm.block.op = .{ .upgrade = .everest };

    var future = base_tx();
    future.nonce_sequence = 1;
    try built.init(future, &phases);
    try expect_rejected(&h, &built, error.TooHigh);

    var greedy = base_tx();
    greedy.max_fee_per_gas = std.math.maxInt(u64);
    try built.init(greedy, &phases);
    try expect_rejected(&h, &built, error.InsufficientBalance);

    var starved = base_tx();
    starved.gas_limit = 1_000;
    try built.init(starved, &phases);
    try expect_rejected(&h, &built, error.GasLimitBelowFloor);
}

fn expect_rejected(h: *Harness, built: *const Built, expected: execute.Error) !void {
    const env = built.env();
    try testing.expectError(expected, execute.execute(.osaka, &h.evm, &env));
    const result = try transaction.transact(&h.evm, .osaka, &env);
    try testing.expectEqual(transaction.Invalid.eip8130_rejected, result.invalid);
    try testing.expectEqual(funding, try balance(h, dev_address));
    try testing.expectEqual(@as(u64, 0), (try h.state.load(dev_address)).info.nonce);
    try testing.expectEqual(@as(u256, 0), try h.storage(store_target, 0));
}

test "eip8130 execute: 2D nonce channels advance and reject replays" {
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    var built: Built = undefined;
    const phases = [_][]const Address{&.{store_target}};
    var keyed = base_tx();
    keyed.nonce_key = 5;
    try built.init(keyed, &phases);
    const env = built.env();
    const executed = (try transaction.transact(&h.evm, .osaka, &env)).executed;
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u64, 0), (try h.state.load(dev_address)).info.nonce);
    const store = nonce.Store{ .state = &h.state };
    try testing.expectEqual(@as(u64, 1), try store.get_nonce(dev_address, 5));
    try testing.expectError(error.TooLow, execute.execute(.osaka, &h.evm, &env));
    // The context getters saw the sender during the calls; transient slots reset after.
    try testing.expectEqual(@as(u256, 0), h.state.transient_load(native.tx_context_address, 0));
}

const fuzz = @import("../../testing/fuzz.zig");

test "eip8130 execute: fuzz phases, gas, fees, and nonces" {
    try fuzz.run_bytes({}, fuzz_execute, .{ .seed = 0x8130_e8ec, .iterations = 48 });
}

/// Reads bounded choices from the fuzz input; exhausted input reads as zero.
const Cursor = struct {
    input: []const u8,
    index: usize = 0,

    fn byte(cursor: *Cursor) u8 {
        if (cursor.index >= cursor.input.len) return 0;
        defer cursor.index += 1;
        return cursor.input[cursor.index];
    }

    fn below(cursor: *Cursor, limit: u8) u8 {
        std.debug.assert(limit > 0);
        return cursor.byte() % limit;
    }
};

/// Invariants: a rejection changes nothing; an included transaction moves exactly the
/// payer's loss to the fee recipients, bills at most `gas_limit` plus the payer floor,
/// and commits a prefix of its phases (all of them exactly when it succeeds).
fn fuzz_execute(_: void, input: []const u8) anyerror!void {
    var cursor = Cursor{ .input = input };
    var h: Harness = undefined;
    try setup(&h);
    defer h.deinit(testing.allocator);
    if (cursor.below(8) == 7) h.evm.block.op = .{ .upgrade = .denim };
    const targets = [_]Address{ store_target, revert_target, primitives.address_from_int(0xe0) };
    var phase_targets: [3][3]Address = undefined;
    var phases: [3][]const Address = undefined;
    const phase_count = 3 - cursor.below(4);
    for (0..phase_count) |index| {
        const call_count = 3 - cursor.below(4);
        for (0..call_count) |call| phase_targets[index][call] = targets[cursor.below(3)];
        phases[index] = phase_targets[index][0..call_count];
    }
    var tx = base_tx();
    // Zero bytes (exhausted input) map to a valid transaction.
    tx.gas_limit = 400_000 - @as(u64, cursor.byte()) * 1_500;
    tx.max_fee_per_gas = 20 - cursor.below(16);
    tx.max_priority_fee_per_gas = cursor.below(6);
    tx.nonce_key = cursor.below(3);
    tx.nonce_sequence = @intFromBool(cursor.below(8) == 7);
    var built: Built = undefined;
    try built.init(tx, phases[0..phase_count]);
    const env = built.env();
    const result = try transaction.transact(&h.evm, .osaka, &env);
    switch (result) {
        .invalid => |reason| {
            try testing.expectEqual(transaction.Invalid.eip8130_rejected, reason);
            try testing.expectEqual(funding, try balance(&h, dev_address));
            try testing.expectEqual(@as(u64, 0), (try h.state.load(dev_address)).info.nonce);
        },
        .executed => |executed| {
            const paid = funding - try balance(&h, dev_address);
            const received = try balance(&h, coinbase) +
                try balance(&h, op_stack.base_fee_vault) +
                try balance(&h, op_stack.l1_fee_vault) +
                try balance(&h, op_stack.operator_fee_vault);
            try testing.expectEqual(paid, received);
            try testing.expect(executed.gas_used <= tx.gas_limit + 100_000);
            try testing.expect(executed.committed_phases <= phase_count);
            const all = executed.committed_phases == phase_count;
            try testing.expectEqual(all, executed.status == .success);
        },
    }
}

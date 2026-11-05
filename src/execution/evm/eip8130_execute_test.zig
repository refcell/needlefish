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

/// slot[calldata word 0] += 1.
const store_code = [_]u8{
    op.PUSH1, 0,        op.CALLDATALOAD, op.DUP1, op.SLOAD, op.PUSH1, 1,
    op.ADD,   op.SWAP1, op.SSTORE,       op.STOP,
};
const revert_code = [_]u8{ op.PUSH1, 0, op.PUSH1, 0, op.REVERT };

const Built = struct {
    signed: eip8130.Signed,
    sender_auth: [65]u8,
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

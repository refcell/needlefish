//! OP Stack / Base transaction semantics: deposits and fee vault routing.

const std = @import("std");
const testing = std.testing;
const primitives = @import("primitives.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const op_stack = @import("op.zig");
const Harness = @import("evm_test.zig").Harness;
const Address = primitives.Address;

const depositor = primitives.address_from_int(0xde9051);
const sender_address = primitives.address_from_int(0x5e4de2);
const target = primitives.address_from_int(0x7a9e7);
const coinbase = primitives.address_from_int(0xc0ffee);

/// SSTORE(0, 1) then STOP.
const store_code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 };
/// SSTORE(0, 1) then INVALID: an exceptional halt after a state change.
const halt_code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0xfe };

fn balance(h: *Harness, address: Address) !u256 {
    return (try h.state.load(address)).info.balance;
}

fn deposit(to: Address, gas_limit: u64) transaction.TxEnv {
    return .{
        .tx_type = .deposit,
        .caller = depositor,
        .gas_limit = gas_limit,
        .to = to,
        .value = 5,
        .mint = 1_000,
    };
}

test "op: deposit mints, skips fees, and refunds normally" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .isthmus };
    h.evm.block.base_fee = 7;
    h.evm.block.coinbase = coinbase;
    try h.database.put_account(target, 0, 1, &store_code);
    const tx = deposit(target, 100_000);
    const executed = (try transaction.transact(&h.evm, .prague, &tx)).executed;
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u64, 21_000 + 22_106), executed.gas_used);
    try testing.expectEqual(@as(u256, 995), try balance(&h, depositor));
    try testing.expectEqual(@as(u256, 5), try balance(&h, target));
    try testing.expectEqual(@as(u64, 1), (try h.state.load(depositor)).info.nonce);
    try testing.expectEqual(@as(u256, 0), try balance(&h, coinbase));
    try testing.expectEqual(@as(u256, 0), try balance(&h, op_stack.base_fee_vault));
    try testing.expectEqual(@as(u256, 1), try h.storage(target, 0));
}

test "op: halted deposit keeps mint and nonce, consumes the gas limit" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .jovian };
    try h.database.put_account(target, 0, 1, &halt_code);
    try h.database.put_account(depositor, 10, 4, &.{});
    const tx = deposit(target, 100_000);
    const executed = (try transaction.transact(&h.evm, .prague, &tx)).executed;
    try testing.expectEqual(evm_module.Status.halt, executed.status);
    try testing.expectEqual(@as(u64, 100_000), executed.gas_used);
    try testing.expectEqual(@as(usize, 0), executed.logs.len);
    try testing.expectEqual(@as(u256, 1_010), try balance(&h, depositor));
    try testing.expectEqual(@as(u64, 5), (try h.state.load(depositor)).info.nonce);
    try testing.expectEqual(@as(u256, 0), try balance(&h, target));
    try testing.expectEqual(@as(u256, 0), try h.storage(target, 0));

    // Below intrinsic gas is a failed deposit too, not an invalid transaction.
    const starved = deposit(target, 20_000);
    const failed = (try transaction.transact(&h.evm, .prague, &starved)).executed;
    try testing.expectEqual(@as(u64, 20_000), failed.gas_used);
    try testing.expectEqual(@as(u256, 2_010), try balance(&h, depositor));
    try testing.expectEqual(@as(u64, 6), (try h.state.load(depositor)).info.nonce);
}

test "op: deposits need OP rules and reject system transactions since Regolith" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    var tx = deposit(target, 100_000);
    const plain = try transaction.transact(&h.evm, .prague, &tx);
    try testing.expectEqual(transaction.Invalid.type_not_supported, plain.invalid);
    h.evm.block.op = .{ .upgrade = .regolith };
    tx.is_system_transaction = true;
    const system = try transaction.transact(&h.evm, .shanghai, &tx);
    try testing.expectEqual(transaction.Invalid.deposit_system_transaction, system.invalid);
    try testing.expectEqual(@as(u256, 0), try balance(&h, depositor));
}

fn put_l1_block(h: *Harness) !void {
    const l1 = op_stack.l1_block_address;
    try h.database.put_account(l1, 0, 1, &.{0x00});
    try h.database.put_storage(l1, op_stack.slot_l1_base_fee, 1_000);
    try h.database.put_storage(l1, op_stack.slot_blob_base_fee, 10);
    const scalars = (@as(u256, 2_000) << (8 * 12)) | (@as(u256, 3_000) << (8 * 8));
    try h.database.put_storage(l1, op_stack.slot_ecotone_scalars, scalars);
    // Operator fee scalar 500_000 (offset 20), constant 77 (offset 24).
    const operator = (@as(u256, 500_000) << (8 * 8)) | 77;
    try h.database.put_storage(l1, op_stack.slot_operator_fee, operator);
}

test "op: L1 fee, base fee, and operator fee go to their vaults" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try put_l1_block(&h);
    h.evm.block.op = .{ .upgrade = .isthmus };
    h.evm.block.base_fee = 7;
    h.evm.block.coinbase = coinbase;
    const initial: u256 = 1_000_000_000_000;
    try h.database.put_account(sender_address, initial, 0, &.{});
    const envelope = [_]u8{ 0x02, 0xf8, 0x00, 0x11, 0x22, 0x00, 0x33, 0x44, 0x55, 0x00, 0x66 };
    const tx = transaction.TxEnv{
        .tx_type = .eip1559,
        .caller = sender_address,
        .gas_limit = 60_000,
        .gas_price = 10,
        .gas_priority_fee = 2,
        .to = target,
        .value = 1_000,
        .envelope = &envelope,
    };
    const executed = (try transaction.transact(&h.evm, .prague, &tx)).executed;
    try testing.expectEqual(@as(u64, 21_000), executed.gas_used);

    const params = try op_stack.load_params(&h.state, .isthmus);
    try testing.expectEqual(@as(u256, 2_000), params.l1_base_fee_scalar);
    try testing.expectEqual(@as(?u256, 3_000), params.l1_blob_base_fee_scalar);
    const l1_fee = params.tx_l1_cost(&envelope, .isthmus);
    try testing.expect(l1_fee > 0);
    const operator_fee: u256 = 21_000 * 500_000 / 1_000_000 + 77;
    try testing.expectEqual(l1_fee, try balance(&h, op_stack.l1_fee_vault));
    try testing.expectEqual(@as(u256, 21_000 * 7), try balance(&h, op_stack.base_fee_vault));
    try testing.expectEqual(operator_fee, try balance(&h, op_stack.operator_fee_vault));
    try testing.expectEqual(@as(u256, 21_000 * 2), try balance(&h, coinbase));
    const spent = 1_000 + 21_000 * 9 + l1_fee + operator_fee;
    try testing.expectEqual(initial - spent, try balance(&h, sender_address));
}

test "op: L1 and operator fees count toward the balance check" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try put_l1_block(&h);
    h.evm.block.op = .{ .upgrade = .isthmus };
    const gas_cost: u256 = 21_000 * 10;
    try h.database.put_account(sender_address, gas_cost, 0, &.{});
    const envelope = [_]u8{ 0x02, 0x01, 0x02, 0x03 };
    const tx = transaction.TxEnv{
        .caller = sender_address,
        .gas_limit = 21_000,
        .gas_price = 10,
        .to = target,
        .envelope = &envelope,
    };
    const result = try transaction.transact(&h.evm, .prague, &tx);
    try testing.expectEqual(transaction.Invalid.insufficient_funds, result.invalid);
    try testing.expectEqual(gas_cost, try balance(&h, sender_address));
}

test "op: Canyon and Everest state transitions" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try op_stack.apply_transition(&h.state, .canyon_create2_deployer);
    const deployer = try h.state.load(op_stack.create2_deployer);
    const code = try h.state.code(deployer);
    try testing.expectEqual(@as(usize, 1584), code.len);
    const keccak = @import("../../common/crypto/root.zig").keccak256;
    const expected = primitives.hex_to_b256(
        "b0550b5b431e30d38000efb7107aaa0ade03d48a7198a140edda9d27134468b2",
    );
    try testing.expectEqualSlices(u8, &expected, &keccak(code));

    try op_stack.apply_transition(&h.state, .everest_nonce_manager);
    const manager = try h.state.load(op_stack.nonce_manager);
    try testing.expectEqualSlices(u8, &.{0xef}, try h.state.code(manager));
    // Existing code is kept.
    try h.database.put_account(op_stack.nonce_manager, 0, 0, &.{ 0x60, 0x00 });
    h.state.reset(h.database.interface());
    try op_stack.apply_transition(&h.state, .everest_nonce_manager);
    const kept = try h.state.load(op_stack.nonce_manager);
    try testing.expectEqualSlices(u8, &.{ 0x60, 0x00 }, try h.state.code(kept));
}

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

const native = @import("native.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn native_call(h: *Harness, to: Address, data: []const u8, value: u256) !transaction.Executed {
    return native_call_gas(h, to, data, value, 200_000);
}

fn native_call_gas(
    h: *Harness,
    to: Address,
    data: []const u8,
    value: u256,
    gas_limit: u64,
) !transaction.Executed {
    try h.database.put_account(sender_address, 1 << 60, 0, &.{});
    h.state.reset(h.database.interface());
    const tx = transaction.TxEnv{
        .caller = sender_address,
        .gas_limit = gas_limit,
        .to = to,
        .data = data,
        .value = value,
    };
    return (try transaction.transact(&h.evm, .osaka, &tx)).executed;
}

fn calldata_gas(data: []const u8) u64 {
    var total: u64 = 0;
    for (data) |byte| total += if (byte == 0) 4 else 16;
    return total;
}

test "op: TxContext falls back to tx.origin and charges 3 gas per word" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .cobalt };
    const data = native.selector_get_transaction_sender;
    const executed = try native_call(&h, native.tx_context_address, &data, 0);
    try testing.expectEqual(evm_module.Status.success, executed.status);
    var expected: [32]u8 = @splat(0);
    expected[12..32].* = sender_address;
    try testing.expectEqualSlices(u8, &expected, executed.output);
    // Execution (21067) is below the EIP-7623 floor of 21000 + 10 * 16 tokens.
    try testing.expectEqual(21_160, executed.gas_used);

    const paid = try native_call(&h, native.tx_context_address, &data, 1);
    try testing.expectEqual(evm_module.Status.revert, paid.status);
    try testing.expectEqualSlices(u8, &native.selector_non_payable, paid.output);
    const unknown = try native_call(&h, native.tx_context_address, &.{ 1, 2 }, 0);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, unknown.output);

    // Before Cobalt the address is an empty account.
    h.evm.block.op = .{ .upgrade = .jovian };
    const plain = try native_call(&h, native.tx_context_address, &data, 0);
    try testing.expectEqual(evm_module.Status.success, plain.status);
    try testing.expectEqual(@as(usize, 0), plain.output.len);
}

test "op: NonceManager getNonce reads the 2D nonce slot" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .cobalt };
    const account = primitives.address_from_int(0xacc0);
    try h.database.put_account(native.nonce_manager_address, 0, 1, &.{0xef});
    try h.database.put_storage(native.nonce_manager_address, native.nonce_slot(account, 7), 42);
    var data: [68]u8 = @splat(0);
    data[0..4].* = native.selector_get_nonce;
    data[16..36].* = account;
    data[67] = 7;
    const executed = try native_call(&h, native.nonce_manager_address, &data, 0);
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u8, 42), executed.output[31]);
    // 3 calldata words at 6 gas, one cold SLOAD; the account was warmed at tx start.
    try testing.expectEqual(21_000 + calldata_gas(&data) + 18 + 2_100, executed.gas_used);

    data[67] = 0;
    const protocol = try native_call(&h, native.nonce_manager_address, &data, 0);
    try testing.expectEqual(evm_module.Status.revert, protocol.status);
    const expected = native.selector_protocol_nonce_not_supported;
    try testing.expectEqualSlices(u8, &expected, protocol.output);
    data[5] = 1; // Dirty address word: a known selector with bad arguments.
    data[67] = 7;
    const dirty = try native_call(&h, native.nonce_manager_address, &data, 0);
    try testing.expectEqualSlices(u8, &native.selector_get_nonce, dirty.output);
}

test "op: native precompiles reject DELEGATECALL without using gas" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .cobalt };
    // DELEGATECALL(gas, TxContext, 0, 0, 0, 0); slot0 = success, slot1 = RETURNDATASIZE.
    const code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73 } ++
        native.tx_context_address ++
        [_]u8{ 0x5a, 0xf4, 0x60, 0x00, 0x55, 0x3d, 0x60, 0x01, 0x55, 0x00 };
    try h.database.put_account(target, 0, 1, &code);
    const executed = try native_call(&h, target, &.{}, 0);
    try testing.expectEqual(evm_module.Status.success, executed.status);
    try testing.expectEqual(@as(u256, 0), try h.storage(target, 0));
    try testing.expectEqual(@as(u256, 4), try h.storage(target, 1));
}

const native_selectors = [_][4]u8{
    native.selector_get_transaction_sender,
    native.selector_get_transaction_payer,
    native.selector_get_transaction_sender_actor_id,
    native.selector_get_nonce,
};

fn fuzz_native(h: *Harness, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    h.evm.block.op = .{ .upgrade = .cobalt };
    const to = if (prng.chance(1, 2)) native.tx_context_address else native.nonce_manager_address;
    var data: [100]u8 = undefined;
    prng.random().bytes(&data);
    data[0..4].* = native_selectors[prng.below(native_selectors.len)];
    if (prng.chance(3, 4)) @memset(data[4..16], 0); // Usually a clean address word.
    const length = prng.below(data.len + 1);
    const value: u256 = if (prng.chance(1, 8)) 1 else 0;
    // EIP-7623 floor (10 gas per token, a nonzero byte is 4 tokens) bounds intrinsic gas.
    const floor = 21_000 + calldata_gas(data[0..length]) * 10 / 4;
    const gas_limit = floor + prng.below(4_000);
    const executed = try native_call_gas(h, to, data[0..length], value, gas_limit);
    try testing.expect(executed.gas_used <= gas_limit);
    switch (executed.status) {
        .success => try testing.expectEqual(@as(usize, 32), executed.output.len),
        .revert => try testing.expect(executed.output.len == 0 or executed.output.len == 4),
        .halt => try testing.expectEqual(gas_limit, executed.gas_used),
    }
    const again = try native_call_gas(h, to, data[0..length], value, gas_limit);
    try testing.expectEqual(executed.status, again.status);
    try testing.expectEqual(executed.gas_used, again.gas_used);
}

test "op fuzz: native precompile calls keep gas and result invariants" {
    const h = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(h);
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try fuzz.run(h, fuzz_native, .{ .seed = 0x6e6174697665, .iterations = 256 });
}

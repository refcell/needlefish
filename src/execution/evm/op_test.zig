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
    // State carries over between calls, like transactions in one block.
    try h.database.put_account(sender_address, 1 << 60, 0, &.{});
    const sender = try h.state.load(sender_address);
    const tx = transaction.TxEnv{
        .caller = sender_address,
        .gas_limit = gas_limit,
        .nonce = sender.info.nonce,
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
    activation.selector_is_activated,
    activation.selector_check_activated,
    activation.selector_admin,
    activation.selector_set_admin,
    activation.selector_activate,
    activation.selector_deactivate,
    policy.functions[0].selector,
    policy.functions[1].selector,
    policy.functions[5].selector,
    policy.functions[7].selector,
    policy.functions[11].selector,
    policy.functions[12].selector,
    policy.functions[16].selector,
};

const native_targets = [_]Address{
    native.tx_context_address,
    native.nonce_manager_address,
    activation.address,
    policy.address,
};

fn fuzz_native(h: *Harness, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    const upgrades = [_]op_stack.Upgrade{ .beryl, .cobalt, .denim };
    const upgrade = upgrades[prng.below(upgrades.len)];
    const admin = if (prng.chance(1, 2)) sender_address else target;
    h.evm.block.op = .{ .upgrade = upgrade, .activation_admin = admin };
    const to = native_targets[prng.below(native_targets.len)];
    var data: [100]u8 = undefined;
    prng.random().bytes(&data);
    data[0..4].* = native_selectors[prng.below(native_selectors.len)];
    if (prng.chance(3, 4)) @memset(data[4..16], 0); // Usually a clean address word.
    const length = prng.below(data.len + 1);
    const value: u256 = if (prng.chance(1, 8)) 1 else 0;
    // EIP-7623 floor (10 gas per token, a nonzero byte is 4 tokens) bounds intrinsic gas.
    const floor = 21_000 + calldata_gas(data[0..length]) * 10 / 4;
    const gas_limit = floor + prng.below(80_000);
    const executed = try native_call_gas(h, to, data[0..length], value, gas_limit);
    try testing.expect(executed.gas_used <= gas_limit);
    switch (executed.status) {
        .success => try testing.expect(executed.output.len == 0 or executed.output.len == 32),
        .revert => try testing.expect(executed.output.len <= 4 + 64),
        .halt => try testing.expectEqual(gas_limit, executed.gas_used),
    }
}

test "op fuzz: native precompile calls keep gas and result invariants" {
    const h = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(h);
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try fuzz.run(h, fuzz_native, .{ .seed = 0x6e6174697665, .iterations = 256 });
}

const activation = @import("native_activation.zig");

fn activation_input(selector: [4]u8, word: u256) [36]u8 {
    var data: [36]u8 = undefined;
    data[0..4].* = selector;
    std.mem.writeInt(u256, data[4..36], word, .big);
    return data;
}

test "op: ActivationRegistry activates features for the configured admin" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    const feature = activation.feature_b20_asset;
    const activate = activation_input(activation.selector_activate, feature);
    const executed = try native_call(&h, activation.address, &activate, 0);
    try testing.expectEqual(evm_module.Status.success, executed.status);
    // Calldata 2 words, cold SLOAD, marker code (deposit, G_create, hash), SSTORE, LOG3.
    const execution: u64 = 12 + 2_100 + (200 + 32_000 + 30 + 6) + 20_000 + 1_500;
    try testing.expectEqual(21_000 + calldata_gas(&activate) + execution, executed.gas_used);
    try testing.expectEqual(@as(usize, 1), executed.logs.len);
    try testing.expectEqual(@as(u256, 1), try h.storage(activation.address, feature_slot(feature)));

    const again = try native_call(&h, activation.address, &activate, 0);
    try testing.expectEqual(evm_module.Status.revert, again.status);
    const already = activation_input(activation.error_already_activated, feature);
    try testing.expectEqualSlices(u8, &already, again.output);
    const query = activation_input(activation.selector_is_activated, feature);
    const answer = try native_call(&h, activation.address, &query, 1); // Beryl keeps value.
    try testing.expectEqual(evm_module.Status.success, answer.status);
    try testing.expectEqual(@as(u8, 1), answer.output[31]);

    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = target };
    const denied = try native_call(&h, activation.address, &activate, 0);
    var unauthorized: [36]u8 = @splat(0);
    unauthorized[0..4].* = activation.error_unauthorized;
    unauthorized[16..36].* = sender_address;
    try testing.expectEqualSlices(u8, &unauthorized, denied.output);
}

fn feature_slot(feature: u256) u256 {
    return activation.feature_slot(native.u256_word(feature));
}

test "op: ActivationRegistry decode errors and admin storage follow the upgrade" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    const short = activation.selector_is_activated ++ [_]u8{1};
    const beryl = try native_call(&h, activation.address, &short, 0);
    const message = "ABI decoding failed: buffer overrun while deserializing";
    const expected = activation.selector_is_activated ++ message.*;
    try testing.expectEqualSlices(u8, &expected, beryl.output);
    const set_admin = activation_input(activation.selector_set_admin, 0xbeef);
    const unknown = try native_call(&h, activation.address, &set_admin, 0);
    try testing.expectEqualSlices(u8, &activation.selector_set_admin, unknown.output);

    h.evm.block.op = .{ .upgrade = .cobalt, .activation_admin = sender_address };
    const cobalt = try native_call(&h, activation.address, &short, 0);
    try testing.expectEqualSlices(u8, &activation.selector_is_activated, cobalt.output);
    const paid = try native_call(&h, activation.address, &set_admin, 1);
    try testing.expectEqualSlices(u8, &native.selector_non_payable, paid.output);
    const changed = try native_call(&h, activation.address, &set_admin, 0);
    try testing.expectEqual(evm_module.Status.success, changed.status);
    const query = activation.selector_admin;
    const current = try native_call(&h, activation.address, &query, 0);
    try testing.expectEqual(@as(u8, 0xef), current.output[31]);
    try testing.expectEqual(@as(u8, 0xbe), current.output[30]);
}

const policy = @import("native_policy.zig");

fn policy_selector(tag: policy.Tag) [4]u8 {
    return policy.functions[@backingInt(tag)].selector;
}

/// selector ++ words ++ (offset-referenced one-word array when `elements` is non-null).
fn policy_input(
    buffer: []u8,
    tag: policy.Tag,
    words: []const u256,
    elements: ?[]const u256,
) []const u8 {
    buffer[0..4].* = policy_selector(tag);
    var length: usize = 4;
    for (words) |word| {
        std.mem.writeInt(u256, buffer[length..][0..32], word, .big);
        length += 32;
    }
    const list = elements orelse return buffer[0..length];
    const head = 32 * (words.len + 1);
    std.mem.writeInt(u256, buffer[length..][0..32], head, .big);
    std.mem.writeInt(u256, buffer[length + 32 ..][0..32], list.len, .big);
    length += 64;
    for (list) |element| {
        std.mem.writeInt(u256, buffer[length..][0..32], element, .big);
        length += 32;
    }
    return buffer[0..length];
}

fn address_int(account: Address) u256 {
    return std.mem.readInt(u160, &account, .big);
}

test "op: PolicyRegistry creates allowlists behind the activation gate" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    var buffer: [4 + 32 * 70]u8 = undefined;
    const create_words = [_]u256{ address_int(sender_address), policy.type_allowlist };
    const create = policy_input(&buffer, .create_policy, &create_words, null);
    const gated = try native_call(&h, policy.address, create, 0);
    const feature = activation.feature_policy_registry;
    const not_activated = activation_input(activation.error_feature_not_activated, feature);
    try testing.expectEqualSlices(u8, &not_activated, gated.output);

    const activate = activation_input(activation.selector_activate, feature);
    const activated = try native_call(&h, activation.address, &activate, 0);
    try testing.expectEqual(evm_module.Status.success, activated.status);
    const created = try native_call(&h, policy.address, create, 0);
    try testing.expectEqual(evm_module.Status.success, created.status);
    const id: u64 = (1 << 56) | 2;
    try testing.expectEqual(@as(u256, id), std.mem.readInt(u256, created.output[0..32], .big));
    try testing.expectEqual(@as(usize, 2), created.logs.len);

    const member = primitives.address_from_int(0xa11ce);
    const update =
        policy_input(&buffer, .update_allowlist, &.{ id, 1 }, &.{address_int(member)});
    const updated = try native_call(&h, policy.address, update, 0);
    try testing.expectEqual(evm_module.Status.success, updated.status);
    const check = policy_input(&buffer, .is_authorized, &.{ id, address_int(member) }, null);
    try testing.expectEqual(@as(u8, 1), (try native_call(&h, policy.address, check, 0)).output[31]);
    const other = policy_input(&buffer, .is_authorized, &.{ id, 0xb0b }, null);
    try testing.expectEqual(@as(u8, 0), (try native_call(&h, policy.address, other, 0)).output[31]);
    const exists = policy_input(&buffer, .policy_exists, &.{policy.always_block_id}, null);
    const builtin = try native_call(&h, policy.address, exists, 0);
    try testing.expectEqual(@as(u8, 1), builtin.output[31]);

    var many: [65]u256 = @splat(address_int(member));
    const big = policy_input(&buffer, .update_allowlist, &.{ id, 1 }, &many);
    const too_large = try native_call_gas(&h, policy.address, big, 0, 1_000_000);
    try testing.expectEqualSlices(u8, &policy.error_batch_size_too_large, too_large.output[0..4]);
    try testing.expectEqual(@as(u8, 64), too_large.output[35]);
}

test "op: PolicyRegistry rejects value and reports Beryl decode failures" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    var buffer: [4 + 64]u8 = undefined;
    const words = [_]u256{ address_int(sender_address), 2 };
    const bad_type = policy_input(&buffer, .create_policy, &words, null);
    const failed = try native_call(&h, policy.address, bad_type, 0);
    const message = "type check failed for \"(address,uint8)\"";
    const expected = policy_selector(.create_policy) ++ message.*;
    try testing.expectEqualSlices(u8, &expected, failed.output);
    const paid = try native_call(&h, policy.address, bad_type, 1);
    try testing.expectEqualSlices(u8, &native.selector_non_payable, paid.output);
}

fn policy_call(h: *Harness, input: []const u8) !transaction.Executed {
    return native_call_gas(h, policy.address, input, 0, 1_000_000);
}

fn output_word(executed: transaction.Executed) u256 {
    return std.mem.readInt(u256, executed.output[0..32], .big);
}

test "op: PolicyRegistry composite and inverted policies (Denim)" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .denim, .activation_admin = sender_address };
    const feature = activation.feature_policy_registry;
    const activate = activation_input(activation.selector_activate, feature);
    _ = try native_call(&h, activation.address, &activate, 0);
    var buffer: [4 + 32 * 10]u8 = undefined;
    const admin = address_int(sender_address);
    const member: u256 = 0xa11ce;
    const allow_create =
        policy_input(&buffer, .create_policy_with_accounts, &.{ admin, 1 }, &.{member});
    const allow: u64 = @intCast(output_word(try policy_call(&h, allow_create)));
    const block_create = policy_input(&buffer, .create_policy, &.{ admin, 0 }, null);
    const block = output_word(try policy_call(&h, block_create));
    try testing.expectEqual(@as(u64, (1 << 56) | 2), allow);
    try testing.expectEqual(@as(u256, 3), block);

    const one_child = policy_input(&buffer, .create_composite_policy, &.{ admin, 3 }, &.{allow});
    const range = try policy_call(&h, one_child);
    try testing.expectEqualSlices(u8, &policy.error_child_policies_outside_of_range, range.output);
    const builtin =
        policy_input(&buffer, .create_composite_policy, &.{ admin, 3 }, &.{ allow, 0 });
    const invalid = try policy_call(&h, builtin);
    try testing.expectEqualSlices(u8, &policy.error_invalid_child_policy, invalid.output[0..4]);
    const as_list = policy_input(&buffer, .create_policy, &.{ admin, 2 }, null);
    const incompatible = try policy_call(&h, as_list);
    try testing.expectEqualSlices(u8, &policy.error_incompatible_policy_type, incompatible.output);

    const create =
        policy_input(&buffer, .create_composite_policy, &.{ admin, 3 }, &.{ allow, block });
    const composite = output_word(try policy_call(&h, create));
    try testing.expectEqual(@as(u256, (3 << 56) | 4), composite);
    const member_check = policy_input(&buffer, .is_authorized, &.{ composite, member }, null);
    try testing.expectEqual(@as(u256, 1), output_word(try policy_call(&h, member_check)));
    const stranger = policy_input(&buffer, .is_authorized, &.{ composite, 0xb0b }, null);
    try testing.expectEqual(@as(u256, 0), output_word(try policy_call(&h, stranger)));
    const children = policy_input(&buffer, .composite_policy_child_ids, &.{composite}, null);
    const ids = try policy_call(&h, children);
    try testing.expectEqual(@as(usize, 128), ids.output.len);
    try testing.expectEqual(@as(u8, 3), ids.output[127]);

    const invert = policy_input(&buffer, .inverted_policy_id, &.{allow}, null);
    const inverted = output_word(try policy_call(&h, invert));
    try testing.expectEqual(@as(u256, allow | (1 << 63)), inverted);
    const negated = policy_input(&buffer, .is_authorized, &.{ inverted, member }, null);
    try testing.expectEqual(@as(u256, 0), output_word(try policy_call(&h, negated)));
    const negated_stranger = policy_input(&buffer, .is_authorized, &.{ inverted, 0xb0b }, null);
    try testing.expectEqual(@as(u256, 1), output_word(try policy_call(&h, negated_stranger)));

    h.evm.block.op = .{ .upgrade = .cobalt, .activation_admin = sender_address };
    const again = policy_input(&buffer, .inverted_policy_id, &.{allow}, null);
    const unknown = try policy_call(&h, again);
    try testing.expectEqualSlices(u8, &policy_selector(.inverted_policy_id), unknown.output);
}

const native_storage = @import("native_storage.zig");

fn storage_context(h: *Harness, upgrade: op_stack.Upgrade, out: []u8) native.Context {
    return .{
        .state = &h.state,
        .upgrade = upgrade,
        .address = target,
        .caller = sender_address,
        .origin = sender_address,
        .value = 0,
        .is_static = false,
        .gas_limit = 10_000_000,
        .out = out,
    };
}

test "op: native string storage round-trips and cleans tails from Cobalt" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try h.database.put_account(target, 0, 1, &.{});
    var out: [64]u8 = undefined;
    const long = "a long token name that needs more than one storage chunk to hold it all";
    var buffer: [native_storage.bytes_length_max]u8 = undefined;
    const tail_slot = std.mem.readInt(u256, &primitives.keccak256(&native.u256_word(9)), .big) + 2;
    inline for (.{ op_stack.Upgrade.beryl, op_stack.Upgrade.cobalt }) |upgrade| {
        var context = storage_context(&h, upgrade, &out);
        try native_storage.store(&context, 9, long);
        try testing.expectEqualStrings(long, try native_storage.load(&context, 9, &buffer));
        try testing.expect(try h.storage(target, tail_slot) != 0);
        try native_storage.store(&context, 9, "B20");
        try testing.expectEqualStrings("B20", try native_storage.load(&context, 9, &buffer));
        const cleaned = try h.storage(target, tail_slot) == 0;
        try testing.expectEqual(upgrade == .cobalt, cleaned);
        try native_storage.delete(&context, 9);
        try testing.expectEqual(@as(u256, 0), try h.storage(target, 9));
    }
}

const b20 = @import("native_b20.zig");
const b20_asset = @import("native_b20_token.zig");
const token_address: Address = .{ 0xb2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
const stablecoin_address: Address = .{
    0xb2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1,
};
const holder = primitives.address_from_int(0x401de2);

fn short_string(comptime text: []const u8) u256 {
    var word: [32]u8 = @splat(0);
    @memcpy(word[0..text.len], text);
    word[31] = 2 * text.len;
    return std.mem.readInt(u256, &word, .big);
}

fn role_slot(role: u256, account: Address) u256 {
    const inner = native.mapping_slot(native.u256_word(role), b20.root + 6);
    return native.mapping_slot(native.address_word(account), inner);
}

/// A Beryl harness with an initialized asset token: the sender holds the admin and mint roles.
fn token_setup(h: *Harness) !void {
    try h.init(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    try h.database.put_account(token_address, 0, 0, &native.marker_code);
    try h.database.put_storage(token_address, b20.slot_name, short_string("Token"));
    try h.database.put_storage(token_address, b20.slot_symbol, short_string("TKN"));
    try h.database.put_storage(token_address, b20.slot_supply_cap, 1_000_000);
    try h.database.put_storage(token_address, b20_asset.asset_root + 1, b20_asset.wad);
    try h.database.put_storage(token_address, role_slot(0, sender_address), 1);
    try h.database.put_storage(token_address, b20.root + 8, 1);
    try h.database.put_storage(token_address, role_slot(b20.role_mint, sender_address), 1);
    try h.database.put_storage(token_address, role_slot(b20.role_seize, sender_address), 1);
    try h.database.put_storage(token_address, b20.root + 14, policy.always_block_id);
    try h.database.put_account(stablecoin_address, 0, 0, &native.marker_code);
    try h.database.put_storage(stablecoin_address, b20.slot_supply_cap, 1_000_000);
    try h.database.put_storage(stablecoin_address, role_slot(b20.role_mint, sender_address), 1);
    try h.database.put_storage(stablecoin_address, b20_asset.stablecoin_root, short_string("USD"));
    h.state.reset(h.database.interface());
}

fn token_input(buffer: []u8, tag: b20_asset.Tag, words: []const u256) []const u8 {
    buffer[0..4].* = b20_asset.selector_of(tag);
    for (words, 0..) |word, index| {
        std.mem.writeInt(u256, buffer[4 + 32 * index ..][0..32], word, .big);
    }
    return buffer[0 .. 4 + 32 * words.len];
}

fn token_call(h: *Harness, tag: b20_asset.Tag, words: []const u256) !transaction.Executed {
    var buffer: [4 + 32 * 8]u8 = undefined;
    return native_call(h, token_address, token_input(&buffer, tag, words), 0);
}

fn output_int(executed: transaction.Executed) u256 {
    return std.mem.readInt(u256, executed.output[0..32], .big);
}

test "op: B-20 asset mints, transfers, and enforces balances and the supply cap" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    const minted = try token_call(&h, .mint, &.{ address_int(sender_address), 600 });
    try testing.expect(minted.status == .success);
    try testing.expectEqual(@as(usize, 1), minted.logs.len);
    const supply = try token_call(&h, .total_supply, &.{});
    try testing.expectEqual(@as(u256, 600), output_int(supply));

    const sent = try token_call(&h, .transfer, &.{ address_int(holder), 250 });
    try testing.expect(sent.status == .success);
    try testing.expectEqual(@as(u256, 1), output_int(sent));
    const holder_balance = try token_call(&h, .balance_of, &.{address_int(holder)});
    try testing.expectEqual(@as(u256, 250), output_int(holder_balance));

    const short = try token_call(&h, .transfer, &.{ address_int(holder), 351 });
    try testing.expect(short.status == .revert);
    try testing.expectEqualSlices(u8, &b20.error_insufficient_balance, short.output[0..4]);
    try testing.expectEqual(@as(usize, 4 + 96), short.output.len);

    const capped = try token_call(&h, .mint, &.{ address_int(holder), 999_401 });
    try testing.expect(capped.status == .revert);
    const exact = try token_call(&h, .mint, &.{ address_int(holder), 999_400 });
    try testing.expect(exact.status == .success);

    const zero = try token_call(&h, .transfer, &.{ 0, 1 });
    try testing.expectEqualSlices(u8, &b20.error_invalid_receiver, zero.output[0..4]);
}

test "op: B-20 asset pause flags, roles, and views" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    // Pausing needs PAUSE_ROLE.
    var buffer: [4 + 32 * 4]u8 = undefined;
    const pause_input = token_input(&buffer, .pause, &.{ 0x20, 1, 0 });
    const denied = try native_call(&h, token_address, pause_input, 0);
    try testing.expectEqualSlices(u8, &b20.error_unauthorized_account, denied.output[0..4]);
    const sender = address_int(sender_address);
    const granted = try token_call(&h, .grant_role, &.{ b20.role_pause, sender });
    try testing.expect(granted.status == .success);
    const paused = try native_call(&h, token_address, pause_input, 0);
    try testing.expect(paused.status == .success);
    const blocked = try token_call(&h, .transfer, &.{ address_int(holder), 0 });
    try testing.expectEqualSlices(u8, &b20.error_contract_paused, blocked.output[0..4]);
    const features = try token_call(&h, .paused_features, &.{});
    try testing.expectEqual(@as(usize, 96), features.output.len);
    // Out-of-range enum is a decode failure; empty arrays revert EmptyFeatureSet.
    const bad_input = token_input(&buffer, .pause, &.{ 0x20, 1, 3 });
    const bad = try native_call(&h, token_address, bad_input, 0);
    try testing.expect(bad.status == .revert);
    const empty_input = token_input(&buffer, .pause, &.{ 0x20, 0 });
    const empty = try native_call(&h, token_address, empty_input, 0);
    try testing.expectEqual(@as(usize, 4), empty.output.len);

    const name = try token_call(&h, .name, &.{});
    try testing.expectEqual(@as(usize, 96), name.output.len);
    try testing.expectEqualStrings("Token", name.output[64..69]);
    const decimals = try token_call(&h, .decimals, &.{});
    try testing.expectEqual(@as(u256, 6), output_int(decimals));
    const domain = try token_call(&h, .eip712_domain, &.{});
    try testing.expectEqual(@as(usize, 7 * 32 + 64 + 64 + 32), domain.output.len);
    try testing.expectEqual(@as(u8, 0x0f), domain.output[0]);

    // Last admin cannot renounce; unknown selectors revert with the bare selector.
    const renounce = try token_call(&h, .renounce_role, &.{ 0, address_int(sender_address) });
    try testing.expect(renounce.status == .revert);
    const unknown = try native_call(&h, token_address, &.{ 0xde, 0xad, 0xbe, 0xef }, 0);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, unknown.output);
    const payable = try native_call(&h, token_address, token_input(&buffer, .name, &.{}), 1);
    try testing.expectEqualSlices(u8, &native.selector_non_payable, payable.output);
}

test "op: B-20 asset metadata, multiplier, allowances, and permit failures" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    var buffer: [4 + 32 * 8]u8 = undefined;
    // updateName needs METADATA_ROLE; with it the name and its event change.
    _ = try token_call(&h, .grant_role, &.{ b20.role_metadata, address_int(sender_address) });
    const abc = short_string("abc") & ~@as(u256, 0xff);
    const input = token_input(&buffer, .update_name, &.{ 0x20, 3, abc });
    const renamed = try native_call(&h, token_address, input, 0);
    try testing.expect(renamed.status == .success);
    try testing.expectEqual(@as(usize, 2), renamed.logs.len);
    const name = try token_call(&h, .name, &.{});
    try testing.expectEqualStrings("abc", name.output[64..67]);

    const operator = try token_call(&h, .update_multiplier, &.{2 * b20_asset.wad});
    try testing.expectEqualSlices(u8, &b20.error_unauthorized_account, operator.output[0..4]);
    _ = try token_call(&h, .grant_role, &.{ b20_asset.role_operator, address_int(sender_address) });
    const doubled = try token_call(&h, .update_multiplier, &.{2 * b20_asset.wad});
    try testing.expect(doubled.status == .success);
    const scaled = try token_call(&h, .to_scaled_balance, &.{10});
    try testing.expectEqual(@as(u256, 20), output_int(scaled));

    const approved = try token_call(&h, .approve, &.{ address_int(holder), 77 });
    try testing.expect(approved.status == .success);
    const pair = [2]u256{ address_int(sender_address), address_int(holder) };
    const allowance = try token_call(&h, .allowance, &pair);
    try testing.expectEqual(@as(u256, 77), output_int(allowance));

    const owner = address_int(holder);
    const expired = try token_call(&h, .permit, &.{ owner, owner, 1, 0, 27, 1, 1 });
    try testing.expect(expired.status == .success or expired.status == .revert);
    const bad_v = try token_call(&h, .permit, &.{ owner, owner, 1, 1 << 40, 29, 1, 1 });
    try testing.expect(bad_v.status == .revert);
    try testing.expectEqual(@as(usize, 4 + 64), bad_v.output.len);
    try testing.expectEqual(owner, std.mem.readInt(u256, bad_v.output[36..68], .big));
}

fn keccak_of(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

/// The EIP-712 permit digest, built from the EIP-2612 type strings (not the token's constants).
fn permit_digest(chain_id: u64, owner: Address, spender: Address, value: u256) [32]u8 {
    const deadline: u256 = 1 << 40;
    var domain: [5 * 32]u8 = @splat(0);
    domain[0..32].* = keccak_of(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    domain[32..64].* = keccak_of("Token");
    domain[64..96].* = keccak_of("1");
    std.mem.writeInt(u256, domain[96..128], chain_id, .big);
    domain[140..160].* = token_address;
    var permit: [6 * 32]u8 = @splat(0);
    permit[0..32].* = keccak_of(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
    );
    permit[44..64].* = owner;
    permit[76..96].* = spender;
    std.mem.writeInt(u256, permit[96..128], value, .big);
    std.mem.writeInt(u256, permit[160..192], deadline, .big); // Nonce 0.
    var message: [66]u8 = undefined;
    message[0..2].* = .{ 0x19, 0x01 };
    message[2..34].* = keccak_of(&domain);
    message[34..66].* = keccak_of(&permit);
    return keccak_of(&message);
}

test "op: B-20 permit meters base/base's second, warm nonce read" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .cobalt, .activation_admin = sender_address };
    const secp256k1 = @import("../../common/crypto/root.zig").secp256k1;
    const key: [32]u8 = @splat(0x42);
    const owner = try secp256k1.address(key);
    const deadline: u256 = 1 << 40;
    const digest = permit_digest(h.evm.config.chain_id, owner, holder, 77);
    const signature = try secp256k1.sign(key, digest);
    const v = 27 + @as(u256, signature.recovery_id);
    const r = std.mem.readInt(u256, &signature.r, .big);
    const s = std.mem.readInt(u256, &signature.s, .big);
    var buffer: [4 + 32 * 8]u8 = undefined;
    const words = [_]u256{ address_int(owner), address_int(holder), 77, deadline, v, r, s };
    const input = token_input(&buffer, .permit, &words);
    const executed = try native_call(&h, token_address, input, 0);
    try testing.expectEqual(evm_module.Status.success, executed.status);
    const allowance = try token_call(&h, .allowance, &.{ address_int(owner), address_int(holder) });
    try testing.expectEqual(@as(u256, 77), output_int(allowance));
    // base/base v2 permit, in order: 8 calldata words; the warm `is_initialized` account read;
    // the cold name read and the three domain hashes; the cold nonce read; the struct and
    // message hashes; recovery; `increment_nonce` reads the nonce again (warm, the 100 gas
    // mainnet block 54049206 charged) and sets it; the cold allowance set; the Approval log
    // (3 topics, 1 data word).
    const native_gas: u64 = 6 * 8 + 100 + 2_100 + (30 + 6) + (30 + 6) + (30 + 6 * 5) + 2_100 +
        (30 + 6 * 6) + (30 + 6 * 3) + 3_000 + 100 + 20_000 + 22_100 + (375 * 4 + 8 * 32);
    try testing.expectEqual(21_000 + calldata_gas(input) + native_gas, executed.gas_used);
}

const token_roles = [_]u256{ 0, b20.role_mint, b20.role_pause, b20.role_burn, b20.role_metadata };

/// Argument words that reach deep token paths: pool accounts, small amounts, role and scope
/// ids, ABI offsets, and occasionally random words.
fn token_word(prng: *Prng) u256 {
    return switch (prng.below(6)) {
        0 => address_int(if (prng.chance(1, 2)) sender_address else holder),
        1 => prng.below(2_000),
        2 => token_roles[prng.below(token_roles.len)],
        3 => b20.PolicyScope.transfer_sender.id(),
        4 => 0x20 * (1 + prng.below(4)),
        else => prng.random().int(u256),
    };
}

fn fuzz_token(h: *Harness, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var buffer: [4 + 32 * 8]u8 = undefined;
    var words: [8]u256 = undefined;
    for (&words) |*word| word.* = token_word(&prng);
    const function = b20_asset.functions[prng.below(b20_asset.functions.len)];
    const count = prng.below(words.len + 1);
    var input = token_input(&buffer, function.tag, words[0..count]);
    if (prng.chance(1, 8)) input = input[0..prng.below(input.len + 1)];
    const floor = 21_000 + calldata_gas(input) * 10 / 4;
    const gas_limit = floor + prng.below(120_000);
    const value: u256 = if (prng.chance(1, 16)) 1 else 0;
    const upgrades = [3]@TypeOf(h.evm.block.op.?.upgrade){ .beryl, .cobalt, .denim };
    const pick: usize = if (prng.chance(1, 3)) 0 else if (prng.chance(1, 2)) 1 else 2;
    h.evm.block.op.?.upgrade = upgrades[pick];
    const token = if (prng.chance(1, 2)) token_address else stablecoin_address;
    const executed = try native_call_gas(h, token, input, value, gas_limit);
    try testing.expect(executed.gas_used <= gas_limit);
    switch (executed.status) {
        .success => try testing.expect(executed.output.len % 32 == 0),
        .revert => try testing.expect(executed.output.len == 0 or executed.output.len >= 4),
        .halt => try testing.expectEqual(gas_limit, executed.gas_used),
    }
    const supply = try h.state.storage_value(token, b20.slot_total_supply);
    const cap = try h.state.storage_value(token, b20.slot_supply_cap);
    try testing.expect(supply <= cap);
}

test "op fuzz: B-20 asset calls keep gas, output, and supply invariants" {
    const h = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(h);
    try token_setup(h);
    defer h.deinit(testing.allocator);
    try fuzz.run(h, fuzz_token, .{ .seed = 0x623230, .iterations = 512 });
}

/// announce([call], id, "d", "u") with one internal call of up to 68 bytes.
fn announce_input(buffer: []u8, call: []const u8, id: u256) []const u8 {
    assert(call.len <= 68);
    var words: [16]u256 = @splat(0);
    words[0] = 4 * 32; // internalCalls
    words[1] = 10 * 32; // id
    words[2] = 12 * 32; // description
    words[3] = 14 * 32; // uri
    words[4] = 1; // one call
    words[5] = 32; // element offset (relative to after the length)
    words[6] = call.len;
    // words 7..9 hold the call bytes (filled below).
    words[10] = 1;
    words[11] = id;
    words[12] = 1;
    words[13] = short_string("d") & ~@as(u256, 0xff);
    words[14] = 1;
    words[15] = short_string("u") & ~@as(u256, 0xff);
    const input = token_input(buffer, .announce, &words);
    @memcpy(buffer[4 + 7 * 32 ..][0..call.len], call);
    return input;
}

const assert = std.debug.assert;

test "op: B-20 asset announce runs internal calls atomically" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    const sender = address_int(sender_address);
    _ = try token_call(&h, .grant_role, &.{ b20_asset.role_operator, sender });
    var call_buffer: [4 + 32 * 2]u8 = undefined;
    const mint_call = token_input(&call_buffer, .mint, &.{ address_int(holder), 5 });
    var buffer: [4 + 32 * 16]u8 = undefined;
    const id = short_string("x") & ~@as(u256, 0xff);
    const announced = try native_call(&h, token_address, announce_input(&buffer, mint_call, id), 0);
    try testing.expect(announced.status == .success);
    try testing.expectEqual(@as(usize, 3), announced.logs.len);
    const balance_after = try token_call(&h, .balance_of, &.{address_int(holder)});
    try testing.expectEqual(@as(u256, 5), output_int(balance_after));

    const reused = try native_call(&h, token_address, announce_input(&buffer, mint_call, id), 0);
    try testing.expect(reused.status == .revert);
    try testing.expectEqual(@as(usize, 4 + 96), reused.output.len);

    const fresh = short_string("y") & ~@as(u256, 0xff);
    const short_input = announce_input(&buffer, mint_call[0..3], fresh);
    const malformed = try native_call(&h, token_address, short_input, 0);
    try testing.expect(malformed.status == .revert);
    try testing.expectEqual(@as(usize, 4 + 96), malformed.output.len);
    const over_cap = token_input(&call_buffer, .mint, &.{ address_int(holder), 1 << 100 });
    const failed = try native_call(&h, token_address, announce_input(&buffer, over_cap, fresh), 0);
    try testing.expect(failed.status == .revert);
    try testing.expectEqual(@as(usize, 4 + 64 + 96), failed.output.len);
}

const b20_factory = @import("native_b20_factory.zig");

const Writer = struct {
    buffer: []u8,
    length: usize = 0,

    fn int(writer: *Writer, value: u256) void {
        std.mem.writeInt(u256, writer.buffer[writer.length..][0..32], value, .big);
        writer.length += 32;
    }

    fn padded(writer: *Writer, bytes: []const u8) void {
        const size = std.mem.alignForward(usize, bytes.len, 32);
        @memset(writer.buffer[writer.length..][0..size], 0);
        @memcpy(writer.buffer[writer.length..][0..bytes.len], bytes);
        writer.length += size;
    }
};

/// createB20(ASSET, salt, abi.encode(B20AssetCreateParams), [init_call]) with 4-byte names.
fn create_input(
    buffer: []u8,
    salt: u256,
    version: u8,
    decimals: u8,
    init_call: ?[]const u8,
) []const u8 {
    var writer = Writer{ .buffer = buffer };
    writer.buffer[0..4].* = b20_factory.selector_of(.create_b20);
    writer.length = 4;
    writer.int(0); // ASSET
    writer.int(salt);
    writer.int(4 * 32); // params offset
    writer.int(4 * 32 + 32 + 320); // initCalls offset
    writer.int(320); // params length
    writer.int(0x20);
    writer.int(version);
    writer.int(0xa0);
    writer.int(0xe0);
    writer.int(address_int(sender_address));
    writer.int(decimals);
    writer.int(4);
    writer.padded("Gold");
    writer.int(3);
    writer.padded("GLD");
    const call = init_call orelse {
        writer.int(0);
        return buffer[0..writer.length];
    };
    writer.int(1);
    writer.int(32);
    writer.int(call.len);
    writer.padded(call);
    return buffer[0..writer.length];
}

fn create_call(h: *Harness, input: []const u8) !transaction.Executed {
    return native_call_gas(h, b20_factory.address, input, 0, 1_000_000);
}

test "op: B-20 factory creates activated asset tokens with init calls" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    var call_buffer: [4 + 64]u8 = undefined;
    const mint_call = token_input(&call_buffer, .mint, &.{ address_int(holder), 100 });
    var buffer: [1024]u8 = undefined;
    const inactive = try create_call(&h, create_input(&buffer, 7, 1, 18, mint_call));
    const not_activated = &activation.error_feature_not_activated;
    try testing.expectEqualSlices(u8, not_activated, inactive.output[0..4]);
    const activate = activation_input(activation.selector_activate, activation.feature_b20_asset);
    try testing.expect((try native_call(&h, activation.address, &activate, 0)).status == .success);

    const created = try create_call(&h, create_input(&buffer, 7, 1, 18, mint_call));
    try testing.expect(created.status == .success);
    try testing.expectEqual(@as(usize, 3), created.logs.len);
    const salt = native.u256_word(7);
    const token = b20_factory.token_address(.asset, sender_address, &salt);
    try testing.expectEqualSlices(u8, &native.address_word(token), created.output);

    var query: [4 + 32]u8 = undefined;
    query[0..4].* = b20_factory.selector_of(.is_b20_initialized);
    query[4..36].* = native.address_word(token);
    const initialized = try native_call(&h, b20_factory.address, &query, 0);
    try testing.expectEqual(@as(u256, 1), output_int(initialized));
    var input_buffer: [4 + 32]u8 = undefined;
    input_buffer[0..4].* = b20_asset.selector_of(.balance_of);
    input_buffer[4..36].* = native.address_word(holder);
    const balance_held = try native_call(&h, token, &input_buffer, 0);
    try testing.expectEqual(@as(u256, 100), output_int(balance_held));
    input_buffer[0..4].* = b20_asset.selector_of(.decimals);
    const decimals = try native_call(&h, token, input_buffer[0..4], 0);
    try testing.expectEqual(@as(u256, 18), output_int(decimals));

    const again = try create_call(&h, create_input(&buffer, 7, 1, 18, null));
    try testing.expectEqual(@as(usize, 36), again.output.len);
    const low = try create_call(&h, create_input(&buffer, 8, 1, 5, null));
    try testing.expectEqual(@as(usize, 36), low.output.len);
    const version = try create_call(&h, create_input(&buffer, 8, 2, 6, null));
    try testing.expectEqual(@as(usize, 68), version.output.len);
    const unknown = try create_call(&h, create_input(&buffer, 8, 1, 6, &.{ 1, 2, 3, 4 }));
    try testing.expect(unknown.status == .revert);
    try testing.expectEqual(@as(usize, 36), unknown.output.len);
    const fresh = try create_call(&h, create_input(&buffer, 8, 1, 6, null));
    try testing.expect(fresh.status == .success);
}

/// createB20(STABLECOIN, salt, abi.encode(B20StablecoinCreateParams), []).
fn create_stablecoin_input(buffer: []u8, salt: u256, currency: []const u8) []const u8 {
    var writer = Writer{ .buffer = buffer };
    writer.buffer[0..4].* = b20_factory.selector_of(.create_b20);
    writer.length = 4;
    writer.int(1); // STABLECOIN
    writer.int(salt);
    writer.int(4 * 32);
    writer.int(4 * 32 + 32 + 384);
    writer.int(384);
    writer.int(0x20);
    writer.int(1);
    writer.int(0xa0);
    writer.int(0xe0);
    writer.int(address_int(sender_address));
    writer.int(0x120);
    writer.int(4);
    writer.padded("Cash");
    writer.int(4);
    writer.padded("CASH");
    writer.int(currency.len);
    writer.padded(currency);
    writer.int(0);
    return buffer[0..writer.length];
}

test "op: B-20 factory creates stablecoins with a currency and fixed decimals" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    h.evm.block.op = .{ .upgrade = .beryl, .activation_admin = sender_address };
    const feature = activation.feature_b20_stablecoin;
    const activate = activation_input(activation.selector_activate, feature);
    try testing.expect((try native_call(&h, activation.address, &activate, 0)).status == .success);
    var buffer: [1024]u8 = undefined;
    const lower = try create_call(&h, create_stablecoin_input(&buffer, 1, "usd"));
    try testing.expect(lower.status == .revert);
    try testing.expectEqual(@as(usize, 4 + 96), lower.output.len);
    const empty = try create_call(&h, create_stablecoin_input(&buffer, 1, ""));
    try testing.expect(empty.status == .revert);
    const created = try create_call(&h, create_stablecoin_input(&buffer, 1, "USD"));
    try testing.expect(created.status == .success);
    try testing.expectEqual(@as(usize, 2), created.logs.len);
    const token = created.output[12..32].*;
    try testing.expectEqual(native.B20Variant.stablecoin, native.b20_variant(token).?);

    var input: [4]u8 = b20_asset.selector_of(.currency);
    const currency = try native_call(&h, token, &input, 0);
    try testing.expectEqualStrings("USD", currency.output[64..67]);
    input = b20_asset.selector_of(.decimals);
    try testing.expectEqual(@as(u256, 6), output_int(try native_call(&h, token, &input, 0)));
    input = b20_asset.selector_of(.multiplier);
    const asset_only = try native_call(&h, token, &input, 0);
    try testing.expectEqualSlices(u8, &input, asset_only.output);
}

test "op: B-20 V2 gates selectors by fork and seizes from non-exempt accounts" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    const early = try token_call(&h, .seize_role, &.{});
    try testing.expectEqualSlices(u8, &b20_asset.selector_of(.seize_role), early.output);
    h.evm.block.op.?.upgrade = .cobalt;
    try testing.expectEqual(b20.role_seize, output_int(try token_call(&h, .seize_role, &.{})));
    const max = output_int(try token_call(&h, .max_ui_multiplier, &.{}));
    try testing.expectEqual(@as(u256, std.math.maxInt(u128)), max);
    const erc165: u256 = 0x01ffc9a7 << 224;
    const supported = try token_call(&h, .supports_interface, &.{erc165});
    try testing.expectEqual(@as(u256, 1), output_int(supported));
    const unpadded = try token_call(&h, .supports_interface, &.{erc165 | 1});
    try testing.expect(unpadded.status == .revert);

    _ = try token_call(&h, .mint, &.{ address_int(holder), 600 });
    const memo: u256 = 0x6d656d6f;
    const seized = try token_call(&h, .seize_with_memo, &.{
        address_int(holder), address_int(sender_address), 100, memo,
    });
    try testing.expect(seized.status == .success);
    try testing.expectEqual(@as(usize, 3), seized.logs.len);
    const left = output_int(try token_call(&h, .balance_of, &.{address_int(holder)}));
    try testing.expectEqual(@as(u256, 500), left);
    const same = try token_call(&h, .seize_with_memo, &.{
        address_int(holder), address_int(holder), 1, memo,
    });
    try testing.expect(same.status == .revert);
    try testing.expectEqualSlices(u8, &b20.error_invalid_receiver, same.output[0..4]);
}

test "op: B-20 V2 schedules, matures, and cancels UI multiplier updates" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    h.evm.block.op.?.upgrade = .cobalt;
    h.evm.block.timestamp = 1000;
    const operator = role_slot(b20_asset.role_operator, sender_address);
    try h.database.put_storage(token_address, operator, 1);
    h.state.reset(h.database.interface());
    const wad = b20_asset.wad;
    const past = try token_call(&h, .update_ui_multiplier, &.{ 2 * wad, 1000 });
    try testing.expect(past.status == .revert);
    const scheduled = try token_call(&h, .update_ui_multiplier, &.{ 2 * wad, 2000 });
    try testing.expect(scheduled.status == .success);
    try testing.expectEqual(wad, output_int(try token_call(&h, .ui_multiplier, &.{})));
    try testing.expectEqual(2 * wad, output_int(try token_call(&h, .new_ui_multiplier, &.{})));
    try testing.expectEqual(@as(u256, 2000), output_int(try token_call(&h, .effective_at, &.{})));
    const again = try token_call(&h, .update_ui_multiplier, &.{ 3 * wad, 3000 });
    try testing.expect(again.status == .revert);
    const cancelled = try token_call(&h, .cancel_ui_multiplier_update, &.{});
    try testing.expectEqual(@as(usize, 1), cancelled.logs.len);
    try testing.expectEqual(@as(u256, 0), output_int(try token_call(&h, .effective_at, &.{})));

    _ = try token_call(&h, .update_ui_multiplier, &.{ 2 * wad, 2000 });
    h.evm.block.timestamp = 2000;
    try testing.expectEqual(2 * wad, output_int(try token_call(&h, .ui_multiplier, &.{})));
    const scaled = output_int(try token_call(&h, .to_ui_amount, &.{10}));
    try testing.expectEqual(@as(u256, 20), scaled);
    const late = try token_call(&h, .cancel_ui_multiplier_update, &.{});
    try testing.expect(late.status == .revert);
    const set = try token_call(&h, .update_multiplier, &.{3 * wad});
    try testing.expectEqual(@as(usize, 2), set.logs.len);
    try testing.expectEqual(3 * wad, output_int(try token_call(&h, .multiplier, &.{})));
    try testing.expectEqual(@as(u256, 0), output_int(try token_call(&h, .effective_at, &.{})));
}

test "op: B-20 V3 rejects crediting the token and always checks the executor policy" {
    var h: Harness = undefined;
    try token_setup(&h);
    defer h.deinit(testing.allocator);
    _ = try token_call(&h, .mint, &.{ address_int(sender_address), 600 });
    h.evm.block.op.?.upgrade = .cobalt;
    const allowed = try token_call(&h, .transfer, &.{ address_int(token_address), 1 });
    try testing.expect(allowed.status == .success);
    h.evm.block.op.?.upgrade = .denim;
    const rejected = try token_call(&h, .transfer, &.{ address_int(token_address), 1 });
    try testing.expect(rejected.status == .revert);
    try testing.expectEqualSlices(u8, &b20.error_invalid_receiver, rejected.output[0..4]);
    const minted = try token_call(&h, .mint, &.{ address_int(token_address), 1 });
    try testing.expect(minted.status == .revert);
    const sent = try token_call(&h, .transfer, &.{ address_int(holder), 1 });
    try testing.expect(sent.status == .success);
}

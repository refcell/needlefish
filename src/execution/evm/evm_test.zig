//! End-to-end EVM tests: bytecode runs through state, frames, and the interpreter.

const std = @import("std");
const primitives = @import("primitives.zig");
const op = @import("opcode.zig");
const env = @import("env.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const MemoryDatabase = @import("memory_db.zig").MemoryDatabase;
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;

pub const test_config = env.Config{
    .memory_bytes_max = 1 << 20,
    .code_arena_bytes = 1 << 22,
    .modexp_modulus_bytes_max = 4096,
};

pub const test_limits = state_module.Limits{
    .accounts_max = 1024,
    .slots_max = 4096,
    .transient_slots_max = 256,
    .journal_entries_max = 1 << 14,
    .logs_max = 256,
    .log_data_bytes_max = 1 << 16,
    .code_bytes_max = 1 << 18,
};

/// A database, state, and EVM wired together for one test.
pub const Harness = struct {
    database: MemoryDatabase,
    state: state_module.State,
    evm: evm_module.Evm,

    pub fn init(harness: *Harness, allocator: std.mem.Allocator) !void {
        harness.database = MemoryDatabase.init(allocator);
        errdefer harness.database.deinit();
        harness.state = try state_module.State.init(
            allocator,
            harness.database.interface(),
            test_limits,
        );
        errdefer harness.state.deinit(allocator);
        harness.evm = try evm_module.Evm.init(allocator, test_config, &harness.state);
    }

    pub fn deinit(harness: *Harness, allocator: std.mem.Allocator) void {
        harness.evm.deinit(allocator);
        harness.state.deinit(allocator);
        harness.database.deinit();
    }

    pub fn call(
        harness: *Harness,
        fork: Fork,
        target: Address,
        input: []const u8,
        gas_limit: u64,
    ) !evm_module.Outcome {
        harness.state.begin_transaction();
        return harness.evm.execute(fork, .{
            .kind = .call,
            .caller = caller,
            .target = target,
            .input = input,
            .gas_limit = gas_limit,
        });
    }

    pub fn storage(harness: *Harness, address: Address, slot: u256) !u256 {
        const account = try harness.state.load(address);
        const access = try harness.state.storage_access(account, slot);
        return access.slot.present;
    }
};

pub const caller = primitives.address_from_int(0xca11e7);
const contract = primitives.address_from_int(0xc0de);
const other = primitives.address_from_int(0x07e7);

fn push1(value: u8) [2]u8 {
    return .{ op.PUSH1, value };
}

/// Code that returns the 32-byte word at memory 0 after `prefix` stored it.
fn return_word(comptime prefix: []const u8) []const u8 {
    return prefix ++ [_]u8{ op.PUSH1, 0, op.MSTORE, op.PUSH1, 32, op.PUSH1, 0, op.RETURN };
}

test "evm: arithmetic program returns result with exact gas" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const code = comptime return_word(&[_]u8{ op.PUSH1, 2, op.PUSH1, 3, op.ADD });
    try h.database.put_account(contract, 0, 1, code);
    const outcome = try h.call(.cancun, contract, &.{}, 100_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 5), primitives.b256_to_u256(outcome.output[0..32].*));
    // 3 + 3 + 3 (ADD) + 3 + 3 + 3 (memory) + 3 + 3 + 0 (RETURN)
    try std.testing.expectEqual(@as(u64, 100_000 - 24), outcome.gas_remaining);
}

test "evm: sstore, sload, and refund" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    // SSTORE(1, 7); SSTORE(1, 0); return SLOAD(2)
    const code = comptime return_word(&[_]u8{
        op.PUSH1, 7, op.PUSH1, 1, op.SSTORE,
        op.PUSH1, 0, op.PUSH1, 1, op.SSTORE,
        op.PUSH1, 2, op.SLOAD,
    });
    try h.database.put_account(contract, 0, 1, code);
    try h.database.put_storage(contract, 2, 0xabc);
    const outcome = try h.call(.cancun, contract, &.{}, 100_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 0xabc), primitives.b256_to_u256(outcome.output[0..32].*));
    try std.testing.expectEqual(@as(u256, 0), try h.storage(contract, 1));
    // 0 -> 7 -> 0 within a transaction refunds 20000 - 100.
    try std.testing.expectEqual(@as(i64, 19_900), outcome.gas_refund);
}

test "evm: revert undoes storage and returns data" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const code = [_]u8{
        op.PUSH1, 9,    op.PUSH1, 1, op.SSTORE,
        op.PUSH1, 0x42, op.PUSH1, 0, op.MSTORE8,
        op.PUSH1, 1,    op.PUSH1, 0, op.REVERT,
    };
    try h.database.put_account(contract, 0, 1, &code);
    const outcome = try h.call(.cancun, contract, &.{}, 100_000);
    try std.testing.expectEqual(evm_module.Status.revert, outcome.status);
    try std.testing.expectEqualSlices(u8, &.{0x42}, outcome.output);
    try std.testing.expectEqual(@as(u256, 0), try h.storage(contract, 1));
    try std.testing.expect(outcome.gas_remaining > 0);
}

test "evm: nested call returns data and propagates gas" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const callee = comptime return_word(&[_]u8{ op.PUSH1, 0x77 });
    try h.database.put_account(other, 0, 1, callee);
    // CALL(gas, other, 0, 0, 0, 0, 32) then return memory[0..32] and success flag in slot 0.
    const code = [_]u8{
        op.PUSH1, 32,        op.PUSH1,          0,        op.PUSH1, 0,         op.PUSH1, 0,
        op.PUSH1, 0,         op.PUSH2,          0x07,     0xe7,     op.GAS,    op.CALL,  op.PUSH1,
        0,        op.SSTORE, op.RETURNDATASIZE, op.PUSH1, 1,        op.SSTORE, op.PUSH1, 32,
        op.PUSH1, 0,         op.RETURN,
    };
    try h.database.put_account(contract, 0, 1, &code);
    const outcome = try h.call(.cancun, contract, &.{}, 200_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 0x77), primitives.b256_to_u256(outcome.output[0..32].*));
    try std.testing.expectEqual(@as(u256, 1), try h.storage(contract, 0));
    try std.testing.expectEqual(@as(u256, 32), try h.storage(contract, 1));
}

test "evm: a callee starts with empty return data after an earlier call returned data" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    // `other` stores its initial RETURNDATASIZE in slot (CALLDATASIZE) and returns a word.
    // An EIP-1167 proxy reads RETURNDATASIZE as a cheap zero, so a stale size corrupts the
    // calldata it forwards (Base mainnet block 53715983, transaction 3).
    const callee = [_]u8{
        op.RETURNDATASIZE, op.CALLDATASIZE, op.SSTORE, op.PUSH1, 0x77, op.PUSH1,  0,
        op.MSTORE,         op.PUSH1,        32,        op.PUSH1, 0,    op.RETURN,
    };
    try h.database.put_account(other, 0, 1, &callee);
    // CALL(gas, other, 0, 0, 0, 0, 32) with no input, then again with one byte of input.
    const call_other = [_]u8{ op.PUSH2, 0x07, 0xe7, op.GAS, op.CALL };
    const first_args = [_]u8{ op.PUSH1, 32, op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0 };
    const second_args = [_]u8{ op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 1, op.PUSH1, 0, op.PUSH1, 0 };
    const code = first_args ++ call_other ++ [_]u8{op.POP} ++ second_args ++ call_other ++
        [_]u8{op.STOP};
    try h.database.put_account(contract, 0, 1, &code);
    const outcome = try h.call(.cancun, contract, &.{}, 300_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 0), try h.storage(other, 0));
    try std.testing.expectEqual(@as(u256, 0), try h.storage(other, 1));
}

test "evm: CREATE deploys runtime code" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    // Init code: return the single byte 0xfe (INVALID) as runtime code.
    // PUSH1 0xfe PUSH1 0 MSTORE8 PUSH1 1 PUSH1 0 RETURN  (10 bytes)
    const init_code = [_]u8{ 0x60, 0xfe, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xf3 };
    // Store init code word-left-aligned at memory 0, CREATE(0, 0, 10), SSTORE(0, addr).
    var code: [64]u8 = undefined;
    var n: usize = 0;
    code[n] = op.PUSH1 + 9;
    n += 1;
    @memcpy(code[n..][0..10], &init_code);
    n += 10;
    const tail = [_]u8{
        op.PUSH1,  22 * 8,   op.SHL,   op.PUSH1,  0,        op.MSTORE,
        op.PUSH1,  10,       op.PUSH1, 0,         op.PUSH1, 0,
        op.CREATE, op.PUSH1, 0,        op.SSTORE, op.STOP,
    };
    @memcpy(code[n..][0..tail.len], &tail);
    n += tail.len;
    try h.database.put_account(contract, 0, 1, code[0..n]);
    const outcome = try h.call(.cancun, contract, &.{}, 1_000_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    const expected = evm_module.create_address(contract, 1);
    const stored = try h.storage(contract, 0);
    try std.testing.expectEqual(primitives.address_to_u256(expected), stored);
    const created = try h.state.load(expected);
    try std.testing.expectEqualSlices(u8, &.{0xfe}, created.info.code.?);
    try std.testing.expectEqual(@as(u64, 1), created.info.nonce);
    try std.testing.expectEqual(@as(u64, 2), (try h.state.load(contract)).info.nonce);
}

test "evm: self-recursion to the depth limit without native recursion" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    // SSTORE(0, SLOAD(0) + 1); CALL(gas, self, 0, 0, 0, 0, 0); STOP
    const code = [_]u8{
        op.PUSH1, 0,          op.SLOAD, op.PUSH1, 1,        op.ADD, op.PUSH1, 0, op.SSTORE,
        op.PUSH1, 0,          op.PUSH1, 0,        op.PUSH1, 0,      op.PUSH1, 0, op.PUSH1,
        0,        op.ADDRESS, op.GAS,   op.CALL,  op.STOP,
    };
    try h.database.put_account(contract, 0, 1, &code);
    const outcome = try h.call(.tangerine, contract, &.{}, 1 << 60);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    // Depth 0 through 1024 each ran once.
    try std.testing.expectEqual(@as(u256, 1025), try h.storage(contract, 0));
}

test "evm: static call forbids state changes" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const writer = [_]u8{ op.PUSH1, 1, op.PUSH1, 0, op.SSTORE, op.STOP };
    try h.database.put_account(other, 0, 1, &writer);
    // STATICCALL(gas, other, 0, 0, 0, 0) and store the result at slot 0.
    const code = [_]u8{
        op.PUSH1, 0,    op.PUSH1,  0,       op.PUSH1,      0,        op.PUSH1, 0,
        op.PUSH2, 0x07, 0xe7,      op.GAS,  op.STATICCALL, op.PUSH1, 5,        op.ADD,
        op.PUSH1, 0,    op.SSTORE, op.STOP,
    };
    try h.database.put_account(contract, 0, 1, &code);
    const outcome = try h.call(.cancun, contract, &.{}, 3_000_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 5), try h.storage(contract, 0));
    try std.testing.expectEqual(@as(u256, 0), try h.storage(other, 0));
}

test "evm: halts consume all gas" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const cases = [_][]const u8{
        &.{op.INVALID},
        &.{op.ADD},
        &.{ op.PUSH1, 3, op.JUMP },
        &.{0x0c},
        &.{ op.PUSH1, 0, op.PUSH1, 1, op.PUSH1, 0, op.RETURNDATACOPY },
    };
    for (cases, 0..) |code, i| {
        const address = primitives.address_from_int(0x1000 + i);
        try h.database.put_account(address, 0, 1, code);
        const outcome = try h.call(.cancun, address, &.{}, 50_000);
        try std.testing.expectEqual(evm_module.Status.halt, outcome.status);
        try std.testing.expectEqual(@as(u64, 0), outcome.gas_remaining);
    }
}

test "evm: opcodes undefined before their fork halt" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try h.database.put_account(contract, 0, 1, &.{ op.PUSH0, op.STOP });
    const london = try h.call(.london, contract, &.{}, 50_000);
    try std.testing.expectEqual(evm_module.Status.halt, london.status);
    const shanghai = try h.call(.shanghai, contract, &.{}, 50_000);
    try std.testing.expectEqual(evm_module.Status.success, shanghai.status);
}

const transaction = @import("transaction.zig");

const Invalid = transaction.Invalid;

fn transact(h: *Harness, tx: *const transaction.TxEnv) !transaction.Result {
    return transaction.transact(&h.evm, .cancun, tx);
}

test "transaction: value transfer pays fees and tip" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const coinbase = primitives.address_from_int(0xc0ffee);
    h.evm.block.coinbase = coinbase;
    h.evm.block.base_fee = 7;
    try h.database.put_account(caller, 1_000_000_000, 0, &.{});
    const tx = transaction.TxEnv{
        .tx_type = .eip1559,
        .caller = caller,
        .gas_limit = 50_000,
        .gas_price = 10,
        .gas_priority_fee = 2,
        .to = other,
        .value = 1000,
    };
    const result = try transaction.transact(&h.evm, .cancun, &tx);
    const executed = result.executed;
    try std.testing.expectEqual(evm_module.Status.success, executed.status);
    try std.testing.expectEqual(@as(u64, 21_000), executed.gas_used);
    const sender = try h.state.load(caller);
    try std.testing.expectEqual(@as(u256, 1_000_000_000 - 1000 - 21_000 * 9), sender.info.balance);
    try std.testing.expectEqual(@as(u64, 1), sender.info.nonce);
    try std.testing.expectEqual(@as(u256, 1000), (try h.state.load(other)).info.balance);
    try std.testing.expectEqual(@as(u256, 21_000 * 2), (try h.state.load(coinbase)).info.balance);
}

test "transaction: invalid transactions change nothing" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try h.database.put_account(caller, 100, 3, &.{});
    var tx = transaction.TxEnv{ .caller = caller, .gas_limit = 21_000, .to = other, .nonce = 3 };
    tx.gas_price = 1;
    try std.testing.expectEqual(Invalid.insufficient_funds, (try transact(&h, &tx)).invalid);
    tx.gas_price = 0;
    tx.nonce = 2;
    try std.testing.expectEqual(Invalid.nonce_too_low, (try transact(&h, &tx)).invalid);
    tx.nonce = 3;
    tx.gas_limit = 20_000;
    try std.testing.expectEqual(Invalid.intrinsic_gas_too_low, (try transact(&h, &tx)).invalid);
    try std.testing.expectEqual(@as(u64, 3), (try h.state.load(caller)).info.nonce);
}

test "transaction: create transaction deploys at sender nonce address" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try h.database.put_account(caller, 1 << 60, 5, &.{});
    const init_code = [_]u8{ 0x60, 0xfe, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xf3 };
    const tx = transaction.TxEnv{
        .caller = caller,
        .gas_limit = 100_000,
        .nonce = 5,
        .data = &init_code,
    };
    const executed = (try transaction.transact(&h.evm, .cancun, &tx)).executed;
    try std.testing.expectEqual(evm_module.Status.success, executed.status);
    const expected = evm_module.create_address(caller, 5);
    try std.testing.expectEqualSlices(u8, &expected, &executed.created.?);
    try std.testing.expectEqual(@as(u64, 6), (try h.state.load(caller)).info.nonce);
}

fn designator(target: Address) [@import("bytecode.zig").delegation_len]u8 {
    const bytecode = @import("bytecode.zig");
    var code: [bytecode.delegation_len]u8 = undefined;
    code[0..3].* = bytecode.delegation_prefix;
    code[3..23].* = target;
    return code;
}

test "evm: a delegated EOA runs its delegate's code" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const authority = primitives.address_from_int(0x07e8);
    try h.database.put_account(other, 0, 1, comptime return_word(&[_]u8{ op.PUSH1, 0x77 }));
    try h.database.put_account(authority, 0, 1, &designator(other));
    const outcome = try h.call(.prague, authority, &.{}, 200_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(@as(u256, 0x77), primitives.b256_to_u256(outcome.output[0..32].*));
}

test "evm: a delegation to a precompile runs empty code, not the precompile" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const authority = primitives.address_from_int(0x07e7);
    const identity = primitives.address_from_int(0x04);
    try h.database.put_account(authority, 0, 1, &designator(identity));
    // Top-level call: the identity precompile would echo the input.
    const direct = try h.call(.prague, authority, "echo", 200_000);
    try std.testing.expectEqual(evm_module.Status.success, direct.status);
    try std.testing.expectEqual(@as(usize, 0), direct.output.len);
    try std.testing.expectEqual(@as(u64, 200_000), direct.gas_remaining);
    // Inner CALL(gas, authority, 0, 0, 0, 0, 32): success and no return data.
    const code = [_]u8{
        op.PUSH1, 32,        op.PUSH1,          0,        op.PUSH1, 0,         op.PUSH1, 0,
        op.PUSH1, 0,         op.PUSH2,          0x07,     0xe7,     op.GAS,    op.CALL,  op.PUSH1,
        0,        op.SSTORE, op.RETURNDATASIZE, op.PUSH1, 1,        op.SSTORE, op.STOP,
    };
    try h.database.put_account(contract, 0, 1, &code);
    const inner = try h.call(.prague, contract, &.{}, 200_000);
    try std.testing.expectEqual(evm_module.Status.success, inner.status);
    try std.testing.expectEqual(@as(u256, 1), try h.storage(contract, 0));
    try std.testing.expectEqual(@as(u256, 0), try h.storage(contract, 1));
}

test "transaction: precompiles are warm by predicate, without loading, for one tx" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const ecrecover = primitives.address_from_int(1);
    const point_evaluation = primitives.address_from_int(0x0a);
    const not_precompile = primitives.address_from_int(0x12);
    h.state.begin_transaction();
    try std.testing.expect(!h.state.is_warm(ecrecover));
    try transaction.warm_system_addresses(.osaka, &h.evm);
    try std.testing.expectEqual(@as(u32, 1), h.state.accounts.count()); // The coinbase only.
    try std.testing.expect(h.state.is_warm(ecrecover));
    try std.testing.expect(h.state.is_warm(point_evaluation));
    try std.testing.expect(!(try h.state.access(ecrecover)).is_cold);
    try std.testing.expect((try h.state.access(not_precompile)).is_cold);
    h.state.begin_transaction(); // A system call or the next tx starts cold.
    try std.testing.expect(!h.state.is_warm(ecrecover));
    try std.testing.expect((try h.state.access(ecrecover)).is_cold);
}

const TraceRecorder = struct {
    events: [16][]const u8 = undefined,
    frames: [8]evm_module.TraceFrame = undefined,
    outcomes: [8]evm_module.Outcome = undefined,
    events_len: u32 = 0,
    frames_len: u32 = 0,
    outcomes_len: u32 = 0,

    fn push(recorder: *TraceRecorder, event: []const u8) void {
        std.debug.assert(recorder.events_len < recorder.events.len);
        recorder.events[recorder.events_len] = event;
        recorder.events_len += 1;
    }

    fn enter(context: *anyopaque, frame: evm_module.TraceFrame) void {
        const recorder: *TraceRecorder = @ptrCast(@alignCast(context));
        recorder.push(@tagName(frame.kind));
        recorder.frames[recorder.frames_len] = frame;
        recorder.frames_len += 1;
    }

    fn exit(context: *anyopaque, outcome: evm_module.Outcome) void {
        const recorder: *TraceRecorder = @ptrCast(@alignCast(context));
        recorder.push("exit");
        recorder.outcomes[recorder.outcomes_len] = outcome;
        recorder.outcomes_len += 1;
    }

    fn log(context: *anyopaque, _: Address, _: []const primitives.B256, _: []const u8) void {
        const recorder: *TraceRecorder = @ptrCast(@alignCast(context));
        recorder.push("log");
    }
};

test "evm: tracer sees nested calls, logs, selfdestruct, and create in order" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const a = primitives.address_from_int(0xaa);
    const b = primitives.address_from_int(0xbb);
    const beneficiary = primitives.address_from_int(0xbe);
    // A: CALL(gas, B, 0, 0, 0, 0, 0); POP; CREATE(0, 0, 0); POP; STOP.
    const code_a = [_]u8{
        op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, // CALL args.
        op.PUSH1, 0xbb, op.GAS, op.CALL, op.POP, // CALL B.
        op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, op.CREATE, op.POP, op.STOP, // CREATE.
    };
    // B: LOG0(0, 0); SELFDESTRUCT(0xbe).
    const code_b = [_]u8{ op.PUSH1, 0, op.PUSH1, 0, op.LOG0, op.PUSH1, 0xbe, op.SELFDESTRUCT };
    try h.database.put_account(a, 0, 1, &code_a);
    try h.database.put_account(b, 5, 1, &code_b);
    h.state.reset(h.database.interface());
    var recorder = TraceRecorder{};
    const tracer = evm_module.Tracer{
        .context = &recorder,
        .enter = TraceRecorder.enter,
        .exit = TraceRecorder.exit,
        .log = TraceRecorder.log,
    };
    h.evm.tracer = &tracer;
    defer h.evm.tracer = null;
    const outcome = try h.call(.osaka, a, &.{}, 1_000_000);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    const expected = [_][]const u8{
        "call", "call", "log", "selfdestruct", "exit", "exit", "create", "exit", "exit",
    };
    try std.testing.expectEqual(@as(u32, expected.len), recorder.events_len);
    for (expected, recorder.events[0..expected.len]) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
    try std.testing.expectEqual(@as(u16, 1), recorder.frames[1].depth);
    try std.testing.expectEqualSlices(u8, &b, &recorder.frames[1].to);
    try std.testing.expectEqualSlices(u8, &beneficiary, &recorder.frames[2].to);
    try std.testing.expectEqual(@as(u256, 5), recorder.frames[2].value);
    const created = evm_module.create_address(a, 1);
    try std.testing.expectEqualSlices(u8, &created, &recorder.frames[3].to);
    try std.testing.expectEqualSlices(u8, &created, &recorder.outcomes[2].created.?);
    // The top frame's exit comes last and reports the transaction's outcome.
    try std.testing.expectEqual(outcome.gas_remaining, recorder.outcomes[3].gas_remaining);
}

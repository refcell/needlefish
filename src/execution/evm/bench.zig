//! EVM micro benchmarks: interpreter loops and full transactions.
//!
//! Each case runs one call (or transaction) per iteration against a fresh state, so
//! ns/op is the cost of one execution. Gas per execution is fixed by the bytecode
//! (see `gas_per_op` in each comment) and gives Mgas/s = gas_per_op * 1000 / ns_per_op.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const transaction = @import("transaction.zig");
const Harness = @import("evm_test.zig").Harness;
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;

const fork: Fork = .prague;
const gas_limit: u64 = 30_000_000;
const caller = primitives.address_from_int(0xca11e2);
const contract = primitives.address_from_int(0xc0de);
const callee = primitives.address_from_int(0xbeef);

/// 1000 x (PUSH 3, PUSH 5, MUL, PUSH 7, ADD, POP) plus loop control.
const arithmetic_code = [_]u8{
    0x61, 0x03, 0xe8, // PUSH2 1000
    0x5b, // JUMPDEST
    0x60,
    0x03,
    0x60,
    0x05,
    0x02,
    0x60,
    0x07,
    0x01,
    0x50,
    0x60, 0x01, 0x90, 0x03, // counter - 1
    0x80, 0x60, 0x03, 0x57, // DUP1 PUSH1 3 JUMPI
    0x00,
};

/// 1000 x (MSTORE counter, KECCAK256 64 bytes, MSTORE hash).
const keccak_code = [_]u8{
    0x61, 0x03, 0xe8,
    0x5b,
    0x80, 0x60, 0x00, 0x52, // mem[0] = counter
    0x60, 0x40, 0x60, 0x00, 0x20, // keccak256(mem[0..64])
    0x60, 0x20, 0x52, // mem[32] = hash
    0x60, 0x01, 0x90,
    0x03, 0x80, 0x60,
    0x03, 0x57, 0x00,
};

/// 200 x (SSTORE(i, i) cold, SLOAD(i) warm).
const storage_code = [_]u8{
    0x60, 0xc8,
    0x5b, 0x80,
    0x80, 0x55,
    0x80, 0x54,
    0x50, 0x60,
    0x01, 0x90,
    0x03, 0x80,
    0x60, 0x02,
    0x57, 0x00,
};

/// 200 x STATICCALL into a contract that STOPs (frame push/pop cost).
const call_code = [_]u8{
    0x60, 0xc8,
    0x5b,
    0x60, 0x20, 0x60, 0x00, 0x60, 0x20, 0x60, 0x00, // ret 32@0, args 32@0
    0x61, 0xbe, 0xef, 0x5a, 0xfa, 0x50, // PUSH2 callee, GAS, STATICCALL, POP
    0x60, 0x01, 0x90, 0x03, 0x80, 0x60,
    0x02, 0x57, 0x00,
};

/// ERC-20 `transfer(to, amount)` with Solidity storage layout (balances at slot 0):
/// checks the sender balance, debits, credits, emits `Transfer`. Hand assembled.
const erc20_code = [_]u8{
    0x33, 0x60, 0x00, 0x52, // mem[0] = caller
    0x60, 0x00, 0x60, 0x20, 0x52, // mem[32] = 0 (mapping slot)
    0x60, 0x40, 0x60, 0x00, 0x20, // from_slot = keccak256(mem[0..64])
    0x80, 0x54, // from_balance
    0x60, 0x24, 0x35, // amount = calldata[36..68]
    0x81, 0x81, 0x11, // amount > from_balance
    0x60, 0x5d, 0x57, // -> revert
    0x80, 0x82, 0x03, // from_balance - amount
    0x83, 0x55, // SSTORE(from_slot)
    0x60, 0x04, 0x35, 0x60, 0x00, 0x52, // mem[0] = to
    0x60, 0x40, 0x60, 0x00, 0x20, // to_slot
    0x80, 0x54, 0x82, 0x01, 0x90, 0x55, // SSTORE(to_slot, to_balance + amount)
    0x60, 0x00, 0x52, // mem[0] = amount
    0x60, 0x04, 0x35, 0x33, // topics: to, from
    0x7f, // PUSH32 keccak256("Transfer(address,address,uint256)")
    0xdd,
    0xf2,
    0x52,
    0xad,
    0x1b,
    0xe2,
    0xc8,
    0x9b,
    0x69,
    0xc2,
    0xb0,
    0x68,
    0xfc,
    0x37,
    0x8d,
    0xaa,
    0x95,
    0x2b,
    0xa7,
    0xf1,
    0x63,
    0xc4,
    0xa1,
    0x16,
    0x28,
    0xf5,
    0x5a,
    0x4d,
    0xf5,
    0x23,
    0xb3,
    0xef,
    0x60, 0x20, 0x60, 0x00, 0xa3, // LOG3(mem[0..32])
    0x00,
    0x5b, 0x60, 0x00, 0x80, 0xfd, // revert(0, 0)
};

comptime {
    assert(erc20_code[0x5d] == 0x5b);
}

var harness_storage: Harness = undefined;
var harness_ready = false;

/// Bench binaries are single threaded; the harness is allocated once on first use.
fn harness() *Harness {
    if (!harness_ready) {
        harness_storage.init(std.heap.page_allocator) catch @panic("bench: harness init");
        harness_ready = true;
    }
    return &harness_storage;
}

fn run_code(code: []const u8, iterations: u32) u64 {
    const h = harness();
    h.database.put_account(contract, 0, 1, code) catch @panic("bench: put code");
    h.database.put_account(callee, 0, 1, &.{0x00}) catch @panic("bench: put callee");
    var gas_used: u64 = 0;
    var iteration: u32 = 0;
    while (iteration < iterations) : (iteration += 1) {
        h.state.reset(h.database.interface());
        const outcome = h.call(fork, contract, &.{}, gas_limit) catch @panic("bench: call");
        assert(outcome.status == .success);
        gas_used += gas_limit - outcome.gas_remaining;
    }
    return gas_used;
}

fn arithmetic(iterations: u32) u64 {
    return run_code(&arithmetic_code, iterations);
}

fn keccak(iterations: u32) u64 {
    return run_code(&keccak_code, iterations);
}

fn storage(iterations: u32) u64 {
    return run_code(&storage_code, iterations);
}

fn calls(iterations: u32) u64 {
    return run_code(&call_code, iterations);
}

/// One EIP-1559 value transfer: validation, gas purchase, warm-up, settlement.
fn transfer(iterations: u32) u64 {
    const h = harness();
    h.database.put_account(caller, 1 << 80, 0, &.{}) catch @panic("bench: put caller");
    h.evm.block = .{ .base_fee = 7, .gas_limit = gas_limit };
    const tx = transaction.TxEnv{
        .tx_type = .eip1559,
        .caller = caller,
        .gas_limit = 21_000,
        .gas_price = 10,
        .gas_priority_fee = 1,
        .to = callee,
        .value = 1,
    };
    var gas_used: u64 = 0;
    var iteration: u32 = 0;
    while (iteration < iterations) : (iteration += 1) {
        h.state.reset(h.database.interface());
        const result = transaction.transact(&h.evm, fork, &tx) catch @panic("bench: transact");
        gas_used += result.executed.gas_used;
    }
    return gas_used;
}

/// One ERC-20 transfer transaction: two cold slots read and written plus a log.
fn erc20_transfer(iterations: u32) u64 {
    const h = harness();
    const token = contract;
    const recipient = primitives.address_from_int(0x2ec1);
    h.database.put_account(caller, 1 << 80, 0, &.{}) catch @panic("bench: put caller");
    h.database.put_account(token, 0, 1, &erc20_code) catch @panic("bench: put token");
    var key: [64]u8 = @splat(0);
    key[12..32].* = caller;
    const slot = std.mem.readInt(u256, &keccak256(&key), .big);
    h.database.put_storage(token, slot, 1 << 64) catch @panic("bench: put balance");
    var data: [68]u8 = @splat(0);
    data[0..4].* = .{ 0xa9, 0x05, 0x9c, 0xbb }; // transfer(address,uint256)
    data[16..36].* = recipient;
    data[67] = 1;
    h.evm.block = .{ .base_fee = 7, .gas_limit = gas_limit };
    const tx = transaction.TxEnv{
        .tx_type = .eip1559,
        .caller = caller,
        .gas_limit = 100_000,
        .gas_price = 10,
        .gas_priority_fee = 1,
        .to = token,
        .data = &data,
    };
    var gas_used: u64 = 0;
    var iteration: u32 = 0;
    while (iteration < iterations) : (iteration += 1) {
        h.state.reset(h.database.interface());
        const result = transaction.transact(&h.evm, fork, &tx) catch @panic("bench: transact");
        assert(result.executed.status == .success);
        assert(result.executed.logs.len == 1);
        gas_used += result.executed.gas_used;
    }
    return gas_used;
}

const keccak256 = @import("../../common/crypto/root.zig").keccak256;
const Case = @import("../../testing/bench.zig").Case;

pub const cases = [_]Case{
    // ~96k gas: 1000 loop iterations of 13 instructions.
    .{ .name = "evm: arithmetic loop (13k ops)", .iterations = 1_000, .run = arithmetic },
    // ~150k gas: 1000 KECCAK256 of 64 bytes.
    .{ .name = "evm: keccak256 loop (1000 x 64 B)", .iterations = 500, .run = keccak },
    // ~4.9M gas: 200 cold SSTOREs and warm SLOADs.
    .{ .name = "evm: storage loop (200 sstore+sload)", .iterations = 500, .run = storage },
    // ~530k gas: 200 STATICCALLs with a cold first access.
    .{ .name = "evm: call loop (200 staticcall)", .iterations = 500, .run = calls },
    .{ .name = "evm: value transfer transaction", .iterations = 10_000, .run = transfer },
    // ~51k gas: the common token transfer path end to end.
    .{ .name = "evm: erc20 transfer transaction", .iterations = 10_000, .run = erc20_transfer },
};

test "evm bench: cases execute successfully" {
    for (cases) |case| {
        std.mem.doNotOptimizeAway(case.run(1));
    }
}

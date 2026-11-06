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
const Evm = @import("evm.zig").Evm;
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

/// 1000 x (MULMOD of two 256-bit words by a 200-bit modulus, DIV of a 256-bit word by a
/// 160-bit one): the full-precision mulDiv shape of AMM math.
// zig fmt: off
const division_code = [_]u8{
    0x61, 0x03, 0xe8, 0x5b, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x97, 0x3d, 0x9c, 0x17, 0x24, 0x11, 0xe2, 0x0b, 0x8f, 0x6b, 0x0d, 0x54,
    0x9b, 0x6f, 0x03, 0x67, 0x5a, 0x16, 0x00, 0xa3, 0x5a, 0x09, 0x99, 0x50,
    0xd8, 0x7f, 0xb6, 0xf6, 0x75, 0xcc, 0x81, 0xe7, 0x4e, 0xf5, 0xe8, 0xe2,
    0x5d, 0x94, 0x0e, 0xd9, 0x04, 0x75, 0x95, 0x31, 0x98, 0x5d, 0x5d, 0x9d,
    0xc9, 0xf8, 0x18, 0x18, 0xe8, 0x11, 0x89, 0x2f, 0x90, 0x2b, 0x7f, 0xd2,
    0x3f, 0x08, 0x24, 0x12, 0x8b, 0x2f, 0x33, 0x0c, 0x5c, 0x7f, 0xd0, 0xa6,
    0xa3, 0xa4, 0x50, 0x65, 0x13, 0x27, 0x0e, 0x26, 0x9e, 0x0d, 0x37, 0xf2,
    0xa7, 0x4d, 0xe4, 0x52, 0xe6, 0xb4, 0x38, 0x09, 0x50, 0x7f, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0xd6,
    0x30, 0xf1, 0xf2, 0x9d, 0x0d, 0xa9, 0x95, 0x3f, 0x48, 0xf1, 0xa0, 0x9f,
    0x76, 0xb5, 0xa1, 0x70, 0xb3, 0x38, 0x7f, 0xb9, 0x26, 0x30, 0x59, 0xf2,
    0x8c, 0x10, 0x5d, 0x1f, 0xb1, 0x7c, 0x23, 0x90, 0xc1, 0x92, 0xcf, 0xd3,
    0xac, 0x94, 0xaf, 0x0f, 0x21, 0xdd, 0xb6, 0x6c, 0xad, 0x4a, 0x26, 0x8d,
    0x11, 0x6e, 0xce, 0x04, 0x50, 0x60, 0x01, 0x90, 0x03, 0x80, 0x60, 0x03,
    0x57, 0x00,
};
// zig fmt: on

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

fn division(iterations: u32) u64 {
    return run_code(&division_code, iterations);
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

const block_transactions = 1000;
const block_senders = 100;
const block_recipients = 200;
var block_data: [block_transactions / 2][68]u8 = undefined;

fn block_sender(index: usize) Address {
    return primitives.address_from_int(0x5e0000 + index);
}

fn block_recipient(index: usize) Address {
    return primitives.address_from_int(0x2e0000 + index);
}

/// 100 funded senders with token balances; the erc20 calldata for every other transaction.
fn block_setup(h: *Harness) void {
    h.database.put_account(contract, 0, 1, &erc20_code) catch @panic("bench: put token");
    for (0..block_senders) |index| {
        const sender = block_sender(index);
        h.database.put_account(sender, 1 << 80, 0, &.{}) catch @panic("bench: put sender");
        var key: [64]u8 = @splat(0);
        key[12..32].* = sender;
        const slot = std.mem.readInt(u256, &keccak256(&key), .big);
        h.database.put_storage(contract, slot, 1 << 64) catch @panic("bench: put balance");
    }
    for (&block_data, 0..) |*data, index| {
        data.* = @splat(0);
        data[0..4].* = .{ 0xa9, 0x05, 0x9c, 0xbb }; // transfer(address,uint256)
        data[16..36].* = block_recipient(index % block_recipients);
        data[67] = 1;
    }
    h.evm.block = .{
        .base_fee = 7,
        .gas_limit = 150_000_000,
        .op = .{ .upgrade = .denim },
    };
}

/// One Denim-era block: 1000 EIP-1559 transactions (alternating ETH and erc20 transfers)
/// from 100 senders to 200 recipients, one state reset per block, no per-tx reset.
fn block(iterations: u32) u64 {
    const h = harness();
    block_setup(h);
    defer h.evm.block = .{};
    var gas_used: u64 = 0;
    var iteration: u32 = 0;
    while (iteration < iterations) : (iteration += 1) {
        h.state.reset(h.database.interface());
        for (0..block_transactions) |index| {
            const is_token = index % 2 == 1;
            const tx = transaction.TxEnv{
                .tx_type = .eip1559,
                .caller = block_sender(index % block_senders),
                .nonce = @intCast(index / block_senders),
                .gas_limit = if (is_token) 100_000 else 21_000,
                .gas_price = 10,
                .gas_priority_fee = 1,
                .to = if (is_token) contract else block_recipient(index % block_recipients),
                .value = if (is_token) 0 else 1,
                .data = if (is_token) &block_data[index / 2] else &.{},
            };
            const result = transaction.transact(&h.evm, fork, &tx) catch @panic("bench: block");
            assert(result.executed.status == .success);
            gas_used += result.executed.gas_used;
        }
    }
    return gas_used;
}

const keccak256 = @import("../../common/crypto/root.zig").keccak256;
const bench = @import("../../testing/bench.zig");
const Case = bench.Case;

/// `just vectors` fetches the public snailtracer bytecode (revm's bench fixture) here.
pub const snailtracer_path = ".cache/vectors/bench/snailtracer.hex";
const snailtracer_bytes_max = 32 * 1024;
const snailtracer_selector = [4]u8{ 0x30, 0x62, 0x7b, 0x7c }; // Benchmark()
var snailtracer_code: [snailtracer_bytes_max]u8 = undefined;
var snailtracer_length: u32 = 0;
var snailtracer_config = false;

/// One snailtracer `Benchmark()` call (~1.1G gas of arithmetic, memory, and jumps).
fn snailtracer(iterations: u32) u64 {
    assert(snailtracer_length > 0);
    const h = harness();
    if (!snailtracer_config) {
        // The test harness caps memory at 1 MiB; run with the production defaults.
        h.evm.deinit(std.heap.page_allocator);
        h.evm = Evm.init(std.heap.page_allocator, .{}, &h.state) catch @panic("bench: evm");
        snailtracer_config = true;
    }
    const code = snailtracer_code[0..snailtracer_length];
    h.database.put_account(contract, 0, 1, code) catch @panic("bench: put code");
    const limit: u64 = 1_000_000_000;
    var gas_used: u64 = 0;
    var iteration: u32 = 0;
    while (iteration < iterations) : (iteration += 1) {
        h.state.reset(h.database.interface());
        const outcome = h.call(fork, contract, &snailtracer_selector, limit) catch
            @panic("bench: call");
        assert(outcome.status == .success);
        gas_used += limit - outcome.gas_remaining;
    }
    return gas_used;
}

const fixture_cases = [_]Case{
    .{ .name = "evm: snailtracer", .iterations = 20, .run = snailtracer },
};

/// Cases whose bytecode is a fetched fixture; skipped (with a note) when it is missing.
pub fn run_fixtures(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches(fixture_cases[0].name, filter)) return;
    load_snailtracer(io) catch |err| {
        std.debug.print("evm: snailtracer skipped ({s}; run `just vectors`)\n", .{
            @errorName(err),
        });
        return;
    };
    bench.run_cases(io, fixture_cases, filter);
}

fn load_snailtracer(io: std.Io) !void {
    var text: [2 * snailtracer_bytes_max + 16]u8 = undefined;
    const read = try std.Io.Dir.cwd().readFile(io, snailtracer_path, &text);
    const hex = std.mem.trim(u8, read, " \n\r\t");
    if (hex.len % 2 != 0 or hex.len / 2 > snailtracer_bytes_max) return error.BadFixture;
    const code = try std.fmt.hexToBytes(&snailtracer_code, hex);
    snailtracer_length = @intCast(code.len);
    assert(snailtracer_length == hex.len / 2);
}

pub const cases = [_]Case{
    // ~96k gas: 1000 loop iterations of 13 instructions.
    .{ .name = "evm: arithmetic loop (13k ops)", .iterations = 1_000, .run = arithmetic },
    // ~56k gas: 1000 MULMOD (512-bit by 200-bit) and DIV (256-bit by 160-bit).
    .{ .name = "evm: mulmod+div loop (1000 x)", .iterations = 500, .run = division },
    // ~150k gas: 1000 KECCAK256 of 64 bytes.
    .{ .name = "evm: keccak256 loop (1000 x 64 B)", .iterations = 500, .run = keccak },
    // ~4.9M gas: 200 cold SSTOREs and warm SLOADs.
    .{ .name = "evm: storage loop (200 sstore+sload)", .iterations = 500, .run = storage },
    // ~530k gas: 200 STATICCALLs with a cold first access.
    .{ .name = "evm: call loop (200 staticcall)", .iterations = 500, .run = calls },
    .{ .name = "evm: value transfer transaction", .iterations = 10_000, .run = transfer },
    // ~51k gas: the common token transfer path end to end.
    .{ .name = "evm: erc20 transfer transaction", .iterations = 10_000, .run = erc20_transfer },
    // ~36M gas: 500 transfers + 500 erc20 transfers through the OP (Denim) tx envelope.
    .{ .name = "evm: block of 1000 transactions", .iterations = 20, .run = block },
};

test "evm bench: cases execute successfully" {
    for (cases) |case| {
        std.mem.doNotOptimizeAway(case.run(1));
    }
}

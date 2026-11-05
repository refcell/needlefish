//! Workload contracts, hand-assembled EVM bytecode (base/base deploys solc-compiled
//! `StorageFiller`, `PrecompileLooper`, and ERC-20 tokens; needlefish has no compiler, so
//! the contracts are small and written opcode by opcode here).
//!
//! - `token`: a minimal ERC-20. `transfer(address,uint256)` moves balance from the caller
//!   (reverts when short) and returns true; `balanceOf(address)`; `mint(address,uint256)`
//!   is an open faucet (anyone may mint; a load-test token, never a real asset). Balances
//!   live at storage slot = address. Transfers and mints log `Transfer`.
//! - `storage`: calldata words `[first_slot, count, value]`; writes `value` to slots
//!   `first_slot .. first_slot + count`. No selector.
//! - `looper`: calldata word `[iterations]`; spins that many loop iterations (40 gas each)
//!   and stops. No selector.
//!
//! Every contract is deployed by `init_code(runtime)`, a 12-byte prefix that copies the
//! runtime that follows it into memory and returns it.

const std = @import("std");
const assert = std.debug.assert;

const txdata = @import("../../batcher/txdata/root.zig");

// Opcodes used below (Ethereum yellow paper numbering).
const STOP = 0x00;
const ADD = 0x01;
const SUB = 0x03;
const LT = 0x10;
const EQ = 0x14;
const ISZERO = 0x15;
const SHR = 0x1c;
const CALLER = 0x33;
const CALLDATALOAD = 0x35;
const CODECOPY = 0x39;
const MSTORE = 0x52;
const SLOAD = 0x54;
const SSTORE = 0x55;
const JUMP = 0x56;
const JUMPI = 0x57;
const JUMPDEST = 0x5b;
const PUSH1 = 0x60;
const PUSH2 = 0x61;
const DUP1 = 0x80;
const DUP2 = 0x81;
const DUP3 = 0x82;
const SWAP1 = 0x90;
const LOG3 = 0xa3;
const RETURN = 0xf3;
const REVERT = 0xfd;

/// `transfer(address,uint256)`.
pub const selector_transfer = [4]u8{ 0xa9, 0x05, 0x9c, 0xbb };
/// `balanceOf(address)`.
pub const selector_balance_of = [4]u8{ 0x70, 0xa0, 0x82, 0x31 };
/// `mint(address,uint256)`.
pub const selector_mint = [4]u8{ 0x40, 0xc1, 0x0f, 0x19 };
/// keccak256("Transfer(address,address,uint256)").
pub const transfer_topic = [32]u8{
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
};

const Label = enum(u8) { transfer, balance_of, mint, fail, loop, done };
const label_count = std.enums.values(Label).len;

/// One assembler item: an opcode, a PUSHn of literal bytes, a jump target (JUMPDEST), or a
/// PUSH2 of a label's offset.
const Item = union(enum) {
    op: u8,
    push: []const u8,
    label: Label,
    target: Label,

    fn size(item: Item) usize {
        return switch (item) {
            .op, .label => 1,
            .push => |bytes| 1 + bytes.len,
            .target => 3,
        };
    }
};

fn o(comptime opcode: u8) Item {
    return .{ .op = opcode };
}

fn p1(comptime value: u8) Item {
    return .{ .push = &[_]u8{value} };
}

fn code_size(comptime items: []const Item) usize {
    var total: usize = 0;
    for (items) |item| total += item.size();
    return total;
}

/// Two passes: label offsets, then bytes. Every referenced label must be defined once.
fn assemble(comptime items: []const Item) [code_size(items)]u8 {
    @setEvalBranchQuota(100_000);
    var offsets: [label_count]?u16 = @splat(null);
    var position: usize = 0;
    for (items) |item| {
        if (item == .label) {
            assert(offsets[@backingInt(item.label)] == null);
            offsets[@backingInt(item.label)] = position;
        }
        position += item.size();
    }
    var code: [code_size(items)]u8 = undefined;
    position = 0;
    for (items) |item| {
        switch (item) {
            .op => |opcode| code[position] = opcode,
            .label => code[position] = JUMPDEST,
            .push => |bytes| {
                assert(bytes.len >= 1 and bytes.len <= 32);
                code[position] = PUSH1 + bytes.len - 1;
                @memcpy(code[position + 1 ..][0..bytes.len], bytes);
            },
            .target => |label| {
                const offset = offsets[@backingInt(label)].?;
                code[position] = PUSH2;
                std.mem.writeInt(u16, code[position + 1 ..][0..2], offset, .big);
            },
        }
        position += item.size();
    }
    assert(position == code.len);
    return code;
}

/// Shared tail: return the 32-byte word on top of the stack.
const return_top = [_]Item{ p1(0), o(MSTORE), p1(32), p1(0), o(RETURN) };

/// `if (selector == expected) goto label`, keeping the selector on the stack.
fn jump_if_selector(comptime expected: *const [4]u8, comptime label: Label) [5]Item {
    return .{ o(DUP1), .{ .push = expected }, o(EQ), .{ .target = label }, o(JUMPI) };
}

/// `balance[to] += amount` for stack [to, amount]; leaves [to, amount].
const credit = [_]Item{ o(DUP2), o(DUP2), o(SLOAD), o(ADD), o(DUP2), o(SSTORE) };

/// ERC-20 runtime. Stack comments list the top first.
pub const token_runtime = assemble(&(
    // Dispatch on selector = calldata[0..4]; anything else reverts.
    [_]Item{ p1(0), o(CALLDATALOAD), p1(0xe0), o(SHR) } ++
        jump_if_selector(&selector_transfer, .transfer) ++
        jump_if_selector(&selector_balance_of, .balance_of) ++
        jump_if_selector(&selector_mint, .mint) ++
        [_]Item{ .{ .label = .fail }, p1(0), o(DUP1), o(REVERT) } ++
        // balanceOf(owner): return sload(owner).
        [_]Item{ .{ .label = .balance_of }, p1(4), o(CALLDATALOAD), o(SLOAD) } ++ return_top ++
        // transfer(to, amount): [amount] -> [balance, amount] -> fail if balance < amount.
        [_]Item{ .{ .label = .transfer }, p1(36), o(CALLDATALOAD), o(CALLER), o(SLOAD) } ++
        [_]Item{ o(DUP2), o(DUP2), o(LT), .{ .target = .fail }, o(JUMPI) } ++
        // balance[caller] = balance - amount; [amount] -> [to, amount].
        [_]Item{ o(DUP2), o(SWAP1), o(SUB), o(CALLER), o(SSTORE), p1(4), o(CALLDATALOAD) } ++
        credit ++
        // memory[0] = amount; log3(0, 32, Transfer, caller, to); return true.
        [_]Item{ o(DUP2), p1(0), o(MSTORE), o(CALLER), .{ .push = &transfer_topic } } ++
        [_]Item{ p1(32), p1(0), o(LOG3), p1(1) } ++ return_top ++
        // mint(to, amount): [to, amount]; credit; log3(0, 32, Transfer, 0, to); stop.
        [_]Item{ .{ .label = .mint }, p1(36), o(CALLDATALOAD), p1(4), o(CALLDATALOAD) } ++
        credit ++
        [_]Item{ o(DUP2), p1(0), o(MSTORE), p1(0), .{ .push = &transfer_topic } } ++
        [_]Item{ p1(32), p1(0), o(LOG3), o(STOP) }));

/// Storage writer runtime: `for (i = 0; i < count; i++) sstore(first_slot + i, value)`.
pub const storage_runtime = assemble(&(
    // [count, first_slot, value]
    [_]Item{ p1(64), o(CALLDATALOAD), p1(0), o(CALLDATALOAD), p1(32), o(CALLDATALOAD) } ++
        // loop: if count == 0 goto done; sstore(slot, value).
        [_]Item{ .{ .label = .loop }, o(DUP1), o(ISZERO), .{ .target = .done }, o(JUMPI) } ++
        [_]Item{ o(DUP3), o(DUP3), o(SSTORE) } ++
        // [count - 1, slot + 1, value]; goto loop.
        [_]Item{ p1(1), o(SWAP1), o(SUB), o(SWAP1), p1(1), o(ADD), o(SWAP1) } ++
        [_]Item{ .{ .target = .loop }, o(JUMP), .{ .label = .done }, o(STOP) }));

/// Looper runtime: `n = calldata[0..32]; while (n != 0) n -= 1`.
pub const looper_runtime = assemble(&([_]Item{ p1(0), o(CALLDATALOAD) } ++
    [_]Item{ .{ .label = .loop }, o(DUP1), o(ISZERO), .{ .target = .done }, o(JUMPI) } ++
    [_]Item{ p1(1), o(SWAP1), o(SUB), .{ .target = .loop }, o(JUMP) } ++
    [_]Item{ .{ .label = .done }, o(STOP) }));

const init_prefix_bytes = 12;

/// Init code: `codecopy(0, 12, len(runtime)); return(0, len(runtime))` ++ runtime.
pub fn init_code(comptime runtime: []const u8) [init_prefix_bytes + runtime.len]u8 {
    comptime assert(runtime.len > 0 and runtime.len <= 0xffff);
    const length: u16 = runtime.len;
    const prefix = [init_prefix_bytes]u8{
        PUSH2, @intCast(length >> 8), @intCast(length & 0xff), DUP1, // [len, len]
        PUSH1, init_prefix_bytes, PUSH1, 0, CODECOPY, // memory[0..len] = runtime; [len]
        PUSH1, 0, RETURN, // return(0, len)
    };
    return prefix ++ runtime[0..runtime.len].*;
}

pub const token_init = init_code(&token_runtime);
pub const storage_init = init_code(&storage_runtime);
pub const looper_init = init_code(&looper_runtime);

pub const Kind = enum(u8) { token, storage, looper };

pub fn init_code_of(kind: Kind) []const u8 {
    return switch (kind) {
        .token => &token_init,
        .storage => &storage_init,
        .looper => &looper_init,
    };
}

pub fn runtime_of(kind: Kind) []const u8 {
    return switch (kind) {
        .token => &token_runtime,
        .storage => &storage_runtime,
        .looper => &looper_runtime,
    };
}

/// Gas for a creation transaction: calldata (with the EIP-7623 floor), the 32000 creation
/// charge, EIP-3860 init code words, the 200-per-byte code deposit, and 100 for the prefix.
pub fn deploy_gas(kind: Kind) u64 {
    const code = init_code_of(kind);
    const words: u64 = (code.len + 31) / 32;
    const deposit = 200 * runtime_of(kind).len;
    const gas = txdata.calldata_gas(code) + 32_000 + 2 * words + deposit + 100;
    assert(gas > 53_000);
    assert(gas < 1_000_000);
    return gas;
}

/// Execution gas per storage slot: a cold zero to non-zero SSTORE (22100) plus 58 for the
/// loop body; written to fresh slots with a non-zero value, so this is exact.
pub const storage_gas_per_slot: u64 = 22_100 + 58;
/// Execution gas outside the loop: argument loads and the final check.
pub const storage_gas_base: u64 = 18 + 20 + 1;
/// Execution gas per looper iteration.
pub const looper_gas_per_iteration: u64 = 40;
/// Execution gas of the looper outside its iterations.
pub const looper_gas_base: u64 = 6 + 20 + 1;
/// Execution gas bound for a token transfer to a fresh recipient: cold sender and
/// recipient loads, one dirtying and one zero-to-non-zero SSTORE, LOG3, and dispatch.
pub const token_transfer_gas: u64 = 2_100 + 2_900 + 2_100 + 20_000 + 1_756 + 500;
/// Execution gas bound for a mint to a fresh holder.
pub const token_mint_gas: u64 = 2_100 + 20_000 + 1_756 + 500;

test {
    _ = @import("contracts_test.zig");
}

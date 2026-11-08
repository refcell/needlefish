//! The bytecode interpreter: runs one frame until it halts or requests a call/create.
//!
//! Dispatch is a labeled `switch` with `continue :dispatch`, which compiles to a
//! threaded jump table: each opcode handler jumps straight to the next handler.
//! Every arm is instantiated with a comptime opcode *and* comptime fork, so stack
//! bounds, static gas, and fork rules are constants in the generated code.
//!
//! The program counter, the remaining gas, and the stack (pointer and length) live in
//! `Registers`, a local the compiler keeps in machine registers, as evm2 does. Opcodes that
//! touch only those (arithmetic, stack, PUSH, jumps) run on them directly; every other opcode
//! is a sync point: the registers are written to the frame, the opcode runs on the frame, and
//! the registers are reloaded (evm2's `DYNAMIC_GAS`/`HOOKED` instructions).
//!
//! The loop is bounded by gas: every instruction that does not exit costs >= 1 gas.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const op = @import("opcode.zig");
const gas = @import("gas.zig");
const uint = @import("uint.zig");
const memory_module = @import("memory.zig");
const stack_module = @import("stack.zig");
const bytecode = @import("bytecode.zig");
const opcode_profile = @import("opcode_profile.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const Fork = @import("fork.zig").Fork;
const Evm = evm_module.Evm;
const Frame = evm_module.Frame;
const Exit = evm_module.Exit;
const CallKind = evm_module.CallKind;

const Stack = stack_module.Stack;

/// Interpreter state kept in machine registers between opcodes; `Frame` holds the
/// authoritative copy only at sync points and when `run` returns.
const Registers = struct {
    pc: u32,
    gas: u64,
    stack: Stack,
};

/// Run `frame` in place until it exits.
pub fn run(comptime fork: Fork, evm: *Evm, frame: *Frame) Exit {
    @setEvalBranchQuota(100_000);
    const f = frame;
    // Immutable for the frame's lifetime: loaded once, not through `f` after every store.
    const analyzed = f.analyzed;
    var registers = Registers{ .pc = f.pc, .gas = f.gas, .stack = f.stack };
    const r = &registers;
    // Set when a step halts. A plain `bool` continue flag instead of a `?Exit` result: Zig
    // lowered the optional to a load from a constant global, and a branch, on every opcode.
    var exit: Exit = undefined;
    loop: {
        dispatch: switch (analyzed.code[r.pc]) {
            inline else => |opcode| {
                const start = opcode_profile.now();
                defer opcode_profile.record(opcode, start);
                if (!step(fork, opcode, r, &analyzed, f, evm, &exit)) break :loop;
                continue :dispatch analyzed.code[r.pc];
            },
        }
    }
    f.pc = r.pc;
    f.gas = r.gas;
    f.stack.len = r.stack.len;
    assert(f.stack.items == r.stack.items);
    assert(frame.stack.len <= 1024);
    return exit;
}

inline fn step(
    comptime fork: Fork,
    comptime opcode: u8,
    r: *Registers,
    analyzed: *const bytecode.Analyzed,
    f: *Frame,
    evm: *Evm,
    exit: *Exit,
) bool {
    @setEvalBranchQuota(100_000);
    if (comptime !op.is_defined(fork, opcode) or opcode == op.INVALID) {
        exit.* = .invalid_opcode;
        return false;
    }
    const inputs: u32 = comptime op.table[opcode].inputs;
    const outputs: u32 = comptime op.table[opcode].outputs;
    if (comptime inputs > 0 or outputs > 0) {
        // One compare for both bounds: `len < inputs` wraps to a huge value, and otherwise
        // `len - inputs + outputs > 1024` overflows the stack.
        if (r.stack.len -% inputs > stack_module.limit - outputs) {
            @branchHint(.cold);
            exit.* = if (r.stack.len < inputs) .stack_underflow else .stack_overflow;
            return false;
        }
    }
    const cost = comptime gas.static_cost(fork, opcode);
    if (comptime cost > 0) {
        if (r.gas < cost) {
            @branchHint(.cold);
            exit.* = .out_of_gas;
            return false;
        }
        r.gas -= cost;
    }
    r.pc += 1;
    if (comptime in_registers(opcode)) {
        return execute_registers(fork, opcode, r, analyzed, f, evm, exit);
    }
    // Sync point: the opcode reads or writes frame state beyond the registers.
    f.pc = r.pc;
    f.gas = r.gas;
    f.stack.len = r.stack.len;
    const result = execute(fork, opcode, f, evm);
    r.pc = f.pc;
    r.gas = f.gas;
    r.stack.len = f.stack.len;
    if (result) |halt| {
        exit.* = halt;
        return false;
    }
    return true;
}

/// Opcodes that run on the registers: they read frame and block fields and may charge memory
/// expansion from the gas register, but never call into state, return, or start a frame.
fn in_registers(comptime opcode: u8) bool {
    return switch (opcode) {
        op.STOP, op.ADD, op.MUL, op.SUB, op.DIV, op.SDIV, op.MOD, op.SMOD => true,
        op.ADDMOD, op.MULMOD, op.SIGNEXTEND, op.LT, op.GT, op.SLT, op.SGT, op.EQ => true,
        op.ISZERO, op.AND, op.OR, op.XOR, op.NOT, op.BYTE, op.SHL, op.SHR, op.SAR => true,
        op.CLZ, op.PUSH0, op.POP, op.JUMP, op.JUMPI, op.JUMPDEST, op.PC, op.MSIZE => true,
        op.GAS, op.PUSH1...op.PUSH32, op.DUP1...op.DUP16, op.SWAP1...op.SWAP16 => true,
        op.MLOAD, op.MSTORE, op.MSTORE8, op.MCOPY => true,
        op.ADDRESS, op.ORIGIN, op.CALLER, op.CALLVALUE, op.CALLDATALOAD => true,
        op.CALLDATASIZE, op.CODESIZE, op.GASPRICE, op.RETURNDATASIZE, op.CHAINID => true,
        op.COINBASE, op.TIMESTAMP, op.NUMBER, op.PREVRANDAO, op.GASLIMIT, op.BASEFEE => true,
        op.BLOBHASH, op.BLOBBASEFEE => true,
        else => false,
    };
}

inline fn execute_registers(
    comptime fork: Fork,
    comptime opcode: u8,
    r: *Registers,
    analyzed: *const bytecode.Analyzed,
    f: *Frame,
    evm: *const Evm,
    exit: *Exit,
) bool {
    const s = &r.stack;
    switch (opcode) {
        op.STOP => {
            exit.* = .stop;
            return false;
        },
        op.ADD => binary(s, add),
        op.MUL => binary(s, mul),
        op.SUB => binary(s, sub),
        op.DIV => binary(s, div),
        op.SDIV => binary(s, sdiv),
        op.MOD => binary(s, mod),
        op.SMOD => binary(s, smod),
        op.ADDMOD => ternary(s, addmod),
        op.MULMOD => ternary(s, mulmod),
        op.SIGNEXTEND => binary(s, signextend),
        op.LT => binary(s, lt),
        op.GT => binary(s, gt),
        op.SLT => binary(s, slt),
        op.SGT => binary(s, sgt),
        op.EQ => binary(s, eq),
        op.ISZERO => s.peek(0).* = @intFromBool(s.peek(0).* == 0),
        op.AND => binary(s, bit_and),
        op.OR => binary(s, bit_or),
        op.XOR => binary(s, bit_xor),
        op.NOT => s.peek(0).* = ~s.peek(0).*,
        op.BYTE => binary(s, byte),
        op.SHL => binary(s, shl),
        op.SHR => binary(s, shr),
        op.SAR => binary(s, sar),
        op.CLZ => s.peek(0).* = @clz(s.peek(0).*),
        op.PUSH0 => s.push(0),
        op.PUSH1...op.PUSH32 => push(opcode - op.PUSH1 + 1, r, analyzed),
        op.DUP1...op.DUP16 => s.dup(opcode - op.DUP1 + 1),
        op.SWAP1...op.SWAP16 => s.swap(opcode - op.SWAP1 + 1),
        op.POP => _ = s.pop(),
        op.JUMP, op.JUMPI => if (!jump(opcode == op.JUMPI, r, analyzed)) {
            exit.* = .invalid_jump;
            return false;
        },
        op.JUMPDEST => {},
        op.PC => s.push(r.pc - 1),
        op.MSIZE => s.push(f.memory.len),
        op.GAS => s.push(r.gas),
        op.MLOAD, op.MSTORE, op.MSTORE8, op.MCOPY => {
            if (!memory_op(opcode, s, &f.memory, &r.gas)) {
                exit.* = .out_of_gas;
                return false;
            }
        },
        else => environment_value(fork, opcode, s, f, evm),
    }
    return true;
}

/// Sync-point opcodes: run on the frame (`f.pc`, `f.gas`, `f.stack` are current).
fn execute(comptime fork: Fork, comptime opcode: u8, f: *Frame, evm: *Evm) ?Exit {
    comptime assert(!in_registers(opcode));
    const s = &f.stack;
    switch (opcode) {
        op.EXP => return exp(fork, f),
        op.KECCAK256 => return keccak(f),
        op.ADDRESS...op.BLOBBASEFEE => return environment(fork, opcode, f, evm),
        op.SLOAD => return sload(fork, f, evm),
        op.SSTORE => return sstore(fork, f, evm),
        op.TLOAD => s.peek(0).* = evm.state.transient_load(f.address, s.peek(0).*),
        op.TSTORE => return tstore(f, evm),
        op.LOG0...op.LOG4 => return log(opcode - op.LOG0, f, evm),
        op.CREATE => return create(fork, false, f, evm),
        op.CREATE2 => return create(fork, true, f, evm),
        op.CALL => return call(fork, .call, f, evm),
        op.CALLCODE => return call(fork, .callcode, f, evm),
        op.DELEGATECALL => return call(fork, .delegatecall, f, evm),
        op.STATICCALL => return call(fork, .staticcall, f, evm),
        op.RETURN => return output(f, .return_),
        op.REVERT => return output(f, .revert),
        op.SELFDESTRUCT => return self_destruct(fork, f, evm),
        else => return .invalid_opcode,
    }
    return null;
}

// ------------------------------------------------------------------ arithmetic

inline fn binary(s: *Stack, comptime function: anytype) void {
    const a = s.pop();
    const b = s.peek(0);
    b.* = function(a, b.*);
}

inline fn ternary(s: *Stack, comptime function: anytype) void {
    const a = s.pop();
    const b = s.pop();
    const c = s.peek(0);
    c.* = function(a, b, c.*);
}

pub fn add(a: u256, b: u256) u256 {
    return a +% b;
}
pub fn mul(a: u256, b: u256) u256 {
    return a *% b;
}
pub fn sub(a: u256, b: u256) u256 {
    return a -% b;
}
// Division goes through `uint`: LLVM's generic u256 division is ~100x slower.
pub fn div(a: u256, b: u256) u256 {
    return uint.div(a, b);
}
pub fn mod(a: u256, b: u256) u256 {
    return uint.rem(a, b);
}

const sign_bit: u256 = 1 << 255;

fn magnitude(x: u256) u256 {
    return if (x & sign_bit != 0) 0 -% x else x;
}

/// Two's-complement division truncating toward zero; minInt / -1 wraps to minInt.
pub fn sdiv(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    const quotient = uint.div(magnitude(a), magnitude(b));
    const negative = (a ^ b) & sign_bit != 0;
    return if (negative) 0 -% quotient else quotient;
}

/// The remainder takes the sign of the dividend.
pub fn smod(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    const remainder = uint.rem(magnitude(a), magnitude(b));
    return if (a & sign_bit != 0) 0 -% remainder else remainder;
}

pub fn addmod(a: u256, b: u256, n: u256) u256 {
    if (n == 0) return 0;
    const sum = @as(u320, a) + b;
    return uint.div_rem(u320, sum, n).remainder;
}

pub fn mulmod(a: u256, b: u256, n: u256) u256 {
    if (n == 0) return 0;
    if (a == 0 or b == 0) return 0;
    const product = uint.wide_mul(a, b);
    // `mulmod(a, b, not(0))` is how full-precision mulDiv (Uniswap FullMath) gets the
    // product's high word; 2^256 = 1 mod (2^256 - 1), so it reduces to hi + lo.
    if (n == std.math.maxInt(u256)) return uint.reduce_all_ones(product);
    return uint.div_rem(u512, product, n).remainder;
}

pub fn exponent(base: u256, power: u256) u256 {
    var result: u256 = 1;
    var square = base;
    var remaining = power;
    while (remaining != 0) {
        if (remaining & 1 == 1) result *%= square;
        square *%= square;
        remaining >>= 1;
    }
    return result;
}

fn exp(comptime fork: Fork, f: *Frame) ?Exit {
    const base = f.stack.pop();
    const power = f.stack.peek(0);
    const cost = gas.exp_cost(fork, power.*) - gas.high;
    if (f.gas < cost) return .out_of_gas;
    f.gas -= cost;
    power.* = exponent(base, power.*);
    return null;
}

pub fn signextend(index: u256, value: u256) u256 {
    if (index >= 31) return value;
    const shift: u8 = @intCast(248 - index * 8);
    const shifted: i256 = @bitCast(value << shift);
    return @bitCast(shifted >> shift);
}

pub fn lt(a: u256, b: u256) u256 {
    return @intFromBool(a < b);
}
pub fn gt(a: u256, b: u256) u256 {
    return @intFromBool(a > b);
}
pub fn slt(a: u256, b: u256) u256 {
    return @intFromBool(@as(i256, @bitCast(a)) < @as(i256, @bitCast(b)));
}
pub fn sgt(a: u256, b: u256) u256 {
    return @intFromBool(@as(i256, @bitCast(a)) > @as(i256, @bitCast(b)));
}
pub fn eq(a: u256, b: u256) u256 {
    return @intFromBool(a == b);
}
pub fn bit_and(a: u256, b: u256) u256 {
    return a & b;
}
pub fn bit_or(a: u256, b: u256) u256 {
    return a | b;
}
pub fn bit_xor(a: u256, b: u256) u256 {
    return a ^ b;
}

pub fn byte(index: u256, value: u256) u256 {
    if (index >= 32) return 0;
    const shift: u8 = @intCast(8 * (31 - index));
    return (value >> shift) & 0xff;
}

pub fn shl(shift: u256, value: u256) u256 {
    if (shift >= 256) return 0;
    return value << @intCast(shift);
}

pub fn shr(shift: u256, value: u256) u256 {
    if (shift >= 256) return 0;
    return value >> @intCast(shift);
}

pub fn sar(shift: u256, value: u256) u256 {
    const signed: i256 = @bitCast(value);
    if (shift >= 256) return if (signed < 0) std.math.maxInt(u256) else 0;
    return @bitCast(signed >> @intCast(shift));
}

// ------------------------------------------------------------------ memory

pub const Range = struct { offset: u64, size: u64 };

/// Charge `gas_left` for and grow `memory` to cover `[offset, offset + size)`.
inline fn memory_range(memory: *Memory, gas_left: *u64, offset: u256, size: u256) ?Range {
    if (size == 0) return .{ .offset = 0, .size = 0 };
    if (offset > std.math.maxInt(u32) or size > std.math.maxInt(u32)) return null;
    const range = Range{ .offset = @intCast(offset), .size = @intCast(size) };
    const end = range.offset + range.size;
    // Within the active size (the common case) nothing is charged or grown.
    if (end <= memory.len) return range;
    const cost = memory.expansion_cost(range.offset, range.size) orelse return null;
    if (gas_left.* < cost) return null;
    gas_left.* -= cost;
    memory.grow(end);
    assert(memory.len >= end);
    return range;
}

const Memory = memory_module.Memory;

fn charge_copy(gas_left: *u64, size: u64) bool {
    const cost = gas.copy_cost(size);
    if (gas_left.* < cost) return false;
    gas_left.* -= cost;
    return true;
}

/// MLOAD, MSTORE, MSTORE8, MCOPY: run on the registers (`gas_left` is the gas register).
/// False when the gas cannot pay for the expansion or copy (out of gas).
inline fn memory_op(comptime opcode: u8, s: *Stack, memory: *Memory, gas_left: *u64) bool {
    switch (opcode) {
        op.MLOAD => {
            const offset = s.peek(0);
            const range = memory_range(memory, gas_left, offset.*, 32) orelse return false;
            offset.* = primitives.word_from_be(memory.word(range.offset));
        },
        op.MSTORE => {
            const offset = s.pop();
            const value = s.pop();
            const range = memory_range(memory, gas_left, offset, 32) orelse return false;
            primitives.word_to_be(memory.word(range.offset), value);
        },
        op.MSTORE8 => {
            const offset = s.pop();
            const value = s.pop();
            const range = memory_range(memory, gas_left, offset, 1) orelse return false;
            memory.slice(range.offset, 1)[0] = @truncate(value);
        },
        op.MCOPY => {
            const destination = s.pop();
            const source = s.pop();
            const size = s.pop();
            if (size == 0) return true;
            const end = @max(destination, source);
            const range = memory_range(memory, gas_left, end, size) orelse return false;
            if (!charge_copy(gas_left, range.size)) return false;
            const bytes = memory.bytes;
            const src: usize = @intCast(source);
            const dst: usize = @intCast(destination);
            const count: usize = @intCast(size);
            if (dst <= src) {
                std.mem.copyForwards(u8, bytes[dst..][0..count], bytes[src..][0..count]);
            } else {
                std.mem.copyBackwards(u8, bytes[dst..][0..count], bytes[src..][0..count]);
            }
        },
        else => comptime unreachable,
    }
    return true;
}

fn keccak(f: *Frame) ?Exit {
    const offset = f.stack.pop();
    const size = f.stack.peek(0);
    const range = memory_range(&f.memory, &f.gas, offset, size.*) orelse return .out_of_gas;
    const cost = gas.keccak256_word * gas.words_for(range.size);
    if (f.gas < cost) return .out_of_gas;
    f.gas -= cost;
    const data = f.memory.slice(range.offset, range.size);
    size.* = primitives.b256_to_u256(primitives.keccak256(data));
    return null;
}

/// Copy `source` (zero-padded) into memory: CALLDATACOPY, CODECOPY, EXTCODECOPY.
fn copy_to_memory(
    f: *Frame,
    memory_offset: u256,
    source: []const u8,
    offset: u256,
    size: u256,
) ?Exit {
    const range = memory_range(&f.memory, &f.gas, memory_offset, size) orelse return .out_of_gas;
    if (!charge_copy(&f.gas, range.size)) return .out_of_gas;
    if (range.size == 0) return null;
    memory_module.copy_padded(f.memory.slice(range.offset, range.size), source, offset);
    return null;
}

// ------------------------------------------------------------------ control flow

inline fn push(comptime size: u8, r: *Registers, analyzed: *const bytecode.Analyzed) void {
    comptime assert(size >= 1 and size <= 32);
    // The code is padded, so an immediate running past the end reads zeros.
    const immediate = analyzed.code[r.pc..][0..size];
    const value: u256 = if (size <= 8) blk: {
        var buffer: [8]u8 = @splat(0);
        buffer[8 - size ..].* = immediate.*;
        break :blk std.mem.readInt(u64, &buffer, .big);
    } else blk: {
        var buffer: [32]u8 = @splat(0);
        buffer[32 - size ..].* = immediate.*;
        break :blk primitives.word_from_be(&buffer);
    };
    r.stack.push(value);
    r.pc += size;
}

/// JUMP, or JUMPI when `conditional`. False on a jump to a non-JUMPDEST (invalid jump).
inline fn jump(
    comptime conditional: bool,
    r: *Registers,
    analyzed: *const bytecode.Analyzed,
) bool {
    const destination = r.stack.pop();
    if (conditional) {
        const condition = r.stack.pop();
        if (condition == 0) return true;
    }
    if (!analyzed.is_jumpdest(destination)) return false;
    r.pc = @intCast(destination);
    return true;
}

fn output(f: *Frame, comptime exit: Exit) ?Exit {
    const offset = f.stack.pop();
    const size = f.stack.pop();
    const range = memory_range(&f.memory, &f.gas, offset, size) orelse return .out_of_gas;
    f.output_offset = range.offset;
    f.output_size = range.size;
    return exit;
}

// ------------------------------------------------------------------ environment

/// Environment reads that only push a frame, transaction, or block value (register opcodes).
inline fn environment_value(
    comptime fork: Fork,
    comptime opcode: u8,
    s: *Stack,
    f: *const Frame,
    evm: *const Evm,
) void {
    switch (opcode) {
        op.ADDRESS => s.push(primitives.address_to_u256(f.address)),
        op.ORIGIN => s.push(primitives.address_to_u256(evm.tx.origin)),
        op.CALLER => s.push(primitives.address_to_u256(f.caller)),
        op.CALLVALUE => s.push(f.value),
        op.CALLDATALOAD => {
            var word: [32]u8 = undefined;
            memory_module.copy_padded(&word, f.input, s.peek(0).*);
            s.peek(0).* = primitives.word_from_be(&word);
        },
        op.CALLDATASIZE => s.push(f.input.len),
        op.CODESIZE => s.push(f.analyzed.len),
        op.GASPRICE => s.push(evm.tx.gas_price),
        op.RETURNDATASIZE => s.push(evm.return_data().len),
        op.CHAINID => s.push(evm.config.chain_id),
        else => block_value(fork, opcode, s, evm),
    }
}

/// Environment opcodes that copy into memory or read state (sync points).
fn environment(comptime fork: Fork, comptime opcode: u8, f: *Frame, evm: *Evm) ?Exit {
    const s = &f.stack;
    switch (opcode) {
        op.CALLDATACOPY => {
            const memory_offset = s.pop();
            const offset = s.pop();
            const size = s.pop();
            return copy_to_memory(f, memory_offset, f.input, offset, size);
        },
        op.CODECOPY => {
            const memory_offset = s.pop();
            const offset = s.pop();
            const size = s.pop();
            return copy_to_memory(f, memory_offset, f.analyzed.original(), offset, size);
        },
        op.RETURNDATACOPY => return return_data_copy(f, evm),
        op.BALANCE, op.EXTCODESIZE, op.EXTCODECOPY, op.EXTCODEHASH => {
            return external_account(fork, opcode, f, evm);
        },
        op.BLOCKHASH => return block_hash(f, evm),
        op.SELFBALANCE => {
            const account = evm.state.load(f.address) catch |err| return evm.fail(err);
            s.push(account.info.balance);
        },
        else => comptime unreachable,
    }
    return null;
}

inline fn block_value(comptime fork: Fork, comptime opcode: u8, s: *Stack, evm: *const Evm) void {
    switch (opcode) {
        op.COINBASE => s.push(primitives.address_to_u256(evm.block.coinbase)),
        op.TIMESTAMP => s.push(evm.block.timestamp),
        op.NUMBER => s.push(evm.block.number),
        op.PREVRANDAO => if (fork.at_least(.merge)) {
            s.push(primitives.b256_to_u256(evm.block.prevrandao));
        } else {
            s.push(evm.block.difficulty);
        },
        op.GASLIMIT => s.push(evm.block.gas_limit),
        op.BASEFEE => s.push(evm.block.base_fee),
        op.BLOBHASH => {
            const index = s.peek(0);
            const hashes = evm.tx.blob_hashes;
            index.* = if (index.* < hashes.len)
                primitives.b256_to_u256(hashes[@intCast(index.*)])
            else
                0;
        },
        op.BLOBBASEFEE => s.push(evm.block.blob_base_fee),
        else => comptime unreachable,
    }
}

fn return_data_copy(f: *Frame, evm: *Evm) ?Exit {
    const memory_offset = f.stack.pop();
    const offset = f.stack.pop();
    const size = f.stack.pop();
    const data = evm.return_data();
    const end = @as(u257, offset) + size;
    if (end > data.len) return .return_data_out_of_bounds;
    const range = memory_range(&f.memory, &f.gas, memory_offset, size) orelse return .out_of_gas;
    if (!charge_copy(&f.gas, range.size)) return .out_of_gas;
    if (range.size == 0) return null;
    const start: usize = @intCast(offset);
    @memcpy(f.memory.slice(range.offset, range.size), data[start..][0..range.size]);
    return null;
}

fn charge_cold_account(comptime fork: Fork, f: *Frame, is_cold: bool) bool {
    if (!fork.at_least(.berlin) or !is_cold) return true;
    if (f.gas < gas.cold_account_access_extra) return false;
    f.gas -= gas.cold_account_access_extra;
    return true;
}

fn external_account(comptime fork: Fork, comptime opcode: u8, f: *Frame, evm: *Evm) ?Exit {
    const s = &f.stack;
    const address = primitives.u256_to_address(s.pop());
    const access = evm.state.access(address) catch |err| return evm.fail(err);
    if (!charge_cold_account(fork, f, access.is_cold)) return .out_of_gas;
    const account = access.account;
    switch (opcode) {
        op.BALANCE => s.push(account.info.balance),
        op.EXTCODEHASH => if (account.is_empty_for(fork)) {
            s.push(0);
        } else {
            s.push(primitives.b256_to_u256(account.info.code_hash));
        },
        op.EXTCODESIZE => {
            const code = evm.state.code(account) catch |err| return evm.fail(err);
            s.push(code.len);
        },
        op.EXTCODECOPY => {
            const memory_offset = s.pop();
            const offset = s.pop();
            const size = s.pop();
            const code = evm.state.code(account) catch |err| return evm.fail(err);
            return copy_to_memory(f, memory_offset, code, offset, size);
        },
        else => comptime unreachable,
    }
    return null;
}

fn block_hash(f: *Frame, evm: *Evm) ?Exit {
    const number = f.stack.peek(0);
    const current = evm.block.number;
    if (number.* >= current or current - number.* > 256) {
        number.* = 0;
        return null;
    }
    const hash = evm.state.block_hash(@intCast(number.*)) catch |err| return evm.fail(err);
    number.* = primitives.b256_to_u256(hash);
    return null;
}

// ------------------------------------------------------------------ storage and logs

fn sload(comptime fork: Fork, f: *Frame, evm: *Evm) ?Exit {
    const key = f.stack.peek(0);
    const access = evm.state.storage_access(f.account, key.*) catch |err| return evm.fail(err);
    if (fork.at_least(.berlin) and access.is_cold) {
        if (f.gas < gas.cold_sload_extra) return .out_of_gas;
        f.gas -= gas.cold_sload_extra;
    }
    key.* = access.slot.present;
    return null;
}

fn sstore(comptime fork: Fork, f: *Frame, evm: *Evm) ?Exit {
    if (f.is_static) return .static_violation;
    if (gas.sstore_requires_stipend(fork) and f.gas <= gas.call_stipend) return .out_of_gas;
    const key = f.stack.pop();
    const value = f.stack.pop();
    const access = evm.state.storage_access(f.account, key) catch |err| return evm.fail(err);
    const slot = access.slot;
    const cost = gas.sstore(fork, slot.original, slot.present, value, access.is_cold);
    if (f.gas < cost.cost) return .out_of_gas;
    f.gas -= cost.cost;
    f.refund += cost.refund;
    evm.state.storage_write(f.account, slot, value) catch |err| return evm.fail(err);
    return null;
}

fn tstore(f: *Frame, evm: *Evm) ?Exit {
    if (f.is_static) return .static_violation;
    const key = f.stack.pop();
    const value = f.stack.pop();
    evm.state.transient_store(f.address, key, value) catch |err| return evm.fail(err);
    return null;
}

fn log(comptime topic_count: u8, f: *Frame, evm: *Evm) ?Exit {
    if (f.is_static) return .static_violation;
    const offset = f.stack.pop();
    const size = f.stack.pop();
    var topics: [4]primitives.B256 = undefined;
    inline for (0..topic_count) |i| topics[i] = primitives.u256_to_b256(f.stack.pop());
    const range = memory_range(&f.memory, &f.gas, offset, size) orelse return .out_of_gas;
    const cost = gas.log_data_byte * range.size;
    if (f.gas < cost) return .out_of_gas;
    f.gas -= cost;
    const data = f.memory.slice(range.offset, range.size);
    evm.state.log(f.address, topics[0..topic_count], data) catch |err| return evm.fail(err);
    if (evm.tracer) |tracer| tracer.log(tracer.context, f.address, topics[0..topic_count], data);
    return null;
}

// ------------------------------------------------------------------ calls

fn create(comptime fork: Fork, comptime is_create2: bool, f: *Frame, evm: *Evm) ?Exit {
    if (f.is_static) return .static_violation;
    const value = f.stack.pop();
    const offset = f.stack.pop();
    const size = f.stack.pop();
    const salt: u256 = if (is_create2) f.stack.pop() else 0;
    const range = memory_range(&f.memory, &f.gas, offset, size) orelse return .out_of_gas;
    if (fork.at_least(.shanghai)) {
        if (range.size > evm.config.initcode_size_max) return .out_of_gas;
        const cost = gas.initcode_cost(range.size);
        if (f.gas < cost) return .out_of_gas;
        f.gas -= cost;
    }
    if (is_create2) {
        const cost = gas.keccak256_word * gas.words_for(range.size);
        if (f.gas < cost) return .out_of_gas;
        f.gas -= cost;
    }
    var limit = f.gas;
    if (fork.at_least(.tangerine)) limit = gas.all_but_one_64th(limit);
    f.gas -= limit;
    evm.pending = .{ .create = .{
        .is_create2 = is_create2,
        .caller = f.address,
        .value = value,
        .init_code = f.memory.slice(range.offset, range.size),
        .salt = salt,
        .gas_limit = limit,
    } };
    return .create;
}

fn call(comptime fork: Fork, comptime kind: CallKind, f: *Frame, evm: *Evm) ?Exit {
    const s = &f.stack;
    const gas_requested = s.pop();
    const target = primitives.u256_to_address(s.pop());
    const value: u256 = if (kind == .call or kind == .callcode) s.pop() else 0;
    const in_offset = s.pop();
    const in_size = s.pop();
    const out_offset = s.pop();
    const out_size = s.pop();
    if (kind == .call and value != 0 and f.is_static) return .static_violation;
    const in_range = memory_range(&f.memory, &f.gas, in_offset, in_size) orelse
        return .out_of_gas;
    const out_range = memory_range(&f.memory, &f.gas, out_offset, out_size) orelse
        return .out_of_gas;
    const access = evm.state.access(target) catch |err| return evm.fail(err);
    var cost: u64 = 0;
    if (fork.at_least(.berlin) and access.is_cold) cost += gas.cold_account_access_extra;
    if (value != 0) cost += gas.call_value;
    if (kind == .call and call_creates_account(fork, access.account, value)) {
        cost += gas.new_account;
    }
    var code_address = target;
    var code_account = access.account;
    if (fork.at_least(.prague)) {
        const code = evm.state.code(access.account) catch |err| return evm.fail(err);
        if (bytecode.delegation_target(code)) |delegate| {
            const delegated = evm.state.access(delegate) catch |err| return evm.fail(err);
            cost += if (delegated.is_cold) gas.cold_account_access else gas.warm_storage_read;
            code_address = delegate;
            code_account = delegated.account;
        }
    }
    if (f.gas < cost) return .out_of_gas;
    f.gas -= cost;
    const requested: u64 = @intCast(@min(gas_requested, std.math.maxInt(u64)));
    var limit = requested;
    if (fork.at_least(.tangerine)) {
        limit = @min(requested, gas.all_but_one_64th(f.gas));
    } else if (requested > f.gas) return .out_of_gas;
    f.gas -= limit;
    if (value != 0) limit += gas.call_stipend;
    evm.pending = .{ .call = .{
        .kind = kind,
        .target = target,
        .code_address = code_address,
        .target_account = access.account,
        .code_account = code_account,
        .value = value,
        .input = f.memory.slice(in_range.offset, in_range.size),
        .gas_limit = limit,
        .return_offset = out_range.offset,
        .return_size = out_range.size,
    } };
    return .call;
}

fn call_creates_account(
    comptime fork: Fork,
    account: *const state_module.Account,
    value: u256,
) bool {
    if (fork.at_least(.spurious_dragon)) return value != 0 and account.info.is_empty();
    return account.is_empty_for(fork);
}

fn self_destruct(comptime fork: Fork, f: *Frame, evm: *Evm) ?Exit {
    if (f.is_static) return .static_violation;
    const target = primitives.u256_to_address(f.stack.pop());
    const balance = f.account.info.balance;
    const result = evm.state.self_destruct(fork, f.address, target) catch |err| {
        return evm.fail(err);
    };
    var cost: u64 = 0;
    if (fork.at_least(.berlin) and result.target_cold) cost += gas.cold_account_access;
    if (fork.at_least(.spurious_dragon)) {
        if (result.had_value and result.target_empty) cost += gas.new_account;
    } else if (fork.at_least(.tangerine) and result.target_empty) {
        cost += gas.new_account;
    }
    if (f.gas < cost) return .out_of_gas;
    f.gas -= cost;
    if (!result.previously_destroyed) f.refund += gas.selfdestruct_refund(fork);
    if (evm.tracer) |tracer| trace_self_destruct(tracer, f, target, balance);
    return .self_destruct;
}

/// callTracer reports SELFDESTRUCT as a zero-gas child frame moving the balance.
fn trace_self_destruct(
    tracer: *const evm_module.Tracer,
    f: *Frame,
    target: primitives.Address,
    balance: u256,
) void {
    tracer.enter(tracer.context, .{
        .kind = .selfdestruct,
        .from = f.address,
        .to = target,
        .value = balance,
        .gas = 0,
        .input = &.{},
        .depth = f.depth + 1,
    });
    tracer.exit(tracer.context, .{
        .status = .success,
        .exit = .self_destruct,
        .gas_remaining = 0,
        .gas_refund = 0,
        .output = &.{},
    });
}

test "interpreter: arithmetic helpers" {
    const max = std.math.maxInt(u256);
    const min_signed: u256 = 1 << 255;
    try std.testing.expectEqual(@as(u256, 0), add(max, 1));
    try std.testing.expectEqual(@as(u256, 0), div(5, 0));
    try std.testing.expectEqual(min_signed, sdiv(min_signed, max));
    try std.testing.expectEqual(max, sdiv(1, max));
    try std.testing.expectEqual(@as(u256, 0), smod(min_signed, max));
    try std.testing.expectEqual(max - 1, smod(max - 7, 3));
    try std.testing.expectEqual(@as(u256, 2), addmod(max, 2, max));
    try std.testing.expectEqual(@as(u256, 1), mulmod(max, max, max - 1));
    try std.testing.expectEqual(@as(u256, 1024), exponent(2, 10));
    try std.testing.expectEqual(@as(u256, 0), exponent(2, 256));
    try std.testing.expectEqual(max, signextend(0, 0xff));
    try std.testing.expectEqual(@as(u256, 0x7f), signextend(0, 0x7f));
    try std.testing.expectEqual(@as(u256, 0xff), byte(31, 0x1ff));
    try std.testing.expectEqual(max, sar(300, min_signed));
    try std.testing.expectEqual(@as(u256, 1), shr(255, min_signed));
    try std.testing.expectEqual(@as(u256, 0), shl(256, 1));
    try std.testing.expectEqual(@as(u256, 1), slt(max, 0));
}

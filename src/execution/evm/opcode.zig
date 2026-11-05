//! EVM opcode numbers and static metadata: stack inputs/outputs, immediate size, and
//! the fork that introduced each opcode. Gas lives in `gas.zig`.

const std = @import("std");
const assert = std.debug.assert;
const Fork = @import("fork.zig").Fork;

pub const STOP = 0x00;
pub const ADD = 0x01;
pub const MUL = 0x02;
pub const SUB = 0x03;
pub const DIV = 0x04;
pub const SDIV = 0x05;
pub const MOD = 0x06;
pub const SMOD = 0x07;
pub const ADDMOD = 0x08;
pub const MULMOD = 0x09;
pub const EXP = 0x0a;
pub const SIGNEXTEND = 0x0b;
pub const LT = 0x10;
pub const GT = 0x11;
pub const SLT = 0x12;
pub const SGT = 0x13;
pub const EQ = 0x14;
pub const ISZERO = 0x15;
pub const AND = 0x16;
pub const OR = 0x17;
pub const XOR = 0x18;
pub const NOT = 0x19;
pub const BYTE = 0x1a;
pub const SHL = 0x1b;
pub const SHR = 0x1c;
pub const SAR = 0x1d;
pub const CLZ = 0x1e;
pub const KECCAK256 = 0x20;
pub const ADDRESS = 0x30;
pub const BALANCE = 0x31;
pub const ORIGIN = 0x32;
pub const CALLER = 0x33;
pub const CALLVALUE = 0x34;
pub const CALLDATALOAD = 0x35;
pub const CALLDATASIZE = 0x36;
pub const CALLDATACOPY = 0x37;
pub const CODESIZE = 0x38;
pub const CODECOPY = 0x39;
pub const GASPRICE = 0x3a;
pub const EXTCODESIZE = 0x3b;
pub const EXTCODECOPY = 0x3c;
pub const RETURNDATASIZE = 0x3d;
pub const RETURNDATACOPY = 0x3e;
pub const EXTCODEHASH = 0x3f;
pub const BLOCKHASH = 0x40;
pub const COINBASE = 0x41;
pub const TIMESTAMP = 0x42;
pub const NUMBER = 0x43;
pub const PREVRANDAO = 0x44;
pub const GASLIMIT = 0x45;
pub const CHAINID = 0x46;
pub const SELFBALANCE = 0x47;
pub const BASEFEE = 0x48;
pub const BLOBHASH = 0x49;
pub const BLOBBASEFEE = 0x4a;
pub const POP = 0x50;
pub const MLOAD = 0x51;
pub const MSTORE = 0x52;
pub const MSTORE8 = 0x53;
pub const SLOAD = 0x54;
pub const SSTORE = 0x55;
pub const JUMP = 0x56;
pub const JUMPI = 0x57;
pub const PC = 0x58;
pub const MSIZE = 0x59;
pub const GAS = 0x5a;
pub const JUMPDEST = 0x5b;
pub const TLOAD = 0x5c;
pub const TSTORE = 0x5d;
pub const MCOPY = 0x5e;
pub const PUSH0 = 0x5f;
pub const PUSH1 = 0x60;
pub const PUSH2 = 0x61;
pub const PUSH32 = 0x7f;
pub const DUP1 = 0x80;
pub const DUP16 = 0x8f;
pub const SWAP1 = 0x90;
pub const SWAP16 = 0x9f;
pub const LOG0 = 0xa0;
pub const LOG4 = 0xa4;
pub const CREATE = 0xf0;
pub const CALL = 0xf1;
pub const CALLCODE = 0xf2;
pub const RETURN = 0xf3;
pub const DELEGATECALL = 0xf4;
pub const CREATE2 = 0xf5;
pub const STATICCALL = 0xfa;
pub const REVERT = 0xfd;
pub const INVALID = 0xfe;
pub const SELFDESTRUCT = 0xff;

pub const Info = struct {
    name: []const u8,
    /// Items popped from the stack.
    inputs: u8,
    /// Items pushed onto the stack.
    outputs: u8,
    /// Immediate bytes following the opcode (PUSH1..PUSH32).
    immediate_bytes: u8 = 0,
    /// First fork where the opcode is defined.
    since: Fork = .frontier,
    defined: bool = true,
};

const undefined_info = Info{ .name = "UNDEFINED", .inputs = 0, .outputs = 0, .defined = false };

pub const table: [256]Info = build_table();

/// Whether `op` is a valid instruction at `fork`. Undefined opcodes act like INVALID.
pub fn is_defined(fork: Fork, op: u8) bool {
    const info = table[op];
    return info.defined and fork.at_least(info.since);
}

fn build_table() [256]Info {
    @setEvalBranchQuota(20_000);
    var t: [256]Info = @splat(undefined_info);
    const Entry = struct { u8, []const u8, u8, u8, Fork };
    const entries = [_]Entry{
        .{ STOP, "STOP", 0, 0, .frontier },
        .{ ADD, "ADD", 2, 1, .frontier },
        .{ MUL, "MUL", 2, 1, .frontier },
        .{ SUB, "SUB", 2, 1, .frontier },
        .{ DIV, "DIV", 2, 1, .frontier },
        .{ SDIV, "SDIV", 2, 1, .frontier },
        .{ MOD, "MOD", 2, 1, .frontier },
        .{ SMOD, "SMOD", 2, 1, .frontier },
        .{ ADDMOD, "ADDMOD", 3, 1, .frontier },
        .{ MULMOD, "MULMOD", 3, 1, .frontier },
        .{ EXP, "EXP", 2, 1, .frontier },
        .{ SIGNEXTEND, "SIGNEXTEND", 2, 1, .frontier },
        .{ LT, "LT", 2, 1, .frontier },
        .{ GT, "GT", 2, 1, .frontier },
        .{ SLT, "SLT", 2, 1, .frontier },
        .{ SGT, "SGT", 2, 1, .frontier },
        .{ EQ, "EQ", 2, 1, .frontier },
        .{ ISZERO, "ISZERO", 1, 1, .frontier },
        .{ AND, "AND", 2, 1, .frontier },
        .{ OR, "OR", 2, 1, .frontier },
        .{ XOR, "XOR", 2, 1, .frontier },
        .{ NOT, "NOT", 1, 1, .frontier },
        .{ BYTE, "BYTE", 2, 1, .frontier },
        .{ SHL, "SHL", 2, 1, .constantinople },
        .{ SHR, "SHR", 2, 1, .constantinople },
        .{ SAR, "SAR", 2, 1, .constantinople },
        .{ CLZ, "CLZ", 1, 1, .osaka },
        .{ KECCAK256, "KECCAK256", 2, 1, .frontier },
        .{ ADDRESS, "ADDRESS", 0, 1, .frontier },
        .{ BALANCE, "BALANCE", 1, 1, .frontier },
        .{ ORIGIN, "ORIGIN", 0, 1, .frontier },
        .{ CALLER, "CALLER", 0, 1, .frontier },
        .{ CALLVALUE, "CALLVALUE", 0, 1, .frontier },
        .{ CALLDATALOAD, "CALLDATALOAD", 1, 1, .frontier },
        .{ CALLDATASIZE, "CALLDATASIZE", 0, 1, .frontier },
        .{ CALLDATACOPY, "CALLDATACOPY", 3, 0, .frontier },
        .{ CODESIZE, "CODESIZE", 0, 1, .frontier },
        .{ CODECOPY, "CODECOPY", 3, 0, .frontier },
        .{ GASPRICE, "GASPRICE", 0, 1, .frontier },
        .{ EXTCODESIZE, "EXTCODESIZE", 1, 1, .frontier },
        .{ EXTCODECOPY, "EXTCODECOPY", 4, 0, .frontier },
        .{ RETURNDATASIZE, "RETURNDATASIZE", 0, 1, .byzantium },
        .{ RETURNDATACOPY, "RETURNDATACOPY", 3, 0, .byzantium },
        .{ EXTCODEHASH, "EXTCODEHASH", 1, 1, .constantinople },
        .{ BLOCKHASH, "BLOCKHASH", 1, 1, .frontier },
        .{ COINBASE, "COINBASE", 0, 1, .frontier },
        .{ TIMESTAMP, "TIMESTAMP", 0, 1, .frontier },
        .{ NUMBER, "NUMBER", 0, 1, .frontier },
        .{ PREVRANDAO, "PREVRANDAO", 0, 1, .frontier },
        .{ GASLIMIT, "GASLIMIT", 0, 1, .frontier },
        .{ CHAINID, "CHAINID", 0, 1, .istanbul },
        .{ SELFBALANCE, "SELFBALANCE", 0, 1, .istanbul },
        .{ BASEFEE, "BASEFEE", 0, 1, .london },
        .{ BLOBHASH, "BLOBHASH", 1, 1, .cancun },
        .{ BLOBBASEFEE, "BLOBBASEFEE", 0, 1, .cancun },
        .{ POP, "POP", 1, 0, .frontier },
        .{ MLOAD, "MLOAD", 1, 1, .frontier },
        .{ MSTORE, "MSTORE", 2, 0, .frontier },
        .{ MSTORE8, "MSTORE8", 2, 0, .frontier },
        .{ SLOAD, "SLOAD", 1, 1, .frontier },
        .{ SSTORE, "SSTORE", 2, 0, .frontier },
        .{ JUMP, "JUMP", 1, 0, .frontier },
        .{ JUMPI, "JUMPI", 2, 0, .frontier },
        .{ PC, "PC", 0, 1, .frontier },
        .{ MSIZE, "MSIZE", 0, 1, .frontier },
        .{ GAS, "GAS", 0, 1, .frontier },
        .{ JUMPDEST, "JUMPDEST", 0, 0, .frontier },
        .{ TLOAD, "TLOAD", 1, 1, .cancun },
        .{ TSTORE, "TSTORE", 2, 0, .cancun },
        .{ MCOPY, "MCOPY", 3, 0, .cancun },
        .{ PUSH0, "PUSH0", 0, 1, .shanghai },
        .{ CREATE, "CREATE", 3, 1, .frontier },
        .{ CALL, "CALL", 7, 1, .frontier },
        .{ CALLCODE, "CALLCODE", 7, 1, .frontier },
        .{ RETURN, "RETURN", 2, 0, .frontier },
        .{ DELEGATECALL, "DELEGATECALL", 6, 1, .homestead },
        .{ CREATE2, "CREATE2", 4, 1, .constantinople },
        .{ STATICCALL, "STATICCALL", 6, 1, .byzantium },
        .{ REVERT, "REVERT", 2, 0, .byzantium },
        .{ INVALID, "INVALID", 0, 0, .frontier },
        .{ SELFDESTRUCT, "SELFDESTRUCT", 1, 0, .frontier },
    };
    for (entries) |e| {
        t[e[0]] = .{ .name = e[1], .inputs = e[2], .outputs = e[3], .since = e[4] };
    }
    const push_names = names("PUSH", 32);
    const dup_names = names("DUP", 16);
    const swap_names = names("SWAP", 16);
    for (0..32) |i| {
        t[PUSH1 + i] = .{
            .name = push_names[i],
            .inputs = 0,
            .outputs = 1,
            .immediate_bytes = i + 1,
        };
    }
    for (0..16) |i| {
        t[DUP1 + i] = .{ .name = dup_names[i], .inputs = i + 1, .outputs = i + 2 };
        t[SWAP1 + i] = .{ .name = swap_names[i], .inputs = i + 2, .outputs = i + 2 };
    }
    const log_names = names("LOG", 5);
    for (0..5) |i| {
        t[LOG0 + i] = .{ .name = log_names[i], .inputs = i + 2, .outputs = 0 };
    }
    // INVALID is "defined" in the table so it has a name, but always halts.
    return t;
}

fn names(comptime prefix: []const u8, comptime count: u8) [count][]const u8 {
    var out: [count][]const u8 = undefined;
    for (0..count) |i| {
        const base = if (std.mem.eql(u8, prefix, "LOG")) 0 else 1;
        out[i] = std.fmt.comptimePrint("{s}{d}", .{ prefix, i + base });
    }
    return out;
}

comptime {
    assert(table[PUSH32].immediate_bytes == 32);
    assert(table[DUP16].inputs == 16 and table[DUP16].outputs == 17);
    assert(table[SWAP16].inputs == 17);
    assert(table[LOG4].inputs == 6);
    assert(!table[0x0c].defined);
}

test "opcode: definition by fork" {
    try std.testing.expect(is_defined(.frontier, ADD));
    try std.testing.expect(!is_defined(.frontier, DELEGATECALL));
    try std.testing.expect(is_defined(.homestead, DELEGATECALL));
    try std.testing.expect(!is_defined(.london, PUSH0));
    try std.testing.expect(is_defined(.shanghai, PUSH0));
    try std.testing.expect(!is_defined(.prague, CLZ));
    try std.testing.expect(is_defined(.osaka, CLZ));
    try std.testing.expect(!is_defined(.osaka, 0xef));
    try std.testing.expectEqualStrings("PUSH1", table[PUSH1].name);
    try std.testing.expectEqualStrings("LOG0", table[LOG0].name);
    try std.testing.expectEqualStrings("SWAP16", table[SWAP16].name);
}

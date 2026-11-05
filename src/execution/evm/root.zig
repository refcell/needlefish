//! The EVM: interpreter, gas schedule, journaled state, frames, and transactions.
//! Mirrors revm / op-revm as used by base/base `crates/common/evm`.

const std = @import("std");

pub const primitives = @import("primitives.zig");
pub const fork = @import("fork.zig");
pub const opcode = @import("opcode.zig");
pub const gas = @import("gas.zig");
pub const stack = @import("stack.zig");
pub const memory = @import("memory.zig");
pub const bytecode = @import("bytecode.zig");
pub const env = @import("env.zig");
pub const state = @import("state.zig");
pub const memory_db = @import("memory_db.zig");
pub const interpreter = @import("interpreter.zig");
pub const evm = @import("evm.zig");
pub const precompiles = @import("precompiles.zig");
pub const transaction = @import("transaction.zig");
pub const op = @import("op.zig");
pub const state_test = @import("state_test.zig");

test {
    _ = @import("evm_test.zig");
    _ = @import("op_test.zig");
}

pub const Fork = fork.Fork;
pub const Address = primitives.Address;
pub const B256 = primitives.B256;
pub const Evm = evm.Evm;
pub const State = state.State;
pub const MemoryDatabase = memory_db.MemoryDatabase;

test {
    std.testing.refAllDecls(@This());
}

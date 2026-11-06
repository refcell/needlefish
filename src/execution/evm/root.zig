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
pub const uint = @import("uint.zig");
pub const interpreter = @import("interpreter.zig");
pub const evm = @import("evm.zig");
pub const precompiles = @import("precompiles.zig");
pub const transaction = @import("transaction.zig");
pub const op = @import("op.zig");
pub const native = @import("native.zig");
pub const eip8130_config = @import("eip8130_config.zig");
pub const eip8130_auth = @import("eip8130_auth.zig");
pub const eip8130_apply = @import("eip8130_apply.zig");
pub const eip8130_tx = @import("eip8130_tx.zig");
pub const eip8130_nonce = @import("eip8130_nonce.zig");
pub const eip8130_execute = @import("eip8130_execute.zig");
pub const eip8130_simulate = @import("eip8130_simulate.zig");
pub const bench = @import("bench.zig");
pub const opcode_profile = @import("opcode_profile.zig");
pub const state_test = @import("state_test.zig");
pub const tx_check = @import("tx_check.zig");

test {
    _ = @import("evm_test.zig");
    _ = @import("op_test.zig");
    _ = @import("evm_fuzz.zig");
    _ = @import("arith_fuzz.zig");
    _ = @import("memory_fuzz.zig");
    _ = @import("call_fuzz.zig");
    _ = @import("sstore_fuzz.zig");
    _ = @import("create_fuzz.zig");
    _ = @import("tx_check.zig");
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

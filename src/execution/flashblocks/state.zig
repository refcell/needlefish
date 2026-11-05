//! The pending state builder interface. base/base `state_builder.rs`
//! (`PendingStateBuilder`) re-executes every pending transaction on top of the canonical
//! state so pending-tag RPC calls see balances, nonces, receipts, and `eth_call` results.
//!
//! The processor drives any type with these declarations (duck-typed at comptime):
//!
//! - `fn reset(builder: *T) void` — the pending blocks were cleared or are about to be
//!   rebuilt from scratch; drop all executed state.
//! - `fn execute(builder: *T, block: *const pending.Block, start: u32, end: u32)
//!   Error!void` — execute transactions `start..end` of `block` (the next ones after
//!   everything executed since the last `reset`, in order).
//!
//! `Noop` executes nothing; `state_executor.ExecutorState` re-executes on the node's
//! `Executor` over the canonical state.

const std = @import("std");
const assert = std.debug.assert;

const pending = @import("pending.zig");

pub const Error = error{ExecutionFailed};

/// Fails at compile time unless `T` implements the interface.
pub fn assert_interface(comptime T: type) void {
    comptime {
        const reset: fn (*T) void = T.reset;
        const execute: fn (*T, *const pending.Block, u32, u32) Error!void = T.execute;
        _ = reset;
        _ = execute;
    }
}

/// Executes nothing; the pending view still carries the flashblocks' own data.
pub const Noop = struct {
    resets: u64 = 0,
    executed: u64 = 0,

    pub fn reset(builder: *Noop) void {
        builder.resets += 1;
        assert(builder.resets > 0);
    }

    pub fn execute(builder: *Noop, block: *const pending.Block, start: u32, end: u32) Error!void {
        assert(start <= end);
        assert(end <= block.transaction_count);
        builder.executed += end - start;
    }
};

comptime {
    assert_interface(Noop);
}

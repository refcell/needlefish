//! Transaction manager (base/base `crates/utilities/tx-manager`).
//!
//! Gives each logical send one nonce, publishes it, replaces stuck versions with bumped
//! fees (EIP-1559 tip/fee cap, EIP-4844 blob fee cap), and reports it once it is buried
//! `num_confirmations` deep, with a bounded set of concurrent sends. The core is sans-IO
//! (`manager.Manager`): it emits actions and consumes their results, so the same code
//! runs over JSON-RPC in a binary and against a fake L1 in the simulator.

const std = @import("std");

pub const fees = @import("fees.zig");
pub const errors = @import("errors.zig");
pub const nonce = @import("nonce.zig");
pub const send_state = @import("send_state.zig");
pub const manager = @import("manager.zig");
pub const driver = @import("driver.zig");
pub const metrics = @import("metrics.zig");

pub const Manager = manager.Manager;
pub const Driver = driver.Driver;
pub const Config = manager.Config;
pub const Action = manager.Action;
pub const Completion = manager.Completion;
pub const PublishError = errors.PublishError;
pub const classify = errors.classify;

test {
    std.testing.refAllDecls(@This());
    _ = @import("sim_test.zig");
    _ = @import("driver_test.zig");
}

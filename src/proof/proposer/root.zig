//! Output-root proposer (base/base `crates/proof/proposer`): recovers the latest proposal
//! from the anchor and the factory, dispatches proofs for the next ranges, and submits
//! games that chain from the anchor or the parent game. A deterministic state machine over
//! injected chain, prover and submitter interfaces.

const std = @import("std");

pub const intervals = @import("intervals.zig");
pub const target = @import("target.zig");
pub const interfaces = @import("interfaces.zig");
pub const recovery = @import("recovery.zig");
pub const dispatcher = @import("dispatcher.zig");
pub const collector = @import("collector.zig");
pub const pipeline = @import("pipeline.zig");
pub const fakes = @import("fakes.zig");
pub const rpc_chain = @import("rpc_chain.zig");
pub const tx_submitter = @import("tx_submitter.zig");
pub const config = @import("config.zig");
pub const dry_run = @import("dry_run.zig");

pub const Intervals = intervals.Intervals;
pub const RecoveredState = target.RecoveredState;
pub const Pipeline = pipeline.Pipeline;
pub const Config = pipeline.Config;

test {
    std.testing.refAllDecls(@This());
    _ = @import("recovery_test.zig");
    _ = @import("pipeline_test.zig");
    _ = @import("sim_test.zig");
    _ = @import("rpc_chain_test.zig");
    _ = @import("tx_submitter_test.zig");
}

//! Proof-system contract bindings: ABI codecs for the `DisputeGameFactory`,
//! `AnchorStateRegistry`, `DelayedWETH` and `AggregateVerifier` calls the proposer and
//! challenger make.

pub const abi = @import("abi.zig");
pub const dispute_game_factory = @import("dispute_game_factory.zig");
pub const anchor_state_registry = @import("anchor_state_registry.zig");
pub const delayed_weth = @import("delayed_weth.zig");
pub const aggregate_verifier = @import("aggregate_verifier.zig");
pub const tee_prover_registry = @import("tee_prover_registry.zig");
pub const cert_manager = @import("cert_manager.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

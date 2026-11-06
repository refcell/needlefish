//! `proof/primitives`: shared proof types (base/base `crates/proof/primitives`): the
//! per-chain config hash, the TEE proof journal, and the `AggregateVerifier` proof bytes.
//! The proposal and proof result types are the prover service's
//! (`prover_service/protocol.zig`).

const std = @import("std");

pub const per_chain_config = @import("per_chain_config.zig");
pub const proposal = @import("proposal.zig");
pub const proof_encoder = @import("proof_encoder.zig");

pub const PerChainConfig = per_chain_config.PerChainConfig;
pub const config_hash_for_chain = per_chain_config.config_hash_for_chain;
pub const ProofJournal = proposal.ProofJournal;
pub const Proposal = proposal.Proposal;

test {
    std.testing.refAllDecls(@This());
}

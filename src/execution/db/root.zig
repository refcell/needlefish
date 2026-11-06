//! Execution database. Mirrors base/base `crates/execution` storage (reth db/provider).
//!
//! Sub-modules are re-exported here as they land:
//! - `storage`: crash-safe storage engine (superblock, journal, checkpoints) over an injected
//!   sector storage, with a deterministic fault-injecting simulator.
//! - `state`: state provider (accounts, storage, code, block hashes) with a block overlay.
//! - `witness`: execution witness (`debug_executionWitness`) and stateless `SparseState`.
//! - `witness_block`: the witness of a stored block (unwind to its parent, run, restore).
//! - `witness_codec`: canonical witness encoding and its keccak256 preimage view (proof lane).
//! - `witness_json`: the witness's `debug_executionWitness` JSON shape and exact length.
//! - `witness_diff`: compare two witnesses down to accounts and slots (`witness-diff` tool).
//! - `replay_roots`: trie-only state/receipts/transactions root check from RPC proofs.

const std = @import("std");
pub const storage = @import("storage/root.zig");

pub const changeset = @import("changeset.zig");
pub const state = @import("state.zig");
pub const overlay = @import("overlay.zig");
pub const chain = @import("chain.zig");
pub const snapshot = @import("snapshot.zig");
pub const evm_backend = @import("evm_backend.zig");
pub const history = @import("history.zig");
pub const path_index = @import("path_index.zig");
pub const proof_set = @import("proof_set.zig");
pub const witness = @import("witness.zig");
pub const witness_block = @import("witness_block.zig");
pub const witness_codec = @import("witness_codec.zig");
pub const witness_diff = @import("witness_diff.zig");
pub const witness_json = @import("witness_json.zig");
pub const replay_roots = @import("replay_roots.zig");
pub const code_store = @import("code_store.zig");
pub const flat_trees = @import("flat_trees.zig");
pub const database = @import("database.zig");
pub const bench = @import("bench.zig");

pub const Changeset = changeset.Changeset;
pub const AccountInfo = changeset.AccountInfo;
pub const State = state.State;
pub const Overlay = overlay.Overlay;
pub const ChainStore = chain.ChainStore;
pub const HistoryStore = history.Store;
pub const SparseState = witness.SparseState;

test {
    std.testing.refAllDecls(@This());
    _ = @import("state_test.zig");
    _ = @import("chain_test.zig");
    _ = @import("history_test.zig");
    _ = @import("witness_test.zig");
    _ = @import("witness_differential_test.zig");
    _ = @import("witness_evm_test.zig");
    _ = @import("has_storage_test.zig");
    _ = @import("witness_block_test.zig");
    _ = @import("witness_codec_test.zig");
    _ = @import("witness_header_test.zig");
    _ = @import("replay_roots_test.zig");
    _ = @import("database_test.zig");
    _ = @import("database_history_test.zig");
    _ = @import("database_code_test.zig");
    _ = @import("database_flat_test.zig");
}

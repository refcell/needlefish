//! Merkle Patricia Trie. Mirrors base/base `crates/execution/trie` and alloy-trie.
//!
//! - `nibbles`: nibble paths and hex-prefix encoding.
//! - `node`: leaf, extension, and branch encoding; child references.
//! - `hash_builder`: streaming root from sorted leaves and subtrie hashes.
//! - `trie`: mutable in-memory trie with cached hashes and `eth_getProof` proofs.
//! - `proof`: proof verification.
//! - `ordered`: transactions, receipts, and withdrawals roots.
//! - `state_trie`: account and storage tries with an incremental state root.
//! - `sparse`: sparse trie over witness preimages, for stateless updates.
//! - `path_targets`: sorted key paths for multi-key walks (witness proofs in one descent).

const std = @import("std");

pub const rlp = @import("rlp.zig");
pub const nibbles = @import("nibbles.zig");
pub const node = @import("node.zig");
pub const hash_builder = @import("hash_builder.zig");
pub const trie = @import("trie.zig");
pub const proof = @import("proof.zig");
pub const ordered = @import("ordered.zig");
pub const state_trie = @import("state_trie.zig");
pub const sparse = @import("sparse.zig");
pub const path_targets = @import("path_targets.zig");
pub const bench = @import("bench.zig");

pub const Nibbles = nibbles.Nibbles;
pub const Hash = node.Hash;
pub const RlpNode = node.RlpNode;
pub const empty_root = node.empty_root;
pub const HashBuilder = hash_builder.HashBuilder;
pub const HashBuilderType = hash_builder.HashBuilderType;
pub const TrieType = trie.TrieType;
pub const verify_proof = proof.verify;
pub const ordered_trie_root = ordered.ordered_trie_root;
pub const StateTrie = state_trie.StateTrie;
pub const Account = state_trie.Account;
pub const StorageEntry = state_trie.StorageEntry;
pub const StorageRange = state_trie.StorageRange;
pub const SparseTrie = sparse.SparseTrie;
pub const PathTarget = path_targets.PathTarget;

test {
    std.testing.refAllDecls(@This());
    _ = @import("trie_test.zig");
    _ = @import("state_trie_test.zig");
    _ = @import("storage_range_test.zig");
}

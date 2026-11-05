//! `proof/mpt`: tries read and updated through the preimage oracle. Port of base/base
//! `crates/proof/mpt`.
//!
//! The mutable trie itself is `execution/trie/sparse.zig` (`SparseTrie`): it already
//! opens nodes lazily from preimages, updates with exact root recomputation, and keeps
//! untouched subtries blinded, which is what the Rust `TrieNode` does. This module adds
//! the oracle-backed resolver it runs on, a lenient node decoder, and the ordered list
//! walker for transaction and receipt tries.

const std = @import("std");

pub const node = @import("node.zig");
pub const oracle_resolver = @import("oracle_resolver.zig");
pub const list_walker = @import("list_walker.zig");
pub const key_reader = @import("key_reader.zig");

pub const OracleResolver = oracle_resolver.OracleResolver;
pub const SparseTrie = @import("../../execution/trie/root.zig").SparseTrie;

test {
    std.testing.refAllDecls(@This());
    _ = @import("mpt_test.zig");
}

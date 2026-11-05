//! `proof/executor`: the stateless L2 block executor of the fault-proof program. Port of
//! base/base `crates/proof/executor`.
//!
//! Execution reuses the node's block executor and the trie-db lane's `SparseState`; this
//! module supplies the oracle-backed state source, header assembly, and output roots.

const std = @import("std");

pub const oracle_fallback = @import("oracle_fallback.zig");
pub const builder = @import("builder.zig");

pub const OracleFallback = oracle_fallback.OracleFallback;
pub const Builder = builder.Builder;
pub const output_root_from_parts = builder.output_root_from_parts;

test {
    std.testing.refAllDecls(@This());
    _ = @import("executor_test.zig");
}

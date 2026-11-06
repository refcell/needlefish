//! Validating follower (`base follow`, docs/SYNC_PLAN.md M1): re-executes every block of a
//! live chain over a stateless, long-lived sparse state fetched on demand and checks every
//! header field. Pure: `bin/base/follow.zig` does the RPC.
//!
//! - `follower`: the per-block state machine (probe, fetch, verify, rebase).
//! - `proofs`: walks untrusted `eth_getProof` results for their trie nodes.

const std = @import("std");

pub const follower = @import("follower.zig");
pub const proofs = @import("proofs.zig");
pub const Follower = follower.Follower;

test {
    std.testing.refAllDecls(@This());
    _ = @import("follower_test.zig");
}

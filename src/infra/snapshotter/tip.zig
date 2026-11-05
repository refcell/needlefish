//! Tip check before a snapshot (base/base `snapshotter/src/tip.rs`): the node's latest
//! block must be within `freshness_s` of the wall clock, otherwise the run is skipped and
//! the node is left untouched. Pure decision; the binary fetches the block and the time.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");

/// base/base default freshness window.
pub const freshness_default_s: u64 = 10;

pub const Status = struct {
    block_number: u64,
    block_hash: [32]u8,
    at_tip: bool,
};

pub fn decide(block_timestamp_s: u64, now_s: u64, freshness_s: u64) bool {
    assert(freshness_s > 0);
    // A block from the future (clock skew) counts as fresh, as in base/base.
    const age_s = now_s -| block_timestamp_s;
    return age_s <= freshness_s;
}

/// Fetches `latest` over `client` and decides against `now_s`.
pub fn check(client: *rpc.Client, now_s: u64, freshness_s: u64) !Status {
    assert(freshness_s > 0);
    const block = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
    if (block == .null) return error.NoLatestBlock;
    const timestamp = try rpc.quantity(u64, try rpc.field(block, "timestamp"));
    return .{
        .block_number = try rpc.quantity(u64, try rpc.field(block, "number")),
        .block_hash = try rpc.fixed(32, try rpc.field(block, "hash")),
        .at_tip = decide(timestamp, now_s, freshness_s),
    };
}

test "tip: freshness window" {
    try std.testing.expect(decide(100, 110, 10));
    try std.testing.expect(!decide(100, 111, 10));
    try std.testing.expect(decide(120, 110, 10)); // Skewed clock.
}

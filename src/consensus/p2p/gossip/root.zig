//! `gossip`: gossipsub v1.1 wire codecs for OP Stack unsafe-block gossip. Mirrors
//! base/base `crates/consensus/gossip`.

const std = @import("std");

pub const rpc = @import("rpc.zig");
pub const snappy = @import("snappy.zig");
pub const seen = @import("seen.zig");
pub const mcache = @import("mcache.zig");
pub const peer_score = @import("peer_score.zig");
pub const router = @import("router.zig");

test {
    _ = @import("router_test.zig");
}

test {
    std.testing.refAllDecls(@This());
}

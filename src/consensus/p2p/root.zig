//! `p2p` group: from-scratch discv5, libp2p, and gossipsub for OP Stack unsafe-block
//! gossip. Mirrors base/base `crates/consensus/{peers,disc,gossip}`.

const std = @import("std");

pub const gossip = @import("gossip/root.zig");
pub const peers = @import("peers/root.zig");

test {
    std.testing.refAllDecls(@This());
}

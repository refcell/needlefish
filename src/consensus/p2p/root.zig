//! `p2p` group: from-scratch discv5, libp2p, and gossipsub for OP Stack unsafe-block
//! gossip. Mirrors base/base `crates/consensus/{peers,disc,gossip}`.

const std = @import("std");

pub const gossip = @import("gossip/root.zig");
pub const peers = @import("peers/root.zig");
pub const disc = @import("disc/root.zig");
pub const libp2p = @import("libp2p/root.zig");
pub const bench = @import("bench.zig");
pub const service = @import("service.zig");
pub const transport = @import("transport.zig");
pub const options = @import("options.zig");
pub const network = @import("network.zig");
pub const rpc = @import("rpc.zig");
pub const metrics = @import("metrics.zig");

test {
    std.testing.refAllDecls(@This());
}

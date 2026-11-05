//! `gossip`: gossipsub v1.1 wire codecs for OP Stack unsafe-block gossip. Mirrors
//! base/base `crates/consensus/gossip`.

const std = @import("std");

pub const rpc = @import("rpc.zig");
pub const snappy = @import("snappy.zig");

test {
    std.testing.refAllDecls(@This());
}

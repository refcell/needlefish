//! libp2p from scratch: multistream-select, Noise XX secure channel, and yamux
//! multiplexing. Every piece is an IO-free state machine over byte buffers so the
//! deterministic simulator can drive it; the TCP transport plugs in on top.

const std = @import("std");

pub const multistream = @import("multistream.zig");

test {
    std.testing.refAllDecls(@This());
}

//! libp2p from scratch: multistream-select, Noise XX secure channel, and yamux
//! multiplexing. Every piece is an IO-free state machine over byte buffers so the
//! deterministic simulator can drive it; the TCP transport plugs in on top.

const std = @import("std");

pub const multistream = @import("multistream.zig");
pub const protobuf = @import("protobuf.zig");
pub const identity = @import("identity.zig");
pub const chacha_poly = @import("chacha_poly.zig");
pub const noise = @import("noise.zig");
pub const yamux = @import("yamux.zig");
pub const identify = @import("identify.zig");
pub const ping = @import("ping.zig");
pub const connections = @import("connections.zig");
pub const connection = @import("connection.zig");

test {
    std.testing.refAllDecls(@This());
}

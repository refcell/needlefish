//! `batcher` group. Mirrors base/base `crates/batcher`: turns L2 blocks into channels,
//! frames, and L1 transactions (calldata or blobs).

const std = @import("std");

pub const frame = @import("frame/root.zig");
pub const blobs = @import("blobs/root.zig");
pub const comp = @import("comp/root.zig");
pub const channel = @import("channel/root.zig");
pub const devnet = @import("devnet/root.zig");
pub const txdata = @import("txdata/root.zig");
pub const rpc = @import("rpc/root.zig");

test {
    std.testing.refAllDecls(@This());
}

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
pub const source = @import("source/root.zig");
pub const txmgr = @import("txmgr/root.zig");
pub const service = @import("service/root.zig");
pub const metrics = @import("metrics/root.zig");
pub const throttle = @import("throttle/root.zig");

test {
    std.testing.refAllDecls(@This());
}

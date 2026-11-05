//! Rollup protocol types: frames, channels, batches, L1 info, deposits, system config.
//! Mirrors base/base `crates/consensus/protocol`.

const std = @import("std");

pub const block = @import("block.zig");
pub const frame = @import("frame.zig");
pub const channel = @import("channel.zig");

pub const BlockId = block.BlockId;
pub const BlockInfo = block.BlockInfo;
pub const L2BlockInfo = block.L2BlockInfo;
pub const Frame = frame.Frame;
pub const ChannelId = frame.ChannelId;
pub const Channel = channel.Channel;

test {
    std.testing.refAllDecls(@This());
}

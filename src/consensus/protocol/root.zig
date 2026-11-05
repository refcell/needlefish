//! Rollup protocol types: frames, channels, batches, L1 info, deposits, system config.
//! Mirrors base/base `crates/consensus/protocol`.

const std = @import("std");

pub const block = @import("block.zig");
pub const frame = @import("frame.zig");
pub const channel = @import("channel.zig");
pub const rollup_config = @import("rollup_config.zig");
pub const system_config = @import("system_config.zig");

pub const BlockId = block.BlockId;
pub const BlockInfo = block.BlockInfo;
pub const L2BlockInfo = block.L2BlockInfo;
pub const Frame = frame.Frame;
pub const ChannelId = frame.ChannelId;
pub const Channel = channel.Channel;
pub const RollupConfig = rollup_config.RollupConfig;
pub const Upgrade = rollup_config.Upgrade;
pub const Feature = rollup_config.Feature;
pub const SystemConfig = system_config.SystemConfig;

test {
    std.testing.refAllDecls(@This());
}

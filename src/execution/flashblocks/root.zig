//! `execution/flashblocks`: the flashblocks consumer. Mirrors base/base
//! `crates/execution/flashblocks` and the subscription part of `flashblocks-node`:
//! a WebSocket `Subscriber` feeds decoded flashblocks to the `Processor`, which validates
//! their order, assembles `PendingBlocks`, parks early arrivals in the `Cache`, and drives
//! a pending `state` builder.

const std = @import("std");

pub const validation = @import("validation.zig");
pub const pending = @import("pending.zig");
pub const cache = @import("cache.zig");
pub const state = @import("state.zig");
pub const state_executor = @import("state_executor.zig");
pub const processor = @import("processor.zig");
pub const subscriber = @import("subscriber.zig");
pub const rpc = @import("rpc.zig");
pub const pubsub = @import("pubsub.zig");

pub const PendingBlocks = pending.PendingBlocks;
pub const Cache = cache.Cache;
pub const Processor = processor.Processor;
pub const Subscriber = subscriber.Subscriber;
pub const ExecutorState = state_executor.ExecutorState;

test {
    std.testing.refAllDecls(@This());
    _ = @import("consumer_test.zig");
    _ = @import("state_executor_test.zig");
    _ = @import("rpc_test.zig");
}

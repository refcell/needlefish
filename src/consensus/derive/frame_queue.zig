//! Frame queue: parses batcher payloads into frames and, after Holocene, prunes frames
//! that break strict ordering.
//! Mirrors base/base `crates/consensus/derive/src/stages/frame_queue.rs`.
//!
//! Frames borrow the payload returned by `Retrieval.next_data`. That is safe because the
//! queue only asks for new data once it is empty, and the payload stays valid until then.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");

const Frame = protocol.frame.Frame;
const BlockInfo = protocol.block.BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Error = errors.Error;

pub const FrameQueue = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    frames: std.ArrayList(Frame) = .empty,
    /// Index of the next frame to hand out.
    head: u32 = 0,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) FrameQueue {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(queue: *FrameQueue) void {
        queue.frames.deinit(queue.allocator);
        queue.* = undefined;
    }

    pub fn len(queue: *const FrameQueue) u32 {
        assert(queue.head <= queue.frames.items.len);
        return @intCast(queue.frames.items.len - queue.head);
    }

    pub fn clear(queue: *FrameQueue) void {
        queue.frames.clearRetainingCapacity();
        queue.head = 0;
    }

    /// Returns the next frame. `error.NotEnoughData` means a payload was consumed without
    /// producing frames; the caller just steps again.
    pub fn next_frame(
        queue: *FrameQueue,
        retrieval: anytype,
        chain: anytype,
        blobs: anytype,
    ) Error!Frame {
        if (queue.len() == 0) try queue.load(retrieval, chain, blobs);
        if (queue.len() == 0) return error.NotEnoughData;
        defer queue.head += 1;
        return queue.frames.items[queue.head];
    }

    fn load(queue: *FrameQueue, retrieval: anytype, chain: anytype, blobs: anytype) Error!void {
        assert(queue.len() == 0);
        queue.clear();
        const data = try retrieval.next_data(chain, blobs);
        // A payload holds at most one frame per `encoded_overhead` bytes.
        const frames_max = data.len / Frame.encoded_overhead + 1;
        try queue.frames.ensureTotalCapacity(queue.allocator, frames_max);
        queue.frames.items.len = frames_max;
        const parsed = protocol.frame.parse_frames(data, queue.frames.items) catch {
            // An invalid payload is dropped as a whole.
            queue.clear();
            return;
        };
        queue.frames.items.len = parsed.len;
        const origin = retrieval.origin() orelse return error.MissingOrigin;
        if (queue.rollup.is_feature_active(.strict_derivation_ordering, origin.timestamp)) {
            prune(&queue.frames);
        }
    }

    /// Holocene frame ordering: within a payload, frames of a channel must be consecutive
    /// from zero, nothing may follow a closing frame, and an unclosed channel is dropped
    /// when a new channel starts.
    pub fn prune(frames: *std.ArrayList(Frame)) void {
        var index: usize = 0;
        // Removals happen at most `len` times. A drain removes `k` frames and steps `index`
        // back by `k`, so advances total at most `2 * len`: at most `3 * len` iterations.
        const iterations_max = frames.items.len * 3 + 1;
        for (0..iterations_max) |_| {
            if (index + 1 >= frames.items.len) break;
            const previous = frames.items[index];
            const next = frames.items[index + 1];
            const extends = std.mem.eql(u8, &previous.id, &next.id);
            if (extends and (previous.number + 1 != next.number or previous.is_last)) {
                _ = frames.orderedRemove(index + 1);
            } else if (!extends and next.number != 0) {
                _ = frames.orderedRemove(index + 1);
            } else if (!extends and !previous.is_last) {
                // `next` starts a new channel while `previous` is unclosed: drop the
                // unclosed channel's frames, which are consecutive up to `index`.
                var first = index;
                while (first > 0 and std.mem.eql(u8, &frames.items[first - 1].id, &previous.id)) {
                    first -= 1;
                }
                frames.replaceRangeAssumeCapacity(first, index + 1 - first, &.{});
                // Re-check the new boundary pair (base/base `i.saturating_sub(drained)`).
                index = first -| 1;
            } else {
                index += 1;
            }
        } else unreachable; // Proof: see the iteration bound above.
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const Spec = struct { id: u8, number: u16, last: bool };

fn spec_frame(spec: Spec) Frame {
    return .{ .id = @splat(spec.id), .number = spec.number, .data = "", .is_last = spec.last };
}

fn expect_pruned(specs: []const Spec, expected: []const usize) !void {
    var frames: std.ArrayList(Frame) = .empty;
    defer frames.deinit(testing.allocator);
    for (specs) |spec| try frames.append(testing.allocator, spec_frame(spec));
    FrameQueue.prune(&frames);
    try testing.expectEqual(expected.len, frames.items.len);
    for (expected, frames.items) |index, frame| {
        try testing.expectEqualDeep(spec_frame(specs[index]), frame);
    }
}

test "frame queue: holocene pruning (base/base cases)" {
    // Unordered: a frame after the closing frame is dropped.
    try expect_pruned(&.{
        .{ .id = 0xee, .number = 0, .last = false }, .{ .id = 0xee, .number = 1, .last = false },
        .{ .id = 0xee, .number = 2, .last = true },  .{ .id = 0xee, .number = 3, .last = false },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 0, 1, 2, 4, 5 });
    // Non-sequential frames are dropped.
    try expect_pruned(&.{
        .{ .id = 0xee, .number = 0, .last = false }, .{ .id = 0xee, .number = 1, .last = false },
        .{ .id = 0xee, .number = 3, .last = true },  .{ .id = 0xee, .number = 4, .last = false },
    }, &.{ 0, 1 });
    // An unclosed channel is replaced by the next one.
    try expect_pruned(&.{
        .{ .id = 0xee, .number = 0, .last = false }, .{ .id = 0xee, .number = 1, .last = false },
        .{ .id = 0xee, .number = 2, .last = false }, .{ .id = 0xee, .number = 3, .last = false },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 4, 5 });
    // A channel that does not start at frame zero is dropped.
    try expect_pruned(&.{
        .{ .id = 0xdd, .number = 0, .last = false }, .{ .id = 0xdd, .number = 1, .last = false },
        .{ .id = 0xdd, .number = 2, .last = false }, .{ .id = 0xdd, .number = 3, .last = true },
        .{ .id = 0xee, .number = 1, .last = false }, .{ .id = 0xee, .number = 2, .last = true },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 0, 1, 2, 3, 6, 7 });
    // Unclosed channel followed by an invalid start keeps the unclosed frames.
    try expect_pruned(&.{
        .{ .id = 0xee, .number = 0, .last = false }, .{ .id = 0xee, .number = 1, .last = false },
        .{ .id = 0xee, .number = 2, .last = false }, .{ .id = 0xee, .number = 3, .last = false },
        .{ .id = 0xff, .number = 1, .last = false }, .{ .id = 0xff, .number = 2, .last = true },
    }, &.{ 0, 1, 2, 3 });
    // Replace channel.
    try expect_pruned(&.{
        .{ .id = 0xdd, .number = 0, .last = false }, .{ .id = 0xdd, .number = 1, .last = true },
        .{ .id = 0xee, .number = 0, .last = false }, .{ .id = 0xee, .number = 1, .last = false },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 0, 1, 4, 5 });
    // Interleaved invalid and valid channels.
    try expect_pruned(&.{
        .{ .id = 0x01, .number = 0, .last = false }, .{ .id = 0x02, .number = 0, .last = false },
        .{ .id = 0x01, .number = 1, .last = true },  .{ .id = 0x02, .number = 1, .last = false },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 4, 5 });
    try expect_pruned(&.{
        .{ .id = 0x01, .number = 0, .last = false }, .{ .id = 0x02, .number = 0, .last = false },
        .{ .id = 0x01, .number = 1, .last = true },  .{ .id = 0x02, .number = 1, .last = true },
        .{ .id = 0xff, .number = 0, .last = false }, .{ .id = 0xff, .number = 1, .last = true },
    }, &.{ 1, 3, 4, 5 });
}

test "frame queue: seeded fuzz prune invariants" {
    var prng = Prng.init(0x50525545);
    var specs: [24]Spec = undefined;
    var frames: std.ArrayList(Frame) = .empty;
    defer frames.deinit(testing.allocator);
    for (0..2_000) |_| {
        frames.clearRetainingCapacity();
        const count = prng.below(specs.len + 1);
        for (specs[0..count]) |*spec| {
            spec.* = .{
                .id = @intCast(prng.below(3)),
                .number = @intCast(prng.below(4)),
                .last = prng.chance(1, 3),
            };
            try frames.append(testing.allocator, spec_frame(spec.*));
        }
        FrameQueue.prune(&frames);
        const items = frames.items;
        for (items, 0..) |frame, index| {
            if (index == 0) continue;
            const previous = items[index - 1];
            if (std.mem.eql(u8, &previous.id, &frame.id)) {
                try testing.expect(previous.number + 1 == frame.number and !previous.is_last);
            } else {
                try testing.expect(frame.number == 0 and previous.is_last);
            }
        }
    }
}

test "frame queue: loads payloads through retrieval" {
    const Retrieval = @import("retrieval.zig").Retrieval;
    const TestChain = @import("test_chain.zig").TestChain;
    const L1Transaction = @import("providers.zig").L1Transaction;
    const Address = @import("../../common/primitives/root.zig").Address;
    const inbox = Address.init(@splat(0x11));
    const batcher = Address.init(@splat(0x22));
    var rollup: RollupConfig = .{ .batch_inbox_address = inbox };
    rollup.upgrades.set(.holocene, 0);

    var payload: [1 + 3 * 30]u8 = undefined;
    payload[0] = protocol.frame.derivation_version_0;
    var written: usize = 1;
    const frames = [_]Frame{
        .{ .id = @splat(1), .number = 0, .data = "abcdefg", .is_last = false },
        .{ .id = @splat(1), .number = 2, .data = "dropped", .is_last = true },
        .{ .id = @splat(1), .number = 1, .data = "closing", .is_last = true },
    };
    for (&frames) |*frame| written += frame.encode(payload[written..]).len;
    var chain = TestChain.init(2, 0, 12);
    const transactions = [_]L1Transaction{
        .{ .tx_type = 2, .to = inbox, .from = batcher, .input = payload[0..written] },
        .{ .tx_type = 2, .to = inbox, .from = batcher, .input = "garbage" },
    };
    chain.transactions[0] = &transactions;

    var retrieval = Retrieval.init(testing.allocator, &rollup);
    defer retrieval.deinit();
    try retrieval.reset(&chain, chain.blocks[0].id(), .{ .batcher_address = batcher });
    var queue = FrameQueue.init(testing.allocator, &rollup);
    defer queue.deinit();
    const first = try queue.next_frame(&retrieval, &chain, &chain);
    try testing.expectEqualStrings("abcdefg", first.data);
    const second = try queue.next_frame(&retrieval, &chain, &chain);
    try testing.expectEqualStrings("closing", second.data);
    try testing.expectError(error.NotEnoughData, queue.next_frame(&retrieval, &chain, &chain));
    try testing.expectError(error.Eof, queue.next_frame(&retrieval, &chain, &chain));
}

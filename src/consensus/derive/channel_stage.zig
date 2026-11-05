//! Channel stages: frames → complete channel data.
//!
//! Before Holocene the channel bank buffers many channels at once, keyed by id, and emits
//! them in arrival order (any ready one after Granite). After Holocene the channel
//! assembler builds exactly one channel from in-order frames. The provider switches
//! between them as the L1 origin crosses the Holocene activation.
//! Mirrors base/base `crates/consensus/derive/src/stages/channel/{channel_bank,
//! channel_assembler,channel_provider}.rs`.
//!
//! The upstream stage (`prev`) exposes `next_frame() Error!Frame` and
//! `origin() ?BlockInfo`. Returned channel data is owned by the caller.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");

const Frame = protocol.frame.Frame;
const ChannelId = protocol.frame.ChannelId;
const Channel = protocol.channel.Channel;
const BlockInfo = protocol.block.BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const Error = errors.Error;

pub const max_channel_bank_size: u64 = 100_000_000;
pub const fjord_max_channel_bank_size: u64 = 1_000_000_000;

fn timed_out(rollup: *const RollupConfig, channel: *const Channel, origin: BlockInfo) bool {
    const timeout = rollup.channel_timeout_at(origin.timestamp);
    return channel.open_block.number +| timeout < origin.number;
}

fn add_frame_or_drop(
    allocator: Allocator,
    channel: *Channel,
    frame: Frame,
    origin: BlockInfo,
) Error!bool {
    channel.add_frame(allocator, frame, origin) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return false;
    };
    return true;
}

pub const ChannelBank = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    channels: std.AutoHashMapUnmanaged(ChannelId, Channel) = .empty,
    /// Channel ids in arrival order.
    queue: std.ArrayList(ChannelId) = .empty,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) ChannelBank {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(bank: *ChannelBank) void {
        bank.clear();
        bank.channels.deinit(bank.allocator);
        bank.queue.deinit(bank.allocator);
        bank.* = undefined;
    }

    pub fn clear(bank: *ChannelBank) void {
        var iterator = bank.channels.valueIterator();
        while (iterator.next()) |channel| channel.deinit(bank.allocator);
        bank.channels.clearRetainingCapacity();
        bank.queue.clearRetainingCapacity();
    }

    pub fn size(bank: *const ChannelBank) u64 {
        var total: u64 = 0;
        var iterator = bank.channels.valueIterator();
        while (iterator.next()) |channel| total += channel.estimated_size;
        return total;
    }

    fn remove_at(bank: *ChannelBank, index: usize) void {
        const id = bank.queue.orderedRemove(index);
        var entry = bank.channels.fetchRemove(id).?;
        entry.value.deinit(bank.allocator);
        assert(bank.channels.count() == bank.queue.items.len);
    }

    /// Evicts the oldest channels until the bank fits its size limit.
    fn prune(bank: *ChannelBank, origin: BlockInfo) void {
        var limit = max_channel_bank_size;
        if (bank.rollup.is_feature_active(.channel_bank_size_expansion, origin.timestamp)) {
            limit = fjord_max_channel_bank_size;
        }
        var total = bank.size();
        while (total > limit) {
            assert(bank.queue.items.len > 0);
            const channel = bank.channels.getPtr(bank.queue.items[0]).?;
            total -= channel.estimated_size;
            bank.remove_at(0);
        }
    }

    pub fn ingest_frame(bank: *ChannelBank, frame: Frame, origin: BlockInfo) Error!void {
        try bank.queue.ensureUnusedCapacity(bank.allocator, 1);
        const entry = try bank.channels.getOrPut(bank.allocator, frame.id);
        if (!entry.found_existing) {
            entry.value_ptr.* = Channel.init(frame.id, origin);
            bank.queue.appendAssumeCapacity(frame.id);
        }
        if (timed_out(bank.rollup, entry.value_ptr, origin)) return;
        if (!try add_frame_or_drop(bank.allocator, entry.value_ptr, frame, origin)) return;
        bank.prune(origin);
    }

    /// Returns ready channel data, null when a timed-out head channel was dropped, or
    /// `error.Eof` when nothing is ready.
    pub fn read(bank: *ChannelBank, origin: BlockInfo) Error!?[]u8 {
        if (bank.queue.items.len == 0) return error.Eof;
        const first = bank.channels.getPtr(bank.queue.items[0]).?;
        if (timed_out(bank.rollup, first, origin)) {
            bank.remove_at(0);
            return null;
        }
        if (!bank.rollup.is_feature_active(.ready_channel_selection, origin.timestamp)) {
            return try bank.try_read_at(0, origin) orelse error.Eof;
        }
        for (0..bank.queue.items.len) |index| {
            if (try bank.try_read_at(index, origin)) |data| return data;
        }
        return error.Eof;
    }

    fn try_read_at(bank: *ChannelBank, index: usize, origin: BlockInfo) Error!?[]u8 {
        const channel = bank.channels.getPtr(bank.queue.items[index]).?;
        if (timed_out(bank.rollup, channel, origin) or !channel.is_ready()) return null;
        const data = try channel.frame_data_alloc(bank.allocator);
        bank.remove_at(index);
        return data;
    }

    pub fn next_data(bank: *ChannelBank, prev: anytype) Error!?[]u8 {
        const origin = prev.origin() orelse return error.MissingOrigin;
        if (bank.read(origin)) |data| {
            return data;
        } else |err| {
            if (err != error.Eof) return err;
        }
        const frame = try prev.next_frame();
        try bank.ingest_frame(frame, origin);
        return error.NotEnoughData;
    }
};

pub const ChannelAssembler = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    channel: ?Channel = null,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) ChannelAssembler {
        return .{ .allocator = allocator, .rollup = rollup };
    }

    pub fn deinit(assembler: *ChannelAssembler) void {
        assembler.clear();
        assembler.* = undefined;
    }

    pub fn clear(assembler: *ChannelAssembler) void {
        if (assembler.channel) |*channel| channel.deinit(assembler.allocator);
        assembler.channel = null;
    }

    pub fn next_data(assembler: *ChannelAssembler, prev: anytype) Error!?[]u8 {
        const origin = prev.origin() orelse return error.MissingOrigin;
        if (assembler.channel) |*channel| {
            if (timed_out(assembler.rollup, channel, origin)) assembler.clear();
        }
        const frame = try prev.next_frame();
        if (frame.number == 0) {
            assembler.clear();
            assembler.channel = Channel.init(frame.id, origin);
        }
        const channel = &(assembler.channel orelse return error.NotEnoughData);
        // Out-of-order frames are dropped (the frame queue already pruned most).
        if (frame.number != channel.frame_count()) return error.NotEnoughData;
        if (!try add_frame_or_drop(assembler.allocator, channel, frame, origin)) {
            return error.NotEnoughData;
        }
        const size_max = assembler.rollup.max_rlp_bytes_per_channel(origin.timestamp);
        if (channel.estimated_size > size_max) {
            assembler.clear();
            return error.NotEnoughData;
        }
        if (!channel.is_ready()) return error.NotEnoughData;
        const data = try channel.frame_data_alloc(assembler.allocator);
        assembler.clear();
        return data;
    }
};

/// Switches between the bank and the assembler on the Holocene boundary. Switching
/// discards the buffered channels of the old stage, as base/base does.
pub const ChannelProvider = struct {
    rollup: *const RollupConfig,
    mode: enum { unset, bank, assembler } = .unset,
    bank: ChannelBank,
    assembler: ChannelAssembler,

    pub fn init(allocator: Allocator, rollup: *const RollupConfig) ChannelProvider {
        return .{
            .rollup = rollup,
            .bank = ChannelBank.init(allocator, rollup),
            .assembler = ChannelAssembler.init(allocator, rollup),
        };
    }

    pub fn deinit(provider: *ChannelProvider) void {
        provider.bank.deinit();
        provider.assembler.deinit();
        provider.* = undefined;
    }

    pub fn attempt_update(provider: *ChannelProvider, origin: BlockInfo) void {
        const holocene = provider.rollup.is_feature_active(
            .strict_derivation_ordering,
            origin.timestamp,
        );
        const wanted: @TypeOf(provider.mode) = if (holocene) .assembler else .bank;
        if (provider.mode == wanted) return;
        provider.bank.clear();
        provider.assembler.clear();
        provider.mode = wanted;
        assert(provider.mode != .unset);
    }

    /// Clears buffered channels (reset, activation, flush).
    pub fn clear(provider: *ChannelProvider, origin: BlockInfo) void {
        provider.attempt_update(origin);
        provider.bank.clear();
        provider.assembler.clear();
    }

    pub fn next_data(provider: *ChannelProvider, prev: anytype) Error!?[]u8 {
        const origin = prev.origin() orelse return error.MissingOrigin;
        provider.attempt_update(origin);
        return switch (provider.mode) {
            .bank => provider.bank.next_data(prev),
            .assembler => provider.assembler.next_data(prev),
            .unset => unreachable, // Proof: attempt_update always sets a mode.
        };
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// Upstream stub: hands out `frames` in order, then `error.Eof`.
const TestFrames = struct {
    frames: []const Frame,
    index: usize = 0,
    block: ?BlockInfo = .{},

    fn next_frame(stub: *TestFrames) Error!Frame {
        if (stub.index == stub.frames.len) return error.Eof;
        defer stub.index += 1;
        return stub.frames[stub.index];
    }

    fn origin(stub: *const TestFrames) ?BlockInfo {
        return stub.block;
    }
};

fn test_frame(id: u8, number: u16, data: []const u8, is_last: bool) Frame {
    return .{ .id = @splat(id), .number = number, .data = data, .is_last = is_last };
}

/// Steps `next_data` until it yields data or upstream reports Eof.
fn drain(provider: anytype, stub: *TestFrames) !?[]u8 {
    for (0..64) |_| {
        const data = provider.next_data(stub) catch |err| switch (err) {
            error.NotEnoughData => continue,
            error.Eof => return null,
            else => return err,
        } orelse continue;
        return data;
    }
    unreachable;
}

test "channel bank: interleaved channels emit in arrival order" {
    const rollup: RollupConfig = .{ .channel_timeout = 10 };
    var bank = ChannelBank.init(testing.allocator, &rollup);
    defer bank.deinit();
    const frames = [_]Frame{
        test_frame(1, 1, "b", true),
        test_frame(2, 0, "x", true),
        test_frame(1, 0, "a", false),
    };
    var stub: TestFrames = .{ .frames = &frames };
    // Pre-Granite only the head channel (1) may be read, so channel 2 waits.
    const first = (try drain(&bank, &stub)).?;
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("ab", first);
    const second = (try drain(&bank, &stub)).?;
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("x", second);
    try testing.expectEqual(null, try drain(&bank, &stub));
}

test "channel bank: granite reads any ready channel; timeouts drop channels" {
    var rollup: RollupConfig = .{ .channel_timeout = 10, .granite_channel_timeout = 2 };
    rollup.upgrades.set(.granite, 0);
    var bank = ChannelBank.init(testing.allocator, &rollup);
    defer bank.deinit();
    try bank.ingest_frame(test_frame(1, 0, "a", false), .{ .number = 0 });
    try bank.ingest_frame(test_frame(2, 0, "x", true), .{ .number = 0 });
    const data = (try bank.read(.{ .number = 1 })).?;
    defer testing.allocator.free(data);
    try testing.expectEqualStrings("x", data);
    try testing.expectError(error.Eof, bank.read(.{ .number = 2 }));
    try testing.expectEqual(null, try bank.read(.{ .number = 3 }));
    try testing.expectError(error.Eof, bank.read(.{ .number = 3 }));
    // A frame for a timed-out channel is ignored but the channel is still tracked.
    try bank.ingest_frame(test_frame(3, 0, "c", false), .{ .number = 3 });
    try bank.ingest_frame(test_frame(3, 1, "d", true), .{ .number = 6 });
    try testing.expectEqual(null, try bank.read(.{ .number = 6 }));
}

test "channel bank: prunes oldest channels over the size limit" {
    const rollup: RollupConfig = .{ .channel_timeout = 10 };
    var bank = ChannelBank.init(testing.allocator, &rollup);
    defer bank.deinit();
    // Each frame counts its data plus `size_overhead`; size the data to exceed the limit
    // with the second channel.
    const big = try testing.allocator.alloc(u8, max_channel_bank_size / 2 + 1);
    defer testing.allocator.free(big);
    @memset(big, 0xaa);
    try bank.ingest_frame(test_frame(1, 0, big, false), .{});
    try bank.ingest_frame(test_frame(2, 0, big, false), .{});
    try testing.expectEqual(@as(usize, 1), bank.queue.items.len);
    try testing.expectEqual(@as(u8, 2), bank.queue.items[0][0]);
}

test "channel assembler: in-order frames, restarts, and size limit" {
    var rollup: RollupConfig = .{ .channel_timeout = 10 };
    rollup.upgrades.set(.holocene, 0);
    var assembler = ChannelAssembler.init(testing.allocator, &rollup);
    defer assembler.deinit();
    const frames = [_]Frame{
        test_frame(1, 1, "orphan", false), // No open channel: dropped.
        test_frame(1, 0, "a", false),
        test_frame(1, 2, "skip", true), // Out of order: dropped.
        test_frame(2, 0, "x", false), // Restarts with a new channel.
        test_frame(2, 1, "y", true),
        test_frame(3, 0, "lone", true),
    };
    var stub: TestFrames = .{ .frames = &frames };
    const first = (try drain(&assembler, &stub)).?;
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("xy", first);
    const second = (try drain(&assembler, &stub)).?;
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("lone", second);
    try testing.expectEqual(null, try drain(&assembler, &stub));
}

test "channel provider: switches stage at holocene" {
    var rollup: RollupConfig = .{ .channel_timeout = 10 };
    rollup.upgrades.set(.holocene, 100);
    var provider = ChannelProvider.init(testing.allocator, &rollup);
    defer provider.deinit();
    const frames = [_]Frame{ test_frame(1, 0, "a", false), test_frame(1, 1, "b", true) };
    var stub: TestFrames = .{ .frames = &frames, .block = .{ .timestamp = 50 } };
    try testing.expectError(error.NotEnoughData, provider.next_data(&stub));
    try testing.expect(provider.mode == .bank);
    stub.block = .{ .timestamp = 100 };
    // The switch drops the partial bank channel; frame 1 then has no open channel.
    try testing.expectError(error.NotEnoughData, provider.next_data(&stub));
    try testing.expect(provider.mode == .assembler);
    try testing.expectEqual(null, try drain(&provider, &stub));
}

test "channel stages: seeded fuzz frame streams" {
    var prng = Prng.init(0x4348414e);
    var rollup: RollupConfig = .{ .channel_timeout = 4 };
    var frames: [32]Frame = undefined;
    const payloads = [_][]const u8{ "", "a", "bc", "def" };
    for (0..300) |round| {
        rollup.upgrades.set(.holocene, if (round % 2 == 0) 0 else null);
        rollup.upgrades.set(.granite, if (round % 3 == 0) 0 else null);
        const count = prng.below(frames.len + 1);
        for (frames[0..count]) |*frame| {
            frame.* = test_frame(
                @intCast(prng.below(3)),
                @intCast(prng.below(4)),
                payloads[prng.below(payloads.len)],
                prng.chance(1, 3),
            );
        }
        var provider = ChannelProvider.init(testing.allocator, &rollup);
        defer provider.deinit();
        var stub: TestFrames = .{ .frames = frames[0..count] };
        for (0..frames.len * 2 + 2) |_| {
            stub.block.?.number += prng.below(2);
            const data = provider.next_data(&stub) catch |err| switch (err) {
                error.NotEnoughData => continue,
                error.Eof => break,
                else => return err,
            } orelse continue;
            defer testing.allocator.free(data);
            try testing.expect(data.len <= 3 * 4);
        }
    }
}

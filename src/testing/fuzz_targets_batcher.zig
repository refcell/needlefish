//! Model-based fuzz target for the batcher's channel manager (`batcher/channel/manager.zig`).
//!
//! A fuzzed interleaving of block additions (including reorged parents), L1 heads, closes,
//! drains, and resets drives the manager with random channel configurations. Every emitted
//! transaction goes through the consensus-side decoders (frame parsing, channel
//! reassembly, decompression, batch reading). Properties:
//!   - each completed channel holds the next accepted blocks, exactly: no gap, no
//!     duplicate, no reordering, and byte-identical batch contents;
//!   - a reorged parent is rejected without changing state;
//!   - a final close and drain delivers every block accepted since the last reset.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const manager_module = @import("../batcher/channel/manager.zig");
const source = @import("../batcher/source/root.zig");
const protocol = @import("../consensus/protocol/root.zig");
const primitives = @import("../common/primitives/root.zig");

const B256 = primitives.B256;
const Manager = manager_module.Manager;
const SingleBatch = protocol.batch.SingleBatch;
const batch_reader = protocol.batch_reader;

const operations_max = 96;
const tx_bytes_max = 48;
const batch_bytes_max = 256;
const drain_frames_max = 4096;
const decompressed_bytes_max = 64 * 1024;

/// A small selector; see `fuzz_targets.draw_below` for why not `valueRangeAtMost`.
fn draw_below(smith: *Smith, comptime n: u8) u8 {
    comptime assert(n > 0);
    return smith.value(u8) % n;
}

/// Blocks are a pure function of their number and the run's content seed.
const Chain = struct {
    content_seed: u64,

    fn hash(chain: Chain, number: u64) B256 {
        var result: B256 = .zero;
        std.mem.writeInt(u64, result.bytes[0..8], chain.content_seed, .big);
        std.mem.writeInt(u64, result.bytes[24..32], number, .big);
        return result;
    }

    fn tx(chain: Chain, number: u64, out: *[tx_bytes_max]u8) []const u8 {
        var prng = Prng.init(chain.content_seed ^ (number *% 0x9e37_79b9_7f4a_7c15));
        const length: usize = @intCast(prng.range(1, tx_bytes_max));
        out[0] = 0x02;
        // Low-entropy fill half the time so compression ratios vary.
        if (prng.chance(1, 2)) {
            @memset(out[1..length], @truncate(number));
        } else {
            prng.fill(out[1..length]);
        }
        return out[0..length];
    }

    fn block(
        chain: Chain,
        number: u64,
        tx_buffer: *[tx_bytes_max]u8,
        txs: *[1][]const u8,
    ) source.L2Block {
        assert(number > 0);
        txs[0] = chain.tx(number, tx_buffer);
        return .{
            .number = number,
            .hash = chain.hash(number),
            .parent_hash = chain.hash(number - 1),
            .timestamp = number * 2,
            .l1_origin = .{ .number = number / 6, .hash = chain.hash(1_000_000 + number / 6) },
            .sequence_number = number % 6,
            .transactions = txs,
        };
    }
};

const Checker = struct {
    chain: Chain,
    /// Channel frames and decoding; brotli's window is too large for a fixed scratch.
    arena: std.heap.ArenaAllocator,
    channel: ?protocol.Channel = null,
    /// Next block number a completed channel must start with.
    pending_from: u64,
    channels_completed: u32 = 0,

    fn on_tx_data(checker: *Checker, tx_data: []const u8) !void {
        var frames_buffer: [2]protocol.Frame = undefined;
        const frames = try protocol.frame.parse_frames(tx_data, &frames_buffer);
        try std.testing.expectEqual(@as(usize, 1), frames.len);
        const frame = frames[0];
        const same = if (checker.channel) |*channel|
            std.mem.eql(u8, &channel.id, &frame.id)
        else
            false;
        if (!same) {
            // A reset abandons a partly drained channel; frames of a channel are contiguous.
            try std.testing.expectEqual(@as(u16, 0), frame.number);
            _ = checker.arena.reset(.retain_capacity);
            checker.channel = protocol.Channel.init(frame.id, .{});
        }
        const channel = &checker.channel.?;
        try channel.add_frame(checker.arena.allocator(), frame, .{});
        if (!channel.is_ready()) {
            try std.testing.expect(!frame.is_last);
            return;
        }
        try std.testing.expect(frame.is_last);
        try checker.check_channel(channel);
        checker.channel = null;
        checker.channels_completed += 1;
    }

    fn check_channel(checker: *Checker, channel: *protocol.Channel) !void {
        const allocator = checker.arena.allocator();
        const data = try channel.frame_data_alloc(allocator);
        const decompressed = try batch_reader.decompress_channel(
            allocator,
            data,
            decompressed_bytes_max,
            true,
        );
        var reader = batch_reader.BatchReader.init(decompressed);
        var count: u32 = 0;
        // Each batch item is at least a few bytes, so the input bounds the loop.
        for (0..decompressed.len + 1) |_| {
            const raw = (try reader.next()) orelse break;
            try std.testing.expect(raw.batch_type == .single);
            const batch = try SingleBatch.decode(allocator, raw.payload);
            try checker.check_batch(&batch, checker.pending_from + count);
            count += 1;
        }
        try std.testing.expect(count > 0);
        checker.pending_from += count;
    }

    fn check_batch(checker: *const Checker, batch: *const SingleBatch, number: u64) !void {
        var tx_buffer: [tx_bytes_max]u8 = undefined;
        var txs: [1][]const u8 = undefined;
        const expected = checker.chain.block(number, &tx_buffer, &txs);
        try std.testing.expectEqual(expected.timestamp, batch.timestamp);
        try std.testing.expect(expected.parent_hash.eql(batch.parent_hash));
        try std.testing.expectEqual(expected.l1_origin.number, batch.epoch_num);
        try std.testing.expect(expected.l1_origin.hash.eql(batch.epoch_hash));
        try std.testing.expectEqual(@as(usize, 1), batch.transactions.len);
        try std.testing.expectEqualSlices(u8, txs[0], batch.transactions[0]);
    }
};

fn draw_config(smith: *Smith) manager_module.Config {
    const overhead = protocol.Frame.encoded_overhead;
    const frame_sizes = [_]u32{ overhead + 1, overhead + 16, 96, 200, 512, 1400 };
    const inputs = [_]u32{ batch_bytes_max, 512, 1024, 4096 };
    return .{
        .channel = .{
            .frame_size_max = frame_sizes[draw_below(smith, frame_sizes.len)],
            .target_frames = 1 + draw_below(smith, 4),
            .compression_ratio_percent = 1 + draw_below(smith, 100),
            .input_bytes_max = inputs[draw_below(smith, inputs.len)],
            .algorithm = if (draw_below(smith, 4) == 0) .brotli else .zlib,
        },
        .max_channel_duration_l1_blocks = draw_below(smith, 4),
        .batch_bytes_max = batch_bytes_max,
    };
}

/// One fuzzed manager operation, checked against the model.
fn step(
    smith: *Smith,
    manager: *Manager,
    checker: *Checker,
    next_number: *u64,
    l1_head: *u64,
) !void {
    var tx_buffer: [tx_bytes_max]u8 = undefined;
    var txs: [1][]const u8 = undefined;
    switch (draw_below(smith, 8)) {
        0, 1, 2 => {
            const block = checker.chain.block(next_number.*, &tx_buffer, &txs);
            if (manager.add_block(&block, l1_head.*)) {
                next_number.* += 1;
            } else |err| try std.testing.expectEqual(error.Backpressure, err);
        },
        3 => {
            const before = manager.next_block_number() orelse return;
            var block = checker.chain.block(next_number.*, &tx_buffer, &txs);
            block.parent_hash.bytes[31] ^= 1;
            try std.testing.expectError(error.Reorg, manager.add_block(&block, l1_head.*));
            try std.testing.expectEqual(before, manager.next_block_number().?);
        },
        4 => {
            l1_head.* += 1;
            manager.on_l1_head(l1_head.*);
        },
        5 => if (!manager.has_pending_frames()) manager.close_open(),
        6 => if (manager.next_tx_data()) |tx_data| try checker.on_tx_data(tx_data),
        else => if (draw_below(smith, 4) == 0) {
            // Restart from an earlier block, as after a safe-head reset.
            manager.reset();
            const rewind = draw_below(smith, 8);
            next_number.* = @max(1, next_number.* -| rewind);
            checker.pending_from = next_number.*;
        },
    }
}

/// Closes and drains until nothing is left; every accepted block must be delivered.
fn finish(manager: *Manager, checker: *Checker, next_number: u64) !void {
    var frames: u32 = 0;
    for (0..3) |_| {
        if (!manager.has_pending_frames()) manager.close_open();
        while (manager.next_tx_data()) |tx_data| : (frames += 1) {
            try std.testing.expect(frames < drain_frames_max);
            try checker.on_tx_data(tx_data);
        }
    }
    try std.testing.expect(!manager.has_pending_frames());
    try std.testing.expectEqual(next_number, checker.pending_from);
}

fn fuzz_channel_manager(_: void, smith: *Smith) anyerror!void {
    const allocator = std.testing.allocator;
    const config = draw_config(smith);
    var seed: [16]u8 = undefined;
    smith.bytes(&seed);
    var manager = try Manager.init(allocator, config, seed);
    defer manager.deinit(allocator);
    var next_number: u64 = 1 + draw_below(smith, 100);
    var checker: Checker = .{
        .chain = .{ .content_seed = smith.value(u64) },
        .arena = .init(allocator),
        .pending_from = next_number,
    };
    defer checker.arena.deinit();
    var l1_head: u64 = 0;
    var operation: u32 = 0;
    while (operation < operations_max and !smith.eosWeightedSimple(15, 1)) : (operation += 1) {
        try step(smith, &manager, &checker, &next_number, &l1_head);
    }
    try finish(&manager, &checker, next_number);
}

test "fuzz_targets_batcher: channel manager delivers every accepted block exactly once" {
    try fuzz.run({}, fuzz_channel_manager, .{ .iterations = 256 });
}

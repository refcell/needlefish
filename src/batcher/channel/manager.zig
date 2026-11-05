//! Channel manager: L2 blocks in, transaction payloads (`version ++ frame`) out.
//!
//! Two channel buffers alternate: one open channel collects batches while the other,
//! closed, hands out its frames. When the open channel fills and the closed one still
//! has frames, `add_block` refuses the block (`error.Backpressure`) and the caller
//! retries it later, so memory stays fixed and blocks are never dropped.
//!
//! Each channel item is `rlp_string(batch_type ++ rlp(batch))` (OP Stack spec); we emit
//! singular batches (type 0). A block whose parent hash does not extend the previous
//! block signals an L2 reorg: the caller resets and restarts from the safe head.

const std = @import("std");
const assert = std.debug.assert;
const channel_module = @import("root.zig");
const frame_module = @import("../frame/root.zig");
const source = @import("../source/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const batch_module = @import("../../consensus/protocol/batch.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");

const ChannelOut = channel_module.ChannelOut;
const B256 = primitives.B256;

pub const singular_batch_type: u8 = 0;

pub const Config = struct {
    channel: channel_module.Config,
    /// Close a channel once this many L1 blocks passed since its first block (0: off).
    max_channel_duration_l1_blocks: u64 = 0,
    /// Largest single batch item (bounded by the channel input cap).
    batch_bytes_max: u32 = 1024 * 1024,
};

pub const AddError = error{ Backpressure, Reorg, BatchTooLarge };

pub const Manager = struct {
    config: Config,
    channels: [2]ChannelOut,
    /// Index of the open channel; the other one is closed or empty.
    open_index: u1,
    /// L1 head when the open channel received its first block.
    open_since_l1: ?u64,
    /// Whether the closed slot holds frames not yet handed out.
    draining: bool,
    last_block: ?struct { number: u64, hash: B256 },
    batch_buffer: []u8,
    tx_data_buffer: []u8,
    next_channel_id: u64,
    channel_id_seed: [16]u8,
    /// First and last L2 block numbers of each channel buffer's contents.
    first_block: [2]u64 = .{ 0, 0 },
    last_block_of: [2]u64 = .{ 0, 0 },

    /// `channel_id_seed` (from the injected randomness) keeps channel ids unique
    /// across restarts; ids are the seed with a counter mixed into the low bytes.
    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        channel_id_seed: [16]u8,
    ) !Manager {
        assert(config.batch_bytes_max <= config.channel.input_bytes_max);
        var first = try ChannelOut.init(allocator, config.channel, channel_id_seed);
        errdefer first.deinit(allocator);
        var second = try ChannelOut.init(allocator, config.channel, channel_id_seed);
        errdefer second.deinit(allocator);
        const batch_buffer = try allocator.alloc(u8, config.batch_bytes_max);
        errdefer allocator.free(batch_buffer);
        const tx_data_buffer = try allocator.alloc(u8, config.channel.frame_size_max + 1);
        var manager: Manager = .{
            .config = config,
            .channels = .{ first, second },
            .open_index = 0,
            .open_since_l1 = null,
            .draining = false,
            .last_block = null,
            .batch_buffer = batch_buffer,
            .tx_data_buffer = tx_data_buffer,
            .next_channel_id = 0,
            .channel_id_seed = channel_id_seed,
        };
        manager.channels[0].reset(manager.take_channel_id());
        return manager;
    }

    pub fn deinit(manager: *Manager, allocator: std.mem.Allocator) void {
        for (&manager.channels) |*channel| channel.deinit(allocator);
        allocator.free(manager.batch_buffer);
        allocator.free(manager.tx_data_buffer);
        manager.* = undefined;
    }

    fn take_channel_id(manager: *Manager) frame_module.ChannelId {
        var id = manager.channel_id_seed;
        const low = std.mem.readInt(u64, id[8..16], .big) +% manager.next_channel_id;
        std.mem.writeInt(u64, id[8..16], low, .big);
        manager.next_channel_id += 1;
        return id;
    }

    /// Drops all channel state; the next block may start anywhere.
    pub fn reset(manager: *Manager) void {
        manager.open_index = 0;
        manager.open_since_l1 = null;
        manager.draining = false;
        manager.last_block = null;
        manager.channels[0].reset(manager.take_channel_id());
    }

    pub fn next_block_number(manager: *const Manager) ?u64 {
        const last = manager.last_block orelse return null;
        return last.number + 1;
    }

    fn open(manager: *Manager) *ChannelOut {
        return &manager.channels[manager.open_index];
    }

    /// Adds one block's batch. `l1_head` is the current L1 head number.
    pub fn add_block(
        manager: *Manager,
        block: *const source.L2Block,
        l1_head: u64,
    ) AddError!void {
        if (manager.last_block) |last| {
            assert(block.number == last.number + 1);
            if (!block.parent_hash.eql(last.hash)) return error.Reorg;
        }
        const item = try encode_batch_item(block, manager.batch_buffer);
        manager.open().add_batch(item) catch {
            // Full: close it, and retry in the other buffer if that one is free.
            if (manager.draining) return error.Backpressure;
            manager.close_open();
            if (manager.draining) {
                manager.open().add_batch(item) catch return error.BatchTooLarge;
            }
        };
        if (manager.open_since_l1 == null) manager.open_since_l1 = l1_head;
        if (manager.open().batch_count == 1) manager.first_block[manager.open_index] = block.number;
        manager.last_block_of[manager.open_index] = block.number;
        manager.last_block = .{ .number = block.number, .hash = block.hash };
        assert(manager.open().batch_count > 0);
    }

    /// Closes the open channel when it is full or too old. Call on every new L1 head.
    pub fn on_l1_head(manager: *Manager, l1_head: u64) void {
        if (manager.draining) return;
        const since = manager.open_since_l1 orelse return;
        const duration = manager.config.max_channel_duration_l1_blocks;
        const expired = duration > 0 and l1_head >= since + duration;
        if (expired or manager.open().is_full()) manager.close_open();
    }

    /// Closes the open channel (if it has batches) and opens the other buffer.
    pub fn close_open(manager: *Manager) void {
        assert(!manager.draining);
        if (manager.open().batch_count == 0) return;
        manager.open().close();
        manager.draining = true;
        manager.open_index +%= 1;
        manager.channels[manager.open_index].reset(manager.take_channel_id());
        manager.open_since_l1 = null;
    }

    /// Next transaction payload, or null. Valid until the next call.
    pub fn next_tx_data(manager: *Manager) ?[]const u8 {
        if (!manager.draining) return null;
        const closed = &manager.channels[manager.open_index +% 1];
        const frame = closed.next_frame() orelse unreachable; // Draining implies frames.
        if (frame.is_last) manager.draining = false;
        const frames = [_]frame_module.Frame{frame};
        return frame_module.encode_tx_data(&frames, manager.tx_data_buffer);
    }

    /// First L2 block of the channel whose frames `next_tx_data` hands out, if any.
    pub fn draining_first_block(manager: *const Manager) ?u64 {
        if (!manager.draining) return null;
        return manager.first_block[manager.open_index +% 1];
    }

    /// Last L2 block of the channel whose frames `next_tx_data` hands out, if any.
    pub fn draining_last_block(manager: *const Manager) ?u64 {
        if (!manager.draining) return null;
        return manager.last_block_of[manager.open_index +% 1];
    }

    pub fn has_pending_frames(manager: *const Manager) bool {
        return manager.draining;
    }
};

/// Writes `rlp_string(0x00 ++ rlp(singular_batch))` for `block` into `out`.
pub fn encode_batch_item(block: *const source.L2Block, out: []u8) error{BatchTooLarge}![]u8 {
    const batch: batch_module.SingleBatch = .{
        .parent_hash = block.parent_hash,
        .epoch_num = block.l1_origin.number,
        .epoch_hash = block.l1_origin.hash,
        .timestamp = block.timestamp,
        .transactions = block.transactions,
    };
    const content_length = 1 + batch.encoded_length();
    const total = rlp.header_length(content_length) + content_length;
    if (total > out.len) return error.BatchTooLarge;
    var encoder = rlp.Encoder.init(out[0..total]);
    encoder.string_header(content_length);
    encoder.raw(&.{singular_batch_type});
    // Prefix: RLP string header plus the batch type byte.
    const prefix_bytes = encoder.written().len;
    assert(prefix_bytes - 1 + content_length == total);
    _ = batch.encode(out[prefix_bytes..total]);
    return out[0..total];
}

const testing = std.testing;
const comp = @import("../comp/root.zig");

fn test_block(number: u64, parent: B256, transactions: []const []const u8) source.L2Block {
    var hash: B256 = .zero;
    std.mem.writeInt(u64, hash.bytes[0..8], number, .big);
    return .{
        .number = number,
        .hash = hash,
        .parent_hash = parent,
        .timestamp = 1000 + number,
        .l1_origin = .{ .number = number / 4, .hash = .{ .bytes = @splat(7) } },
        .sequence_number = number % 4,
        .transactions = transactions,
    };
}

test "manager: blocks become frames that decode back to the same batches" {
    var manager = try Manager.init(testing.allocator, .{
        .channel = .{ .frame_size_max = 200, .target_frames = 8, .input_bytes_max = 64 * 1024 },
        .max_channel_duration_l1_blocks = 2,
        .batch_bytes_max = 4096,
    }, @splat(0x5a));
    defer manager.deinit(testing.allocator);
    const txs = [_][]const u8{ "\x02tx-one", "\x02tx-two" };
    var parent: B256 = .zero;
    for (1..6) |number| {
        const block = test_block(number, parent, &txs);
        try manager.add_block(&block, 10);
        parent = block.hash;
    }
    try testing.expectEqual(@as(?u64, 6), manager.next_block_number());
    try testing.expectEqual(@as(?[]const u8, null), manager.next_tx_data());
    manager.on_l1_head(11);
    try testing.expect(!manager.has_pending_frames());
    manager.on_l1_head(12);
    try testing.expect(manager.has_pending_frames());

    // Reassemble through the consensus channel and decode every batch item.
    var bank = protocol.Channel.init(manager.channels[0].id, .{});
    defer bank.deinit(testing.allocator);
    while (manager.next_tx_data()) |tx_data| {
        var frames: [1]frame_module.Frame = undefined;
        const parsed = try frame_module.parse_frames(tx_data, &frames);
        try bank.add_frame(testing.allocator, parsed[0], .{ .number = 12 });
    }
    try testing.expect(bank.is_ready());
    const compressed = try bank.frame_data_alloc(testing.allocator);
    defer testing.allocator.free(compressed);
    const window = try testing.allocator.alloc(u8, std.compress.flate.max_window_len);
    defer testing.allocator.free(window);
    var plain: [8192]u8 = undefined;
    const items = try comp.zlib_decompress(compressed, window, &plain);
    var decoder = rlp.Decoder.init(items);
    var count: u64 = 0;
    while (!decoder.is_empty()) : (count += 1) {
        const item = try decoder.bytes();
        try testing.expectEqual(singular_batch_type, item[0]);
        var batch = try batch_module.SingleBatch.decode(testing.allocator, item[1..]);
        defer batch.deinit(testing.allocator);
        try testing.expectEqual(1000 + count + 1, batch.timestamp);
        try testing.expectEqual(@as(usize, 2), batch.transactions.len);
        try testing.expectEqualStrings("\x02tx-two", batch.transactions[1]);
    }
    try testing.expectEqual(@as(u64, 5), count);
}

test "manager: reorg, backpressure, and reset" {
    var manager = try Manager.init(testing.allocator, .{
        .channel = .{
            .frame_size_max = 100,
            .input_bytes_max = 600,
            .compression_ratio_percent = 100,
        },
        .batch_bytes_max = 600,
    }, @splat(1));
    defer manager.deinit(testing.allocator);
    var big_tx: [201]u8 = @splat('y');
    big_tx[0] = 0x02;
    const big = [_][]const u8{&big_tx};
    var parent: B256 = .zero;
    var number: u64 = 1;
    // Fill both buffers: the second fill must report backpressure, not drop data.
    const outcome = while (number < 20) : (number += 1) {
        const block = test_block(number, parent, &big);
        manager.add_block(&block, 0) catch |err| break err;
        parent = block.hash;
    } else unreachable;
    try testing.expectEqual(error.Backpressure, outcome);
    try testing.expect(manager.has_pending_frames());
    const wrong_parent = test_block(number, .{ .bytes = @splat(9) }, &big);
    while (manager.next_tx_data()) |_| {}
    try testing.expectError(error.Reorg, manager.add_block(&wrong_parent, 0));
    manager.reset();
    try testing.expectEqual(@as(?u64, null), manager.next_block_number());
    try manager.add_block(&wrong_parent, 0);
}

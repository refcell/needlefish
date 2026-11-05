//! Batch inspector (`base devnet batches`): scans L1 blocks for batcher transactions to
//! the batch inbox, reassembles channels with the consensus `Channel`, decompresses them
//! and prints every batch. A debugging and smoke-test tool in the spirit of op-node's
//! batch_decoder; it reuses the derivation code, so what it prints is what a verifier
//! would read. Blob transactions are counted but not decoded (needs a beacon API).
//!
//! CLI tool, not a hot path: it allocates from the caller's arena, bounded by `Limits`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const rpc = @import("../rpc/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const frame_module = @import("../../consensus/protocol/frame.zig");
const batch_module = @import("../../consensus/protocol/batch.zig");
const batch_reader = @import("../../consensus/protocol/batch_reader.zig");

const Address = primitives.Address;

pub const Limits = struct {
    channels_open_max: u32 = 16,
    frames_per_tx_max: u32 = 64,
    input_bytes_max: u32 = 1 << 20,
    decompressed_bytes_max: u64 = 10_000_000,
};

pub const Params = struct {
    inbox: Address,
    /// Only transactions from this sender count (the batcher), when set.
    sender: ?Address = null,
    from_block: u64,
    to_block: u64,
};

pub const Summary = struct {
    inbox_txs: u32 = 0,
    blob_txs: u32 = 0,
    frames: u32 = 0,
    invalid_frames: u32 = 0,
    channels: u32 = 0,
    singular_batches: u32 = 0,
    span_batches: u32 = 0,
    l2_transactions: u64 = 0,
};

const OpenChannel = struct { channel: protocol.Channel, opened_at: u64 };

pub fn inspect(
    arena: Allocator,
    client: *rpc.Client,
    params: Params,
    limits: Limits,
    out: *Writer,
) !Summary {
    assert(params.from_block <= params.to_block);
    var summary: Summary = .{};
    var open: std.ArrayList(OpenChannel) = try .initCapacity(arena, limits.channels_open_max);
    const input = try arena.alloc(u8, limits.input_bytes_max);
    const frames = try arena.alloc(frame_module.Frame, limits.frames_per_tx_max);
    var number = params.from_block;
    while (number <= params.to_block) : (number += 1) {
        var text: [48]u8 = undefined;
        const block_params = std.fmt.bufPrint(&text, "[\"0x{x}\",true]", .{number}) catch
            unreachable; // A u64 quantity fits.
        const block = try client.call("eth_getBlockByNumber", block_params);
        if (block == .null) break; // Past the head.
        const transactions = try rpc.field(block, "transactions");
        if (transactions != .array) return error.MalformedResponse;
        for (transactions.array.items) |tx| {
            if (!try is_batcher_tx(tx, params)) continue;
            summary.inbox_txs += 1;
            if (try rpc.quantity(u8, try rpc.field(tx, "type")) == 3) {
                summary.blob_txs += 1;
                continue;
            }
            const data = try rpc.data(try rpc.field(tx, "input"), input);
            const parsed = frame_module.parse_frames(data, frames) catch {
                summary.invalid_frames += 1;
                continue;
            };
            for (parsed) |frame| {
                summary.frames += 1;
                try add_frame(arena, &open, frame, number, limits, &summary, out);
            }
        }
    }
    for (open.items) |*pending| {
        try out.print("channel 0x{x}: incomplete ({d} frames)\n", .{
            &pending.channel.id,
            pending.channel.frame_count(),
        });
    }
    return summary;
}

fn is_batcher_tx(tx: std.json.Value, params: Params) !bool {
    const to = tx.object.get("to") orelse return false;
    if (to != .string) return false;
    const to_address: Address = .{ .bytes = try rpc.fixed(20, to) };
    if (!to_address.eql(params.inbox)) return false;
    const sender = params.sender orelse return true;
    const from: Address = .{ .bytes = try rpc.fixed(20, try rpc.field(tx, "from")) };
    return from.eql(sender);
}

fn add_frame(
    arena: Allocator,
    open: *std.ArrayList(OpenChannel),
    frame: frame_module.Frame,
    l1_number: u64,
    limits: Limits,
    summary: *Summary,
    out: *Writer,
) !void {
    const index = for (open.items, 0..) |pending, position| {
        if (std.mem.eql(u8, &pending.channel.id, &frame.id)) break position;
    } else blk: {
        if (open.items.len == limits.channels_open_max) return error.TooManyOpenChannels;
        const info: protocol.BlockInfo = .{ .number = l1_number };
        open.appendAssumeCapacity(.{
            .channel = protocol.Channel.init(frame.id, info),
            .opened_at = l1_number,
        });
        break :blk open.items.len - 1;
    };
    const pending = &open.items[index];
    pending.channel.add_frame(arena, frame, .{ .number = l1_number }) catch |err| {
        try out.print("channel 0x{x}: frame {d} rejected: {t}\n", .{
            &frame.id,
            frame.number,
            err,
        });
        summary.invalid_frames += 1;
        return;
    };
    if (!pending.channel.is_ready()) return;
    const data = try pending.channel.frame_data_alloc(arena);
    try out.print("channel 0x{x}: {d} frames, L1 blocks {d}..{d}\n", .{
        &frame.id,
        pending.channel.frame_count(),
        pending.opened_at,
        l1_number,
    });
    summary.channels += 1;
    _ = open.swapRemove(index);
    try print_batches(arena, data, limits, summary, out);
}

fn print_batches(
    arena: Allocator,
    data: []const u8,
    limits: Limits,
    summary: *Summary,
    out: *Writer,
) !void {
    const limit = limits.decompressed_bytes_max;
    const plain = batch_reader.decompress_channel(arena, data, limit, true) catch |err| {
        try out.print("  undecodable channel data: {t}\n", .{err});
        return;
    };
    var reader = batch_reader.BatchReader.init(plain);
    while (reader.next() catch |err| {
        try out.print("  batch stream error: {t}\n", .{err});
        return;
    }) |raw| {
        switch (raw.batch_type) {
            .single => {
                var batch = try batch_module.SingleBatch.decode(arena, raw.payload);
                defer batch.deinit(arena);
                summary.singular_batches += 1;
                summary.l2_transactions += batch.transactions.len;
                try out.print("  singular batch: timestamp {d}, epoch {d}, {d} txs\n", .{
                    batch.timestamp,
                    batch.epoch_num,
                    batch.transactions.len,
                });
            },
            .span => {
                summary.span_batches += 1;
                try out.print("  span batch: {d} bytes\n", .{raw.payload.len});
            },
        }
    }
}

const testing = std.testing;
const manager_module = @import("../channel/manager.zig");
const source = @import("../source/root.zig");

test "inspect: decodes the batches a channel manager produced" {
    var manager = try manager_module.Manager.init(testing.allocator, .{
        .channel = .{ .frame_size_max = 40, .target_frames = 64, .input_bytes_max = 64 * 1024 },
        .batch_bytes_max = 4096,
    }, @splat(0x11));
    defer manager.deinit(testing.allocator);
    const txs = [_][]const u8{"\x02l2-tx"};
    var parent: primitives.B256 = .zero;
    for (1..4) |number| {
        var hash: primitives.B256 = .zero;
        hash.bytes[31] = @intCast(number);
        const block: source.L2Block = .{
            .number = number,
            .hash = hash,
            .parent_hash = parent,
            .timestamp = 100 + 2 * number,
            .l1_origin = .{ .number = 7, .hash = .zero },
            .sequence_number = number,
            .transactions = &txs,
        };
        try manager.add_block(&block, 0);
        parent = hash;
    }
    manager.close_open();

    // One L1 block holding every frame tx (plus an unrelated transfer).
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var block_json: Writer.Allocating = .init(arena);
    try block_json.writer.writeAll("{\"transactions\":[{\"type\":\"0x2\",\"to\":\"0x" ++
        "1111111111111111111111111111111111111111\",\"input\":\"0x\"}");
    var frame_count: u32 = 0;
    while (manager.next_tx_data()) |tx_data| : (frame_count += 1) {
        try block_json.writer.print(",{{\"type\":\"0x2\",\"to\":\"0x{x}\",\"input\":\"0x{x}\"}}", .{
            &@as([20]u8, @splat(0xff)),
            tx_data,
        });
    }
    try block_json.writer.writeAll("]}");
    try testing.expect(frame_count > 1);
    var canned: rpc.CannedTransport = .{ .answers = &.{
        .{ .method = "eth_getBlockByNumber", .result = block_json.written() },
    } };
    var client = try rpc.Client.init(testing.allocator, canned.transport(), .{
        .response_bytes_max = 64 * 1024,
        .parse_bytes_max = 1 << 20,
    });
    defer client.deinit(testing.allocator);
    var output: Writer.Allocating = .init(arena);
    const summary = try inspect(arena, &client, .{
        .inbox = .{ .bytes = @splat(0xff) },
        .from_block = 5,
        .to_block = 5,
    }, .{}, &output.writer);
    try testing.expectEqual(frame_count, summary.inbox_txs);
    try testing.expectEqual(@as(u32, 1), summary.channels);
    try testing.expectEqual(@as(u32, 3), summary.singular_batches);
    try testing.expectEqual(@as(u64, 3), summary.l2_transactions);
    try testing.expect(std.mem.indexOf(u8, output.written(), "timestamp 106, epoch 7") != null);
}

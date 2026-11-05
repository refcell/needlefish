//! Startup synchronization (base/base `recent_txs.rs` and `wait_for_node_sync`).
//!
//! With `--wait-node-sync` the batcher waits until the rollup node's `current_l1` reaches a
//! target L1 block before batching, so it does not resubmit data the node has not yet
//! derived. The target is the L1 head, or with `--check-recent-txs-depth N` the L1 block
//! where the batcher's latest transaction within the last N blocks landed.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../rpc/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

/// base/base `MAX_CHECK_RECENT_TXS_DEPTH`.
pub const recent_txs_depth_max: u64 = 128;

pub const Error = rpc.Error || rpc.DecodeError;

/// The L1 block where the batcher's nonce last changed within `depth` blocks of the head,
/// or the oldest scanned block when it did not change. If L1 reorganizes mid-scan
/// (the nonce goes backwards) the head is returned, as in base/base.
pub fn recent_tx_target(l1: *rpc.Client, batcher: Address, depth: u64) Error!u64 {
    assert(depth > 0);
    assert(depth <= recent_txs_depth_max);
    const current_l1 = try rpc.quantity(u64, try l1.call("eth_blockNumber", "[]"));
    const oldest_l1 = current_l1 -| depth;
    const current_nonce = try nonce_at(l1, batcher, current_l1);
    const oldest_nonce = try nonce_at(l1, batcher, oldest_l1);
    if (oldest_nonce > current_nonce) return current_l1;
    if (oldest_nonce == current_nonce) return oldest_l1;
    // Smallest block in (oldest, current] whose nonce equals the current nonce.
    var low = oldest_l1 + 1;
    var high = current_l1;
    var iterations: u32 = 0;
    while (low < high) : (iterations += 1) {
        assert(iterations < 64); // Halves a range of at most `depth` blocks.
        const middle = low + (high - low) / 2;
        const nonce = try nonce_at(l1, batcher, middle);
        if (nonce > current_nonce) return current_l1;
        if (nonce == current_nonce) high = middle else low = middle + 1;
    }
    assert(low > oldest_l1 and low <= current_l1);
    return low;
}

/// True once the rollup node's `current_l1` has reached `target_l1`.
pub fn node_synced(rollup: *rpc.Client, target_l1: u64) Error!bool {
    const status = try rollup.call("optimism_syncStatus", "[]");
    const current_l1 = try rpc.number(try rpc.field(try rpc.field(status, "current_l1"), "number"));
    return current_l1 >= target_l1;
}

fn nonce_at(l1: *rpc.Client, batcher: Address, block: u64) Error!u64 {
    var buffer: [96]u8 = undefined;
    const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\",\"0x{x}\"]", .{
        &batcher.bytes,
        block,
    }) catch unreachable; // Fixed-size content.
    return rpc.quantity(u64, try l1.call("eth_getTransactionCount", params));
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// L1 with a per-block nonce history and a rollup node reporting `current_l1`.
const FakeChain = struct {
    head: u64 = 0,
    nonce_at: [512]u64 = @splat(0),
    node_l1: u64 = 0,
    /// Raises every nonce read after this many reads (L1 changed mid-scan).
    reorg_after_reads: ?u32 = null,
    reads: u32 = 0,

    fn transport(chain: *FakeChain) rpc.Transport {
        return .{ .context = chain, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const chain: *FakeChain = @ptrCast(@alignCast(context));
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        var buffer: [96]u8 = undefined;
        const result = if (std.mem.indexOf(u8, body, "eth_getTransactionCount") != null) blk: {
            const tag_start = std.mem.lastIndexOf(u8, body, ",\"0x").? + 4;
            const tag_end = std.mem.indexOfScalarPos(u8, body, tag_start, '"').?;
            const block = std.fmt.parseInt(u64, body[tag_start..tag_end], 16) catch
                return error.TransportFailed;
            if (block > chain.head) return error.TransportFailed;
            chain.reads += 1;
            var nonce = chain.nonce_at[@intCast(block)];
            if (chain.reorg_after_reads) |limit| {
                if (chain.reads > limit) nonce += 100;
            }
            break :blk std.fmt.bufPrint(&buffer, "\"0x{x}\"", .{nonce}) catch unreachable;
        } else if (std.mem.indexOf(u8, body, "eth_blockNumber") != null)
            std.fmt.bufPrint(&buffer, "\"0x{x}\"", .{chain.head}) catch unreachable
        else
            std.fmt.bufPrint(&buffer, "{{\"current_l1\":{{\"number\":{d}}}}}", .{
                chain.node_l1,
            }) catch unreachable;
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, result }) catch
            return error.ResponseTooLarge;
        return text.len;
    }

    /// Mines blocks `1..=head`; each block bumps the nonce with `chance_percent`.
    fn build(chain: *FakeChain, prng: *Prng, head: u64, chance_percent: u8) void {
        assert(head < chain.nonce_at.len);
        chain.head = head;
        for (1..@intCast(head + 1)) |block| {
            const bump: u64 = if (prng.chance(chance_percent, 100)) 1 else 0;
            chain.nonce_at[block] = chain.nonce_at[block - 1] + bump;
        }
    }
};

fn test_client(chain: *FakeChain) !rpc.Client {
    return rpc.Client.init(testing.allocator, chain.transport(), .{});
}

/// Reference: scan every block from the head down.
fn expected_target(chain: *const FakeChain, depth: u64) u64 {
    const oldest = chain.head -| depth;
    const current = chain.nonce_at[@intCast(chain.head)];
    if (chain.nonce_at[@intCast(oldest)] == current) return oldest;
    var block = chain.head;
    while (block > oldest and chain.nonce_at[@intCast(block - 1)] == current) block -= 1;
    return block;
}

test "sync: recent tx target matches base/base's example" {
    var chain: FakeChain = .{ .head = 10 };
    // Nonce 1 at block 5, 2 at 8, 3 at 9 (base/base `finds_block_where_current_nonce...`).
    for (0..11) |block| chain.nonce_at[block] = if (block >= 9) 3 else if (block >= 8) 2 else 1;
    var client = try test_client(&chain);
    defer client.deinit(testing.allocator);
    const zero: Address = .{ .bytes = @splat(0) };
    try testing.expectEqual(@as(u64, 9), try recent_tx_target(&client, zero, 5));
    // No activity in the window: the oldest scanned block.
    try testing.expectEqual(@as(u64, 9), try recent_tx_target(&client, zero, 1));
    // L1 changed during the binary search: fall back to the head.
    chain.reorg_after_reads = chain.reads + 2;
    try testing.expectEqual(@as(u64, 10), try recent_tx_target(&client, zero, 5));
    // The oldest block's nonce is above the head's (reorg): the head.
    chain.reorg_after_reads = null;
    chain.nonce_at[5] = 4;
    try testing.expectEqual(@as(u64, 10), try recent_tx_target(&client, zero, 5));
}

test "sync: seeded fuzz of the recent tx target against a linear scan" {
    var prng = Prng.init(0x5c);
    for (0..200) |_| {
        var chain: FakeChain = .{};
        chain.build(&prng, prng.range(0, 400), @intCast(prng.range(0, 100)));
        var client = try test_client(&chain);
        defer client.deinit(testing.allocator);
        const depth = prng.range(1, recent_txs_depth_max);
        const target = try recent_tx_target(&client, .{ .bytes = @splat(1) }, depth);
        try testing.expectEqual(expected_target(&chain, depth), target);
        try testing.expect(chain.reads <= 2 + 8);
    }
}

test "sync: node synced compares current_l1 with the target" {
    var chain: FakeChain = .{ .node_l1 = 7 };
    var client = try test_client(&chain);
    defer client.deinit(testing.allocator);
    try testing.expect(try node_synced(&client, 7));
    try testing.expect(!try node_synced(&client, 8));
}

test "sync: fuzz nonce histories" {
    try testing.fuzz({}, fuzz_target, .{});
}

fn fuzz_target(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [256]u8 = undefined;
    const length = smith.slice(&bytes);
    var chain: FakeChain = .{ .head = length };
    for (bytes[0..length], 1..) |byte, block| {
        chain.nonce_at[block] = chain.nonce_at[block - 1] + (byte & 1);
    }
    var client = try test_client(&chain);
    defer client.deinit(testing.allocator);
    const depth = 1 + (if (length > 0) bytes[0] else 0) % recent_txs_depth_max;
    const target = try recent_tx_target(&client, .{ .bytes = @splat(2) }, depth);
    try testing.expectEqual(expected_target(&chain, depth), target);
}

//! Parallel transaction sender recovery for block import.
//!
//! Recovering a sender (secp256k1 ecrecover, about 30 us) dominates the cost of executing
//! simple transactions, and it is a pure function of the raw transaction, so a block's
//! senders are recovered up front on scoped threads (spawned and joined per call; the
//! calling thread takes the first chunk). The result is identical for any thread count,
//! so execution stays deterministic. Entries that cannot be recovered (deposits,
//! undecodable or invalid signatures) are left null and the executor recovers (and
//! rejects) them inline as before.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

/// Upper bound on worker threads per call.
pub const threads_max = 64;
/// Blocks with fewer transactions are recovered on the calling thread: spawning costs
/// more than it saves.
pub const parallel_transactions_min = 32;
/// Recovery needs a few KiB of stack; keep the reservation small.
const stack_size_bytes = 256 * 1024;

/// Recovers the sender of every raw transaction into `out` using up to `threads` extra
/// threads. `out[i]` is null when transaction `i` has no recoverable signature.
pub fn recover(
    raws: []const []const u8,
    out: []?Address,
    recoverer: consensus.Recoverer,
    threads: u32,
) void {
    assert(out.len == raws.len);
    assert(threads <= threads_max);
    const workers: u32 = if (raws.len < parallel_transactions_min) 0 else threads;
    const chunks: u32 = @min(workers + 1, @as(u32, @intCast(@max(raws.len, 1))));
    const chunk_size = std.math.divCeil(usize, raws.len, chunks) catch unreachable; // chunks>0.
    var handles: [threads_max]?std.Thread = @splat(null);
    for (1..chunks) |chunk| {
        const range = chunk_range(raws.len, chunk_size, chunk);
        handles[chunk - 1] = std.Thread.spawn(
            .{ .stack_size = stack_size_bytes },
            recover_range,
            .{ raws[range.start..range.end], out[range.start..range.end], recoverer },
        ) catch null;
    }
    const first = chunk_range(raws.len, chunk_size, 0);
    recover_range(raws[first.start..first.end], out[first.start..first.end], recoverer);
    for (1..chunks) |chunk| {
        if (handles[chunk - 1]) |handle| {
            handle.join();
        } else {
            // The spawn failed: recover that chunk here.
            const range = chunk_range(raws.len, chunk_size, chunk);
            recover_range(raws[range.start..range.end], out[range.start..range.end], recoverer);
        }
    }
}

const Range = struct { start: usize, end: usize };

fn chunk_range(count: usize, chunk_size: usize, chunk: usize) Range {
    const start = @min(chunk * chunk_size, count);
    const end = @min(start + chunk_size, count);
    assert(start <= end and end <= count);
    return .{ .start = start, .end = end };
}

fn recover_range(raws: []const []const u8, out: []?Address, recoverer: consensus.Recoverer) void {
    assert(raws.len == out.len);
    for (raws, out) |raw, *sender| {
        sender.* = null;
        const envelope = consensus.Envelope.decode(raw) catch continue;
        if (envelope == .deposit) continue;
        sender.* = envelope.recover_sender(recoverer);
    }
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn signed_transfer(buffer: []u8, key_index: u32, nonce: u64) ![]const u8 {
    var key: [32]u8 = @splat(0);
    std.mem.writeInt(u32, key[28..32], key_index + 1, .big);
    const tx: consensus.Eip1559 = .{
        .chain_id = 1337,
        .nonce = nonce,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 10,
        .gas_limit = 21_000,
        .to = .{ .call = primitives.Address.zero },
        .value = 1,
        .input = &.{},
        .access_list = .empty,
    };
    return (try consensus.tx.sign(tx, key)).encode_to(buffer);
}

var test_buffers: [80][128]u8 = undefined;

/// Same senders as a sequential recovery for any thread count, with garbage mixed in.
fn check_matches_sequential(prng: *Prng, count: usize, threads: u32) !void {
    assert(count <= test_buffers.len);
    var raws: [80][]const u8 = undefined;
    for (raws[0..count], 0..) |*raw, index| {
        if (prng.chance(1, 8)) {
            const size = prng.range(0, 64);
            prng.fill(test_buffers[index][0..size]);
            raw.* = test_buffers[index][0..size];
        } else {
            raw.* = try signed_transfer(&test_buffers[index], @intCast(prng.below(4)), index);
        }
    }
    var expected: [80]?Address = undefined;
    recover_range(raws[0..count], expected[0..count], consensus.recover_address);
    var actual: [80]?Address = undefined;
    recover(raws[0..count], actual[0..count], consensus.recover_address, threads);
    for (expected[0..count], actual[0..count]) |want, got| {
        try testing.expectEqual(want == null, got == null);
        if (want) |address| try testing.expectEqualSlices(u8, &address.bytes, &got.?.bytes);
    }
}

test "senders: parallel recovery matches sequential recovery" {
    var prng = Prng.init(0x5e1de2);
    try check_matches_sequential(&prng, 0, 4);
    try check_matches_sequential(&prng, 5, 4); // Below the parallel threshold.
    try check_matches_sequential(&prng, 80, 3);
    try check_matches_sequential(&prng, 33, 64); // More threads than useful chunks.
}

test "senders: seeded fuzz of counts and thread counts" {
    var prng = Prng.init(0xf022);
    for (0..6) |_| {
        const count = prng.range(0, 80);
        try check_matches_sequential(&prng, count, @intCast(prng.range(0, 8)));
    }
}

fn fuzz_recover(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try check_matches_sequential(&prng, prng.range(0, 80), @intCast(prng.range(0, 8)));
}

test "senders: fuzz" {
    try testing.fuzz({}, fuzz_recover, .{});
}

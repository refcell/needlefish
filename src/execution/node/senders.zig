//! Parallel transaction sender recovery for block import.
//!
//! Recovering a sender (secp256k1 ecrecover, about 30 us) dominates the cost of executing
//! simple transactions, and it is a pure function of the raw transaction, so a block's
//! senders are recovered on scoped threads (spawned and joined per block) claiming small
//! batches in order from a shared atomic counter, while the calling thread executes the
//! transactions whose batches are done (`Pipeline`), helping with unclaimed batches
//! whenever it would otherwise wait. The result is identical
//! for any thread count, so execution stays deterministic. Entries that cannot be
//! recovered (deposits, undecodable or invalid signatures) are left null and the
//! executor recovers (and rejects) them inline as before.

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

/// Transactions claimed per grab from the shared counter: small enough to balance
/// fast and slow cores, large enough that the atomic is noise.
pub const batch_size = 8;

/// Done flags `Pipeline` needs for `transactions` transactions (one per batch).
pub fn batches_for(transactions: usize) usize {
    return std.math.divCeil(usize, transactions, batch_size) catch unreachable;
}

/// Work shared by the calling thread and the workers of one pipeline.
const Job = struct {
    raws: []const []const u8,
    out: []?Address,
    /// Per batch: 1 once its senders are written (release), read with acquire.
    done: []std.atomic.Value(u32),
    recoverer: consensus.Recoverer,
    next: std.atomic.Value(u32) = .init(0),

    /// Claims batches until none are left. Every index is claimed exactly once.
    fn work(job: *Job) void {
        const count: u32 = @intCast(job.raws.len);
        var grabs: u32 = 0;
        while (grabs <= count / batch_size) : (grabs += 1) {
            if (!job.claim_one()) return;
        }
    }

    /// Recovers the next unclaimed batch; false when every batch is claimed.
    fn claim_one(job: *Job) bool {
        const count: u32 = @intCast(job.raws.len);
        const start = job.next.fetchAdd(batch_size, .monotonic);
        if (start >= count) return false;
        const end = @min(start + batch_size, count);
        recover_range(job.raws[start..end], job.out[start..end], job.recoverer);
        job.done[start / batch_size].store(1, .release);
        return true;
    }
};

/// Recovery overlapped with execution: workers recover batches in order while the
/// caller executes; `wait_for(i)` returns once `out[i]` is written, recovering unclaimed
/// batches itself instead of idling. `finish` joins the workers and must run (also on
/// error) before `out`, `done` or the pipeline go out of scope.
pub const Pipeline = struct {
    job: Job,
    handles: [threads_max]?std.Thread = @splat(null),
    workers: u32 = 0,

    pub fn start(
        pipeline: *Pipeline,
        raws: []const []const u8,
        out: []?Address,
        done: []std.atomic.Value(u32),
        recoverer: consensus.Recoverer,
        threads: u32,
    ) void {
        assert(out.len == raws.len);
        assert(done.len >= batches_for(raws.len));
        assert(threads <= threads_max);
        assert(raws.len <= std.math.maxInt(u32) - batch_size);
        for (done[0..batches_for(raws.len)]) |*flag| flag.store(0, .monotonic);
        const job: Job = .{ .raws = raws, .out = out, .done = done, .recoverer = recoverer };
        pipeline.* = .{ .job = job };
        if (raws.len < parallel_transactions_min or threads == 0) return; // Caller recovers.
        // No more workers than batches beyond the caller's first.
        const workers = @min(threads, batches_for(raws.len) - 1);
        for (pipeline.handles[0..workers]) |*handle| {
            // A failed spawn only means less parallelism: the caller drains the rest.
            handle.* = std.Thread.spawn(
                .{ .stack_size = stack_size_bytes },
                Job.work,
                .{&pipeline.job},
            ) catch null;
        }
        pipeline.workers = @intCast(workers);
    }

    /// Blocks until `out[index]` is written.
    pub fn wait_for(pipeline: *Pipeline, index: usize) void {
        assert(index < pipeline.job.raws.len);
        const flag = &pipeline.job.done[index / batch_size];
        while (flag.load(.acquire) == 0) {
            if (!pipeline.job.claim_one()) std.atomic.spinLoopHint();
        }
    }

    /// Recovers whatever is left and joins the workers.
    pub fn finish(pipeline: *Pipeline) void {
        pipeline.job.work();
        for (pipeline.handles[0..pipeline.workers]) |handle| if (handle) |thread| thread.join();
        pipeline.workers = 0;
        assert(pipeline.job.next.load(.monotonic) >= pipeline.job.raws.len);
    }
};

/// Recovers the sender of every raw transaction into `out` using up to `threads` extra
/// threads. `out[i]` is null when transaction `i` has no recoverable signature.
pub fn recover(
    raws: []const []const u8,
    out: []?Address,
    recoverer: consensus.Recoverer,
    threads: u32,
) void {
    var done_buffer: [batches_for(4096)]std.atomic.Value(u32) = undefined;
    if (raws.len > 4096) {
        recover_range(raws, out, recoverer);
        return;
    }
    var pipeline: Pipeline = undefined;
    pipeline.start(raws, out, &done_buffer, recoverer, threads);
    pipeline.finish();
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
    for (expected[0..count], actual[0..count]) |want, got| try expect_same(want, got);
    // Pipelined: each entry is final as soon as `wait_for` returns, whatever the order.
    var piped: [80]?Address = undefined;
    var done: [batches_for(80)]std.atomic.Value(u32) = undefined;
    var pipeline: Pipeline = undefined;
    pipeline.start(raws[0..count], piped[0..count], &done, consensus.recover_address, threads);
    defer pipeline.finish();
    const stride = prng.range(1, 9);
    var visited: usize = 0;
    var index: usize = if (count > 0) prng.below(count) else 0;
    while (visited < count) : (visited += 1) {
        pipeline.wait_for(index);
        try expect_same(expected[index], piped[index]);
        index = (index + stride) % count;
    }
}

fn expect_same(want: ?Address, got: ?Address) !void {
    try testing.expectEqual(want == null, got == null);
    if (want) |address| try testing.expectEqualSlices(u8, &address.bytes, &got.?.bytes);
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

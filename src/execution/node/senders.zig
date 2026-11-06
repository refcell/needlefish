//! Parallel transaction sender recovery for block import.
//!
//! Recovering a sender (secp256k1 ecrecover, about 30 us) dominates the cost of executing
//! simple transactions, and it is a pure function of the raw transaction, so a block's
//! senders are recovered by a static worker `Pool` (spawned once, sleeping on a futex
//! between blocks, as `trie/rehash_pool.zig`) claiming small batches in order from a
//! shared counter, while the calling thread executes the transactions whose batches are
//! done (`Pipeline`), helping with unclaimed batches whenever it would otherwise wait.
//! Claims carry the run's generation, so a worker waking after its run ended claims
//! nothing. The result is identical for any thread count, so execution stays
//! deterministic. Entries that cannot be recovered (deposits, undecodable or invalid
//! signatures) are left null and the executor recovers (and rejects) them inline.
//!
//! A futex is a synchronization primitive, not I/O: the calls go straight to the OS
//! through `std.Io.Threaded`. Without a pool (DST, the simulator) the caller recovers.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

/// Upper bound on worker threads.
pub const threads_max = 64;
/// Blocks with fewer transactions are recovered on the calling thread: waking the
/// workers costs more than it saves.
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

/// Work of one pipeline, shared by the calling thread and the pool's workers.
const Job = struct {
    raws: []const []const u8,
    out: []?Address,
    /// Per batch: 1 once its senders are written (release), read with acquire.
    done: []std.atomic.Value(u32),
    recoverer: consensus.Recoverer,

    fn recover_batch(job: *const Job, start: u32) void {
        assert(start < job.raws.len);
        assert(start % batch_size == 0);
        const end = @min(start + batch_size, job.raws.len);
        recover_range(job.raws[start..end], job.out[start..end], job.recoverer);
        job.done[start / batch_size].store(1, .release);
    }
};

/// Static recovery workers. Heap-pinned: the workers hold its address.
pub const Pool = struct {
    /// Bumped once per run (and at `destroy`): the futex word workers sleep on.
    generation: std.atomic.Value(u32) = .init(0),
    /// `generation << 32 | next transaction index`: a claim succeeds only in its run.
    claim: std.atomic.Value(u64) = .init(0),
    /// Transactions of the current run (atomic: a late worker may read the next run's).
    count: std.atomic.Value(u32) = .init(0),
    /// Batches of the current run recovered so far.
    completed: std.atomic.Value(u32) = .init(0),
    stopping: bool = false,
    /// The current run's job; dereferenced only after a successful claim.
    job: ?*const Job = null,
    threads: [threads_max]std.Thread = undefined,
    thread_count: u32 = 0,

    /// Spawns up to `thread_count` workers. A failed spawn only means less parallelism
    /// (with none, the caller recovers everything).
    pub fn create(allocator: std.mem.Allocator, thread_count: u32) error{OutOfMemory}!*Pool {
        assert(thread_count > 0);
        assert(thread_count <= threads_max);
        const pool = try allocator.create(Pool);
        pool.* = .{};
        for (0..thread_count) |index| {
            const config: std.Thread.SpawnConfig = .{ .stack_size = stack_size_bytes };
            pool.threads[index] = std.Thread.spawn(config, work, .{pool}) catch break;
            pool.thread_count += 1;
        }
        assert(pool.thread_count <= thread_count);
        return pool;
    }

    /// Stops and joins the workers.
    pub fn destroy(pool: *Pool, allocator: std.mem.Allocator) void {
        assert(pool.job == null);
        pool.stopping = true;
        _ = pool.generation.fetchAdd(1, .release);
        futex_wake(&pool.generation, std.math.maxInt(u32));
        for (pool.threads[0..pool.thread_count]) |thread| thread.join();
        allocator.destroy(pool);
    }

    /// Publishes `job` and wakes the workers; returns the run's generation.
    fn begin(pool: *Pool, job: *const Job) u32 {
        assert(pool.job == null);
        assert(job.raws.len > 0 and job.raws.len <= std.math.maxInt(u32) - batch_size);
        pool.job = job;
        pool.count.store(@intCast(job.raws.len), .monotonic);
        pool.completed.store(0, .monotonic);
        const generation = pool.generation.load(.monotonic) +% 1;
        pool.claim.store(@as(u64, generation) << 32, .release);
        pool.generation.store(generation, .release);
        futex_wake(&pool.generation, pool.thread_count);
        return generation;
    }

    /// Recovers the next unclaimed batch of run `generation`; false when none is left.
    fn claim_batch(pool: *Pool, generation: u32) bool {
        // A failed exchange means another thread claimed a batch (or a newer run started,
        // which needs every batch of this one claimed): bounded by the batch count.
        var attempts: u32 = 0;
        while (attempts < 2 * threads_max + 2) : (attempts += 1) {
            const claim = pool.claim.load(.acquire);
            if (claim >> 32 != generation) return false; // That run is over.
            const start: u32 = @truncate(claim);
            if (start >= pool.count.load(.monotonic)) return false;
            // The count may belong to a newer run; then the exchange fails.
            if (pool.claim.cmpxchgStrong(claim, claim + batch_size, .acq_rel, .acquire) != null) {
                continue;
            }
            // The run cannot end before this batch completes: the job holds.
            pool.job.?.recover_batch(start);
            _ = pool.completed.fetchAdd(1, .release);
            return true;
        }
        return false; // Contended: the caller retries (or drains the batch itself later).
    }

    /// Claims the rest, waits for batches in flight, and retires the run.
    fn end(pool: *Pool, generation: u32) void {
        assert(pool.job != null);
        const batches: u32 = @intCast(batches_for(pool.job.?.raws.len));
        // Every round claims a batch or loses a race to a thread that did: bounded.
        var rounds: u64 = 0;
        while (!pool.claimed_all(generation)) : (rounds += 1) {
            assert(rounds < @as(u64, batches) * (2 * threads_max + 2) + 1);
            _ = pool.claim_batch(generation);
        }
        // Every batch is claimed; the rest finish within one batch's recovery time.
        while (pool.completed.load(.acquire) < batches) std.atomic.spinLoopHint();
        assert(pool.completed.load(.monotonic) == batches);
        pool.job = null;
    }

    fn claimed_all(pool: *Pool, generation: u32) bool {
        const claim = pool.claim.load(.acquire);
        assert(claim >> 32 == generation);
        return @as(u32, @truncate(claim)) >= pool.count.load(.monotonic);
    }

    /// Worker main loop: runs until `destroy`.
    fn work(pool: *Pool) void {
        var seen: u32 = 0;
        while (true) {
            const generation = pool.generation.load(.acquire);
            if (generation == seen) {
                futex_wait(&pool.generation, seen);
                continue;
            }
            seen = generation;
            if (pool.stopping) return;
            var batches: u32 = 0;
            while (batches < std.math.maxInt(u32)) : (batches += 1) {
                if (!pool.claim_batch(generation)) break;
            }
        }
    }
};

/// Recovery overlapped with execution: the pool's workers recover batches in order while
/// the caller executes; `wait_for(i)` returns once `out[i]` is written, recovering
/// unclaimed batches itself instead of idling. `finish` must run (also on error) before
/// `out`, `done` or the pipeline go out of scope.
pub const Pipeline = struct {
    job: Job,
    pool: ?*Pool = null,
    generation: u32 = 0,
    /// Without a pool: the next transaction the caller recovers.
    next: u32 = 0,

    pub fn start(
        pipeline: *Pipeline,
        raws: []const []const u8,
        out: []?Address,
        done: []std.atomic.Value(u32),
        recoverer: consensus.Recoverer,
        pool: ?*Pool,
    ) void {
        pipeline.start_with(raws, out, done, recoverer, pool, parallel_transactions_min);
    }

    /// `start` waking the workers from `parallel_min` transactions on: a prefetch ahead of
    /// its block hides the wake-up cost, so it uses the pool for any block.
    pub fn start_with(
        pipeline: *Pipeline,
        raws: []const []const u8,
        out: []?Address,
        done: []std.atomic.Value(u32),
        recoverer: consensus.Recoverer,
        pool: ?*Pool,
        parallel_min: usize,
    ) void {
        assert(parallel_min > 0);
        assert(out.len == raws.len);
        assert(done.len >= batches_for(raws.len));
        assert(raws.len <= std.math.maxInt(u32) - batch_size);
        for (done[0..batches_for(raws.len)]) |*flag| flag.store(0, .monotonic);
        const job: Job = .{ .raws = raws, .out = out, .done = done, .recoverer = recoverer };
        pipeline.* = .{ .job = job };
        if (raws.len < parallel_min) return; // Caller recovers.
        const workers = pool orelse return;
        pipeline.pool = workers;
        pipeline.generation = workers.begin(&pipeline.job);
    }

    /// Blocks until `out[index]` is written.
    pub fn wait_for(pipeline: *Pipeline, index: usize) void {
        assert(index < pipeline.job.raws.len);
        const flag = &pipeline.job.done[index / batch_size];
        while (flag.load(.acquire) == 0) {
            if (!pipeline.claim_one()) std.atomic.spinLoopHint();
        }
    }

    fn claim_one(pipeline: *Pipeline) bool {
        if (pipeline.pool) |pool| return pool.claim_batch(pipeline.generation);
        if (pipeline.next >= pipeline.job.raws.len) return false;
        pipeline.job.recover_batch(pipeline.next);
        pipeline.next += batch_size;
        return true;
    }

    /// Recovers whatever is left and retires the run.
    pub fn finish(pipeline: *Pipeline) void {
        if (pipeline.pool) |pool| {
            pool.end(pipeline.generation);
            pipeline.pool = null;
            return;
        }
        const count = pipeline.job.raws.len;
        while (pipeline.next < count) : (pipeline.next += batch_size) {
            pipeline.job.recover_batch(pipeline.next);
        }
        assert(pipeline.next >= count);
    }
};

/// Recovers the sender of every raw transaction into `out`, on `pool` too when given.
/// `out[i]` is null when transaction `i` has no recoverable signature.
pub fn recover(
    raws: []const []const u8,
    out: []?Address,
    recoverer: consensus.Recoverer,
    pool: ?*Pool,
) void {
    var done_buffer: [batches_for(4096)]std.atomic.Value(u32) = undefined;
    if (raws.len > 4096) {
        recover_range(raws, out, recoverer);
        return;
    }
    var pipeline: Pipeline = undefined;
    pipeline.start(raws, out, &done_buffer, recoverer, pool);
    pipeline.finish();
}

fn futex_io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn futex_wait(word: *const std.atomic.Value(u32), expected: u32) void {
    futex_io().futexWaitUncancelable(u32, &word.raw, expected);
}

fn futex_wake(word: *const std.atomic.Value(u32), waiters_max: u32) void {
    futex_io().futexWake(u32, &word.raw, waiters_max);
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
    const pool: ?*Pool = if (threads > 0) try Pool.create(testing.allocator, threads) else null;
    defer if (pool) |workers| workers.destroy(testing.allocator);
    var actual: [80]?Address = undefined;
    recover(raws[0..count], actual[0..count], consensus.recover_address, pool);
    for (expected[0..count], actual[0..count]) |want, got| try expect_same(want, got);
    // Pipelined: each entry is final as soon as `wait_for` returns, whatever the order.
    var piped: [80]?Address = undefined;
    var done: [batches_for(80)]std.atomic.Value(u32) = undefined;
    var pipeline: Pipeline = undefined;
    pipeline.start(raws[0..count], piped[0..count], &done, consensus.recover_address, pool);
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

test "senders: one pool serves many runs of any size" {
    var prng = Prng.init(0xb0b);
    const pool = try Pool.create(testing.allocator, 3);
    defer pool.destroy(testing.allocator);
    var raws: [80][]const u8 = undefined;
    for (&raws, 0..) |*raw, index| {
        raw.* = try signed_transfer(&test_buffers[index], @intCast(index % 5), index);
    }
    var expected: [80]?Address = undefined;
    recover_range(&raws, &expected, consensus.recover_address);
    for (0..24) |_| {
        const count = prng.range(0, 80);
        var actual: [80]?Address = undefined;
        recover(raws[0..count], actual[0..count], consensus.recover_address, pool);
        for (expected[0..count], actual[0..count]) |want, got| try expect_same(want, got);
        try testing.expect(pool.job == null);
    }
}

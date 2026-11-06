//! Static worker pool for the parallel storage-trie rehash in `StateTrie.flush` (and the
//! account-trie rehash after a bulk load, `StateTrie.bulk_finish`).
//!
//! The threads are spawned once at `init` and sleep on a futex between flushes (no spawn per
//! block). One `run` publishes a bounded list of chunks (at most `chunks_max` ranges of the
//! trie's collected dirty nodes), wakes the workers, and claims chunks on the calling thread
//! too; workers and caller claim from one counter, so a worker that wakes late or runs on a
//! slow core takes fewer chunks instead of holding up the flush. `run` returns once every
//! chunk is hashed, so the caller reads the caches afterwards. A worker that wakes after
//! its run ended finds nothing to claim: claims carry the run's generation.
//!
//! No shared mutable state: each chunk holds the dirty nodes of whole, distinct storage tries
//! (`TrieType.collect_dirty_split`), and `TrieType.hash_collected` writes only its own chunk
//! and the caches of the nodes in it, keeping its batch buffers on its own stack. A node
//! reads the caches of its children, which are either clean (written by nobody during the
//! run) or dirty and then in the same chunk. Hashing is a pure function of the trie, so the
//! caches are bit-identical to a serial rehash for any split and any thread count.
//!
//! A futex is a synchronization primitive, not I/O: the futex calls go straight to the OS
//! through `std.Io.Threaded` (they ignore its state). With zero threads nothing here runs,
//! which is how DST and the simulator use it.

const std = @import("std");
const assert = std.debug.assert;

/// Upper bound on worker threads.
pub const threads_max = 16;
/// Upper bound on chunks per run.
pub const chunks_max = 64;
/// Hashing needs a few KiB of stack (batch buffers, sort); keep the reservation small.
const stack_size_bytes = 256 * 1024;

/// One pool serves any `TrieType`: `run` takes the trie and its `hash_collected`.
pub const RehashPool = struct {
    const Pool = @This();
    const HashFunction = *const fn (trie: *anyopaque, range: []u64) void;

    /// Bumped once per `run` (and once at `deinit`): the futex word workers sleep on.
    generation: std.atomic.Value(u32) = .init(0),
    /// `generation << 32 | next chunk`: a claim succeeds only within its own run.
    claim: std.atomic.Value(u64) = .init(0),
    /// Chunks of the current run hashed so far.
    done: std.atomic.Value(u32) = .init(0),
    stopping: bool = false,
    /// The trie of the current run and its `hash_collected`.
    trie: ?*anyopaque = null,
    hash: HashFunction = undefined,
    /// Chunks of the current run, written by the caller before the claim word is
    /// published (release) and read after a successful claim (acquire).
    chunks: [chunks_max][]u64 = @splat(&.{}),
    /// Atomic: a worker woken late may read it while the next run writes it.
    chunk_count: std.atomic.Value(u32) = .init(0),
    threads: [threads_max]std.Thread = undefined,
    thread_count: u32 = 0,

    /// Spawns `thread_count` workers. `pool` must not move until `deinit`.
    pub fn init(pool: *Pool, thread_count: u32) !void {
        assert(thread_count > 0);
        assert(thread_count <= threads_max);
        pool.* = .{};
        errdefer pool.deinit();
        for (0..thread_count) |index| {
            const config: std.Thread.SpawnConfig = .{ .stack_size = stack_size_bytes };
            pool.threads[index] = try std.Thread.spawn(config, work, .{pool});
            pool.thread_count += 1;
        }
        assert(pool.thread_count == thread_count);
    }

    /// Stops and joins the workers.
    pub fn deinit(pool: *Pool) void {
        assert(pool.trie == null);
        pool.stopping = true;
        _ = pool.generation.fetchAdd(1, .release);
        futex_wake(&pool.generation, std.math.maxInt(u32));
        for (pool.threads[0..pool.thread_count]) |thread| thread.join();
        pool.* = undefined;
    }

    /// Hashes every chunk, on the workers and the calling thread, and returns once all
    /// are done. Chunks must be disjoint slices of `trie.order`, each holding whole tries.
    pub fn run(pool: *Pool, trie: anytype, chunks: []const []u64) void {
        assert(chunks.len >= 1);
        assert(chunks.len <= chunks_max);
        assert(pool.trie == null);
        const Trie = @TypeOf(trie.*);
        pool.trie = trie;
        pool.hash = struct {
            fn hash(context: *anyopaque, range: []u64) void {
                const typed: *Trie = @ptrCast(@alignCast(context));
                typed.hash_collected(range);
            }
        }.hash;
        @memcpy(pool.chunks[0..chunks.len], chunks);
        const count: u32 = @intCast(chunks.len);
        pool.chunk_count.store(count, .monotonic);
        pool.done.store(0, .monotonic);
        const generation = pool.generation.load(.monotonic) +% 1;
        pool.claim.store(@as(u64, generation) << 32, .release);
        pool.generation.store(generation, .release);
        futex_wake(&pool.generation, pool.thread_count);
        pool.drain(generation);
        // Every chunk is claimed; the rest finish within one chunk's hashing time.
        while (pool.done.load(.acquire) < count) std.atomic.spinLoopHint();
        assert(pool.done.load(.monotonic) == count);
        assert(pool.claim.load(.monotonic) == (@as(u64, generation) << 32 | count));
        pool.trie = null;
    }

    /// Claims and hashes chunks of run `generation` until none are left.
    fn drain(pool: *Pool, generation: u32) void {
        // A failed exchange means another thread claimed a chunk (the claim word changes
        // otherwise only when a new run starts, after every chunk was claimed), and a run
        // has at most `chunks_max` claims: the loop ends within the bound.
        var attempts: u32 = 0;
        while (attempts < 2 * chunks_max + 2) : (attempts += 1) {
            const claim = pool.claim.load(.acquire);
            if (claim >> 32 != generation) return; // That run is over.
            const index: u32 = @truncate(claim);
            if (index >= pool.chunk_count.load(.monotonic)) return;
            // The count may belong to a newer run; then the exchange fails.
            if (pool.claim.cmpxchgStrong(claim, claim + 1, .acq_rel, .acquire) != null) {
                continue;
            }
            // The run cannot end before this chunk is done: `trie` and the chunk hold.
            pool.hash(pool.trie.?, pool.chunks[index]);
            _ = pool.done.fetchAdd(1, .release);
        }
        unreachable; // Bounded above: at most `chunks_max` claims and as many failures.
    }

    /// Worker main loop: runs until `deinit`.
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
            pool.drain(generation);
        }
    }
};

fn futex_io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn futex_wait(word: *const std.atomic.Value(u32), expected: u32) void {
    futex_io().futexWaitUncancelable(u32, &word.raw, expected);
}

fn futex_wake(word: *const std.atomic.Value(u32), waiters_max: u32) void {
    futex_io().futexWake(u32, &word.raw, waiters_max);
}

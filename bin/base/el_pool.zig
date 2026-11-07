//! A multi-peer devp2p block source for catch-up: one worker thread and one RLPx connection
//! per execution peer, all fetching fixed segments of `segment_blocks` blocks at once, and
//! the blocks handed out in ascending order (`Pool.next`), as `el_source.Source` does for
//! one peer.
//!
//! Segments live in a window of `window` slots ahead of the consumer. A worker takes the
//! lowest segment no one is fetching, fetches and checks it (`el_source.fetch`: numbers,
//! parent links inside the segment, transactions roots), and swaps its buffer into the
//! slot. Fast peers therefore take more segments. A segment one worker has held longer than
//! `hedge_after_ms` is fetched by an idle worker too, and the first answer wins, so a slow
//! peer cannot hold up the consumer. The consumer checks the parent link across segments:
//! the first block of each segment must name the last handed-out block's hash, the first of
//! all the given `parent`. A segment that breaks it is dropped, refetched, and its peer
//! cooled down.
//!
//! Peer scoring: a peer that fails (connection, decode, check) or answers short (it is
//! behind) is cooled down, longer each consecutive time, and reconnected after.
//!
//! The pool stops short of the tip: segments past the block the chain schedule puts at now,
//! minus `margin_blocks`, are not fetched, and `next` returns false when the consumer
//! reaches them. A single-peer `Source` follows the tip from there.

const std = @import("std");
const base = @import("base");

const el_source = @import("el_source.zig");
const unsafe_watch = @import("unsafe_watch.zig");
const enode = base.consensus.p2p.peers.enode;
const curve = base.common.crypto.secp256k1;
const ChainConfig = base.common.chains.ChainConfig;
const RollupConfig = base.consensus.protocol.RollupConfig;
const Io = std.Io;
const assert = std.debug.assert;

pub const segment_blocks = 128;
pub const workers_max = 64;
pub const window_max = 64;
const hedge_after_ms = 2_000;
const behind_cooldown_ms = 15_000;
const rejected_cooldown_ms = 120_000;
const failure_cooldown_ms_max = 60_000;
/// The consumer gives up after this long without a segment while peers exist.
const stall_ms_max = 300_000;
const wait_ms = 100;
/// Per segment: headers are ~700 bytes each. Bodies vary widely: some Base Sepolia ranges
/// hold over 20 MiB per 128 blocks. Only the touched part of each buffer becomes resident.
const segment_headers_bytes = 1 << 20;
const segment_bodies_bytes = 64 << 20;

const State = enum { empty, fetching, ready };

const Slot = struct {
    segment: u64,
    state: State = .empty,
    /// Workers fetching this segment now (two when hedged).
    fetchers: u32 = 0,
    owner: u32 = 0,
    started_ms: i64 = 0,
    fetched_by: u32 = 0,
    batch: el_source.Batch,
};

pub const Worker = struct {
    pool: *Pool,
    index: u32,
    target: el_source.Target,
    peer: el_source.Peer,
    batch: el_source.Batch,
    scratch: [][]const u8,
    thread: ?std.Thread = null,
    label: [8]u8,
    // Guarded by `pool.mutex`.
    /// Between `take` and `finish`: the worker uses its peer.
    busy: bool = false,
    segments: u64 = 0,
    blocks: u64 = 0,
    fetch_ms: u64 = 0,
    failures: u32 = 0,
    consecutive_failures: u32 = 0,
    behind: u32 = 0,
    rejected: u32 = 0,
    hedges: u32 = 0,
    cooldown_until_ms: i64 = 0,

    /// Blocks per second while fetching (0 before the first segment).
    pub fn rate(worker: *const Worker) u64 {
        if (worker.fetch_ms == 0) return 0;
        return worker.blocks * 1000 / worker.fetch_ms;
    }
};

const Job = struct { segment: u64, generation: u64, first: u64 };

pub const Options = struct {
    from: u64,
    parent: ?[32]u8,
    window: u32 = 24,
    margin_blocks: u64 = 2 * segment_blocks,
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: Io,
    chain: *const ChainConfig,
    rollup: RollupConfig,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    secret: [32]u8,
    margin_blocks: u64,
    window: u32,
    slots: []Slot,
    workers: [workers_max]*Worker = undefined,
    worker_count: u32 = 0,
    stopping: bool = false,
    /// Workers take no segments (a `Source` follows the tip meanwhile).
    parked: bool = false,
    /// Bumped by `reset`: answers to jobs of an older generation are dropped.
    generation: u64 = 0,
    // The consumer's position: segment 0 starts at `first_number`.
    first_number: u64,
    base_segment: u64 = 0,
    index: u32 = 0,
    parent: ?[32]u8,
    transactions: [][]const u8,
    // Counters (consumer).
    blocks: u64 = 0,
    transactions_count: u64 = 0,
    duplicates: u64 = 0,

    pub fn create(
        allocator: std.mem.Allocator,
        io: Io,
        chain: *const ChainConfig,
        options: Options,
    ) !*Pool {
        assert(options.window > 1 and options.window <= window_max);
        const pool = try allocator.create(Pool);
        errdefer allocator.destroy(pool);
        const slots = try allocator.alloc(Slot, options.window);
        errdefer allocator.free(slots);
        var allocated: usize = 0;
        errdefer for (slots[0..allocated]) |*slot| slot.batch.free(allocator);
        for (slots, 0..) |*slot, index| {
            slot.* = .{ .segment = index, .batch = try alloc_batch(allocator) };
            allocated += 1;
        }
        const transactions = try allocator.alloc([]const u8, el_source.transactions_max);
        pool.* = .{
            .allocator = allocator,
            .io = io,
            .chain = chain,
            .rollup = unsafe_watch.rollup_for(chain),
            .secret = el_source.random_secret(io),
            .margin_blocks = options.margin_blocks,
            .window = options.window,
            .slots = slots,
            .first_number = options.from,
            .parent = options.parent,
            .transactions = transactions,
        };
        return pool;
    }

    /// Stops and joins every worker, then frees everything.
    pub fn destroy(pool: *Pool) void {
        pool.mutex.lockUncancelable(pool.io);
        pool.stopping = true;
        pool.condition.broadcast(pool.io);
        // A worker blocked on a read wakes when its connection shuts down.
        for (pool.workers[0..pool.worker_count]) |worker| worker.peer.shutdown();
        pool.mutex.unlock(pool.io);
        const allocator = pool.allocator;
        for (pool.workers[0..pool.worker_count]) |worker| {
            if (worker.thread) |thread| thread.join();
            worker.peer.close();
            worker.peer.free(allocator);
            worker.batch.free(allocator);
            allocator.free(worker.scratch);
            allocator.destroy(worker);
        }
        for (pool.slots) |*slot| slot.batch.free(allocator);
        allocator.free(pool.slots);
        allocator.free(pool.transactions);
        allocator.destroy(pool);
    }

    /// Adds a peer by enode text and starts its worker; false when it is invalid, already
    /// in the pool, or the pool is full.
    pub fn add_peer(pool: *Pool, text: []const u8) !bool {
        const record = enode.parse(text) catch return false;
        const compressed = record.public_key;
        const remote = curve.decompress_public_key(&compressed) orelse return false;
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        if (pool.worker_count == workers_max) return false;
        for (pool.workers[0..pool.worker_count]) |worker| {
            if (std.mem.eql(u8, &worker.target.remote, &remote)) return false;
        }
        const allocator = pool.allocator;
        const worker = try allocator.create(Worker);
        errdefer allocator.destroy(worker);
        var peer = try el_source.Peer.alloc(allocator, pool.io);
        errdefer peer.free(allocator);
        peer.quiet = true;
        var batch = try alloc_batch(allocator);
        errdefer batch.free(allocator);
        const scratch = try allocator.alloc([]const u8, el_source.transactions_max);
        errdefer allocator.free(scratch);
        var label: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&label, "{x}", .{compressed[1..5]}) catch unreachable;
        worker.* = .{
            .pool = pool,
            .index = pool.worker_count,
            .target = .{
                .address = switch (record.address) {
                    .ip4 => |ip| .{ .ip4 = .{ .bytes = ip, .port = record.tcp_port } },
                    .ip6 => |ip| .{ .ip6 = .{ .bytes = ip, .port = record.tcp_port } },
                },
                .remote = remote,
                .secret = pool.secret,
                .chain = pool.chain,
            },
            .peer = peer,
            .batch = batch,
            .scratch = scratch,
            .label = label,
        };
        worker.thread = try std.Thread.spawn(.{}, work, .{worker});
        pool.workers[pool.worker_count] = worker;
        pool.worker_count += 1;
        return true;
    }

    /// Adds every peer in `path` (one enode per line; `#` comments, blank lines and a
    /// `?discport=` suffix allowed). Returns how many were new.
    pub fn load_peers(pool: *Pool, path: []const u8) !u32 {
        var buffer: [64 * 1024]u8 = undefined;
        const text = try Io.Dir.cwd().readFile(pool.io, path, &buffer);
        var added: u32 = 0;
        var lines = std.mem.tokenizeAny(u8, text, "\r\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            const end = std.mem.indexOfScalar(u8, trimmed, '?') orelse trimmed.len;
            if (try pool.add_peer(trimmed[0..end])) added += 1;
        }
        return added;
    }

    /// The number of the next block `next` hands out.
    pub fn next_number(pool: *const Pool) u64 {
        return pool.first_number + pool.base_segment * segment_blocks + pool.index;
    }

    /// Parks the workers: they finish the segment in hand and take no more until `reset`.
    pub fn park(pool: *Pool) void {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        pool.parked = true;
        pool.condition.broadcast(pool.io);
    }

    /// Moves the consumer to `from` (whose parent is `parent`), drops every segment, and
    /// unparks the workers.
    pub fn reset(pool: *Pool, from: u64, parent: ?[32]u8) void {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        pool.parked = false;
        pool.generation += 1;
        pool.first_number = from;
        pool.base_segment = 0;
        pool.index = 0;
        pool.parent = parent;
        for (pool.slots, 0..) |*slot, index| {
            slot.segment = index;
            slot.state = .empty;
            slot.fetchers = 0;
        }
        pool.condition.broadcast(pool.io);
    }

    /// The highest block number the chain schedule puts at or before now.
    pub fn tip_estimate(pool: *const Pool) u64 {
        const now = Io.Clock.real.now(pool.io);
        const time_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
        return last_block_at(&pool.rollup, time_ms);
    }

    fn segment_first(pool: *const Pool, segment: u64) u64 {
        return pool.first_number + segment * segment_blocks;
    }

    /// Fetch only segments that end at least `margin_blocks` below the tip.
    fn fetchable(pool: *const Pool, segment: u64, limit_number: u64) bool {
        return pool.segment_first(segment) + segment_blocks - 1 <= limit_number;
    }

    fn fetch_limit(pool: *const Pool) u64 {
        return pool.tip_estimate() -| pool.margin_blocks;
    }

    fn now_ms(pool: *const Pool) i64 {
        return Io.Clock.awake.now(pool.io).toMilliseconds();
    }

    /// The next block in ascending order, or false once the next segment is too close to
    /// the tip for the pool to fetch (switch to a `Source`). Blocks stay valid until the
    /// next call.
    pub fn next(pool: *Pool, block: *el_source.Block) !bool {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        pool.release_consumed();
        const waited_from = pool.now_ms();
        while (true) {
            const slot = &pool.slots[pool.base_segment % pool.window];
            assert(slot.segment == pool.base_segment);
            const near_tip = !pool.fetchable(pool.base_segment, pool.fetch_limit());
            if (pool.index == 0 and near_tip) return false;
            if (slot.state == .ready) {
                if (pool.index == 0 and !pool.linked(slot)) continue;
                block.* = try slot.batch.block(pool.index, pool.transactions);
                pool.index += 1;
                pool.parent = block.hash;
                pool.blocks += 1;
                pool.transactions_count += block.transactions.len;
                assert(block.number + 1 == pool.next_number());
                return true;
            }
            if (pool.worker_count == 0) return error.NoPeers;
            if (pool.now_ms() - waited_from > stall_ms_max) return error.Stalled;
            pool.condition.waitTimeout(pool.io, &pool.mutex, .{ .duration = .{
                .raw = .fromMilliseconds(wait_ms),
                .clock = .awake,
            } }) catch {};
        }
    }

    /// Frees the base slot once every block in it was handed out (on the call after the
    /// last one, so that block stayed valid).
    fn release_consumed(pool: *Pool) void {
        if (pool.index < segment_blocks) return;
        assert(pool.index == segment_blocks);
        const slot = &pool.slots[pool.base_segment % pool.window];
        assert(slot.state == .ready);
        slot.segment += pool.window;
        slot.state = .empty;
        slot.fetchers = 0;
        pool.base_segment += 1;
        pool.index = 0;
        pool.condition.broadcast(pool.io);
    }

    /// The ready base slot names the last handed-out block as parent; if not, it is
    /// dropped for a refetch and its peer cooled down.
    fn linked(pool: *Pool, slot: *Slot) bool {
        const parent = pool.parent orelse return true;
        if (std.mem.eql(u8, &parent, &slot.batch.parent)) return true;
        const worker = pool.workers[slot.fetched_by];
        worker.rejected += 1;
        worker.cooldown_until_ms = pool.now_ms() + rejected_cooldown_ms;
        std.debug.print("el-pool: peer {s} segment at {d} does not link; refetching\n", .{
            worker.label, slot.batch.first,
        });
        slot.state = .empty;
        pool.condition.broadcast(pool.io);
        return false;
    }

    /// Waits for a segment to fetch: the lowest unclaimed one in the window, else a stale
    /// claim to hedge. Null when stopping.
    fn take(pool: *Pool, worker: *Worker) ?Job {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        while (!pool.stopping) {
            const now = pool.now_ms();
            if (!pool.parked and worker.cooldown_until_ms <= now) {
                if (pool.claim(worker, now)) |job| {
                    worker.busy = true;
                    return job;
                }
            }
            pool.condition.waitTimeout(pool.io, &pool.mutex, .{ .duration = .{
                .raw = .fromMilliseconds(wait_ms * 2),
                .clock = .awake,
            } }) catch {};
        }
        return null;
    }

    fn claim(pool: *Pool, worker: *Worker, now: i64) ?Job {
        const limit_number = pool.fetch_limit();
        var segment = pool.base_segment;
        var hedge: ?*Slot = null;
        while (segment < pool.base_segment + pool.window) : (segment += 1) {
            if (!pool.fetchable(segment, limit_number)) break;
            const slot = &pool.slots[segment % pool.window];
            assert(slot.segment == segment);
            switch (slot.state) {
                .empty => {
                    slot.state = .fetching;
                    slot.fetchers = 1;
                    slot.owner = worker.index;
                    slot.started_ms = now;
                    return pool.make_job(segment);
                },
                .fetching => if (hedge == null and slot.fetchers == 1 and
                    slot.owner != worker.index and now - slot.started_ms > hedge_after_ms)
                {
                    hedge = slot;
                },
                .ready => {},
            }
        }
        const slot = hedge orelse return null;
        slot.fetchers += 1;
        worker.hedges += 1;
        return pool.make_job(slot.segment);
    }

    fn make_job(pool: *const Pool, segment: u64) Job {
        return .{
            .segment = segment,
            .generation = pool.generation,
            .first = pool.segment_first(segment),
        };
    }

    /// Records a worker's answer for `job`: the fetched batch (swapped into the slot) or a
    /// failure (the segment goes back to the queue and the worker cools down).
    fn finish(pool: *Pool, worker: *Worker, job: Job, result: anyerror!u32, elapsed_ms: u64) void {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        defer pool.condition.broadcast(pool.io);
        assert(worker.busy);
        worker.busy = false;
        const slot = &pool.slots[job.segment % pool.window];
        const current = job.generation == pool.generation and slot.segment == job.segment;
        if (current) slot.fetchers -|= 1;
        const count = result catch |err| {
            worker.failures += 1;
            worker.consecutive_failures += 1;
            const shift: u5 = @intCast(@min(worker.consecutive_failures, 6));
            const cooldown: i64 = @min(@as(i64, 1000) << shift, failure_cooldown_ms_max);
            worker.cooldown_until_ms = pool.now_ms() + cooldown;
            std.debug.print("el-pool: peer {s} failed ({s}); cooling down {d} ms\n", .{
                worker.label, @errorName(err), cooldown,
            });
            if (current and slot.state == .fetching and slot.fetchers == 0) slot.state = .empty;
            return;
        };
        worker.consecutive_failures = 0;
        if (count < segment_blocks) {
            // The peer is behind the segment: let the others have it.
            worker.behind += 1;
            worker.cooldown_until_ms = pool.now_ms() + behind_cooldown_ms;
            if (current and slot.state == .fetching and slot.fetchers == 0) slot.state = .empty;
            return;
        }
        worker.fetch_ms += elapsed_ms;
        if (!current or slot.state == .ready) {
            pool.duplicates += 1;
            return;
        }
        std.mem.swap(el_source.Batch, &slot.batch, &worker.batch);
        slot.state = .ready;
        slot.fetched_by = worker.index;
        worker.segments += 1;
        worker.blocks += count;
    }

    /// Lends the open connection of the fastest idle peer: swaps it with `peer` (an
    /// unconnected one, which the worker reconnects when it next fetches). Returns the
    /// lent peer's target, or null when no idle worker is connected. Park first.
    pub fn lend_fastest(pool: *Pool, peer: *el_source.Peer) ?el_source.Target {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        assert(pool.parked and !peer.connected);
        var best: ?*Worker = null;
        for (pool.workers[0..pool.worker_count]) |worker| {
            if (worker.busy or !worker.peer.connected) continue;
            if (best == null or worker.rate() > best.?.rate()) best = worker;
        }
        const worker = best orelse return null;
        std.mem.swap(el_source.Peer, &worker.peer, peer);
        worker.peer.quiet = true;
        peer.quiet = false;
        assert(peer.connected and !worker.peer.connected);
        return worker.target;
    }

    /// Every peer's target, fastest fetch rate first, into `output`; returns how many.
    pub fn targets_by_rate(pool: *Pool, output: []el_source.Target) usize {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        var order: [workers_max]*Worker = undefined;
        const workers = order[0..pool.worker_count];
        @memcpy(workers, pool.workers[0..pool.worker_count]);
        std.mem.sort(*Worker, workers, {}, faster);
        const count = @min(output.len, workers.len);
        for (output[0..count], workers[0..count]) |*target, worker| target.* = worker.target;
        return count;
    }

    pub fn print_peers(pool: *Pool) void {
        pool.mutex.lockUncancelable(pool.io);
        defer pool.mutex.unlock(pool.io);
        for (pool.workers[0..pool.worker_count]) |worker| {
            std.debug.print("  peer {s}: {d} blocks, {d} blocks/s fetching, {d} failures, " ++
                "{d} behind, {d} rejected, {d} hedges, connected {}\n", .{
                worker.label,    worker.blocks,         worker.rate(),
                worker.failures, worker.behind,         worker.rejected,
                worker.hedges,   worker.peer.connected,
            });
        }
    }
};

/// The highest block number whose scheduled time is at or before `time_ms`.
pub fn last_block_at(rollup: *const RollupConfig, time_ms: u64) u64 {
    var low: u64 = 0;
    var high: u64 = 1 << 40;
    while (low < high) {
        const middle = low + (high - low + 1) / 2;
        if (rollup.l2_block_timestamp_ms(middle) <= time_ms) low = middle else high = middle - 1;
    }
    assert(rollup.l2_block_timestamp_ms(low) <= time_ms or low == 0);
    return low;
}

fn faster(_: void, a: *Worker, b: *Worker) bool {
    return a.rate() > b.rate();
}

fn alloc_batch(allocator: std.mem.Allocator) !el_source.Batch {
    return el_source.Batch.alloc(
        allocator,
        segment_blocks,
        segment_headers_bytes,
        segment_bodies_bytes,
    );
}

/// A worker's loop: take a segment, (re)connect if needed, fetch, report.
fn work(worker: *Worker) void {
    const pool = worker.pool;
    while (pool.take(worker)) |job| {
        const started = pool.now_ms();
        const result = fetch_segment(worker, job.first);
        const elapsed: u64 = @intCast(@max(pool.now_ms() - started, 1));
        pool.finish(worker, job, result, elapsed);
    }
}

fn fetch_segment(worker: *Worker, first: u64) !u32 {
    const peer = &worker.peer;
    if (!peer.connected) _ = try peer.open(&worker.target);
    errdefer peer.close();
    return el_source.fetch(peer, &worker.batch, first, segment_blocks, null, worker.scratch);
}

test "el-pool: the tip estimate inverts the block schedule" {
    const rollup = unsafe_watch.rollup_for(&base.common.chains.sepolia);
    // Both sides of the boundary, in the 200 ms (Denim) era and well before it.
    for ([_]u64{ 1_000_000, 55_000_000, 55_700_123 }) |number| {
        const time_ms = rollup.l2_block_timestamp_ms(number);
        try std.testing.expectEqual(number, last_block_at(&rollup, time_ms));
        try std.testing.expectEqual(number - 1, last_block_at(&rollup, time_ms - 1));
    }
}

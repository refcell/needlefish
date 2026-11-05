//! The best-transactions view for flashblocks. Mirrors base/base
//! `crates/builder/core/src/flashblocks/best_txs.rs` (`BestFlashblocksTxs`) and
//! `crates/execution/payload/src/rejection_cache.rs` (`RejectionCache`).
//!
//! Each flashblock asks the pool for a fresh priority-ordered snapshot (`Pool.select`:
//! highest effective tip first, nonces ascending per sender) and walks it through this
//! view, which skips:
//! - transactions already committed by an earlier flashblock of the same block (the pool
//!   still holds them until the block is canonical);
//! - transactions in the rejection cache: hashes that failed execution recently, shared
//!   across blocks with a capacity and a time-to-live (base/base: 100k entries, 30 min);
//! - later nonces of a sender after `mark_invalid` (reth `BestTransactions::mark_invalid`
//!   drops the sender's descendants, since they cannot execute without the gap filled).
//!
//! Resting predicates and parking (base/base `RestingPredicateMode`, off by default) are
//! not ported yet; see the lane file.
//!
//! All tables are allocated at `init`; the hot path (`next`, `mark_*`) does not allocate.

const std = @import("std");
const assert = std.debug.assert;

const txpool = @import("../../execution/txpool/root.zig");

pub const Tx = txpool.Tx;
pub const B256 = txpool.B256;
pub const Address = txpool.Address;

/// base/base `REJECTION_CACHE_MAX_CAPACITY` / `REJECTION_CACHE_TTL`.
pub const rejection_cache_capacity_default: u32 = 100_000;
pub const rejection_cache_ttl_ns_default: u64 = 30 * 60 * std.time.ns_per_s;

/// Recently rejected transaction hashes with a capacity and time-to-live. Insertion order
/// is kept in a FIFO ring; at capacity the oldest insertion is evicted (moka's TinyLFU
/// eviction is approximated by FIFO: either way a full cache forgets old rejections).
/// Re-inserting a hash refreshes its time-to-live, as `moka::Cache::insert` does.
pub const RejectionCache = struct {
    /// The live insert of a hash; `sequence` names the ring slot that owns it.
    const Live = struct { inserted_ns: u64, sequence: u64 };
    const Map = std.AutoHashMapUnmanaged([32]u8, Live);
    const Item = struct { hash: [32]u8, inserted_ns: u64, sequence: u64 };

    map: Map = .empty,
    ring: []Item,
    head: u32 = 0,
    count: u32 = 0,
    sequence_next: u64 = 0,
    ttl_ns: u64,

    pub fn init(allocator: std.mem.Allocator, capacity: u32, ttl_ns: u64) !RejectionCache {
        assert(capacity > 0);
        assert(ttl_ns > 0);
        const ring = try allocator.alloc(Item, capacity);
        errdefer allocator.free(ring);
        var map: Map = .empty;
        try map.ensureTotalCapacity(allocator, capacity);
        return .{ .map = map, .ring = ring, .ttl_ns = ttl_ns };
    }

    pub fn deinit(cache: *RejectionCache, allocator: std.mem.Allocator) void {
        cache.map.deinit(allocator);
        allocator.free(cache.ring);
        cache.* = undefined;
    }

    /// Live entries (expired ones may linger until the next insert).
    pub fn entry_count(cache: *const RejectionCache) u32 {
        assert(cache.map.count() <= cache.count);
        return cache.map.count();
    }

    pub fn is_rejected(cache: *const RejectionCache, hash: B256, now_ns: u64) bool {
        const live = cache.map.get(hash.bytes) orelse return false;
        assert(live.inserted_ns <= now_ns);
        return now_ns - live.inserted_ns < cache.ttl_ns;
    }

    pub fn mark_rejected(cache: *RejectionCache, hashes: []const B256, now_ns: u64) void {
        for (hashes) |hash| cache.insert(hash, now_ns);
    }

    pub fn insert(cache: *RejectionCache, hash: B256, now_ns: u64) void {
        const capacity: u32 = @intCast(cache.ring.len);
        // Drop expired entries from the front, then make room for one.
        while (cache.count > 0) {
            const oldest = cache.ring[cache.head];
            const expired = now_ns -| oldest.inserted_ns >= cache.ttl_ns;
            if (!expired and cache.count < capacity) break;
            cache.pop_oldest();
        }
        assert(cache.count < capacity);
        const sequence = cache.sequence_next;
        cache.sequence_next += 1;
        cache.ring[(cache.head + cache.count) % capacity] = .{
            .hash = hash.bytes,
            .inserted_ns = now_ns,
            .sequence = sequence,
        };
        cache.count += 1;
        // Capacity was reserved at init and the map never exceeds `count` entries.
        cache.map.putAssumeCapacity(hash.bytes, .{ .inserted_ns = now_ns, .sequence = sequence });
        assert(cache.map.count() <= cache.count);
    }

    fn pop_oldest(cache: *RejectionCache) void {
        assert(cache.count > 0);
        const oldest = cache.ring[cache.head];
        // A later re-insert of the same hash owns the map entry: keep it.
        if (cache.map.get(oldest.hash)) |live| {
            if (live.sequence == oldest.sequence) assert(cache.map.remove(oldest.hash));
        }
        cache.head = (cache.head + 1) % @as(u32, @intCast(cache.ring.len));
        cache.count -= 1;
    }
};

pub const Options = struct {
    /// Most transactions one block can commit across all its flashblocks.
    committed_max: u32 = 16 * 1024,
    /// Most distinct senders marked invalid within one snapshot walk.
    invalid_senders_max: u32 = 4096,
};

/// Walks one pool snapshot per flashblock. `refresh` installs the next snapshot; the
/// committed set persists for the whole block and is cleared by `reset_block`.
pub const BestFlashblocksTxs = struct {
    const HashSet = std.AutoHashMapUnmanaged([32]u8, void);
    /// Invalid sender to the lowest invalid nonce.
    const SenderMap = std.AutoHashMapUnmanaged([20]u8, u64);

    snapshot: []const *const Tx = &.{},
    cursor: u32 = 0,
    current: ?*const Tx = null,
    committed: HashSet = .empty,
    committed_max: u32,
    invalid_senders: SenderMap = .empty,
    invalid_senders_max: u32,
    rejection_cache: *const RejectionCache,
    rejection_cache_hits: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        rejection_cache: *const RejectionCache,
        options: Options,
    ) !BestFlashblocksTxs {
        assert(options.committed_max > 0);
        assert(options.invalid_senders_max > 0);
        var committed: HashSet = .empty;
        try committed.ensureTotalCapacity(allocator, options.committed_max);
        errdefer committed.deinit(allocator);
        var invalid_senders: SenderMap = .empty;
        try invalid_senders.ensureTotalCapacity(allocator, options.invalid_senders_max);
        return .{
            .committed = committed,
            .committed_max = options.committed_max,
            .invalid_senders = invalid_senders,
            .invalid_senders_max = options.invalid_senders_max,
            .rejection_cache = rejection_cache,
        };
    }

    pub fn deinit(best: *BestFlashblocksTxs, allocator: std.mem.Allocator) void {
        best.invalid_senders.deinit(allocator);
        best.committed.deinit(allocator);
        best.* = undefined;
    }

    /// Starts a new block: forgets committed transactions and the current snapshot.
    pub fn reset_block(best: *BestFlashblocksTxs) void {
        best.committed.clearRetainingCapacity();
        best.refresh(&.{});
        assert(best.committed.count() == 0);
    }

    /// base/base `refresh_iterator`: installs the next flashblock's pool snapshot. A new
    /// snapshot reflects the pool's current state, so per-walk invalid senders reset.
    pub fn refresh(best: *BestFlashblocksTxs, snapshot: []const *const Tx) void {
        best.snapshot = snapshot;
        best.cursor = 0;
        best.current = null;
        best.invalid_senders.clearRetainingCapacity();
        assert(best.invalid_senders.count() == 0);
    }

    /// The next executable candidate, or null when the snapshot is exhausted.
    pub fn next(best: *BestFlashblocksTxs, now_ns: u64) ?*const Tx {
        best.current = null;
        while (best.cursor < best.snapshot.len) {
            const tx = best.snapshot[best.cursor];
            best.cursor += 1;
            if (best.committed.contains(tx.hash.bytes)) continue;
            if (best.invalid_senders.get(tx.sender.bytes)) |nonce| {
                if (tx.nonce >= nonce) continue;
            }
            if (best.rejection_cache.is_rejected(tx.hash, now_ns)) {
                best.rejection_cache_hits += 1;
                best.mark_sender_invalid(tx.sender, tx.nonce);
                continue;
            }
            best.current = tx;
            return tx;
        }
        assert(best.cursor == best.snapshot.len);
        return null;
    }

    /// base/base `mark_invalid`: the current transaction failed; skip its sender's later
    /// nonces for the rest of this snapshot.
    pub fn mark_invalid(best: *BestFlashblocksTxs, sender: Address, nonce: u64) void {
        const current = best.current orelse return;
        // base/base debug-asserts the caller names the current transaction.
        assert(current.sender.eql(sender) and current.nonce == nonce);
        best.mark_sender_invalid(sender, nonce);
        best.current = null;
    }

    /// The current transaction was included: later flashblocks must skip it.
    pub fn mark_current_committed(best: *BestFlashblocksTxs) void {
        const current = best.current orelse return;
        best.insert_committed(current.hash);
        best.current = null;
    }

    /// Marks hashes committed by other means (e.g. the sequencer's forced transactions).
    pub fn mark_committed(best: *BestFlashblocksTxs, hashes: []const B256) void {
        for (hashes) |hash| best.insert_committed(hash);
    }

    pub fn is_committed(best: *const BestFlashblocksTxs, hash: B256) bool {
        return best.committed.contains(hash.bytes);
    }

    fn insert_committed(best: *BestFlashblocksTxs, hash: B256) void {
        // A block cannot hold more than `committed_max` transactions (sized from the gas
        // limit at startup), so the reserved capacity always suffices.
        assert(best.committed.count() < best.committed_max or best.committed.contains(hash.bytes));
        best.committed.putAssumeCapacity(hash.bytes, {});
    }

    fn mark_sender_invalid(best: *BestFlashblocksTxs, sender: Address, nonce: u64) void {
        const entry = best.invalid_senders.getPtr(sender.bytes);
        if (entry) |lowest| {
            lowest.* = @min(lowest.*, nonce);
            return;
        }
        // Past the bound, stop tracking new senders: their later nonces are then tried and
        // fail in execution, which is slower but still correct.
        if (best.invalid_senders.count() == best.invalid_senders_max) return;
        best.invalid_senders.putAssumeCapacity(sender.bytes, nonce);
    }
};

test {
    _ = @import("best_txs_test.zig");
}

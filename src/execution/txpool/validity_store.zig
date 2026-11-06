//! Pool-side storage for `base_sendRawTransactionValidity`: the predicates of each pooled
//! validity transaction, kept until the transaction leaves the pool or its block-number
//! bound passes. A builder includes such a transaction only when `admits` holds for the
//! block it builds (builder enforcement); `PoolSink` pools a transaction together with its
//! predicates.
//!
//! Static: `entries_max` transactions and `predicates_total_max` predicates in one arena,
//! compacted (bounded by the arena size) when its tail is full. EIP-8130 validity
//! transactions are refused here: their nonce lanes need the RPC's lane lookup.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const txpool = @import("root.zig");
const validity = @import("validity.zig");

const B256 = primitives.B256;
const Predicate = validity.Predicate;

pub const Error = error{ StoreFull, AlreadyStored, Eip8130Unsupported };

const Entry = struct { hash: B256, start: u32, count: u32, expiry: u64 };

pub const Store = struct {
    entries: []Entry,
    entry_count: u32 = 0,
    arena: []Predicate,
    /// First free arena slot; slots below it belong to live entries or holes.
    arena_used: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        entries_max: u32,
        predicates_total_max: u32,
    ) !Store {
        assert(entries_max > 0 and predicates_total_max >= validity.predicates_max);
        const entries = try allocator.alloc(Entry, entries_max);
        errdefer allocator.free(entries);
        const arena = try allocator.alloc(Predicate, predicates_total_max);
        return .{ .entries = entries, .arena = arena };
    }

    pub fn deinit(store: *Store, allocator: std.mem.Allocator) void {
        allocator.free(store.entries);
        allocator.free(store.arena);
        store.* = undefined;
    }

    pub fn count(store: *const Store) u32 {
        return store.entry_count;
    }

    fn find(store: *const Store, hash: B256) ?u32 {
        for (store.entries[0..store.entry_count], 0..) |entry, index| {
            if (entry.hash.eql(hash)) return @intCast(index);
        }
        return null;
    }

    /// The predicates stored for `hash` (valid until the next insert or compaction).
    pub fn get(store: *const Store, hash: B256) ?[]const Predicate {
        const index = store.find(hash) orelse return null;
        const entry = store.entries[index];
        return store.arena[entry.start..][0..entry.count];
    }

    /// Stores `predicates` (validated by the caller, with a finite block-number bound).
    pub fn insert(store: *Store, hash: B256, predicates: []const Predicate) Error!void {
        assert(predicates.len > 0 and predicates.len <= validity.predicates_max);
        if (store.find(hash) != null) return error.AlreadyStored;
        if (store.entry_count == store.entries.len) return error.StoreFull;
        const needed: u32 = @intCast(predicates.len);
        if (store.arena_used + needed > store.arena.len) store.compact();
        if (store.arena_used + needed > store.arena.len) return error.StoreFull;
        const bound = validity.block_expiry_bound(predicates) orelse 0;
        const start = store.arena_used;
        @memcpy(store.arena[start..][0..needed], predicates);
        store.arena_used += needed;
        store.entries[store.entry_count] = .{
            .hash = hash,
            .start = start,
            .count = needed,
            .expiry = std.math.cast(u64, bound) orelse std.math.maxInt(u64),
        };
        store.entry_count += 1;
        assert(store.arena_used <= store.arena.len);
    }

    pub fn remove(store: *Store, hash: B256) bool {
        const index = store.find(hash) orelse return false;
        store.entry_count -= 1;
        store.entries[index] = store.entries[store.entry_count];
        if (store.entry_count == 0) store.arena_used = 0;
        return true;
    }

    /// Moves live predicates to the arena front, in start order (no holes left).
    fn compact(store: *Store) void {
        const live = store.entries[0..store.entry_count];
        std.mem.sortUnstable(Entry, live, {}, start_less);
        var used: u32 = 0;
        for (live) |*entry| {
            assert(entry.start >= used);
            std.mem.copyForwards(
                Predicate,
                store.arena[used..][0..entry.count],
                store.arena[entry.start..][0..entry.count],
            );
            entry.start = used;
            used += entry.count;
        }
        store.arena_used = used;
    }

    fn start_less(_: void, left: Entry, right: Entry) bool {
        return left.start < right.start;
    }

    /// After a new head: drops entries whose transaction left `pool`, and evicts (from the
    /// pool too) transactions that can no longer be included from `next_block` on.
    /// Returns how many transactions were evicted.
    pub fn prune(store: *Store, pool: *txpool.Pool, next_block: u64) u32 {
        var evicted: u32 = 0;
        var index: u32 = 0;
        while (index < store.entry_count) {
            const entry = store.entries[index];
            const pooled = pool.get(entry.hash) != null;
            if (pooled and entry.expiry >= next_block) {
                index += 1;
                continue;
            }
            if (pooled) {
                assert(pool.remove(entry.hash));
                evicted += 1;
            }
            assert(store.remove(entry.hash)); // Swaps the last entry into `index`.
        }
        return evicted;
    }

    /// Whether the builder may include `hash` in the block `context` describes: true for
    /// transactions without predicates, else when every stored predicate holds.
    pub fn admits(
        store: *const Store,
        hash: B256,
        reader: validity.Reader,
        context: validity.Context,
    ) !bool {
        const predicates = store.get(hash) orelse return true;
        return validity.all_match(predicates, reader, context);
    }
};

/// Account state for pooling a transaction (the node's head state).
pub const Accounts = struct {
    context: *anyopaque,
    account: *const fn (context: *anyopaque, address: [20]u8) txpool.Account,
};

/// Pools validity transactions with their predicates (the RPC's validity sink).
pub const PoolSink = struct {
    pool: *txpool.Pool,
    store: *Store,
    accounts: Accounts,

    pub fn submit(
        sink: *PoolSink,
        transaction: *const txpool.Tx,
        predicates: []const Predicate,
    ) (Error || txpool.AddError)!void {
        if (transaction.tx_type == 0x79) return error.Eip8130Unsupported;
        if (sink.store.count() == sink.store.entries.len) return error.StoreFull;
        const account = sink.accounts.account(sink.accounts.context, transaction.sender.bytes);
        _ = try sink.pool.add(transaction.*, account);
        sink.store.insert(transaction.hash, predicates) catch |err| {
            assert(sink.pool.remove(transaction.hash)); // Never pooled unenforced.
            return err;
        };
        assert(sink.store.get(transaction.hash) != null);
    }
};

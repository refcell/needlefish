//! Execution metering for the builder. Mirrors base/base `crates/builder/metering`
//! (`MeteringStore`) and `crates/builder/core/src/execution_metering_mode.rs`.
//!
//! An external simulator meters pending transactions and pushes the results
//! (`base_setMeteringInformation`); the builder reads them when deciding whether a
//! transaction fits a block's execution-time budget. The store is an LRU cache with
//! a time-to-live (base/base: 10k entries, 30 s). When the builder includes a transaction
//! that had no metering yet, it records when (`needed_at`); metering that arrives later
//! is a *late arrival*: it is counted (latency, predicted time) and not cached, since the
//! transaction is already in a block.
//!
//! Time is injected (`now_ns` on every call); all memory is allocated at `init`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");

pub const schedule = @import("schedule.zig");

pub const B256 = primitives.B256;

/// base/base `DEFAULT_METERING_STORE_MAX_CAPACITY` / `DEFAULT_METERING_STORE_TTL_SECS`.
pub const capacity_default: u32 = 10_000;
pub const ttl_ns_default: u64 = 30 * std.time.ns_per_s;

/// base/base `ExecutionMeteringMode`: off, log-only (`dry_run`), or reject over-budget
/// transactions (`enforce`).
pub const ExecutionMeteringMode = enum {
    off,
    dry_run,
    enforce,

    pub fn is_enabled(mode: ExecutionMeteringMode) bool {
        return mode == .dry_run or mode == .enforce;
    }

    pub fn is_dry_run(mode: ExecutionMeteringMode) bool {
        return mode == .dry_run;
    }

    /// The CLI spelling (clap `ValueEnum`: `off`, `dry-run`, `enforce`).
    pub fn parse(text: []const u8) ?ExecutionMeteringMode {
        if (std.mem.eql(u8, text, "off")) return .off;
        if (std.mem.eql(u8, text, "dry-run")) return .dry_run;
        if (std.mem.eql(u8, text, "enforce")) return .enforce;
        return null;
    }
};

/// The parts of base/base `MeterBundleResponse` the builder reads.
pub const Metering = struct {
    total_gas_used: u64,
    total_execution_time_us: u64,
    state_block_number: u64 = 0,
};

/// A fixed-capacity map with least-recently-used eviction and a time-to-live measured
/// from insertion (moka `time_to_live`). Reads refresh recency, not the time-to-live.
pub fn LruTtl(comptime Value: type) type {
    return struct {
        const Self = @This();
        const none: u32 = std.math.maxInt(u32);
        const Node = struct {
            key: [32]u8,
            value: Value,
            inserted_ns: u64,
            newer: u32,
            older: u32,
        };

        pub const Removal = enum { none, size, expired };

        map: std.AutoHashMapUnmanaged([32]u8, u32) = .empty,
        nodes: []Node,
        free: []u32,
        free_count: u32,
        newest: u32 = none,
        oldest: u32 = none,
        ttl_ns: u64,

        pub fn init(allocator: std.mem.Allocator, capacity: u32, ttl_ns: u64) !Self {
            assert(capacity > 0 and capacity < none);
            assert(ttl_ns > 0);
            const nodes = try allocator.alloc(Node, capacity);
            errdefer allocator.free(nodes);
            const free = try allocator.alloc(u32, capacity);
            errdefer allocator.free(free);
            for (free, 0..) |*slot, index| slot.* = @intCast(capacity - 1 - index);
            var map: std.AutoHashMapUnmanaged([32]u8, u32) = .empty;
            try map.ensureTotalCapacity(allocator, capacity);
            return .{
                .map = map,
                .nodes = nodes,
                .free = free,
                .free_count = capacity,
                .ttl_ns = ttl_ns,
            };
        }

        pub fn deinit(table: *Self, allocator: std.mem.Allocator) void {
            table.map.deinit(allocator);
            allocator.free(table.free);
            allocator.free(table.nodes);
            table.* = undefined;
        }

        pub fn count(table: *const Self) u32 {
            assert(table.map.count() + table.free_count == table.nodes.len);
            return table.map.count();
        }

        pub fn contains(table: *const Self, key: B256, now_ns: u64) bool {
            const index = table.map.get(key.bytes) orelse return false;
            return !table.expired(index, now_ns);
        }

        /// The live value for `key`, marking it most recently used.
        pub fn get(table: *Self, key: B256, now_ns: u64) ?Value {
            const index = table.map.get(key.bytes) orelse return null;
            if (table.expired(index, now_ns)) return null;
            table.unlink(index);
            table.link_newest(index);
            return table.nodes[index].value;
        }

        /// Inserts or replaces `key` (restarting its time-to-live). Returns why an entry
        /// was evicted to make room, if one was.
        pub fn insert(table: *Self, key: B256, value: Value, now_ns: u64) Removal {
            if (table.map.get(key.bytes)) |index| {
                table.nodes[index].value = value;
                table.nodes[index].inserted_ns = now_ns;
                table.unlink(index);
                table.link_newest(index);
                return .none;
            }
            var removal: Removal = .none;
            if (table.free_count == 0) {
                const victim = table.oldest;
                assert(victim != none);
                removal = if (table.expired(victim, now_ns)) .expired else .size;
                table.remove_index(victim);
            }
            assert(table.free_count > 0);
            table.free_count -= 1;
            const index = table.free[table.free_count];
            table.nodes[index] = .{
                .key = key.bytes,
                .value = value,
                .inserted_ns = now_ns,
                .newer = none,
                .older = none,
            };
            table.link_newest(index);
            table.map.putAssumeCapacityNoClobber(key.bytes, index);
            return removal;
        }

        /// Removes `key`; returns its value if it was present and live.
        pub fn remove(table: *Self, key: B256, now_ns: u64) ?Value {
            const index = table.map.get(key.bytes) orelse return null;
            const live = !table.expired(index, now_ns);
            const value = table.nodes[index].value;
            table.remove_index(index);
            return if (live) value else null;
        }

        /// Drops expired entries from the oldest end; returns how many. Expired entries
        /// are invisible either way; this frees their slots and counts expirations.
        pub fn expire(table: *Self, now_ns: u64) u32 {
            var expired_count: u32 = 0;
            // Entries are not ordered by insertion time (reads reorder them), so walk the
            // whole list once, oldest first. Bounded by the capacity.
            var cursor = table.oldest;
            var steps: usize = 0;
            while (cursor != none) : (steps += 1) {
                assert(steps < table.nodes.len);
                const newer = table.nodes[cursor].newer;
                if (table.expired(cursor, now_ns)) {
                    table.remove_index(cursor);
                    expired_count += 1;
                }
                cursor = newer;
            }
            return expired_count;
        }

        pub fn clear(table: *Self) void {
            table.map.clearRetainingCapacity();
            for (table.free, 0..) |*slot, index| slot.* = @intCast(table.nodes.len - 1 - index);
            table.free_count = @intCast(table.nodes.len);
            table.newest = none;
            table.oldest = none;
            assert(table.count() == 0);
        }

        fn expired(table: *const Self, index: u32, now_ns: u64) bool {
            return now_ns -| table.nodes[index].inserted_ns >= table.ttl_ns;
        }

        fn remove_index(table: *Self, index: u32) void {
            assert(table.map.remove(table.nodes[index].key));
            table.unlink(index);
            table.free[table.free_count] = index;
            table.free_count += 1;
            assert(table.free_count <= table.nodes.len);
        }

        fn unlink(table: *Self, index: u32) void {
            const node = &table.nodes[index];
            if (node.newer != none) table.nodes[node.newer].older = node.older else {
                assert(table.newest == index);
                table.newest = node.older;
            }
            if (node.older != none) table.nodes[node.older].newer = node.newer else {
                assert(table.oldest == index);
                table.oldest = node.newer;
            }
            node.newer = none;
            node.older = none;
        }

        fn link_newest(table: *Self, index: u32) void {
            const node = &table.nodes[index];
            assert(node.newer == none and node.older == none);
            node.older = table.newest;
            if (table.newest != none) table.nodes[table.newest].newer = index;
            table.newest = index;
            if (table.oldest == none) table.oldest = index;
        }
    };
}

/// base/base `BuilderMetrics` metering-store metrics.
pub const Metrics = struct {
    store_size: metrics.Gauge = .{},
    lru_evictions: metrics.Counter = .{},
    ttl_expirations: metrics.Counter = .{},
    late_arrivals: metrics.Counter = .{},
    late_arrival_latency_ms: metrics.Histogram = .init(&late_arrival_latency_buckets_ms),
    late_arrival_execution_time_us: metrics.Histogram = .init(&execution_time_buckets_us),
};

const late_arrival_latency_buckets_ms = [_]f64{ 1, 5, 10, 50, 100, 250, 500, 1000, 5000 };
const execution_time_buckets_us = [_]f64{ 10, 100, 1000, 10_000, 100_000, 1_000_000 };

/// base/base `MeteringStore` (a `MeteringProvider`).
pub const MeteringStore = struct {
    cache: LruTtl(Metering),
    needed_at: LruTtl(u64),
    enabled: bool,
    metrics: Metrics = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        enabled: bool,
        capacity: u32,
        ttl_ns: u64,
    ) !MeteringStore {
        var cache = try LruTtl(Metering).init(allocator, capacity, ttl_ns);
        errdefer cache.deinit(allocator);
        const needed_at = try LruTtl(u64).init(allocator, capacity, ttl_ns);
        return .{ .cache = cache, .needed_at = needed_at, .enabled = enabled };
    }

    pub fn deinit(store: *MeteringStore, allocator: std.mem.Allocator) void {
        store.needed_at.deinit(allocator);
        store.cache.deinit(allocator);
        store.* = undefined;
    }

    pub fn len(store: *const MeteringStore) u32 {
        return store.cache.count();
    }

    pub fn is_enabled(store: *const MeteringStore) bool {
        return store.enabled;
    }

    pub fn set_enabled(store: *MeteringStore, enabled: bool) void {
        store.enabled = enabled;
    }

    /// Metering for `hash`, or null when disabled, unknown, or expired.
    pub fn get(store: *MeteringStore, hash: B256, now_ns: u64) ?Metering {
        if (!store.enabled) return null;
        return store.cache.get(hash, now_ns);
    }

    /// base/base `insert`: a late arrival (the transaction was already included without
    /// metering) is counted and dropped; anything else is cached. Inserting works while
    /// disabled, as in base/base.
    pub fn insert(store: *MeteringStore, hash: B256, metering: Metering, now_ns: u64) void {
        if (store.needed_at.remove(hash, now_ns)) |needed_ns| {
            assert(needed_ns <= now_ns);
            store.metrics.late_arrivals.increment();
            const latency_ms = @as(f64, @floatFromInt(now_ns - needed_ns)) / 1e6;
            store.metrics.late_arrival_latency_ms.observe(latency_ms);
            const execution_us: f64 = @floatFromInt(metering.total_execution_time_us);
            store.metrics.late_arrival_execution_time_us.observe(execution_us);
            return;
        }
        switch (store.cache.insert(hash, metering, now_ns)) {
            .none => {},
            .size => store.metrics.lru_evictions.increment(),
            .expired => store.metrics.ttl_expirations.increment(),
        }
        store.metrics.store_size.set(store.cache.count());
        assert(store.cache.count() <= store.cache.nodes.len);
    }

    /// The builder included `hash` with no metering available: a later insert is late.
    pub fn mark_included_without_metering(store: *MeteringStore, hash: B256, now_ns: u64) void {
        if (!store.enabled or store.cache.contains(hash, now_ns)) return;
        if (store.needed_at.contains(hash, now_ns)) return; // `entry().or_insert`: keep first.
        _ = store.needed_at.insert(hash, now_ns, now_ns);
    }

    /// The builder skipped `hash` (e.g. still waiting for metering): not late after all.
    pub fn skip(store: *MeteringStore, hash: B256, now_ns: u64) void {
        _ = store.needed_at.remove(hash, now_ns);
    }

    /// Forgets metering for included or permanently rejected transactions.
    pub fn remove(store: *MeteringStore, hashes: []const B256, now_ns: u64) void {
        for (hashes) |hash| _ = store.cache.remove(hash, now_ns);
        store.metrics.store_size.set(store.cache.count());
    }

    pub fn clear(store: *MeteringStore) void {
        store.cache.clear();
        store.needed_at.clear();
        store.metrics.store_size.set(0);
    }

    /// Frees expired slots and counts their expirations (moka does this in the
    /// background; call it from a periodic tick).
    pub fn expire(store: *MeteringStore, now_ns: u64) void {
        const expired = store.cache.expire(now_ns);
        store.metrics.ttl_expirations.add(expired);
        _ = store.needed_at.expire(now_ns);
        store.metrics.store_size.set(store.cache.count());
    }
};

test {
    _ = @import("root_test.zig");
    _ = schedule;
}

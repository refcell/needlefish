//! The bounded in-memory event store that replaces base/base's Postgres table.
//!
//! Events live in a fixed ring of `events_max` slots in insertion order; their variable
//! bytes (event id, labels, `data`, bundle keys) live in a byte arena used as a FIFO ring of
//! `arena_bytes`. Inserting into a full ring or arena evicts the oldest events. Expired
//! events (`event_time` older than `retention_ns`) are never served and are evicted from
//! the head by `prune`. Everything is allocated in `init`.
//!
//! Lookups go through chained hash indexes with intrusive doubly linked chains (O(1)
//! unlink on eviction): `event_id` (unique, for dedupe), tx hash, block number, block hash,
//! `data.bundle_id`, `data.bundle_hash`, and one list of the rejected event types.
//! Query results are sorted like base/base's SQL: oldest first by
//! (`event_time`, `ingested_at`, `event_id`), or newest first by (`event_time`, `event_id`)
//! for rejected events.

const std = @import("std");
const assert = std.debug.assert;

const event_module = @import("event.zig");
const lazy_alloc = @import("../../utilities/lazy_alloc/root.zig");

const Event = event_module.Event;

/// base/base `DEFAULT_TRANSACTION_EVENT_QUERY_LIMIT`.
pub const query_limit_default: u32 = 500;
/// base/base `MAX_TRANSACTION_EVENT_QUERY_LIMIT`.
pub const query_limit_max: u32 = 2_000;
/// Arena bytes a record needs beyond its source line (copied bundle keys).
pub const record_overhead_bytes: u32 = 2 * event_module.bundle_key_size_max;

const none: u32 = std.math.maxInt(u32);

pub const RetentionClass = event_module.RetentionClass;

pub const Options = struct {
    events_max: u32,
    arena_bytes: u32,
    /// Per retention class: events whose `event_time` is older than this are expired.
    retention_ns: std.EnumArray(RetentionClass, u64),
};

pub const Record = struct {
    event: Event,
    ingested_at_ns: u64,
};

pub const EvictReason = enum { capacity, retention };

pub const Key = union(enum) {
    tx_hash: [32]u8,
    block_number: u64,
    block_hash: [32]u8,
    bundle: []const u8,
};

pub const RejectedQuery = struct {
    /// Inclusive.
    from_block: ?u64 = null,
    /// Inclusive.
    to_block: ?u64 = null,
    /// Inclusive.
    from_time_ns: ?u64 = null,
    /// Exclusive.
    to_time_ns: ?u64 = null,
    limit: u32 = query_limit_default,
};

const Index = enum(u8) {
    event_id,
    tx_hash,
    block_number,
    block_hash,
    bundle_id,
    bundle_hash,
    rejected,
};
const index_count = std.enums.values(Index).len;

const Text = enum(u8) { event_id, network, payload_id, request_id, data, bundle_id, bundle_hash };
const text_count = std.enums.values(Text).len;

const Present = packed struct(u8) {
    network: bool = false,
    tx_hash: bool = false,
    block_hash: bool = false,
    block_number: bool = false,
    payload_id: bool = false,
    request_id: bool = false,
    bundle_id: bool = false,
    bundle_hash: bool = false,
};

const Link = struct { previous: u32 = none, next: u32 = none };

const Slot = struct {
    sequence: u64,
    event_time_ns: u64,
    ingested_at_ns: u64,
    block_number: u64,
    tx_hash: [32]u8,
    block_hash: [32]u8,
    offset: u32,
    lengths: [text_count]u32,
    present: Present,
    producer: event_module.Producer,
    event_type: event_module.EventType,
    links: [index_count]Link,

    fn size(slot: *const Slot) u32 {
        var total: u32 = 0;
        for (slot.lengths) |length| total += length;
        return total;
    }
};

pub const Stats = struct {
    evicted_capacity: u64 = 0,
    evicted_retention: u64 = 0,
};

pub const Store = struct {
    options: Options,
    slots: []Slot,
    arena: []u8,
    buckets: [index_count][]u32,
    bucket_mask: u32,
    /// Query scratch: matching slot indices.
    matches: []u32,
    head: u32 = 0,
    count: u32 = 0,
    arena_start: u32 = 0,
    arena_end: u32 = 0,
    arena_used: u64 = 0,
    sequence_next: u64 = 0,
    stats: Stats = .{},

    pub fn init(allocator: std.mem.Allocator, options: Options) !Store {
        assert(options.events_max > 0 and options.events_max < none / 2);
        assert(options.arena_bytes > 0);
        const bucket_count = std.math.ceilPowerOfTwoAssert(u32, @max(options.events_max, 2));
        const slots = try lazy_alloc.alloc(allocator, Slot, options.events_max);
        errdefer lazy_alloc.free(allocator, slots);
        const arena = try lazy_alloc.alloc(allocator, u8, options.arena_bytes);
        errdefer lazy_alloc.free(allocator, arena);
        const matches = try lazy_alloc.alloc(allocator, u32, options.events_max);
        errdefer lazy_alloc.free(allocator, matches);
        var buckets: [index_count][]u32 = undefined;
        var allocated: u32 = 0;
        errdefer for (buckets[0..allocated]) |list| allocator.free(list);
        for (&buckets, std.enums.values(Index)) |*list, index| {
            list.* = try allocator.alloc(u32, if (index == .rejected) 1 else bucket_count);
            @memset(list.*, none);
            allocated += 1;
        }
        assert(allocated == index_count);
        return .{
            .options = options,
            .slots = slots,
            .arena = arena,
            .buckets = buckets,
            .bucket_mask = bucket_count - 1,
            .matches = matches,
        };
    }

    pub fn deinit(store: *Store, allocator: std.mem.Allocator) void {
        for (store.buckets) |list| allocator.free(list);
        lazy_alloc.free(allocator, store.matches);
        lazy_alloc.free(allocator, store.arena);
        lazy_alloc.free(allocator, store.slots);
        store.* = undefined;
    }

    /// Arena bytes `record` takes.
    pub fn record_size(record: *const Record) u64 {
        const value = &record.event;
        var total: u64 = value.event_id.len + value.data.len;
        if (value.network) |text| total += text.len;
        if (value.payload_id) |text| total += text.len;
        if (value.request_id) |text| total += text.len;
        if (value.bundle_id) |text| total += text.len;
        if (value.bundle_hash) |text| total += text.len;
        assert(total >= value.event_id.len);
        return total;
    }

    pub fn find_event_id(store: *const Store, event_id: []const u8) ?u32 {
        assert(event_id.len > 0);
        const head = store.bucket_of(.event_id, event_id);
        var slot_index = store.buckets[@backingInt(Index.event_id)][head];
        var steps: u32 = 0;
        while (slot_index != none) : (steps += 1) {
            assert(steps < store.count);
            const slot = &store.slots[slot_index];
            if (std.mem.eql(u8, store.text_of(slot, .event_id), event_id)) return slot_index;
            slot_index = slot.links[@backingInt(Index.event_id)].next;
        }
        return null;
    }

    /// Inserts a record whose `event_id` is not stored, evicting the oldest events when the
    /// ring or arena is full. Returns the slot index.
    pub fn insert(store: *Store, record: *const Record) u32 {
        const size = record_size(record);
        assert(size <= store.arena.len);
        assert(store.find_event_id(record.event.event_id) == null);
        if (store.count == store.options.events_max) store.evict_head(.capacity);
        const offset = store.reserve(@intCast(size));
        const slot_index = (store.head + store.count) % store.options.events_max;
        const slot = &store.slots[slot_index];
        slot.* = slot_of(record, store.sequence_next, offset);
        store.copy_texts(slot, &record.event);
        assert(slot.size() == size);
        store.count += 1;
        store.sequence_next += 1;
        store.arena_end = offset + @as(u32, @intCast(size));
        store.arena_used += size;
        store.link_all(slot_index);
        return slot_index;
    }

    fn slot_of(record: *const Record, sequence: u64, offset: u32) Slot {
        const value = &record.event;
        assert(value.event_id.len > 0);
        return .{
            .sequence = sequence,
            .event_time_ns = value.event_time_ns,
            .ingested_at_ns = record.ingested_at_ns,
            .block_number = value.block_number orelse 0,
            .tx_hash = value.tx_hash orelse @splat(0),
            .block_hash = value.block_hash orelse @splat(0),
            .offset = offset,
            .lengths = @splat(0),
            .present = .{
                .network = value.network != null,
                .tx_hash = value.tx_hash != null,
                .block_hash = value.block_hash != null,
                .block_number = value.block_number != null,
                .payload_id = value.payload_id != null,
                .request_id = value.request_id != null,
                .bundle_id = value.bundle_id != null,
                .bundle_hash = value.bundle_hash != null,
            },
            .producer = value.producer,
            .event_type = value.event_type,
            .links = @splat(.{}),
        };
    }

    fn copy_texts(store: *Store, slot: *Slot, value: *const Event) void {
        const texts = [text_count]?[]const u8{
            value.event_id, value.network,   value.payload_id,  value.request_id,
            value.data,     value.bundle_id, value.bundle_hash,
        };
        var cursor = slot.offset;
        for (texts, &slot.lengths) |maybe_text, *length| {
            const bytes = maybe_text orelse continue;
            @memcpy(store.arena[cursor..][0..bytes.len], bytes);
            length.* = @intCast(bytes.len);
            cursor += length.*;
        }
        assert(cursor - slot.offset == slot.size());
    }

    /// An arena offset with `size` contiguous free bytes, evicting the oldest as needed.
    fn reserve(store: *Store, size: u32) u32 {
        const capacity: u32 = @intCast(store.arena.len);
        assert(size <= capacity);
        var evictions: u32 = 0;
        while (evictions <= store.options.events_max) : (evictions += 1) {
            if (store.count == 0) {
                store.arena_start = 0;
                store.arena_end = 0;
                return 0;
            }
            if (store.arena_end > store.arena_start) {
                if (capacity - store.arena_end >= size) return store.arena_end;
                if (store.arena_start >= size) return 0;
            } else if (store.arena_start - store.arena_end >= size) {
                return store.arena_end;
            }
            store.evict_head(.capacity);
        }
        unreachable; // An empty arena fits any record.
    }

    /// Evicts the oldest event.
    pub fn evict_head(store: *Store, reason: EvictReason) void {
        assert(store.count > 0);
        const slot_index = store.head;
        store.unlink_all(slot_index);
        store.arena_used -= store.slots[slot_index].size();
        store.head = (store.head + 1) % store.options.events_max;
        store.count -= 1;
        if (store.count > 0) store.arena_start = store.slots[store.head].offset;
        switch (reason) {
            .capacity => store.stats.evicted_capacity += 1,
            .retention => store.stats.evicted_retention += 1,
        }
        assert(store.count < store.options.events_max);
    }

    /// Removes the newest event (rolls back an insert whose journal write failed).
    pub fn pop_tail(store: *Store) void {
        assert(store.count > 0);
        const slot_index = (store.head + store.count - 1) % store.options.events_max;
        const slot = &store.slots[slot_index];
        store.unlink_all(slot_index);
        store.arena_used -= slot.size();
        store.count -= 1;
        store.sequence_next -= 1;
        assert(slot.sequence == store.sequence_next);
        if (store.count == 0) return;
        const last = &store.slots[(store.head + store.count - 1) % store.options.events_max];
        store.arena_end = last.offset + last.size();
    }

    /// Evicts expired events from the head (insertion order, so an expired event behind a
    /// live one waits; queries never serve it). Returns how many were evicted.
    pub fn prune(store: *Store, now_ns: u64) u32 {
        var evicted: u32 = 0;
        while (store.count > 0 and evicted < store.options.events_max) : (evicted += 1) {
            if (!store.expired(&store.slots[store.head], now_ns)) break;
            store.evict_head(.retention);
        }
        assert(store.count == 0 or evicted <= store.options.events_max);
        return evicted;
    }

    /// The newest `count` slots in insertion order (the tail), oldest of them first.
    pub fn tail_slot(store: *const Store, back: u32) u32 {
        assert(back < store.count);
        const position = store.count - 1 - back;
        return (store.head + position) % store.options.events_max;
    }

    /// The slot at logical position `position` (0 is the oldest).
    pub fn slot_at(store: *const Store, position: u32) u32 {
        assert(position < store.count);
        return (store.head + position) % store.options.events_max;
    }

    pub fn sequence_of(store: *const Store, slot_index: u32) u64 {
        assert(slot_index < store.slots.len);
        return store.slots[slot_index].sequence;
    }

    pub fn get(store: *const Store, slot_index: u32) Record {
        assert(slot_index < store.slots.len);
        const slot = &store.slots[slot_index];
        const present = slot.present;
        return .{ .ingested_at_ns = slot.ingested_at_ns, .event = .{
            .event_id = store.text_of(slot, .event_id),
            .event_time_ns = slot.event_time_ns,
            .producer = slot.producer,
            .event_type = slot.event_type,
            .network = if (present.network) store.text_of(slot, .network) else null,
            .tx_hash = if (present.tx_hash) slot.tx_hash else null,
            .block_hash = if (present.block_hash) slot.block_hash else null,
            .block_number = if (present.block_number) slot.block_number else null,
            .payload_id = if (present.payload_id) store.text_of(slot, .payload_id) else null,
            .request_id = if (present.request_id) store.text_of(slot, .request_id) else null,
            .data = store.text_of(slot, .data),
            .bundle_id = if (present.bundle_id) store.text_of(slot, .bundle_id) else null,
            .bundle_hash = if (present.bundle_hash) store.text_of(slot, .bundle_hash) else null,
        } };
    }

    fn text_of(store: *const Store, slot: *const Slot, which: Text) []const u8 {
        var offset = slot.offset;
        for (slot.lengths[0..@backingInt(which)]) |length| offset += length;
        const length = slot.lengths[@backingInt(which)];
        assert(offset + length <= store.arena.len);
        return store.arena[offset..][0..length];
    }

    // Indexes.

    /// The index key bytes of a slot, or null when the slot is not in that index.
    fn key_bytes(store: *const Store, slot: *const Slot, index: Index) ?[]const u8 {
        return switch (index) {
            .event_id => store.text_of(slot, .event_id),
            .tx_hash => if (slot.present.tx_hash) &slot.tx_hash else null,
            .block_number => if (slot.present.block_number)
                std.mem.asBytes(&slot.block_number)
            else
                null,
            .block_hash => if (slot.present.block_hash) &slot.block_hash else null,
            .bundle_id => if (slot.present.bundle_id) store.text_of(slot, .bundle_id) else null,
            .bundle_hash => if (slot.present.bundle_hash)
                store.text_of(slot, .bundle_hash)
            else
                null,
            .rejected => if (slot.event_type.rejected()) "" else null,
        };
    }

    fn bucket_of(store: *const Store, index: Index, key: []const u8) u32 {
        if (index == .rejected) return 0;
        const hash = std.hash.Wyhash.hash(@backingInt(index), key);
        const result: u32 = @truncate(hash & store.bucket_mask);
        assert(result < store.buckets[@backingInt(index)].len);
        return result;
    }

    fn link_all(store: *Store, slot_index: u32) void {
        const slot = &store.slots[slot_index];
        for (std.enums.values(Index)) |index| {
            const key = store.key_bytes(slot, index) orelse continue;
            const head = &store.buckets[@backingInt(index)][store.bucket_of(index, key)];
            const link = &slot.links[@backingInt(index)];
            link.* = .{ .previous = none, .next = head.* };
            if (head.* != none) store.slots[head.*].links[@backingInt(index)].previous = slot_index;
            head.* = slot_index;
        }
    }

    fn unlink_all(store: *Store, slot_index: u32) void {
        const slot = &store.slots[slot_index];
        for (std.enums.values(Index)) |index| {
            const key = store.key_bytes(slot, index) orelse continue;
            const link = slot.links[@backingInt(index)];
            if (link.previous == none) {
                const head = &store.buckets[@backingInt(index)][store.bucket_of(index, key)];
                assert(head.* == slot_index);
                head.* = link.next;
            } else {
                store.slots[link.previous].links[@backingInt(index)].next = link.next;
            }
            if (link.next != none) {
                store.slots[link.next].links[@backingInt(index)].previous = link.previous;
            }
            slot.links[@backingInt(index)] = .{};
        }
    }

    // Queries.

    /// Live events matching `key`, oldest first, at most `limit` (clamped to 1..2000).
    pub fn query(store: *Store, key: Key, limit: u32, now_ns: u64) []const u32 {
        var found: u32 = 0;
        switch (key) {
            .tx_hash => |*hash| found = store.collect(.tx_hash, hash, now_ns, null, found),
            .block_hash => |*hash| found = store.collect(.block_hash, hash, now_ns, null, found),
            .block_number => |*number| {
                const bytes = std.mem.asBytes(number);
                found = store.collect(.block_number, bytes, now_ns, null, found);
            },
            .bundle => |bundle_key| {
                found = store.collect(.bundle_id, bundle_key, now_ns, null, found);
                found = store.collect(.bundle_hash, bundle_key, now_ns, bundle_key, found);
            },
        }
        const matches = store.matches[0..found];
        std.sort.heap(u32, matches, store, older_than);
        return matches[0..@min(found, clamp_limit(limit))];
    }

    /// Appends live slots of `index` whose key equals `key` to `matches[found..]`. With
    /// `skip_bundle_id`, slots whose `bundle_id` equals it were already collected.
    fn collect(
        store: *Store,
        index: Index,
        key: []const u8,
        now_ns: u64,
        skip_bundle_id: ?[]const u8,
        found_start: u32,
    ) u32 {
        var found = found_start;
        var slot_index = store.buckets[@backingInt(index)][store.bucket_of(index, key)];
        var steps: u32 = 0;
        while (slot_index != none) : (steps += 1) {
            assert(steps < store.count);
            const slot = &store.slots[slot_index];
            defer slot_index = slot.links[@backingInt(index)].next;
            if (store.expired(slot, now_ns)) continue;
            if (!std.mem.eql(u8, store.key_bytes(slot, index).?, key)) continue;
            if (skip_bundle_id) |skip| {
                const bundle_id = store.text_of(slot, .bundle_id);
                if (slot.present.bundle_id and std.mem.eql(u8, bundle_id, skip)) continue;
            }
            store.matches[found] = slot_index;
            found += 1;
        }
        assert(found <= store.count);
        return found;
    }

    /// Live rejected events (SIMULATION_FAILED, BUILDER_REJECTED, BUILDER_EXPIRED) matching
    /// `filter`, newest first.
    pub fn query_rejected(store: *Store, filter: RejectedQuery, now_ns: u64) []const u32 {
        var found: u32 = 0;
        var slot_index = store.buckets[@backingInt(Index.rejected)][0];
        var steps: u32 = 0;
        while (slot_index != none) : (steps += 1) {
            assert(steps < store.count);
            const slot = &store.slots[slot_index];
            defer slot_index = slot.links[@backingInt(Index.rejected)].next;
            if (store.expired(slot, now_ns) or !matches_filter(slot, filter)) continue;
            store.matches[found] = slot_index;
            found += 1;
        }
        const matches = store.matches[0..found];
        std.sort.heap(u32, matches, store, newer_than);
        return matches[0..@min(found, clamp_limit(filter.limit))];
    }

    fn expired(store: *const Store, slot: *const Slot, now_ns: u64) bool {
        return store.expired_time(slot.event_type, slot.event_time_ns, now_ns);
    }

    /// Whether `value` is older than its retention class's window at `now_ns`.
    pub fn expired_at(store: *const Store, value: Event, now_ns: u64) bool {
        return store.expired_time(value.event_type, value.event_time_ns, now_ns);
    }

    fn expired_time(
        store: *const Store,
        event_type: event_module.EventType,
        event_time_ns: u64,
        now_ns: u64,
    ) bool {
        const cutoff_ns = now_ns -| store.options.retention_ns.get(event_type.retention_class());
        assert(cutoff_ns <= now_ns);
        return event_time_ns < cutoff_ns;
    }

    fn matches_filter(slot: *const Slot, filter: RejectedQuery) bool {
        assert(slot.event_type.rejected());
        const block_filtered = filter.from_block != null or filter.to_block != null;
        if (block_filtered and !slot.present.block_number) return false;
        if (filter.from_block) |from| if (slot.block_number < from) return false;
        if (filter.to_block) |to| if (slot.block_number > to) return false;
        if (filter.from_time_ns) |from| if (slot.event_time_ns < from) return false;
        if (filter.to_time_ns) |to| if (slot.event_time_ns >= to) return false;
        return true;
    }

    fn older_than(store: *const Store, a: u32, b: u32) bool {
        const left = &store.slots[a];
        const right = &store.slots[b];
        if (left.event_time_ns != right.event_time_ns) {
            return left.event_time_ns < right.event_time_ns;
        }
        if (left.ingested_at_ns != right.ingested_at_ns) {
            return left.ingested_at_ns < right.ingested_at_ns;
        }
        return store.id_order(left, right) == .lt;
    }

    fn newer_than(store: *const Store, a: u32, b: u32) bool {
        const left = &store.slots[a];
        const right = &store.slots[b];
        if (left.event_time_ns != right.event_time_ns) {
            return left.event_time_ns > right.event_time_ns;
        }
        return store.id_order(left, right) == .gt;
    }

    fn id_order(store: *const Store, left: *const Slot, right: *const Slot) std.math.Order {
        assert(left.lengths[@backingInt(Text.event_id)] > 0);
        assert(right.lengths[@backingInt(Text.event_id)] > 0);
        return std.mem.order(u8, store.text_of(left, .event_id), store.text_of(right, .event_id));
    }
};

/// base/base `normalize_limit`: clamp to 1..`query_limit_max`.
pub fn clamp_limit(limit: u32) u32 {
    const clamped = std.math.clamp(limit, 1, query_limit_max);
    assert(clamped >= 1 and clamped <= query_limit_max);
    return clamped;
}

test {
    _ = @import("store_test.zig");
}

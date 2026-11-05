//! Kademlia routing table for discv5: 256 buckets by log2 XOR distance, each holding at
//! most `bucket_size` live entries plus a small replacement cache. Entries live in a
//! fixed pool allocated once at init; buckets hold pool indices, so memory is bounded by
//! `Config.nodes_max` regardless of how many buckets are populated.
//!
//! Policy (discv5 / Kademlia): a new node joins its bucket if there is room. A full
//! bucket parks the node in the replacement cache and asks the caller to ping the least
//! recently seen entry; if that entry keeps failing it is evicted and the freshest
//! replacement is promoted. Per-bucket and per-table limits on nodes sharing an IPv4 /24
//! subnet resist eclipse attacks, like the `discv5` crate's IP limits.

const std = @import("std");
const assert = std.debug.assert;
const enr = @import("../peers/enr.zig");
const ip = @import("../peers/ip.zig");

pub const bucket_count = 256;
pub const NodeId = enr.NodeId;
const none: u16 = std.math.maxInt(u16);

pub const Config = struct {
    bucket_size: u8 = 16,
    replacements_max: u8 = 8,
    /// Total entries (live + replacements) across all buckets.
    nodes_max: u16 = 1024,
    /// Consecutive failures before a live entry is evicted.
    failures_max: u8 = 2,
    /// Nodes from one IPv4 /24 allowed per bucket and per table (0 disables).
    subnet_bucket_max: u8 = 2,
    subnet_table_max: u8 = 10,
};

pub const Endpoint = struct {
    address: ip.Address,
    port: u16,

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        if (a.port != b.port) return false;
        return std.meta.eql(a.address, b.address);
    }
};

pub const Entry = struct {
    node_id: NodeId,
    record: enr.Record,
    endpoint: Endpoint,
    last_seen_ns: u64,
    failures: u8,
    /// Liveness confirmed by a response since insertion.
    verified: bool,
};

pub const InsertResult = union(enum) {
    added,
    updated,
    /// Parked in the replacement cache; ping `least_recent` to decide eviction.
    pending: struct { least_recent: NodeId },
    rejected_self,
    rejected_subnet,
    rejected_full,
};

const Bucket = struct {
    live: [256]u16 = undefined,
    live_count: u8 = 0,
    replacements: [256]u16 = undefined,
    replacements_count: u8 = 0,
};

/// Log2 XOR distance in `0..256`; 0 means equal ids.
pub fn log_distance(a: NodeId, b: NodeId) u16 {
    const x = std.mem.readInt(u256, &a, .big) ^ std.mem.readInt(u256, &b, .big);
    const distance: u16 = 256 - @as(u16, @clz(x));
    assert(distance <= 256);
    return distance;
}

fn xor_distance(a: NodeId, b: NodeId) u256 {
    return std.mem.readInt(u256, &a, .big) ^ std.mem.readInt(u256, &b, .big);
}

fn subnet_of(endpoint: Endpoint) ?[3]u8 {
    return switch (endpoint.address) {
        .ip4 => |value| value[0..3].*,
        .ip6 => null,
    };
}

pub const Table = struct {
    local_id: NodeId,
    config: Config,
    pool: []Entry,
    free: []u16,
    free_count: u16,
    buckets: *[bucket_count]Bucket,

    pub fn init(allocator: std.mem.Allocator, local_id: NodeId, config: Config) !Table {
        assert(config.bucket_size > 0 and config.nodes_max > 0);
        assert(config.failures_max > 0);
        const pool = try allocator.alloc(Entry, config.nodes_max);
        errdefer allocator.free(pool);
        const free = try allocator.alloc(u16, config.nodes_max);
        errdefer allocator.free(free);
        const buckets = try allocator.create([bucket_count]Bucket);
        buckets.* = @splat(.{});
        for (free, 0..) |*slot, index| slot.* = @intCast(config.nodes_max - 1 - index);
        return .{
            .local_id = local_id,
            .config = config,
            .pool = pool,
            .free = free,
            .free_count = config.nodes_max,
            .buckets = buckets,
        };
    }

    pub fn deinit(table: *Table, allocator: std.mem.Allocator) void {
        allocator.destroy(table.buckets);
        allocator.free(table.free);
        allocator.free(table.pool);
        table.* = undefined;
    }

    pub fn live_count(table: *const Table) u32 {
        var total: u32 = 0;
        for (table.buckets) |*bucket| total += bucket.live_count;
        return total;
    }

    fn bucket_for(table: *Table, node_id: NodeId) ?*Bucket {
        const distance = log_distance(table.local_id, node_id);
        if (distance == 0) return null;
        return &table.buckets[distance - 1];
    }

    fn find(table: *Table, indices: []const u16, node_id: NodeId) ?usize {
        for (indices, 0..) |index, position| {
            if (std.mem.eql(u8, &table.pool[index].node_id, &node_id)) return position;
        }
        return null;
    }

    /// The live entry for `node_id`, or null.
    pub fn get(table: *Table, node_id: NodeId) ?*Entry {
        const bucket = table.bucket_for(node_id) orelse return null;
        const position = table.find(bucket.live[0..bucket.live_count], node_id) orelse
            return null;
        return &table.pool[bucket.live[position]];
    }

    /// Inserts or refreshes a record learned at `endpoint`.
    pub fn insert(
        table: *Table,
        record: *const enr.Record,
        endpoint: Endpoint,
        now_ns: u64,
    ) InsertResult {
        const node_id = record.node_id();
        const bucket = table.bucket_for(node_id) orelse return .rejected_self;
        if (table.find(bucket.live[0..bucket.live_count], node_id)) |position| {
            const entry = &table.pool[bucket.live[position]];
            if (record.sequence >= entry.record.sequence) entry.record = record.*;
            entry.endpoint = endpoint;
            return .updated;
        }
        if (!table.subnet_allows(bucket, endpoint)) return .rejected_subnet;
        if (bucket.live_count < table.config.bucket_size) {
            const index = table.allocate() orelse return .rejected_full;
            table.pool[index] = new_entry(node_id, record, endpoint, now_ns);
            bucket.live[bucket.live_count] = index;
            bucket.live_count += 1;
            return .added;
        }
        table.park(bucket, node_id, record, endpoint, now_ns) orelse return .rejected_full;
        return .{ .pending = .{ .least_recent = table.least_recent(bucket) } };
    }

    fn new_entry(
        node_id: NodeId,
        record: *const enr.Record,
        endpoint: Endpoint,
        now_ns: u64,
    ) Entry {
        return .{
            .node_id = node_id,
            .record = record.*,
            .endpoint = endpoint,
            .last_seen_ns = now_ns,
            .failures = 0,
            .verified = false,
        };
    }

    /// Adds or refreshes `node_id` in the replacement cache, evicting the oldest.
    fn park(
        table: *Table,
        bucket: *Bucket,
        node_id: NodeId,
        record: *const enr.Record,
        endpoint: Endpoint,
        now_ns: u64,
    ) ?void {
        const replacements = bucket.replacements[0..bucket.replacements_count];
        if (table.find(replacements, node_id)) |position| {
            table.pool[replacements[position]] = new_entry(node_id, record, endpoint, now_ns);
            return;
        }
        if (table.config.replacements_max == 0) return null;
        if (bucket.replacements_count == table.config.replacements_max) {
            // Oldest replacement is at the front.
            table.release(bucket.replacements[0]);
            remove_at(&bucket.replacements, &bucket.replacements_count, 0);
        }
        const index = table.allocate() orelse return null;
        table.pool[index] = new_entry(node_id, record, endpoint, now_ns);
        bucket.replacements[bucket.replacements_count] = index;
        bucket.replacements_count += 1;
        assert(bucket.replacements_count <= table.config.replacements_max);
    }

    fn least_recent(table: *Table, bucket: *const Bucket) NodeId {
        assert(bucket.live_count > 0);
        var oldest = bucket.live[0];
        for (bucket.live[1..bucket.live_count]) |index| {
            if (table.pool[index].last_seen_ns < table.pool[oldest].last_seen_ns) oldest = index;
        }
        return table.pool[oldest].node_id;
    }

    fn subnet_allows(table: *Table, bucket: *const Bucket, endpoint: Endpoint) bool {
        const subnet = subnet_of(endpoint) orelse return true;
        if (table.config.subnet_bucket_max > 0) {
            var in_bucket: u32 = 0;
            for (bucket.live[0..bucket.live_count]) |index| {
                const other = subnet_of(table.pool[index].endpoint) orelse continue;
                if (std.mem.eql(u8, &other, &subnet)) in_bucket += 1;
            }
            if (in_bucket >= table.config.subnet_bucket_max) return false;
        }
        if (table.config.subnet_table_max > 0) {
            var in_table: u32 = 0;
            for (table.buckets) |*other_bucket| {
                for (other_bucket.live[0..other_bucket.live_count]) |index| {
                    const other = subnet_of(table.pool[index].endpoint) orelse continue;
                    if (std.mem.eql(u8, &other, &subnet)) in_table += 1;
                }
            }
            if (in_table >= table.config.subnet_table_max) return false;
        }
        return true;
    }

    fn allocate(table: *Table) ?u16 {
        if (table.free_count == 0) return null;
        table.free_count -= 1;
        const index = table.free[table.free_count];
        assert(index < table.pool.len);
        return index;
    }

    fn release(table: *Table, index: u16) void {
        assert(index < table.pool.len);
        assert(table.free_count < table.free.len);
        table.free[table.free_count] = index;
        table.free_count += 1;
    }

    /// Records a successful response from `node_id`.
    pub fn mark_alive(table: *Table, node_id: NodeId, now_ns: u64) void {
        const entry = table.get(node_id) orelse return;
        entry.last_seen_ns = now_ns;
        entry.failures = 0;
        entry.verified = true;
    }

    /// Records a failed request. Returns true if the entry was evicted (and the freshest
    /// replacement, if any, promoted).
    pub fn mark_failed(table: *Table, node_id: NodeId) bool {
        const bucket = table.bucket_for(node_id) orelse return false;
        const position = table.find(bucket.live[0..bucket.live_count], node_id) orelse
            return false;
        const entry = &table.pool[bucket.live[position]];
        entry.failures +|= 1;
        if (entry.failures < table.config.failures_max) return false;
        table.release(bucket.live[position]);
        remove_at(&bucket.live, &bucket.live_count, position);
        if (bucket.replacements_count > 0) {
            const freshest = bucket.replacements[bucket.replacements_count - 1];
            bucket.replacements_count -= 1;
            bucket.live[bucket.live_count] = freshest;
            bucket.live_count += 1;
        }
        assert(bucket.live_count <= table.config.bucket_size);
        return true;
    }

    /// Copies up to `output.len` live entries at log distance `distance` (1..256).
    pub fn at_distance(table: *Table, distance: u16, output: []*const Entry) usize {
        assert(distance >= 1 and distance <= bucket_count);
        const bucket = &table.buckets[distance - 1];
        const count = @min(output.len, bucket.live_count);
        for (bucket.live[0..count], output[0..count]) |index, *slot| slot.* = &table.pool[index];
        return count;
    }

    /// Up to `output.len` live entries closest to `target`, nearest first.
    pub fn closest(table: *Table, target: NodeId, output: []*const Entry) usize {
        var count: usize = 0;
        for (table.buckets) |*bucket| {
            for (bucket.live[0..bucket.live_count]) |index| {
                const entry = &table.pool[index];
                count = insert_sorted(output, count, entry, target);
            }
        }
        assert(count <= output.len);
        return count;
    }

    /// Least recently seen live entry in the bucket at `distance`, for liveness pings.
    pub fn least_recent_at(table: *Table, distance: u16) ?NodeId {
        assert(distance >= 1 and distance <= bucket_count);
        const bucket = &table.buckets[distance - 1];
        if (bucket.live_count == 0) return null;
        return table.least_recent(bucket);
    }
};

fn insert_sorted(output: []*const Entry, count: usize, entry: *const Entry, target: NodeId) usize {
    assert(count <= output.len);
    const distance = xor_distance(entry.node_id, target);
    var position = count;
    while (position > 0 and xor_distance(output[position - 1].node_id, target) > distance) {
        position -= 1;
    }
    if (position == output.len) return count;
    const new_count = @min(count + 1, output.len);
    var index = new_count - 1;
    while (index > position) : (index -= 1) output[index] = output[index - 1];
    output[position] = entry;
    return new_count;
}

fn remove_at(items: *[256]u16, count: *u8, position: usize) void {
    assert(position < count.*);
    var index = position;
    while (index + 1 < count.*) : (index += 1) items[index] = items[index + 1];
    count.* -= 1;
}

test {
    _ = @import("table_test.zig");
}

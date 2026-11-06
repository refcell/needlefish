//! Routing table tests. Records are real signed ENRs from seeded keys, so node ids are
//! pseudo-random and nearly all land in the top buckets — which exercises full buckets,
//! replacement caches, and eviction.

const std = @import("std");
const table_module = @import("table.zig");
const Table = table_module.Table;
const enr = @import("../peers/enr.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const record_count = 48;

fn make_records(prng: *Prng, output: []enr.Record) !void {
    for (output, 0..) |*record, index| {
        var secret: secp256k1.SecretKey = undefined;
        while (true) {
            prng.fill(&secret);
            secp256k1.validate_secret_key(secret) catch continue;
            break;
        }
        const octet: u8 = @intCast(index % 250);
        record.* = try enr.build(secret, .{ .ip4 = .{ 10, octet, octet, 1 }, .udp = 9000 });
    }
}

fn endpoint_of(record: *const enr.Record) table_module.Endpoint {
    return .{ .address = .{ .ip4 = record.ip4().? }, .port = record.udp().? };
}

test "table: log distance" {
    const zero: enr.NodeId = @splat(0);
    var one = zero;
    one[31] = 1;
    var top = zero;
    top[0] = 0x80;
    try std.testing.expectEqual(@as(u16, 0), table_module.log_distance(zero, zero));
    try std.testing.expectEqual(@as(u16, 1), table_module.log_distance(zero, one));
    try std.testing.expectEqual(@as(u16, 256), table_module.log_distance(zero, top));
}

test "table: insert, full bucket, eviction promotes replacement" {
    var prng = Prng.init(0x7461_626c);
    var records: [record_count]enr.Record = undefined;
    try make_records(&prng, &records);
    var table = try Table.init(std.testing.allocator, @splat(0), .{
        .bucket_size = 4,
        .replacements_max = 2,
        .nodes_max = 64,
        .subnet_bucket_max = 0,
        .subnet_table_max = 0,
    });
    defer table.deinit(std.testing.allocator);

    var pending_seen = false;
    var pending_target: enr.NodeId = undefined;
    for (&records, 0..) |*record, index| {
        switch (table.insert(record, endpoint_of(record), index)) {
            .added => {},
            .pending => |value| {
                pending_seen = true;
                pending_target = value.least_recent;
            },
            else => |result| {
                std.debug.print("unexpected {s}\n", .{@tagName(result)});
                return error.TestUnexpectedResult;
            },
        }
    }
    try std.testing.expect(pending_seen);
    const again = table.insert(&records[0], endpoint_of(&records[0]), 99);
    try std.testing.expectEqual(.updated, std.meta.activeTag(again));
    // Failing the least recent entry twice evicts it and promotes a replacement.
    const distance = table_module.log_distance(table.local_id, pending_target);
    var before: [16]*const table_module.Entry = undefined;
    const count_before = table.at_distance(distance, &before);
    try std.testing.expect(!table.mark_failed(pending_target));
    try std.testing.expect(table.mark_failed(pending_target));
    try std.testing.expect(table.get(pending_target) == null);
    var after: [16]*const table_module.Entry = undefined;
    try std.testing.expectEqual(count_before, table.at_distance(distance, &after));
}

test "table: alive resets failures and closest is sorted" {
    var prng = Prng.init(0x636c_6f73);
    var records: [24]enr.Record = undefined;
    try make_records(&prng, &records);
    var table = try Table.init(std.testing.allocator, @splat(0x55), .{ .subnet_table_max = 0 });
    defer table.deinit(std.testing.allocator);
    for (&records) |*record| _ = table.insert(record, endpoint_of(record), 0);

    const id = records[0].node_id();
    try std.testing.expect(!table.mark_failed(id));
    table.mark_alive(id, 5);
    try std.testing.expect(!table.mark_failed(id));
    try std.testing.expect(table.get(id).?.verified);

    var target: enr.NodeId = undefined;
    prng.fill(&target);
    var nearest: [8]*const table_module.Entry = undefined;
    const count = table.closest(target, &nearest);
    try std.testing.expectEqual(@as(usize, 8), count);
    for (nearest[1..count], 0..) |entry, index| {
        const previous = std.mem.readInt(u256, &nearest[index].node_id, .big) ^
            std.mem.readInt(u256, &target, .big);
        const current = std.mem.readInt(u256, &entry.node_id, .big) ^
            std.mem.readInt(u256, &target, .big);
        try std.testing.expect(previous <= current);
    }
}

test "table: subnet limits and self rejection" {
    var prng = Prng.init(0x7375_626e);
    var records: [8]enr.Record = undefined;
    try make_records(&prng, &records);
    var table = try Table.init(std.testing.allocator, records[0].node_id(), .{
        .subnet_bucket_max = 0,
        .subnet_table_max = 2,
    });
    defer table.deinit(std.testing.allocator);
    const shared: table_module.Endpoint = .{ .address = .{ .ip4 = .{ 1, 2, 3, 4 } }, .port = 1 };
    const self_result = table.insert(&records[0], shared, 0);
    try std.testing.expectEqual(.rejected_self, std.meta.activeTag(self_result));
    try std.testing.expectEqual(.added, std.meta.activeTag(table.insert(&records[1], shared, 0)));
    try std.testing.expectEqual(.added, std.meta.activeTag(table.insert(&records[2], shared, 0)));
    const subnet_result = table.insert(&records[3], shared, 0);
    try std.testing.expectEqual(.rejected_subnet, std.meta.activeTag(subnet_result));
    const ip6: table_module.Endpoint = .{ .address = .{ .ip6 = @splat(1) }, .port = 1 };
    try std.testing.expectEqual(.added, std.meta.activeTag(table.insert(&records[3], ip6, 0)));
}

test "table: seeded operations keep pool accounting consistent" {
    var prng = Prng.init(0x706f_6f6c);
    var records: [32]enr.Record = undefined;
    try make_records(&prng, &records);
    const config: table_module.Config = .{
        .bucket_size = 3,
        .replacements_max = 2,
        .nodes_max = 20,
        .subnet_bucket_max = 0,
        .subnet_table_max = 0,
    };
    var table = try Table.init(std.testing.allocator, @splat(0), config);
    defer table.deinit(std.testing.allocator);
    for (0..2000) |step| {
        const record = &records[prng.below(records.len)];
        switch (prng.below(3)) {
            0 => _ = table.insert(record, endpoint_of(record), step),
            1 => table.mark_alive(record.node_id(), step),
            else => _ = table.mark_failed(record.node_id()),
        }
        var used: u32 = 0;
        for (table.buckets) |*bucket| {
            try std.testing.expect(bucket.live_count <= config.bucket_size);
            try std.testing.expect(bucket.replacements_count <= config.replacements_max);
            used += bucket.live_count + bucket.replacements_count;
        }
        try std.testing.expectEqual(@as(u32, config.nodes_max), used + table.free_count);
    }
}

const Tag = std.meta.Tag(table_module.InsertResult);

/// Inserts `record` at the endpoint it advertises; returns the result's tag.
fn put(table: *Table, record: *const enr.Record, now_ns: u64) Tag {
    return std.meta.activeTag(table.insert(record, endpoint_of(record), now_ns));
}

fn test_secret(prng: *Prng) secp256k1.SecretKey {
    var secret: secp256k1.SecretKey = undefined;
    while (true) {
        prng.fill(&secret);
        secp256k1.validate_secret_key(secret) catch continue;
        return secret;
    }
}

test "table: a replayed older record cannot move a live node" {
    var prng = Prng.init(0x7365_7121);
    var local: [1]enr.Record = undefined;
    try make_records(&prng, &local);
    var table = try Table.init(std.testing.allocator, local[0].node_id(), .{
        .subnet_bucket_max = 0,
        .subnet_table_max = 2,
    });
    defer table.deinit(std.testing.allocator);
    const secret = test_secret(&prng);
    const v1 = try enr.build(secret, .{ .sequence = 1, .ip4 = .{ 1, 1, 1, 1 }, .udp = 1 });
    const v2 = try enr.build(secret, .{ .sequence = 2, .ip4 = .{ 2, 2, 2, 2 }, .udp = 2 });
    const v3 = try enr.build(secret, .{ .sequence = 3, .ip4 = .{ 3, 3, 3, 3 }, .udp = 3 });
    const id = v2.node_id();
    try std.testing.expectEqual(Tag.added, put(&table, &v2, 0));
    table.mark_alive(id, 1);
    // The replay is refused outright: record, endpoint, and liveness stay.
    const stale = table.insert(&v1, endpoint_of(&v1), 2);
    try std.testing.expectEqual(.rejected_stale, std.meta.activeTag(stale));
    try std.testing.expect(table.get(id).?.endpoint.eql(endpoint_of(&v2)));
    try std.testing.expectEqual(@as(u64, 2), table.get(id).?.record.sequence);
    try std.testing.expect(table.get(id).?.verified);
    // The same record again refreshes nothing.
    try std.testing.expectEqual(Tag.updated, put(&table, &v2, 3));
    try std.testing.expect(table.get(id).?.verified);
    // A newer record moves the node and liveness must be proven again.
    try std.testing.expectEqual(Tag.updated, put(&table, &v3, 4));
    try std.testing.expect(table.get(id).?.endpoint.eql(endpoint_of(&v3)));
    try std.testing.expect(!table.get(id).?.verified);
    // A move into a full subnet is refused; a move within its own /24 is fine.
    var crowd: [2]enr.Record = undefined;
    for (&crowd, 0..) |*record, index| {
        record.* = try enr.build(test_secret(&prng), .{
            .ip4 = .{ 9, 9, 9, @intCast(index + 1) },
            .udp = 9,
        });
        const result = table.insert(record, endpoint_of(record), 5);
        try std.testing.expectEqual(.added, std.meta.activeTag(result));
    }
    const v4 = try enr.build(secret, .{ .sequence = 4, .ip4 = .{ 9, 9, 9, 99 }, .udp = 4 });
    const crowded = table.insert(&v4, endpoint_of(&v4), 6);
    try std.testing.expectEqual(.rejected_subnet, std.meta.activeTag(crowded));
    try std.testing.expect(table.get(id).?.endpoint.eql(endpoint_of(&v3)));
    const v5 = try enr.build(secret, .{ .sequence = 5, .ip4 = .{ 3, 3, 3, 4 }, .udp = 5 });
    try std.testing.expectEqual(Tag.updated, put(&table, &v5, 7));
    try std.testing.expect(table.get(id).?.endpoint.eql(endpoint_of(&v5)));
}

test "table: seeded record versions in any order keep the newest, endpoint consistent" {
    var prng = Prng.init(0x7665_7273);
    var local: [1]enr.Record = undefined;
    try make_records(&prng, &local);
    var table = try Table.init(std.testing.allocator, local[0].node_id(), .{
        .bucket_size = 2,
        .replacements_max = 2,
    });
    defer table.deinit(std.testing.allocator);
    const nodes = 6;
    const versions = 5;
    var records: [nodes][versions]enr.Record = undefined;
    for (&records) |*node| {
        const secret = test_secret(&prng);
        for (node, 0..) |*record, version| {
            const octet: u8 = @intCast(prng.below(250));
            record.* = try enr.build(secret, .{
                .sequence = version + 1,
                .ip4 = .{ octet, octet, @intCast(version), 1 },
                .udp = @intCast(1000 + version),
            });
        }
    }
    var newest: [nodes]u64 = @splat(0);
    for (0..2000) |step| {
        const node = prng.below(nodes);
        const version = prng.below(versions);
        const record = &records[node][version];
        const now: u64 = step;
        _ = table.insert(record, endpoint_of(record), now);
        if (prng.below(4) == 0) table.mark_alive(record.node_id(), now);
        if (prng.below(16) == 0) _ = table.mark_failed(record.node_id());
        for (&records, 0..) |*versions_of, index| {
            const entry = table.get(versions_of[0].node_id()) orelse {
                newest[index] = 0; // Evicted: the table may learn it afresh.
                continue;
            };
            // While live, never older than what the table already showed for this node.
            try std.testing.expect(entry.record.sequence >= newest[index]);
            newest[index] = entry.record.sequence;
            try std.testing.expect(entry.endpoint.eql(endpoint_of(&entry.record)));
        }
    }
}

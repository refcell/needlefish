//! Sequencer leader tracking (base/base `sequencers.rs`, `--sequencer-urls`).
//!
//! The batcher reads unsafe blocks and sync status from one of several sequencers: the
//! first that answers `admin_sequencerActive` with `true`. When none is active (or none
//! answers) the current leader is kept, as in base/base, so a flaky sequencer set never
//! stops batching. Each endpoint has an L2 EL client and a rollup node client, which may
//! be the same URL (base/base's combined node) or two (needlefish's EL and CL).

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../rpc/root.zig");

pub const sequencers_max = 8;

pub const Endpoint = struct {
    l2: *rpc.Client,
    rollup: *rpc.Client,
};

pub const Refresh = struct {
    /// Endpoints that answered `true`.
    active_count: u8,
    leader_changed: bool,
};

pub const Sequencers = struct {
    endpoints: [sequencers_max]Endpoint,
    count: u8,
    leader: u8 = 0,

    pub fn init(endpoints: []const Endpoint) Sequencers {
        assert(endpoints.len > 0);
        assert(endpoints.len <= sequencers_max);
        var sequencers: Sequencers = .{
            .endpoints = undefined,
            .count = @intCast(endpoints.len),
        };
        @memcpy(sequencers.endpoints[0..endpoints.len], endpoints);
        return sequencers;
    }

    pub fn current(sequencers: *const Sequencers) Endpoint {
        assert(sequencers.leader < sequencers.count);
        return sequencers.endpoints[sequencers.leader];
    }

    /// Asks every endpoint whether it is the active sequencer and makes the first active
    /// one the leader. A single endpoint is always the leader and is not polled.
    pub fn refresh(sequencers: *Sequencers) Refresh {
        if (sequencers.count == 1) return .{ .active_count = 1, .leader_changed = false };
        var active_count: u8 = 0;
        var first_active: ?u8 = null;
        for (sequencers.endpoints[0..sequencers.count], 0..) |endpoint, index| {
            if (!is_active(endpoint.rollup)) continue;
            active_count += 1;
            if (first_active == null) first_active = @intCast(index);
        }
        const leader = first_active orelse
            return .{ .active_count = 0, .leader_changed = false };
        const changed = leader != sequencers.leader;
        sequencers.leader = leader;
        assert(active_count > 0 and sequencers.leader < sequencers.count);
        return .{ .active_count = active_count, .leader_changed = changed };
    }
};

fn is_active(rollup: *rpc.Client) bool {
    const result = rollup.call("admin_sequencerActive", "[]") catch return false;
    return result == .bool and result.bool;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// A rollup node answering `admin_sequencerActive` with `active`, or failing.
const FakeNode = struct {
    active: bool = false,
    down: bool = false,
    calls: u32 = 0,

    fn transport(node: *FakeNode) rpc.Transport {
        return .{ .context = node, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const node: *FakeNode = @ptrCast(@alignCast(context));
        node.calls += 1;
        if (node.down) return error.TransportFailed;
        assert(std.mem.indexOf(u8, body, "admin_sequencerActive") != null);
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, node.active }) catch
            return error.ResponseTooLarge;
        return text.len;
    }
};

const Fixture = struct {
    nodes: [sequencers_max]FakeNode = @splat(.{}),
    clients: [sequencers_max]rpc.Client = undefined,
    count: u8,

    fn init(fixture: *Fixture) !Sequencers {
        var endpoints: [sequencers_max]Endpoint = undefined;
        for (0..fixture.count) |index| {
            fixture.clients[index] = try rpc.Client.init(
                testing.allocator,
                fixture.nodes[index].transport(),
                .{},
            );
            const client = &fixture.clients[index];
            endpoints[index] = .{ .l2 = client, .rollup = client };
        }
        return Sequencers.init(endpoints[0..fixture.count]);
    }

    fn deinit(fixture: *Fixture) void {
        for (fixture.clients[0..fixture.count]) |*client| client.deinit(testing.allocator);
    }
};

fn expect_refresh(active_count: u8, leader_changed: bool, actual: Refresh) !void {
    try testing.expectEqual(active_count, actual.active_count);
    try testing.expectEqual(leader_changed, actual.leader_changed);
}

test "sequencers: the first active endpoint leads; none active keeps the leader" {
    var fixture: Fixture = .{ .count = 3 };
    var sequencers = try fixture.init();
    defer fixture.deinit();
    fixture.nodes[2].active = true;
    try expect_refresh(1, true, sequencers.refresh());
    try testing.expectEqual(&fixture.clients[2], sequencers.current().l2);
    fixture.nodes[2].down = true; // Failover in progress: nobody is active.
    try expect_refresh(0, false, sequencers.refresh());
    try testing.expectEqual(@as(u8, 2), sequencers.leader);
    fixture.nodes[0].active = true;
    fixture.nodes[1].active = true;
    try expect_refresh(2, true, sequencers.refresh());
    try testing.expectEqual(@as(u8, 0), sequencers.leader);
}

test "sequencers: a single endpoint is never polled" {
    var fixture: Fixture = .{ .count = 1 };
    var sequencers = try fixture.init();
    defer fixture.deinit();
    _ = sequencers.refresh();
    try testing.expectEqual(@as(u32, 0), fixture.nodes[0].calls);
    try testing.expectEqual(@as(u8, 0), sequencers.leader);
}

test "sequencers: seeded fuzz matches a reference leader rule" {
    var prng = Prng.init(0x5e9);
    var fixture: Fixture = .{ .count = sequencers_max };
    var sequencers = try fixture.init();
    defer fixture.deinit();
    for (0..500) |_| {
        sequencers.count = @intCast(prng.range(2, sequencers_max));
        sequencers.leader = @intCast(prng.below(sequencers.count));
        var expected_leader = sequencers.leader;
        var expected_active: u8 = 0;
        var index: u8 = sequencers.count;
        while (index > 0) {
            index -= 1;
            const node = &fixture.nodes[index];
            node.active = prng.chance(1, 3);
            node.down = prng.chance(1, 5);
            if (node.active and !node.down) {
                expected_active += 1;
                expected_leader = index;
            }
        }
        const before = sequencers.leader;
        const result = sequencers.refresh();
        try testing.expectEqual(expected_active, result.active_count);
        try testing.expectEqual(expected_leader, sequencers.leader);
        try testing.expectEqual(before != expected_leader, result.leader_changed);
    }
}

test "sequencers: fuzz activity patterns" {
    try testing.fuzz({}, fuzz_refresh, .{});
}

fn fuzz_refresh(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    const length = smith.slice(&bytes);
    var fixture: Fixture = .{ .count = sequencers_max };
    var sequencers = try fixture.init();
    defer fixture.deinit();
    for (bytes[0..length]) |byte| {
        const node = &fixture.nodes[byte % sequencers_max];
        node.active = byte & 0x10 != 0;
        node.down = byte & 0x20 != 0;
        const result = sequencers.refresh();
        try testing.expect(sequencers.leader < sequencers.count);
        if (result.active_count > 0) {
            const leader = &fixture.nodes[sequencers.leader];
            try testing.expect(leader.active and !leader.down);
        }
    }
}

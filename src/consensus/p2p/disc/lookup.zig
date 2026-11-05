//! Iterative Kademlia lookup state (discv5 `FINDNODE` lookups). Keeps the
//! `candidates_max` closest known nodes to a target, sorted by XOR distance, and hands
//! out the closest unasked candidate while fewer than `parallelism` queries are in
//! flight. The lookup ends when every candidate has answered or failed, or after
//! `queries_max` queries.

const std = @import("std");
const assert = std.debug.assert;
const enr = @import("../peers/enr.zig");
const table = @import("table.zig");

pub const candidates_max = 16;
pub const parallelism = 3;
pub const queries_max = 3 * candidates_max;

pub const State = enum(u8) { fresh, asking, responded, failed };

pub const Candidate = struct {
    record: enr.Record,
    node_id: enr.NodeId,
    distance: u256,
    state: State,
};

pub const Lookup = struct {
    target: enr.NodeId = @splat(0),
    candidates: [candidates_max]Candidate = undefined,
    count: u8 = 0,
    queries: u16 = 0,
    active: bool = false,

    pub fn start(lookup: *Lookup, target: enr.NodeId) void {
        assert(!lookup.active);
        lookup.* = .{ .target = target, .active = true };
        assert(lookup.count == 0);
    }

    fn distance_to(lookup: *const Lookup, node_id: enr.NodeId) u256 {
        return std.mem.readInt(u256, &node_id, .big) ^ std.mem.readInt(u256, &lookup.target, .big);
    }

    /// Adds a record if it is new and among the closest seen. Returns true if added.
    pub fn add(lookup: *Lookup, record: *const enr.Record) bool {
        assert(lookup.active);
        const node_id = record.node_id();
        for (lookup.candidates[0..lookup.count]) |*candidate| {
            if (std.mem.eql(u8, &candidate.node_id, &node_id)) return false;
        }
        const distance = lookup.distance_to(node_id);
        var position: usize = lookup.count;
        while (position > 0 and lookup.candidates[position - 1].distance > distance) position -= 1;
        if (position == candidates_max) return false;
        const new_count = @min(lookup.count + 1, candidates_max);
        // Never drop an in-flight candidate off the end: its response is still expected.
        if (new_count == lookup.count and lookup.candidates[new_count - 1].state == .asking) {
            return false;
        }
        var index: usize = new_count - 1;
        while (index > position) : (index -= 1) {
            lookup.candidates[index] = lookup.candidates[index - 1];
        }
        lookup.candidates[position] = .{
            .record = record.*,
            .node_id = node_id,
            .distance = distance,
            .state = .fresh,
        };
        lookup.count = @intCast(new_count);
        assert(lookup.count <= candidates_max);
        return true;
    }

    fn in_flight(lookup: *const Lookup) u32 {
        var total: u32 = 0;
        for (lookup.candidates[0..lookup.count]) |*candidate| {
            if (candidate.state == .asking) total += 1;
        }
        return total;
    }

    /// The next candidate to query (marked `asking`), or null.
    pub fn next(lookup: *Lookup) ?*Candidate {
        if (!lookup.active) return null;
        if (lookup.queries >= queries_max) return null;
        if (lookup.in_flight() >= parallelism) return null;
        for (lookup.candidates[0..lookup.count]) |*candidate| {
            if (candidate.state != .fresh) continue;
            candidate.state = .asking;
            lookup.queries += 1;
            return candidate;
        }
        return null;
    }

    fn find(lookup: *Lookup, node_id: enr.NodeId) ?*Candidate {
        for (lookup.candidates[0..lookup.count]) |*candidate| {
            if (std.mem.eql(u8, &candidate.node_id, &node_id)) return candidate;
        }
        return null;
    }

    pub fn on_response(lookup: *Lookup, node_id: enr.NodeId) void {
        const candidate = lookup.find(node_id) orelse return;
        if (candidate.state == .asking) candidate.state = .responded;
    }

    pub fn on_failure(lookup: *Lookup, node_id: enr.NodeId) void {
        const candidate = lookup.find(node_id) orelse return;
        if (candidate.state == .asking) candidate.state = .failed;
    }

    /// True once no query is in flight and none can be started.
    pub fn finished(lookup: *const Lookup) bool {
        if (!lookup.active) return true;
        if (lookup.in_flight() > 0) return false;
        if (lookup.queries >= queries_max) return true;
        for (lookup.candidates[0..lookup.count]) |*candidate| {
            if (candidate.state == .fresh) return false;
        }
        return true;
    }

    /// FINDNODE distances to ask `node_id` for: the log distance of the target from the
    /// node and its two neighbours (like geth's `lookupDistances`).
    pub fn distances_for(lookup: *const Lookup, node_id: enr.NodeId, output: *[3]u16) []const u16 {
        const center = table.log_distance(lookup.target, node_id);
        var count: usize = 0;
        output[count] = @max(center, 1);
        count += 1;
        if (center + 1 <= 256 and center >= 1) {
            output[count] = center + 1;
            count += 1;
        }
        if (center > 1) {
            output[count] = center - 1;
            count += 1;
        }
        assert(count >= 1 and count <= 3);
        return output[0..count];
    }
};

const secp256k1 = @import("../peers/secp256k1.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "lookup: keeps closest sorted, respects parallelism, finishes" {
    var prng = Prng.init(0x6c6f_6f6b);
    var lookup: Lookup = .{};
    var target: enr.NodeId = undefined;
    prng.fill(&target);
    lookup.start(target);
    var added: u32 = 0;
    for (0..24) |_| {
        var secret: secp256k1.SecretKey = undefined;
        prng.fill(&secret);
        const record = enr.build(secret, .{}) catch continue;
        if (lookup.add(&record)) added += 1;
        try std.testing.expect(!lookup.add(&record));
    }
    try std.testing.expect(added >= candidates_max);
    try std.testing.expectEqual(@as(u8, candidates_max), lookup.count);
    for (lookup.candidates[1..lookup.count], 0..) |candidate, index| {
        try std.testing.expect(lookup.candidates[index].distance <= candidate.distance);
    }
    var asked: [parallelism]enr.NodeId = undefined;
    for (&asked) |*slot| slot.* = lookup.next().?.node_id;
    try std.testing.expect(lookup.next() == null);
    try std.testing.expect(!lookup.finished());
    lookup.on_response(asked[0]);
    lookup.on_failure(asked[1]);
    lookup.on_response(asked[2]);
    var rounds: u32 = 0;
    while (lookup.next()) |candidate| : (rounds += 1) lookup.on_response(candidate.node_id);
    try std.testing.expect(lookup.finished());
    try std.testing.expectEqual(@as(u32, candidates_max - parallelism), rounds);
}

test "lookup: distances" {
    var lookup: Lookup = .{};
    lookup.start(@splat(0));
    var output: [3]u16 = undefined;
    var far: enr.NodeId = @splat(0);
    far[0] = 0x80;
    try std.testing.expectEqualSlices(u16, &.{ 256, 255 }, lookup.distances_for(far, &output));
    var near: enr.NodeId = @splat(0);
    near[31] = 1;
    try std.testing.expectEqualSlices(u16, &.{ 1, 2 }, lookup.distances_for(near, &output));
    try std.testing.expectEqualSlices(u16, &.{1}, lookup.distances_for(@splat(0), &output));
}

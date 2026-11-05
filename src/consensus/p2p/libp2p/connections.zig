//! Connection limits (base/base `gossip/src/config.rs` `ConnectionLimitsConfig`, applied
//! through libp2p `connection_limits`): bounded pending inbound/outbound handshakes,
//! established connections in total and per direction, and per peer. Pure bookkeeping:
//! the transport asks before accepting or dialing and reports transitions.
//!
//! Protected peers bypass the pending-outbound and established limits (base/base
//! `connection_limits.bypass_peer_id` on `opp2p_protectPeer`), up to `bypass_max` extra
//! connections; the per-peer limit still applies.

const std = @import("std");
const assert = std.debug.assert;
const peer_id = @import("../peers/peer_id.zig");

pub const Limits = struct {
    pending_inbound_max: u32 = 5,
    pending_outbound_max: u32 = 16,
    established_max: u32 = 30,
    established_inbound_max: u32 = 30,
    established_outbound_max: u32 = 30,
    established_per_peer_max: u32 = 1,
    /// Connections allowed beyond `established_max` for protected peers.
    bypass_max: u32 = 8,
};

pub const Direction = enum { inbound, outbound };

pub const Error = error{
    PendingInboundLimit,
    PendingOutboundLimit,
    EstablishedLimit,
    EstablishedInboundLimit,
    EstablishedOutboundLimit,
    PerPeerLimit,
};

const Connection = struct { peer: peer_id.PeerId, direction: Direction };

pub const Manager = struct {
    limits: Limits,
    pending_inbound: u32 = 0,
    pending_outbound: u32 = 0,
    established: []Connection,
    established_count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Manager {
        assert(limits.established_max > 0 and limits.established_per_peer_max > 0);
        assert(limits.established_inbound_max <= limits.established_max);
        const capacity = limits.established_max + limits.bypass_max;
        const established = try allocator.alloc(Connection, capacity);
        return .{ .limits = limits, .established = established };
    }

    pub fn deinit(manager: *Manager, allocator: std.mem.Allocator) void {
        allocator.free(manager.established);
        manager.* = undefined;
    }

    /// Reserves a pending slot before a handshake starts.
    pub fn begin(manager: *Manager, direction: Direction) Error!void {
        return manager.begin_bypass(direction, false);
    }

    /// `begin`, but a protected peer's outbound dial skips the pending limit.
    pub fn begin_bypass(manager: *Manager, direction: Direction, bypass: bool) Error!void {
        switch (direction) {
            .inbound => {
                if (manager.pending_inbound == manager.limits.pending_inbound_max) {
                    return error.PendingInboundLimit;
                }
                manager.pending_inbound += 1;
            },
            .outbound => {
                const full = manager.pending_outbound >= manager.limits.pending_outbound_max;
                if (full and !bypass) return error.PendingOutboundLimit;
                manager.pending_outbound += 1;
            },
        }
    }

    /// Releases a pending slot after a failed handshake.
    pub fn abort(manager: *Manager, direction: Direction) void {
        switch (direction) {
            .inbound => {
                assert(manager.pending_inbound > 0);
                manager.pending_inbound -= 1;
            },
            .outbound => {
                assert(manager.pending_outbound > 0);
                manager.pending_outbound -= 1;
            },
        }
    }

    /// Converts a pending slot into an established connection with `peer`. On error the
    /// pending slot is released and the caller closes the connection.
    pub fn establish(manager: *Manager, peer: peer_id.PeerId, direction: Direction) Error!void {
        return manager.establish_bypass(peer, direction, false);
    }

    /// `establish`; with `bypass` (a protected peer) only the per-peer limit and the
    /// `bypass_max` headroom apply.
    pub fn establish_bypass(
        manager: *Manager,
        peer: peer_id.PeerId,
        direction: Direction,
        bypass: bool,
    ) Error!void {
        manager.abort(direction);
        if (manager.established_count == manager.established.len) return error.EstablishedLimit;
        if (manager.count_peer(&peer) >= manager.limits.established_per_peer_max) {
            return error.PerPeerLimit;
        }
        if (!bypass) try manager.check_regular(direction);
        manager.established[manager.established_count] = .{ .peer = peer, .direction = direction };
        manager.established_count += 1;
        assert(manager.established_count <= manager.established.len);
    }

    fn check_regular(manager: *const Manager, direction: Direction) Error!void {
        if (manager.established_count >= manager.limits.established_max) {
            return error.EstablishedLimit;
        }
        const in_direction = manager.count_direction(direction);
        switch (direction) {
            .inbound => if (in_direction >= manager.limits.established_inbound_max) {
                return error.EstablishedInboundLimit;
            },
            .outbound => if (in_direction >= manager.limits.established_outbound_max) {
                return error.EstablishedOutboundLimit;
            },
        }
    }

    pub fn close(manager: *Manager, peer: peer_id.PeerId, direction: Direction) void {
        for (manager.established[0..manager.established_count], 0..) |*connection, index| {
            if (connection.direction != direction or !connection.peer.eql(&peer)) continue;
            manager.established_count -= 1;
            manager.established[index] = manager.established[manager.established_count];
            return;
        }
        unreachable; // Closing a connection that was never established is a caller bug.
    }

    fn count_direction(manager: *const Manager, direction: Direction) u32 {
        var count: u32 = 0;
        for (manager.established[0..manager.established_count]) |connection| {
            count += @intFromBool(connection.direction == direction);
        }
        return count;
    }

    pub fn count_peer(manager: *const Manager, peer: *const peer_id.PeerId) u32 {
        var count: u32 = 0;
        for (manager.established[0..manager.established_count]) |*connection| {
            count += @intFromBool(connection.peer.eql(peer));
        }
        return count;
    }
};

fn test_peer(index: u8) peer_id.PeerId {
    var bytes: [34]u8 = undefined;
    bytes[0] = 0x12;
    bytes[1] = 32;
    @memset(bytes[2..], index);
    return peer_id.from_bytes(&bytes) catch unreachable;
}

test "connections: pending, established, and per-peer limits" {
    var manager = try Manager.init(std.testing.allocator, .{
        .pending_inbound_max = 2,
        .established_max = 3,
        .established_inbound_max = 2,
    });
    defer manager.deinit(std.testing.allocator);
    try manager.begin(.inbound);
    try manager.begin(.inbound);
    try std.testing.expectError(error.PendingInboundLimit, manager.begin(.inbound));
    try manager.establish(test_peer(1), .inbound);
    try std.testing.expectError(error.PerPeerLimit, manager.establish(test_peer(1), .inbound));
    try std.testing.expectEqual(@as(u32, 0), manager.pending_inbound);
    try manager.begin(.inbound);
    try manager.establish(test_peer(2), .inbound);
    try manager.begin(.inbound);
    const third = manager.establish(test_peer(3), .inbound);
    try std.testing.expectError(error.EstablishedInboundLimit, third);
    try manager.begin(.outbound);
    try manager.establish(test_peer(3), .outbound);
    try manager.begin(.outbound);
    try std.testing.expectError(error.EstablishedLimit, manager.establish(test_peer(4), .outbound));
    manager.close(test_peer(1), .inbound);
    try std.testing.expectEqual(@as(u32, 0), manager.count_peer(&test_peer(1)));
    try manager.begin(.outbound);
    try manager.establish(test_peer(4), .outbound);
}

test "connections: protected peers bypass the established limits" {
    var manager = try Manager.init(std.testing.allocator, .{
        .pending_outbound_max = 1,
        .established_max = 1,
        .established_inbound_max = 1,
        .established_outbound_max = 1,
        .bypass_max = 1,
    });
    defer manager.deinit(std.testing.allocator);
    try manager.begin(.outbound);
    try std.testing.expectError(error.PendingOutboundLimit, manager.begin(.outbound));
    try manager.begin_bypass(.outbound, true);
    try manager.establish(test_peer(1), .outbound);
    try std.testing.expectError(error.EstablishedLimit, manager.establish(test_peer(2), .outbound));
    try manager.begin_bypass(.outbound, true);
    try manager.establish_bypass(test_peer(3), .outbound, true);
    // Headroom is exhausted, and the per-peer limit still holds.
    try manager.begin(.inbound);
    const fourth = manager.establish_bypass(test_peer(4), .inbound, true);
    try std.testing.expectError(error.EstablishedLimit, fourth);
    manager.close(test_peer(3), .outbound);
    try manager.begin(.inbound);
    const again = manager.establish_bypass(test_peer(1), .inbound, true);
    try std.testing.expectError(error.PerPeerLimit, again);
    try std.testing.expectEqual(@as(u32, 0), manager.pending_outbound + manager.pending_inbound);
}

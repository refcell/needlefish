//! Connection gater (base/base `gossip/src/gater.rs` + `gate.rs`): decides whether to
//! dial or accept a peer. Tracks blocked peers, IPs, and subnets; protected peers; dials
//! in progress; and per-address redial counts within a dial period. Every set is a fixed
//! capacity array sized at init; a full set rejects the insert and reports it.
//!
//! DNS multiaddrs are resolved by the caller (resolution is IO). Outbound dials to an
//! unresolved DNS address are allowed and inbound ones rejected, like base/base's
//! `DnsResolutionFailure::{Allow, Reject}`.

const std = @import("std");
const assert = std.debug.assert;
const ip = @import("ip.zig");
const multiaddr = @import("multiaddr.zig");
const peer_id = @import("peer_id.zig");

const ns_per_s = std.time.ns_per_s;

pub const Config = struct {
    /// Dials allowed per address within `dial_period_ns`. Null: one dial (base/base
    /// default `peer_redialing: None` blocks any redial); 0: unlimited.
    peer_redialing: ?u32 = null,
    dial_period_ns: u64 = 3600 * ns_per_s,
    pending_dial_timeout_ns: u64 = 30 * ns_per_s,
    blocked_peers_max: u32 = 256,
    blocked_addresses_max: u32 = 256,
    blocked_subnets_max: u32 = 64,
    protected_peers_max: u32 = 64,
    pending_dials_max: u32 = 128,
    dialed_addresses_max: u32 = 1024,
};

pub const Error = error{
    InvalidMultiaddr,
    InvalidIpAddress,
    AlreadyDialing,
    ThresholdReached,
    PeerBlocked,
    AddressBlocked,
    SubnetBlocked,
};

pub const Subnet = struct {
    address: ip.Address,
    prefix_bits: u8,

    pub fn contains(subnet: Subnet, address: ip.Address) bool {
        return switch (subnet.address) {
            .ip4 => |base| switch (address) {
                .ip4 => |value| prefix_eql(&base, &value, subnet.prefix_bits),
                .ip6 => false,
            },
            .ip6 => |base| switch (address) {
                .ip6 => |value| prefix_eql(&base, &value, subnet.prefix_bits),
                .ip4 => false,
            },
        };
    }
};

fn prefix_eql(a: []const u8, b: []const u8, prefix_bits: u8) bool {
    assert(a.len == b.len);
    assert(prefix_bits <= a.len * 8);
    const full = prefix_bits / 8;
    if (!std.mem.eql(u8, a[0..full], b[0..full])) return false;
    const rest: u3 = @intCast(prefix_bits % 8);
    if (rest == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rest));
    return a[full] & mask == b[full] & mask;
}

/// Fixed-capacity set of values compared with `std.meta.eql`.
fn Set(comptime T: type) type {
    return struct {
        const Self = @This();
        items: []T,
        count: u32 = 0,

        fn index_of(set: *const Self, value: T) ?u32 {
            for (set.items[0..set.count], 0..) |item, index| {
                if (std.meta.eql(item, value)) return @intCast(index);
            }
            return null;
        }

        pub fn contains(set: *const Self, value: T) bool {
            return set.index_of(value) != null;
        }

        /// False when the set is full.
        pub fn insert(set: *Self, value: T) bool {
            if (set.contains(value)) return true;
            if (set.count == set.items.len) return false;
            set.items[set.count] = value;
            set.count += 1;
            return true;
        }

        pub fn remove(set: *Self, value: T) void {
            const index = set.index_of(value) orelse return;
            set.count -= 1;
            set.items[index] = set.items[set.count];
        }

        pub fn slice(set: *const Self) []const T {
            return set.items[0..set.count];
        }
    };
}

const PendingDial = struct { peer: peer_id.PeerId, started_ns: u64 };
const DialInfo = struct { address: multiaddr.Multiaddr, dials: u32, last_dial_ns: u64 };

pub const Gater = struct {
    config: Config,
    blocked_peers: Set(peer_id.PeerId),
    blocked_addresses: Set(ip.Address),
    blocked_subnets: Set(Subnet),
    protected_peers: Set(peer_id.PeerId),
    pending: []PendingDial,
    pending_count: u32 = 0,
    dialed: []DialInfo,
    dialed_count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Gater {
        assert(config.pending_dials_max > 0 and config.dialed_addresses_max > 0);
        var gater: Gater = .{
            .config = config,
            .blocked_peers = .{ .items = &.{} },
            .blocked_addresses = .{ .items = &.{} },
            .blocked_subnets = .{ .items = &.{} },
            .protected_peers = .{ .items = &.{} },
            .pending = &.{},
            .dialed = &.{},
        };
        errdefer gater.deinit(allocator);
        const PeerId = peer_id.PeerId;
        gater.blocked_peers.items = try allocator.alloc(PeerId, config.blocked_peers_max);
        const addresses_max = config.blocked_addresses_max;
        gater.blocked_addresses.items = try allocator.alloc(ip.Address, addresses_max);
        gater.blocked_subnets.items = try allocator.alloc(Subnet, config.blocked_subnets_max);
        gater.protected_peers.items = try allocator.alloc(PeerId, config.protected_peers_max);
        gater.pending = try allocator.alloc(PendingDial, config.pending_dials_max);
        gater.dialed = try allocator.alloc(DialInfo, config.dialed_addresses_max);
        return gater;
    }

    pub fn deinit(gater: *Gater, allocator: std.mem.Allocator) void {
        allocator.free(gater.dialed);
        allocator.free(gater.pending);
        allocator.free(gater.protected_peers.items);
        allocator.free(gater.blocked_subnets.items);
        allocator.free(gater.blocked_addresses.items);
        allocator.free(gater.blocked_peers.items);
        gater.* = undefined;
    }

    pub fn block_peer(gater: *Gater, peer: peer_id.PeerId) bool {
        return gater.blocked_peers.insert(peer);
    }
    pub fn unblock_peer(gater: *Gater, peer: peer_id.PeerId) void {
        gater.blocked_peers.remove(peer);
    }
    pub fn block_address(gater: *Gater, address: ip.Address) bool {
        return gater.blocked_addresses.insert(address);
    }
    pub fn unblock_address(gater: *Gater, address: ip.Address) void {
        gater.blocked_addresses.remove(address);
    }
    pub fn block_subnet(gater: *Gater, subnet: Subnet) bool {
        return gater.blocked_subnets.insert(subnet);
    }
    pub fn unblock_subnet(gater: *Gater, subnet: Subnet) void {
        gater.blocked_subnets.remove(subnet);
    }
    pub fn protect_peer(gater: *Gater, peer: peer_id.PeerId) bool {
        return gater.protected_peers.insert(peer);
    }
    pub fn unprotect_peer(gater: *Gater, peer: peer_id.PeerId) void {
        gater.protected_peers.remove(peer);
    }

    fn find_dialed(gater: *Gater, address: *const multiaddr.Multiaddr) ?*DialInfo {
        for (gater.dialed[0..gater.dialed_count]) |*info| {
            if (info.address.eql(address)) return info;
        }
        return null;
    }

    /// True while a dial to `peer` is pending.
    pub fn is_dialing(gater: *const Gater, peer: peer_id.PeerId) bool {
        return gater.find_pending(&peer) != null;
    }

    fn find_pending(gater: *const Gater, peer: *const peer_id.PeerId) ?u32 {
        for (gater.pending[0..gater.pending_count], 0..) |*dial, index| {
            if (dial.peer.eql(peer)) return @intCast(index);
        }
        return null;
    }

    fn dial_blocked_by_threshold(
        gater: *Gater,
        address: *const multiaddr.Multiaddr,
        now_ns: u64,
    ) bool {
        const info = gater.find_dialed(address) orelse return false;
        if (now_ns - info.last_dial_ns > gater.config.dial_period_ns) return false;
        const redialing = gater.config.peer_redialing orelse return true;
        if (redialing == 0) return false;
        return info.dials >= redialing;
    }

    fn check_address(gater: *const Gater, address: ip.Address) Error!void {
        if (gater.blocked_addresses.contains(address)) return error.AddressBlocked;
        for (gater.blocked_subnets.slice()) |subnet| {
            if (subnet.contains(address)) return error.SubnetBlocked;
        }
    }

    pub fn can_connect_outbound(
        gater: *Gater,
        address: *const multiaddr.Multiaddr,
        now_ns: u64,
    ) Error!void {
        const peer = address.peer() orelse return error.InvalidMultiaddr;
        if (gater.find_pending(&peer) != null) return error.AlreadyDialing;
        const protected = gater.protected_peers.contains(peer);
        if (!protected and gater.dial_blocked_by_threshold(address, now_ns)) {
            return error.ThresholdReached;
        }
        if (gater.blocked_peers.contains(peer)) return error.PeerBlocked;
        // Unresolved DNS addresses are allowed outbound (base/base `Allow`).
        const host = ip_of(address) orelse return;
        try gater.check_address(host);
    }

    pub fn can_connect_inbound(
        gater: *const Gater,
        peer: peer_id.PeerId,
        address: ip.Address,
    ) Error!void {
        if (gater.blocked_peers.contains(peer)) return error.PeerBlocked;
        try gater.check_address(address);
    }

    /// A dial to `address` started. Returns false if the pending table is full.
    pub fn dialing(gater: *Gater, address: *const multiaddr.Multiaddr, now_ns: u64) bool {
        const peer = address.peer() orelse return false;
        if (gater.find_pending(&peer) != null) return true;
        if (gater.pending_count == gater.pending.len) return false;
        gater.pending[gater.pending_count] = .{ .peer = peer, .started_ns = now_ns };
        gater.pending_count += 1;
        return true;
    }

    /// A dial to `address` completed (successfully or not): count it.
    pub fn dialed_address(gater: *Gater, address: *const multiaddr.Multiaddr, now_ns: u64) void {
        const info = gater.find_dialed(address) orelse blk: {
            if (gater.dialed_count == gater.dialed.len) gater.evict_oldest_dialed();
            gater.dialed[gater.dialed_count] = .{
                .address = address.*,
                .dials = 0,
                .last_dial_ns = now_ns,
            };
            gater.dialed_count += 1;
            break :blk &gater.dialed[gater.dialed_count - 1];
        };
        if (now_ns - info.last_dial_ns > gater.config.dial_period_ns) info.dials = 0;
        info.dials += 1;
        info.last_dial_ns = now_ns;
        assert(gater.dialed_count <= gater.dialed.len);
    }

    fn evict_oldest_dialed(gater: *Gater) void {
        assert(gater.dialed_count > 0);
        var oldest: u32 = 0;
        for (gater.dialed[0..gater.dialed_count], 0..) |info, index| {
            if (info.last_dial_ns < gater.dialed[oldest].last_dial_ns) oldest = @intCast(index);
        }
        gater.dialed_count -= 1;
        gater.dialed[oldest] = gater.dialed[gater.dialed_count];
    }

    pub fn remove_dial(gater: *Gater, peer: peer_id.PeerId) void {
        const index = gater.find_pending(&peer) orelse return;
        gater.pending_count -= 1;
        gater.pending[index] = gater.pending[gater.pending_count];
    }

    /// Writes peers whose dial has been pending longer than the timeout.
    pub fn expired_dials(
        gater: *const Gater,
        now_ns: u64,
        output: []peer_id.PeerId,
    ) []peer_id.PeerId {
        var count: usize = 0;
        for (gater.pending[0..gater.pending_count]) |dial| {
            if (count == output.len) break;
            if (now_ns - dial.started_ns <= gater.config.pending_dial_timeout_ns) continue;
            output[count] = dial.peer;
            count += 1;
        }
        return output[0..count];
    }

    pub fn can_disconnect(gater: *const Gater, peer: peer_id.PeerId) bool {
        return !gater.protected_peers.contains(peer);
    }

    /// Drops dial records older than the dial period.
    pub fn prune(gater: *Gater, now_ns: u64) void {
        var index: u32 = 0;
        while (index < gater.dialed_count) {
            if (now_ns - gater.dialed[index].last_dial_ns > gater.config.dial_period_ns) {
                gater.dialed_count -= 1;
                gater.dialed[index] = gater.dialed[gater.dialed_count];
            } else index += 1;
        }
    }
};

fn ip_of(address: *const multiaddr.Multiaddr) ?ip.Address {
    var components = address.iterator();
    while (components.next() catch return null) |component| switch (component) {
        .ip4 => |value| return .{ .ip4 = value },
        .ip6 => |value| return .{ .ip6 = value },
        else => {},
    };
    return null;
}

const secp256k1 = @import("secp256k1.zig");

fn test_address(text_buffer: []u8, host: []const u8, seed: u8) !multiaddr.Multiaddr {
    var secret: secp256k1.SecretKey = @splat(seed);
    secret[0] = 1;
    const peer = peer_id.from_public_key(try secp256k1.public_key(secret));
    var peer_text: [peer_id.text_length_max]u8 = undefined;
    const peer_string = peer.format(&peer_text);
    const text = try std.fmt.bufPrint(text_buffer, "{s}/tcp/9222/p2p/{s}", .{ host, peer_string });
    return multiaddr.parse(text);
}

test "gater: blocks peers, addresses, subnets" {
    var gater = try Gater.init(std.testing.allocator, .{ .peer_redialing = 0 });
    defer gater.deinit(std.testing.allocator);
    var buffer: [multiaddr.text_length_max]u8 = undefined;
    const address = try test_address(&buffer, "/ip4/10.1.2.3", 1);
    const peer = address.peer().?;
    try gater.can_connect_outbound(&address, 0);
    try std.testing.expect(gater.block_peer(peer));
    try std.testing.expectError(error.PeerBlocked, gater.can_connect_outbound(&address, 0));
    gater.unblock_peer(peer);
    const ten: Subnet = .{ .address = .{ .ip4 = .{ 10, 0, 0, 0 } }, .prefix_bits = 8 };
    try std.testing.expect(gater.block_subnet(ten));
    try std.testing.expectError(error.SubnetBlocked, gater.can_connect_outbound(&address, 0));
    const inside = gater.can_connect_inbound(peer, .{ .ip4 = .{ 10, 9, 9, 9 } });
    try std.testing.expectError(error.SubnetBlocked, inside);
    try gater.can_connect_inbound(peer, .{ .ip4 = .{ 11, 0, 0, 1 } });
    try std.testing.expect(gater.block_address(.{ .ip4 = .{ 11, 0, 0, 1 } }));
    const blocked = gater.can_connect_inbound(peer, .{ .ip4 = .{ 11, 0, 0, 1 } });
    try std.testing.expectError(error.AddressBlocked, blocked);
    const dns = try test_address(&buffer, "/dns4/example.org", 2);
    try gater.can_connect_outbound(&dns, 0);
}

test "gater: dial tracking, redial threshold, protection, expiry" {
    var gater = try Gater.init(std.testing.allocator, .{ .peer_redialing = 2 });
    defer gater.deinit(std.testing.allocator);
    var buffer: [multiaddr.text_length_max]u8 = undefined;
    const address = try test_address(&buffer, "/ip4/1.2.3.4", 3);
    const peer = address.peer().?;
    try std.testing.expect(gater.dialing(&address, 0));
    try std.testing.expectError(error.AlreadyDialing, gater.can_connect_outbound(&address, 0));
    var expired: [4]peer_id.PeerId = undefined;
    try std.testing.expectEqual(@as(usize, 0), gater.expired_dials(10 * ns_per_s, &expired).len);
    try std.testing.expectEqual(@as(usize, 1), gater.expired_dials(31 * ns_per_s, &expired).len);
    gater.remove_dial(peer);
    gater.dialed_address(&address, 1);
    try gater.can_connect_outbound(&address, 2);
    gater.dialed_address(&address, 3);
    try std.testing.expectError(error.ThresholdReached, gater.can_connect_outbound(&address, 4));
    try std.testing.expect(gater.protect_peer(peer));
    try gater.can_connect_outbound(&address, 4);
    try std.testing.expect(!gater.can_disconnect(peer));
    gater.unprotect_peer(peer);
    // After the dial period the counter resets.
    try gater.can_connect_outbound(&address, 3 + 3601 * ns_per_s);
    gater.prune(3 + 3601 * ns_per_s);
    try std.testing.expectEqual(@as(u32, 0), gater.dialed_count);
}

test "gater: default config refuses any redial within the period" {
    var gater = try Gater.init(std.testing.allocator, .{});
    defer gater.deinit(std.testing.allocator);
    var buffer: [multiaddr.text_length_max]u8 = undefined;
    const address = try test_address(&buffer, "/ip6/::1", 4);
    gater.dialed_address(&address, 0);
    try std.testing.expectError(error.ThresholdReached, gater.can_connect_outbound(&address, 1));
}

test "gater: subnet prefix matching" {
    const subnet: Subnet = .{ .address = .{ .ip4 = .{ 192, 168, 0, 0 } }, .prefix_bits = 20 };
    try std.testing.expect(subnet.contains(.{ .ip4 = .{ 192, 168, 15, 255 } }));
    try std.testing.expect(!subnet.contains(.{ .ip4 = .{ 192, 168, 16, 0 } }));
    try std.testing.expect(!subnet.contains(.{ .ip6 = @splat(0) }));
    const all: Subnet = .{ .address = .{ .ip6 = @splat(0) }, .prefix_bits = 0 };
    try std.testing.expect(all.contains(.{ .ip6 = @splat(0xff) }));
}

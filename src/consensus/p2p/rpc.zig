//! The `opp2p_*` admin JSON-RPC API (base/base `crates/consensus/rpc/src/p2p.rs`,
//! `gossip/src/rpc/{request,types}.rs`) over `p2p.Service`, for `utilities/rpc.Router`.
//!
//! JSON shapes and names follow base/base (camelCase, `peerID`, `nodeID`, `ENR`,
//! `chainID`, `bannedIPS`, `IPColocationFactor`; connectedness and direction as integers).
//! Peer agent, protocol version, protocols (up to 8), listen addresses (up to 4), and
//! latency come from identify and ping. `opp2p_self` reports what base/base reports (agent
//! `base`, inbound, its protocol list, the local TCP multiaddr). Fields this node does not
//! track are zero: per-topic score parts and req/resp scores.
//! Differences: `opp2p_blockPeer` also disconnects the peer (base/base blacklists it in
//! gossipsub, which drops all its messages), and `opp2p_protectPeer` does not lift
//! connection limits (only gater limits).

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const service_module = @import("service.zig");
const enr = @import("peers/enr.zig");
const ip = @import("peers/ip.zig");
const gater = @import("peers/gater.zig");
const multiaddr = @import("peers/multiaddr.zig");
const peer_id = @import("peers/peer_id.zig");
const router_module = @import("gossip/router.zig");

const Service = service_module.Service;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const methods = [_]rpc.Method(*Service){
    .{ .name = "opp2p_self", .handler = self_info },
    .{ .name = "opp2p_peerCount", .handler = peer_count },
    .{ .name = "opp2p_peers", .handler = peers },
    .{ .name = "opp2p_peerStats", .handler = peer_stats },
    .{ .name = "opp2p_discoveryTable", .handler = discovery_table },
    .{ .name = "opp2p_blockPeer", .handler = block_peer },
    .{ .name = "opp2p_unblockPeer", .handler = unblock_peer },
    .{ .name = "opp2p_listBlockedPeers", .handler = list_blocked_peers },
    .{ .name = "opp2p_blockAddr", .handler = block_addr },
    .{ .name = "opp2p_unblockAddr", .handler = unblock_addr },
    .{ .name = "opp2p_listBlockedAddrs", .handler = list_blocked_addrs },
    .{ .name = "opp2p_blockSubnet", .handler = block_subnet },
    .{ .name = "opp2p_unblockSubnet", .handler = unblock_subnet },
    .{ .name = "opp2p_listBlockedSubnets", .handler = list_blocked_subnets },
    .{ .name = "opp2p_protectPeer", .handler = protect_peer },
    .{ .name = "opp2p_unprotectPeer", .handler = unprotect_peer },
    .{ .name = "opp2p_connectPeer", .handler = connect_peer },
    .{ .name = "opp2p_disconnectPeer", .handler = disconnect_peer },
};

pub const Router = rpc.Router(*Service, &methods);

const connectedness_connected = 1;
const direction_inbound = 1;
const direction_outbound = 2;

// ------------------------------------------------------------------------ queries

fn self_info(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    const record = &service.discovery.local_record;
    const peer = peer_id.from_public_key(record.public_key);
    var info: service_module.PeerInfo = .{ .agent_version = .init("base") };
    for (self_protocols, 0..) |protocol, index| info.protocols[index] = .init(protocol);
    info.protocols_count = self_protocols.len;
    if (multiaddr.from_enr(record)) |address| {
        info.addresses[0] = address;
        info.addresses_count = 1;
    }
    try write_peer_info(service, call.writer, .{
        .peer = peer,
        .node_id = record.node_id(),
        .record = record,
        .info = &info,
        .direction = direction_inbound,
        .score = 0,
        .behaviour_penalty = 0,
    });
}

/// base/base's reported protocol list for `opp2p_self`.
const self_protocols = [_][]const u8{
    "/ipfs/id/push/1.0.0", "/meshsub/1.1.0", "/ipfs/ping/1.0.0", "/meshsub/1.2.0",
    "/ipfs/id/1.0.0",      "/meshsub/1.0.0", "/floodsub/1.0.0",
};

comptime {
    assert(self_protocols.len <= service_module.PeerInfo.protocols_max);
}

fn peer_count(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("connectedDiscovery");
    try writer.integer(service.discovery.table.live_count());
    try writer.key("connectedGossip");
    try writer.integer(service.connected_count());
    try writer.end_object();
}

/// `opp2p_peers(connected)`: this node only tracks connected peers, so both values list
/// the same set.
fn peers(service: *Service, call: *Call) HandlerError!void {
    _ = try call.params.boolean();
    try call.params.finish();
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("totalConnected");
    try writer.integer(service.connected_count());
    try writer.key("peers");
    try writer.begin_object();
    for (&service.connected, 0..) |*connection, slot| {
        if (!connection.active) continue;
        var text: [peer_id.text_length_max]u8 = undefined;
        try writer.key(connection.peer.format(&text));
        try write_connected_peer(service, writer, @intCast(slot));
    }
    try writer.end_object();
    try writer.key("bannedPeers");
    try write_peer_list(writer, service.gater.blocked_peers.slice());
    try writer.key("bannedIPS");
    try write_address_list(writer, service.gater.blocked_addresses.slice());
    try writer.key("bannedSubnets");
    try write_subnet_list(writer, service.gater.blocked_subnets.slice());
    try writer.end_object();
}

fn peer_stats(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    var per_topic: [4]u32 = @splat(0);
    for (&service.connected, 0..) |*connection, slot| {
        if (!connection.active) continue;
        const topics = service.gossip.router.peer(@intCast(slot)).topics;
        for (service.gossip.topics, &per_topic) |topic, *count| {
            count.* += @intFromBool(topics & (@as(u8, 1) << @intCast(topic)) != 0);
        }
    }
    const writer = call.writer;
    try writer.begin_object();
    try field_integer(writer, "connected", service.connected_count());
    try field_integer(writer, "table", service.discovery.table.live_count());
    const names = [_][]const u8{ "blocksTopic", "blocksTopicV2", "blocksTopicV3", "blocksTopicV4" };
    for (names, per_topic) |name, count| try field_integer(writer, name, count);
    try field_integer(writer, "banned", service.gater.blocked_peers.slice().len);
    try field_integer(writer, "known", service.gater.dialed_count);
    try field_integer(writer, "maxPeerCount", service.config.limits.established_max);
    try writer.end_object();
}

fn discovery_table(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    const writer = call.writer;
    try writer.begin_array();
    var entries: [32]*const @import("disc/table.zig").Entry = undefined;
    var distance: u16 = 1;
    while (distance <= 256) : (distance += 1) {
        const count = service.discovery.table.at_distance(distance, &entries);
        for (entries[0..count]) |entry| {
            var text: [enr.text_length_max]u8 = undefined;
            try writer.string(enr.encode_text(&text, &entry.record));
        }
    }
    try writer.end_array();
}

// ----------------------------------------------------------------------- commands

fn block_peer(service: *Service, call: *Call) HandlerError!void {
    const peer = try param_peer(call);
    if (!service.gater.block_peer(peer)) return call.fail(rpc.code.server_error, "list full");
    _ = service.disconnect_peer(&peer);
    try call.writer.null_value();
}

fn unblock_peer(service: *Service, call: *Call) HandlerError!void {
    service.gater.unblock_peer(try param_peer(call));
    try call.writer.null_value();
}

fn list_blocked_peers(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    try write_peer_list(call.writer, service.gater.blocked_peers.slice());
}

fn block_addr(service: *Service, call: *Call) HandlerError!void {
    const address = try param_address(call);
    if (!service.gater.block_address(address)) {
        return call.fail(rpc.code.server_error, "list full");
    }
    try call.writer.null_value();
}

fn unblock_addr(service: *Service, call: *Call) HandlerError!void {
    service.gater.unblock_address(try param_address(call));
    try call.writer.null_value();
}

fn list_blocked_addrs(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    try write_address_list(call.writer, service.gater.blocked_addresses.slice());
}

fn block_subnet(service: *Service, call: *Call) HandlerError!void {
    const subnet = try param_subnet(call);
    if (!service.gater.block_subnet(subnet)) return call.fail(rpc.code.server_error, "list full");
    try call.writer.null_value();
}

fn unblock_subnet(service: *Service, call: *Call) HandlerError!void {
    service.gater.unblock_subnet(try param_subnet(call));
    try call.writer.null_value();
}

fn list_blocked_subnets(service: *Service, call: *Call) HandlerError!void {
    try call.params.finish();
    try write_subnet_list(call.writer, service.gater.blocked_subnets.slice());
}

fn protect_peer(service: *Service, call: *Call) HandlerError!void {
    const peer = try param_peer(call);
    if (!service.gater.protect_peer(peer)) return call.fail(rpc.code.server_error, "list full");
    try call.writer.null_value();
}

fn unprotect_peer(service: *Service, call: *Call) HandlerError!void {
    service.gater.unprotect_peer(try param_peer(call));
    try call.writer.null_value();
}

/// Dials a multiaddr with a `/p2p/` peer id (base/base `dial_multiaddr`): the gater and
/// limits may still refuse it, silently, like base/base.
fn connect_peer(service: *Service, call: *Call) HandlerError!void {
    const text = try call.params.string();
    try call.params.finish();
    const address = multiaddr.parse(text) catch return error.InvalidParams;
    if (address.peer() == null) return error.InvalidParams;
    service.dial(&address, service.now_ns);
    try call.writer.null_value();
}

fn disconnect_peer(service: *Service, call: *Call) HandlerError!void {
    const peer = try param_peer(call);
    _ = service.disconnect_peer(&peer);
    try call.writer.null_value();
}

// ------------------------------------------------------------------------- params

fn param_peer(call: *Call) HandlerError!peer_id.PeerId {
    const text = try call.params.string();
    try call.params.finish();
    return peer_id.parse(text) catch error.InvalidParams;
}

fn param_address(call: *Call) HandlerError!ip.Address {
    const text = try call.params.string();
    try call.params.finish();
    return ip.parse(text) catch error.InvalidParams;
}

/// `a.b.c.d/n` or `x::/n` (CIDR).
fn param_subnet(call: *Call) HandlerError!gater.Subnet {
    const text = try call.params.string();
    try call.params.finish();
    return parse_subnet(text) catch error.InvalidParams;
}

pub fn parse_subnet(text: []const u8) error{Invalid}!gater.Subnet {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.Invalid;
    const address = ip.parse(text[0..slash]) catch return error.Invalid;
    const bits = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.Invalid;
    const bits_max: u8 = switch (address) {
        .ip4 => 32,
        .ip6 => 128,
    };
    if (bits > bits_max) return error.Invalid;
    return .{ .address = address, .prefix_bits = bits };
}

// ------------------------------------------------------------------------- output

const PeerInfo = struct {
    peer: peer_id.PeerId,
    node_id: enr.NodeId,
    record: ?*const enr.Record,
    info: *const service_module.PeerInfo,
    direction: u8,
    score: f64,
    behaviour_penalty: f64,
    protected: bool = false,
};

fn write_connected_peer(service: *Service, writer: *json.Writer, slot: router_module.Slot) !void {
    const connection = &service.connected[slot];
    assert(connection.active);
    const key = connection.peer.secp256k1_public_key();
    const counters = &service.gossip.router.peer(slot).counters;
    try write_peer_info(service, writer, .{
        .peer = connection.peer,
        .node_id = if (key) |value| enr.node_id_from_public_key(value) else @splat(0),
        .record = null,
        .info = &connection.info,
        .direction = switch (connection.direction) {
            .inbound => direction_inbound,
            .outbound => direction_outbound,
        },
        .score = service.gossip.router.peer_score_value(slot),
        .behaviour_penalty = counters.behaviour_penalty,
        .protected = service.gater.protected_peers.contains(connection.peer),
    });
}

fn write_peer_info(service: *Service, writer: *json.Writer, info: PeerInfo) !void {
    try writer.begin_object();
    var text: [peer_id.text_length_max]u8 = undefined;
    try writer.key("peerID");
    try writer.string(info.peer.format(&text));
    try writer.key("nodeID");
    var node_id_text: [2 + 64]u8 = undefined;
    node_id_text[0..2].* = "0x".*;
    node_id_text[2..].* = std.fmt.bytesToHex(info.node_id, .lower);
    try writer.string(&node_id_text);
    try field_string(writer, "userAgent", info.info.agent_version.slice());
    try field_string(writer, "protocolVersion", info.info.protocol_version.slice());
    if (info.record) |record| {
        var record_text: [enr.text_length_max]u8 = undefined;
        try field_string(writer, "ENR", enr.encode_text(&record_text, record));
    }
    try writer.key("addresses");
    try writer.begin_array();
    for (info.info.addresses[0..info.info.addresses_count]) |*address| {
        var address_text: [multiaddr.text_length_max]u8 = undefined;
        try writer.string(address.format(&address_text));
    }
    try writer.end_array();
    try writer.key("protocols");
    if (info.info.protocols_count == 0) {
        try writer.null_value();
    } else {
        try writer.begin_array();
        for (info.info.protocols[0..info.info.protocols_count]) |*protocol| {
            try writer.string(protocol.slice());
        }
        try writer.end_array();
    }
    try field_integer(writer, "connectedness", connectedness_connected);
    try field_integer(writer, "direction", info.direction);
    try writer.key("protected");
    try writer.boolean(info.protected);
    try field_integer(writer, "chainID", service.config.rollup.l2_chain_id);
    // Nanoseconds, like op-node's Go `time.Duration`; base/base always reports 0.
    try field_integer(writer, "latency", info.info.latency_ns);
    try writer.key("gossipBlocks");
    try writer.boolean(true);
    try writer.key("scores");
    try write_scores(writer, info.score, info.behaviour_penalty);
    try writer.end_object();
}

fn write_scores(writer: *json.Writer, total: f64, behaviour_penalty: f64) !void {
    try writer.begin_object();
    try writer.key("gossip");
    try writer.begin_object();
    try field_float(writer, "total", total);
    try writer.key("blocks");
    try writer.begin_object();
    const topic_fields = [_][]const u8{
        "timeInMesh",            "firstMessageDeliveries",
        "meshMessageDeliveries", "invalidMessageDeliveries",
    };
    for (topic_fields) |name| try field_float(writer, name, 0);
    try writer.end_object();
    try field_float(writer, "IPColocationFactor", 0);
    try field_float(writer, "behavioralPenalty", behaviour_penalty);
    try writer.end_object();
    try writer.key("reqResp");
    try writer.begin_object();
    for ([_][]const u8{ "validResponses", "errorResponses", "rejectedPayloads" }) |name| {
        try field_float(writer, name, 0);
    }
    try writer.end_object();
    try writer.end_object();
}

fn write_peer_list(writer: *json.Writer, list: []const peer_id.PeerId) !void {
    try writer.begin_array();
    for (list) |*peer| {
        var text: [peer_id.text_length_max]u8 = undefined;
        try writer.string(peer.format(&text));
    }
    try writer.end_array();
}

fn write_address_list(writer: *json.Writer, list: []const ip.Address) !void {
    try writer.begin_array();
    for (list) |address| {
        var text: [64]u8 = undefined;
        try writer.string(ip.format(&text, address));
    }
    try writer.end_array();
}

fn write_subnet_list(writer: *json.Writer, list: []const gater.Subnet) !void {
    try writer.begin_array();
    for (list) |subnet| {
        var address: [64]u8 = undefined;
        var text: [80]u8 = undefined;
        const formatted = std.fmt.bufPrint(&text, "{s}/{d}", .{
            ip.format(&address, subnet.address),
            subnet.prefix_bits,
        }) catch unreachable; // 64 + 4 bytes fit in 80.
        try writer.string(formatted);
    }
    try writer.end_array();
}

fn field_integer(writer: *json.Writer, name: []const u8, value: anytype) !void {
    try writer.key(name);
    try writer.integer(value);
}

fn field_string(writer: *json.Writer, name: []const u8, value: []const u8) !void {
    try writer.key(name);
    try writer.string(value);
}

fn field_float(writer: *json.Writer, name: []const u8, value: f64) !void {
    try writer.key(name);
    var text: [64]u8 = undefined;
    const finite = if (std.math.isFinite(value)) value else 0;
    try writer.raw(std.fmt.bufPrint(&text, "{d}", .{finite}) catch unreachable);
}

test {
    _ = @import("rpc_test.zig");
}

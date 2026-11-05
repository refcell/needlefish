//! discv5 node as an IO-free state machine (the role of base/base `disc/driver.rs` plus
//! the `discv5` crate it wraps). The host feeds it datagrams (`on_packet`) and time
//! (`tick`) and drains `pop_outgoing` (datagrams to send) and `pop_discovered` (verified
//! records advertising our chain id). All randomness comes from the injected
//! `std.Random`, so the deterministic simulator can drive many nodes reproducibly.
//!
//! Memory is allocated once in `init` from `Config` limits; nothing allocates afterwards.
//! Every queue is fixed-capacity; overflow drops (datagram semantics) and is counted.

const std = @import("std");
const assert = std.debug.assert;
const enr = @import("../peers/enr.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const messages = @import("messages.zig");
const table_module = @import("table.zig");
const session_module = @import("session.zig");
const lookup_module = @import("lookup.zig");

pub const Endpoint = table_module.Endpoint;
const ns_per_ms = std.time.ns_per_ms;

pub const Config = struct {
    chain_id: u64,
    /// Random-target lookup interval (base/base default: 5 s).
    lookup_interval_ns: u64 = 5000 * ns_per_ms,
    request_timeout_ns: u64 = 500 * ns_per_ms,
    handshake_timeout_ns: u64 = 1000 * ns_per_ms,
    sessions_max: u32 = 256,
    pending_max: u32 = 64,
    challenges_max: u32 = 64,
    outbox_max: u32 = 64,
    discovered_max: u32 = 64,
    /// Upper bound accepted for a NODES `total` field.
    nodes_responses_max: u8 = 8,
    /// Records returned per FINDNODE (spec recommendation: 16).
    findnode_results_max: u8 = 16,
    table: table_module.Config = .{},
};

pub const Stats = struct {
    packets_received: u64 = 0,
    packets_invalid: u64 = 0,
    outbox_dropped: u64 = 0,
    discovered_dropped: u64 = 0,
    handshakes_completed: u64 = 0,
    requests_timed_out: u64 = 0,
    records_rejected: u64 = 0,
};

pub const Datagram = struct {
    endpoint: Endpoint,
    length: u16,
    bytes: [packet.size_max]u8,

    pub fn slice(datagram: *const Datagram) []const u8 {
        assert(datagram.length <= packet.size_max);
        return datagram.bytes[0..datagram.length];
    }
};

const RequestKind = enum(u8) { ping, findnode };

const Pending = struct {
    used: bool,
    node_id: enr.NodeId,
    endpoint: Endpoint,
    public_key: secp256k1.PublicKey,
    request_id: messages.RequestId,
    nonce: packet.Nonce,
    deadline_ns: u64,
    kind: RequestKind,
    distances: [3]u16,
    distances_count: u8,
    nodes_total: u8,
    nodes_received: u8,
    handshake_sent: bool,
    plaintext_length: u16,
    plaintext: [messages.plaintext_length_max]u8,
};

const Challenge = struct {
    used: bool,
    node_id: enr.NodeId,
    endpoint: Endpoint,
    deadline_ns: u64,
    data: [crypto.challenge_length]u8,
};

fn Ring(comptime T: type) type {
    return struct {
        const Self = @This();
        items: []T,
        head: u32 = 0,
        count: u32 = 0,

        fn push(ring: *Self) ?*T {
            if (ring.count == ring.items.len) return null;
            const index = (ring.head + ring.count) % @as(u32, @intCast(ring.items.len));
            ring.count += 1;
            return &ring.items[index];
        }

        fn pop(ring: *Self) ?*const T {
            if (ring.count == 0) return null;
            const item = &ring.items[ring.head];
            ring.head = (ring.head + 1) % @as(u32, @intCast(ring.items.len));
            ring.count -= 1;
            return item;
        }
    };
}

pub const Service = struct {
    config: Config,
    random: std.Random,
    secret: secp256k1.SecretKey,
    local_record: enr.Record,
    local_id: enr.NodeId,
    table: table_module.Table,
    sessions: session_module.Cache,
    pending: []Pending,
    challenges: []Challenge,
    outbox: Ring(Datagram),
    discovered: Ring(enr.Record),
    lookup: lookup_module.Lookup = .{},
    next_lookup_ns: u64 = 0,
    stats: Stats = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        secret: secp256k1.SecretKey,
        local_record: enr.Record,
        random: std.Random,
    ) !Service {
        assert(config.pending_max > 0 and config.outbox_max > 0);
        assert(std.mem.eql(u8, &local_record.public_key, &(try secp256k1.public_key(secret))));
        const local_id = local_record.node_id();
        var table = try table_module.Table.init(allocator, local_id, config.table);
        errdefer table.deinit(allocator);
        var sessions = try session_module.Cache.init(allocator, config.sessions_max);
        errdefer sessions.deinit(allocator);
        const pending = try allocator.alloc(Pending, config.pending_max);
        errdefer allocator.free(pending);
        for (pending) |*slot| slot.used = false;
        const challenges = try allocator.alloc(Challenge, config.challenges_max);
        errdefer allocator.free(challenges);
        for (challenges) |*slot| slot.used = false;
        const outbox = try allocator.alloc(Datagram, config.outbox_max);
        errdefer allocator.free(outbox);
        const discovered = try allocator.alloc(enr.Record, config.discovered_max);
        return .{
            .config = config,
            .random = random,
            .secret = secret,
            .local_record = local_record,
            .local_id = local_id,
            .table = table,
            .sessions = sessions,
            .pending = pending,
            .challenges = challenges,
            .outbox = .{ .items = outbox },
            .discovered = .{ .items = discovered },
        };
    }

    pub fn deinit(service: *Service, allocator: std.mem.Allocator) void {
        allocator.free(service.discovered.items);
        allocator.free(service.outbox.items);
        allocator.free(service.challenges);
        allocator.free(service.pending);
        service.sessions.deinit(allocator);
        service.table.deinit(allocator);
        service.* = undefined;
    }

    pub fn pop_outgoing(service: *Service) ?*const Datagram {
        return service.outbox.pop();
    }

    pub fn pop_discovered(service: *Service) ?*const enr.Record {
        return service.discovered.pop();
    }

    /// Seeds the table with a boot record and pings it to start a session.
    pub fn add_boot_record(service: *Service, record: *const enr.Record, now_ns: u64) void {
        const endpoint = endpoint_of(record) orelse return;
        const result = service.table.insert(record, endpoint, now_ns);
        if (result == .added or result == .updated) {
            service.publish(record);
            service.send_ping(record.node_id(), endpoint, record.public_key, now_ns);
        }
    }

    /// The UDP endpoint a record advertises (IPv4 preferred).
    pub fn endpoint_of(record: *const enr.Record) ?Endpoint {
        if (record.ip4()) |address| {
            const port = record.udp() orelse return null;
            return .{ .address = .{ .ip4 = address }, .port = port };
        }
        if (record.ip6()) |address| {
            const port = record.udp6() orelse record.udp() orelse return null;
            return .{ .address = .{ .ip6 = address }, .port = port };
        }
        return null;
    }

    fn publish(service: *Service, record: *const enr.Record) void {
        if (enr.validate_chain(record, service.config.chain_id) != .valid) return;
        const slot = service.discovered.push() orelse {
            service.stats.discovered_dropped += 1;
            return;
        };
        slot.* = record.*;
    }

    // ---------------------------------------------------------------- time

    pub fn tick(service: *Service, now_ns: u64) void {
        service.expire_pending(now_ns);
        for (service.challenges) |*challenge| {
            if (challenge.used and challenge.deadline_ns <= now_ns) challenge.used = false;
        }
        if (service.lookup.active and service.lookup.finished()) {
            service.lookup.active = false;
            service.next_lookup_ns = now_ns + service.config.lookup_interval_ns;
        }
        if (!service.lookup.active and now_ns >= service.next_lookup_ns) {
            service.start_lookup(now_ns);
        }
        service.drive_lookup(now_ns);
    }

    fn expire_pending(service: *Service, now_ns: u64) void {
        for (service.pending) |*pending| {
            if (!pending.used or pending.deadline_ns > now_ns) continue;
            pending.used = false;
            service.stats.requests_timed_out += 1;
            _ = service.table.mark_failed(pending.node_id);
            if (pending.kind == .findnode) service.lookup.on_failure(pending.node_id);
        }
    }

    fn start_lookup(service: *Service, now_ns: u64) void {
        var target: enr.NodeId = undefined;
        service.random.bytes(&target);
        service.lookup.start(target);
        var closest: [lookup_module.candidates_max]*const table_module.Entry = undefined;
        const count = service.table.closest(target, &closest);
        for (closest[0..count]) |entry| _ = service.lookup.add(&entry.record);
        if (count == 0) {
            service.lookup.active = false;
            service.next_lookup_ns = now_ns + service.config.lookup_interval_ns;
        }
    }

    fn drive_lookup(service: *Service, now_ns: u64) void {
        var budget: u32 = lookup_module.parallelism;
        while (budget > 0) : (budget -= 1) {
            const candidate = service.lookup.next() orelse return;
            const endpoint = endpoint_of(&candidate.record) orelse {
                service.lookup.on_failure(candidate.node_id);
                continue;
            };
            var distances: [3]u16 = undefined;
            const wanted = service.lookup.distances_for(candidate.node_id, &distances);
            const sent = service.send_findnode(
                candidate.node_id,
                endpoint,
                candidate.record.public_key,
                wanted,
                now_ns,
            );
            if (!sent) service.lookup.on_failure(candidate.node_id);
        }
    }

    // ---------------------------------------------------------------- requests

    fn claim_pending(service: *Service) ?*Pending {
        for (service.pending) |*pending| {
            if (!pending.used) return pending;
        }
        return null;
    }

    fn send_ping(
        service: *Service,
        node_id: enr.NodeId,
        endpoint: Endpoint,
        public_key: secp256k1.PublicKey,
        now_ns: u64,
    ) void {
        const pending = service.claim_pending() orelse return;
        pending.kind = .ping;
        pending.distances_count = 0;
        const message: messages.Message = .{ .ping = .{
            .request_id = service.new_request_id(),
            .enr_seq = service.local_record.sequence,
        } };
        service.start_request(pending, node_id, endpoint, public_key, &message, now_ns);
    }

    fn send_findnode(
        service: *Service,
        node_id: enr.NodeId,
        endpoint: Endpoint,
        public_key: secp256k1.PublicKey,
        distances: []const u16,
        now_ns: u64,
    ) bool {
        assert(distances.len >= 1 and distances.len <= 3);
        const pending = service.claim_pending() orelse return false;
        pending.kind = .findnode;
        pending.distances_count = @intCast(distances.len);
        @memcpy(pending.distances[0..distances.len], distances);
        var findnode: messages.Findnode = .{ .request_id = service.new_request_id() };
        @memcpy(findnode.distances[0..distances.len], distances);
        findnode.distances_count = @intCast(distances.len);
        const message: messages.Message = .{ .findnode = findnode };
        service.start_request(pending, node_id, endpoint, public_key, &message, now_ns);
        return true;
    }

    fn new_request_id(service: *Service) messages.RequestId {
        return messages.RequestId.from_int(service.random.int(u64));
    }

    fn start_request(
        service: *Service,
        pending: *Pending,
        node_id: enr.NodeId,
        endpoint: Endpoint,
        public_key: secp256k1.PublicKey,
        message: *const messages.Message,
        now_ns: u64,
    ) void {
        // Requests are small and fixed-shape; they always fit one packet.
        const plaintext = messages.encode(&pending.plaintext, message) catch unreachable;
        pending.used = true;
        pending.node_id = node_id;
        pending.endpoint = endpoint;
        pending.public_key = public_key;
        pending.request_id = message.request_id();
        pending.plaintext_length = @intCast(plaintext.len);
        pending.nodes_total = 0;
        pending.nodes_received = 0;
        pending.handshake_sent = false;
        pending.deadline_ns = now_ns + service.config.request_timeout_ns;
        if (service.sessions.get(node_id, endpoint)) |session| {
            if (service.send_message(session, plaintext, now_ns)) |nonce| {
                pending.nonce = nonce;
                return;
            }
            service.sessions.remove(session);
        }
        // No session: a random packet provokes WHOAREYOU, answered by a handshake.
        pending.nonce = service.send_random(node_id, endpoint);
        pending.deadline_ns = now_ns + service.config.handshake_timeout_ns;
    }

    fn outgoing_slot(service: *Service, endpoint: Endpoint) ?*Datagram {
        const slot = service.outbox.push() orelse {
            service.stats.outbox_dropped += 1;
            return null;
        };
        slot.endpoint = endpoint;
        return slot;
    }

    fn emit(service: *Service, endpoint: Endpoint, outgoing: *const packet.Outgoing) void {
        const slot = service.outgoing_slot(endpoint) orelse return;
        // Outgoing packets are built from bounded parts that always fit 1280 bytes.
        const bytes = packet.encode(&slot.bytes, outgoing) catch unreachable;
        slot.length = @intCast(bytes.len);
    }

    /// Encrypts `plaintext` for an established session. Null if the nonce space is spent.
    fn send_message(
        service: *Service,
        session: *session_module.Session,
        plaintext: []const u8,
        now_ns: u64,
    ) ?packet.Nonce {
        const nonce = session_module.next_nonce(session, service.random, now_ns) orelse return null;
        var outgoing: packet.Outgoing = .{
            .dest_id = session.node_id,
            .masking_iv = undefined,
            .nonce = nonce,
            .authdata = .{ .message = service.local_id },
            .plaintext = plaintext,
            .key = session.write_key,
        };
        service.random.bytes(&outgoing.masking_iv);
        service.emit(session.endpoint, &outgoing);
        return nonce;
    }

    fn send_random(service: *Service, node_id: enr.NodeId, endpoint: Endpoint) packet.Nonce {
        var filler: [20]u8 = undefined;
        service.random.bytes(&filler);
        var outgoing: packet.Outgoing = .{
            .dest_id = node_id,
            .masking_iv = undefined,
            .nonce = undefined,
            .authdata = .{ .message = service.local_id },
            .plaintext = &filler,
        };
        service.random.bytes(&outgoing.masking_iv);
        service.random.bytes(&outgoing.nonce);
        service.random.bytes(&outgoing.key);
        service.emit(endpoint, &outgoing);
        return outgoing.nonce;
    }

    // ---------------------------------------------------------------- receive

    pub fn on_packet(service: *Service, from: Endpoint, bytes: []const u8, now_ns: u64) void {
        service.stats.packets_received += 1;
        var decoded: packet.Decoded = undefined;
        packet.decode(&decoded, service.local_id, bytes) catch {
            service.stats.packets_invalid += 1;
            return;
        };
        switch (decoded.authdata) {
            .message => |src_id| service.on_message_packet(from, src_id, &decoded, now_ns),
            .whoareyou => |challenge| service.on_whoareyou(from, &decoded, challenge, now_ns),
            .handshake => |handshake| service.on_handshake(from, &decoded, &handshake, now_ns),
        }
    }

    fn on_message_packet(
        service: *Service,
        from: Endpoint,
        src_id: enr.NodeId,
        decoded: *const packet.Decoded,
        now_ns: u64,
    ) void {
        var plaintext: [packet.size_max]u8 = undefined;
        if (service.sessions.get(src_id, from)) |session| {
            if (packet.open_message(decoded, session.read_key, &plaintext)) |opened| {
                session.last_used_ns = now_ns;
                service.handle_message(from, src_id, opened, now_ns);
                return;
            } else |_| {}
        }
        service.send_whoareyou(from, src_id, decoded.nonce, now_ns);
    }

    fn find_challenge(service: *Service, node_id: enr.NodeId, endpoint: Endpoint) ?*Challenge {
        for (service.challenges) |*challenge| {
            if (!challenge.used) continue;
            if (!std.mem.eql(u8, &challenge.node_id, &node_id)) continue;
            if (challenge.endpoint.eql(endpoint)) return challenge;
        }
        return null;
    }

    fn send_whoareyou(
        service: *Service,
        to: Endpoint,
        node_id: enr.NodeId,
        nonce: packet.Nonce,
        now_ns: u64,
    ) void {
        // A fresh challenge replaces any in progress for this node: the spec allows
        // re-sending, and a new nonce must be echoed for the initiator to match it.
        const challenge = service.find_challenge(node_id, to) orelse
            service.claim_challenge(now_ns);
        var outgoing: packet.Outgoing = .{
            .dest_id = node_id,
            .masking_iv = undefined,
            .nonce = nonce,
            .authdata = .{ .whoareyou = .{ .id_nonce = undefined, .enr_seq = 0 } },
        };
        service.random.bytes(&outgoing.masking_iv);
        service.random.bytes(&outgoing.authdata.whoareyou.id_nonce);
        if (service.table.get(node_id)) |entry| {
            outgoing.authdata.whoareyou.enr_seq = entry.record.sequence;
        }
        var buffer: [packet.size_max]u8 = undefined;
        const bytes = packet.encode(&buffer, &outgoing) catch unreachable; // Fixed 63 bytes.
        var unmasked: packet.Decoded = undefined;
        packet.decode(&unmasked, node_id, bytes) catch unreachable; // We just encoded it.
        challenge.* = .{
            .used = true,
            .node_id = node_id,
            .endpoint = to,
            .deadline_ns = now_ns + service.config.handshake_timeout_ns,
            .data = undefined,
        };
        const data = unmasked.authenticated_data(&challenge.data);
        assert(data.len == crypto.challenge_length);
        const slot = service.outgoing_slot(to) orelse return;
        @memcpy(slot.bytes[0..bytes.len], bytes);
        slot.length = @intCast(bytes.len);
    }

    fn claim_challenge(service: *Service, now_ns: u64) *Challenge {
        _ = now_ns;
        var oldest = &service.challenges[0];
        for (service.challenges) |*challenge| {
            if (!challenge.used) return challenge;
            if (challenge.deadline_ns < oldest.deadline_ns) oldest = challenge;
        }
        return oldest;
    }

    fn find_pending_by_nonce(service: *Service, nonce: packet.Nonce) ?*Pending {
        for (service.pending) |*pending| {
            if (pending.used and std.mem.eql(u8, &pending.nonce, &nonce)) return pending;
        }
        return null;
    }

    fn on_whoareyou(
        service: *Service,
        from: Endpoint,
        decoded: *const packet.Decoded,
        challenge: packet.Whoareyou,
        now_ns: u64,
    ) void {
        const pending = service.find_pending_by_nonce(decoded.nonce) orelse return;
        if (!pending.endpoint.eql(from) or pending.handshake_sent) return;
        var challenge_data: [packet.size_max]u8 = undefined;
        const data = decoded.authenticated_data(&challenge_data);
        if (data.len != crypto.challenge_length) return;

        var ephemeral: secp256k1.SecretKey = undefined;
        var ephemeral_public: secp256k1.PublicKey = undefined;
        while (true) {
            service.random.bytes(&ephemeral);
            ephemeral_public = secp256k1.public_key(ephemeral) catch continue;
            break;
        }
        const remote_id = pending.node_id;
        const keys = crypto.derive_keys(
            ephemeral,
            pending.public_key,
            service.local_id,
            remote_id,
            data,
        ) catch return;
        // Our own secret was validated at init.
        const signature = crypto.id_sign(service.secret, data, ephemeral_public, remote_id) catch
            unreachable;
        const include_record = challenge.enr_seq < service.local_record.sequence;
        const write_key = keys.initiator_key;
        const session = service.sessions.put(remote_id, from, write_key, keys.recipient_key, now_ns);
        // A freshly installed session has nonce counter 0, far from exhaustion.
        const nonce = session_module.next_nonce(session, service.random, now_ns).?;
        var outgoing: packet.Outgoing = .{
            .dest_id = pending.node_id,
            .masking_iv = undefined,
            .nonce = nonce,
            .authdata = .{ .handshake = .{
                .src_id = service.local_id,
                .signature = signature,
                .ephemeral_public_key = ephemeral_public,
                .record = if (include_record) service.local_record.raw() else "",
            } },
            .plaintext = pending.plaintext[0..pending.plaintext_length],
            .key = keys.initiator_key,
        };
        service.random.bytes(&outgoing.masking_iv);
        service.emit(from, &outgoing);
        pending.nonce = nonce;
        pending.handshake_sent = true;
        pending.deadline_ns = now_ns + service.config.request_timeout_ns;
    }

    fn on_handshake(
        service: *Service,
        from: Endpoint,
        decoded: *const packet.Decoded,
        handshake: *const packet.Handshake,
        now_ns: u64,
    ) void {
        const challenge = service.find_challenge(handshake.src_id, from) orelse return;
        var record_storage: enr.Record = undefined;
        const record = service.handshake_record(handshake, &record_storage) orelse {
            service.stats.records_rejected += 1;
            return;
        };
        const proof_ok = crypto.id_verify(
            record.public_key,
            handshake.signature,
            &challenge.data,
            handshake.ephemeral_public_key,
            service.local_id,
        );
        if (!proof_ok) return;
        const keys = crypto.derive_keys(
            service.secret,
            handshake.ephemeral_public_key,
            handshake.src_id,
            service.local_id,
            &challenge.data,
        ) catch return;
        var plaintext: [packet.size_max]u8 = undefined;
        const opened = packet.open_message(decoded, keys.initiator_key, &plaintext) catch return;
        challenge.used = false;
        const write_key = keys.recipient_key;
        _ = service.sessions.put(handshake.src_id, from, write_key, keys.initiator_key, now_ns);
        service.stats.handshakes_completed += 1;
        if (handshake.record.len > 0) service.learn(record, now_ns);
        service.handle_message(from, handshake.src_id, opened, now_ns);
    }

    /// The initiator's record: from the handshake (verified, id must match) or our table.
    fn handshake_record(
        service: *Service,
        handshake: *const packet.Handshake,
        storage: *enr.Record,
    ) ?*const enr.Record {
        if (handshake.record.len > 0) {
            storage.* = enr.decode(handshake.record) catch return null;
            if (!std.mem.eql(u8, &storage.node_id(), &handshake.src_id)) return null;
            return storage;
        }
        const entry = service.table.get(handshake.src_id) orelse return null;
        return &entry.record;
    }

    /// Inserts a verified record; publishes it and probes a full bucket's oldest entry.
    fn learn(service: *Service, record: *const enr.Record, now_ns: u64) void {
        const endpoint = endpoint_of(record) orelse return;
        switch (service.table.insert(record, endpoint, now_ns)) {
            .added => service.publish(record),
            .pending => |value| {
                const entry = service.table.get(value.least_recent) orelse return;
                service.send_ping(entry.node_id, entry.endpoint, entry.record.public_key, now_ns);
            },
            else => {},
        }
    }

    // ---------------------------------------------------------------- messages

    fn handle_message(
        service: *Service,
        from: Endpoint,
        src_id: enr.NodeId,
        plaintext: []const u8,
        now_ns: u64,
    ) void {
        const message = messages.decode(plaintext) catch {
            service.stats.packets_invalid += 1;
            return;
        };
        switch (message) {
            .ping => |ping| service.reply_pong(from, src_id, &ping, now_ns),
            .findnode => |*findnode| service.reply_nodes(from, src_id, findnode, now_ns),
            .talkreq => |talkreq| {
                const response: messages.Message = .{ .talkresp = .{
                    .request_id = talkreq.request_id,
                    .response = "",
                } };
                service.reply(from, src_id, &response, now_ns);
            },
            .pong => |pong| service.on_pong(src_id, &pong, now_ns),
            .nodes => |*nodes| service.on_nodes(src_id, nodes, now_ns),
            .talkresp => {},
        }
    }

    fn reply(
        service: *Service,
        to: Endpoint,
        node_id: enr.NodeId,
        message: *const messages.Message,
        now_ns: u64,
    ) void {
        const session = service.sessions.get(node_id, to) orelse return;
        var buffer: [messages.plaintext_length_max]u8 = undefined;
        const plaintext = messages.encode(&buffer, message) catch return;
        _ = service.send_message(session, plaintext, now_ns);
    }

    fn reply_pong(
        service: *Service,
        from: Endpoint,
        src_id: enr.NodeId,
        ping: *const messages.Ping,
        now_ns: u64,
    ) void {
        const pong: messages.Message = .{ .pong = .{
            .request_id = ping.request_id,
            .enr_seq = service.local_record.sequence,
            .address = from.address,
            .port = from.port,
        } };
        service.reply(from, src_id, &pong, now_ns);
        service.table.mark_alive(src_id, now_ns);
    }

    fn reply_nodes(
        service: *Service,
        from: Endpoint,
        src_id: enr.NodeId,
        findnode: *const messages.Findnode,
        now_ns: u64,
    ) void {
        var found: [32]*const enr.Record = undefined;
        var found_count: usize = 0;
        const limit = @min(service.config.findnode_results_max, found.len);
        for (findnode.distances_slice()) |distance| {
            if (found_count == limit) break;
            if (distance == 0) {
                found[found_count] = &service.local_record;
                found_count += 1;
                continue;
            }
            var entries: [32]*const table_module.Entry = undefined;
            const count = service.table.at_distance(distance, entries[0 .. limit - found_count]);
            for (entries[0..count]) |entry| {
                found[found_count] = &entry.record;
                found_count += 1;
            }
        }
        service.send_nodes(from, src_id, findnode.request_id, found[0..found_count], now_ns);
    }

    /// Splits records across NODES messages that each fit one packet.
    fn send_nodes(
        service: *Service,
        to: Endpoint,
        node_id: enr.NodeId,
        request_id: messages.RequestId,
        records: []const *const enr.Record,
        now_ns: u64,
    ) void {
        // Three maximum-size records plus framing always fit a packet's plaintext.
        const per_message = 3;
        comptime assert(per_message * enr.size_max + 32 <= messages.plaintext_length_max);
        const total: u64 = @max(1, (records.len + per_message - 1) / per_message);
        var start: usize = 0;
        var sent: u64 = 0;
        while (sent < total) : (sent += 1) {
            const end = @min(start + per_message, records.len);
            var nodes: messages.Nodes = .{ .request_id = request_id, .total = total };
            for (records[start..end], 0..) |record, index| nodes.records[index] = record.raw();
            nodes.records_count = @intCast(end - start);
            const message: messages.Message = .{ .nodes = nodes };
            service.reply(to, node_id, &message, now_ns);
            start = end;
        }
        assert(start == records.len);
    }

    fn find_pending(service: *Service, node_id: enr.NodeId, id: messages.RequestId) ?*Pending {
        for (service.pending) |*pending| {
            if (!pending.used or !std.mem.eql(u8, &pending.node_id, &node_id)) continue;
            if (pending.request_id.eql(&id)) return pending;
        }
        return null;
    }

    fn on_pong(
        service: *Service,
        src_id: enr.NodeId,
        pong: *const messages.Pong,
        now_ns: u64,
    ) void {
        const pending = service.find_pending(src_id, pong.request_id) orelse return;
        if (pending.kind != .ping) return;
        pending.used = false;
        service.table.mark_alive(src_id, now_ns);
    }

    fn on_nodes(
        service: *Service,
        src_id: enr.NodeId,
        nodes: *const messages.Nodes,
        now_ns: u64,
    ) void {
        const pending = service.find_pending(src_id, nodes.request_id) orelse return;
        if (pending.kind != .findnode) return;
        if (nodes.total == 0 or nodes.total > service.config.nodes_responses_max) {
            pending.used = false;
            service.lookup.on_failure(src_id);
            return;
        }
        pending.nodes_total = @intCast(nodes.total);
        for (nodes.records_slice()) |raw| service.on_found_record(pending, raw, now_ns);
        pending.nodes_received += 1;
        if (pending.nodes_received >= pending.nodes_total) {
            pending.used = false;
            service.table.mark_alive(src_id, now_ns);
            service.lookup.on_response(src_id);
        }
    }

    fn on_found_record(
        service: *Service,
        pending: *const Pending,
        raw: []const u8,
        now_ns: u64,
    ) void {
        const record = enr.decode(raw) catch {
            service.stats.records_rejected += 1;
            return;
        };
        const node_id = record.node_id();
        const distance = table_module.log_distance(pending.node_id, node_id);
        const asked = pending.distances[0..pending.distances_count];
        const requested = std.mem.indexOfScalar(u16, asked, distance);
        if (requested == null) {
            service.stats.records_rejected += 1;
            return;
        }
        if (std.mem.eql(u8, &node_id, &service.local_id)) return;
        service.learn(&record, now_ns);
        if (service.lookup.active) _ = service.lookup.add(&record);
    }
};

test {
    _ = @import("service_test.zig");
}

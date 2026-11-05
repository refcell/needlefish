//! `p2p.Network(IO)`: what the consensus node embeds. It turns `--p2p.*` options into a
//! `Service` (discovery, gossip, gater, limits, bans) plus a TCP `Transport(IO)`, builds
//! and signs the local ENR, and seeds bootnodes (the chain's public list by default,
//! base/base behavior). ENR bootnodes seed discovery; enode bootnodes are dialed directly.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const service_module = @import("service.zig");
const transport_module = @import("transport.zig");
const options_module = @import("options.zig");
const boot = @import("peers/boot.zig");
const enr = @import("peers/enr.zig");
const ip = @import("peers/ip.zig");
const node_key = @import("peers/node_key.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const block = @import("gossip/block.zig");
const router_module = @import("gossip/router.zig");
const primitives = @import("../../common/primitives/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");

const Service = service_module.Service;
const Options = options_module.Options;
const ns_per_s = std.time.ns_per_s;

pub const Error = error{ NoUnsafeBlockSigner, InvalidNodeKey, InvalidBootnode };

/// The node's secp256k1 key: `--p2p.priv.raw`, else the contents of `--p2p.priv.path`
/// (read by the caller), else a fresh key from `random`.
pub fn node_secret(
    options: *const Options,
    key_file_contents: ?[]const u8,
    random: std.Random,
) Error!secp256k1.SecretKey {
    const text = options.priv_raw orelse key_file_contents;
    if (text) |contents| {
        const key = node_key.parse(contents) catch return error.InvalidNodeKey;
        return key.secret;
    }
    return node_key.generate(random).secret;
}

/// Maps options to the service configuration (base/base `P2PArgs::config`).
pub fn service_config(
    options: *const Options,
    rollup: *const rollup_config.RollupConfig,
    unsafe_block_signer: primitives.Address,
) service_module.Config {
    assert(options.redial_period_min > 0);
    return .{
        .rollup = rollup,
        .unsafe_block_signer = options.unsafe_block_signer orelse unsafe_block_signer,
        .block_time_s = rollup.block_time,
        .disc = .{
            .chain_id = rollup.l2_chain_id,
            .lookup_interval_ns = options.discovery_interval_s * ns_per_s,
        },
        .gater = .{
            .peer_redialing = options.redial,
            .dial_period_ns = options.redial_period_min * 60 * ns_per_s,
            .pending_dial_timeout_ns = options.pending_dial_timeout_s * ns_per_s,
        },
        .limits = .{
            .pending_outbound_max = options.max_pending_outgoing,
            .established_max = options.peers_hi,
            .established_inbound_max = options.peers_hi,
            .established_outbound_max = options.peers_hi,
        },
        .ban_enabled = options.ban_peers,
        .ban_threshold = @floatFromInt(options.ban_threshold),
        .ban_duration_ns = options.ban_duration_min * 60 * ns_per_s,
        .mesh = .{
            .d = options.gossip_mesh_d,
            .d_low = options.gossip_mesh_lo,
            .d_high = options.gossip_mesh_dhi,
            .d_lazy = options.gossip_mesh_dlazy,
        },
        .score_level = options.scoring,
        .topic_scoring = options.topic_scoring,
    };
}

/// The local record: advertised address and ports, falling back to the listen ones.
pub fn local_record(
    options: *const Options,
    secret: secp256k1.SecretKey,
    chain_id: u64,
) !enr.Record {
    var fields: enr.Fields = .{
        .tcp = options.advertise_tcp orelse options.listen_tcp,
        .udp = options.advertise_udp orelse options.listen_udp,
        .opstack = .{ .chain_id = chain_id },
    };
    const address = options.advertise_ip orelse options.listen_ip;
    switch (address) {
        .ip4 => |bytes| {
            if (!std.mem.allEqual(u8, &bytes, 0)) fields.ip4 = bytes;
        },
        .ip6 => |bytes| {
            if (!std.mem.allEqual(u8, &bytes, 0)) fields.ip6 = bytes;
        },
    }
    return enr.build(secret, fields);
}

pub fn Network(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Transport = transport_module.Transport(IO);

        service: *Service,
        transport: Transport,
        options: Options,
        record: enr.Record,

        /// `self` must not move afterwards. `seed` feeds per-connection noise keys and must
        /// come from OS entropy in production.
        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            rollup: *const rollup_config.RollupConfig,
            options: Options,
            secret: secp256k1.SecretKey,
            unsafe_block_signer: primitives.Address,
            random: std.Random,
            seed: u64,
        ) !void {
            self.options = options;
            self.record = try local_record(&options, secret, rollup.l2_chain_id);
            const config = service_config(&options, rollup, unsafe_block_signer);
            self.service = try Service.create(allocator, config, secret, self.record, random);
            errdefer self.service.destroy(allocator);
            const listen = switch (options.listen_ip) {
                .ip4 => |bytes| io_module.Address.ip4(bytes, options.listen_tcp),
                .ip6 => |bytes| io_module.Address.ip6(bytes, options.listen_tcp),
            };
            try self.transport.init(allocator, io, self.service, .{
                .listen = listen,
                .identity_secret = secret,
                .seed = seed,
                .links_max = options.peers_hi + options.max_pending_outgoing,
            });
        }

        /// Opens the listener and seeds bootnodes. Bad bootnode text is skipped and
        /// counted in the return value.
        pub fn start(self: *Self) !u32 {
            try self.transport.start();
            const now = self.transport.io.now_realtime_ns();
            const configured = self.options.bootnode_slice();
            const chain_id = self.service.config.rollup.l2_chain_id;
            const texts = if (configured.len > 0) configured else boot.for_chain(chain_id);
            var invalid: u32 = 0;
            for (texts) |text| {
                const node = boot.parse(text) catch {
                    invalid += 1;
                    continue;
                };
                switch (node) {
                    .record => |*record| if (!self.options.no_discovery) {
                        self.service.add_boot_record(record, now);
                    },
                    .enode => {
                        const address = node.to_multiaddr() orelse continue;
                        self.service.dial(&address, now);
                    },
                }
            }
            self.transport.execute_commands();
            return invalid;
        }

        pub fn stop(self: *Self) void {
            self.transport.stop();
        }

        /// Frees memory after `stop` once the IO loop has drained the completions.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.transport.deinit();
            self.service.destroy(allocator);
        }

        /// Signs and gossips an unsafe block (sequencer).
        pub fn publish_block(
            self: *Self,
            secret_key: [32]u8,
            parent_beacon_block_root: ?primitives.B256,
            payload: block.ExecutionPayload,
        ) !router_module.Id {
            const now = self.transport.io.now_realtime_ns();
            const id = try self.service.publish_block(
                secret_key,
                parent_beacon_block_root,
                payload,
                now,
            );
            self.transport.pump_all();
            return id;
        }

        /// The next validated unsafe block from the network, decoded into `scratch`.
        pub fn pop_block(self: *Self, scratch: []u8) ?block.Envelope {
            return self.service.pop_block(scratch);
        }

        pub fn peer_count(self: *const Self) u32 {
            return self.service.connected_count();
        }
    };
}

// --------------------------------------------------------------------------- tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "network: options map to the service configuration" {
    const options = try options_module.parse(&.{
        "--p2p.peers.hi=12", "--p2p.ban.peers",       "--p2p.ban.duration=5",
        "--p2p.redial=3",    "--p2p.gossip.mesh.d=6",
    });
    var rollup: rollup_config.RollupConfig = .{ .l2_chain_id = 8453 };
    rollup.block_time = 2;
    const config = service_config(&options, &rollup, .zero);
    try testing.expectEqual(@as(u32, 12), config.limits.established_max);
    try testing.expect(config.ban_enabled);
    try testing.expectEqual(@as(u64, 300 * ns_per_s), config.ban_duration_ns);
    try testing.expectEqual(@as(?u32, 3), config.gater.peer_redialing);
    try testing.expectEqual(@as(u32, 6), config.mesh.d);
    try testing.expectEqual(@as(u64, 8453), config.disc.chain_id);
}

test "network: local record advertises the configured address and ports" {
    const options = try options_module.parse(&.{
        "--p2p.advertise.ip=1.2.3.4", "--p2p.advertise.tcp=1000",
    });
    var secret: secp256k1.SecretKey = @splat(0);
    secret[31] = 3;
    const record = try local_record(&options, secret, 84532);
    try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, record.ip4().?);
    try testing.expectEqual(@as(u16, 1000), record.tcp().?);
    try testing.expectEqual(@as(u16, 9223), record.udp().?);
    try testing.expectEqual(enr.Validation.valid, enr.validate_chain(&record, 84532));
    const unspecified = try local_record(&(try options_module.parse(&.{})), secret, 8453);
    try testing.expect(unspecified.ip4() == null);
}

test "network: node key from raw hex, file contents, or random" {
    var prng = Prng.init(1);
    const raw_flag = "--p2p.priv.raw=0x" ++
        "00000000000000000000000000000000000000000000000000000000000000" ++ "07";
    const raw_options = try options_module.parse(&.{raw_flag});
    const from_raw = try node_secret(&raw_options, null, prng.random());
    try testing.expectEqual(@as(u8, 7), from_raw[31]);
    const defaults = try options_module.parse(&.{});
    const key_file = "00000000000000000000000000000000" ++
        "00000000000000000000000000000009\n";
    const from_file = try node_secret(&defaults, key_file, prng.random());
    try testing.expectEqual(@as(u8, 9), from_file[31]);
    const random_key = try node_secret(&defaults, null, prng.random());
    try secp256k1.validate_secret_key(random_key);
    try testing.expectError(error.InvalidNodeKey, node_secret(&defaults, "zz", prng.random()));
}

test "network: two nodes over SimIo connect through an enode bootnode" {
    const allocator = testing.allocator;
    var world = try io_module.SimWorld.init(allocator, .{ .seed = 3 });
    defer world.deinit();
    var ios: [2]io_module.SimIo = undefined;
    var networks: [2]Network(io_module.SimIo) = undefined;
    var prngs: [2]Prng = .{ Prng.init(1), Prng.init(2) };
    var rollup: rollup_config.RollupConfig = .{ .l2_chain_id = 8453 };
    rollup.block_time = 2;
    var secrets: [2]secp256k1.SecretKey = .{ @splat(0), @splat(0) };
    secrets[0][31] = 3;
    secrets[1][31] = 4;
    var enode_text: [256]u8 = undefined;
    const enode = try enode_for(&enode_text, secrets[0], .{ 10, 0, 0, 1 }, 9222);
    for (0..2) |index| {
        const host: [4]u8 = .{ 10, 0, 0, @intCast(index + 1) };
        try io_module.SimIo.init(&ios[index], allocator, &world, .{
            .host = io_module.Address.ip4(host, 0),
        });
        var listen: [32]u8 = undefined;
        const listen_flag =
            try std.fmt.bufPrint(&listen, "--p2p.listen.ip=10.0.0.{d}", .{index + 1});
        const bootnodes = if (index == 0) "--p2p.no-discovery" else enode;
        const options = try options_module.parse(&.{ listen_flag, bootnodes, "--p2p.peers.hi=4" });
        const random = prngs[index].random();
        const network = &networks[index];
        const io = &ios[index];
        try network.init(allocator, io, &rollup, options, secrets[index], .zero, random, index);
        _ = try networks[index].start();
    }
    defer for (&networks, &ios) |*network, *io| {
        network.deinit(allocator);
        io.deinit();
    };
    world.run_for_ns(3 * ns_per_s);
    try testing.expectEqual(@as(u32, 1), networks[0].peer_count());
    try testing.expectEqual(@as(u32, 1), networks[1].peer_count());
    for (&networks) |*network| network.stop();
    world.run_for_ns(100 * std.time.ns_per_ms);
}

fn enode_for(output: []u8, secret: secp256k1.SecretKey, host: [4]u8, port: u16) ![]const u8 {
    const public = try secp256k1.public_key(secret);
    const uncompressed = try secp256k1.decompress(public);
    const hex = std.fmt.bytesToHex(uncompressed[1..], .lower);
    return std.fmt.bufPrint(output, "--p2p.bootnodes=enode://{s}@{d}.{d}.{d}.{d}:{d}", .{
        &hex, host[0], host[1], host[2], host[3], port,
    });
}

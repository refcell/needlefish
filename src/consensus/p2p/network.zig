//! `p2p.Network(IO)`: what the consensus node embeds. It turns `--p2p.*` options into a
//! `Service` (discovery, gossip, gater, limits, bans) plus a TCP `Transport(IO)`, builds
//! and signs the local ENR, and seeds bootnodes (the chain's public list by default,
//! base/base behavior). ENR bootnodes seed discovery; enode bootnodes are dialed directly.

const metrics_module = @import("metrics.zig");
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
const store_module = @import("peers/store.zig");
const store_file_module = @import("peers/store_file.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const block = @import("gossip/block.zig");
const router_module = @import("gossip/router.zig");
const primitives = @import("../../common/primitives/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");

const Service = service_module.Service;
const Options = options_module.Options;
const ns_per_s = std.time.ns_per_s;
/// base/base syncs the bootstore file every 60 s (discv5 driver `store_interval`).
pub const bootstore_sync_interval_ns = 60 * ns_per_s;
/// `--p2p.bootnodes-file` read limit: 64 entries of the longest ENR text plus comments.
pub const bootnodes_file_size_max = 64 * 1024;

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
        .redial_known_interval_ns = options.redial_known_interval_s * ns_per_s,
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
        /// Known peers persisted across restarts (base/base bootstore), unless disabled.
        store: ?store_module.Store = null,
        /// The `--p2p.bootstore` file behind `store`, synced through the IO layer.
        bootstore_file: ?BootstoreFile = null,
        /// Bootstore file contents that were not valid bootstore JSON (treated as empty).
        bootstore_invalid: u64 = 0,

        /// `--p2p.bootnodes-file`, read once at start (base/base appends it to
        /// `--p2p.bootnodes`; the chain defaults apply only when both are empty).
        bootnodes_file: ?BootnodesFile = null,
        /// Bootnode texts that did not parse, from flags and the bootnodes file.
        bootnodes_invalid: u32 = 0,

        pub const BootnodesFile = store_file_module.StoreFile(IO, Self, .{
            .loaded = on_bootnodes_loaded,
        });
        pub const BootstoreFile = store_file_module.StoreFile(IO, Self, .{
            .loaded = on_bootstore_loaded,
            .produce = save_bootstore,
        });

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
            // discv5 over UDP on `--p2p.listen.udp`, unless `--p2p.no-discovery`.
            const discovery_listen: ?io_module.Address =
                if (options.no_discovery) null else listen.with_port(options.listen_udp);
            self.store = null;
            if (!options.no_bootstore) {
                self.store = try store_module.Store.init(allocator, store_module.capacity_default);
            }
            errdefer if (self.store) |*store| store.deinit(allocator);
            self.bootstore_file = null;
            self.bootstore_invalid = 0;
            if (self.store != null) {
                if (options.bootstore) |path| {
                    self.bootstore_file = @as(BootstoreFile, undefined);
                    const capacity = self.bootstore_length_max();
                    const interval = bootstore_sync_interval_ns;
                    try self.bootstore_file.?.init(allocator, io, self, path, capacity, interval);
                }
            }
            errdefer if (self.bootstore_file) |*file| file.deinit(allocator);
            self.bootnodes_file = null;
            self.bootnodes_invalid = 0;
            if (options.bootnodes_file) |path| {
                self.bootnodes_file = @as(BootnodesFile, undefined);
                const size = bootnodes_file_size_max;
                try self.bootnodes_file.?.init(allocator, io, self, path, size, ns_per_s);
            }
            errdefer if (self.bootnodes_file) |*file| file.deinit(allocator);
            try self.transport.init(allocator, io, self.service, .{
                .listen = listen,
                .identity_secret = secret,
                .seed = seed,
                .links_max = options.peers_hi + options.max_pending_outgoing,
                .discovery_listen = discovery_listen,
            });
        }

        /// Opens the listener and seeds bootnodes. Bad bootnode text is skipped and
        /// counted in the return value. With `--p2p.bootnodes-file`, its entries are seeded
        /// once the read completes (see `bootnodes_invalid`).
        pub fn start(self: *Self) !u32 {
            try self.transport.start();
            if (self.bootstore_file) |*file| file.start();
            const configured = self.options.bootnode_slice();
            const chain_id = self.service.config.rollup.l2_chain_id;
            var invalid: u32 = 0;
            if (self.bootnodes_file) |*file| {
                invalid = self.seed_bootnodes(configured);
                file.start();
            } else {
                const defaults = boot.for_chain(chain_id);
                invalid = self.seed_bootnodes(if (configured.len > 0) configured else defaults);
            }
            self.bootnodes_invalid += invalid;
            self.transport.execute_commands();
            return invalid;
        }

        fn seed_bootnodes(self: *Self, texts: []const []const u8) u32 {
            const now = self.transport.io.now_realtime_ns();
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
            assert(invalid <= texts.len);
            return invalid;
        }

        /// Appends the file's entries to the flag bootnodes and seeds them; falls back to the
        /// chain defaults when neither gave any (also when the file could not be read).
        fn on_bootnodes_loaded(self: *Self, contents: []const u8) void {
            const before = self.options.bootnodes_count;
            options_module.add_bootnodes_file(&self.options, contents) catch {
                self.bootnodes_invalid += 1; // More than `bootnodes_max`: the rest is ignored.
            };
            assert(self.options.bootnodes_count >= before);
            const added = self.options.bootnode_slice()[before..];
            if (self.options.bootnodes_count == 0) {
                const chain_id = self.service.config.rollup.l2_chain_id;
                self.bootnodes_invalid += self.seed_bootnodes(boot.for_chain(chain_id));
            } else {
                self.bootnodes_invalid += self.seed_bootnodes(added);
            }
            self.transport.execute_commands();
        }

        /// Stops the transport and writes a final bootstore image.
        pub fn stop(self: *Self) void {
            if (self.bootnodes_file) |*file| file.stop();
            if (self.bootstore_file) |*file| file.stop();
            self.transport.stop();
        }

        /// True while a bootstore/bootnodes file operation, its timer, or a UDP completion
        /// is outstanding; after `stop`, run the IO loop until false before `deinit`.
        pub fn busy(self: *const Self) bool {
            const bootnodes = if (self.bootnodes_file) |*file| file.busy() else false;
            const bootstore = if (self.bootstore_file) |*file| file.busy() else false;
            return bootnodes or bootstore or self.transport.busy();
        }

        /// Frees memory after the IO layer crashed (`SimIo.crash`): nothing is drained or
        /// closed, because the crash already dropped every operation and descriptor.
        pub fn deinit_after_crash(self: *Self, allocator: std.mem.Allocator) void {
            self.transport.forget_after_crash();
            if (self.bootnodes_file) |*file| file.forget_after_crash();
            if (self.bootstore_file) |*file| file.forget_after_crash();
            assert(!self.busy());
            self.deinit(allocator);
        }

        /// Frees memory after `stop` once the IO loop has drained the completions.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.bootnodes_file) |*file| file.deinit(allocator);
            if (self.bootstore_file) |*file| file.deinit(allocator);
            if (self.store) |*store| store.deinit(allocator);
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

        /// Loads bootstore JSON (file contents) and seeds discovery with every record for
        /// this chain. Returns how many records were seeded; 0 when the bootstore is off.
        pub fn load_bootstore(self: *Self, contents: []const u8) error{InvalidFormat}!u32 {
            const store = if (self.store) |*value| value else return 0;
            _ = try store.load(contents);
            const now = self.transport.io.now_realtime_ns();
            const chain_id = self.service.config.rollup.l2_chain_id;
            var seeded: u32 = 0;
            var index: u32 = 0;
            while (index < store.count) : (index += 1) {
                const record = store.at(index);
                if (enr.validate_chain(record, chain_id) != .valid) continue;
                self.service.add_boot_record(record, now);
                seeded += 1;
            }
            assert(seeded <= store.count);
            return seeded;
        }

        fn on_bootstore_loaded(self: *Self, contents: []const u8) void {
            assert(self.store != null);
            if (std.mem.trim(u8, contents, " \t\r\n").len == 0) return; // A new file.
            _ = self.load_bootstore(contents) catch {
                self.bootstore_invalid += 1;
                return;
            };
            assert(self.store.?.count > 0 or contents.len > 0);
        }

        /// Bytes `save_bootstore` needs at most.
        pub fn bootstore_length_max(self: *const Self) usize {
            const store = if (self.store) |*value| value else return 0;
            return 2 + store.records.len * (enr.text_length_max + 3);
        }

        /// Merges the discovery table into the bootstore and returns its JSON for the
        /// caller to write (base/base syncs every 60 s). Empty when the bootstore is off.
        pub fn save_bootstore(self: *Self, output: []u8) []const u8 {
            const store = if (self.store) |*value| value else return output[0..0];
            assert(output.len >= self.bootstore_length_max());
            const table = &self.service.discovery.table;
            var entries: [32]*const @import("disc/table.zig").Entry = undefined;
            var distance: u16 = 1;
            while (distance <= 256) : (distance += 1) {
                const count = table.at_distance(distance, &entries);
                for (entries[0..count]) |entry| store.add(&entry.record);
            }
            return store.serialize(output);
        }

        pub fn peer_count(self: *const Self) u32 {
            return self.service.connected_count();
        }

        /// Copies service and transport state into `metrics` (call before each scrape).
        pub fn update_metrics(self: *const Self, metrics: *metrics_module.Metrics) void {
            const stats = self.transport.stats;
            var network: metrics_module.TransportStats = .{
                .accepted = stats.accepted,
                .dialed = stats.dialed,
                .dial_failures = stats.dial_failures,
                .closed = stats.closed,
                .bytes_received = stats.bytes_received,
                .bytes_sent = stats.bytes_sent,
                .bootstore_records = if (self.store) |*store| store.count else 0,
            };
            if (self.bootstore_file) |*file| {
                const file_stats = file.stats;
                network.bootstore_events = .{
                    file_stats.open_errors, file_stats.loads,
                    file_stats.load_errors, file_stats.saves,
                    file_stats.save_errors, file_stats.saves_skipped,
                    self.bootstore_invalid,
                };
            }
            metrics.update(self.service, network);
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
    // Node 0 boots discovery from node 1's record; discv5 runs over SimIo UDP.
    const node1_record = try enr.build(secrets[1], .{
        .ip4 = .{ 10, 0, 0, 2 },
        .tcp = 9222,
        .udp = 9223,
        .opstack = .{ .chain_id = 8453 },
    });
    var record_text: [enr.text_length_max]u8 = undefined;
    var boot_flag: [enr.text_length_max + 16]u8 = undefined;
    const node1_enr = try std.fmt.bufPrint(&boot_flag, "--p2p.bootnodes={s}", .{
        enr.encode_text(&record_text, &node1_record),
    });
    for (0..2) |index| {
        const host: [4]u8 = .{ 10, 0, 0, @intCast(index + 1) };
        try io_module.SimIo.init(&ios[index], allocator, &world, .{
            .host = io_module.Address.ip4(host, 0),
        });
        var listen: [32]u8 = undefined;
        const listen_flag =
            try std.fmt.bufPrint(&listen, "--p2p.listen.ip=10.0.0.{d}", .{index + 1});
        const bootnodes = if (index == 0) node1_enr else enode;
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
    // Node 1 learned node 0's record over discv5 (UDP), and the bootstore carries it.
    try testing.expect(networks[1].transport.stats.datagrams_received > 0);
    const json = try allocator.alloc(u8, networks[1].bootstore_length_max());
    defer allocator.free(json);
    const saved = networks[1].save_bootstore(json);
    var text: [enr.text_length_max]u8 = undefined;
    const node0_text = enr.encode_text(&text, &networks[0].record);
    try testing.expect(std.mem.indexOf(u8, saved, node0_text) != null);
    try testing.expect(try networks[0].load_bootstore(saved) >= 1);
    try testing.expectError(error.InvalidFormat, networks[0].load_bootstore("{"));
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

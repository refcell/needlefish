//! In-process interop: two full p2p `Network`s (as `base consensus` runs them) find each
//! other only through discv5 over SimIo UDP, connect over libp2p, and gossip sequencer
//! blocks both ways. Each received block goes through the consensus side's
//! `gossip_bridge` (gossip envelope -> engine envelope -> gossip payload) and must
//! re-hash to the block hash that was published, so the p2p wire format and the
//! consensus types agree end to end. Covers the Ecotone (v3) and Isthmus (v4) topics.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../utilities/io/root.zig");
const network_module = @import("network.zig");
const options_module = @import("options.zig");
const enr = @import("peers/enr.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const block = @import("gossip/block.zig");
const ssz = @import("gossip/ssz_payload.zig");
const validity = @import("gossip/validity.zig");
const gossip_bridge = @import("../service/gossip_bridge.zig");
const primitives = @import("../../common/primitives/root.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const consensus_types = @import("../../common/consensus/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const testing = std.testing;
const Network = network_module.Network(io_module.SimIo);
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;
const chain_id = 8453;
const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };

const Pair = struct {
    world: io_module.SimWorld,
    ios: [2]io_module.SimIo,
    networks: [2]Network,
    prngs: [2]Prng,
    secrets: [2]secp256k1.SecretKey,
    rollup: rollup_config.RollupConfig,
    sequencer_key: [32]u8,
    signer: primitives.Address,
    scratch: []u8,
    /// `Options` borrows its argument strings, so they live as long as the networks.
    boot_flags: [2][enr.text_length_max + 16]u8,
    listen_flags: [2][32]u8,

    /// Each node boots discovery from the other's ENR only: no enode, no manual dial.
    fn init(pair: *Pair, upgrade: rollup_config.Upgrade) !void {
        return pair.init_flags(upgrade, .{ .boot_other = true }, .{ .boot_other = true });
    }

    const Flags = struct {
        boot_other: bool,
        bootstore: bool = false,
        bootnodes_file: bool = false,
    };

    const Chaos = struct { seed: u64 = 0x1e70, datagram_loss_ppm: u32 = 0, reset_ppm: u32 = 0 };

    fn init_flags(pair: *Pair, upgrade: rollup_config.Upgrade, a: Flags, b: Flags) !void {
        return pair.init_chaos(upgrade, a, b, .{});
    }

    fn init_chaos(
        pair: *Pair,
        upgrade: rollup_config.Upgrade,
        a: Flags,
        b: Flags,
        chaos: Chaos,
    ) !void {
        const allocator = testing.allocator;
        pair.rollup = .{ .l2_chain_id = chain_id, .block_time = 2 };
        pair.rollup.upgrades.set(upgrade, 0);
        pair.sequencer_key = @splat(0);
        pair.sequencer_key[31] = 5;
        pair.secrets = .{ @splat(0), @splat(0) };
        pair.secrets[0][31] = 3;
        pair.secrets[1][31] = 4;
        pair.prngs = .{ Prng.init(1), Prng.init(2) };
        pair.world = try io_module.SimWorld.init(allocator, .{
            .seed = chaos.seed,
            .datagram_loss_ppm = chaos.datagram_loss_ppm,
            .reset_ppm = chaos.reset_ppm,
        });
        errdefer pair.world.deinit();
        pair.scratch = try allocator.alloc(u8, 10 << 20);
        pair.signer = .{ .bytes = try common_secp256k1.address(pair.sequencer_key) };
        for (0..2) |index| {
            const host: [4]u8 = .{ 10, 0, 0, @intCast(index + 1) };
            try io_module.SimIo.init(&pair.ios[index], allocator, &pair.world, .{
                .host = io_module.Address.ip4(host, 0),
            });
        }
        try pair.init_network(0, a);
        try pair.init_network(1, b);
        for (&pair.networks) |*network| _ = try network.start();
    }

    /// Without `boot_other` the node falls back to the chain's default bootnodes, which
    /// are unreachable in the simulation.
    fn init_network(pair: *Pair, index: usize, flags: Flags) !void {
        assert(index < 2);
        const allocator = testing.allocator;
        const other = 1 - index;
        const other_record = try enr.build(pair.secrets[other], .{
            .ip4 = .{ 10, 0, 0, @intCast(other + 1) },
            .tcp = 9222,
            .udp = 9223,
            .opstack = .{ .chain_id = chain_id },
        });
        var record_text: [enr.text_length_max]u8 = undefined;
        const bootnodes = try std.fmt.bufPrint(&pair.boot_flags[index], "--p2p.bootnodes={s}", .{
            enr.encode_text(&record_text, &other_record),
        });
        const listen_text = "--p2p.listen.ip=10.0.0.{d}";
        const listen_flag = try std.fmt.bufPrint(&pair.listen_flags[index], listen_text, .{
            index + 1,
        });
        var arguments: [4][]const u8 = undefined;
        var count: usize = 0;
        arguments[count] = listen_flag;
        count += 1;
        if (flags.boot_other) {
            arguments[count] = bootnodes;
            count += 1;
        }
        if (flags.bootstore) {
            arguments[count] = "--p2p.bootstore=bootstore.json";
            count += 1;
        }
        if (flags.bootnodes_file) {
            arguments[count] = "--p2p.bootnodes-file=bootnodes.txt";
            count += 1;
        }
        const options = try options_module.parse(arguments[0..count]);
        try pair.networks[index].init(
            allocator,
            &pair.ios[index],
            &pair.rollup,
            options,
            pair.secrets[index],
            pair.signer,
            pair.prngs[index].random(),
            index,
        );
    }

    fn deinit(pair: *Pair) void {
        for (&pair.networks) |*network| network.stop();
        pair.drain(&pair.networks[0]);
        pair.drain(&pair.networks[1]);
        for (&pair.networks, &pair.ios) |*network, *io| {
            network.deinit(testing.allocator);
            io.deinit();
        }
        testing.allocator.free(pair.scratch);
        pair.world.deinit();
    }

    /// Runs the IO loop until a stopped network has no operations outstanding.
    fn drain(pair: *Pair, network: *Network) void {
        assert(network.transport.stopped);
        pair.world.run_for_ns(100 * ns_per_ms);
        var rounds: u32 = 0;
        while (network.busy()) : (rounds += 1) {
            assert(rounds < 10_000); // A stopped network drains in bounded time.
            pair.world.run_for_ns(10 * ns_per_ms);
        }
    }

    /// Stops node `index`, drains, and starts a fresh network on the same host and disk.
    fn restart(pair: *Pair, index: usize, flags: Flags) !void {
        const network = &pair.networks[index];
        network.stop();
        pair.drain(network);
        network.deinit(testing.allocator);
        try pair.init_network(index, flags);
        _ = try network.start();
    }

    /// Writes `contents` to a new file on node `index`'s simulated disk.
    fn write_file(pair: *Pair, index: usize, path: []const u8, contents: []const u8) !void {
        const Writer = struct {
            done: bool = false,
            failed: bool = false,
            fn on_write(
                writer: *@This(),
                _: *io_module.SimIo.Completion,
                result: io_module.WriteError!usize,
            ) void {
                writer.done = true;
                _ = result catch {
                    writer.failed = true;
                };
            }
        };
        const io = &pair.ios[index];
        const fd = try io.open_file(path, .create);
        defer io.close_now(fd);
        var writer: Writer = .{};
        var completion: io_module.SimIo.Completion = .{};
        io.write(*Writer, &writer, Writer.on_write, &completion, fd, contents, 0);
        while (!writer.done) pair.world.run_for_ns(ns_per_ms);
        if (writer.failed) return error.WriteFailed;
    }

    /// Crashes node `index` (its process dies: pending IO and unsynced disk writes are
    /// lost), then starts a fresh network on the same host and disk.
    fn crash_restart(pair: *Pair, index: usize, flags: Flags) !void {
        pair.ios[index].crash();
        pair.networks[index].deinit_after_crash(testing.allocator);
        try pair.init_network(index, flags);
        _ = try pair.networks[index].start();
    }

    /// Publishes from `from` until the other node has it (gossip under loss can need a
    /// retry when the mesh is still forming); returns false if it never arrived.
    fn deliver(pair: *Pair, from: usize, number: u64, random: std.Random) !bool {
        for (0..10) |_| {
            pair.exchange(from, number, random) catch |err| switch (err) {
                error.BlockNotDelivered => {
                    pair.run(1 * ns_per_s);
                    continue;
                },
                else => return err,
            };
            return true;
        }
        return false;
    }

    fn run(pair: *Pair, duration_ns: u64) void {
        var elapsed_ns: u64 = 0;
        while (elapsed_ns < duration_ns) : (elapsed_ns += 10 * ns_per_ms) {
            pair.world.run_for_ns(10 * ns_per_ms);
            for (&pair.networks) |*network| network.transport.execute_commands();
        }
    }

    /// A sealed-looking payload with random header fields and 0-3 deposit transactions.
    fn payload(pair: *Pair, number: u64, random: std.Random, storage: []u8) !ssz.ExecutionPayload {
        assert(storage.len >= 4096);
        var transactions: [3][]const u8 = undefined;
        const count = random.uintAtMost(usize, transactions.len);
        var offset: usize = 2048;
        for (transactions[0..count], 0..) |*transaction, index| {
            const deposit: consensus_types.Envelope = .{ .deposit = .{
                .source_hash = .{ .bytes = @splat(@truncate(number + index)) },
                .from = .zero,
                .to = .create,
                .mint = random.int(u32),
                .value = random.int(u32),
                .gas_limit = 1_000_000,
                .is_system_transaction = false,
                .input = "needlefish interop",
            } };
            transaction.* = deposit.encode_to(storage[offset..]);
            offset += transaction.len;
        }
        const now_s = pair.ios[0].now_realtime_ns() / ns_per_s;
        var result: ssz.ExecutionPayload = .{
            .version = block.version_at(&pair.rollup, now_s),
            .block_number = number,
            .timestamp = now_s,
            .gas_limit = 30_000_000 + @as(u64, random.int(u16)),
            .gas_used = random.int(u16),
            .base_fee_per_gas = 1 + @as(u64, random.int(u8)),
            .extra_data = "base",
            .transactions = ssz.Transactions.encode(storage[0..2048], transactions[0..count]),
        };
        random.bytes(&result.parent_hash.bytes);
        random.bytes(&result.state_root.bytes);
        random.bytes(&result.prev_randao.bytes);
        if (@backingInt(result.version) >= @backingInt(ssz.Version.v4)) {
            random.bytes(&result.withdrawals_root.bytes);
        }
        result.block_hash = try validity.block_hash(&pair.rollup, &result, beacon_root);
        return result;
    }

    /// Publishes from `from`, then checks the other node received it and that the
    /// consensus bridge round-trips it to the same block hash.
    fn exchange(pair: *Pair, from: usize, number: u64, random: std.Random) !void {
        var storage: [4096]u8 = undefined;
        const sent = try pair.payload(number, random, &storage);
        _ = try pair.networks[from].publish_block(pair.sequencer_key, beacon_root, sent);
        pair.run(300 * ns_per_ms);
        const envelope = pair.networks[1 - from].pop_block(pair.scratch) orelse
            return error.BlockNotDelivered;
        try testing.expect(envelope.payload.block_hash.eql(sent.block_hash));
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const decoded = try gossip_bridge.decode_gossip(arena.allocator(), &envelope);
        try testing.expectEqual(number, decoded.payload.block_number);
        try testing.expectEqual(sent.transactions.count, decoded.payload.transactions.len);
        var reencoded_storage: [4096]u8 = undefined;
        const reencoded = try gossip_bridge.encode_gossip(
            &pair.rollup,
            &decoded,
            &reencoded_storage,
        );
        const root = decoded.parent_beacon_block_root;
        const rehashed = try validity.block_hash(&pair.rollup, &reencoded, root);
        try testing.expect(rehashed.eql(sent.block_hash));
    }
};

fn expect_interop(upgrade: rollup_config.Upgrade, seed: u64) !void {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    try pair.init(upgrade);
    defer pair.deinit();
    pair.run(5 * ns_per_s);
    for (&pair.networks) |*network| {
        try testing.expectEqual(@as(u32, 1), network.peer_count());
        // The connection came from discovery over UDP, not from an enode bootnode.
        try testing.expect(network.transport.stats.datagrams_received > 0);
    }
    var prng = Prng.init(seed);
    const random = prng.random();
    for (0..12) |round| {
        try pair.exchange(round % 2, 100 + round, random);
    }
}

test "p2p interop: two networks gossip Ecotone (v3) blocks through the consensus bridge" {
    try expect_interop(.ecotone, 0xec0);
}

test "p2p interop: two networks gossip Isthmus (v4) blocks through the consensus bridge" {
    try expect_interop(.isthmus, 0x157);
}

test "p2p interop: a restarted node finds its peer again from the bootstore file alone" {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    // Node 0 boots from node 1 and keeps a bootstore; node 1 knows nobody.
    const persistent: Pair.Flags = .{ .boot_other = true, .bootstore = true };
    try pair.init_flags(.ecotone, persistent, .{ .boot_other = false });
    defer pair.deinit();
    pair.run(5 * ns_per_s);
    try testing.expectEqual(@as(u32, 1), pair.networks[0].peer_count());
    pair.run(61 * ns_per_s);
    const file = &pair.networks[0].bootstore_file.?;
    try testing.expect(file.stats.saves >= 1);
    try testing.expectEqual(@as(u64, 1), file.stats.loads);
    // Restart both: node 1 forgets everything, and node 0 has no bootnode for node 1, so
    // only the file can lead them back together.
    try pair.restart(1, .{ .boot_other = false });
    try pair.restart(0, .{ .boot_other = false, .bootstore = true });
    try testing.expectEqual(@as(u32, 0), pair.networks[0].peer_count());
    pair.run(5 * ns_per_s);
    const restarted = &pair.networks[0];
    try testing.expectEqual(@as(u64, 1), restarted.bootstore_file.?.stats.loads);
    try testing.expectEqual(@as(u64, 0), restarted.bootstore_invalid);
    try testing.expect(restarted.store.?.count >= 1);
    try testing.expectEqual(@as(u32, 1), restarted.peer_count());
    var prng = Prng.init(7);
    try pair.exchange(1, 1, prng.random());
}

test "p2p interop: --p2p.bootnodes-file is read through the io layer and seeded" {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    // Node 0 starts with no bootnode at all, then learns node 1 from its file.
    try pair.init_flags(.ecotone, .{ .boot_other = false }, .{ .boot_other = false });
    defer pair.deinit();
    const record = try enr.build(pair.secrets[1], .{
        .ip4 = .{ 10, 0, 0, 2 },
        .tcp = 9222,
        .udp = 9223,
        .opstack = .{ .chain_id = chain_id },
    });
    var text: [enr.text_length_max]u8 = undefined;
    var contents_storage: [enr.text_length_max + 64]u8 = undefined;
    const contents = try std.fmt.bufPrint(&contents_storage, "# devnet\n\n{s}\n", .{
        enr.encode_text(&text, &record),
    });
    try pair.write_file(0, "bootnodes.txt", contents);
    try pair.restart(0, .{ .boot_other = false, .bootnodes_file = true });
    pair.run(5 * ns_per_s);
    const network = &pair.networks[0];
    try testing.expectEqual(@as(u64, 1), network.bootnodes_file.?.stats.loads);
    try testing.expectEqual(@as(u32, 1), network.options.bootnodes_count);
    try testing.expectEqual(@as(u32, 0), network.bootnodes_invalid);
    try testing.expectEqual(@as(u32, 1), network.peer_count());
}

test "p2p interop: a missing bootnodes file falls back to the chain defaults" {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    const flags: Pair.Flags = .{ .boot_other = false, .bootnodes_file = true };
    try pair.init_flags(.ecotone, flags, .{ .boot_other = false });
    defer pair.deinit();
    pair.run(100 * ns_per_ms);
    const network = &pair.networks[0];
    try testing.expectEqual(@as(u64, 1), network.bootnodes_file.?.stats.open_errors);
    try testing.expectEqual(@as(u32, 0), network.options.bootnodes_count);
    try testing.expect(network.service.discovery.boot_records_count > 0);
}

test "p2p interop: crash-restart under packet loss rejoins and keeps gossiping" {
    for (0..4) |seed| {
        crash_restart_seed(seed) catch |err| {
            std.debug.print("crash-restart: failing seed={d}\n", .{seed});
            return err;
        };
    }
}

fn crash_restart_seed(seed: u64) !void {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    var prng = Prng.init(seed);
    const random = prng.random();
    const persistent: Pair.Flags = .{ .boot_other = true, .bootstore = true };
    try pair.init_chaos(.ecotone, persistent, .{ .boot_other = false }, .{
        .seed = 0xc4a5 + seed,
        .datagram_loss_ppm = 100_000,
        .reset_ppm = 500,
    });
    defer pair.deinit();
    pair.run(8 * ns_per_s);
    try testing.expectEqual(@as(u32, 1), pair.networks[0].peer_count());
    pair.run(61 * ns_per_s); // At least one bootstore sync.
    try testing.expect(try pair.deliver(1, 1, random));
    // Crash mid-gossip: a block is in flight when node 0 dies.
    var storage: [4096]u8 = undefined;
    const lost = try pair.payload(2, random, &storage);
    _ = try pair.networks[1].publish_block(pair.sequencer_key, beacon_root, lost);
    pair.run(random.uintAtMost(u64, 20) * ns_per_ms);
    try pair.crash_restart(0, .{ .boot_other = false, .bootstore = true });
    const restarted = &pair.networks[0];
    try testing.expectEqual(@as(u32, 0), restarted.peer_count());
    pair.run(10 * ns_per_s);
    try testing.expectEqual(@as(u64, 1), restarted.bootstore_file.?.stats.loads);
    try testing.expect(restarted.store.?.count >= 1);
    try testing.expectEqual(@as(u32, 1), restarted.peer_count());
    // New blocks reach the restarted node, and its own blocks reach the peer.
    try testing.expect(try pair.deliver(1, 3, random));
    try testing.expect(try pair.deliver(0, 4, random));
}

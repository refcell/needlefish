//! p2p micro benchmarks, listed in `src/testing/bench_main.zig`.
//!
//! Fixtures are built on first use from the page allocator (benchmark scaffolding, not
//! library code). Block-like payloads are 128 KiB of semi-compressible bytes, roughly the
//! size of a busy L2 block after snappy.

const std = @import("std");
const assert = std.debug.assert;

const noise = @import("libp2p/noise.zig");
const secp256k1 = @import("peers/secp256k1.zig");
const snappy = @import("gossip/snappy.zig");
const rpc = @import("gossip/rpc.zig");
const seen = @import("gossip/seen.zig");
const router_module = @import("gossip/router.zig");
const peer_id = @import("peers/peer_id.zig");
const service_module = @import("service.zig");
const enr = @import("peers/enr.zig");
const ssz = @import("gossip/ssz_payload.zig");
const validity = @import("gossip/validity.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus_types = @import("../../common/consensus/root.zig");
const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const rollup_config = @import("../protocol/rollup_config.zig");
const Direction = @import("libp2p/connections.zig").Direction;
const block = @import("gossip/block.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const sha256 = @import("../../common/crypto/sha256.zig");
const IpAddress = @import("peers/ip.zig").Address;
const Prng = @import("../../testing/prng.zig").Prng;

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
    bytes_per_op: u64 = 0,
};

const payload_bytes = 128 * 1024;

pub const cases = [_]Case{
    .{ .name = "p2p/noise XX handshake", .iterations = 100, .run = bench_handshake },
    .{
        .name = "p2p/poly1305 std 64 KiB",
        .iterations = 20_000,
        .run = bench_poly1305_std,
        .bytes_per_op = 64 * 1024,
    },
    .{
        .name = "p2p/noise transport seal+open 64 KiB",
        .iterations = 10_000,
        .run = bench_transport,
        .bytes_per_op = noise.plaintext_length_max,
    },
    .{
        .name = "p2p/snappy compress 128 KiB",
        .iterations = 1_000,
        .run = bench_snappy_compress,
        .bytes_per_op = payload_bytes,
    },
    .{
        .name = "p2p/snappy decompress 128 KiB",
        .iterations = 1_000,
        .run = bench_snappy_decompress,
        .bytes_per_op = payload_bytes,
    },
    .{
        .name = "p2p/gossip rpc decode 128 KiB publish",
        .iterations = 100_000,
        .run = bench_rpc_decode,
        .bytes_per_op = payload_bytes,
    },
    .{ .name = "p2p/gossip seen insert", .iterations = 1_000_000, .run = bench_seen },
    .{
        .name = "p2p/gossip publish+drain to 8 peers",
        .iterations = 1_000,
        .run = bench_router,
        .bytes_per_op = payload_bytes,
    },
    .{
        .name = "p2p/gossip control flood rpc (4000 iwant + 1000 idontwant ids)",
        .iterations = 200,
        .run = bench_control_flood,
    },
    .{
        .name = "p2p/block gossip end to end 128 KiB",
        .iterations = 200,
        .run = bench_end_to_end,
        .bytes_per_op = payload_bytes,
    },
    stage("p2p/stage sha256 128 KiB", 2_000, bench_sha256, payload_bytes),
    stage("p2p/stage keccak256 128 KiB", 2_000, bench_keccak, payload_bytes),
    stage("p2p/stage message id 128 KiB", 1_000, bench_message_id_stage, payload_bytes),
    stage("p2p/stage block decode 128 KiB", 1_000, bench_block_decode, payload_bytes),
    stage("p2p/stage transactions root 128 KiB", 1_000, bench_transactions_root, payload_bytes),
    stage("p2p/stage check transactions 128 KiB", 1_000, bench_check_transactions, payload_bytes),
    stage("p2p/stage recover signer", 1_000, bench_recover_signer, 0),
    .{
        .name = "p2p/block gossip sequencer 128 KiB",
        .iterations = 200,
        .run = bench_sequencer,
        .bytes_per_op = payload_bytes,
    },
};

fn stage(name: []const u8, iterations: u32, run: *const fn (u32) u64, bytes: u64) Case {
    assert(iterations > 0);
    return .{ .name = name, .iterations = iterations, .run = run, .bytes_per_op = bytes };
}

var payload_storage: [payload_bytes]u8 = undefined;
var payload_ready = false;

/// Semi-compressible: random words with repeated runs, like RLP-encoded transactions.
fn payload() *const [payload_bytes]u8 {
    if (!payload_ready) {
        var prng = Prng.init(0x626c_6f63);
        var index: usize = 0;
        while (index < payload_bytes) : (index += 32) {
            if (prng.chance(1, 3)) {
                @memset(payload_storage[index..][0..32], 0);
            } else {
                prng.fill(payload_storage[index..][0..32]);
            }
        }
        payload_ready = true;
    }
    return &payload_storage;
}

fn noise_config(prng: *Prng) noise.Config {
    var config: noise.Config = undefined;
    var attempts: u32 = 0;
    while (attempts < 64) : (attempts += 1) {
        prng.fill(&config.identity_secret);
        secp256k1.validate_secret_key(config.identity_secret) catch continue;
        break;
    }
    prng.fill(&config.static_seed);
    prng.fill(&config.ephemeral_seed);
    return config;
}

/// Runs one full XX handshake in memory and returns both transports.
fn handshake(prng: *Prng) [2]noise.Transport {
    var initiator = noise.Handshake.init(.initiator, noise_config(prng)) catch unreachable;
    var responder = noise.Handshake.init(.responder, noise_config(prng)) catch unreachable;
    var buffers: [2][noise.handshake_output_length_max]u8 = undefined;
    _ = responder.start(&buffers[1]) catch unreachable;
    var pending = initiator.start(&buffers[0]) catch unreachable;
    var message: u32 = 1;
    while (pending.len > 0) : (message += 1) {
        assert(message <= 3);
        const to_responder = message % 2 == 1;
        const receiver = if (to_responder) &responder else &initiator;
        var scratch: [noise.handshake_output_length_max]u8 = undefined;
        const step = receiver.receive(pending, &scratch) catch unreachable;
        assert(step.consumed == pending.len);
        const out = if (to_responder) &buffers[1] else &buffers[0];
        @memcpy(out[0..step.output.len], step.output);
        pending = out[0..step.output.len];
    }
    return .{ initiator.finish(), responder.finish() };
}

fn bench_handshake(iterations: u32) u64 {
    var prng = Prng.init(1);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        const transports = handshake(&prng);
        checksum +%= transports[0].handshake_hash[0];
    }
    return checksum;
}

fn bench_poly1305_std(iterations: u32) u64 {
    return bench_mac(std.crypto.onetimeauth.Poly1305, iterations);
}

fn bench_mac(comptime Mac: type, iterations: u32) u64 {
    const message = payload()[0 .. 64 * 1024];
    var key: [32]u8 = @splat(7);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        var tag: [16]u8 = undefined;
        Mac.create(&tag, message, &key);
        key[0] = tag[0];
        checksum +%= tag[1];
    }
    return checksum;
}

fn bench_transport(iterations: u32) u64 {
    var prng = Prng.init(2);
    var transports = handshake(&prng);
    const plaintext = payload()[0..noise.plaintext_length_max];
    var sealed: [noise.prefix_length + noise.message_length_max]u8 = undefined;
    var opened: [noise.plaintext_length_max]u8 = undefined;
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        const frame = transports[0].encrypt_frame(plaintext, &sealed) catch unreachable;
        const result = (transports[1].decrypt_frame(frame, &opened) catch unreachable).?;
        checksum +%= result.plaintext[0];
    }
    return checksum;
}

var compressed_storage: [snappy.max_compressed_length(payload_bytes)]u8 = undefined;
var compressor: snappy.Compressor = .{};

fn bench_snappy_compress(iterations: u32) u64 {
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= compressor.compress(payload(), &compressed_storage).len;
    }
    return checksum;
}

fn bench_snappy_decompress(iterations: u32) u64 {
    const compressed = compressor.compress(payload(), &compressed_storage);
    var output: [payload_bytes]u8 = undefined;
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        const decoded = snappy.decompress(compressed, &output, payload_bytes) catch unreachable;
        checksum +%= decoded.len;
    }
    return checksum;
}

var rpc_scratch: rpc.RpcDefault = undefined;
var rpc_encoded: [payload_bytes + 256]u8 = undefined;

fn bench_rpc_decode(iterations: u32) u64 {
    rpc_scratch.reset();
    rpc_scratch.add_publish(.{ .topic = "/optimism/8453/3/blocks", .data = payload() }) catch {
        unreachable; // One publish fits the default limits.
    };
    const encoded = rpc_scratch.encode(&rpc_encoded);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        rpc_scratch.decode(encoded) catch unreachable;
        checksum +%= rpc_scratch.publish_slice().len;
    }
    return checksum;
}

var seen_cache: seen.SeenCache(8192) = .{};

fn bench_seen(iterations: u32) u64 {
    var checksum: u64 = 0;
    var id: seen.Id = @splat(0);
    for (0..iterations) |index| {
        // Sequential counters hashed by multiplication: uniform prefixes, unique ids.
        std.mem.writeInt(u64, id[0..8], @as(u64, index) *% 0x9e37_79b9_7f4a_7c15, .little);
        checksum +%= @intFromBool(seen_cache.insert(&id, index));
    }
    return checksum;
}

fn bench_message_id(_: ?*anyopaque, topic: []const u8, data: []const u8) seen.Id {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(topic);
    hasher.update(data);
    return hasher.finalResult()[0..20].*;
}

fn bench_router(iterations: u32) u64 {
    var prng = Prng.init(3);
    var router = router_module.Router.init(std.heap.page_allocator, .{
        .message_id = bench_message_id,
        .mcache = .{ .entries_max = 64, .arena_bytes = 16 * payload_bytes },
    }, prng.random()) catch @panic("bench router: out of memory");
    defer router.deinit(std.heap.page_allocator);
    const topic = router.subscribe("/optimism/8453/3/blocks") catch unreachable;
    var subscribe: rpc.RpcDefault = undefined;
    subscribe.reset();
    subscribe.add_subscription(.{ .subscribe = true, .topic_id = router.topic_name(topic) }) catch {
        unreachable; // One subscription fits the default limits.
    };
    var frame: [256]u8 = undefined;
    const subscribe_frame = subscribe.encode(&frame);
    for (0..8) |index| {
        var bytes: [34]u8 = @splat(@intCast(index + 1));
        bytes[0] = 0x12;
        bytes[1] = 32;
        const slot = router.add_peer(peer_id.from_bytes(&bytes) catch unreachable, true, null, 0).?;
        router.on_rpc(slot, subscribe_frame, 0) catch unreachable;
    }
    router.heartbeat(1);
    const output = std.heap.page_allocator.alloc(u8, payload_bytes + 4096) catch {
        @panic("bench router: out of memory");
    };
    defer std.heap.page_allocator.free(output);
    var data = payload().*;
    var checksum: u64 = 0;
    for (0..iterations) |index| {
        std.mem.writeInt(u64, data[0..8], index, .little);
        _ = router.publish(topic, &data, index + 2) catch unreachable;
        for (0..8) |slot| {
            while (router.drain(@intCast(slot), output)) |bytes| checksum +%= bytes.len;
        }
    }
    return checksum;
}

/// One hostile RPC per op against a router whose cache and delivery log are full
/// (1024 entries each, the production sizes): 4000 random IWANT ids and 1000 random
/// IDONTWANT ids, none of them cached. A heartbeat every 50 RPCs.
fn bench_control_flood(iterations: u32) u64 {
    var prng = Prng.init(4);
    var router = router_module.Router.init(std.heap.page_allocator, .{
        .message_id = bench_message_id,
        .mcache = .{ .entries_max = 1024, .arena_bytes = 1 << 20 },
    }, prng.random()) catch @panic("bench control flood: out of memory");
    defer router.deinit(std.heap.page_allocator);
    const topic = router.subscribe("/optimism/8453/3/blocks") catch unreachable;
    var bytes: [34]u8 = @splat(1);
    bytes[0] = 0x12;
    bytes[1] = 32;
    const attacker = router.add_peer(peer_id.from_bytes(&bytes) catch unreachable, true, null, 0).?;
    var data: [64]u8 = @splat(0);
    for (0..1024) |index| {
        std.mem.writeInt(u64, data[0..8], index, .little);
        _ = router.publish(topic, &data, 1) catch unreachable;
    }
    const ids = std.heap.page_allocator.alloc([20]u8, 5000) catch @panic("out of memory");
    defer std.heap.page_allocator.free(ids);
    var views: [5000][]const u8 = undefined;
    for (ids, &views) |*id, *view| {
        prng.fill(id);
        view.* = id;
    }
    var message: rpc.RpcDefault = undefined;
    message.reset();
    message.add_iwant(views[0..4000]) catch unreachable; // 4000 <= message_ids_max.
    for (0..1000 / 32) |index| {
        message.add_idontwant(views[4000 + index * 32 ..][0..32]) catch unreachable;
    }
    const frame = std.heap.page_allocator.alloc(u8, 256 * 1024) catch @panic("out of memory");
    defer std.heap.page_allocator.free(frame);
    const encoded = message.encode(frame);
    var now_ns: u64 = 2;
    for (0..iterations) |index| {
        if (index % 50 == 0) {
            now_ns += 500 * std.time.ns_per_ms;
            router.heartbeat(now_ns);
        }
        router.on_rpc(attacker, encoded, now_ns) catch unreachable;
    }
    return router.stats.slow_peer +% encoded.len;
}

test "p2p bench: cases run" {
    for (cases) |case| _ = case.run(1);
}

// ------------------------------------------------------------- end to end

/// Sequencer service -> noise -> verifier service for one 128 KiB block per op:
/// SSZ encode, sign, snappy, gossipsub publish and drain (sequencer); seal and open in
/// noise frames (wire); gossipsub decode, snappy, signature recovery, block-hash check,
/// SSZ decode, and pop (verifier). Yamux framing and socket IO are not included.
/// The sequencer-side block hash comes from the execution layer in production, so the
/// fixture computes the transactions root once and only rehashes the header per op.
const EndToEnd = struct {
    rollup: rollup_config.RollupConfig,
    sequencer_secret: [32]u8,
    services: [2]*service_module.Service,
    slots: [2]service_module.Slot,
    prngs: [2]Prng,
    wire: [2]noise.Transport,
    transaction_storage: []u8,
    transaction: []const u8,
    transactions_storage: []u8,
    transactions_root: primitives.B256,
    buffer: []u8,
    /// Where the receiving side's noise frames open into.
    opened: []u8,
    scratch: []u8,
    now_ns: u64,
    number: u64 = 0,

    const allocator = std.heap.page_allocator;
    const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };

    fn create() *EndToEnd {
        const fixture = allocator.create(EndToEnd) catch @panic("bench e2e: out of memory");
        fixture.init() catch |err| std.debug.panic("bench e2e: {s}", .{@errorName(err)});
        return fixture;
    }

    fn init(fixture: *EndToEnd) !void {
        fixture.rollup = .{ .l2_chain_id = 8453, .block_time = 2 };
        fixture.rollup.upgrades.set(.ecotone, 0);
        fixture.sequencer_secret = @splat(0);
        fixture.sequencer_secret[31] = 5;
        fixture.now_ns = 1_700_000_000 * std.time.ns_per_s;
        fixture.buffer = try allocator.alloc(u8, 2 * payload_bytes);
        fixture.opened = try allocator.alloc(u8, 2 * payload_bytes);
        fixture.scratch = try allocator.alloc(u8, snappy.gossip_size_max);
        var key_prng = Prng.init(0xe2e);
        fixture.wire = handshake(&key_prng);
        for (0..2) |index| fixture.services[index] = try fixture.create_service(index);
        try fixture.connect();
        try fixture.init_transaction();
    }

    fn create_service(fixture: *EndToEnd, index: usize) !*service_module.Service {
        var secret: secp256k1.SecretKey = @splat(0);
        secret[31] = @intCast(index + 1);
        const record = try enr.build(secret, .{
            .ip4 = .{ 10, 0, @intCast(index), 1 },
            .udp = 9000,
            .tcp = 9222,
            .opstack = .{ .chain_id = 8453 },
        });
        const signer: primitives.Address = .{
            .bytes = try common_secp256k1.address(fixture.sequencer_secret),
        };
        fixture.prngs[index] = Prng.init(index + 1);
        return service_module.Service.create(allocator, .{
            .rollup = &fixture.rollup,
            .unsafe_block_signer = signer,
            .disc = .{ .chain_id = 8453 },
            .mcache = .{ .entries_max = 64, .arena_bytes = 16 * payload_bytes },
            .accepted_bytes = 16 * payload_bytes,
        }, secret, record, fixture.prngs[index].random());
    }

    /// Links the two services directly and lets subscriptions and the mesh settle.
    fn connect(fixture: *EndToEnd) !void {
        for (0..2) |index| {
            const other = 1 - index;
            const record = &fixture.services[other].discovery.local_record;
            const remote = peer_id.from_public_key(record.public_key);
            const direction: Direction = if (index == 0) .outbound else .inbound;
            const address: IpAddress = .{ .ip4 = .{ 10, 0, @intCast(other), 1 } };
            try fixture.services[index].limits.begin(direction);
            fixture.slots[index] = try fixture.services[index].on_connected(
                remote,
                direction,
                address,
                fixture.now_ns,
            );
        }
        for (0..8) |_| {
            fixture.now_ns += std.time.ns_per_s;
            for (fixture.services) |service| service.tick(fixture.now_ns);
            _ = fixture.pump();
        }
    }

    fn init_transaction(fixture: *EndToEnd) !void {
        fixture.transaction_storage = try allocator.alloc(u8, payload_bytes + 1024);
        const deposit: consensus_types.Envelope = .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(1) },
            .from = .zero,
            .to = .create,
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = payload()[0 .. payload_bytes - 256],
        } };
        fixture.transaction = deposit.encode_to(fixture.transaction_storage);
        fixture.transactions_storage = try allocator.alloc(u8, fixture.transaction.len + 64);
        fixture.transactions_root = validity.transactions_root(fixture.transaction_list());
    }

    fn transaction_list(fixture: *EndToEnd) ssz.Transactions {
        return ssz.Transactions.encode(fixture.transactions_storage, &.{fixture.transaction});
    }

    /// Moves every queued RPC both ways through the noise wire; returns the frames moved.
    fn pump(fixture: *EndToEnd) u32 {
        var moved: u32 = 0;
        for (0..64) |_| {
            var any = false;
            for (0..2) |from| {
                const to = 1 - from;
                const service = fixture.services[from];
                const frame = service.drain_gossip(fixture.slots[from], fixture.buffer) orelse
                    continue;
                const opened = fixture.carry(from, frame);
                const header = (rpc.frame_decode(opened, rpc.frame_size_max_default) catch
                    unreachable).?;
                const receiver = fixture.services[to];
                receiver.on_gossip_frame(fixture.slots[to], header.payload, fixture.now_ns);
                moved += 1;
                any = true;
            }
            if (!any) break;
        }
        return moved;
    }

    /// Seals `frame` in noise frames and opens them on the other side into `opened`.
    fn carry(fixture: *EndToEnd, from: usize, frame: []const u8) []const u8 {
        assert(frame.len <= fixture.opened.len);
        var sealed: [noise.prefix_length + noise.message_length_max]u8 = undefined;
        var offset: usize = 0;
        while (offset < frame.len) {
            const take = @min(frame.len - offset, noise.plaintext_length_max);
            const chunk = frame[offset..][0..take];
            const out = fixture.wire[from].encrypt_frame(chunk, &sealed) catch unreachable;
            const target = fixture.opened[offset..][0..take];
            const opened = (fixture.wire[1 - from].decrypt_frame(out, target) catch
                unreachable).?;
            assert(opened.plaintext.len == take);
            offset += take;
        }
        return fixture.opened[0..frame.len];
    }

    /// One block. With `deliver` false the sequencer's frames are drained and dropped,
    /// which isolates the sequencer stage.
    fn step(fixture: *EndToEnd, deliver: bool) u64 {
        fixture.number += 1;
        fixture.now_ns += 2 * std.time.ns_per_s;
        var value: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = fixture.number,
            .timestamp = fixture.now_ns / std.time.ns_per_s,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = fixture.transaction_list(),
        };
        const header = validity.header_from_payload(
            &fixture.rollup,
            &value,
            beacon_root,
            fixture.transactions_root,
        );
        value.block_hash = header.hash();
        const sequencer = fixture.services[0];
        const secret = fixture.sequencer_secret;
        _ = sequencer.publish_block(secret, beacon_root, value, fixture.now_ns) catch
            @panic("bench e2e: publish failed");
        if (!deliver) {
            var bytes: u64 = 0;
            const slot = fixture.slots[0];
            while (sequencer.drain_gossip(slot, fixture.buffer)) |frame| bytes += frame.len;
            assert(bytes > 0);
            return bytes;
        }
        _ = fixture.pump();
        const verifier = fixture.services[1];
        verifier.tick(fixture.now_ns);
        const envelope = verifier.pop_block(fixture.scratch) orelse
            @panic("bench e2e: block not delivered");
        assert(envelope.payload.block_number == fixture.number);
        return envelope.payload.transactions.bytes.len;
    }
};

var end_to_end: ?*EndToEnd = null;
var sequencer_only: ?*EndToEnd = null;

fn bench_end_to_end(iterations: u32) u64 {
    const fixture = end_to_end orelse blk: {
        end_to_end = EndToEnd.create();
        break :blk end_to_end.?;
    };
    var checksum: u64 = 0;
    for (0..iterations) |_| checksum +%= fixture.step(true);
    return checksum;
}

fn bench_sequencer(iterations: u32) u64 {
    const fixture = sequencer_only orelse blk: {
        sequencer_only = EndToEnd.create();
        break :blk sequencer_only.?;
    };
    var checksum: u64 = 0;
    for (0..iterations) |_| checksum +%= fixture.step(false);
    return checksum;
}

// ------------------------------------------------------------- verifier stages

/// One signed, compressed 128 KiB v3 block, built from the end-to-end fixture.
const Message = struct {
    fixture: *EndToEnd,
    bytes: []u8,

    fn get() *const Message {
        if (message_ready) return &message_storage;
        const fixture = EndToEnd.create();
        var value: ssz.ExecutionPayload = .{
            .version = .v3,
            .block_number = 1,
            .timestamp = fixture.now_ns / std.time.ns_per_s,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = fixture.transaction_list(),
        };
        const root = EndToEnd.beacon_root;
        value.block_hash = validity.header_from_payload(
            &fixture.rollup,
            &value,
            root,
            fixture.transactions_root,
        ).hash();
        const length = block.signed_length(value);
        const out_length = snappy.max_compressed_length(length);
        const out = std.heap.page_allocator.alloc(u8, @intCast(out_length)) catch unreachable;
        const scratch = std.heap.page_allocator.alloc(u8, @intCast(length)) catch unreachable;
        var message_compressor: snappy.Compressor = .{};
        const secret = fixture.sequencer_secret;
        const bytes = block.encode_signed(
            8453,
            secret,
            root,
            value,
            scratch,
            &message_compressor,
            out,
        ) catch unreachable;
        message_storage = .{ .fixture = fixture, .bytes = bytes };
        message_ready = true;
        return &message_storage;
    }
};

var message_storage: Message = undefined;
var message_ready = false;

fn bench_sha256(iterations: u32) u64 {
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        var hasher = sha256.Hasher.init();
        hasher.update(payload());
        checksum +%= hasher.final()[0];
    }
    return checksum;
}

fn bench_keccak(iterations: u32) u64 {
    var checksum: u64 = 0;
    for (0..iterations) |_| checksum +%= keccak.keccak256(payload())[0];
    return checksum;
}

fn bench_message_id_stage(iterations: u32) u64 {
    const message = Message.get();
    const topic = "/optimism/8453/2/blocks";
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= block.message_id(topic, message.bytes, message.fixture.scratch)[0];
    }
    return checksum;
}

fn bench_block_decode(iterations: u32) u64 {
    const message = Message.get();
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        const envelope = block.decode(.v3, message.bytes, message.fixture.scratch) catch
            unreachable;
        checksum +%= envelope.payload_hash.bytes[0];
    }
    return checksum;
}

fn bench_transactions_root(iterations: u32) u64 {
    const message = Message.get();
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= validity.transactions_root(message.fixture.transaction_list()).bytes[0];
    }
    return checksum;
}

fn bench_check_transactions(iterations: u32) u64 {
    const message = Message.get();
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        validity.check_transactions(message.fixture.transaction_list()) catch unreachable;
        checksum += 1;
    }
    return checksum;
}

fn bench_recover_signer(iterations: u32) u64 {
    const message = Message.get();
    const envelope = block.decode(.v3, message.bytes, message.fixture.scratch) catch
        unreachable;
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        const signer = block.recover_signer(&envelope, 8453) orelse unreachable;
        checksum +%= signer.bytes[0];
    }
    return checksum;
}

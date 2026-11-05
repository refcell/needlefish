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
};

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

test "p2p bench: cases run" {
    for (cases) |case| _ = case.run(1);
}

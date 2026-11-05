//! Simulated packet network with fault injection.
//!
//! Packets are delivered in `(deliver_ns, sequence)` order, so delivery is a pure
//! function of the seed. Random per-packet latency produces reordering; drops,
//! duplicates, and partitions are injected from config. Crashed nodes are modelled
//! by the cluster, which discards packets addressed to them on delivery.
//!
//! In-flight capacity is fixed at init. A full network drops the packet and counts it:
//! senders must tolerate loss anyway.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../prng.zig").Prng;

pub const NodeId = u8;
pub const node_count_max = 8;

pub const Config = struct {
    latency_ns_min: u64 = 1 * std.time.ns_per_ms,
    latency_ns_max: u64 = 50 * std.time.ns_per_ms,
    /// Probability of dropping a packet, in parts per million.
    drop_ppm: u32 = 0,
    /// Probability of delivering a packet twice, in parts per million.
    duplicate_ppm: u32 = 0,
    /// Maximum packets in flight.
    capacity: u32 = 4096,
};

pub const Stats = struct {
    sent: u64 = 0,
    delivered: u64 = 0,
    dropped_random: u64 = 0,
    dropped_partition: u64 = 0,
    dropped_full: u64 = 0,
    duplicated: u64 = 0,
};

pub fn Network(comptime Message: type) type {
    return struct {
        const Self = @This();

        pub const Packet = struct {
            deliver_ns: u64,
            sequence: u64,
            from: NodeId,
            to: NodeId,
            message: Message,
        };

        config: Config,
        heap: []Packet,
        count: u32 = 0,
        sequence: u64 = 0,
        /// Nodes in different groups cannot exchange packets.
        group: [node_count_max]u8 = @splat(0),
        stats: Stats = .{},

        pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
            assert(config.capacity > 0);
            assert(config.latency_ns_min <= config.latency_ns_max);
            assert(config.drop_ppm <= 1_000_000);
            assert(config.duplicate_ppm <= 1_000_000);
            const heap = try allocator.alloc(Packet, config.capacity);
            return .{ .config = config, .heap = heap };
        }

        pub fn deinit(network: *Self, allocator: std.mem.Allocator) void {
            allocator.free(network.heap);
            network.* = undefined;
        }

        pub fn send(
            network: *Self,
            prng: *Prng,
            now_ns: u64,
            from: NodeId,
            to: NodeId,
            message: Message,
        ) void {
            assert(from < node_count_max);
            assert(to < node_count_max);
            assert(from != to);
            network.stats.sent += 1;
            if (prng.chance(network.config.drop_ppm, 1_000_000)) {
                network.stats.dropped_random += 1;
                return;
            }
            const copies: u32 = if (prng.chance(network.config.duplicate_ppm, 1_000_000)) 2 else 1;
            network.stats.duplicated += copies - 1;
            var copy: u32 = 0;
            while (copy < copies) : (copy += 1) {
                const latency_ns = prng.range(
                    network.config.latency_ns_min,
                    network.config.latency_ns_max,
                );
                network.push(.{
                    .deliver_ns = now_ns + latency_ns,
                    .sequence = network.sequence,
                    .from = from,
                    .to = to,
                    .message = message,
                });
                network.sequence += 1;
            }
        }

        /// Next packet due at or before `now_ns`, skipping packets cut by a partition.
        pub fn pop_due(network: *Self, now_ns: u64) ?Packet {
            while (network.count > 0) {
                if (network.heap[0].deliver_ns > now_ns) return null;
                const packet = network.pop();
                assert(packet.deliver_ns <= now_ns);
                if (network.group[packet.from] != network.group[packet.to]) {
                    network.stats.dropped_partition += 1;
                    continue;
                }
                network.stats.delivered += 1;
                return packet;
            }
            return null;
        }

        pub fn partition(network: *Self, group: [node_count_max]u8) void {
            network.group = group;
        }

        pub fn heal(network: *Self) void {
            network.group = @splat(0);
        }

        pub fn partitioned(network: *const Self) bool {
            for (network.group) |g| if (g != 0) return true;
            return false;
        }

        fn less(a: Packet, b: Packet) bool {
            if (a.deliver_ns != b.deliver_ns) return a.deliver_ns < b.deliver_ns;
            assert(a.sequence != b.sequence);
            return a.sequence < b.sequence;
        }

        fn push(network: *Self, packet: Packet) void {
            if (network.count == network.heap.len) {
                network.stats.dropped_full += 1;
                return;
            }
            var index: usize = network.count;
            network.heap[index] = packet;
            network.count += 1;
            while (index > 0) {
                const parent = (index - 1) / 2;
                if (!less(network.heap[index], network.heap[parent])) break;
                std.mem.swap(Packet, &network.heap[index], &network.heap[parent]);
                index = parent;
            }
        }

        fn pop(network: *Self) Packet {
            assert(network.count > 0);
            const top = network.heap[0];
            network.count -= 1;
            network.heap[0] = network.heap[network.count];
            const count: usize = network.count;
            var index: usize = 0;
            while (true) {
                const left = 2 * index + 1;
                if (left >= count) break;
                var child = left;
                if (left + 1 < count and less(network.heap[left + 1], network.heap[left])) {
                    child = left + 1;
                }
                if (!less(network.heap[child], network.heap[index])) break;
                std.mem.swap(Packet, &network.heap[index], &network.heap[child]);
                index = child;
            }
            return top;
        }
    };
}

const TestNetwork = Network(u64);

test "network: delivers in time order with sequence tie-break" {
    var prng = Prng.init(1);
    var network = try TestNetwork.init(std.testing.allocator, .{ .capacity = 512 });
    defer network.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 500) : (i += 1) network.send(&prng, i, 0, 1, i);
    var last_ns: u64 = 0;
    var delivered: u64 = 0;
    while (network.pop_due(std.math.maxInt(u64))) |packet| {
        try std.testing.expect(packet.deliver_ns >= last_ns);
        last_ns = packet.deliver_ns;
        delivered += 1;
    }
    try std.testing.expectEqual(@as(u64, 500), delivered);
    try std.testing.expectEqual(@as(u32, 0), network.count);
}

test "network: partition drops cross-group packets" {
    var prng = Prng.init(2);
    var network = try TestNetwork.init(std.testing.allocator, .{});
    defer network.deinit(std.testing.allocator);
    var group: [node_count_max]u8 = @splat(0);
    group[1] = 1;
    network.partition(group);
    network.send(&prng, 0, 0, 1, 7);
    network.send(&prng, 0, 0, 2, 8);
    const packet = network.pop_due(std.math.maxInt(u64)).?;
    try std.testing.expectEqual(@as(u64, 8), packet.message);
    try std.testing.expect(network.pop_due(std.math.maxInt(u64)) == null);
    try std.testing.expectEqual(@as(u64, 1), network.stats.dropped_partition);
}

test "network: full network drops and counts" {
    var prng = Prng.init(3);
    var network = try TestNetwork.init(std.testing.allocator, .{ .capacity = 4 });
    defer network.deinit(std.testing.allocator);
    var i: u64 = 0;
    while (i < 10) : (i += 1) network.send(&prng, 0, 0, 1, i);
    try std.testing.expectEqual(@as(u64, 6), network.stats.dropped_full);
}

fn fuzz_network(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var network = try TestNetwork.init(std.testing.allocator, .{
        .capacity = 64,
        .drop_ppm = smith.valueRangeAtMost(u32, 0, 1_000_000),
        .duplicate_ppm = smith.valueRangeAtMost(u32, 0, 1_000_000),
    });
    defer network.deinit(std.testing.allocator);
    var now_ns: u64 = 0;
    var last_ns: u64 = 0;
    var step: u32 = 0;
    while (step < 256 and !smith.eos()) : (step += 1) {
        now_ns += smith.valueRangeAtMost(u64, 0, 100 * std.time.ns_per_ms);
        if (smith.value(bool)) network.send(&prng, now_ns, 0, 1, now_ns);
        while (network.pop_due(now_ns)) |packet| {
            try std.testing.expect(packet.deliver_ns <= now_ns);
            try std.testing.expect(packet.deliver_ns >= last_ns);
            last_ns = packet.deliver_ns;
        }
    }
    const s = network.stats;
    try std.testing.expect(s.delivered + s.dropped_random + s.dropped_full + network.count <=
        s.sent + s.duplicated);
}

test "network: fuzz ordering and accounting" {
    try @import("../fuzz.zig").run({}, fuzz_network, .{ .iterations = 128 });
}

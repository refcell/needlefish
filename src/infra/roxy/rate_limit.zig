//! Per-client token-bucket rate limits for roxy (base/base proxyd-style: a client over its
//! rate gets HTTP 429 with JSON-RPC error -32016, "over rate limit").
//!
//! Clients are keyed by IP (resolved through `utilities/trusted_proxy`, so clients behind a
//! trusted load balancer get their own buckets). Buckets live in a fixed-capacity
//! open-addressing table: a lookup probes at most `probe_max` slots; when the client has no
//! bucket and none of those slots is free, the slot idle longest is evicted. An evicted
//! client restarts with a full bucket, so eviction can only make the limiter more lenient,
//! never block a client wrongly. No allocation after init.
//!
//! Tokens are kept in millitokens so refill is exact in integer arithmetic.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../../utilities/io/common.zig");

pub const Address = io_common.Address;

pub const Options = struct {
    /// Sustained requests per second per client; 0 disables limiting.
    requests_per_s: u32 = 0,
    /// Bucket size: requests a client may burst after idling.
    burst: u32 = 20,

    pub fn enabled(options: Options) bool {
        return options.requests_per_s > 0;
    }
};

pub const probe_max = 8;

pub fn Limiter(comptime buckets_max: u32) type {
    comptime assert(std.math.isPowerOfTwo(buckets_max));
    comptime assert(buckets_max >= probe_max);
    return struct {
        const Self = @This();

        const Bucket = struct {
            used: bool = false,
            key: [17]u8 = undefined,
            millitokens: u64 = 0,
            last_ms: u64 = 0,
        };

        options: Options,
        buckets: [buckets_max]Bucket = @splat(.{}),
        evictions: u64 = 0,

        pub fn init(options: Options) Self {
            assert(options.enabled());
            assert(options.burst > 0);
            return .{ .options = options };
        }

        fn key_of(client: Address) [17]u8 {
            var key: [17]u8 = undefined;
            key[0] = @backingInt(client.family);
            key[1..17].* = client.bytes;
            return key;
        }

        /// Takes one token for `client`; false when the client is over its rate.
        pub fn allow(limiter: *Self, client: Address, now_ms: u64) bool {
            const capacity = @as(u64, limiter.options.burst) * 1000;
            const bucket = limiter.find(key_of(client), now_ms);
            assert(bucket.used);
            const elapsed_ms = now_ms -| bucket.last_ms;
            const refill = elapsed_ms *| limiter.options.requests_per_s;
            bucket.millitokens = @min(capacity, bucket.millitokens +| refill);
            bucket.last_ms = @max(bucket.last_ms, now_ms);
            if (bucket.millitokens < 1000) return false;
            bucket.millitokens -= 1000;
            assert(bucket.millitokens <= capacity);
            return true;
        }

        /// The bucket for `key`, creating it full (in a free slot or by eviction).
        fn find(limiter: *Self, key: [17]u8, now_ms: u64) *Bucket {
            const start: u32 = @truncate(std.hash.Wyhash.hash(0x0b0c, &key));
            var free: ?*Bucket = null;
            var stalest: *Bucket = &limiter.buckets[start & (buckets_max - 1)];
            for (0..probe_max) |offset| {
                const index = (start +% @as(u32, @intCast(offset))) & (buckets_max - 1);
                const bucket = &limiter.buckets[index];
                if (!bucket.used) {
                    if (free == null) free = bucket;
                    continue;
                }
                if (std.mem.eql(u8, &bucket.key, &key)) return bucket;
                if (bucket.last_ms < stalest.last_ms or !stalest.used) stalest = bucket;
            }
            const slot = free orelse evict: {
                limiter.evictions += 1;
                break :evict stalest;
            };
            slot.* = .{
                .used = true,
                .key = key,
                .millitokens = @as(u64, limiter.options.burst) * 1000,
                .last_ms = now_ms,
            };
            return slot;
        }
    };
}

/// Body of the 429 answer (JSON-RPC error, id null as in proxyd).
pub const over_limit_body =
    "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32016,\"message\":\"over rate limit\"}}";

const testing = std.testing;

test "rate limit: burst, then the sustained rate" {
    var limiter = Limiter(64).init(.{ .requests_per_s = 10, .burst = 5 });
    const client = Address.ip4(.{ 203, 0, 113, 7 }, 0);
    for (0..5) |_| try testing.expect(limiter.allow(client, 0));
    try testing.expect(!limiter.allow(client, 0));
    // 100 ms refills one token at 10 req/s.
    try testing.expect(limiter.allow(client, 100));
    try testing.expect(!limiter.allow(client, 150));
    // Another client has its own bucket.
    try testing.expect(limiter.allow(Address.ip4(.{ 203, 0, 113, 8 }, 0), 150));
    // Idle refills only up to the burst.
    var allowed: u32 = 0;
    for (0..20) |_| allowed += @intFromBool(limiter.allow(client, 60_000));
    try testing.expectEqual(@as(u32, 5), allowed);
}

test "rate limit: a full table evicts the idlest bucket" {
    var limiter = Limiter(8).init(.{ .requests_per_s = 1, .burst = 1 });
    for (0..64) |index| {
        _ = limiter.allow(Address.ip4(.{ 10, 0, 0, @intCast(index) }, 0), index);
    }
    try testing.expect(limiter.evictions > 0);
    // An evicted client starts again with a full bucket.
    try testing.expect(limiter.allow(Address.ip4(.{ 10, 0, 0, 0 }, 0), 100));
}

fn check_rate(random: std.Random) !void {
    const rate = random.intRangeAtMost(u32, 1, 1000);
    const burst = random.intRangeAtMost(u32, 1, 100);
    var limiter = Limiter(16).init(.{ .requests_per_s = rate, .burst = burst });
    var allowed: [4]u64 = @splat(0);
    var now_ms: u64 = 0;
    for (0..500) |_| {
        now_ms += random.uintAtMost(u64, 50);
        const client_index = random.uintLessThan(u8, 4);
        const client = Address.ip4(.{ 198, 51, 100, client_index }, 0);
        allowed[client_index] += @intFromBool(limiter.allow(client, now_ms));
    }
    // No eviction with 4 clients in 16 buckets, so each stays within burst + rate * time.
    try testing.expectEqual(@as(u64, 0), limiter.evictions);
    for (allowed) |count| try testing.expect(count <= burst + rate * now_ms / 1000);
}

test "rate limit: seeded fuzz never exceeds burst plus rate" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7a7e);
    for (0..200) |_| try check_rate(prng.random());
}

test "rate limit: fuzz never exceeds burst plus rate" {
    try testing.fuzz({}, fuzz_rate, .{});
}

fn fuzz_rate(_: void, smith: *testing.Smith) anyerror!void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    try check_rate(prng.random());
}

//! Storage roots of the L2ToL1MessagePasser predeploy for pre-Isthmus output roots
//! (base/base `EngineQueries::OutputAtBlock`: `eth_getProof(L2_TO_L1_MESSAGE_PASSER, [])`
//! at the block, using `storageHash`). From Isthmus the block header's `withdrawalsRoot`
//! carries the root and no proof is needed.
//!
//! Same discipline as `l2_provider.zig`: a miss enqueues one `eth_getProof` keyed by block
//! hash (immutable, so entries never expire) and returns `error.NotAvailable`; the caller
//! asks again later. Failed or mismatched responses are dropped and re-requested on the next
//! query. Like base/base, the proof itself is not verified: the execution client is trusted.
//! Bounds: one request in flight, a fixed de-duplicating queue, a fixed LRU cache.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const predeploys = @import("../../common/consensus/predeploys.zig");
const errors = @import("../derive/errors.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const ProviderError = errors.ProviderError;

pub const entries_max = 64;
pub const queue_size_max = 8;
const request_size_max = 512;

pub const Options = struct {
    jwt_secret: ?jwt.Secret = null,
};

pub const Stats = struct { requests: u64 = 0, failures: u64 = 0, hits: u64 = 0 };

const Entry = struct { used: u64 = 0, hash: B256 = .zero, root: B256 = .zero };

pub const ParseError = error{InvalidProof};

/// The `storageHash` of an `eth_getProof` result, checked to be for the message passer.
pub fn parse_storage_hash(raw: []const u8) ParseError!B256 {
    const address_raw = (json.find_path(raw, &.{"address"}) catch null) orelse
        return error.InvalidProof;
    const address = parse_string_fixed(20, address_raw) catch return error.InvalidProof;
    if (!std.mem.eql(u8, &address, &predeploys.l2_to_l1_message_passer.bytes)) {
        return error.InvalidProof;
    }
    const hash_raw = (json.find_path(raw, &.{"storageHash"}) catch null) orelse
        return error.InvalidProof;
    const hash = parse_string_fixed(32, hash_raw) catch return error.InvalidProof;
    assert(hash.len == 32);
    return .{ .bytes = hash };
}

fn parse_string_fixed(comptime N: usize, raw: []const u8) error{Invalid}![N]u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.Invalid;
    const text = raw[1 .. raw.len - 1];
    // Addresses may be checksummed; parse_fixed accepts either case.
    return json.parse_fixed(N, text) catch return error.Invalid;
}

pub fn MessagePasserRoots(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        client: Rpc,
        options: Options,
        entries: [entries_max]Entry = @splat(.{}),
        queue: [queue_size_max]B256 = undefined,
        queue_count: u32 = 0,
        in_flight: ?B256 = null,
        clock: u64 = 0,
        stats: Stats = .{},

        /// `roots` must not move after `init` while a request is in flight.
        pub fn init(
            roots: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            options: Options,
        ) !void {
            const client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            roots.* = .{ .io = io, .client = client, .options = options };
            assert(roots.queue_count == 0);
            assert(roots.in_flight == null);
        }

        pub fn deinit(roots: *Self) void {
            assert(roots.in_flight == null);
            roots.client.deinit();
            roots.* = undefined;
        }

        pub fn tick(roots: *Self) void {
            assert(roots.queue_count <= queue_size_max);
            roots.client.http.tick();
            roots.pump();
        }

        pub fn busy(roots: *const Self) bool {
            return roots.in_flight != null or roots.queue_count > 0;
        }

        /// The message passer storage root at block `hash`; a miss starts a fetch.
        pub fn storage_root(roots: *Self, hash: B256) ProviderError!B256 {
            assert(roots.queue_count <= queue_size_max);
            for (&roots.entries) |*entry| {
                if (entry.used == 0 or !entry.hash.eql(hash)) continue;
                roots.clock += 1;
                entry.used = roots.clock;
                roots.stats.hits += 1;
                return entry.root;
            }
            roots.enqueue(hash);
            roots.pump();
            return error.NotAvailable;
        }

        fn enqueue(roots: *Self, hash: B256) void {
            if (roots.in_flight) |current| {
                if (current.eql(hash)) return;
            }
            for (roots.queue[0..roots.queue_count]) |queued| {
                if (queued.eql(hash)) return;
            }
            if (roots.queue_count == queue_size_max) {
                // Newest first: drop the oldest queued request.
                std.mem.copyForwards(B256, roots.queue[0 .. queue_size_max - 1], roots.queue[1..]);
                roots.queue_count -= 1;
            }
            roots.queue[roots.queue_count] = hash;
            roots.queue_count += 1;
            assert(roots.queue_count <= queue_size_max);
        }

        fn pump(roots: *Self) void {
            var attempts: u32 = 0;
            while (attempts < queue_size_max) : (attempts += 1) {
                if (roots.in_flight != null or roots.queue_count == 0) return;
                if (roots.client.http.busy()) return;
                roots.in_flight = roots.queue[0];
                const pending = roots.queue[0..roots.queue_count];
                std.mem.copyForwards(B256, pending[0 .. pending.len - 1], pending[1..]);
                roots.queue_count -= 1;
                roots.stats.requests += 1;
                if (roots.options.jwt_secret) |secret| {
                    var token_buffer: [jwt.token_size_max]u8 = undefined;
                    const now_s = roots.io.now_realtime_ns() / std.time.ns_per_s;
                    roots.client.set_bearer(jwt.create(secret, now_s, &token_buffer));
                }
                const hash = &roots.in_flight.?;
                const method = "eth_getProof";
                roots.client.call(*Self, roots, on_result, method, hash, write_params) catch {
                    roots.in_flight = null;
                    roots.stats.failures += 1;
                    continue;
                };
                return;
            }
        }

        fn write_params(hash: *const B256, writer: *json.Writer) json.Writer.WriteError!void {
            try writer.data(&predeploys.l2_to_l1_message_passer.bytes);
            try writer.begin_array();
            try writer.end_array();
            try writer.data(&hash.bytes);
        }

        fn on_result(
            roots: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &roots.client);
            const hash = roots.in_flight.?;
            roots.in_flight = null;
            defer roots.pump();
            const outcome = result catch return roots.fail();
            const raw = switch (outcome) {
                .ok => |raw| raw,
                .rpc_error => return roots.fail(),
            };
            const root = parse_storage_hash(raw) catch return roots.fail();
            roots.insert(hash, root);
        }

        fn fail(roots: *Self) void {
            roots.stats.failures += 1;
        }

        fn insert(roots: *Self, hash: B256, root: B256) void {
            var victim = &roots.entries[0];
            for (&roots.entries) |*entry| {
                if (entry.used < victim.used) victim = entry;
            }
            roots.clock += 1;
            victim.* = .{ .used = roots.clock, .hash = hash, .root = root };
            assert(victim.used != 0);
        }
    };
}

const testing = std.testing;
const harness_module = @import("sim_harness.zig");
const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Prng = @import("../../testing/prng.zig").Prng;
const Roots = MessagePasserRoots(@import("../../utilities/io/root.zig").SimIo);

const proof_json =
    \\{"address":"0x4200000000000000000000000000000000000016","accountProof":[],
    \\"balance":"0x0","codeHash":"0x00","nonce":"0x0","storageProof":[],
    \\"storageHash":"0x8ed4baae3a927be3dea54996b4d5899f8c01e7594bf50b17dc1e741388ce3d12"}
;

fn write_proof(buffer: []u8, address: Address, hash: B256) ![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try writer.begin_object();
    try writer.key("address");
    try writer.data(&address.bytes);
    try writer.key("storageProof");
    try writer.begin_array();
    try writer.end_array();
    try writer.key("storageHash");
    try writer.data(&hash.bytes);
    try writer.end_object();
    return out.buffered();
}

test "message passer roots: parses storageHash for the message passer only" {
    const root = try parse_storage_hash(proof_json);
    try testing.expectEqual(@as(u8, 0x8e), root.bytes[0]);
    try testing.expectEqual(@as(u8, 0x12), root.bytes[31]);
    var buffer: [512]u8 = undefined;
    const other = try write_proof(&buffer, .{ .bytes = @splat(1) }, root);
    try testing.expectError(error.InvalidProof, parse_storage_hash(other));
    try testing.expectError(error.InvalidProof, parse_storage_hash("{}"));
    try testing.expectError(error.InvalidProof, parse_storage_hash("null"));
    const short = "{\"address\":\"0x4200000000000000000000000000000000000016\"," ++
        "\"storageHash\":\"0x01\"}";
    try testing.expectError(error.InvalidProof, parse_storage_hash(short));
}

test "message passer roots: seeded fuzz round-trips storage hashes" {
    var prng = Prng.init(0x16);
    var buffer: [512]u8 = undefined;
    for (0..256) |_| {
        var hash: B256 = undefined;
        prng.fill(&hash.bytes);
        const raw = try write_proof(&buffer, predeploys.l2_to_l1_message_passer, hash);
        try testing.expect((try parse_storage_hash(raw)).eql(hash));
        // Truncation inside the values is rejected (only the path is validated, so a
        // missing closing brace alone is accepted).
        const cut = prng.below(raw.len - 1);
        if (parse_storage_hash(raw[0..cut])) |_| return error.TestUnexpectedResult else |_| {}
    }
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    const length = smith.slice(&buffer);
    _ = parse_storage_hash(buffer[0..length]) catch {};
}

test "message passer roots: fuzz eth_getProof results" {
    try testing.fuzz({}, fuzz_parse, .{});
}

test "message passer roots: fetches once per block hash and caches" {
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getProof", .params_contain = "0x42", .result = proof_json });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x16);
    defer harness.deinit();
    var roots: Roots = undefined;
    try roots.init(
        testing.allocator,
        &harness.client_io,
        harness.address,
        harness_module.client_options,
        .{ .jwt_secret = .{ .bytes = @splat(7) } },
    );
    defer roots.deinit();
    const block: B256 = .{ .bytes = @splat(0xb1) };
    try testing.expectError(error.NotAvailable, roots.storage_root(block));
    try testing.expectError(error.NotAvailable, roots.storage_root(block)); // De-duplicated.
    for (0..8) |_| {
        roots.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 4);
    }
    const root = try roots.storage_root(block);
    try testing.expectEqual(@as(u8, 0x8e), root.bytes[0]);
    try testing.expectEqual(@as(u64, 1), roots.stats.requests);
    try testing.expectEqual(@as(u64, 1), roots.stats.hits);
    try testing.expect(std.mem.indexOf(u8, fake.body(), "0xb1b1") != null);
    try testing.expect(std.mem.startsWith(u8, fake.authorization(), "Bearer "));
    try testing.expect(!roots.busy());
}

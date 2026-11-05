//! Follow mode source (base/base `service/follow`): instead of deriving, the node fetches
//! L2 blocks from a source node's execution RPC (`--source-l2-rpc`), in order, and inserts
//! them as unsafe payloads; every 30 s it reads the source's `safe` and `finalized` labels,
//! which the node promotes after checking them against its own chain.
//!
//! `Follower(IO)` is the source side as a non-blocking state machine: one request in flight
//! (the next block, or a label), one decoded block waiting for the node (`ready`, consumed
//! with `consume`), and a retry backoff after a missing block or a failure. Deviations from
//! base/base: no prefetch window (one block at a time), no proof gate, and no L1 origin
//! check of promoted labels.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const protocol = @import("../protocol/root.zig");
const l2_block_full = @import("../sources/l2_block_full.zig");
const header_json = @import("../sources/header_json.zig");

const BlockInfo = protocol.block.BlockInfo;
pub const PayloadEnvelope = l2_block_full.PayloadEnvelope;

/// base/base `SAFETY_POLL_INTERVAL`.
pub const label_poll_interval_ns: u64 = 30 * std.time.ns_per_s;
/// Wait before asking again for a block the source does not have yet, or after a failure.
pub const retry_interval_ns: u64 = std.time.ns_per_s;
const request_size_max = 256;

pub const Label = enum { safe, finalized };

pub const Stats = struct {
    blocks: u64 = 0,
    not_found: u64 = 0,
    failures: u64 = 0,
    label_reads: u64 = 0,
};

/// The source's labels from the latest completed poll (null where the source has none).
pub const Labels = struct {
    safe: ?BlockInfo = null,
    finalized: ?BlockInfo = null,
};

const Request = union(enum) { block: u64, label: Label };

pub fn Follower(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        client: Rpc,
        arena: std.heap.ArenaAllocator,
        limits: l2_block_full.Limits = .{},
        in_flight: ?Request = null,
        /// The next block number to fetch once the node's unsafe head reaches its parent.
        next_number: u64 = 0,
        ready: ?PayloadEnvelope = null,
        retry_at_ns: u64 = 0,
        labels_polled_ns: ?u64 = null,
        labels_reading: Labels = .{},
        labels: ?Labels = null,
        stats: Stats = .{},

        /// `follower` must not move after `init` while a request is in flight.
        pub fn init(
            follower: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
        ) !void {
            const client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            follower.* = .{ .io = io, .client = client, .arena = .init(allocator) };
            assert(follower.in_flight == null);
            assert(follower.ready == null);
        }

        pub fn deinit(follower: *Self) void {
            assert(follower.in_flight == null);
            follower.client.deinit();
            follower.arena.deinit();
            follower.* = undefined;
        }

        pub fn busy(follower: *const Self) bool {
            return follower.in_flight != null;
        }

        /// Starts the next request when idle. `unsafe_number` is the node's unsafe head;
        /// blocks are only fetched while `fetch` (the node can insert one).
        pub fn tick(follower: *Self, unsafe_number: u64, fetch: bool) void {
            follower.client.http.tick();
            if (follower.in_flight != null) return;
            if (follower.client.http.busy()) return;
            const now_ns = follower.io.now_monotonic_ns();
            if (follower.labels_due(now_ns)) {
                follower.labels_polled_ns = now_ns;
                follower.labels_reading = .{};
                return follower.start(.{ .label = .safe });
            }
            if (!fetch or follower.ready != null or now_ns < follower.retry_at_ns) return;
            // A reset or a reorg moves the head; always continue from it.
            follower.next_number = unsafe_number + 1;
            follower.start(.{ .block = follower.next_number });
            assert(follower.next_number > unsafe_number);
        }

        fn labels_due(follower: *const Self, now_ns: u64) bool {
            const polled_ns = follower.labels_polled_ns orelse return true;
            assert(now_ns >= polled_ns);
            return now_ns - polled_ns >= label_poll_interval_ns;
        }

        /// The fetched block, valid until `consume`.
        pub fn take(follower: *const Self) ?*const PayloadEnvelope {
            if (follower.ready) |*envelope| return envelope;
            return null;
        }

        pub fn consume(follower: *Self) void {
            assert(follower.ready != null);
            follower.ready = null;
            _ = follower.arena.reset(.{ .retain_with_limit = 4 * 1024 * 1024 });
            assert(follower.take() == null);
        }

        /// The labels of the last completed poll, once.
        pub fn take_labels(follower: *Self) ?Labels {
            const labels = follower.labels orelse return null;
            follower.labels = null;
            return labels;
        }

        fn start(follower: *Self, request: Request) void {
            assert(follower.in_flight == null);
            follower.in_flight = request;
            const method = "eth_getBlockByNumber";
            const params = &follower.in_flight.?;
            follower.client.call(*Self, follower, on_result, method, params, write_params) catch {
                follower.in_flight = null;
                follower.fail();
            };
        }

        fn write_params(request: *const Request, writer: *json.Writer) json.Writer.WriteError!void {
            switch (request.*) {
                .block => |number| {
                    try writer.quantity(number);
                    try writer.boolean(true);
                },
                .label => |label| {
                    try writer.string(@tagName(label));
                    try writer.boolean(false);
                },
            }
        }

        fn on_result(
            follower: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &follower.client);
            const request = follower.in_flight.?;
            follower.in_flight = null;
            const outcome = result catch return follower.fail();
            const raw = switch (outcome) {
                .ok => |raw| raw,
                .rpc_error => return follower.fail(),
            };
            switch (request) {
                .block => |number| follower.on_block(number, raw),
                .label => |label| follower.on_label(label, raw),
            }
        }

        fn on_block(follower: *Self, number: u64, raw: []const u8) void {
            assert(follower.ready == null);
            if (std.mem.eql(u8, raw, "null")) {
                follower.stats.not_found += 1;
                follower.retry_at_ns = follower.io.now_monotonic_ns() + retry_interval_ns;
                return;
            }
            const allocator = follower.arena.allocator();
            const envelope = l2_block_full.decode_envelope(allocator, raw, follower.limits) catch {
                _ = follower.arena.reset(.retain_capacity);
                return follower.fail();
            };
            if (envelope.payload.block_number != number) {
                _ = follower.arena.reset(.retain_capacity);
                return follower.fail();
            }
            follower.ready = envelope;
            follower.stats.blocks += 1;
        }

        fn on_label(follower: *Self, label: Label, raw: []const u8) void {
            follower.stats.label_reads += 1;
            var extra: [header_json.extra_data_size_max]u8 = undefined;
            const info: ?BlockInfo = if (std.mem.eql(u8, raw, "null"))
                null
            else if (header_json.decode(raw, &extra)) |decoded|
                decoded.block_info()
            else |_|
                return follower.fail();
            switch (label) {
                .safe => {
                    follower.labels_reading.safe = info;
                    follower.start(.{ .label = .finalized });
                },
                .finalized => {
                    follower.labels_reading.finalized = info;
                    follower.labels = follower.labels_reading;
                },
            }
        }

        fn fail(follower: *Self) void {
            follower.stats.failures += 1;
            follower.retry_at_ns = follower.io.now_monotonic_ns() + retry_interval_ns;
            assert(follower.stats.failures > 0);
        }
    };
}

/// Checks a source label against the local block at its height (base/base
/// `verified_local_block`): `.skip` outside `[floor, ceiling]`, `.mismatch` when the local
/// hash differs, `.promote` otherwise.
pub const Verdict = enum { skip, promote, mismatch };

pub fn verify_label(source: BlockInfo, local: ?BlockInfo, floor: u64, ceiling: u64) Verdict {
    if (source.number < floor or source.number > ceiling) return .skip;
    const block = local orelse return .skip;
    assert(block.number == source.number);
    if (!block.hash.eql(source.hash)) return .mismatch;
    return .promote;
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;

test "follow: verify_label skips out of range, flags hash mismatches" {
    const source: BlockInfo = .{ .number = 5, .hash = .init(@splat(5)) };
    try testing.expectEqual(Verdict.skip, verify_label(source, null, 0, 10));
    try testing.expectEqual(Verdict.skip, verify_label(source, source, 6, 10));
    try testing.expectEqual(Verdict.skip, verify_label(source, source, 0, 4));
    try testing.expectEqual(Verdict.promote, verify_label(source, source, 5, 5));
    var other = source;
    other.hash = .init(@splat(6));
    try testing.expectEqual(Verdict.mismatch, verify_label(source, other, 0, 10));
}

test "follow: seeded fuzz over verify_label" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xf011);
    for (0..1024) |_| {
        const number = prng.below(64);
        const source: BlockInfo = .{ .number = number, .hash = .init(@splat(prng.int(u8))) };
        var local = source;
        if (prng.chance(1, 3)) local.hash = .init(@splat(prng.int(u8)));
        const floor = prng.below(64);
        const ceiling = prng.below(64);
        const verdict = verify_label(source, local, floor, ceiling);
        const in_range = number >= floor and number <= ceiling;
        try testing.expectEqual(!in_range, verdict == .skip);
        if (verdict == .promote) try testing.expect(local.hash.eql(source.hash));
    }
}

const sim_harness = @import("../sources/sim_harness.zig");
const fixtures = @import("../sources/fixtures.zig");
const FakeRpc = sim_harness.FakeRpc;
const SimFollower = Follower(@import("../../utilities/io/root.zig").SimIo);

fn run_follower(
    harness: anytype,
    follower: *SimFollower,
    unsafe_number: u64,
    rounds: u32,
) void {
    for (0..rounds) |_| {
        follower.tick(unsafe_number, true);
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
}

test "follow: reads labels, fetches the next block in order, backs off on a miss" {
    var block: fixtures.L2FullBlock = undefined;
    block.init(1, .init(@splat(1)), 0, &.{});
    var text_buffer: [16 * 1024]u8 = undefined;
    const text = try block.json_text(&text_buffer);
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "\"safe\"", .result = text });
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "\"0x1\"", .result = text });
    var harness: sim_harness.Harness(*FakeRpc, FakeRpc.handle) = undefined;
    try harness.init(&fake, 0xf0);
    defer harness.deinit();
    var follower: SimFollower = undefined;
    try follower.init(
        testing.allocator,
        &harness.client_io,
        harness.address,
        sim_harness.client_options,
    );
    defer follower.deinit();
    run_follower(&harness, &follower, 0, 10);
    const labels = follower.take_labels().?;
    try testing.expect(labels.safe.?.hash.eql(block.hash()));
    try testing.expect(labels.finalized == null);
    try testing.expect(follower.take_labels() == null);
    const envelope = follower.take().?;
    try testing.expectEqual(@as(u64, 1), envelope.payload.block_number);
    try testing.expect(envelope.payload.block_hash.eql(block.hash()));
    run_follower(&harness, &follower, 0, 4); // Nothing new until the node consumes it.
    try testing.expectEqual(@as(u64, 1), follower.stats.blocks);
    follower.consume();
    run_follower(&harness, &follower, 1, 4); // Block 2 is not there yet.
    try testing.expect(follower.take() == null);
    try testing.expect(follower.stats.not_found >= 1);
    const misses = follower.stats.not_found;
    run_follower(&harness, &follower, 1, 2); // Within the backoff: no new request.
    try testing.expect(follower.stats.not_found <= misses + 1);
    // A head that went back (reset) restarts from its child; a wrong number fails.
    fake.entries[1].params_contain = "\"0x2\"";
    run_follower(&harness, &follower, 1, 20);
    try testing.expect(follower.take() == null);
    try testing.expect(follower.stats.failures >= 1);
    while (follower.busy()) harness.world.run_for_ns(std.time.ns_per_s / 10);
}

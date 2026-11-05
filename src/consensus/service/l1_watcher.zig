//! L1 head watcher: polls L1 `latest`, `safe` and `finalized` block headers over JSON-RPC
//! and keeps the newest of each (base/base `service/src/actors/l1_watcher/actor.rs` with
//! its polling block streams). Headers are hash-verified before they are accepted.
//!
//! Tick-driven and non-blocking: `tick` starts at most one request when the previous one
//! finished and the tag's poll interval elapsed. Failures are counted and retried on the
//! next interval. Difference: system config and unsafe-block-signer log watching is not
//! done here; the derivation pipeline reads system config updates from L1 receipts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const protocol = @import("../protocol/root.zig");
const header_json = @import("../sources/header_json.zig");

const BlockInfo = protocol.block.BlockInfo;

pub const Tag = enum(u8) {
    latest,
    safe,
    finalized,

    fn text(tag: Tag) []const u8 {
        return @tagName(tag);
    }
};

pub const Options = struct {
    head_poll_interval_ns: u64 = std.time.ns_per_s,
    finalized_poll_interval_ns: u64 = 12 * std.time.ns_per_s,
};

pub const Stats = struct { requests: u64 = 0, failures: u64 = 0 };

const request_size_max = 512;

pub fn L1Watcher(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        client: Rpc,
        options: Options,
        heads: [3]?BlockInfo = .{ null, null, null },
        due_ns: [3]u64 = .{ 0, 0, 0 },
        in_flight: ?Tag = null,
        stats: Stats = .{},

        /// `watcher` must not move afterwards while a request is in flight.
        pub fn init(
            watcher: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            options: Options,
        ) !void {
            assert(options.head_poll_interval_ns > 0);
            assert(options.finalized_poll_interval_ns > 0);
            const client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            watcher.* = .{ .io = io, .client = client, .options = options };
        }

        pub fn deinit(watcher: *Self) void {
            assert(watcher.in_flight == null);
            watcher.client.deinit();
            watcher.* = undefined;
        }

        pub fn busy(watcher: *const Self) bool {
            return watcher.in_flight != null;
        }

        pub fn head(watcher: *const Self, tag: Tag) ?BlockInfo {
            return watcher.heads[@backingInt(tag)];
        }

        fn interval_ns(watcher: *const Self, tag: Tag) u64 {
            return if (tag == .latest)
                watcher.options.head_poll_interval_ns
            else
                watcher.options.finalized_poll_interval_ns;
        }

        /// Starts the most overdue poll, if any and nothing is in flight.
        pub fn tick(watcher: *Self) void {
            watcher.client.http.tick();
            if (watcher.in_flight != null or watcher.client.http.busy()) return;
            const now_ns = watcher.io.now_monotonic_ns();
            var chosen: ?Tag = null;
            for (std.enums.values(Tag)) |tag| {
                if (watcher.due_ns[@backingInt(tag)] > now_ns) continue;
                const best = chosen orelse {
                    chosen = tag;
                    continue;
                };
                if (watcher.due_ns[@backingInt(tag)] < watcher.due_ns[@backingInt(best)]) {
                    chosen = tag;
                }
            }
            const tag = chosen orelse return;
            watcher.due_ns[@backingInt(tag)] = now_ns + watcher.interval_ns(tag);
            watcher.in_flight = tag;
            watcher.stats.requests += 1;
            const method = "eth_getBlockByNumber";
            const params = &watcher.in_flight.?;
            watcher.client.call(*Self, watcher, on_result, method, params, write_params) catch {
                watcher.in_flight = null;
                watcher.stats.failures += 1;
            };
        }

        fn write_params(tag: *const Tag, writer: *json.Writer) json.Writer.WriteError!void {
            try writer.string(tag.text());
            try writer.boolean(false);
        }

        fn on_result(
            watcher: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &watcher.client);
            const tag = watcher.in_flight.?;
            watcher.in_flight = null;
            const raw = switch (result catch return watcher.fail()) {
                .ok => |raw| raw,
                .rpc_error => return watcher.fail(),
            };
            if (std.mem.eql(u8, raw, "null")) return; // e.g. no finalized block yet.
            var extra: [header_json.extra_data_size_max]u8 = undefined;
            const decoded = header_json.decode(raw, &extra) catch return watcher.fail();
            const info = decoded.block_info();
            const slot = &watcher.heads[@backingInt(tag)];
            // Heads may move back on an L1 reorg; accept the newest observation.
            slot.* = info;
            assert(watcher.heads[@backingInt(tag)].?.hash.eql(decoded.hash));
        }

        fn fail(watcher: *Self) void {
            watcher.stats.failures += 1;
            assert(watcher.in_flight == null);
        }
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const sim = @import("../../utilities/io/root.zig");
const harness_module = @import("../sources/sim_harness.zig");
const fixtures = @import("../sources/fixtures.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Watcher = L1Watcher(sim.SimIo);

test "l1 watcher: polls tags, verifies headers, tolerates null and garbage" {
    var head_text: [4096]u8 = undefined;
    var safe_text: [4096]u8 = undefined;
    const head = fixtures.header_for(&.{}, 20, .init(@splat(1)));
    const safe = fixtures.header_for(&.{}, 10, .init(@splat(2)));
    var fake: FakeRpc = .{};
    const method = "eth_getBlockByNumber";
    fake.add(.{
        .method = method,
        .params_contain = "latest",
        .result = try fixtures.block_json(&head_text, &head, &.{}, false),
    });
    fake.add(.{
        .method = method,
        .params_contain = "safe",
        .result = try fixtures.block_json(&safe_text, &safe, &.{}, false),
    });
    fake.add(.{ .method = method, .params_contain = "finalized", .result = "{\"x\":1}" });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x31);
    defer harness.deinit();
    var watcher: Watcher = undefined;
    const options: Options = .{ .finalized_poll_interval_ns = std.time.ns_per_s };
    const http_options = harness_module.client_options;
    const client_io = &harness.client_io;
    try watcher.init(testing.allocator, client_io, harness.address, http_options, options);
    defer watcher.deinit();
    try testing.expectEqual(@as(?BlockInfo, null), watcher.head(.latest));
    for (0..6) |_| {
        watcher.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 4);
    }
    try testing.expectEqual(@as(u64, 20), watcher.head(.latest).?.number);
    try testing.expect(watcher.head(.latest).?.hash.eql(head.hash()));
    try testing.expectEqual(@as(u64, 10), watcher.head(.safe).?.number);
    try testing.expectEqual(@as(?BlockInfo, null), watcher.head(.finalized));
    try testing.expect(watcher.stats.failures >= 1);
    try testing.expect(watcher.stats.requests >= 3);
    while (watcher.busy()) harness.world.run_for_ns(std.time.ns_per_s / 4);
}

//! L2 provider tests over the simulated network: misses enqueue fetches, completions fill
//! block info and system config caches, null results surface once, malformed responses
//! never reach the caller, and by-number results expire.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const protocol = @import("../protocol/root.zig");
const harness_module = @import("sim_harness.zig");
const fixtures = @import("fixtures.zig");
const l2_provider = @import("l2_provider.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Provider = l2_provider.L2Provider(io.SimIo);
const RollupConfig = protocol.rollup_config.RollupConfig;

const Fixture = struct {
    fake: FakeRpc = .{},
    harness: Harness = undefined,
    provider: Provider = undefined,
    rollup: RollupConfig = .{ .block_time = 2 },
    text: [4096]u8 = undefined,
    block: []const u8 = "",
    hash: [32]u8 = undefined,
    hash_hex: [66]u8 = undefined,
    full: fixtures.L2FullBlock = undefined,
    full_text: [8192]u8 = undefined,

    fn init(fixture: *Fixture, options: l2_provider.Options) !void {
        fixture.rollup.upgrades.set(.holocene, 0);
        fixture.block = try fixtures.l2_block_json(&fixture.text, 7, &fixture.hash);
        _ = try std.fmt.bufPrint(&fixture.hash_hex, "0x{x}", .{&fixture.hash});
        const fake = &fixture.fake;
        const by_number = "eth_getBlockByNumber";
        fake.add(.{ .method = by_number, .params_contain = "\"0x7\"", .result = fixture.block });
        fake.add(.{ .method = by_number, .params_contain = "\"0x8\"", .result = "{\"bad\":1}" });
        fake.add(.{ .method = by_number, .params_contain = "\"safe\"", .result = fixture.block });
        fixture.full.init(9, .init(@splat(0x08)), 1, &.{});
        const full = try fixture.full.json_text(&fixture.full_text);
        fake.add(.{ .method = by_number, .params_contain = "\"0x9\"", .result = full });
        fake.add(.{
            .method = "eth_getBlockByHash",
            .params_contain = &fixture.hash_hex,
            .result = fixture.block,
        });
        try fixture.harness.init(&fixture.fake, 0x12);
        errdefer fixture.harness.deinit();
        try fixture.provider.init(
            testing.allocator,
            &fixture.harness.client_io,
            fixture.harness.address,
            harness_module.client_options,
            &fixture.rollup,
            options,
        );
    }

    fn deinit(fixture: *Fixture) void {
        fixture.provider.deinit();
        fixture.harness.deinit();
    }
};

test "l2 provider: misses fetch, completions fill info and system config" {
    var fixture: Fixture = .{};
    try fixture.init(.{ .jwt_secret = .{ .bytes = @splat(0x42) } });
    defer fixture.deinit();
    const provider = &fixture.provider;
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(7));
    fixture.harness.run();
    const info = try provider.l2_block_info_by_number(7);
    try testing.expectEqualSlices(u8, &fixture.hash, &info.block_info.hash.bytes);
    try testing.expectEqual(@as(u64, 507), info.l1_origin.number);
    try testing.expectEqual(@as(u64, 1), info.sequence_number);
    // The by-number fetch also filled the hash-keyed cache.
    const requests = fixture.fake.requests;
    const by_hash = try provider.l2_block_info_by_hash(info.block_info.hash);
    try testing.expectEqual(info, by_hash);
    const config = try provider.system_config_by_l2_hash(info.block_info.hash);
    try testing.expectEqual(requests, fixture.fake.requests);
    try testing.expectEqual(@as(u64, 30_000_000), config.gas_limit);
    try testing.expectEqual(@as(?u32, 250), config.eip1559_denominator);
    try testing.expectEqual(@as(?u32, 6), config.eip1559_elasticity);
    try testing.expectEqual(protocol.l2_system_config.encode_scalar(2, 3), config.scalar);
    try testing.expect(config.batcher_address.eql(.init(@splat(0xba))));
    try testing.expect(std.mem.startsWith(u8, fixture.fake.authorization(), "Bearer ey"));
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_label(.safe));
    fixture.harness.run();
    try testing.expectEqual(info, try provider.l2_block_info_by_label(.safe));
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_label(.finalized));
    fixture.harness.run();
    try testing.expectError(error.NotFound, provider.l2_block_info_by_label(.finalized));
}

test "l2 provider: full safe blocks by number, malformed dropped" {
    var fixture: Fixture = .{};
    try fixture.init(.{ .full_blocks = 2 });
    defer fixture.deinit();
    const provider = &fixture.provider;
    try testing.expectError(error.NotAvailable, provider.l2_block_by_number(9));
    fixture.harness.run();
    const block = try provider.l2_block_by_number(9);
    try testing.expectEqual(@as(?u64, 509), block.l1_origin_number);
    try testing.expectEqual(@as(usize, 1), block.transactions.len);
    try testing.expectEqual(@as(u8, 0x7e), block.transactions[0][0]);
    const requests = fixture.fake.requests;
    _ = try provider.l2_block_by_number(9);
    try testing.expectEqual(requests, fixture.fake.requests);
    try testing.expectError(error.NotAvailable, provider.l2_block_by_number(8));
    fixture.harness.run();
    try testing.expectError(error.NotAvailable, provider.l2_block_by_number(8));
    fixture.harness.run();
    try testing.expect(provider.stats.failures >= 1);
    try testing.expect(!provider.busy());
}

test "l2 provider: null once as NotFound, malformed dropped, by-number expiry" {
    var fixture: Fixture = .{};
    try fixture.init(.{ .block_by_number_ttl_ns = 3 * std.time.ns_per_s / 2 });
    defer fixture.deinit();
    const provider = &fixture.provider;
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(99));
    fixture.harness.run();
    try testing.expectError(error.NotFound, provider.l2_block_info_by_number(99));
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(99));
    fixture.harness.run();
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(8));
    fixture.harness.run();
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(8));
    try testing.expect(provider.stats.failures >= 1);
    fixture.harness.run();
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(7));
    fixture.harness.run();
    _ = try provider.l2_block_info_by_number(7);
    fixture.harness.run(); // One simulated second: past the TTL.
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(7));
    fixture.harness.run();
    try testing.expect(!provider.busy());
}

test "l2 provider: seeded fuzz, queue stays bounded" {
    var fixture: Fixture = .{};
    try fixture.init(.{ .queue_size = 4, .cache_entries = 2 });
    defer fixture.deinit();
    const provider = &fixture.provider;
    var prng = Prng.init(0x4c325052);
    for (0..300) |_| {
        const number = prng.below(12);
        if (provider.l2_block_info_by_number(number)) |info| {
            try testing.expectEqual(number, info.block_info.number);
        } else |err| switch (err) {
            error.NotAvailable, error.NotFound => {},
            else => return err,
        }
        try testing.expect(provider.queue_count <= 4);
        if (prng.chance(1, 4)) fixture.harness.run();
    }
    fixture.harness.run();
    fixture.harness.run();
    try testing.expect(!provider.busy());
}

test "l2 provider: a pruned body surfaces once as Pruned with its header" {
    var fixture: Fixture = .{};
    try fixture.init(.{});
    defer fixture.deinit();
    const Header = @import("../../common/consensus/root.zig").Header;
    const header: Header = .{ .number = 10, .timestamp = 20, .gas_limit = 30_000_000 };
    var text: [4096]u8 = undefined;
    // No transactions: the body (and its L1 info deposit) was pruned.
    const pruned = try fixtures.block_json(&text, &header, &.{}, true);
    const by_number = "eth_getBlockByNumber";
    fixture.fake.add(.{ .method = by_number, .params_contain = "\"0xa\"", .result = pruned });
    const provider = &fixture.provider;
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(10));
    fixture.harness.run();
    try testing.expectError(error.Pruned, provider.l2_block_info_by_number(10));
    const last = provider.last_pruned.?;
    try testing.expectEqual(@as(u64, 10), last.header.number);
    try testing.expectEqual(@as(u64, 20), last.header.timestamp);
    try testing.expectEqualSlices(u8, &header.hash().bytes, &last.header.hash.bytes);
    try testing.expectEqual(@as(u64, 1), provider.stats.pruned);
    try testing.expectEqual(@as(u64, 0), provider.stats.failures);
    // Reported once; the next query fetches again.
    try testing.expectError(error.NotAvailable, provider.l2_block_info_by_number(10));
    fixture.harness.run();
    try testing.expect(!provider.busy());
}

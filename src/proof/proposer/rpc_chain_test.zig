//! The proposer's RPC chain adapter against canned JSON-RPC answers over SimIo: contract
//! calls are matched by selector, results decoded, the anchor snapshot pinned to one L1
//! block, and intervals resolved through the 0.3.0 version gate.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const registry = @import("../contracts/anchor_state_registry.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const rpc_chain = @import("rpc_chain.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Chain = rpc_chain.RpcChain(Endpoint);

const hash_a = "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";

/// `"0x<abi.encode(values)>"`, allocated in `arena`.
fn returns(arena: std.mem.Allocator, values: []const abi.Value) ![]const u8 {
    var buffer: [1024]u8 = undefined;
    const encoded = try abi.encode_call(&buffer, @splat(0), values);
    return std.fmt.allocPrint(arena, "\"0x{x}\"", .{encoded[4..]});
}

/// `"0x<selector>`, matched against the call's `data` parameter.
fn selector_param(arena: std.mem.Allocator, function: [4]u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "\"0x{x}", .{&function});
}

fn add_call(fake: *FakeRpc, arena: std.mem.Allocator, function: [4]u8, result: []const u8) !void {
    fake.add(.{
        .method = "eth_call",
        .params_contain = try selector_param(arena, function),
        .result = result,
    });
}

fn add_contracts(fake: *FakeRpc, arena: std.mem.Allocator, version: []const u8) !void {
    fake.add(.{ .method = "eth_blockNumber", .result = "\"0x10\"" });
    try add_call(fake, arena, registry.get_anchor_root, try returns(arena, &.{
        .{ .word = @splat(0xaa) }, .{ .uint = 100 },
    }));
    try add_call(fake, arena, registry.anchor_game, try returns(arena, &.{
        .{ .address = @splat(0x0b) },
    }));
    try add_call(fake, arena, factory.game_count, try returns(arena, &.{.{ .uint = 7 }}));
    try add_call(fake, arena, factory.games, try returns(arena, &.{
        .{ .address = @splat(0x0c) }, .{ .uint = 1234 },
    }));
    try add_call(fake, arena, factory.game_impls, try returns(arena, &.{
        .{ .address = @splat(0x1d) },
    }));
    try add_call(fake, arena, rpc_chain.verifier.version, try returns(arena, &.{
        .{ .bytes = version },
    }));
    const pair = try returns(arena, &.{ .{ .uint = 600 }, .{ .uint = 100 } });
    try add_call(fake, arena, rpc_chain.verifier.intervals_for_starting_block, pair);
    const legacy_block = try returns(arena, &.{.{ .uint = 1800 }});
    try add_call(fake, arena, rpc_chain.verifier.block_interval, legacy_block);
    const legacy_intermediate = try returns(arena, &.{.{ .uint = 300 }});
    try add_call(fake, arena, rpc_chain.verifier.intermediate_block_interval, legacy_intermediate);
    fake.add(.{
        .method = "optimism_outputAtBlock",
        .params_contain = "\"0xc\"",
        .result = "{\"outputRoot\":" ++ hash_a ++ ",\"blockRef\":{\"hash\":" ++ hash_a ++
            ",\"number\":12}}",
    });
}

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

const Fixture = struct {
    harness: Harness,
    fake: FakeRpc = .{},
    l1_client: Endpoint.Client,
    rollup_client: Endpoint.Client,
    l1: Endpoint,
    rollup: Endpoint,

    fn create(arena: std.mem.Allocator, version: []const u8) !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.fake = .{};
        try add_contracts(&self.fake, arena, version);
        try self.harness.init(&self.fake, 0x51);
        errdefer self.harness.deinit();
        const options = harness_module.client_options;
        const address = self.harness.address;
        self.l1_client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        errdefer self.l1_client.deinit();
        self.rollup_client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        const pump: endpoint_module.Pump = .{ .context = &self.harness, .step = step };
        self.l1 = .init(allocator, &self.l1_client, pump, 100_000);
        self.rollup = .init(allocator, &self.rollup_client, pump, 100_000);
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.l1.deinit();
        self.rollup.deinit();
        self.rollup_client.deinit();
        self.l1_client.deinit();
        self.harness.deinit();
        testing.allocator.destroy(self);
    }

    fn chain(self: *Fixture) Chain {
        return .init(&self.l1, &self.rollup, .{
            .factory = @splat(0xfa),
            .anchor_state_registry = @splat(0xa5),
            .game_type = 621,
        });
    }
};

test "rpc chain: anchor, games, outputs and fork-aware intervals" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator(), "0.3.0");
    defer self.destroy();
    var adapter = self.chain();
    const chain = adapter.chain();

    const snapshot = try chain.anchor_snapshot();
    try testing.expectEqual(@as(u64, 100), snapshot.root.l2_block_number);
    try testing.expectEqual(@as(u8, 0xaa), snapshot.root.root[0]);
    try testing.expectEqual(@as([20]u8, @splat(0x0b)), snapshot.game);
    // Both registry reads are pinned to the block number read first.
    try testing.expect(std.mem.indexOf(u8, self.fake.body(), "\"0x10\"") != null);

    try testing.expectEqual(@as(u64, 7), try chain.game_count());
    const extra: [factory.extra_data_prefix_bytes]u8 = @splat(1);
    const game = try chain.game_lookup(621, @splat(2), &extra);
    try testing.expectEqual(@as([20]u8, @splat(0x0c)), game.?);

    const output = try chain.output_at_block(12);
    try testing.expectEqual(@as(u8, 0xaa), output.output_root[0]);
    // The node answers null for a block it does not have.
    try testing.expectError(error.BlockNotFound, chain.output_at_block(13));

    const intervals = try chain.intervals_for(5000);
    try testing.expectEqual(@as(u64, 600), intervals.block_interval);
    try testing.expectEqual(@as(u64, 100), intervals.intermediate_block_interval);
}

test "rpc chain: verifiers below 0.3.0 use the fixed interval getters" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator(), "0.2.4");
    defer self.destroy();
    var adapter = self.chain();
    const intervals = try adapter.chain().intervals_for(5000);
    try testing.expectEqual(@as(u64, 1800), intervals.block_interval);
    try testing.expectEqual(@as(u64, 300), intervals.intermediate_block_interval);
    // The sync status call fails cleanly against a node without it.
    try testing.expectError(error.Unavailable, adapter.chain().sync_status());
}

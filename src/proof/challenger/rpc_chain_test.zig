//! The challenger's RPC chain view against canned JSON-RPC answers over SimIo: contract
//! calls are matched by selector, results decoded, the anchor snapshot pinned to one L1
//! block, intervals resolved through the 0.3.0 version gate, L1 headers checked against
//! their hash, and failures mapped onto the view's error sets.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const verifier = @import("../contracts/aggregate_verifier.zig");
const registry = @import("../contracts/anchor_state_registry.zig");
const weth = @import("../contracts/delayed_weth.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const consensus = @import("../../common/consensus/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const rpc_chain = @import("rpc_chain.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Chain = rpc_chain.RpcChain(Endpoint);
const Allocator = std.mem.Allocator;

const game: [20]u8 = @splat(0x6a);

/// `"0x<abi.encode(values)>"`, allocated in `arena`.
fn returns(arena: Allocator, values: []const abi.Value) ![]const u8 {
    var buffer: [1024]u8 = undefined;
    const encoded = try abi.encode_call(&buffer, @splat(0), values);
    return std.fmt.allocPrint(arena, "\"0x{x}\"", .{encoded[4..]});
}

fn add_call(fake: *FakeRpc, arena: Allocator, function: [4]u8, values: []const abi.Value) !void {
    fake.add(.{
        .method = "eth_call",
        .params_contain = try std.fmt.allocPrint(arena, "\"0x{x}", .{&function}),
        .result = try returns(arena, values),
    });
}

/// A JSON hex string of `bytes`.
fn hex_string(arena: Allocator, bytes: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "\"0x{x}\"", .{bytes});
}

/// L1 header number 77 answered by its hash; returns the hash.
fn add_l1_header(fake: *FakeRpc, arena: Allocator) ![32]u8 {
    var buffer: [600]u8 = undefined;
    const raw = rlp.encode_to(&buffer, consensus.Header{ .number = 77 });
    const hash = crypto.keccak256(raw);
    fake.add(.{
        .method = "debug_getRawHeader",
        .params_contain = try std.fmt.allocPrint(arena, "0x{x}", .{&hash}),
        .result = try hex_string(arena, raw),
    });
    return hash;
}

fn add_games(fake: *FakeRpc, arena: Allocator, version: []const u8) !void {
    try add_call(fake, arena, factory.game_count, &.{.{ .uint = 3 }});
    try add_call(fake, arena, factory.game_at_index, &.{
        .{ .uint = 621 }, .{ .uint = 1234 }, .{ .address = game },
    });
    try add_call(fake, arena, factory.game_impls, &.{.{ .address = @splat(0x1d) }});
    try add_call(fake, arena, factory.games, &.{ .{ .address = game }, .{ .uint = 1234 } });
    try add_call(fake, arena, verifier.status, &.{.{ .uint = 2 }});
    try add_call(fake, arena, verifier.tee_prover, &.{.{ .address = @splat(0x7e) }});
    try add_call(fake, arena, verifier.zk_prover, &.{.{ .address = @splat(0x2c) }});
    try add_call(fake, arena, verifier.countered_index, &.{.{ .uint = 2 }});
    try add_call(fake, arena, verifier.root_claim, &.{.{ .word = @splat(0xcc) }});
    try add_call(fake, arena, verifier.l2_sequence_number, &.{.{ .uint = 1600 }});
    try add_call(fake, arena, verifier.parent_address, &.{.{ .address = @splat(0x9a) }});
    try add_call(fake, arena, verifier.starting_block_number, &.{.{ .uint = 1000 }});
    try add_call(fake, arena, verifier.l1_head, &.{.{ .word = @splat(0x11) }});
    try add_call(fake, arena, verifier.version, &.{.{ .bytes = version }});
    try add_call(fake, arena, verifier.intervals_for_starting_block, &.{
        .{ .uint = 600 }, .{ .uint = 100 },
    });
    try add_call(fake, arena, verifier.block_interval, &.{.{ .uint = 1800 }});
    try add_call(fake, arena, verifier.intermediate_block_interval, &.{.{ .uint = 300 }});
    const roots: [64]u8 = @as([32]u8, @splat(0xd1)) ++ @as([32]u8, @splat(0xd2));
    try add_call(fake, arena, verifier.intermediate_output_roots, &.{.{ .bytes = &roots }});
    try add_call(fake, arena, verifier.intermediate_output_root, &.{.{ .word = @splat(0xd2) }});
    fake.add(.{ .method = "eth_blockNumber", .result = "\"0x10\"" });
    try add_call(fake, arena, registry.get_anchor_root, &.{
        .{ .word = @splat(0xaa) }, .{ .uint = 1 },
    });
    // The registry's anchor game reverts.
    fake.add(.{
        .method = "eth_call",
        .params_contain = try std.fmt.allocPrint(arena, "\"0x{x}", .{&registry.anchor_game}),
        .rpc_error = "{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x\"}",
    });
    var buffer: [600]u8 = undefined;
    const l1_raw = try hex_string(arena, rlp.encode_to(&buffer, consensus.Header{ .number = 77 }));
    _ = try add_l1_header(fake, arena);
    // A node answering a hash with another block's header.
    fake.add(.{ .method = "debug_getRawHeader", .params_contain = "0x5555", .result = l1_raw });
    const l2_raw = rlp.encode_to(&buffer, consensus.Header{ .number = 5 });
    fake.add(.{
        .method = "debug_getRawHeader",
        .params_contain = "[\"0x5\"]",
        .result = try hex_string(arena, l2_raw),
    });
    fake.add(.{ .method = "debug_getRawHeader", .params_contain = "[\"0x6\"]" });
}

fn add_registry(fake: *FakeRpc, arena: Allocator, version: []const u8) !void {
    _ = version;
    fake.add(.{ .method = "eth_blockNumber", .result = "\"0x10\"" });
    try add_call(fake, arena, registry.get_anchor_root, &.{
        .{ .word = @splat(0xaa) }, .{ .uint = 100 },
    });
    try add_call(fake, arena, registry.anchor_game, &.{.{ .address = @splat(0x0b) }});
    try add_call(fake, arena, verifier.anchor_state_registry, &.{.{ .address = @splat(0xa5) }});
    try add_call(fake, arena, registry.is_game_finalized, &.{.{ .boolean = true }});
    try add_call(fake, arena, registry.is_game_blacklisted, &.{.{ .boolean = false }});
    try add_call(fake, arena, registry.is_game_retired, &.{.{ .boolean = true }});
    try add_call(fake, arena, registry.is_game_respected, &.{.{ .boolean = true }});
    try add_call(fake, arena, registry.paused, &.{.{ .boolean = false }});
    try add_call(fake, arena, verifier.bond_recipient, &.{.{ .address = @splat(0xbe) }});
    try add_call(fake, arena, verifier.zk_prover, &.{.{ .address = @splat(0x2c) }});
    try add_call(fake, arena, verifier.resolved_at, &.{.{ .uint = 5000 }});
    try add_call(fake, arena, verifier.game_over, &.{.{ .boolean = true }});
    try add_call(fake, arena, verifier.bond_unlocked, &.{.{ .boolean = true }});
    try add_call(fake, arena, verifier.bond_claimed, &.{.{ .boolean = false }});
    try add_call(fake, arena, verifier.delayed_weth, &.{.{ .address = @splat(0x3e) }});
    try add_call(fake, arena, weth.delay, &.{.{ .uint = 604800 }});
    try add_call(fake, arena, weth.withdrawals, &.{ .{ .uint = 80 }, .{ .uint = 6000 } });
}

const AddFn = *const fn (*FakeRpc, Allocator, []const u8) anyerror!void;

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

const Fixture = struct {
    harness: Harness,
    fake: FakeRpc = .{},
    l1_client: Endpoint.Client,
    l2_client: Endpoint.Client,
    l1: Endpoint,
    l2: Endpoint,
    adapter: Chain,

    fn create(arena: Allocator, add: AddFn, version: []const u8) !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.fake = .{};
        try add(&self.fake, arena, version);
        try self.harness.init(&self.fake, 0x52);
        errdefer self.harness.deinit();
        const options = harness_module.client_options;
        const address = self.harness.address;
        self.l1_client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        errdefer self.l1_client.deinit();
        self.l2_client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        const pump: endpoint_module.Pump = .{ .context = &self.harness, .step = step };
        self.l1 = .init(allocator, &self.l1_client, pump, 100_000);
        self.l2 = .init(allocator, &self.l2_client, pump, 100_000);
        self.adapter = .init(&self.l1, &self.l2, .{
            .factory = @splat(0xfa),
            .anchor_state_registry = @splat(0xa5),
        });
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.l1.deinit();
        self.l2.deinit();
        self.l2_client.deinit();
        self.l1_client.deinit();
        self.harness.deinit();
        testing.allocator.destroy(self);
    }
};

test "challenger rpc chain: factory and game reads with fork-aware intervals" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator(), add_games, "0.3.0");
    defer self.destroy();
    const view = self.adapter.view();

    try testing.expectEqual(@as(u64, 3), try view.game_count());
    const at = try view.game_at_index(2);
    try testing.expectEqual(@as(u32, 621), at.game_type);
    try testing.expectEqual(game, at.proxy);
    const state = try view.game_state(game);
    try testing.expectEqual(verifier.GameStatus.defender_wins, state.status);
    try testing.expectEqual(@as([20]u8, @splat(0x7e)), state.tee_prover);
    try testing.expectEqual(@as(u64, 2), state.countered_index);
    const info = try view.game_info(game);
    try testing.expectEqual(@as(u64, 1600), info.l2_block_number);
    try testing.expectEqual(@as(u64, 1000), info.starting_block_number);
    try testing.expectEqual(@as([32]u8, @splat(0xcc)), info.root_claim);
    try testing.expectEqual(@as([20]u8, @splat(0x9a)), info.parent);
    const expected: verifier.Intervals = .{ .block = 600, .intermediate_block = 100 };
    try testing.expectEqual(expected, info.intervals);
    const factory_intervals = try view.implementation_intervals(621, 1000);
    try testing.expectEqual(@as(u64, 600), factory_intervals.block);

    var roots: [4][32]u8 = undefined;
    const read = try view.intermediate_roots(game, &roots);
    try testing.expectEqual(@as(usize, 2), read.len);
    try testing.expectEqual(@as(u8, 0xd2), read[1][0]);
    var short: [1][32]u8 = undefined;
    try testing.expectError(error.ChainUnavailable, view.intermediate_roots(game, &short));
    try testing.expectEqual(@as(u8, 0xd2), (try view.intermediate_root(game, 1))[31]);
    const extra: [factory.extra_data_prefix_bytes]u8 = @splat(1);
    try testing.expectEqual(game, (try view.factory_game(621, @splat(0xcc), &extra)).?);
    // A revert is a failed read.
    try testing.expectError(error.ChainUnavailable, view.anchor_snapshot());
}

test "challenger rpc chain: headers and legacy intervals" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const self = try Fixture.create(arena, add_games, "0.2.1");
    defer self.destroy();
    const view = self.adapter.view();

    const info = try view.game_info(game);
    const expected: verifier.Intervals = .{ .block = 1800, .intermediate_block = 300 };
    try testing.expectEqual(expected, info.intervals);
    var buffer: [600]u8 = undefined;
    const expected_l1 = rlp.encode_to(&buffer, consensus.Header{ .number = 77 });
    try testing.expectEqual(@as(u64, 77), try view.l1_block_number(crypto.keccak256(expected_l1)));
    // An unknown hash (the fake answers null) and a header that does not hash to the
    // requested hash are both failed reads.
    try testing.expectError(error.ChainUnavailable, view.l1_block_number(@splat(0x44)));
    try testing.expectError(error.ChainUnavailable, view.l1_block_number(@splat(0x55)));
    var header: [600]u8 = undefined;
    const raw = try view.l2_header(5, &header);
    const decoded = try rlp.decode_exact(consensus.Header, raw);
    try testing.expectEqual(@as(u64, 5), decoded.number);
    try testing.expectError(error.BlockNotAvailable, view.l2_header(6, &header));
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.ChainUnavailable, view.l2_header(5, &tiny));
}

test "challenger rpc chain: anchor, registry, bonds and withdrawals" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator(), add_registry, "");
    defer self.destroy();
    const view = self.adapter.view();

    const snapshot = try view.anchor_snapshot();
    try testing.expectEqual(@as(u64, 100), snapshot.anchor_root.l2_block_number);
    try testing.expectEqual(@as([20]u8, @splat(0x0b)), snapshot.anchor_game);
    // Both registry reads are pinned to the block number read first.
    try testing.expect(std.mem.indexOf(u8, self.fake.body(), "\"0x10\"") != null);

    const registry_address = try view.anchor_registry_of(game);
    try testing.expectEqual(@as([20]u8, @splat(0xa5)), registry_address);
    try testing.expect(try view.is_game_finalized(registry_address, game));
    const preflight = try view.anchor_preflight(registry_address, game);
    try testing.expect(!preflight.blacklisted and preflight.retired and preflight.respected);
    try testing.expect(preflight.permanently_ineligible());
    try testing.expectEqual(@as(u64, 100), preflight.anchor_root.l2_block_number);

    const bonds = try view.bond_state(game);
    try testing.expectEqual(@as([20]u8, @splat(0xbe)), bonds.bond_recipient);
    try testing.expectEqual(@as(u64, 5000), bonds.resolved_at);
    try testing.expect(bonds.game_over and bonds.bond_unlocked and !bonds.bond_claimed);
    try testing.expectEqual(@as([20]u8, @splat(0x3e)), bonds.delayed_weth);
    try testing.expectEqual(@as(u64, 604800), try view.weth_delay_seconds(bonds.delayed_weth));
    const pending = try view.withdrawal(bonds.delayed_weth, game, bonds.bond_recipient);
    try testing.expectEqual(@as(u256, 80), pending.amount);
    try testing.expectEqual(@as(u64, 6000), pending.timestamp);
}

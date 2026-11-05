//! L2 chain provider tests: L2 headers and transaction tries (an L1 info deposit first)
//! served through the in-process oracle.

const std = @import("std");
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const test_oracle = @import("../test_oracle.zig");
const l2_chain_provider = @import("l2_chain_provider.zig");
const L2ChainProvider = l2_chain_provider.L2ChainProvider;

const B256 = primitives.B256;
const blocks = 4;
const Calldata = [protocol.l1_info.calldata_length_max]u8;
const batcher: primitives.Address = .{ .bytes = @splat(0xba) };

const Fixture = struct {
    store: test_oracle.MapStore,
    harness: preimage.InProcess,
    resolver: mpt.OracleResolver,
    rollup: protocol.RollupConfig,
    hashes: [blocks]B256 = undefined,

    fn init(fixture: *Fixture) !void {
        fixture.store = .init();
        try fixture.harness.init(
            testing.allocator,
            fixture.store.fetcher(),
            preimage.in_process.ignore_hints,
            .{ .channel_bytes = 8192 },
        );
        fixture.resolver = try .init(testing.allocator, fixture.harness.oracle_reader(), .{
            .bytes_max = 1 << 20,
            .entries_max = 4096,
        });
        fixture.rollup = .{ .l2_chain_id = 1 };
        try fixture.build_chain();
    }

    fn deinit(fixture: *Fixture) void {
        fixture.resolver.deinit(testing.allocator);
        fixture.harness.deinit(testing.allocator);
        fixture.store.deinit();
    }

    /// The L1 info deposit of L2 block `number`: L1 origin `number / 2`.
    fn deposit(number: u64, calldata: *Calldata) consensus.Envelope {
        const info: protocol.L1BlockInfo = .{
            .format = .ecotone,
            .number = number / 2,
            .time = 100 + number,
            .block_hash = .{ .bytes = @splat(@intCast(0x10 + number / 2)) },
            .sequence_number = number % 2,
            .batcher_address = batcher,
            .base_fee_scalar = 7,
        };
        return .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(@intCast(number)) },
            .from = .{ .bytes = @splat(0xde) },
            .to = .{ .call = .{ .bytes = @splat(0x15) } },
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = info.encode_calldata(calldata),
        } };
    }

    /// Block 0 is the rollup genesis; blocks 1.. carry one L1 info deposit.
    fn build_chain(fixture: *Fixture) !void {
        var parent: B256 = .zero;
        for (&fixture.hashes, 0..) |*hash, number| {
            var header: consensus.Header = .{
                .parent_hash = parent,
                .number = number,
                .timestamp = 2 * number,
                .gas_limit = 30_000_000,
            };
            if (number > 0) {
                var calldata: [protocol.l1_info.calldata_length_max]u8 = undefined;
                var buffer: [512]u8 = undefined;
                const encoded = deposit(number, &calldata).encode_to(&buffer);
                const root = try test_oracle.store_list(&fixture.store, &.{encoded});
                header.transactions_root = .{ .bytes = root };
            }
            var buffer: [1024]u8 = undefined;
            hash.* = header.hash();
            try fixture.store.put(.keccak256(hash.bytes), rlp.encode_to(&buffer, header));
            parent = hash.*;
            if (number == 0) {
                fixture.rollup.genesis.l2 = .{ .number = 0, .hash = hash.* };
                fixture.rollup.genesis.system_config = .{ .batcher_address = batcher };
            }
        }
    }

    fn provider(fixture: *Fixture, head: usize) !L2ChainProvider {
        return .init(
            testing.allocator,
            &fixture.resolver,
            fixture.harness.hint_writer(),
            &fixture.rollup,
            fixture.hashes[head].bytes,
            .{ .items_max = 8 },
        );
    }
};

test "l2_chain_provider: block info and system config come from the L1 info deposit" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider(blocks - 1);
    defer provider.deinit(testing.allocator);
    try testing.expectError(error.NotFound, provider.l2_block_info_by_number(blocks));
    for ([_]u64{ 3, 1, 2, 0 }) |number| {
        const info = try provider.l2_block_info_by_number(number);
        try testing.expect(info.block_info.hash.eql(fixture.hashes[number]));
        const origin: u64 = if (number == 0) 0 else number / 2;
        try testing.expectEqual(origin, info.l1_origin.number);
        try testing.expectEqual(if (number == 0) 0 else number % 2, info.sequence_number);
        const config = try provider.system_config_by_l2_hash(fixture.hashes[number]);
        try testing.expect(config.batcher_address.eql(batcher));
    }
    const safe = try provider.l2_block_by_number(2);
    try testing.expectEqual(@as(usize, 1), safe.transactions.len);
    try testing.expectEqual(@as(?u64, 1), safe.l1_origin_number);
    try testing.expectEqual(@as(?l2_chain_provider.Failure, null), provider.failure);
}

test "l2_chain_provider: remembered program-built blocks need no oracle" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider(1);
    defer provider.deinit(testing.allocator);
    const built: protocol.BlockInfo = .{
        .hash = .{ .bytes = @splat(0x77) },
        .number = 2,
        .parent_hash = fixture.hashes[1],
        .timestamp = 4,
    };
    const info: protocol.L2BlockInfo = .{ .block_info = built, .l1_origin = .{ .number = 1 } };
    provider.set_head(built);
    provider.remember(info, .{ .batcher_address = batcher });
    const found = try provider.l2_block_info_by_number(2);
    try testing.expect(found.block_info.hash.eql(built.hash));
    const parent = try provider.l2_block_info_by_number(1);
    try testing.expect(parent.block_info.hash.eql(fixture.hashes[1]));
}

test "l2_chain_provider: a block without an L1 info deposit is a failure" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var provider = try fixture.provider(1);
    defer provider.deinit(testing.allocator);
    // Not the genesis hash at the genesis number.
    fixture.rollup.genesis.l2.hash = .{ .bytes = @splat(1) };
    try testing.expectError(error.NotFound, provider.l2_block_info_by_number(0));
    try testing.expect(provider.failure != null);
}

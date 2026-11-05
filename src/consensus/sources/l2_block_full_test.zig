//! Full L2 block decoding tests: blocks written by the execution lane's eth formatter
//! (deposits with every OP field, signed types 0-3, withdrawals) decode back to the exact
//! EIP-2718 bytes; tampering is caught by the hash and root checks. Ends with a seeded
//! round-trip fuzz over random blocks, a seeded mutation fuzz, and a coverage-guided target.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const protocol = @import("../protocol/root.zig");
const fixtures = @import("fixtures.zig");
const l2_block_full = @import("l2_block_full.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const L2FullBlock = fixtures.L2FullBlock;

const genesis_default: ChainGenesis = .{};

fn user_deposit(input: []const u8, create: bool) Envelope {
    return .{ .deposit = .{
        .source_hash = .init(@splat(0x5c)),
        .from = .init(@splat(0x11)),
        .to = if (create) .create else .{ .call = .init(@splat(0x22)) },
        .mint = 1_000_000_000_000,
        .value = 77,
        .gas_limit = 90_000,
        .is_system_transaction = false,
        .input = input,
    } };
}

fn expect_transactions(block: *const L2FullBlock, decoded: *const l2_block_full.L2Block) !void {
    try testing.expectEqual(block.count, decoded.transactions.len);
    for (block.transactions(), decoded.transactions) |envelope, bytes| {
        var buffer: [2048]u8 = undefined;
        try testing.expectEqualSlices(u8, envelope.encode_to(&buffer), bytes);
    }
}

test "l2 block full: decodes deposits, signed transactions, and withdrawals" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const signed = fixtures.signed_transactions();
    const extra = [_]Envelope{
        user_deposit("deploy", true), signed[0], signed[1], signed[2], signed[3],
    };
    var block: L2FullBlock = undefined;
    block.init(9, .init(@splat(8)), 2, &extra);
    block.withdrawals[0] = .{ .index = 3, .validator_index = 4, .address = .zero, .amount = 5 };
    block.withdrawal_count = 1;
    var buffer: [16 * 1024]u8 = undefined;
    const text = try block.json_text(&buffer);
    const decoded = try l2_block_full.decode(arena.allocator(), text, &genesis_default, .{});
    try testing.expect(decoded.info.block_info.hash.eql(block.hash()));
    try testing.expectEqual(@as(u64, 509), decoded.info.l1_origin.number);
    try testing.expectEqual(@as(u64, 2), decoded.info.sequence_number);
    try testing.expect(decoded.prev_randao.eql(.init(@splat(0x3d))));
    try testing.expect(decoded.fee_recipient.eql(.init(@splat(0xfe))));
    try testing.expectEqual(@as(u64, 30_000_000), decoded.gas_limit);
    try testing.expectEqualStrings("needlefish", decoded.extra_data);
    try testing.expect(decoded.withdrawals_root.?.eql(primitives.empty_root_hash));
    try testing.expect(decoded.parent_beacon_block_root.?.eql(.init(@splat(0xbe))));
    try testing.expectEqual(@as(usize, 1), decoded.withdrawals.?.len);
    try testing.expectEqual(@as(u64, 5), decoded.withdrawals.?[0].amount_gwei);
    try expect_transactions(&block, &decoded);
    try testing.expectEqual(@as(u8, 0x7e), decoded.transactions[1][0]);
}

test "l2 block full: genesis anchors at the rollup genesis" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var block: L2FullBlock = undefined;
    block.init(0, .zero, 0, &.{});
    var buffer: [8 * 1024]u8 = undefined;
    const text = try block.json_text(&buffer);
    var genesis: ChainGenesis = .{ .l1 = .{ .number = 40, .hash = .init(@splat(4)) } };
    const allocator = arena.allocator();
    const mismatch = l2_block_full.decode(allocator, text, &genesis, .{});
    try testing.expectError(error.GenesisMismatch, mismatch);
    genesis.l2.hash = block.hash();
    const decoded = try l2_block_full.decode(allocator, text, &genesis, .{});
    try testing.expectEqual(@as(u64, 40), decoded.info.l1_origin.number);
    try testing.expectEqual(@as(u64, 0), decoded.info.sequence_number);
}

test "l2 block full: rejects tampering, missing deposits, and hash-only bodies" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const signed = fixtures.signed_transactions();
    var block: L2FullBlock = undefined;
    block.init(5, .zero, 0, &.{ user_deposit("x", false), signed[2] });
    var buffer: [16 * 1024]u8 = undefined;
    const text = try block.json_text(&buffer);
    const genesis = &genesis_default;

    // A changed deposit field no longer hashes to the reported hash.
    const mint = std.mem.indexOf(u8, text, "\"mint\":\"0xe8d4a51000\"").?;
    buffer[mint + 10] = '9';
    const tampered = l2_block_full.decode(allocator, text, genesis, .{});
    try testing.expectError(error.HashMismatch, tampered);
    buffer[mint + 10] = 'e';
    _ = try l2_block_full.decode(allocator, text, genesis, .{});

    // A block whose transactions differ from the header's root.
    var other: L2FullBlock = undefined;
    other.init(5, .zero, 0, &.{signed[2]});
    other.header = block.header;
    const root_text = try other.json_text(&buffer);
    const root = l2_block_full.decode(allocator, root_text, genesis, .{});
    try testing.expectError(error.RootMismatch, root);

    // The first transaction must be the L1 info deposit.
    other.init(5, .zero, 0, &.{signed[2]});
    other.envelopes[0] = signed[1];
    other.header = fixtures.header_for(other.transactions(), 5, .zero);
    const no_deposit = try other.json_text(&buffer);
    const missing = l2_block_full.decode(allocator, no_deposit, genesis, .{});
    try testing.expectError(error.MissingL1InfoDeposit, missing);

    var hashes_buffer: [8 * 1024]u8 = undefined;
    const header = &block.header;
    const hashes = try fixtures.block_json(&hashes_buffer, header, block.transactions(), false);
    const hash_only = l2_block_full.decode(allocator, hashes, genesis, .{});
    try testing.expectError(error.InvalidJson, hash_only);
    const too_many: l2_block_full.Limits = .{ .transactions = .{ .transactions_max = 2 } };
    const full_text = try block.json_text(&buffer);
    const large = l2_block_full.decode(allocator, full_text, genesis, too_many);
    try testing.expectError(error.TooLarge, large);
}

/// Builds a random block from `signed` and random deposits; its memory lives in `block`.
fn random_block(
    prng: *Prng,
    block: *L2FullBlock,
    inputs: *[8][16]u8,
    signed: *const [4]Envelope,
) void {
    var extra: [8]Envelope = undefined;
    const count = prng.below(extra.len + 1);
    for (extra[0..count], 0..) |*envelope, index| {
        if (prng.chance(1, 2)) {
            envelope.* = signed[prng.below(signed.len)];
            continue;
        }
        prng.fill(&inputs[index]);
        const input = inputs[index][0..prng.below(17)];
        envelope.* = .{ .deposit = .{
            .source_hash = .init(@splat(prng.int(u8))),
            .from = .init(@splat(prng.int(u8))),
            .to = if (prng.chance(1, 4)) .create else .{ .call = .init(@splat(prng.int(u8))) },
            .mint = if (prng.chance(1, 2)) 0 else prng.int(u64),
            .value = if (prng.chance(1, 2)) 0 else prng.int(u128),
            .gas_limit = prng.int(u32),
            .is_system_transaction = prng.chance(1, 8),
            .input = input,
        } };
    }
    block.init(1 + prng.below(1000), .init(@splat(prng.int(u8))), prng.below(4), extra[0..count]);
    block.withdrawal_count = @intCast(prng.below(fixtures.l2_full_withdrawals_max + 1));
    for (block.withdrawals[0..block.withdrawal_count]) |*item| {
        item.* = .{
            .index = prng.int(u64),
            .validator_index = prng.int(u32),
            .address = .init(@splat(prng.int(u8))),
            .amount = prng.int(u64),
        };
    }
}

test "l2 block full: seeded round trip and mutation fuzz" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const signed = fixtures.signed_transactions();
    var prng = Prng.init(0xb10c);
    var block: L2FullBlock = undefined;
    var inputs: [8][16]u8 = undefined;
    var buffer: [16 * 1024]u8 = undefined;
    for (0..200) |_| {
        _ = arena.reset(.retain_capacity);
        random_block(&prng, &block, &inputs, &signed);
        const text = try block.json_text(&buffer);
        const allocator = arena.allocator();
        const decoded = try l2_block_full.decode(allocator, text, &genesis_default, .{});
        try expect_transactions(&block, &decoded);
        try testing.expect(decoded.info.block_info.hash.eql(block.hash()));
        try testing.expectEqual(block.withdrawal_count, decoded.withdrawals.?.len);
        for (0..prng.range(1, 3)) |_| {
            const position = prng.below(text.len);
            buffer[position] = switch (prng.below(3)) {
                0 => "{}[],:\"0x1fn"[prng.below(12)],
                1 => prng.int(u8),
                2 => "0123456789abcdef"[prng.below(16)],
                else => unreachable,
            };
        }
        _ = arena.reset(.retain_capacity);
        decode_arbitrary(arena.allocator(), buffer[0..text.len]);
    }
}

fn decode_arbitrary(allocator: std.mem.Allocator, input: []const u8) void {
    const decoded = l2_block_full.decode(allocator, input, &genesis_default, .{}) catch return;
    // Whatever decodes is self-consistent: one L1 info deposit leads a non-genesis block.
    assert(decoded.transactions.len > 0);
    assert(decoded.transactions[0][0] == 0x7e);
}

fn fuzz_l2_block_full(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [4096]u8 = undefined;
    const size = smith.slice(&input);
    var memory: [64 * 1024]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    decode_arbitrary(fixed.allocator(), input[0..size]);
}

test "l2 block full: fuzz decoder" {
    try std.testing.fuzz({}, fuzz_l2_block_full, .{});
}

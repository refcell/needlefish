//! AttributesMatch tests ported from base/base `crates/consensus/engine/src/attributes.rs`,
//! plus a seeded fuzz (a block built from attributes matches; one mutated field yields
//! the expected mismatch) and a `std.testing.fuzz` target over arbitrary pairs.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const primitives = @import("../../common/primitives/root.zig");
const tx = @import("../../common/consensus/tx.zig");
const protocol = @import("../protocol/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;
const attributes_match = @import("attributes_match.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const RollupConfig = protocol.rollup_config.RollupConfig;
const L2Block = attributes_match.L2Block;
const Mismatch = attributes_match.Mismatch;
const FeeParams = attributes_match.FeeParams;
const Tag = std.meta.Tag(Mismatch);

const canyon = attributes_match.fee_params_canyon_default;

fn default_attributes() AttributesWithParent {
    return .{
        .attributes = .{
            .timestamp = 0,
            .prev_randao = .zero,
            .suggested_fee_recipient = .zero,
            .withdrawals = null,
            .parent_beacon_block_root = null,
            .transactions = &.{},
            .no_tx_pool = true,
            .gas_limit = 0,
            .eip1559_params = null,
            .min_base_fee = null,
        },
        .parent = .{},
        .derived_from = .{},
        .is_last_in_span = true,
    };
}

fn check(
    config: *const RollupConfig,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) ?Mismatch {
    return attributes_match.check(config, canyon, attributes, block);
}

fn expect_tag(expected: Tag, result: ?Mismatch) !void {
    const mismatch = result orelse return error.TestExpectedMismatch;
    try testing.expectEqual(expected, std.meta.activeTag(mismatch));
}

fn deposit_tx(buffer: []u8, source: u8, input: []const u8) []u8 {
    const envelope: tx.Envelope = .{ .deposit = .{
        .source_hash = .init(@splat(source)),
        .from = .zero,
        .to = .{ .call = .zero },
        .mint = 0,
        .value = 0,
        .gas_limit = 1_000_000,
        .is_system_transaction = false,
        .input = input,
    } };
    return envelope.encode_to(buffer);
}

fn holocene_extra(denominator: u32, elasticity: u32) [9]u8 {
    var extra: [9]u8 = undefined;
    extra[0] = 0;
    std.mem.writeInt(u32, extra[1..5], denominator, .big);
    std.mem.writeInt(u32, extra[5..9], elasticity, .big);
    return extra;
}

fn jovian_extra(denominator: u32, elasticity: u32, min_base_fee: u64) [17]u8 {
    var extra: [17]u8 = undefined;
    extra[0] = 1;
    std.mem.writeInt(u32, extra[1..5], denominator, .big);
    std.mem.writeInt(u32, extra[5..9], elasticity, .big);
    std.mem.writeInt(u64, extra[9..17], min_base_fee, .big);
    return extra;
}

fn params(denominator: u32, elasticity: u32) [8]u8 {
    var result: [8]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], denominator, .big);
    std.mem.writeInt(u32, result[4..8], elasticity, .big);
    return result;
}

test "attributes match: default attributes match the default block" {
    const config: RollupConfig = .{};
    const attributes = default_attributes();
    const block: L2Block = .{ .info = .{} };
    try testing.expect(check(&config, &attributes, &block) == null);
}

test "attributes match: header field mismatches" {
    const config: RollupConfig = .{};
    const attributes = default_attributes();
    var block: L2Block = .{ .info = .{} };
    block.info.block_info.parent_hash = .init(@splat(0x12));
    try expect_tag(.parent_hash, check(&config, &attributes, &block));
    block = .{ .info = .{} };
    block.info.block_info.timestamp = 1234567890;
    try expect_tag(.timestamp, check(&config, &attributes, &block));
    block = .{ .info = .{} };
    block.prev_randao = .init(@splat(0x34));
    try expect_tag(.prev_randao, check(&config, &attributes, &block));
    block = .{ .info = .{} };
    block.gas_limit = 123456;
    const gas = check(&config, &attributes, &block).?;
    try testing.expectEqual([2]u64{ 0, 123456 }, gas.gas_limit);
    block = .{ .info = .{}, .parent_beacon_block_root = .init(@splat(1)) };
    try expect_tag(.parent_beacon_block_root, check(&config, &attributes, &block));
    block = .{ .info = .{}, .fee_recipient = .init(@splat(9)) };
    try expect_tag(.fee_recipient, check(&config, &attributes, &block));
}

test "attributes match: transactions" {
    const config: RollupConfig = .{};
    var buffer_a: [256]u8 = undefined;
    var buffer_b: [256]u8 = undefined;
    const tx_a = deposit_tx(&buffer_a, 1, "a");
    const tx_b = deposit_tx(&buffer_b, 2, "b");
    var attributes = default_attributes();
    var attribute_txs = [_][]u8{tx_a};
    attributes.attributes.transactions = &attribute_txs;
    var block: L2Block = .{ .info = .{}, .transactions = &.{tx_a} };
    try testing.expect(check(&config, &attributes, &block) == null);

    block.transactions = &.{ tx_a, tx_b };
    const length = check(&config, &attributes, &block).?;
    try testing.expectEqual([2]u64{ 1, 2 }, length.transaction_len);

    block.transactions = &.{tx_b};
    const content = check(&config, &attributes, &block).?;
    try testing.expect(content.transaction_content.attributes.eql(primitives.keccak256(tx_a)));
    try testing.expect(content.transaction_content.block.eql(primitives.keccak256(tx_b)));

    // Trailing bytes after a valid encoding: not canonical (base/base
    // `attributes_mismatch_non_canonical_transaction_encoding`).
    var trailing: [257]u8 = undefined;
    @memcpy(trailing[0..tx_a.len], tx_a);
    trailing[tx_a.len] = 0;
    attribute_txs[0] = trailing[0 .. tx_a.len + 1];
    block.transactions = &.{tx_a};
    try expect_tag(.malformed_attributes_transaction, check(&config, &attributes, &block));

    // Empty attributes against a non-empty block.
    attributes.attributes.transactions = &.{};
    try expect_tag(.transaction_len, check(&config, &attributes, &block));
}

fn holocene_setup(config: *RollupConfig, attributes: *AttributesWithParent, block: *L2Block) void {
    config.* = .{};
    config.upgrades.set(.holocene, 0);
    attributes.* = default_attributes();
    attributes.attributes.withdrawals = &.{};
    block.* = .{ .info = .{}, .withdrawals = &.{}, .withdrawals_root = primitives.empty_root_hash };
}

test "attributes match: eip1559 parameters under holocene" {
    var config: RollupConfig = undefined;
    var attributes: AttributesWithParent = undefined;
    var block: L2Block = undefined;
    holocene_setup(&config, &attributes, &block);
    try expect_tag(.missing_attributes_eip1559, check(&config, &attributes, &block));

    attributes.attributes.eip1559_params = @splat(0);
    try expect_tag(.invalid_extra_data_length, check(&config, &attributes, &block));

    const zero_extra = holocene_extra(0, 0);
    block.extra_data = &zero_extra;
    const zero = check(&config, &attributes, &block).?;
    try testing.expect(zero.eip1559_parameters.attributes.eql(canyon));
    try testing.expect(zero.eip1559_parameters.block.eql(.{ .elasticity = 0, .denominator = 0 }));

    const canyon_extra = holocene_extra(250, 6);
    block.extra_data = &canyon_extra;
    try testing.expect(check(&config, &attributes, &block) == null);

    const custom_extra = holocene_extra(100, 2);
    block.extra_data = &custom_extra;
    attributes.attributes.eip1559_params = params(100, 2);
    try testing.expect(check(&config, &attributes, &block) == null);
    attributes.attributes.eip1559_params = params(99, 2);
    const custom = check(&config, &attributes, &block).?;
    try testing.expect(custom.eip1559_parameters.attributes.eql(.{
        .elasticity = 2,
        .denominator = 99,
    }));

    attributes.attributes.eip1559_params = params(5, 0);
    try expect_tag(.invalid_eip1559_params_combination, check(&config, &attributes, &block));

    var bad_version = holocene_extra(100, 2);
    bad_version[0] = 10;
    block.extra_data = &bad_version;
    attributes.attributes.eip1559_params = params(100, 2);
    try expect_tag(.invalid_extra_data_version, check(&config, &attributes, &block));
}

test "attributes match: jovian min base fee" {
    var config: RollupConfig = undefined;
    var attributes: AttributesWithParent = undefined;
    var block: L2Block = undefined;
    holocene_setup(&config, &attributes, &block);
    config.upgrades.set(.jovian, 0);
    attributes.attributes.eip1559_params = params(100, 2);
    // Holocene encoding after Jovian has the wrong length.
    const holocene_encoded = holocene_extra(100, 2);
    block.extra_data = &holocene_encoded;
    try expect_tag(.invalid_extra_data_length, check(&config, &attributes, &block));

    const extra_123 = jovian_extra(100, 2, 123);
    block.extra_data = &extra_123;
    try expect_tag(.missing_attributes_min_base_fee, check(&config, &attributes, &block));
    attributes.attributes.min_base_fee = 123;
    try testing.expect(check(&config, &attributes, &block) == null);
    const extra_456 = jovian_extra(100, 2, 456);
    block.extra_data = &extra_456;
    const result = check(&config, &attributes, &block).?;
    try testing.expectEqual([2]u64{ 123, 456 }, result.min_base_fee);
}

test "attributes match: withdrawals rules" {
    var config: RollupConfig = .{};
    var attributes = default_attributes();
    var block: L2Block = .{ .info = .{} };
    attributes.attributes.withdrawals = &.{};
    try expect_tag(.bedrock_withdrawals, check(&config, &attributes, &block));

    config.upgrades.set(.canyon, 0);
    try expect_tag(.canyon_withdrawals_not_empty, check(&config, &attributes, &block));
    block.withdrawals = &.{};
    try expect_tag(.canyon_not_empty_hash, check(&config, &attributes, &block));
    block.withdrawals_root = primitives.empty_root_hash;
    try testing.expect(check(&config, &attributes, &block) == null);
    attributes.attributes.withdrawals = null;
    try expect_tag(.canyon_withdrawals_not_empty, check(&config, &attributes, &block));

    var isthmus: RollupConfig = .{};
    isthmus.upgrades.set(.isthmus, 0);
    attributes.attributes.withdrawals = &.{};
    attributes.attributes.eip1559_params = params(250, 6);
    const extra = holocene_extra(250, 6);
    block = .{ .info = .{}, .withdrawals = &.{}, .extra_data = &extra };
    try expect_tag(.isthmus_missing_withdrawals_root, check(&isthmus, &attributes, &block));
    // After Isthmus any root is accepted (the L2-to-L1 message passer storage root).
    block.withdrawals_root = .init(@splat(7));
    try testing.expect(check(&isthmus, &attributes, &block) == null);
}

test "attributes match: deposits only helpers" {
    var buffer: [256]u8 = undefined;
    const deposit = deposit_tx(&buffer, 1, "");
    const user = [_]u8{ 0x02, 0xc0 };
    try testing.expect(attributes_match.is_deposits_only(&.{}));
    try testing.expect(attributes_match.is_deposits_only(&.{ deposit, deposit }));
    try testing.expect(!attributes_match.is_deposits_only(&.{ deposit, &user }));
    try testing.expectEqual(@as(u32, 1), attributes_match.deposits_prefix_len(&.{
        deposit,
        &user,
        deposit,
    }));
}

/// Attributes and a block built to match them, from fuzz input.
const Pair = struct {
    config: RollupConfig,
    attributes: AttributesWithParent,
    block: L2Block,
    transactions: [4][]u8,
    buffers: [4][160]u8,
    extra: [17]u8,

    fn init(pair: *Pair, prng: *Prng) void {
        pair.config = .{};
        const fork = prng.below(4);
        if (fork >= 1) pair.config.upgrades.set(.canyon, 0);
        if (fork >= 2) pair.config.upgrades.set(.holocene, 0);
        if (fork >= 3) pair.config.upgrades.set(.jovian, 0);
        pair.attributes = default_attributes();
        const payload = &pair.attributes.attributes;
        payload.timestamp = prng.int(u64);
        payload.prev_randao = .init(@splat(prng.int(u8)));
        payload.suggested_fee_recipient = .init(@splat(prng.int(u8)));
        payload.gas_limit = prng.int(u64);
        payload.parent_beacon_block_root = if (prng.chance(1, 2)) .init(@splat(3)) else null;
        pair.attributes.parent.block_info.hash = .init(@splat(prng.int(u8)));
        const count = prng.below(pair.transactions.len + 1);
        for (0..count) |index| {
            var input: [8]u8 = undefined;
            prng.fill(&input);
            pair.transactions[index] = deposit_tx(&pair.buffers[index], @intCast(index), &input);
        }
        payload.transactions = pair.transactions[0..count];
        pair.block = .{
            .info = .{ .block_info = .{
                .parent_hash = pair.attributes.parent.block_info.hash,
                .timestamp = payload.timestamp,
            } },
            .prev_randao = payload.prev_randao,
            .gas_limit = payload.gas_limit,
            .fee_recipient = payload.suggested_fee_recipient,
            .parent_beacon_block_root = payload.parent_beacon_block_root,
            .transactions = pair.transactions[0..count],
        };
        pair.init_fork_fields(prng, fork);
    }

    fn init_fork_fields(pair: *Pair, prng: *Prng, fork: u64) void {
        const payload = &pair.attributes.attributes;
        if (fork >= 1) {
            payload.withdrawals = &.{};
            pair.block.withdrawals = &.{};
            pair.block.withdrawals_root = primitives.empty_root_hash;
        }
        if (fork < 2) return;
        const denominator: u32 = @intCast(prng.range(1, 1000));
        const elasticity: u32 = @intCast(prng.range(1, 20));
        payload.eip1559_params = params(denominator, elasticity);
        if (fork == 2) {
            pair.extra[0..9].* = holocene_extra(denominator, elasticity);
            pair.block.extra_data = pair.extra[0..9];
        } else {
            const min_base_fee = prng.int(u64);
            payload.min_base_fee = min_base_fee;
            pair.extra = jovian_extra(denominator, elasticity, min_base_fee);
            pair.block.extra_data = &pair.extra;
        }
    }

    fn result(pair: *const Pair) ?Mismatch {
        return check(&pair.config, &pair.attributes, &pair.block);
    }
};

/// Mutates one field of the block and returns the mismatch it must produce: every other
/// field still matches, so the check reports exactly this one.
fn mutate(pair: *Pair, prng: *Prng) ?Tag {
    const block = &pair.block;
    const choice = prng.below(6);
    switch (choice) {
        0 => block.info.block_info.parent_hash.bytes[0] +%= 1,
        1 => block.info.block_info.timestamp +%= 1,
        2 => block.prev_randao.bytes[31] +%= 1,
        3 => block.gas_limit +%= 1,
        4 => block.fee_recipient.bytes[0] +%= 1,
        5 => {
            if (block.transactions.len == 0) return null;
            block.transactions = block.transactions[0 .. block.transactions.len - 1];
        },
        else => unreachable,
    }
    const tags = [_]Tag{
        .parent_hash, .timestamp, .prev_randao, .gas_limit, .fee_recipient, .transaction_len,
    };
    return tags[choice];
}

test "attributes match: seeded fuzz" {
    var prng = Prng.init(0x5eed_a77e);
    for (0..500) |_| {
        var pair: Pair = undefined;
        pair.init(&prng);
        try testing.expect(pair.result() == null);
        const expected = mutate(&pair, &prng) orelse continue;
        try expect_tag(expected, pair.result());
    }
}

fn fuzz_check(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var pair: Pair = undefined;
    pair.init(&prng);
    if (pair.result() != null) return error.TestUnexpectedMismatch;
    var junk: [64]u8 = undefined;
    const length = smith.slice(&junk);
    pair.block.extra_data = junk[0..length];
    if (smith.value(bool)) pair.block.transactions = &.{junk[0..length]};
    const first = pair.result();
    const second = pair.result();
    try testing.expectEqual(first == null, second == null);
}

test "attributes match: fuzz arbitrary pairs" {
    try testing.fuzz({}, fuzz_check, .{});
}

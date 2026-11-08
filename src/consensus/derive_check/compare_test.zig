//! Comparison tests on a recorded Base Sepolia block (56060011: Jovian extra data, 200 ms
//! blocks, an L1 info and a BaseTimeUpdate deposit, two user transactions). Attributes are
//! rebuilt from the full block, so they match; each test then breaks one compared field
//! and expects the matching mismatch and report.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const chains = @import("../../common/chains/root.zig");
const l2_block = @import("../sources/l2_block.zig");
const l2_block_full = @import("../sources/l2_block_full.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;
const compare = @import("compare.zig");
const start = @import("start.zig");

const full_json = @embedFile("testdata/base_sepolia_56060011_full.json");
const header_json = @embedFile("testdata/base_sepolia_56060011_header.json");
const number: u64 = 56_060_011;

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    rollup: @import("../protocol/root.zig").RollupConfig,
    block: compare.L2Block,
    attributes: AttributesWithParent,

    fn init(fixture: *Fixture) !void {
        fixture.arena = .init(testing.allocator);
        errdefer fixture.arena.deinit();
        fixture.rollup = start.rollup_config_for(&chains.sepolia);
        const arena = fixture.arena.allocator();
        fixture.block = try l2_block_full.decode(arena, full_json, &fixture.rollup.genesis, .{});
        fixture.attributes = try attributes_of(arena, &fixture.block);
    }

    fn deinit(fixture: *Fixture) void {
        fixture.arena.deinit();
    }

    fn check(fixture: *const Fixture, block: *const compare.L2Block) ?compare.Mismatch {
        const params = start.fee_params_canyon(&chains.sepolia);
        return compare.check(&fixture.rollup, params, &fixture.attributes, block);
    }

    fn header(fixture: *Fixture) !compare.HeaderView {
        return compare.decode_header(fixture.arena.allocator(), header_json, &fixture.attributes);
    }
};

/// The attributes a verifier derives for `block` (Jovian: EIP-1559 params and minimum base
/// fee from the extra data, empty withdrawals).
fn attributes_of(arena: Allocator, block: *const compare.L2Block) !AttributesWithParent {
    const transactions = try arena.alloc([]u8, block.transactions.len);
    for (transactions, block.transactions) |*copy, original| copy.* = try arena.dupe(u8, original);
    const extra = block.extra_data;
    const header = block.info.block_info;
    return .{
        .attributes = .{
            .timestamp = header.timestamp,
            .prev_randao = block.prev_randao,
            .suggested_fee_recipient = block.fee_recipient,
            .withdrawals = &.{},
            .parent_beacon_block_root = block.parent_beacon_block_root,
            .transactions = transactions,
            .no_tx_pool = true,
            .gas_limit = block.gas_limit,
            .eip1559_params = extra[1..9].*,
            .min_base_fee = std.mem.readInt(u64, extra[9..17], .big),
        },
        .parent = .{ .block_info = .{ .hash = header.parent_hash, .number = header.number - 1 } },
        .derived_from = null,
        .is_last_in_span = false,
    };
}

const Tag = std.meta.Tag(compare.Mismatch);

/// The kind of mismatch; a match fails the test (a compared field was not compared).
fn tag_of(fixture: *const Fixture, block: *const compare.L2Block) !Tag {
    const mismatch = fixture.check(block) orelse return error.ExpectedMismatch;
    return std.meta.activeTag(mismatch);
}

test "derive check compare: header path matches the recorded block" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    try testing.expectEqual(number, fixture.block.info.block_info.number);
    try testing.expectEqual(@as(usize, 4), fixture.block.transactions.len);
    try testing.expectEqual(@as(?compare.Mismatch, null), fixture.check(&fixture.block));

    const view = try fixture.header();
    try testing.expect(view.transactions_root_match);
    try testing.expectEqual(@as(?compare.Mismatch, null), fixture.check(&view.block));
    // The L1 origin and sequence number come from the derived L1 info deposit.
    try testing.expect(view.block.info.eql(fixture.block.info));

    const config = try compare.system_config_of(&fixture.rollup, &view.block);
    const reference = try l2_block.decode_with_system_config(full_json, &fixture.rollup);
    try testing.expect(std.meta.eql(reference.system_config, config));
    try testing.expect(reference.info.eql(view.block.info));
}

test "derive check compare: a changed transaction fails the root and names the index" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const changed = fixture.attributes.attributes.transactions[3];
    changed[changed.len - 1] ^= 1;
    const view = try fixture.header();
    try testing.expect(!view.transactions_root_match);
    try testing.expectEqual(@as(usize, 0), view.block.transactions.len);
    const mismatch = fixture.check(&fixture.block) orelse return error.ExpectedMismatch;
    try testing.expectEqual(@as(u32, 3), mismatch.transaction_content.index);

    var buffer: [64 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try compare.write_report(&writer, mismatch, &fixture.attributes, &fixture.block);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "l2 block 56060011") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transaction_content") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transaction index 3") != null);
    var hex: [16]u8 = undefined;
    const tail = fixture.block.transactions[3][changed.len - 4 ..];
    const reference_tail = try std.fmt.bufPrint(&hex, "{x}", .{tail});
    try testing.expect(std.mem.indexOf(u8, text, reference_tail) != null);
}

test "derive check compare: a dropped transaction is a count mismatch with the missing encoding" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const all = fixture.attributes.attributes.transactions;
    fixture.attributes.attributes.transactions = all[0..3];
    const mismatch = fixture.check(&fixture.block) orelse return error.ExpectedMismatch;
    try testing.expectEqual([2]u64{ 3, 4 }, mismatch.transaction_len);
    var buffer: [64 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try compare.write_report(&writer, mismatch, &fixture.attributes, &fixture.block);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "derived:   absent") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transaction index 3") != null);
}

test "derive check compare: every header field is compared" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const view = try fixture.header();
    const payload = &fixture.attributes.attributes;
    const original = payload.*;
    const Case = struct { tag: Tag };
    var cases: [7]Case = undefined;

    payload.timestamp += 1;
    cases[0] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.prev_randao.bytes[0] ^= 1;
    cases[1] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.gas_limit -= 1;
    cases[2] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.suggested_fee_recipient.bytes[19] ^= 1;
    cases[3] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.parent_beacon_block_root = .zero;
    cases[4] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.eip1559_params.?[7] +%= 1;
    cases[5] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    payload.min_base_fee.? += 1;
    cases[6] = .{ .tag = try tag_of(&fixture, &view.block) };
    payload.* = original;
    try testing.expectEqual(@as(?compare.Mismatch, null), fixture.check(&view.block));

    const expected = [_]Tag{
        .timestamp,                .prev_randao,        .gas_limit,    .fee_recipient,
        .parent_beacon_block_root, .eip1559_parameters, .min_base_fee,
    };
    for (expected, cases) |tag, case| try testing.expectEqual(tag, case.tag);
}

test "derive check compare: a block that is not the parent's child is rejected" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    fixture.attributes.parent.block_info.number += 1;
    try testing.expectError(error.NumberMismatch, fixture.header());
    fixture.attributes.parent.block_info.number -= 1;
    var parent = &fixture.attributes.parent.block_info.hash;
    parent.bytes[0] ^= 1;
    const view = try fixture.header();
    try testing.expectEqual(.parent_hash, try tag_of(&fixture, &view.block));
}

test "derive check compare: seeded fuzz of the header decoder" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x4844_5243);
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var buffer: [header_json.len]u8 = undefined;
    for (0..300) |_| {
        @memcpy(&buffer, header_json);
        for (0..1 + prng.below(4)) |_| {
            buffer[prng.below(buffer.len)] = prng.int(u8);
        }
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        // Any single-byte change breaks the hash binding, the JSON, or both.
        const outcome = compare.decode_header(scratch.allocator(), &buffer, &fixture.attributes);
        if (outcome) |view| {
            try testing.expect(view.block.info.block_info.number == number);
        } else |_| {}
    }
}

test "derive check compare: fuzz the header decoder" {
    try testing.fuzz({}, fuzz_header, .{});
}

fn fuzz_header(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    const length = smith.slice(&input);
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const view = compare.decode_header(scratch.allocator(), input[0..length], &fixture.attributes);
    if (view) |decoded| {
        std.debug.assert(decoded.block.info.block_info.number == number);
    } else |_| {}
}

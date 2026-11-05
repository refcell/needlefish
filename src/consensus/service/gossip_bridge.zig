//! Converts between the engine's execution payloads (`insert_task.Envelope`) and the p2p
//! gossip payloads (`p2p.gossip.block`), for publishing sealed sequencer blocks and for
//! inserting gossiped unsafe blocks. base/base converts between `OpExecutionPayloadEnvelope`
//! and its SSZ form in `crates/consensus/gossip` the same way.
//!
//! Neither direction allocates on its own: gossip encoding writes into a caller buffer, and
//! decoding borrows the gossip bytes and takes the transaction slice table from an allocator
//! (the node uses an arena that is reset per block).

const std = @import("std");
const assert = std.debug.assert;

const insert_task = @import("../engine/insert_task.zig");
const block = @import("../p2p/gossip/block.zig");
const ssz = @import("../p2p/gossip/ssz_payload.zig");
const rollup_config = @import("../protocol/rollup_config.zig");

pub const Envelope = insert_task.Envelope;
pub const Withdrawal = ssz.Withdrawal;

/// Bytes `encode_gossip` needs for `envelope`'s transactions and withdrawals.
pub fn gossip_storage_size(envelope: *const Envelope) u64 {
    const payload = &envelope.payload;
    const withdrawals: u64 = if (payload.withdrawals) |items| items.len else 0;
    const size = ssz.Transactions.list_length(payload.transactions) + withdrawals * 44;
    assert(size >= payload.transactions.len * 4);
    return size;
}

pub const EncodeError = error{ StorageTooSmall, TooManyWithdrawals, ExtraDataTooLong };

/// The gossip payload for a sealed block, at the gossip version for its timestamp. Variable
/// data borrows `envelope` (extra data) and `storage` (transactions, withdrawals).
pub fn encode_gossip(
    rollup: *const rollup_config.RollupConfig,
    envelope: *const Envelope,
    storage: []u8,
) EncodeError!block.ExecutionPayload {
    const source = &envelope.payload;
    if (gossip_storage_size(envelope) > storage.len) return error.StorageTooSmall;
    if (source.extra_data.len > ssz.extra_data_size_max) return error.ExtraDataTooLong;
    const withdrawals = source.withdrawals orelse &.{};
    if (withdrawals.len > ssz.withdrawals_count_max) return error.TooManyWithdrawals;
    var payload: block.ExecutionPayload = .{
        .version = block.version_at(rollup, source.timestamp),
        .parent_hash = source.parent_hash,
        .fee_recipient = source.fee_recipient,
        .state_root = source.state_root,
        .receipts_root = source.receipts_root,
        .logs_bloom = source.logs_bloom,
        .prev_randao = source.prev_randao,
        .block_number = source.block_number,
        .gas_limit = source.gas_limit,
        .gas_used = source.gas_used,
        .timestamp = source.timestamp,
        .extra_data = source.extra_data,
        .base_fee_per_gas = source.base_fee_per_gas,
        .block_hash = source.block_hash,
        .blob_gas_used = source.blob_gas_used orelse 0,
        .excess_blob_gas = source.excess_blob_gas orelse 0,
        .withdrawals_root = source.withdrawals_root orelse .zero,
    };
    payload.transactions = ssz.Transactions.encode(storage, source.transactions);
    const used = payload.transactions.bytes.len;
    payload.withdrawals = ssz.Withdrawals.encode(storage[used..], withdrawals);
    assert(payload.transactions.count == source.transactions.len);
    assert(payload.withdrawals.count == withdrawals.len);
    return payload;
}

/// The engine envelope for a gossiped block. Transactions borrow the gossip bytes; the slice
/// table and withdrawals come from `allocator`.
pub fn decode_gossip(
    allocator: std.mem.Allocator,
    envelope: *const block.Envelope,
) std.mem.Allocator.Error!Envelope {
    const source = &envelope.payload;
    const transactions = try allocator.alloc([]const u8, source.transactions.count);
    for (transactions, 0..) |*transaction, index| {
        transaction.* = source.transactions.get(@intCast(index));
    }
    var withdrawals: ?[]Withdrawal = null;
    if (source.has_withdrawals()) {
        const items = try allocator.alloc(Withdrawal, source.withdrawals.count);
        for (items, 0..) |*item, index| item.* = source.withdrawals.get(@intCast(index));
        withdrawals = items;
    }
    const v3 = source.has_blob_gas();
    const v4 = @backingInt(source.version) >= @backingInt(ssz.Version.v4);
    const result: Envelope = .{
        .payload = .{
            .parent_hash = source.parent_hash,
            .fee_recipient = source.fee_recipient,
            .state_root = source.state_root,
            .receipts_root = source.receipts_root,
            .logs_bloom = source.logs_bloom,
            .prev_randao = source.prev_randao,
            .block_number = source.block_number,
            .gas_limit = source.gas_limit,
            .gas_used = source.gas_used,
            .timestamp = source.timestamp,
            .extra_data = source.extra_data,
            .base_fee_per_gas = source.base_fee_per_gas,
            .block_hash = source.block_hash,
            .transactions = transactions,
            .withdrawals = withdrawals,
            .blob_gas_used = if (v3) source.blob_gas_used else null,
            .excess_blob_gas = if (v3) source.excess_blob_gas else null,
            .withdrawals_root = if (v4) source.withdrawals_root else null,
        },
        .parent_beacon_block_root = envelope.parent_beacon_block_root,
    };
    assert(result.payload.transactions.len == source.transactions.count);
    assert(result.payload.block_hash.eql(source.block_hash));
    return result;
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn rollup_all_active() rollup_config.RollupConfig {
    var rollup: rollup_config.RollupConfig = .{ .block_time = 2 };
    rollup.upgrades.set(.canyon, 0);
    rollup.upgrades.set(.ecotone, 0);
    rollup.upgrades.set(.isthmus, 0);
    return rollup;
}

/// gossip -> engine -> gossip keeps every field (versions match when all forks are active).
fn round_trip(prng: *Prng, version: ssz.Version) !void {
    var rollup = rollup_all_active();
    var storage: [8192]u8 = undefined;
    var original = ssz.random_payload(prng, version, &storage);
    original.timestamp = prng.below(1 << 40);
    if (!original.has_withdrawals()) original.withdrawals = .{};
    if (!original.has_blob_gas()) {
        original.blob_gas_used = 0;
        original.excess_blob_gas = 0;
    }
    if (version != .v4) original.withdrawals_root = .zero;
    const gossip_envelope: block.Envelope = .{
        .version = version,
        .signature = @splat(0),
        .y_parity = 0,
        .parent_beacon_block_root = if (block.has_parent_beacon_root(version)) .zero else null,
        .payload = original,
        .payload_hash = .zero,
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const engine = try decode_gossip(arena.allocator(), &gossip_envelope);
    try testing.expectEqual(version == .v4, engine.payload.withdrawals_root != null);
    if (version != .v4) return; // Earlier versions re-encode at the all-active version.
    var out: [8192]u8 = undefined;
    const back = try encode_gossip(&rollup, &engine, &out);
    try testing.expectEqual(version, back.version);
    try testing.expectEqualSlices(u8, original.transactions.bytes, back.transactions.bytes);
    try testing.expectEqualSlices(u8, original.withdrawals.bytes, back.withdrawals.bytes);
    try testing.expectEqualSlices(u8, original.extra_data, back.extra_data);
    try testing.expect(original.block_hash.eql(back.block_hash));
    try testing.expect(original.withdrawals_root.eql(back.withdrawals_root));
    try testing.expectEqual(original.base_fee_per_gas, back.base_fee_per_gas);
    try testing.expectEqual(original.excess_blob_gas, back.excess_blob_gas);
}

test "gossip bridge: seeded round trip for every payload version" {
    var prng = Prng.init(0x6055);
    const versions = [_]ssz.Version{ .v1, .v2, .v3, .v4 };
    for (0..256) |_| try round_trip(&prng, versions[prng.below(versions.len)]);
}

test "gossip bridge: encode picks the version by timestamp and checks storage" {
    var rollup: rollup_config.RollupConfig = .{ .block_time = 2 };
    rollup.upgrades.set(.canyon, 10);
    const transactions = [_][]const u8{ "ab", "cde" };
    var envelope: Envelope = .{ .payload = .{
        .parent_hash = .zero,
        .fee_recipient = .zero,
        .state_root = .zero,
        .receipts_root = .zero,
        .logs_bloom = .zero,
        .prev_randao = .zero,
        .block_number = 1,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = 4,
        .extra_data = &.{},
        .base_fee_per_gas = 7,
        .block_hash = .init(@splat(1)),
        .transactions = &transactions,
    } };
    try testing.expectEqual(@as(u64, 13), gossip_storage_size(&envelope));
    var small: [12]u8 = undefined;
    try testing.expectError(error.StorageTooSmall, encode_gossip(&rollup, &envelope, &small));
    var storage: [64]u8 = undefined;
    const before = try encode_gossip(&rollup, &envelope, &storage);
    try testing.expectEqual(ssz.Version.v1, before.version);
    try testing.expectEqualSlices(u8, "cde", before.transactions.get(1));
    envelope.payload.timestamp = 10;
    envelope.payload.withdrawals = &.{};
    const after = try encode_gossip(&rollup, &envelope, &storage);
    try testing.expectEqual(ssz.Version.v2, after.version);
    try testing.expectEqual(@as(u32, 0), after.withdrawals.count);
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [2048]u8 = undefined;
    const len = smith.slice(&bytes);
    const version: ssz.Version = .v4;
    const envelope = block.decode_decompressed(version, bytes[0..len]) catch return;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const engine = try decode_gossip(arena.allocator(), &envelope);
    var rollup = rollup_all_active();
    var out: [4096]u8 = undefined;
    if (gossip_storage_size(&engine) > out.len) return;
    const back = try encode_gossip(&rollup, &engine, &out);
    try testing.expect(back.block_hash.eql(envelope.payload.block_hash));
}

test "gossip bridge: fuzz decode then encode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

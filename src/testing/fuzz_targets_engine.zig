//! Differential fuzz targets for the Engine API JSON codecs of the two lanes that speak
//! it: the consensus client (`consensus/sources/engine_json.zig`) and the execution
//! server (`execution/rpc/engine_json.zig`).
//!
//! Random execution payloads (V1 through V4 field sets, empty and full byte strings,
//! zero and maximal quantities) and payload attributes (every optional OP field present
//! or absent) are written by one lane and parsed by the other. Properties:
//!   - payloads: consensus write -> execution parse, and execution write -> consensus
//!     decode, both return the original payload exactly;
//!   - attributes: consensus write -> execution parse returns the original attributes;
//!   - payload status and forkchoice-updated results: execution write -> consensus
//!     decode returns the original (validation errors without JSON escapes, which the
//!     consensus decoder documents it keeps escaped).
//! A mismatch is a wire incompatibility between the node's own halves.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const json = @import("../utilities/json/root.zig");
const primitives = @import("../common/primitives/root.zig");
const consensus_json = @import("../consensus/sources/engine_json.zig");
const execution_json = @import("../execution/rpc/engine_json.zig");
const engine_types = @import("../execution/engine/types.zig");
const attributes_module = @import("../execution/payload/attributes.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const ExecutionPayload = engine_types.ExecutionPayload;
const PayloadAttributes = attributes_module.PayloadAttributes;
const Withdrawal = attributes_module.Withdrawal;

const transactions_max = 6;
const transaction_bytes_max = 64;
const withdrawals_max = 4;
const extra_data_max = 32;
const text_bytes_max = 16 * 1024;

/// Backing storage for one generated payload or attributes value.
const Storage = struct {
    transaction_bytes: [transactions_max][transaction_bytes_max]u8,
    transactions: [transactions_max][]const u8,
    withdrawals: [withdrawals_max]Withdrawal,
    extra_data: [extra_data_max]u8,
};

/// Quantities skewed toward the encoding edges: zero, one, small, and the type maximum.
fn quantity(comptime T: type, prng: *Prng) T {
    return switch (prng.below(5)) {
        0 => 0,
        1 => 1,
        2 => @intCast(prng.below(1 << 16)),
        3 => std.math.maxInt(T),
        else => @truncate(@as(u256, prng.int(u64)) << @intCast(prng.below(193))),
    };
}

fn bytes32(prng: *Prng) B256 {
    var result: B256 = undefined;
    if (prng.chance(1, 4)) result.bytes = @splat(0) else prng.fill(&result.bytes);
    return result;
}

fn address(prng: *Prng) Address {
    var result: Address = undefined;
    prng.fill(&result.bytes);
    return result;
}

fn transactions(prng: *Prng, storage: *Storage) []const []const u8 {
    const count: usize = @intCast(prng.below(transactions_max + 1));
    for (storage.transactions[0..count], storage.transaction_bytes[0..count]) |*tx, *bytes| {
        const length: usize = @intCast(prng.range(1, transaction_bytes_max));
        prng.fill(bytes[0..length]);
        tx.* = bytes[0..length];
    }
    return storage.transactions[0..count];
}

fn withdrawals(prng: *Prng, storage: *Storage) []const Withdrawal {
    const count: usize = @intCast(prng.below(withdrawals_max + 1));
    for (storage.withdrawals[0..count]) |*withdrawal| {
        withdrawal.* = .{
            .index = quantity(u64, prng),
            .validator_index = quantity(u64, prng),
            .address = address(prng),
            .amount_gwei = quantity(u64, prng),
        };
    }
    return storage.withdrawals[0..count];
}

fn generate_payload(prng: *Prng, storage: *Storage) ExecutionPayload {
    const version = prng.below(4); // V1 .. V4 field sets.
    const extra_length: usize = @intCast(prng.below(extra_data_max + 1));
    prng.fill(storage.extra_data[0..extra_length]);
    var payload: ExecutionPayload = .{
        .parent_hash = bytes32(prng),
        .fee_recipient = address(prng),
        .state_root = bytes32(prng),
        .receipts_root = bytes32(prng),
        .logs_bloom = undefined,
        .prev_randao = bytes32(prng),
        .block_number = quantity(u64, prng),
        .gas_limit = quantity(u64, prng),
        .gas_used = quantity(u64, prng),
        .timestamp = quantity(u64, prng),
        .extra_data = storage.extra_data[0..extra_length],
        .base_fee_per_gas = quantity(u256, prng),
        .block_hash = bytes32(prng),
        .transactions = transactions(prng, storage),
    };
    if (prng.chance(1, 3)) payload.logs_bloom.bytes = @splat(0) else {
        prng.fill(&payload.logs_bloom.bytes);
    }
    if (version >= 1) payload.withdrawals = withdrawals(prng, storage);
    if (version >= 2) {
        payload.blob_gas_used = quantity(u64, prng);
        payload.excess_blob_gas = quantity(u64, prng);
    }
    if (version >= 3) payload.withdrawals_root = bytes32(prng);
    return payload;
}

fn generate_attributes(prng: *Prng, storage: *Storage) PayloadAttributes {
    var attributes: PayloadAttributes = .{
        .timestamp = quantity(u64, prng),
        .prev_randao = bytes32(prng),
        .suggested_fee_recipient = address(prng),
    };
    if (prng.chance(1, 2)) attributes.withdrawals = withdrawals(prng, storage);
    if (prng.chance(1, 2)) attributes.parent_beacon_block_root = bytes32(prng);
    if (prng.chance(1, 2)) attributes.transactions = transactions(prng, storage);
    if (prng.chance(1, 2)) attributes.no_tx_pool = prng.chance(1, 2);
    if (prng.chance(1, 2)) attributes.gas_limit = quantity(u64, prng);
    if (prng.chance(1, 2)) {
        var params: [8]u8 = undefined;
        prng.fill(&params);
        attributes.eip1559_params = params;
    }
    if (prng.chance(1, 2)) attributes.min_base_fee = quantity(u64, prng);
    return attributes;
}

fn render(
    buffer: []u8,
    comptime write: anytype,
    value: anytype,
) ![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try write(&writer, value);
    return out.buffered();
}

const ExecutionSpace = struct {
    bytes: [text_bytes_max]u8 = undefined,
    transactions: [transactions_max][]const u8 = undefined,
    withdrawals: [withdrawals_max]Withdrawal = undefined,
    hashes: [4]B256 = undefined,

    fn space(storage: *ExecutionSpace) execution_json.Space {
        return .{
            .bytes = &storage.bytes,
            .transactions = &storage.transactions,
            .withdrawals = &storage.withdrawals,
            .hashes = &storage.hashes,
        };
    }
};

fn fuzz_payload(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var storage: Storage = undefined;
    const payload = generate_payload(&prng, &storage);
    var text_buffer: [text_bytes_max]u8 = undefined;
    var execution_storage: ExecutionSpace = .{};
    var space = execution_storage.space();

    // Consensus writes (engine_newPayload), execution parses.
    const sent = try render(&text_buffer, consensus_json.write_payload, &payload);
    const parsed = try execution_json.parse_payload(sent, &space);
    try std.testing.expectEqualDeep(payload, parsed);

    // Execution writes (engine_getPayload), consensus decodes.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const returned = try render(&text_buffer, execution_json.write_payload, &payload);
    const decoded = try consensus_json.decode_payload(arena.allocator(), returned, .{});
    try std.testing.expectEqualDeep(payload, decoded);
}

fn fuzz_attributes(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var storage: Storage = undefined;
    const attributes = generate_attributes(&prng, &storage);
    var text_buffer: [text_bytes_max]u8 = undefined;
    var execution_storage: ExecutionSpace = .{};
    var space = execution_storage.space();
    const sent = try render(&text_buffer, consensus_json.write_attributes, &attributes);
    const parsed = try execution_json.parse_attributes(sent, &space);
    try std.testing.expectEqualDeep(attributes, parsed);
}

fn generate_status(prng: *Prng, error_buffer: *[64]u8) engine_types.PayloadStatus {
    const statuses = [_]engine_types.Status{ .valid, .invalid, .syncing, .accepted };
    var status: engine_types.PayloadStatus = .{
        .status = statuses[@intCast(prng.below(statuses.len))],
    };
    if (prng.chance(1, 2)) status.latest_valid_hash = bytes32(prng);
    if (prng.chance(1, 2)) {
        const alphabet = "abcXYZ019 :-_.";
        const length: usize = @intCast(prng.below(error_buffer.len + 1));
        for (error_buffer[0..length]) |*c| c.* = alphabet[@intCast(prng.below(alphabet.len))];
        status.validation_error = error_buffer[0..length];
    }
    return status;
}

fn fuzz_status(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var error_buffer: [64]u8 = undefined;
    var updated: engine_types.ForkchoiceUpdated = .{
        .payload_status = generate_status(&prng, &error_buffer),
    };
    if (prng.chance(1, 2)) {
        var id: attributes_module.PayloadId = undefined;
        prng.fill(&id);
        updated.payload_id = id;
    }
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var text_buffer: [1024]u8 = undefined;
    const write_status = execution_json.write_status;
    const status_text = try render(&text_buffer, write_status, updated.payload_status);
    const status = try consensus_json.decode_payload_status(allocator, status_text, .{});
    try std.testing.expectEqualDeep(updated.payload_status, status);
    const write_updated = execution_json.write_forkchoice_updated;
    const updated_text = try render(&text_buffer, write_updated, updated);
    const decoded = try consensus_json.decode_forkchoice_updated(allocator, updated_text, .{});
    try std.testing.expectEqualDeep(updated, decoded);
}

test "fuzz_targets_engine: payload status and forkchoice results cross the boundary" {
    try fuzz.run({}, fuzz_status, .{ .iterations = 512 });
}

test "fuzz_targets_engine: payloads cross the consensus/execution JSON boundary intact" {
    try fuzz.run({}, fuzz_payload, .{ .iterations = 512 });
}

test "fuzz_targets_engine: payload attributes cross the JSON boundary intact" {
    try fuzz.run({}, fuzz_attributes, .{ .iterations = 512 });
}

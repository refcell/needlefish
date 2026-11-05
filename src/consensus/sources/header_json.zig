//! Decodes the header part of an `eth_getBlockByNumber` / `eth_getBlockByHash` result into
//! the consensus `Header` and checks that it hashes to the block's reported `hash`.
//!
//! The hash check binds every decoded field to the block hash, so a header that decodes
//! is the header of that block (whatever the RPC claims). Unknown keys are ignored;
//! known keys are strict. Mirrors the header handling of base/base
//! `crates/consensus/providers/src/chain_provider.rs` (`header.hash_slow()`).

const std = @import("std");
const assert = std.debug.assert;

const object = @import("json_object.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const protocol = @import("../protocol/root.zig");

const Header = consensus.Header;
const B256 = primitives.B256;
const BlockInfo = protocol.block.BlockInfo;
const L1Header = protocol.l1_info.L1Header;
const Error = object.Error;

/// Post-merge Ethereum caps extra data at 32 bytes; older clique chains used 97.
pub const extra_data_size_max = 128;

pub const DecodeError = Error || error{HashMismatch};

const Key = enum(u5) {
    parent_hash,
    ommers_hash,
    beneficiary,
    state_root,
    transactions_root,
    receipts_root,
    logs_bloom,
    difficulty,
    number,
    gas_limit,
    gas_used,
    timestamp,
    extra_data,
    mix_hash,
    nonce,
    base_fee_per_gas,
    withdrawals_root,
    blob_gas_used,
    excess_blob_gas,
    parent_beacon_block_root,
    requests_hash,
    hash,
};

const keys = std.StaticStringMap(Key).initComptime(.{
    .{ "parentHash", .parent_hash },
    .{ "sha3Uncles", .ommers_hash },
    .{ "miner", .beneficiary },
    .{ "stateRoot", .state_root },
    .{ "transactionsRoot", .transactions_root },
    .{ "receiptsRoot", .receipts_root },
    .{ "logsBloom", .logs_bloom },
    .{ "difficulty", .difficulty },
    .{ "number", .number },
    .{ "gasLimit", .gas_limit },
    .{ "gasUsed", .gas_used },
    .{ "timestamp", .timestamp },
    .{ "extraData", .extra_data },
    .{ "mixHash", .mix_hash },
    .{ "nonce", .nonce },
    .{ "baseFeePerGas", .base_fee_per_gas },
    .{ "withdrawalsRoot", .withdrawals_root },
    .{ "blobGasUsed", .blob_gas_used },
    .{ "excessBlobGas", .excess_blob_gas },
    .{ "parentBeaconBlockRoot", .parent_beacon_block_root },
    .{ "requestsHash", .requests_hash },
    .{ "hash", .hash },
});

const key_count = @typeInfo(Key).@"enum".field_names.len;
const Seen = object.Seen(key_count);

/// Every pre-London field plus the block hash.
const required_mask: u64 = blk: {
    var mask: u64 = 0;
    for (0..@backingInt(Key.nonce) + 1) |index| mask |= @as(u64, 1) << index;
    break :blk mask | @as(u64, 1) << @backingInt(Key.hash);
};

/// A verified header. `header.extra_data` borrows the caller's buffer.
pub const Decoded = struct {
    header: Header,
    hash: B256,

    pub fn block_info(decoded: *const Decoded) BlockInfo {
        return .{
            .hash = decoded.hash,
            .number = decoded.header.number,
            .parent_hash = decoded.header.parent_hash,
            .timestamp = decoded.header.timestamp,
        };
    }

    pub fn l1_header(decoded: *const Decoded) L1Header {
        const header = &decoded.header;
        return .{
            .number = header.number,
            .timestamp = header.timestamp,
            .hash = decoded.hash,
            .base_fee = header.base_fee_per_gas,
            .excess_blob_gas = header.excess_blob_gas,
            .parent_hash = header.parent_hash,
            .mix_hash = header.mix_hash,
            .blob_gas_used = header.blob_gas_used,
            .parent_beacon_block_root = header.parent_beacon_block_root,
            .requests_hash = header.requests_hash,
        };
    }
};

/// Decodes the header fields of a block object and verifies its hash. Keys that are not
/// header fields (transactions, uncles, size, ...) are skipped.
pub fn decode(raw: []const u8, extra_data: *[extra_data_size_max]u8) DecodeError!Decoded {
    var iterator = try object.ObjectIterator.init(raw);
    var header: Header = .{};
    var hash_claimed: B256 = .zero;
    var seen: Seen = .{};
    var fields: u32 = 0;
    while (try iterator.next()) |field| : (fields += 1) {
        if (fields > raw.len) unreachable; // Every field consumes input.
        const key = keys.get(field.key) orelse continue;
        try seen.see(@backingInt(key));
        if (key == .hash) {
            hash_claimed = try object.hash(field.value);
        } else {
            try apply(&header, key, field, extra_data);
        }
    }
    try seen.require(required_mask);
    if (!header.optionals_contiguous()) return error.InvalidField;
    const computed = header.hash();
    if (!computed.eql(hash_claimed)) return error.HashMismatch;
    assert(seen.has(@backingInt(Key.number)));
    return .{ .header = header, .hash = computed };
}

fn apply(
    header: *Header,
    key: Key,
    field: object.Field,
    extra_data: *[extra_data_size_max]u8,
) Error!void {
    assert(key != .hash);
    const value = field.value;
    switch (key) {
        .parent_hash => header.parent_hash = try object.hash(value),
        .ommers_hash => header.ommers_hash = try object.hash(value),
        .beneficiary => header.beneficiary = try object.address(value),
        .state_root => header.state_root = try object.hash(value),
        .transactions_root => header.transactions_root = try object.hash(value),
        .receipts_root => header.receipts_root = try object.hash(value),
        .logs_bloom => header.logs_bloom = .{ .bytes = try object.fixed(256, value) },
        .difficulty => header.difficulty = try object.quantity(u256, value),
        .number => header.number = try object.quantity(u64, value),
        .gas_limit => header.gas_limit = try object.quantity(u64, value),
        .gas_used => header.gas_used = try object.quantity(u64, value),
        .timestamp => header.timestamp = try object.quantity(u64, value),
        .extra_data => {
            const size = try object.data_size(value);
            if (size > extra_data_size_max) return error.TooLarge;
            try object.data_into(value, extra_data[0..size]);
            header.extra_data = extra_data[0..size];
        },
        .mix_hash => header.mix_hash = try object.hash(value),
        .nonce => header.nonce = .init(try object.fixed(8, value)),
        .base_fee_per_gas => header.base_fee_per_gas = try object.quantity(u64, value),
        .withdrawals_root => header.withdrawals_root = try object.hash(value),
        .blob_gas_used => header.blob_gas_used = try object.quantity(u64, value),
        .excess_blob_gas => header.excess_blob_gas = try object.quantity(u64, value),
        .parent_beacon_block_root => {
            header.parent_beacon_block_root = try object.hash(value);
        },
        .requests_hash => header.requests_hash = try object.hash(value),
        .hash => unreachable,
    }
}

/// Returns the raw `transactions` array of a block object, or null when absent.
pub fn transactions_raw(raw: []const u8) Error!?[]const u8 {
    var iterator = try object.ObjectIterator.init(raw);
    var fields: u32 = 0;
    while (try iterator.next()) |field| : (fields += 1) {
        assert(fields <= raw.len);
        if (!std.mem.eql(u8, field.key, "transactions")) continue;
        if (field.value.tag != .array_begin) return error.InvalidJson;
        return field.raw;
    }
    return null;
}

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "header json: decodes and verifies the hash" {
    const header = fixtures.header_for(&.{}, 42, .init(@splat(3)));
    var buffer: [4096]u8 = undefined;
    const text = try fixtures.block_json(&buffer, &header, &.{}, false);
    var extra: [extra_data_size_max]u8 = undefined;
    const decoded = try decode(text, &extra);
    try testing.expect(decoded.hash.eql(header.hash()));
    try testing.expectEqualStrings("needlefish", decoded.header.extra_data);
    try testing.expectEqual(@as(u64, 42), decoded.block_info().number);
    try testing.expectEqual(@as(?u64, 0), decoded.l1_header().excess_blob_gas);
    try testing.expectEqualStrings("[]", (try transactions_raw(text)).?);
    const at = std.mem.indexOf(u8, text, "\"timestamp\":\"0x").? + 15;
    buffer[at] = if (buffer[at] == '1') '2' else '1';
    try testing.expectError(error.HashMismatch, decode(text, &extra));
}

test "header json: rejects missing, duplicate, and null fields" {
    var extra: [extra_data_size_max]u8 = undefined;
    try testing.expectError(error.MissingField, decode("{\"number\":\"0x1\"}", &extra));
    try testing.expectError(
        error.InvalidJson,
        decode("{\"number\":\"0x1\",\"number\":\"0x2\"}", &extra),
    );
    try testing.expectError(error.InvalidJson, decode("{\"requestsHash\":null}", &extra));
    try testing.expectError(error.InvalidJson, decode("[]", &extra));
}

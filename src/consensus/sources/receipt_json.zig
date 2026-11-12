//! Decodes an `eth_getBlockReceipts` result into the derivation view (`log.Receipt`) and,
//! optionally, verifies the receipts trie root against the (hash-verified) header, which
//! binds every log the pipeline reads (deposits, system config updates) to the block hash.
//! Mirrors base/base `AlloyChainProvider::receipts_by_hash`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const object = @import("json_object.zig");
const transaction_json = @import("transaction_json.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const ordered = @import("../../execution/trie/ordered.zig");
const protocol = @import("../protocol/root.zig");

const B256 = primitives.B256;
const Receipt = protocol.log.Receipt;
const Log = protocol.log.Log;

pub const Error = transaction_json.Error;

pub const Limits = struct {
    receipts_max: u32 = 8192,
    logs_per_receipt_max: u32 = 16 * 1024,
    log_data_size_max: u32 = 4 * 1024 * 1024,
};

/// LOG0..LOG4.
pub const topics_max = 4;

const Key = enum(u3) { tx_type, status, cumulative_gas_used, logs_bloom, logs };

const keys = std.StaticStringMap(Key).initComptime(.{
    .{ "type", .tx_type },
    .{ "status", .status },
    .{ "cumulativeGasUsed", .cumulative_gas_used },
    .{ "logsBloom", .logs_bloom },
    .{ "logs", .logs },
});

/// One decoded receipt: the derivation view plus, when verifying, its consensus form.
const Decoded = struct { receipt: Receipt, consensus: ?consensus.Receipt };

/// Decodes the receipts of a block. With `receipts_root`, the consensus receipts are
/// rebuilt and the trie root must match. Returned receipts live in `allocator`.
pub fn decode_block(
    allocator: Allocator,
    scratch: Allocator,
    raw: []const u8,
    receipts_root: ?B256,
    limits: Limits,
) Error![]Receipt {
    const count = try object.array_count(raw, limits.receipts_max);
    const receipts = try allocator.alloc(Receipt, count);
    const encoded = try scratch.alloc([]const u8, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (receipts, encoded) |*receipt, *item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        const verify = receipts_root != null;
        const decoded = try decode(allocator, scratch, element.raw, verify, limits);
        receipt.* = decoded.receipt;
        if (decoded.consensus) |value| {
            const buffer = try scratch.alloc(u8, value.encoded_length());
            item.* = value.encode_to(buffer);
        }
    }
    assert(try iterator.next() == null);
    if (receipts_root) |expected| {
        const root: B256 = .{ .bytes = ordered.ordered_trie_root(encoded) };
        if (!root.eql(expected)) return error.RootMismatch;
    }
    return receipts;
}

/// The EIP-2718 receipt encodings of an `eth_getBlockReceipts` result, verified against
/// `receipts_root` (the raw receipts where `debug_getRawReceipts` is missing).
pub fn encode_block(
    allocator: Allocator,
    raw: []const u8,
    receipts_root: B256,
    limits: Limits,
) Error![]const []const u8 {
    const count = try object.array_count(raw, limits.receipts_max);
    const encoded = try allocator.alloc([]const u8, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (encoded) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        const decoded = try decode(allocator, allocator, element.raw, true, limits);
        const value = decoded.consensus orelse unreachable; // Verified decodes build it.
        item.* = value.encode_to(try allocator.alloc(u8, value.encoded_length()));
    }
    assert(try iterator.next() == null);
    const root: B256 = .{ .bytes = ordered.ordered_trie_root(encoded) };
    if (!root.eql(receipts_root)) return error.RootMismatch;
    return encoded;
}

fn decode(
    allocator: Allocator,
    scratch: Allocator,
    raw: []const u8,
    verify: bool,
    limits: Limits,
) Error!Decoded {
    var iterator = try object.ObjectIterator.init(raw);
    var seen: object.Seen(5) = .{};
    var tx_type: u8 = 0;
    var status: u8 = 0;
    var cumulative_gas_used: u64 = 0;
    var logs_bloom: primitives.Bloom = .zero;
    var logs: []Log = &.{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const key = keys.get(field.key) orelse continue;
        try seen.see(@backingInt(key));
        switch (key) {
            .tx_type => tx_type = try object.quantity(u8, field.value),
            .status => status = try object.quantity(u8, field.value),
            .cumulative_gas_used => {
                cumulative_gas_used = try object.quantity(u64, field.value);
            },
            .logs_bloom => logs_bloom = .{ .bytes = try object.fixed(256, field.value) },
            .logs => logs = try decode_logs(allocator, field.raw, limits),
        }
    }
    // Pre-Byzantium receipts carry a state root instead of a status; L1 has none since.
    try seen.require(0b10010);
    if (status > 1) return error.InvalidField;
    const receipt: Receipt = .{ .success = status == 1, .logs = logs };
    if (!verify) return .{ .receipt = receipt, .consensus = null };
    try seen.require(0b11111);
    const consensus_type = std.enums.fromInt(consensus.TxType, tx_type) orelse
        return error.UnsupportedTransaction;
    if (consensus_type == .deposit or consensus_type == .eip8130) {
        return error.UnsupportedTransaction; // Never on L1.
    }
    return .{ .receipt = receipt, .consensus = .{
        .tx_type = consensus_type,
        .status = receipt.success,
        .cumulative_gas_used = cumulative_gas_used,
        .logs_bloom = logs_bloom,
        .logs = try build_logs(scratch, logs),
    } };
}

fn decode_logs(allocator: Allocator, raw: []const u8, limits: Limits) Error![]Log {
    const count = try object.array_count(raw, limits.logs_per_receipt_max);
    const logs = try allocator.alloc(Log, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (logs) |*log| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        log.* = try decode_log(allocator, element.raw, limits);
    }
    assert(try iterator.next() == null);
    return logs;
}

fn decode_log(allocator: Allocator, raw: []const u8, limits: Limits) Error!Log {
    var iterator = try object.ObjectIterator.init(raw);
    var seen: object.Seen(3) = .{};
    var log: Log = .{ .address = .zero, .topics = &.{}, .data = &.{} };
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "address")) {
            try seen.see(0);
            log.address = try object.address(field.value);
        } else if (std.mem.eql(u8, field.key, "topics")) {
            try seen.see(1);
            log.topics = try transaction_json.decode_hashes(allocator, field.raw, topics_max);
        } else if (std.mem.eql(u8, field.key, "data")) {
            try seen.see(2);
            log.data = try object.data_alloc(allocator, field.value, limits.log_data_size_max);
        }
    }
    try seen.require(0b111);
    assert(log.topics.len <= topics_max);
    return log;
}

fn build_logs(scratch: Allocator, logs: []const Log) Error!consensus.Logs {
    const items = try scratch.alloc(consensus.Log, logs.len);
    var size: usize = 0;
    for (logs, items) |log, *item| {
        const topics_buffer = try scratch.alloc(u8, log.topics.len * 33);
        item.* = .{
            .address = log.address,
            .topics = consensus.HashList.build(topics_buffer, log.topics),
            .data = log.data,
        };
        size += rlp.length(item.*);
    }
    const built = consensus.Logs.build(try scratch.alloc(u8, size), items);
    assert(built.count == logs.len);
    assert(built.payload.len == size);
    return built;
}

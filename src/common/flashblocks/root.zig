//! Flashblocks: the sub-block payload diffs a Base sequencer streams over WebSocket.
//! Mirrors base/base `crates/common/flashblocks` (JSON field names are snake_case; the
//! message is plain JSON or a brotli-compressed JSON document, capped at 5 MiB).
//!
//! Decoding allocates from a caller-supplied arena (one per message); every slice in the
//! result points into it.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rpc_json = @import("../rpc_types/json.zig");
// The brotli decoder is the consensus lane's (channel decompression); flashblocks reuse it.
const brotli = @import("../../consensus/protocol/brotli.zig");

const hex = primitives.hex;
const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;
const Writer = std.Io.Writer;
const Object = rpc_json.Object;

pub const max_decompressed_bytes: u64 = 5 * 1024 * 1024;

/// `<block_number>-<index>`.
pub const FlashblockId = struct {
    block_number: u64 = 0,
    index: u64 = 0,

    pub fn parse(text: []const u8) error{InvalidFlashblockId}!FlashblockId {
        const dash = std.mem.indexOfScalar(u8, text, '-') orelse return error.InvalidFlashblockId;
        const block_number = std.fmt.parseUnsigned(u64, text[0..dash], 10) catch
            return error.InvalidFlashblockId;
        const index = std.fmt.parseUnsigned(u64, text[dash + 1 ..], 10) catch
            return error.InvalidFlashblockId;
        return .{ .block_number = block_number, .index = index };
    }

    /// Writes the id into `buffer` (at least 41 bytes) and returns the text.
    pub fn format(id: FlashblockId, buffer: []u8) []u8 {
        assert(buffer.len >= 41);
        return std.fmt.bufPrint(buffer, "{d}-{d}", .{ id.block_number, id.index }) catch
            unreachable; // Two u64s and a dash fit in 41 bytes.
    }
};

pub const Metadata = struct {
    block_number: u64,
    prev_flashblock_id: FlashblockId = .{},
};

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: Address,
    amount_gwei: u64,
};

/// Fields fixed for the whole block, sent with the first flashblock (index 0).
pub const PayloadBase = struct {
    parent_beacon_block_root: B256,
    parent_hash: B256,
    fee_recipient: Address,
    prev_randao: B256,
    block_number: u64,
    gas_limit: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
};

/// The block state after this flashblock's transactions.
pub const Delta = struct {
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    gas_used: u64,
    block_hash: B256,
    /// EIP-2718 encoded transactions added by this flashblock.
    transactions: []const []const u8,
    withdrawals: []const Withdrawal,
    withdrawals_root: B256,
    blob_gas_used: ?u64 = null,
};

pub const Flashblock = struct {
    payload_id: [8]u8,
    index: u64,
    base: ?PayloadBase,
    diff: Delta,
    metadata: Metadata,
};

pub const DecodeError = error{
    PayloadTooLarge,
    Decompress,
    PayloadParse,
    MetadataParse,
    InvalidField,
    OutOfMemory,
};

/// Decodes a WebSocket message: JSON when it starts (after whitespace) with `{`,
/// brotli-compressed JSON otherwise.
pub fn decode_message(arena: std.mem.Allocator, message: []const u8) DecodeError!Flashblock {
    const text = try message_text(arena, message);
    assert(text.len <= max_decompressed_bytes);
    return decode_json(arena, text);
}

fn message_text(arena: std.mem.Allocator, message: []const u8) DecodeError![]const u8 {
    const trimmed = std.mem.trimStart(u8, message, " \t\r\n");
    if (trimmed.len > 0 and trimmed[0] == '{' and std.unicode.utf8ValidateSlice(message)) {
        if (message.len > max_decompressed_bytes) return error.PayloadTooLarge;
        return message;
    }
    const text = brotli.decompress(arena, message, max_decompressed_bytes) catch |err|
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.OutputLimitExceeded => error.PayloadTooLarge,
            else => error.Decompress,
        };
    if (!std.unicode.utf8ValidateSlice(text)) return error.Decompress;
    return text;
}

// Raw JSON shapes: hex strings are converted (and validated) after parsing.
const RawWithdrawal = struct {
    index: []const u8,
    validatorIndex: []const u8,
    address: []const u8,
    amount: []const u8,
};

const RawBase = struct {
    parent_beacon_block_root: []const u8,
    parent_hash: []const u8,
    fee_recipient: []const u8,
    prev_randao: []const u8,
    block_number: []const u8,
    gas_limit: []const u8,
    timestamp: []const u8,
    extra_data: []const u8,
    base_fee_per_gas: []const u8,
};

const RawDelta = struct {
    state_root: []const u8,
    receipts_root: []const u8,
    logs_bloom: []const u8,
    gas_used: []const u8,
    block_hash: []const u8,
    transactions: []const []const u8,
    withdrawals: []const RawWithdrawal,
    withdrawals_root: []const u8,
    blob_gas_used: ?[]const u8 = null,
};

const RawPayload = struct {
    payload_id: []const u8,
    index: u64,
    base: ?RawBase = null,
    diff: RawDelta,
    metadata: std.json.Value,
};

const RawMetadata = struct {
    block_number: u64,
    prev_flashblock_id: ?[]const u8 = null,
};

pub fn decode_json(arena: std.mem.Allocator, text: []const u8) DecodeError!Flashblock {
    const options: std.json.ParseOptions = .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
        .max_value_len = max_decompressed_bytes,
    };
    const raw = std.json.parseFromSliceLeaky(RawPayload, arena, text, options) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.PayloadParse;
    const metadata_value = raw.metadata;
    const raw_metadata =
        std.json.parseFromValueLeaky(RawMetadata, arena, metadata_value, options) catch |err|
            return if (err == error.OutOfMemory) error.OutOfMemory else error.MetadataParse;
    const previous = if (raw_metadata.prev_flashblock_id) |id|
        FlashblockId.parse(id) catch return error.MetadataParse
    else
        FlashblockId{};
    return .{
        .payload_id = try fixed(8, raw.payload_id),
        .index = raw.index,
        .base = if (raw.base) |base| try convert_base(arena, base) else null,
        .diff = try convert_delta(arena, raw.diff),
        .metadata = .{ .block_number = raw_metadata.block_number, .prev_flashblock_id = previous },
    };
}

fn fixed(comptime size: usize, text: []const u8) DecodeError![size]u8 {
    if (text.len != 2 + size * 2 or !std.mem.startsWith(u8, text, "0x")) return error.InvalidField;
    return hex.decode_array(size, text) catch error.InvalidField;
}

fn quantity(comptime T: type, text: []const u8) DecodeError!T {
    return hex.decode_quantity(T, text) catch error.InvalidField;
}

fn data(arena: std.mem.Allocator, text: []const u8) DecodeError![]const u8 {
    if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidField;
    const length = hex.decoded_length(text) catch return error.InvalidField;
    const output = try arena.alloc(u8, length);
    hex.decode(output, text) catch return error.InvalidField;
    return output;
}

fn convert_base(arena: std.mem.Allocator, raw: RawBase) DecodeError!PayloadBase {
    return .{
        .parent_beacon_block_root = .{ .bytes = try fixed(32, raw.parent_beacon_block_root) },
        .parent_hash = .{ .bytes = try fixed(32, raw.parent_hash) },
        .fee_recipient = .{ .bytes = try fixed(20, raw.fee_recipient) },
        .prev_randao = .{ .bytes = try fixed(32, raw.prev_randao) },
        .block_number = try quantity(u64, raw.block_number),
        .gas_limit = try quantity(u64, raw.gas_limit),
        .timestamp = try quantity(u64, raw.timestamp),
        .extra_data = try data(arena, raw.extra_data),
        .base_fee_per_gas = try quantity(u256, raw.base_fee_per_gas),
    };
}

fn convert_delta(arena: std.mem.Allocator, raw: RawDelta) DecodeError!Delta {
    const transactions = try arena.alloc([]const u8, raw.transactions.len);
    for (transactions, raw.transactions) |*out, text| out.* = try data(arena, text);
    const withdrawals = try arena.alloc(Withdrawal, raw.withdrawals.len);
    for (withdrawals, raw.withdrawals) |*out, item| out.* = .{
        .index = try quantity(u64, item.index),
        .validator_index = try quantity(u64, item.validatorIndex),
        .address = .{ .bytes = try fixed(20, item.address) },
        .amount_gwei = try quantity(u64, item.amount),
    };
    return .{
        .state_root = .{ .bytes = try fixed(32, raw.state_root) },
        .receipts_root = .{ .bytes = try fixed(32, raw.receipts_root) },
        .logs_bloom = .{ .bytes = try fixed(256, raw.logs_bloom) },
        .gas_used = try quantity(u64, raw.gas_used),
        .block_hash = .{ .bytes = try fixed(32, raw.block_hash) },
        .transactions = transactions,
        .withdrawals = withdrawals,
        .withdrawals_root = .{ .bytes = try fixed(32, raw.withdrawals_root) },
        .blob_gas_used = if (raw.blob_gas_used) |text| try quantity(u64, text) else null,
    };
}

/// Writes the payload JSON (`FlashblocksPayloadV1`); `base` is omitted when null.
pub fn write_json(w: *Writer, flashblock: Flashblock) rpc_json.Error!void {
    var object = try Object.begin(w);
    try object.data("payload_id", &flashblock.payload_id);
    try object.key("index");
    try w.print("{d}", .{flashblock.index});
    if (flashblock.base) |base| {
        try object.key("base");
        try write_base(w, base);
    }
    try object.key("diff");
    try write_delta(w, flashblock.diff);
    try object.key("metadata");
    var metadata = try Object.begin(w);
    try metadata.key("block_number");
    try w.print("{d}", .{flashblock.metadata.block_number});
    try metadata.key("prev_flashblock_id");
    var id_buffer: [41]u8 = undefined;
    try w.print("\"{s}\"", .{flashblock.metadata.prev_flashblock_id.format(&id_buffer)});
    try metadata.end();
    try object.end();
}

fn write_base(w: *Writer, base: PayloadBase) rpc_json.Error!void {
    var object = try Object.begin(w);
    try object.fixed("parent_beacon_block_root", base.parent_beacon_block_root);
    try object.fixed("parent_hash", base.parent_hash);
    try object.address("fee_recipient", base.fee_recipient);
    try object.fixed("prev_randao", base.prev_randao);
    try object.quantity("block_number", base.block_number);
    try object.quantity("gas_limit", base.gas_limit);
    try object.quantity("timestamp", base.timestamp);
    try object.data("extra_data", base.extra_data);
    try object.quantity("base_fee_per_gas", base.base_fee_per_gas);
    try object.end();
}

fn write_delta(w: *Writer, delta: Delta) rpc_json.Error!void {
    var object = try Object.begin(w);
    try object.fixed("state_root", delta.state_root);
    try object.fixed("receipts_root", delta.receipts_root);
    try object.fixed("logs_bloom", delta.logs_bloom);
    try object.quantity("gas_used", delta.gas_used);
    try object.fixed("block_hash", delta.block_hash);
    try object.key("transactions");
    try w.writeByte('[');
    for (delta.transactions, 0..) |transaction, index| {
        if (index > 0) try w.writeByte(',');
        try rpc_json.write_data(w, transaction);
    }
    try w.writeAll("]");
    try object.key("withdrawals");
    try w.writeByte('[');
    for (delta.withdrawals, 0..) |withdrawal, index| {
        if (index > 0) try w.writeByte(',');
        var item = try Object.begin(w);
        try item.quantity("index", withdrawal.index);
        try item.quantity("validatorIndex", withdrawal.validator_index);
        try item.address("address", withdrawal.address);
        try item.quantity("amount", withdrawal.amount_gwei);
        try item.end();
    }
    try w.writeByte(']');
    try object.fixed("withdrawals_root", delta.withdrawals_root);
    try object.optional_quantity("blob_gas_used", delta.blob_gas_used);
    try object.end();
}

test {
    _ = @import("root_test.zig");
}

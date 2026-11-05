//! JSON encoding of Engine API requests and decoding of their results, over the execution
//! lane's engine types (`execution/engine/types.zig`, `execution/payload/attributes.zig`).
//! Field names follow the execution-apis Engine API and the OP Stack extensions
//! (payload attributes `transactions`/`noTxPool`/`gasLimit`/`eip1559Params`/`minBaseFee`,
//! `withdrawalsRoot` in V4 payloads, `parentBeaconBlockRoot` in V3+ envelopes), as sent by
//! base/base `crates/consensus/engine/src/client.rs` through alloy.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const json = @import("../../utilities/json/root.zig");
const object = @import("json_object.zig");
const primitives = @import("../../common/primitives/root.zig");
const engine_types = @import("../../execution/engine/types.zig");
const payload_attributes = @import("../../execution/payload/attributes.zig");

const B256 = primitives.B256;
const Writer = json.Writer;
const WriteError = json.Writer.WriteError;

pub const ExecutionPayload = engine_types.ExecutionPayload;
pub const NewPayloadParams = engine_types.NewPayloadParams;
pub const PayloadStatus = engine_types.PayloadStatus;
pub const ForkchoiceState = engine_types.ForkchoiceState;
pub const ForkchoiceUpdated = engine_types.ForkchoiceUpdated;
pub const Version = engine_types.Version;
pub const Withdrawal = engine_types.Withdrawal;
pub const PayloadAttributes = payload_attributes.PayloadAttributes;
pub const PayloadId = payload_attributes.PayloadId;
pub const Error = object.Error;

pub const Limits = struct {
    transactions_max: u32 = 64 * 1024,
    transaction_size_max: u32 = 4 * 1024 * 1024,
    withdrawals_max: u32 = 16,
    execution_requests_max: u32 = 16,
    validation_error_size_max: u32 = 1024,
};

/// `engine_getPayloadV2+` result.
pub const PayloadEnvelope = struct {
    payload: ExecutionPayload,
    block_value: u256,
    parent_beacon_block_root: ?B256 = null,
    should_override_builder: bool = false,
    execution_requests: ?[]const []const u8 = null,
};

fn field_data(writer: *Writer, name: []const u8, bytes: []const u8) WriteError!void {
    try writer.key(name);
    try writer.data(bytes);
}

fn field_quantity(writer: *Writer, name: []const u8, value: anytype) WriteError!void {
    try writer.key(name);
    try writer.quantity(value);
}

fn write_withdrawals(writer: *Writer, withdrawals: []const Withdrawal) WriteError!void {
    try writer.key("withdrawals");
    try writer.begin_array();
    for (withdrawals) |withdrawal| {
        try writer.begin_object();
        try field_quantity(writer, "index", withdrawal.index);
        try field_quantity(writer, "validatorIndex", withdrawal.validator_index);
        try field_data(writer, "address", &withdrawal.address.bytes);
        try field_quantity(writer, "amount", withdrawal.amount_gwei);
        try writer.end_object();
    }
    try writer.end_array();
}

fn write_data_list(writer: *Writer, name: []const u8, items: []const []const u8) WriteError!void {
    try writer.key(name);
    try writer.begin_array();
    for (items) |item| try writer.data(item);
    try writer.end_array();
}

pub fn write_payload(writer: *Writer, payload: *const ExecutionPayload) WriteError!void {
    try writer.begin_object();
    try field_data(writer, "parentHash", &payload.parent_hash.bytes);
    try field_data(writer, "feeRecipient", &payload.fee_recipient.bytes);
    try field_data(writer, "stateRoot", &payload.state_root.bytes);
    try field_data(writer, "receiptsRoot", &payload.receipts_root.bytes);
    try field_data(writer, "logsBloom", &payload.logs_bloom.bytes);
    try field_data(writer, "prevRandao", &payload.prev_randao.bytes);
    try field_quantity(writer, "blockNumber", payload.block_number);
    try field_quantity(writer, "gasLimit", payload.gas_limit);
    try field_quantity(writer, "gasUsed", payload.gas_used);
    try field_quantity(writer, "timestamp", payload.timestamp);
    try field_data(writer, "extraData", payload.extra_data);
    try field_quantity(writer, "baseFeePerGas", payload.base_fee_per_gas);
    try field_data(writer, "blockHash", &payload.block_hash.bytes);
    try write_data_list(writer, "transactions", payload.transactions);
    if (payload.withdrawals) |withdrawals| try write_withdrawals(writer, withdrawals);
    if (payload.blob_gas_used) |used| try field_quantity(writer, "blobGasUsed", used);
    if (payload.excess_blob_gas) |excess| try field_quantity(writer, "excessBlobGas", excess);
    if (payload.withdrawals_root) |root| try field_data(writer, "withdrawalsRoot", &root.bytes);
    try writer.end_object();
}

/// `engine_newPayloadV<version>` params.
pub fn write_new_payload_params(
    writer: *Writer,
    version: Version,
    payload: *const ExecutionPayload,
    params: *const NewPayloadParams,
) WriteError!void {
    assert(@backingInt(version) >= 2 and @backingInt(version) <= 4);
    try write_payload(writer, payload);
    if (version == .v2) return;
    try writer.begin_array();
    for (params.versioned_hashes orelse &.{}) |hash| try writer.data(&hash.bytes);
    try writer.end_array();
    try writer.data(&(params.parent_beacon_block_root orelse B256.zero).bytes);
    if (version == .v3) return;
    try writer.begin_array();
    for (params.execution_requests orelse &.{}) |request| try writer.data(request);
    try writer.end_array();
}

pub fn write_attributes(writer: *Writer, attributes: *const PayloadAttributes) WriteError!void {
    try writer.begin_object();
    try field_quantity(writer, "timestamp", attributes.timestamp);
    try field_data(writer, "prevRandao", &attributes.prev_randao.bytes);
    try field_data(writer, "suggestedFeeRecipient", &attributes.suggested_fee_recipient.bytes);
    if (attributes.withdrawals) |withdrawals| try write_withdrawals(writer, withdrawals);
    if (attributes.parent_beacon_block_root) |root| {
        try field_data(writer, "parentBeaconBlockRoot", &root.bytes);
    }
    if (attributes.transactions) |transactions| {
        try write_data_list(writer, "transactions", transactions);
    }
    if (attributes.no_tx_pool) |no_tx_pool| {
        try writer.key("noTxPool");
        try writer.boolean(no_tx_pool);
    }
    if (attributes.gas_limit) |gas_limit| try field_quantity(writer, "gasLimit", gas_limit);
    if (attributes.eip1559_params) |params| try field_data(writer, "eip1559Params", &params);
    if (attributes.min_base_fee) |fee| try field_quantity(writer, "minBaseFee", fee);
    try writer.end_object();
}

/// `engine_forkchoiceUpdatedV<n>` params.
pub fn write_forkchoice_params(
    writer: *Writer,
    state: *const ForkchoiceState,
    attributes: ?*const PayloadAttributes,
) WriteError!void {
    try writer.begin_object();
    try field_data(writer, "headBlockHash", &state.head_block_hash.bytes);
    try field_data(writer, "safeBlockHash", &state.safe_block_hash.bytes);
    try field_data(writer, "finalizedBlockHash", &state.finalized_block_hash.bytes);
    try writer.end_object();
    if (attributes) |value| try write_attributes(writer, value) else try writer.null_value();
}

// Decoding.

/// Decodes a `PayloadStatusV1`. `validation_error` (still JSON-escaped) is copied into
/// `allocator`.
pub fn decode_payload_status(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!PayloadStatus {
    var iterator = try object.ObjectIterator.init(raw);
    var status: PayloadStatus = .{ .status = .syncing };
    var seen: object.Seen(3) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const value = field.value;
        if (std.mem.eql(u8, field.key, "status")) {
            try seen.see(0);
            if (value.tag != .string) return error.InvalidJson;
            status.status = try parse_status(value.bytes);
        } else if (std.mem.eql(u8, field.key, "latestValidHash")) {
            try seen.see(1);
            status.latest_valid_hash = if (value.tag == .null) null else try object.hash(value);
        } else if (std.mem.eql(u8, field.key, "validationError")) {
            try seen.see(2);
            if (value.tag == .null) continue;
            if (value.tag != .string) return error.InvalidJson;
            if (value.bytes.len > limits.validation_error_size_max) return error.TooLarge;
            status.validation_error = try allocator.dupe(u8, value.bytes);
        }
    }
    try seen.require(0b1);
    return status;
}

fn parse_status(text: []const u8) Error!engine_types.Status {
    const statuses = std.StaticStringMap(engine_types.Status).initComptime(.{
        .{ "VALID", .valid },
        .{ "INVALID", .invalid },
        .{ "SYNCING", .syncing },
        .{ "ACCEPTED", .accepted },
        // Pre-Shanghai status, still sent by some clients; treated as invalid.
        .{ "INVALID_BLOCK_HASH", .invalid },
    });
    return statuses.get(text) orelse error.InvalidField;
}

pub fn decode_forkchoice_updated(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!ForkchoiceUpdated {
    var iterator = try object.ObjectIterator.init(raw);
    var result: ForkchoiceUpdated = .{ .payload_status = .syncing };
    var seen: object.Seen(2) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "payloadStatus")) {
            try seen.see(0);
            result.payload_status = try decode_payload_status(allocator, field.raw, limits);
        } else if (std.mem.eql(u8, field.key, "payloadId")) {
            try seen.see(1);
            if (field.value.tag == .null) continue;
            result.payload_id = try object.fixed(8, field.value);
        }
    }
    try seen.require(0b1);
    return result;
}

const PayloadKey = enum(u5) {
    parent_hash,
    fee_recipient,
    state_root,
    receipts_root,
    logs_bloom,
    prev_randao,
    block_number,
    gas_limit,
    gas_used,
    timestamp,
    extra_data,
    base_fee_per_gas,
    block_hash,
    transactions,
    withdrawals,
    blob_gas_used,
    excess_blob_gas,
    withdrawals_root,
};

const payload_keys = std.StaticStringMap(PayloadKey).initComptime(.{
    .{ "parentHash", .parent_hash },
    .{ "feeRecipient", .fee_recipient },
    .{ "stateRoot", .state_root },
    .{ "receiptsRoot", .receipts_root },
    .{ "logsBloom", .logs_bloom },
    .{ "prevRandao", .prev_randao },
    .{ "blockNumber", .block_number },
    .{ "gasLimit", .gas_limit },
    .{ "gasUsed", .gas_used },
    .{ "timestamp", .timestamp },
    .{ "extraData", .extra_data },
    .{ "baseFeePerGas", .base_fee_per_gas },
    .{ "blockHash", .block_hash },
    .{ "transactions", .transactions },
    .{ "withdrawals", .withdrawals },
    .{ "blobGasUsed", .blob_gas_used },
    .{ "excessBlobGas", .excess_blob_gas },
    .{ "withdrawalsRoot", .withdrawals_root },
});

/// Every V1 field.
const payload_required: u64 = (@as(u64, 1) << (@backingInt(PayloadKey.transactions) + 1)) - 1;

/// Decodes an execution payload; byte strings are allocated from `allocator`.
pub fn decode_payload(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!ExecutionPayload {
    var iterator = try object.ObjectIterator.init(raw);
    var payload: ExecutionPayload = undefined;
    payload.withdrawals = null;
    payload.blob_gas_used = null;
    payload.excess_blob_gas = null;
    payload.withdrawals_root = null;
    var seen: object.Seen(@typeInfo(PayloadKey).@"enum".field_names.len) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const key = payload_keys.get(field.key) orelse continue;
        try seen.see(@backingInt(key));
        try apply_payload(allocator, &payload, key, field, limits);
    }
    try seen.require(payload_required);
    return payload;
}

fn apply_payload(
    allocator: Allocator,
    payload: *ExecutionPayload,
    key: PayloadKey,
    field: object.Field,
    limits: Limits,
) Error!void {
    const value = field.value;
    switch (key) {
        .parent_hash => payload.parent_hash = try object.hash(value),
        .fee_recipient => payload.fee_recipient = try object.address(value),
        .state_root => payload.state_root = try object.hash(value),
        .receipts_root => payload.receipts_root = try object.hash(value),
        .logs_bloom => payload.logs_bloom = .{ .bytes = try object.fixed(256, value) },
        .prev_randao => payload.prev_randao = try object.hash(value),
        .block_number => payload.block_number = try object.quantity(u64, value),
        .gas_limit => payload.gas_limit = try object.quantity(u64, value),
        .gas_used => payload.gas_used = try object.quantity(u64, value),
        .timestamp => payload.timestamp = try object.quantity(u64, value),
        .extra_data => payload.extra_data = try object.data_alloc(allocator, value, 256),
        .base_fee_per_gas => payload.base_fee_per_gas = try object.quantity(u256, value),
        .block_hash => payload.block_hash = try object.hash(value),
        .transactions => payload.transactions = try decode_data_list(
            allocator,
            field.raw,
            limits.transactions_max,
            limits.transaction_size_max,
        ),
        .withdrawals => payload.withdrawals = try decode_withdrawals(allocator, field.raw, limits),
        .blob_gas_used => payload.blob_gas_used = try object.quantity(u64, value),
        .excess_blob_gas => payload.excess_blob_gas = try object.quantity(u64, value),
        .withdrawals_root => payload.withdrawals_root = try object.hash(value),
    }
}

fn decode_data_list(
    allocator: Allocator,
    raw: []const u8,
    count_max: u32,
    size_max: u32,
) Error![]const []const u8 {
    const count = try object.array_count(raw, count_max);
    const items = try allocator.alloc([]const u8, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (items) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        item.* = try object.data_alloc(allocator, element.value, size_max);
    }
    assert(try iterator.next() == null);
    return items;
}

pub fn decode_withdrawals(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error![]Withdrawal {
    const count = try object.array_count(raw, limits.withdrawals_max);
    const withdrawals = try allocator.alloc(Withdrawal, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (withdrawals) |*withdrawal| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        withdrawal.* = try decode_withdrawal(element.raw);
    }
    assert(try iterator.next() == null);
    return withdrawals;
}

fn decode_withdrawal(raw: []const u8) Error!Withdrawal {
    var iterator = try object.ObjectIterator.init(raw);
    var withdrawal: Withdrawal = .{
        .index = 0,
        .validator_index = 0,
        .address = .zero,
        .amount_gwei = 0,
    };
    var seen: object.Seen(4) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "index")) {
            try seen.see(0);
            withdrawal.index = try object.quantity(u64, field.value);
        } else if (std.mem.eql(u8, field.key, "validatorIndex")) {
            try seen.see(1);
            withdrawal.validator_index = try object.quantity(u64, field.value);
        } else if (std.mem.eql(u8, field.key, "address")) {
            try seen.see(2);
            withdrawal.address = try object.address(field.value);
        } else if (std.mem.eql(u8, field.key, "amount")) {
            try seen.see(3);
            withdrawal.amount_gwei = try object.quantity(u64, field.value);
        }
    }
    try seen.require(0b1111);
    return withdrawal;
}

/// `OpExecutionPayloadEnvelope` as posted to `admin_postUnsafePayload`: the payload and,
/// from Ecotone on, the parent beacon block root. Other fields are ignored.
pub const UnsafeEnvelope = struct {
    payload: ExecutionPayload,
    parent_beacon_block_root: ?B256 = null,
};

pub fn decode_unsafe_envelope(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!UnsafeEnvelope {
    var iterator = try object.ObjectIterator.init(raw);
    var envelope: UnsafeEnvelope = .{ .payload = undefined };
    var seen: object.Seen(2) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "executionPayload")) {
            try seen.see(0);
            envelope.payload = try decode_payload(allocator, field.raw, limits);
        } else if (std.mem.eql(u8, field.key, "parentBeaconBlockRoot")) {
            try seen.see(1);
            if (field.value.tag != .null) {
                envelope.parent_beacon_block_root = try object.hash(field.value);
            }
        }
    }
    try seen.require(0b1);
    return envelope;
}

/// Decodes a getPayload V2-V5 envelope. V2 sends `executionPayload` and `blockValue`
/// only; later versions add the beacon root, override flag, and requests. The blobs
/// bundle is always empty on OP and ignored.
pub fn decode_payload_envelope(
    allocator: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!PayloadEnvelope {
    var iterator = try object.ObjectIterator.init(raw);
    var envelope: PayloadEnvelope = .{ .payload = undefined, .block_value = 0 };
    var seen: object.Seen(5) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const value = field.value;
        if (std.mem.eql(u8, field.key, "executionPayload")) {
            try seen.see(0);
            envelope.payload = try decode_payload(allocator, field.raw, limits);
        } else if (std.mem.eql(u8, field.key, "blockValue")) {
            try seen.see(1);
            envelope.block_value = try object.quantity(u256, value);
        } else if (std.mem.eql(u8, field.key, "parentBeaconBlockRoot")) {
            try seen.see(2);
            envelope.parent_beacon_block_root = try object.hash(value);
        } else if (std.mem.eql(u8, field.key, "shouldOverrideBuilder")) {
            try seen.see(3);
            envelope.should_override_builder = try object.boolean(value);
        } else if (std.mem.eql(u8, field.key, "executionRequests")) {
            try seen.see(4);
            const size_max = limits.transaction_size_max;
            const count_max = limits.execution_requests_max;
            envelope.execution_requests =
                try decode_data_list(allocator, field.raw, count_max, size_max);
        }
    }
    try seen.require(0b11);
    return envelope;
}

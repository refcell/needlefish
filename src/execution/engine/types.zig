//! Engine API types: execution payloads (V1-V4, OP Isthmus `withdrawalsRoot`), payload
//! status, forkchoice state, error codes, and per-fork method version rules.
//!
//! Version mapping follows base/base `crates/consensus/engine/src/versions.rs`:
//! forkchoiceUpdated V2 → V3 at Cancun/Ecotone; newPayload V2 → V3 at Cancun → V4 at
//! Prague/Isthmus; getPayload V2 → V3 → V4 → V5 at Osaka/Azul.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;

pub const Version = payload.Version;
pub const Withdrawal = payload.Withdrawal;

pub const ExecutionPayload = struct {
    parent_hash: B256,
    fee_recipient: Address,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    prev_randao: B256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: B256,
    transactions: []const []const u8,
    /// V2+ (Shanghai/Canyon).
    withdrawals: ?[]const Withdrawal = null,
    /// V3+ (Cancun/Ecotone).
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    /// OP V4 (Isthmus): L2ToL1MessagePasser storage root.
    withdrawals_root: ?B256 = null,
};

/// The `newPayloadV3+` side-car parameters.
pub const NewPayloadParams = struct {
    versioned_hashes: ?[]const B256 = null,
    parent_beacon_block_root: ?B256 = null,
    /// V4: EIP-7685 requests (must be empty on OP).
    execution_requests: ?[]const []const u8 = null,
};

pub const Status = enum { valid, invalid, syncing, accepted };

pub const PayloadStatus = struct {
    status: Status,
    latest_valid_hash: ?B256 = null,
    validation_error: ?[]const u8 = null,

    pub fn valid(hash: B256) PayloadStatus {
        return .{ .status = .valid, .latest_valid_hash = hash };
    }

    pub fn invalid(latest_valid_hash: ?B256, reason: []const u8) PayloadStatus {
        return .{
            .status = .invalid,
            .latest_valid_hash = latest_valid_hash,
            .validation_error = reason,
        };
    }

    pub const syncing: PayloadStatus = .{ .status = .syncing };
    pub const accepted: PayloadStatus = .{ .status = .accepted };
};

pub const ForkchoiceState = struct {
    head_block_hash: B256,
    safe_block_hash: B256,
    finalized_block_hash: B256,
};

pub const ForkchoiceUpdated = struct {
    payload_status: PayloadStatus,
    payload_id: ?payload.PayloadId = null,
};

/// Engine API JSON-RPC error codes (execution-apis `common.md`).
pub const ErrorCode = enum(i32) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
    server_error = -32000,
    unknown_payload = -38001,
    invalid_forkchoice_state = -38002,
    invalid_payload_attributes = -38003,
    too_large_request = -38004,
    unsupported_fork = -38005,
};

pub const EngineError = error{
    InvalidParams,
    UnknownPayload,
    InvalidForkchoiceState,
    InvalidPayloadAttributes,
    TooLargeRequest,
    UnsupportedFork,
    InternalError,
};

pub fn error_code(err: EngineError) ErrorCode {
    return switch (err) {
        error.InvalidParams => .invalid_params,
        error.UnknownPayload => .unknown_payload,
        error.InvalidForkchoiceState => .invalid_forkchoice_state,
        error.InvalidPayloadAttributes => .invalid_payload_attributes,
        error.TooLargeRequest => .too_large_request,
        error.UnsupportedFork => .unsupported_fork,
        error.InternalError => .internal_error,
    };
}

pub fn new_payload_version(spec: *const chainspec.ChainSpec, timestamp: u64) Version {
    if (spec.is_ethereum_fork_active(.prague, timestamp)) return .v4;
    if (spec.is_ethereum_fork_active(.cancun, timestamp)) return .v3;
    return .v2;
}

pub fn get_payload_version(spec: *const chainspec.ChainSpec, timestamp: u64) Version {
    if (spec.is_ethereum_fork_active(.osaka, timestamp)) return .v5;
    if (spec.is_ethereum_fork_active(.prague, timestamp)) return .v4;
    if (spec.is_ethereum_fork_active(.cancun, timestamp)) return .v3;
    return .v2;
}

pub fn forkchoice_version(spec: *const chainspec.ChainSpec, timestamp: u64) Version {
    if (spec.is_ethereum_fork_active(.cancun, timestamp)) return .v3;
    return .v2;
}

/// `newPayloadV<n>`: method version must match the payload's fork, and the payload
/// shape (withdrawals, blob fields, side-car params) must match the version.
pub fn validate_new_payload(
    spec: *const chainspec.ChainSpec,
    version: Version,
    p: *const ExecutionPayload,
    params: *const NewPayloadParams,
) EngineError!void {
    const expected = new_payload_version(spec, p.timestamp);
    // V1 is accepted for pre-Shanghai payloads; V2 also accepts V1-shaped payloads.
    const pre_v3_ok = @backingInt(expected) <= 2 and @backingInt(version) <= 2;
    if (version != expected and !pre_v3_ok) return error.UnsupportedFork;
    const shanghai = spec.is_ethereum_fork_active(.shanghai, p.timestamp);
    if (version == .v1 and p.withdrawals != null) return error.InvalidParams;
    if (shanghai != (p.withdrawals != null)) return error.InvalidParams;
    const v3 = @backingInt(version) >= 3;
    if (v3 != (p.blob_gas_used != null and p.excess_blob_gas != null)) return error.InvalidParams;
    if (v3 != (params.versioned_hashes != null)) return error.InvalidParams;
    if (v3 != (params.parent_beacon_block_root != null)) return error.InvalidParams;
    const v4 = @backingInt(version) >= 4;
    if (v4 != (params.execution_requests != null)) return error.InvalidParams;
    if (spec.mode == .l2) {
        if (v4 != (p.withdrawals_root != null)) return error.InvalidParams;
        if (v4 and params.execution_requests.?.len != 0) return error.InvalidParams;
        if (v3 and params.versioned_hashes.?.len != 0) return error.InvalidParams;
        // OP Canyon+: withdrawals list must be empty.
        if (p.withdrawals) |w| if (w.len != 0) return error.InvalidParams;
    } else if (p.withdrawals_root != null) return error.InvalidParams;
    assert(!v4 or v3);
}

/// `getPayloadV<n>`: method version must match the fork of the built payload.
pub fn validate_get_payload(
    spec: *const chainspec.ChainSpec,
    version: Version,
    timestamp: u64,
) EngineError!void {
    const expected = get_payload_version(spec, timestamp);
    if (version == expected) return;
    // getPayloadV1/V2 are interchangeable before Cancun (V1 only before Shanghai).
    if (@backingInt(expected) == 2 and version == .v1) {
        if (spec.is_ethereum_fork_active(.shanghai, timestamp)) return error.UnsupportedFork;
        return;
    }
    return error.UnsupportedFork;
}

const testing = std.testing;

fn empty_payload(timestamp: u64) ExecutionPayload {
    return .{
        .parent_hash = B256.zero,
        .fee_recipient = Address.zero,
        .state_root = B256.zero,
        .receipts_root = B256.zero,
        .logs_bloom = std.mem.zeroes(Bloom),
        .prev_randao = B256.zero,
        .block_number = 1,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = timestamp,
        .extra_data = &.{},
        .base_fee_per_gas = 7,
        .block_hash = B256.zero,
        .transactions = &.{},
    };
}

test "engine types: version selection by fork" {
    const mainnet = &chainspec.ChainSpec.presets.base_mainnet;
    try testing.expectEqual(Version.v2, new_payload_version(mainnet, 1_704_992_401));
    try testing.expectEqual(Version.v3, new_payload_version(mainnet, 1_710_374_401));
    try testing.expectEqual(Version.v4, new_payload_version(mainnet, 1_746_806_401));
    try testing.expectEqual(Version.v4, get_payload_version(mainnet, 1_764_691_201));
    try testing.expectEqual(Version.v5, get_payload_version(mainnet, 1_779_991_200));
    try testing.expectEqual(Version.v4, new_payload_version(mainnet, 1_779_991_200));
    try testing.expectEqual(Version.v3, forkchoice_version(mainnet, 1_779_991_200));
    try testing.expectEqual(Version.v2, forkchoice_version(mainnet, 0));
}

test "engine types: newPayload shape checks (L2 Isthmus+)" {
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    var p = empty_payload(10);
    p.withdrawals = &.{};
    p.blob_gas_used = 0;
    p.excess_blob_gas = 0;
    p.withdrawals_root = B256.zero;
    var params: NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = B256.zero,
        .execution_requests = &.{},
    };
    try validate_new_payload(spec, .v4, &p, &params);
    try testing.expectError(error.UnsupportedFork, validate_new_payload(spec, .v3, &p, &params));
    p.withdrawals_root = null;
    try testing.expectError(error.InvalidParams, validate_new_payload(spec, .v4, &p, &params));
    p.withdrawals_root = B256.zero;
    params.execution_requests = &.{"x"};
    try testing.expectError(error.InvalidParams, validate_new_payload(spec, .v4, &p, &params));
}

test "engine types: newPayload shape checks (L1 Prague)" {
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    var p = empty_payload(12);
    p.withdrawals = &.{};
    p.blob_gas_used = 0;
    p.excess_blob_gas = 0;
    const params: NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = B256.zero,
        .execution_requests = &.{},
    };
    try validate_new_payload(spec, .v4, &p, &params);
    try testing.expectError(error.UnsupportedFork, validate_new_payload(spec, .v2, &p, &params));
    try validate_get_payload(spec, .v4, 12);
    try testing.expectError(error.UnsupportedFork, validate_get_payload(spec, .v3, 12));
}

test "engine types: pre-shanghai accepts v1 and v2" {
    var spec = chainspec.ChainSpec.presets.base_devnet;
    spec.upgrades = @splat(null);
    const p = empty_payload(10);
    try validate_new_payload(&spec, .v1, &p, &.{});
    try validate_new_payload(&spec, .v2, &p, &.{});
    try validate_get_payload(&spec, .v1, 10);
    try testing.expectEqual(ErrorCode.unsupported_fork, error_code(error.UnsupportedFork));
}

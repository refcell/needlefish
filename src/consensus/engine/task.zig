//! Shared definitions of the engine tasks: error severities, the task error set, the
//! polling engine client contract, Engine API version selection, and helpers to build
//! `L2BlockInfo`s from payloads and engine payload attributes from derived attributes.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/task.rs` and
//! `versions.rs`.
//!
//! The client is any pointer type with these non-blocking methods. Each returns
//! `error.NotAvailable` while its request is in flight; the task calls again with the same
//! arguments until the result arrives. Results borrow client memory until the next call.
//!   fn forkchoice_updated(self, Version, *const ForkchoiceState, ?*const EngineAttributes)
//!       ClientError!ForkchoiceUpdated
//!   fn new_payload(self, Version, *const ExecutionPayload, *const NewPayloadParams)
//!       ClientError!PayloadStatus
//!   fn get_payload(self, Version, PayloadId) ClientError!PayloadEnvelope
//!   fn l2_block_by_number(self, u64) ClientError!?L2Block
//!   fn l2_block_info_by_number(self, u64) ClientError!?L2BlockInfo

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const tx = @import("../../common/consensus/tx.zig");
const protocol = @import("../protocol/root.zig");
const engine_json = @import("../sources/engine_json.zig");
const state_module = @import("state.zig");
const attributes_match = @import("attributes_match.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;

pub const Version = engine_json.Version;
pub const ExecutionPayload = engine_json.ExecutionPayload;
pub const NewPayloadParams = engine_json.NewPayloadParams;
pub const PayloadStatus = engine_json.PayloadStatus;
pub const Status = @import("../../execution/engine/types.zig").Status;
pub const ForkchoiceUpdated = engine_json.ForkchoiceUpdated;
pub const EngineForkchoiceState = engine_json.ForkchoiceState;
pub const EngineAttributes = engine_json.PayloadAttributes;
pub const PayloadEnvelope = engine_json.PayloadEnvelope;
pub const PayloadId = engine_json.PayloadId;
pub const L2Block = attributes_match.L2Block;
pub const FeeParams = attributes_match.FeeParams;
pub const EngineState = state_module.EngineState;
pub const SyncState = state_module.SyncState;
pub const SyncStateUpdate = state_module.SyncStateUpdate;

/// How the queue handles a failed task (`EngineTaskErrorSeverity`).
pub const Severity = enum {
    /// Retry the task from its start.
    temporary,
    /// Hand back to the caller and retry on the next drain.
    deferred,
    /// The engine cannot continue.
    critical,
    /// The derivation pipeline and engine must be reset; the queue is cleared.
    reset,
    /// The derivation pipeline must be flushed; the task is dropped.
    flush,
};

/// Errors returned by the polling engine client.
pub const ClientError = error{
    /// The request is in flight. Call again with the same arguments.
    NotAvailable,
    /// Engine API error -38002.
    InvalidForkchoiceState,
    /// Transport failure or any other RPC error.
    RpcFailed,
    /// The block could not be turned into an `L2BlockInfo` (bad L1 info deposit, genesis
    /// hash mismatch).
    InvalidBlock,
};

/// Errors of every task. Zig errors carry no payload, so each base/base error variant
/// becomes a distinct error whose severity is a pure function of the value; nested task
/// errors (a synchronize failure inside an insert) keep their own severity.
pub const Error = error{
    /// The client request is in flight; not a failure.
    NotAvailable,
    // Synchronize (forkchoice update without attributes).
    FinalizedAheadOfUnsafe,
    UnorderedHeads,
    ForkchoiceUpdateFailed,
    InvalidForkchoiceState,
    ForkchoiceInvalidStatus,
    // Build (forkchoice update with attributes).
    AttributesInsertionFailed,
    BuildInvalidPayload,
    BuildUnexpectedStatus,
    MissingPayloadId,
    EngineSyncing,
    // Insert.
    L2BlockInfoConstruction,
    InsertFailed,
    NewPayloadInvalid,
    NewPayloadUnexpectedStatus,
    ForkchoiceUpdateDidNotApply,
    // Seal.
    GetPayloadFailed,
    UnexpectedPayloadVersion,
    DepositOnlyPayloadFailed,
    DepositOnlyPayloadReattemptFailed,
    HoloceneInvalidFlush,
    // Consolidate.
    MissingUnsafeL2Block,
    FailedToFetchUnsafeL2Block,
    FailedToFetchDerivedL2Block,
    ConsolidateDidNotApply,
    // Finalize.
    BlockNotSafe,
    BlockNotFound,
    FinalizeFetchFailed,
};

pub fn severity(err: Error) Severity {
    const result: Severity = switch (err) {
        // Never surfaced as a failure: the queue reports it as pending.
        error.NotAvailable => .temporary,
        error.ForkchoiceUpdateFailed,
        error.AttributesInsertionFailed,
        error.BuildUnexpectedStatus,
        error.MissingPayloadId,
        error.EngineSyncing,
        error.InsertFailed,
        error.NewPayloadInvalid,
        error.NewPayloadUnexpectedStatus,
        error.ForkchoiceUpdateDidNotApply,
        error.GetPayloadFailed,
        error.UnexpectedPayloadVersion,
        error.FailedToFetchUnsafeL2Block,
        error.FailedToFetchDerivedL2Block,
        error.FinalizeFetchFailed,
        => .temporary,
        error.ConsolidateDidNotApply => .deferred,
        error.FinalizedAheadOfUnsafe,
        error.UnorderedHeads,
        error.L2BlockInfoConstruction,
        error.DepositOnlyPayloadFailed,
        error.DepositOnlyPayloadReattemptFailed,
        error.BlockNotSafe,
        error.BlockNotFound,
        => .critical,
        error.InvalidForkchoiceState,
        error.ForkchoiceInvalidStatus,
        error.MissingUnsafeL2Block,
        => .reset,
        error.BuildInvalidPayload, error.HoloceneInvalidFlush => .flush,
    };
    assert(result != .flush or err == error.BuildInvalidPayload or
        err == error.HoloceneInvalidFlush);
    assert(err != error.NotAvailable or result == .temporary);
    return result;
}

/// Read-only configuration shared by every task.
pub const Context = struct {
    rollup: *const RollupConfig,
    /// EIP-1559 parameters substituted for all-zero Holocene `eip1559Params`.
    fee_params_canyon: FeeParams = attributes_match.fee_params_canyon_default,
};

pub fn forkchoice_version(rollup: *const RollupConfig, timestamp: u64) Version {
    const v3 = rollup.is_feature_active(.engine_api_v3, timestamp);
    const result: Version = if (v3) .v3 else .v2;
    assert(result == .v2 or result == .v3);
    return result;
}

pub fn get_payload_version(rollup: *const RollupConfig, timestamp: u64) Version {
    const result: Version = if (rollup.is_feature_active(.engine_api_v5, timestamp))
        .v5
    else if (rollup.is_feature_active(.engine_api_v4, timestamp))
        .v4
    else if (rollup.is_feature_active(.engine_api_v3, timestamp))
        .v3
    else
        .v2;
    assert(@backingInt(result) >= 2);
    assert(result == .v2 or rollup.is_feature_active(.engine_api_v3, timestamp));
    return result;
}

/// `engine_newPayload` version from the payload's shape, as base/base selects it from the
/// payload variant: V4 payloads carry `withdrawalsRoot`, V3 payloads blob gas fields.
pub fn new_payload_version(payload: *const ExecutionPayload) Version {
    const blob_fields = payload.blob_gas_used != null or payload.excess_blob_gas != null;
    const result: Version = if (payload.withdrawals_root != null)
        .v4
    else if (blob_fields)
        .v3
    else
        .v2;
    assert(@backingInt(result) >= 2 and @backingInt(result) <= 4);
    assert(result != .v2 or !blob_fields);
    return result;
}

pub fn engine_forkchoice(sync_state: SyncState) EngineForkchoiceState {
    const forkchoice = sync_state.forkchoice_state();
    const result: EngineForkchoiceState = .{
        .head_block_hash = forkchoice.head_block_hash,
        .safe_block_hash = forkchoice.safe_block_hash,
        .finalized_block_hash = forkchoice.finalized_block_hash,
    };
    assert(result.head_block_hash.eql(sync_state.unsafe_head.block_info.hash));
    assert(result.finalized_block_hash.eql(sync_state.finalized_head.block_info.hash));
    return result;
}

/// Engine API view of derived attributes with only the first `transactions_count`
/// transactions (all of them, or the deposits-only prefix). Borrows `attributes`.
pub fn engine_attributes(
    attributes: *const AttributesWithParent,
    transactions_count: u32,
) EngineAttributes {
    const payload = &attributes.attributes;
    assert(transactions_count <= payload.transactions.len);
    const transactions: []const []const u8 = payload.transactions[0..transactions_count];
    const result: EngineAttributes = .{
        .timestamp = payload.timestamp,
        .prev_randao = payload.prev_randao,
        .suggested_fee_recipient = payload.suggested_fee_recipient,
        .withdrawals = payload.withdrawals,
        .parent_beacon_block_root = payload.parent_beacon_block_root,
        .transactions = transactions,
        .no_tx_pool = payload.no_tx_pool,
        .gas_limit = payload.gas_limit,
        .eip1559_params = payload.eip1559_params,
        .min_base_fee = payload.min_base_fee,
    };
    assert(result.transactions.?.len == transactions_count);
    return result;
}

/// `L2BlockInfo::from_payload_and_genesis`: the genesis block takes its origin from the
/// rollup genesis; any other block decodes it from the L1 info deposit, which must be the
/// first transaction.
pub fn block_info_from_payload(
    payload: *const ExecutionPayload,
    genesis: *const ChainGenesis,
) Error!L2BlockInfo {
    const block_info: protocol.block.BlockInfo = .{
        .hash = payload.block_hash,
        .number = payload.block_number,
        .parent_hash = payload.parent_hash,
        .timestamp = payload.timestamp,
    };
    if (block_info.number == genesis.l2.number) {
        if (!block_info.hash.eql(genesis.l2.hash)) return error.L2BlockInfoConstruction;
        return .{ .block_info = block_info, .l1_origin = genesis.l1, .sequence_number = 0 };
    }
    if (payload.transactions.len == 0) return error.L2BlockInfoConstruction;
    const envelope = tx.Envelope.decode(payload.transactions[0]) catch
        return error.L2BlockInfoConstruction;
    if (envelope != .deposit) return error.L2BlockInfoConstruction;
    const info = L1BlockInfo.decode_calldata(envelope.deposit.input) catch
        return error.L2BlockInfoConstruction;
    const result: L2BlockInfo = .{
        .block_info = block_info,
        .l1_origin = info.id(),
        .sequence_number = info.sequence_number,
    };
    assert(result.block_info.number != genesis.l2.number);
    return result;
}

pub fn sync_state_eql(a: SyncState, b: SyncState) bool {
    const result = a.unsafe_head.eql(b.unsafe_head) and
        a.local_safe_head.eql(b.local_safe_head) and
        a.safe_head.eql(b.safe_head) and a.finalized_head.eql(b.finalized_head);
    assert(!result or a.safe_head.eql(b.safe_head));
    assert(!result or a.unsafe_head.eql(b.unsafe_head));
    return result;
}

/// Applies `update` unless it would break the head ordering invariant
/// (finalized <= safe <= local safe <= unsafe), which is reported as `UnorderedHeads`.
pub fn apply_update(engine_state: *EngineState, update: SyncStateUpdate) Error!void {
    assert(engine_state.sync_state.is_ordered());
    const next = engine_state.sync_state.updated(update);
    if (!next.is_ordered()) return error.UnorderedHeads;
    engine_state.sync_state = next;
    assert(engine_state.sync_state.is_ordered());
}

const testing = std.testing;

test "task: severity of nested errors follows base/base" {
    try testing.expectEqual(Severity.reset, severity(error.ForkchoiceInvalidStatus));
    try testing.expectEqual(Severity.temporary, severity(error.ForkchoiceUpdateFailed));
    try testing.expectEqual(Severity.critical, severity(error.FinalizedAheadOfUnsafe));
    try testing.expectEqual(Severity.flush, severity(error.BuildInvalidPayload));
    try testing.expectEqual(Severity.reset, severity(error.InvalidForkchoiceState));
    try testing.expectEqual(Severity.temporary, severity(error.NewPayloadInvalid));
    try testing.expectEqual(Severity.flush, severity(error.HoloceneInvalidFlush));
    try testing.expectEqual(Severity.deferred, severity(error.ConsolidateDidNotApply));
    try testing.expectEqual(Severity.reset, severity(error.MissingUnsafeL2Block));
    try testing.expectEqual(Severity.critical, severity(error.DepositOnlyPayloadFailed));
}

test "task: engine api versions" {
    var rollup: RollupConfig = .{};
    try testing.expectEqual(Version.v2, forkchoice_version(&rollup, 10));
    try testing.expectEqual(Version.v2, get_payload_version(&rollup, 10));
    rollup.upgrades.set(.ecotone, 5);
    try testing.expectEqual(Version.v3, forkchoice_version(&rollup, 10));
    try testing.expectEqual(Version.v3, get_payload_version(&rollup, 10));
    rollup.upgrades.set(.isthmus, 8);
    try testing.expectEqual(Version.v4, get_payload_version(&rollup, 10));
    try testing.expectEqual(Version.v3, get_payload_version(&rollup, 7));
}

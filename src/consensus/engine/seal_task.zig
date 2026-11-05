//! Seal task: fetches a built payload with `engine_getPayload` and imports it with an
//! insert task (newPayload + forkchoice update), for the sequencer (unsafe) and for derived
//! blocks that replace a mismatching unsafe block (safe). When the engine rejects the
//! payload after Holocene, a deposits-only payload is built and sealed instead and the
//! pipeline is asked to flush; a rejected deposits-only payload is critical.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/tasks/seal/task.rs` and
//! `Engine::fetch_payload`.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const attributes_match = @import("attributes_match.zig");
const insert_module = @import("insert_task.zig");
const BuildTask = @import("build_task.zig").BuildTask;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const L2BlockInfo = protocol.block.L2BlockInfo;
const EngineState = task.EngineState;
const PayloadId = task.PayloadId;
const Error = task.Error;
const InsertTask = insert_module.InsertTask;
const Safety = insert_module.Safety;

pub const SealTask = struct {
    /// The payload being sealed (the deposits-only replacement during the fallback).
    payload_id: PayloadId,
    payload_id_initial: PayloadId,
    /// Borrowed from the owner (queue slot or consolidate task).
    attributes: *const AttributesWithParent,
    safety: Safety,
    phase: enum { get_payload, commit, insert, fallback_build } = .get_payload,
    /// Building the Holocene deposits-only replacement.
    fallback: bool = false,
    /// The fetched payload; its slices borrow the client until the owner copies them
    /// (`envelope_owned`), which the task queue does right after the insert is issued.
    envelope: insert_module.Envelope = undefined,
    envelope_owned: bool = false,
    insert: InsertTask = undefined,
    build: BuildTask = undefined,

    pub fn init(
        payload_id: PayloadId,
        attributes: *const AttributesWithParent,
        safety: Safety,
    ) SealTask {
        return .{
            .payload_id = payload_id,
            .payload_id_initial = payload_id,
            .attributes = attributes,
            .safety = safety,
        };
    }

    pub fn restart(seal: *SealTask) void {
        const payload_id = seal.payload_id_initial;
        const attributes = seal.attributes;
        const safety = seal.safety;
        seal.* = init(payload_id, attributes, safety);
        assert(seal.phase == .get_payload);
        assert(!seal.fallback);
    }

    /// Returns the sealed block. Inside the deposits-only fallback every failure becomes
    /// `DepositOnlyPayloadReattemptFailed` and success `HoloceneInvalidFlush`.
    pub fn step(
        seal: *SealTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!L2BlockInfo {
        const block = seal.step_phases(context, engine_state, client) catch |err| {
            if (err == error.NotAvailable) return error.NotAvailable;
            if (seal.fallback) return error.DepositOnlyPayloadReattemptFailed;
            return err;
        };
        if (seal.fallback) return error.HoloceneInvalidFlush;
        // An insert that skips a stale payload returns the current unsafe head instead.
        assert(seal.phase == .insert);
        return block;
    }

    fn step_phases(
        seal: *SealTask,
        context: *const task.Context,
        engine_state: *EngineState,
        client: anytype,
    ) Error!L2BlockInfo {
        for (0..7) |_| {
            switch (seal.phase) {
                .get_payload => {
                    try seal.get_payload(context, client);
                    seal.envelope_owned = false;
                    seal.insert = .{ .envelope = &seal.envelope, .safety = seal.safety };
                    const commit = context.committer != null and seal.safety == .unsafe_payload;
                    seal.phase = if (commit) .commit else .insert;
                },
                .commit => {
                    // base/base `SealState::Sealed`: the conductor must accept the payload
                    // before it is inserted (and gossiped).
                    const committer = context.committer.?;
                    const payload = &seal.envelope.payload;
                    const root = seal.envelope.parent_beacon_block_root;
                    try committer.commit(committer.context, payload, root);
                    seal.phase = .insert;
                },
                .insert => {
                    return seal.insert.step(context, engine_state, client) catch |err| {
                        if (err == error.NewPayloadInvalid or
                            err == error.NewPayloadUnexpectedStatus)
                        {
                            try seal.start_fallback(context, err);
                            continue;
                        }
                        return err;
                    };
                },
                .fallback_build => {
                    seal.payload_id = try seal.build.step(context, engine_state, client);
                    seal.phase = .get_payload;
                },
            }
        }
        // Proof: get_payload -> commit -> insert -> fallback_build -> get_payload -> commit ->
        // insert is the longest path; a second fallback is `DepositOnlyPayloadFailed`.
        unreachable;
    }

    fn start_fallback(seal: *SealTask, context: *const task.Context, cause: Error) Error!void {
        assert(seal.phase == .insert);
        const transactions = seal.attributes.attributes.transactions;
        if (seal.fallback or attributes_match.is_deposits_only(transactions)) {
            return error.DepositOnlyPayloadFailed;
        }
        const timestamp = seal.attributes.attributes.timestamp;
        if (!context.rollup.is_feature_active(.deposits_only_on_invalid_payload, timestamp)) {
            return cause;
        }
        seal.fallback = true;
        seal.build = BuildTask.init(seal.attributes);
        seal.build.transactions_count = attributes_match.deposits_prefix_len(transactions);
        seal.phase = .fallback_build;
        assert(seal.build.transactions_count < transactions.len);
    }

    fn get_payload(seal: *SealTask, context: *const task.Context, client: anytype) Error!void {
        assert(seal.phase == .get_payload);
        const attributes = &seal.attributes.attributes;
        const version = task.get_payload_version(context.rollup, attributes.timestamp);
        const envelope = client.get_payload(version, seal.payload_id) catch |err|
            return switch (err) {
                error.NotAvailable => error.NotAvailable,
                error.InvalidForkchoiceState, error.RpcFailed, error.InvalidBlock => {
                    return error.GetPayloadFailed;
                },
            };
        const payload = envelope.payload;
        const blob_fields = payload.blob_gas_used != null or payload.excess_blob_gas != null;
        if (version == .v2 and blob_fields) return error.UnexpectedPayloadVersion;
        if (version != .v2 and !blob_fields) return error.UnexpectedPayloadVersion;
        seal.envelope = .{
            .payload = payload,
            .parent_beacon_block_root = switch (version) {
                .v5 => attributes.parent_beacon_block_root,
                .v3, .v4 => envelope.parent_beacon_block_root,
                .v1, .v2 => null,
            },
        };
        assert(seal.envelope.payload.block_hash.eql(payload.block_hash));
    }
};

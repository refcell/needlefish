//! Deterministic in-memory engine client for task tests and simulation. Responses are
//! configured per method (status, error, payload, blocks); scripts queue one-off statuses;
//! every request can be made to return `NotAvailable` for a number of polls (latency) or at
//! random from a seeded PRNG. Calls are recorded for assertions.
//! Mirrors base/base `crates/consensus/engine/src/test_utils/engine_client.rs`.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const L2BlockInfo = protocol.block.L2BlockInfo;
const ClientError = task.ClientError;
const PayloadStatus = task.PayloadStatus;
const L2Block = task.L2Block;

pub const blocks_max = 64;
pub const script_max = 8;

/// One-off results consumed in order before the default applies.
pub const Script = struct {
    items: [script_max]task.Status = undefined,
    count: u32 = 0,
    next: u32 = 0,

    pub fn push(script: *Script, status: task.Status) void {
        assert(script.count < script_max);
        script.items[script.count] = status;
        script.count += 1;
    }

    fn take(script: *Script) ?task.Status {
        if (script.next == script.count) return null;
        assert(script.next < script.count);
        const status = script.items[script.next];
        script.next += 1;
        return status;
    }
};

pub const MockEngine = struct {
    /// Polls each request returns `NotAvailable` before its result.
    latency: u32 = 0,
    /// Random extra `NotAvailable`s: `not_available_percent` of polls when `prng` is set.
    prng: ?*Prng = null,
    not_available_percent: u8 = 0,

    forkchoice_status: task.Status = .valid,
    /// Status for forkchoice updates with attributes (defaults to `forkchoice_status`).
    build_status: ?task.Status = null,
    forkchoice_script: Script = .{},
    forkchoice_error: ?ClientError = null,
    payload_id: ?task.PayloadId = .{ 1, 2, 3, 4, 5, 6, 7, 8 },

    new_payload_status: task.Status = .valid,
    new_payload_script: Script = .{},
    new_payload_error: ?ClientError = null,

    payload: ?task.PayloadEnvelope = null,
    get_payload_error: ?ClientError = null,

    blocks: [blocks_max]?L2Block = @splat(null),
    block_error: ?ClientError = null,

    waiting: u32 = 0,
    forkchoice_calls: u32 = 0,
    build_calls: u32 = 0,
    new_payload_calls: u32 = 0,
    get_payload_calls: u32 = 0,
    block_calls: u32 = 0,
    last_forkchoice: ?task.EngineForkchoiceState = null,
    last_forkchoice_version: ?task.Version = null,
    last_new_payload_version: ?task.Version = null,
    last_get_payload_version: ?task.Version = null,
    last_build_transactions: u32 = 0,

    pub fn set_block(mock: *MockEngine, block: L2Block) void {
        const number = block.info.block_info.number;
        assert(number < blocks_max);
        mock.blocks[number] = block;
        assert(mock.blocks[number] != null);
    }

    /// Returns `NotAvailable` while the current request is "in flight".
    fn poll(mock: *MockEngine) ClientError!void {
        if (mock.prng) |prng| {
            if (prng.below(100) < mock.not_available_percent) return error.NotAvailable;
        }
        if (mock.waiting > 0) {
            mock.waiting -= 1;
            return error.NotAvailable;
        }
        mock.waiting = mock.latency; // The next request starts with the full latency.
        assert(mock.waiting == mock.latency);
    }

    pub fn forkchoice_updated(
        mock: *MockEngine,
        version: task.Version,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) ClientError!task.ForkchoiceUpdated {
        assert(version == .v2 or version == .v3);
        try mock.poll();
        mock.forkchoice_calls += 1;
        mock.last_forkchoice = state.*;
        mock.last_forkchoice_version = version;
        if (mock.forkchoice_error) |err| return err;
        const scripted = mock.forkchoice_script.take();
        if (attributes) |attrs| {
            mock.build_calls += 1;
            mock.last_build_transactions = @intCast(attrs.transactions.?.len);
            const status = scripted orelse mock.build_status orelse mock.forkchoice_status;
            const id = if (status == .valid) mock.payload_id else null;
            return .{ .payload_status = .{ .status = status }, .payload_id = id };
        }
        const status = scripted orelse mock.forkchoice_status;
        return .{ .payload_status = .{ .status = status } };
    }

    pub fn new_payload(
        mock: *MockEngine,
        version: task.Version,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) ClientError!PayloadStatus {
        assert(@backingInt(version) >= 2 and @backingInt(version) <= 4);
        assert(params.parent_beacon_block_root != null);
        try mock.poll();
        mock.new_payload_calls += 1;
        mock.last_new_payload_version = version;
        if (mock.new_payload_error) |err| return err;
        const status = mock.new_payload_script.take() orelse mock.new_payload_status;
        return .{ .status = status, .latest_valid_hash = payload.block_hash };
    }

    pub fn get_payload(
        mock: *MockEngine,
        version: task.Version,
        payload_id: task.PayloadId,
    ) ClientError!task.PayloadEnvelope {
        assert(@backingInt(version) >= 2);
        try mock.poll();
        mock.get_payload_calls += 1;
        mock.last_get_payload_version = version;
        if (mock.get_payload_error) |err| return err;
        const envelope = mock.payload orelse return error.RpcFailed;
        assert(payload_id.len == 8);
        return envelope;
    }

    pub fn l2_block_by_number(mock: *MockEngine, number: u64) ClientError!?L2Block {
        try mock.poll();
        mock.block_calls += 1;
        if (mock.block_error) |err| return err;
        if (number >= blocks_max) return null;
        const block = mock.blocks[number] orelse return null;
        assert(block.info.block_info.number == number);
        return block;
    }

    pub fn l2_block_info_by_number(mock: *MockEngine, number: u64) ClientError!?L2BlockInfo {
        const block = try mock.l2_block_by_number(number) orelse return null;
        assert(block.info.block_info.number == number);
        return block.info;
    }
};

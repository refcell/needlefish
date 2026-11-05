//! Engine task queue tests ported from base/base `task_queue/core.rs` and the insert,
//! consolidate, seal, finalize, and synchronize task tests, over the deterministic mock
//! engine. Ends with a seeded fuzz over random task sequences with random `NotAvailable`
//! and SYNCING injection: the heads stay ordered and every seed replays identically.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const primitives = @import("../../common/primitives/root.zig");
const tx = @import("../../common/consensus/tx.zig");
const protocol = @import("../protocol/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;
const task = @import("task.zig");
const queue_module = @import("task_queue.zig");
const insert_module = @import("insert_task.zig");
const SynchronizeTask = @import("synchronize_task.zig").SynchronizeTask;
const MockEngine = @import("mock_engine.zig").MockEngine;

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const EngineState = task.EngineState;
const EngineTaskQueue = queue_module.EngineTaskQueue;
const StepResult = queue_module.StepResult;

pub const chain_length = 40;

fn hash(number: u64) B256 {
    return .init(@splat(@intCast(number)));
}

/// The canonical test chain: block `number` has hash `[number; 32]` and L1 origin
/// `number` (genesis: the rollup genesis, all zero).
fn info(number: u64) L2BlockInfo {
    assert(number < 256);
    return .{
        .block_info = .{
            .hash = hash(number),
            .number = number,
            .parent_hash = hash(number -| 1),
            .timestamp = number * 2,
        },
        .l1_origin = if (number == 0) .{} else .{ .number = number, .hash = .init(@splat(0xa0)) },
        .sequence_number = 0,
    };
}

/// Payload, block, and attributes of one block of a chain, with their backing memory.
const BlockFixture = struct {
    calldata: [protocol.l1_info.calldata_length_max]u8,
    tx_buffer: [512]u8,
    transactions: [1][]u8,
    info: L2BlockInfo,

    fn init(fixture: *BlockFixture, block_info: L2BlockInfo) void {
        fixture.info = block_info;
        const l1_info: L1BlockInfo = .{
            .format = .bedrock,
            .number = block_info.l1_origin.number,
            .block_hash = block_info.l1_origin.hash,
            .sequence_number = block_info.sequence_number,
        };
        const input = l1_info.encode_calldata(&fixture.calldata);
        const envelope: tx.Envelope = .{ .deposit = .{
            .source_hash = block_info.block_info.hash,
            .from = .zero,
            .to = .{ .call = .zero },
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = input,
        } };
        fixture.transactions[0] = envelope.encode_to(&fixture.tx_buffer);
    }

    fn payload(fixture: *const BlockFixture) task.ExecutionPayload {
        const block_info = fixture.info.block_info;
        return .{
            .parent_hash = block_info.parent_hash,
            .fee_recipient = .zero,
            .state_root = .zero,
            .receipts_root = .zero,
            .logs_bloom = .zero,
            .prev_randao = .zero,
            .block_number = block_info.number,
            .gas_limit = 30_000_000,
            .gas_used = 0,
            .timestamp = block_info.timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = 1,
            .block_hash = block_info.hash,
            .transactions = &fixture.transactions,
        };
    }

    fn block(fixture: *const BlockFixture) task.L2Block {
        return .{
            .info = fixture.info,
            .gas_limit = 30_000_000,
            .transactions = &fixture.transactions,
        };
    }

    /// Derived attributes that match `block()` and build on `parent`.
    fn attributes(fixture: *BlockFixture, parent: L2BlockInfo) AttributesWithParent {
        return .{
            .attributes = .{
                .timestamp = fixture.info.block_info.timestamp,
                .prev_randao = .zero,
                .suggested_fee_recipient = .zero,
                .withdrawals = null,
                .parent_beacon_block_root = null,
                .transactions = &fixture.transactions,
                .no_tx_pool = true,
                .gas_limit = 30_000_000,
                .eip1559_params = null,
                .min_base_fee = null,
            },
            .parent = parent,
            .derived_from = null,
            .is_last_in_span = true,
        };
    }
};

const Chain = struct {
    fixtures: [chain_length]BlockFixture,

    fn init(chain: *Chain) void {
        for (&chain.fixtures, 0..) |*fixture, number| fixture.init(info(number));
    }

    fn load(chain: *const Chain, mock: *MockEngine) void {
        for (&chain.fixtures) |*fixture| mock.set_block(fixture.block());
    }
};

fn state_at(unsafe_number: u64, safe_number: u64, finalized_number: u64) EngineState {
    return .{
        .sync_state = .{
            .unsafe_head = info(unsafe_number),
            .local_safe_head = info(safe_number),
            .safe_head = info(safe_number),
            .finalized_head = info(finalized_number),
        },
        .el_sync_finished = true,
    };
}

const rollup_default: RollupConfig = .{};

fn new_queue(initial: EngineState) !EngineTaskQueue {
    return EngineTaskQueue.init(testing.allocator, .{ .rollup = &rollup_default }, initial, .{
        .capacity = 8,
    });
}

fn expect_failure(result: StepResult, err: task.Error, severity: task.Severity) !void {
    try testing.expect(result == .failed);
    try testing.expectEqual(err, result.failed.err);
    try testing.expectEqual(severity, result.failed.severity);
}

fn step_until_done(queue: *EngineTaskQueue, mock: *MockEngine) StepResult {
    for (0..64) |_| {
        const result = queue.step(mock);
        if (result != .pending) return result;
    }
    return .pending;
}

// Synchronize (base/base synchronize/task_test.rs).

const context_default: task.Context = .{ .rollup = &rollup_default };

fn synchronize(update: task.SyncStateUpdate, state: *EngineState, mock: *MockEngine) !void {
    const synchronize_task: SynchronizeTask = .{ .update = update };
    for (0..16) |_| {
        synchronize_task.step(&context_default, state, mock) catch |err| {
            if (err == error.NotAvailable) continue;
            return err;
        };
        return;
    }
    return error.TestTimeout;
}

test "synchronize: valid response advances sync state" {
    var mock: MockEngine = .{ .latency = 2 };
    var state: EngineState = .{};
    try synchronize(.{ .unsafe_head = info(10) }, &state, &mock);
    try testing.expectEqual(@as(u64, 10), state.sync_state.unsafe_head.block_info.number);
    try testing.expect(state.el_sync_finished);
    try testing.expectEqual(@as(u32, 1), mock.forkchoice_calls);
    try testing.expect(mock.last_forkchoice.?.head_block_hash.eql(hash(10)));
}

test "synchronize: syncing does not advance before el sync finishes" {
    var mock: MockEngine = .{ .forkchoice_status = .syncing };
    var state = state_at(10, 5, 0);
    state.el_sync_finished = false;
    try synchronize(.{
        .unsafe_head = info(12),
        .local_safe_head = info(8),
        .safe_head = info(8),
    }, &state, &mock);
    try testing.expect(state.sync_state.unsafe_head.eql(info(10)));
    try testing.expect(state.sync_state.safe_head.eql(info(5)));
    try testing.expect(!state.el_sync_finished);
}

test "synchronize: syncing keeps safe heads behind the unsafe head" {
    var mock: MockEngine = .{ .forkchoice_status = .syncing };
    var state = state_at(20, 9, 0);
    try synchronize(.{ .local_safe_head = info(15), .safe_head = info(15) }, &state, &mock);
    try testing.expect(state.sync_state.safe_head.eql(info(15)));
    try testing.expect(state.sync_state.local_safe_head.eql(info(15)));
    try testing.expect(state.sync_state.unsafe_head.eql(info(20)));
    try testing.expect(state.el_sync_finished);

    // Never past the unsafe head, and at equal height only with the same hash.
    try synchronize(.{ .safe_head = info(21), .local_safe_head = info(21) }, &state, &mock);
    try testing.expect(state.sync_state.safe_head.eql(info(15)));
    var other = info(20);
    other.block_info.hash = hash(99);
    try synchronize(.{ .safe_head = other, .local_safe_head = other }, &state, &mock);
    try testing.expect(state.sync_state.safe_head.eql(info(15)));
    try synchronize(.{ .safe_head = info(20), .local_safe_head = info(20) }, &state, &mock);
    try testing.expect(state.sync_state.safe_head.eql(info(20)));
}

test "synchronize: syncing then valid advances on the second call" {
    var mock: MockEngine = .{};
    mock.forkchoice_script.push(.syncing);
    var state = state_at(10, 5, 0);
    try synchronize(.{ .unsafe_head = info(11) }, &state, &mock);
    try testing.expect(state.sync_state.unsafe_head.eql(info(10)));
    try synchronize(.{ .unsafe_head = info(11) }, &state, &mock);
    try testing.expect(state.sync_state.unsafe_head.eql(info(11)));
    try testing.expectEqual(@as(u32, 2), mock.forkchoice_calls);
}

test "synchronize: unchanged state skips the forkchoice update" {
    var mock: MockEngine = .{};
    var state = state_at(10, 5, 0);
    try synchronize(.{ .unsafe_head = info(10) }, &state, &mock);
    try testing.expectEqual(@as(u32, 0), mock.forkchoice_calls);
    const forced: SynchronizeTask = .{ .update = .{}, .force = true };
    try forced.step(&context_default, &state, &mock);
    try testing.expectEqual(@as(u32, 1), mock.forkchoice_calls);
}

test "synchronize: errors and their severities" {
    var mock: MockEngine = .{ .forkchoice_status = .invalid };
    var state = state_at(10, 5, 0);
    const update: task.SyncStateUpdate = .{ .unsafe_head = info(11) };
    try testing.expectError(error.ForkchoiceInvalidStatus, synchronize(update, &state, &mock));
    mock.forkchoice_error = error.InvalidForkchoiceState;
    try testing.expectError(error.InvalidForkchoiceState, synchronize(update, &state, &mock));
    mock.forkchoice_error = error.RpcFailed;
    try testing.expectError(error.ForkchoiceUpdateFailed, synchronize(update, &state, &mock));
    try testing.expectEqual(task.Severity.temporary, task.severity(error.ForkchoiceUpdateFailed));
    const behind: task.SyncStateUpdate = .{ .unsafe_head = info(3) };
    try testing.expectError(error.FinalizedAheadOfUnsafe, synchronize(.{
        .unsafe_head = info(3),
        .finalized_head = info(4),
    }, &state, &mock));
    // The engine would reject this forkchoice state; a VALID answer must not unorder heads.
    mock.forkchoice_error = null;
    mock.forkchoice_status = .valid;
    try testing.expectError(error.UnorderedHeads, synchronize(behind, &state, &mock));
    try testing.expect(state.sync_state.unsafe_head.eql(info(10)));
}

// Finalize (base/base finalize/task_test.rs).

test "finalize: not safe, not found, stale, and success" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 1 };
    var queue = try new_queue(state_at(20, 10, 2));
    defer queue.deinit(testing.allocator);

    try queue.enqueue(.{ .finalize = 11 });
    try expect_failure(step_until_done(&queue, &mock), error.BlockNotSafe, .critical);
    queue.clear();

    try queue.enqueue(.{ .finalize = 8 });
    try expect_failure(step_until_done(&queue, &mock), error.BlockNotFound, .critical);
    queue.clear();

    chain.load(&mock);
    try queue.enqueue(.{ .finalize = 8 });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.finalized_head.eql(info(8)));

    const calls = mock.forkchoice_calls;
    try queue.enqueue(.{ .finalize = 4 });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.finalized_head.eql(info(8)));
    try testing.expectEqual(calls, mock.forkchoice_calls);

    mock.forkchoice_status = .invalid;
    try queue.enqueue(.{ .finalize = 9 });
    try expect_failure(step_until_done(&queue, &mock), error.ForkchoiceInvalidStatus, .reset);
    try testing.expectEqual(@as(u32, 0), queue.len());
}

// Insert (base/base insert/task.rs tests).

test "insert: unsafe payload advances only the unsafe head" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 1 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const envelope: insert_module.Envelope = .{ .payload = chain.fixtures[11].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &envelope } });
    const result = step_until_done(&queue, &mock);
    try testing.expect(result.completed.insert.eql(info(11)));
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(11)));
    try testing.expect(queue.state.sync_state.safe_head.eql(info(5)));
    try testing.expectEqual(task.Version.v2, mock.last_new_payload_version.?);
}

test "insert: safe payload advances the safe heads" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const envelope: insert_module.Envelope = .{ .payload = chain.fixtures[6].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &envelope, .safety = .safe_payload } });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(6)));
    try testing.expect(queue.state.sync_state.local_safe_head.eql(info(6)));
    try testing.expect(queue.state.sync_state.safe_head.eql(info(6)));
}

test "insert: stale, duplicate, and non-extending payloads are skipped before import" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const stale: insert_module.Envelope = .{ .payload = chain.fixtures[9].payload() };
    const duplicate: insert_module.Envelope = .{ .payload = chain.fixtures[10].payload() };
    var orphan: insert_module.Envelope = .{ .payload = chain.fixtures[11].payload() };
    orphan.payload.parent_hash = hash(77);
    try queue.enqueue(.{ .insert = .{ .envelope = &stale } });
    try queue.enqueue(.{ .insert = .{ .envelope = &duplicate } });
    try queue.enqueue(.{ .insert = .{ .envelope = &orphan } });
    const drained = queue.drain(&mock, 8);
    try testing.expectEqual(@as(u32, 3), drained.completed);
    try testing.expectEqual(@as(u32, 0), mock.new_payload_calls);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(10)));
}

test "insert: invalid gossiped payload is dropped and the queue continues" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    mock.new_payload_script.push(.invalid);
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const bad: insert_module.Envelope = .{ .payload = chain.fixtures[11].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &bad, .drop_invalid = true } });
    try queue.enqueue(.{ .insert = .{ .envelope = &bad, .drop_invalid = true } });
    const drained = queue.drain(&mock, 8);
    try testing.expectEqual(@as(u32, 2), drained.completed);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(11)));

    // Without dropping, an invalid payload is a temporary failure kept for a retry.
    mock.new_payload_script.push(.invalid);
    const next: insert_module.Envelope = .{ .payload = chain.fixtures[12].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &next } });
    try expect_failure(queue.step(&mock), error.NewPayloadInvalid, .temporary);
    try testing.expectEqual(@as(u32, 1), queue.len());
    try testing.expect(queue.step(&mock) == .completed);
}

test "insert: authoritative payload replaces a newer unsafe head" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    var initial = state_at(15, 6, 0);
    initial.sync_state.local_safe_head = info(9);
    var queue = try new_queue(initial);
    defer queue.deinit(testing.allocator);
    const envelope: insert_module.Envelope = .{ .payload = chain.fixtures[12].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &envelope, .policy = .authoritative } });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(12)));
    try testing.expect(queue.state.sync_state.local_safe_head.eql(info(6)));

    // An authoritative insert whose forkchoice update returns SYNCING did not apply.
    mock.forkchoice_status = .syncing;
    const again: insert_module.Envelope = .{ .payload = chain.fixtures[13].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &again, .policy = .authoritative } });
    try expect_failure(queue.step(&mock), error.ForkchoiceUpdateDidNotApply, .temporary);
}

test "insert: payload shape selects the newPayload version" {
    var chain: Chain = undefined;
    chain.init();
    var payload = chain.fixtures[11].payload();
    try testing.expectEqual(task.Version.v2, task.new_payload_version(&payload));
    payload.blob_gas_used = 0;
    payload.excess_blob_gas = 0;
    try testing.expectEqual(task.Version.v3, task.new_payload_version(&payload));
    payload.withdrawals_root = primitives.empty_root_hash;
    try testing.expectEqual(task.Version.v4, task.new_payload_version(&payload));
    var bad = payload;
    bad.transactions = &.{};
    try testing.expectError(
        error.L2BlockInfoConstruction,
        task.block_info_from_payload(&bad, &rollup_default.genesis),
    );
}

// Build and seal (base/base core.rs and seal tests).

test "build: returns the payload id and builds on the attributes parent" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 2 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const attributes = chain.fixtures[11].attributes(info(10));
    try queue.enqueue(.{ .build = &attributes });
    const result = step_until_done(&queue, &mock);
    try testing.expectEqual(mock.payload_id.?, result.completed.build);
    try testing.expect(mock.last_forkchoice.?.head_block_hash.eql(hash(10)));
    try testing.expectEqual(@as(u32, 1), mock.last_build_transactions);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(10)));

    mock.build_status = .syncing;
    try queue.enqueue(.{ .build = &attributes });
    try expect_failure(step_until_done(&queue, &mock), error.EngineSyncing, .temporary);
    mock.build_status = .invalid;
    try expect_failure(step_until_done(&queue, &mock), error.BuildInvalidPayload, .flush);
    try testing.expectEqual(@as(u32, 0), queue.len());
    mock.build_status = .valid;
    mock.payload_id = null;
    try queue.enqueue(.{ .build = &attributes });
    try expect_failure(step_until_done(&queue, &mock), error.MissingPayloadId, .temporary);
}

test "seal: fetches, imports, and canonicalizes the payload" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 1 };
    mock.payload = .{ .payload = chain.fixtures[11].payload(), .block_value = 0 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const attributes = chain.fixtures[11].attributes(info(10));
    try queue.enqueue(.{ .seal = .{ .payload_id = @splat(1), .attributes = &attributes } });
    const result = step_until_done(&queue, &mock);
    try testing.expect(result.completed.seal.eql(info(11)));
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(11)));
    try testing.expectEqual(task.Version.v2, mock.last_get_payload_version.?);
    const sealed = queue.take_sealed().?;
    try testing.expect(sealed.payload.block_hash.eql(info(11).block_info.hash));
    try testing.expectEqual(
        chain.fixtures[11].payload().transactions.len,
        sealed.payload.transactions.len,
    );
    try testing.expect(queue.take_sealed() == null);

    mock.get_payload_error = error.RpcFailed;
    try queue.enqueue(.{ .seal = .{ .payload_id = @splat(1), .attributes = &attributes } });
    try expect_failure(step_until_done(&queue, &mock), error.GetPayloadFailed, .temporary);
    mock.get_payload_error = null;
    var v3 = chain.fixtures[12].payload();
    v3.blob_gas_used = 0;
    mock.payload = .{ .payload = v3, .block_value = 0 };
    try expect_failure(step_until_done(&queue, &mock), error.UnexpectedPayloadVersion, .temporary);
}

test "seal: deposits-only payload rejected by the engine is critical" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .new_payload_status = .invalid };
    mock.payload = .{ .payload = chain.fixtures[11].payload(), .block_value = 0 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const attributes = chain.fixtures[11].attributes(info(10));
    try queue.enqueue(.{ .seal = .{ .payload_id = @splat(1), .attributes = &attributes } });
    try expect_failure(step_until_done(&queue, &mock), error.DepositOnlyPayloadFailed, .critical);
    try testing.expectEqual(@as(u32, 1), queue.len());
}

test "seal: holocene rebuilds a deposits-only payload and asks for a flush" {
    var chain: Chain = undefined;
    chain.init();
    var rollup: RollupConfig = .{};
    rollup.upgrades.set(.holocene, 1000);
    var mock: MockEngine = .{};
    mock.new_payload_script.push(.invalid);
    // Ecotone is active from Holocene on, so the payload is fetched with getPayloadV3.
    var payload = chain.fixtures[11].payload();
    mock.payload = .{ .payload = payload, .block_value = 0 };
    const context: task.Context = .{ .rollup = &rollup };
    var queue = try EngineTaskQueue.init(testing.allocator, context, state_at(10, 5, 0), .{});
    defer queue.deinit(testing.allocator);
    var attributes = chain.fixtures[11].attributes(info(10));
    var user_tx = [_]u8{ 0x02, 0xc0 };
    var transactions = [_][]u8{ chain.fixtures[11].transactions[0], &user_tx };
    attributes.attributes.transactions = &transactions;

    // Before Holocene the rejection is a temporary insert failure.
    try queue.enqueue(.{ .seal = .{ .payload_id = @splat(1), .attributes = &attributes } });
    try expect_failure(step_until_done(&queue, &mock), error.NewPayloadInvalid, .temporary);
    queue.clear();

    attributes.attributes.timestamp = 1000;
    payload.blob_gas_used = 0;
    payload.excess_blob_gas = 0;
    mock.payload = .{ .payload = payload, .block_value = 0 };
    mock.new_payload_script = .{};
    mock.new_payload_script.push(.invalid);
    try queue.enqueue(.{ .seal = .{ .payload_id = @splat(1), .attributes = &attributes } });
    try expect_failure(step_until_done(&queue, &mock), error.HoloceneInvalidFlush, .flush);
    try testing.expectEqual(@as(u32, 1), mock.last_build_transactions);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(11)));
    try testing.expectEqual(@as(u32, 0), queue.len());
}

// Consolidate (base/base consolidate/task_test.rs).

test "consolidate: matching block advances the safe head" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 1 };
    chain.load(&mock);
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    var attributes = chain.fixtures[6].attributes(info(5));
    attributes.is_last_in_span = false;
    try queue.enqueue(.{ .consolidate = &attributes });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.safe_head.eql(info(6)));
    try testing.expectEqual(@as(u32, 0), mock.forkchoice_calls);

    const last = chain.fixtures[7].attributes(info(6));
    try queue.enqueue(.{ .consolidate = &last });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.safe_head.eql(info(7)));
    try testing.expect(queue.state.sync_state.local_safe_head.eql(info(7)));
    try testing.expectEqual(@as(u32, 1), mock.forkchoice_calls);
    try testing.expect(mock.last_forkchoice.?.safe_block_hash.eql(hash(7)));
}

test "consolidate: mismatch builds and seals the derived block as safe" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    chain.load(&mock);
    var replacement = chain.fixtures[6];
    var replaced_info = info(6);
    replaced_info.block_info.hash = hash(66);
    replacement.init(replaced_info);
    mock.payload = .{ .payload = replacement.payload(), .block_value = 0 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    var attributes = replacement.attributes(info(5));
    attributes.attributes.gas_limit = 1; // Differs from the engine's block.
    try queue.enqueue(.{ .consolidate = &attributes });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expectEqual(@as(u32, 1), mock.build_calls);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(replaced_info));
    try testing.expect(queue.state.sync_state.safe_head.eql(replaced_info));
}

test "consolidate: trailing bytes in an attribute transaction force a rebuild" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    chain.load(&mock);
    mock.payload = .{ .payload = chain.fixtures[6].payload(), .block_value = 0 };
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    var attributes = chain.fixtures[6].attributes(info(5));
    var padded: [513]u8 = undefined;
    const original = chain.fixtures[6].transactions[0];
    @memcpy(padded[0..original.len], original);
    padded[original.len] = 0;
    var transactions = [_][]u8{padded[0 .. original.len + 1]};
    attributes.attributes.transactions = &transactions;
    try queue.enqueue(.{ .consolidate = &attributes });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expectEqual(@as(u32, 1), mock.build_calls);
}

test "consolidate: reconciles a block the engine already has" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    chain.load(&mock);
    var queue = try new_queue(state_at(5, 5, 0));
    defer queue.deinit(testing.allocator);
    const attributes = chain.fixtures[6].attributes(info(5));
    try queue.enqueue(.{ .consolidate = &attributes });
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(6)));
    try testing.expect(queue.state.sync_state.safe_head.eql(info(6)));
    try testing.expectEqual(@as(u32, 0), mock.build_calls);

    // SYNCING leaves the heads behind: deferred to a later drain, then applied.
    mock.forkchoice_script.push(.syncing);
    const next = chain.fixtures[7].attributes(info(6));
    try queue.enqueue(.{ .consolidate = &next });
    try expect_failure(step_until_done(&queue, &mock), error.ConsolidateDidNotApply, .deferred);
    try testing.expect(step_until_done(&queue, &mock) == .completed);
    try testing.expect(queue.state.sync_state.safe_head.eql(info(7)));
}

test "consolidate: missing unsafe block resets and clears the queue" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    var queue = try new_queue(state_at(10, 5, 0));
    defer queue.deinit(testing.allocator);
    const attributes = chain.fixtures[6].attributes(info(5));
    try queue.enqueue(.{ .consolidate = &attributes });
    try queue.enqueue(.{ .finalize = 3 });
    try expect_failure(step_until_done(&queue, &mock), error.MissingUnsafeL2Block, .reset);
    try testing.expectEqual(@as(u32, 0), queue.len());
    mock.block_error = error.RpcFailed;
    try queue.enqueue(.{ .consolidate = &attributes });
    try expect_failure(queue.step(&mock), error.FailedToFetchUnsafeL2Block, .temporary);
}

// Queue (base/base core.rs).

test "queue: priority order, fifo within a priority, and capacity" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{};
    chain.load(&mock);
    var queue = try new_queue(state_at(10, 10, 0));
    defer queue.deinit(testing.allocator);
    const first: insert_module.Envelope = .{ .payload = chain.fixtures[11].payload() };
    const second: insert_module.Envelope = .{ .payload = chain.fixtures[12].payload() };
    try queue.enqueue(.{ .finalize = 4 });
    try queue.enqueue(.{ .synchronize = .{} });
    try queue.enqueue(.{ .insert = .{ .envelope = &first } });
    try queue.enqueue(.{ .insert = .{ .envelope = &second } });
    const order = [_]queue_module.Kind{ .insert, .insert, .finalize, .synchronize };
    for (order) |kind| {
        const result = queue.step(&mock);
        try testing.expectEqual(kind, std.meta.activeTag(result.completed));
    }
    try testing.expect(queue.state.sync_state.unsafe_head.eql(info(12)));
    try testing.expect(queue.step(&mock) == .idle);

    for (0..8) |_| try queue.enqueue(.{ .finalize = 1 });
    try testing.expectError(error.QueueFull, queue.enqueue(.{ .finalize = 1 }));
    queue.clear();
    try testing.expectEqual(@as(u32, 0), queue.len());
}

test "queue: a waiting task stays active over higher priorities" {
    var chain: Chain = undefined;
    chain.init();
    var mock: MockEngine = .{ .latency = 2 };
    chain.load(&mock);
    var queue = try new_queue(state_at(10, 10, 0));
    defer queue.deinit(testing.allocator);
    try queue.enqueue(.{ .finalize = 4 });
    try testing.expect(queue.step(&mock) == .pending);
    const envelope: insert_module.Envelope = .{ .payload = chain.fixtures[11].payload() };
    try queue.enqueue(.{ .insert = .{ .envelope = &envelope } });
    const result = step_until_done(&queue, &mock);
    try testing.expectEqual(queue_module.Kind.finalize, std.meta.activeTag(result.completed));
    const next = step_until_done(&queue, &mock);
    try testing.expectEqual(queue_module.Kind.insert, std.meta.activeTag(next.completed));
}

// Seeded fuzz over random task sequences.

const Fuzz = struct {
    chain: *Chain,
    mock: MockEngine,
    queue: EngineTaskQueue,
    prng: Prng,
    mock_prng: Prng,
    digest: std.hash.Wyhash,

    fn enqueue_random(fuzz: *Fuzz) !void {
        const sync_state = fuzz.queue.state.sync_state;
        const unsafe_number = sync_state.unsafe_head.block_info.number;
        const safe_number = sync_state.safe_head.block_info.number;
        const target = @min(fuzz.prng.below(chain_length - 1) + 1, chain_length - 1);
        const fixture = &fuzz.chain.fixtures[@min(unsafe_number + 1, chain_length - 1)];
        const result = switch (fuzz.prng.below(6)) {
            0, 1 => fuzz.queue.enqueue(.{ .insert = .{
                .envelope = &.{ .payload = fuzz.chain.fixtures[target].payload() },
                .drop_invalid = fuzz.prng.chance(1, 2),
            } }),
            2 => blk: {
                const next = @min(safe_number + 1, chain_length - 1);
                const attributes = fuzz.chain.fixtures[next].attributes(info(next - 1));
                break :blk fuzz.queue.enqueue(.{ .consolidate = &attributes });
            },
            3 => fuzz.queue.enqueue(.{ .finalize = fuzz.prng.below(safe_number + 1) }),
            4 => blk: {
                const attributes = fixture.attributes(sync_state.unsafe_head);
                fuzz.mock.payload = .{ .payload = fixture.payload(), .block_value = 0 };
                break :blk fuzz.queue.enqueue(.{ .seal = .{
                    .payload_id = @splat(3),
                    .attributes = &attributes,
                } });
            },
            5 => fuzz.queue.enqueue(.{ .synchronize = .{ .finalized_head = info(
                fuzz.prng.below(safe_number + 1),
            ) } }),
            else => unreachable,
        };
        result catch |err| switch (err) {
            error.QueueFull => fuzz.digest.update("full"),
            error.OutOfMemory => return err,
        };
    }

    fn configure_mock(fuzz: *Fuzz) void {
        const statuses = [_]task.Status{ .valid, .valid, .valid, .syncing, .invalid };
        fuzz.mock.forkchoice_status = statuses[fuzz.prng.below(statuses.len)];
        fuzz.mock.new_payload_status = statuses[fuzz.prng.below(statuses.len)];
        fuzz.mock.latency = @intCast(fuzz.prng.below(3));
    }

    fn record(fuzz: *Fuzz, result: StepResult) void {
        const tag: u8 = @backingInt(std.meta.activeTag(result));
        fuzz.digest.update(&.{tag});
        if (result == .failed) {
            fuzz.digest.update(@errorName(result.failed.err));
            // A critical task would block the queue forever; the node would stop instead.
            if (result.failed.severity == .critical) fuzz.queue.clear();
        }
        const sync_state = fuzz.queue.state.sync_state;
        const heads = [_]u64{
            sync_state.unsafe_head.block_info.number,
            sync_state.local_safe_head.block_info.number,
            sync_state.safe_head.block_info.number,
            sync_state.finalized_head.block_info.number,
        };
        fuzz.digest.update(std.mem.sliceAsBytes(&heads));
    }
};

fn run_fuzz(chain: *Chain, seed: u64) !u64 {
    var fuzz: Fuzz = .{
        .chain = chain,
        .mock = .{ .not_available_percent = 20 },
        .queue = try new_queue(state_at(0, 0, 0)),
        .prng = Prng.init(seed),
        .mock_prng = Prng.init(seed ^ 0x9e37_79b9),
        .digest = .init(seed),
    };
    defer fuzz.queue.deinit(testing.allocator);
    fuzz.mock.prng = &fuzz.mock_prng;
    chain.load(&fuzz.mock);
    for (0..300) |_| {
        switch (fuzz.prng.below(4)) {
            0 => try fuzz.enqueue_random(),
            1 => fuzz.configure_mock(),
            else => fuzz.record(fuzz.queue.step(&fuzz.mock)),
        }
        try testing.expect(fuzz.queue.state.sync_state.is_ordered());
        try testing.expect(fuzz.queue.len() <= 8);
    }
    return fuzz.digest.final();
}

test "queue: seeded fuzz keeps heads ordered and replays per seed" {
    var chain: Chain = undefined;
    chain.init();
    var seeds = Prng.init(0xe9_61_7e);
    for (0..40) |_| {
        const seed = seeds.int(u64);
        const first = try run_fuzz(&chain, seed);
        const second = try run_fuzz(&chain, seed);
        try testing.expectEqual(first, second);
    }
}

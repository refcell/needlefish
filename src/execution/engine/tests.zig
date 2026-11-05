//! Engine handler tests over an in-memory mock backend, plus seeded and
//! coverage-guided fuzzing of random block trees and forkchoice calls.

const std = @import("std");
const testing = std.testing;
const engine_module = @import("root.zig");
const types = engine_module.types;
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;
const Address = primitives.Address;
const BlockRef = engine_module.BlockRef;

const invalid_marker_gas: u64 = 666;

const Mock = struct {
    const capacity = 128;
    pub const Built = struct { id: payload.PayloadId, timestamp: u64, parent: B256 };

    blocks: [capacity]BlockRef = undefined,
    len: u32 = 0,
    builds: [8]Built = undefined,
    builds_len: u32 = 0,
    forkchoice: ?types.ForkchoiceState = null,

    pub fn block(mock: *Mock, hash: B256) ?BlockRef {
        for (mock.blocks[0..mock.len]) |b| if (b.hash.eql(hash)) return b;
        return null;
    }

    pub fn is_ancestor(mock: *Mock, ancestor: B256, descendant: B256) bool {
        var cursor = mock.block(descendant) orelse return false;
        var steps: u32 = 0;
        while (steps <= capacity) : (steps += 1) {
            if (cursor.hash.eql(ancestor)) return true;
            cursor = mock.block(cursor.parent_hash) orelse return false;
        }
        unreachable; // Parent links strictly decrease the block number.
    }

    pub fn insert(
        mock: *Mock,
        p: *const types.ExecutionPayload,
        _: *const types.NewPayloadParams,
    ) engine_module.InsertResult {
        if (p.gas_used == invalid_marker_gas) return .{ .invalid = "bad state root" };
        if (mock.len == capacity) return .{ .invalid = "mock full" };
        mock.blocks[mock.len] = .{
            .hash = p.block_hash,
            .parent_hash = p.parent_hash,
            .number = p.block_number,
            .timestamp = p.timestamp,
        };
        mock.len += 1;
        return .valid;
    }

    pub fn set_forkchoice(mock: *Mock, state: types.ForkchoiceState) types.EngineError!void {
        mock.forkchoice = state;
    }

    pub fn start_build(
        mock: *Mock,
        id: payload.PayloadId,
        parent: BlockRef,
        attrs: *const payload.PayloadAttributes,
    ) types.EngineError!void {
        const slot = mock.builds_len % mock.builds.len;
        mock.builds[slot] = .{ .id = id, .timestamp = attrs.timestamp, .parent = parent.hash };
        mock.builds_len += 1;
    }

    pub fn built(mock: *Mock, id: payload.PayloadId) ?Built {
        const n = @min(mock.builds_len, mock.builds.len);
        for (mock.builds[0..n]) |b| if (std.mem.eql(u8, &b.id, &id)) return b;
        return null;
    }
};

const Engine = engine_module.Engine(Mock);
const spec = &chainspec.ChainSpec.presets.base_devnet;

fn hash_of(n: u64) B256 {
    var h = B256.zero;
    std.mem.writeInt(u64, h.bytes[24..32], n + 1, .big);
    return h;
}

fn status_of(engine: *Engine, p: *const types.ExecutionPayload) !types.Status {
    return (try engine.new_payload(.v4, p, &v4_params)).status;
}

fn genesis(mock: *Mock) void {
    mock.blocks[0] = .{
        .hash = hash_of(0),
        .parent_hash = B256.zero,
        .number = 0,
        .timestamp = 0,
    };
    mock.len = 1;
}

fn make_payload(parent: BlockRef, id: u64, timestamp: u64) types.ExecutionPayload {
    return .{
        .parent_hash = parent.hash,
        .fee_recipient = Address.zero,
        .state_root = B256.zero,
        .receipts_root = B256.zero,
        .logs_bloom = std.mem.zeroes(primitives.Bloom),
        .prev_randao = B256.zero,
        .block_number = parent.number + 1,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = timestamp,
        .extra_data = &.{},
        .base_fee_per_gas = 1,
        .block_hash = hash_of(id),
        .transactions = &.{},
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .withdrawals_root = B256.zero,
    };
}

const v4_params: types.NewPayloadParams = .{
    .versioned_hashes = &.{},
    .parent_beacon_block_root = B256.zero,
    .execution_requests = &.{},
};

fn fc(head: B256, safe: B256, finalized: B256) types.ForkchoiceState {
    return .{
        .head_block_hash = head,
        .safe_block_hash = safe,
        .finalized_block_hash = finalized,
    };
}

fn attributes(timestamp: u64) payload.PayloadAttributes {
    return .{
        .timestamp = timestamp,
        .prev_randao = B256.zero,
        .suggested_fee_recipient = Address.zero,
        .withdrawals = &.{},
        .parent_beacon_block_root = B256.zero,
        .gas_limit = 30_000_000,
        .eip1559_params = @splat(0),
        .min_base_fee = 0,
    };
}

test "engine: newPayload valid, known, syncing, invalid" {
    var mock: Mock = .{};
    genesis(&mock);
    var engine = Engine.init(spec, &mock);
    const g = mock.blocks[0];
    const p1 = make_payload(g, 1, 2);
    try testing.expectEqual(types.Status.valid, try status_of(&engine, &p1));
    try testing.expectEqual(types.Status.valid, try status_of(&engine, &p1));
    const orphan_parent: BlockRef = .{
        .hash = hash_of(50),
        .parent_hash = B256.zero,
        .number = 5,
        .timestamp = 9,
    };
    const orphan = make_payload(orphan_parent, 51, 10);
    try testing.expectEqual(types.Status.syncing, try status_of(&engine, &orphan));
    var bad = make_payload(mock.block(hash_of(1)).?, 2, 4);
    bad.gas_used = invalid_marker_gas;
    const status = try engine.new_payload(.v4, &bad, &v4_params);
    try testing.expectEqual(types.Status.invalid, status.status);
    try testing.expect(status.latest_valid_hash.?.eql(hash_of(1)));
    // A child of the invalid block is rejected without execution.
    const bad_ref: BlockRef = .{
        .hash = hash_of(2),
        .parent_hash = hash_of(1),
        .number = 2,
        .timestamp = 4,
    };
    const child = make_payload(bad_ref, 3, 6);
    const child_status = try engine.new_payload(.v4, &child, &v4_params);
    try testing.expectEqual(types.Status.invalid, child_status.status);
    try testing.expect(child_status.latest_valid_hash.?.eql(hash_of(1)));
    var early = make_payload(g, 4, 0);
    early.timestamp = 0;
    try testing.expectEqual(types.Status.invalid, try status_of(&engine, &early));
}

test "engine: forkchoice rules and payload building" {
    var mock: Mock = .{};
    genesis(&mock);
    var engine = Engine.init(spec, &mock);
    const p1 = make_payload(mock.blocks[0], 1, 2);
    _ = try engine.new_payload(.v4, &p1, &v4_params);
    const h1 = hash_of(1);
    const head1 = fc(h1, B256.zero, B256.zero);
    const zero = B256.zero;
    const unknown = try engine.forkchoice_updated(.v3, fc(hash_of(99), zero, zero), null);
    try testing.expectEqual(types.Status.syncing, unknown.payload_status.status);
    const not_ancestor = engine.forkchoice_updated(.v3, fc(hash_of(0), zero, h1), null);
    try testing.expectError(error.InvalidForkchoiceState, not_ancestor);
    const zero_head = engine.forkchoice_updated(.v3, fc(zero, zero, zero), null);
    try testing.expectError(error.InvalidParams, zero_head);
    const attrs = attributes(4);
    const updated = try engine.forkchoice_updated(.v3, fc(h1, hash_of(0), hash_of(0)), &attrs);
    try testing.expectEqual(types.Status.valid, updated.payload_status.status);
    try testing.expect(mock.forkchoice.?.head_block_hash.eql(h1));
    const id = updated.payload_id.?;
    try testing.expectEqual(@as(u64, 4), (try engine.get_payload(.v5, id)).timestamp);
    try testing.expectError(error.UnsupportedFork, engine.get_payload(.v3, id));
    try testing.expectError(error.UnknownPayload, engine.get_payload(.v5, @splat(0)));
    // Stale timestamp: forkchoice applies but attributes are rejected.
    const stale = attributes(2);
    const stale_result = engine.forkchoice_updated(.v3, head1, &stale);
    try testing.expectError(error.InvalidPayloadAttributes, stale_result);
    var no_gas = attributes(6);
    no_gas.gas_limit = null;
    const no_gas_result = engine.forkchoice_updated(.v3, head1, &no_gas);
    try testing.expectError(error.InvalidPayloadAttributes, no_gas_result);
    var v2_shape = attributes(6);
    v2_shape.parent_beacon_block_root = null;
    const v2_result = engine.forkchoice_updated(.v2, head1, &v2_shape);
    try testing.expectError(error.UnsupportedFork, v2_result);
}

/// Random block tree + random engine calls; checks statuses against the mock's truth.
fn random_run(prng: *Prng) !void {
    var mock: Mock = .{};
    genesis(&mock);
    var engine = Engine.init(spec, &mock);
    var next_id: u64 = 1;
    for (0..200) |_| {
        const parent = mock.blocks[prng.below(mock.len)];
        switch (prng.below(4)) {
            0, 1 => {
                var p = make_payload(parent, next_id, parent.timestamp + 1 + prng.below(3));
                next_id += 1;
                if (prng.chance(1, 8)) p.gas_used = invalid_marker_gas;
                const status = try engine.new_payload(.v4, &p, &v4_params);
                const stored = mock.block(p.block_hash) != null;
                try testing.expectEqual(stored, status.status == .valid);
            },
            2 => {
                const head = mock.blocks[prng.below(mock.len)];
                const finalized = mock.blocks[prng.below(mock.len)];
                const state = fc(head.hash, B256.zero, finalized.hash);
                const result = engine.forkchoice_updated(.v3, state, null);
                const ok = mock.is_ancestor(finalized.hash, head.hash);
                if (result) |r| {
                    try testing.expect(ok);
                    try testing.expectEqual(types.Status.valid, r.payload_status.status);
                } else |err| {
                    try testing.expect(!ok);
                    try testing.expectEqual(error.InvalidForkchoiceState, err);
                }
            },
            else => {
                const attrs = attributes(parent.timestamp + 1);
                const state = fc(parent.hash, B256.zero, B256.zero);
                const r = try engine.forkchoice_updated(.v3, state, &attrs);
                _ = try engine.get_payload(.v5, r.payload_id.?);
            },
        }
        if (mock.len == Mock.capacity) break;
    }
}

test "engine: seeded fuzz random trees" {
    var prng = Prng.init(0xe461);
    for (0..50) |_| try random_run(&prng);
}

fn fuzz_engine(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try random_run(&prng);
}

test "engine: fuzz" {
    try testing.fuzz({}, fuzz_engine, .{});
}
